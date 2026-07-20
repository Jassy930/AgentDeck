//! Runtime 持久化层的平台无关内部模型。
//!
//! 这些类型不进入 RuntimeEnvelope wire；P3.4 RuntimeCore 负责把内部精确状态/
//! failure 映射成客户端可见 receipt 与 `RuntimeFailure`。

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use agentdeck_protocol::runtime::ConversationConfiguration;
use agentdeck_protocol::runtime::failure::{
    DAEMON_CONVERSATION_CONFIGURATION_CONFLICT, DAEMON_CONVERSATION_CONFIGURATION_REQUIRED,
    DAEMON_CONVERSATION_METADATA_MUTATION_PENDING, DAEMON_RUNTIME_FEATURE_UNAVAILABLE,
};
use agentdeck_protocol::{ActionDecision, ActionRequest, AgentKind, TurnSummary};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use super::approval::{ApprovalClaimantBinding, ApprovalPolicySnapshot};
use super::store::admission::SystemRuntimeCapacityProbe;
pub use super::store::admission::{
    RuntimeCapacityObservation, RuntimeCapacityProbe, RuntimeCapacityProbeError,
};
use super::store::cipher::CipherError;
use super::store::identity::{
    OsRuntimeIdSource, RuntimeId, RuntimeIdError, RuntimeIdKind, RuntimeIdSource,
};
use super::store::sequence::SequenceError;

pub const DEFAULT_RUNTIME_STORE_COMMAND_CAPACITY: usize = 32;
pub const DEFAULT_RUNTIME_BUSY_TIMEOUT_MS: u64 = 5_000;
pub const MAX_RUNTIME_STORE_COMMAND_CAPACITY: usize = 1_024;
pub const DEFAULT_RUNTIME_STORE_LANE_BYTE_CAPACITY: usize = 256 * 1024 * 1024;
pub const MAX_RUNTIME_STORE_LANE_BYTE_CAPACITY: usize = 256 * 1024 * 1024;
pub const MAX_RUNTIME_BUSY_TIMEOUT_MS: u64 = 30_000;
pub const RUNTIME_STORE_SHUTDOWN_GRACE_MS: u64 = 5_000;
pub const MAX_CONVERSATION_QUEUED_COMMANDS: u32 = 32;
pub const MAX_GLOBAL_QUEUED_COMMANDS: u32 = 1_024;
pub const MAX_GLOBAL_QUEUED_PAYLOAD_BYTES: u64 = 256 * 1024 * 1024;
/// daemon 同时安装的 managed/native-present actor 与 live catalog entry 硬上界。
pub const MAX_RUNTIME_LIVE_CONVERSATIONS: u64 = 1_024;
/// native tombstone/retired identity 的额外物理保留上界。
pub const MAX_NATIVE_NONLIVE_IDENTITIES: u64 = 8_192;
/// v6 store 中 live 与 native non-live identity 合计的物理行硬上界。
pub const MAX_RUNTIME_PHYSICAL_CONVERSATIONS: u64 =
    MAX_RUNTIME_LIVE_CONVERSATIONS + MAX_NATIVE_NONLIVE_IDENTITIES;
/// 兼容既有调用方：conversation capacity 始终表示 live actor/catalog 容量。
pub const MAX_RUNTIME_CONVERSATIONS: u64 = MAX_RUNTIME_LIVE_CONVERSATIONS;
pub const MAX_COMMAND_PAYLOAD_BYTES: usize = 256 * 1024;
pub const MAX_CONVERSATION_DESCRIPTOR_BYTES: usize = 1024 * 1024;
pub const MAX_ADAPTER_STATE_REFERENCE_BYTES: usize = 4 * 1024;
pub const MAX_IDEMPOTENCY_KEY_BYTES: usize = 1024;
pub const MAX_EXECUTION_INTENT_BYTES: usize = 1024 * 1024;
pub const MAX_RUNTIME_EVENT_BYTES: usize = 64 * 1024 * 1024;
/// Store-owned Started/terminal record 的独立小上限；任意大 Item/Error 走普通事件事务。
pub const MAX_CRITICAL_COMMAND_RECORD_BYTES: usize = 4 * 1024;
pub const MAX_EXECUTION_FENCE_BYTES: usize = 1024 * 1024;
pub const MAX_COMMAND_RESULT_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_EXECUTION_NONCE_BYTES: usize = 1024;
/// 单个 conversation 恢复页的 retained-memory 硬上界。
///
/// 1 MiB descriptor + 32 * 256 KiB Accepted prompts + 一个 Started prompt/
/// intent/event/fence 的合法最大值低于 80 MiB；该上界独立于 async lane budget，
/// 也绝不允许退化为全库 RecoveryState 物化。
pub const MAX_RECOVERY_PAGE_RETAINED_BYTES: usize = 80 * 1024 * 1024;
pub const COMMAND_QUEUE_TTL_MS: u64 = 24 * 60 * 60 * 1_000;
pub const COMMAND_LEDGER_RETENTION_MS: u64 = 30 * 24 * 60 * 60 * 1_000;
pub const MAX_APPROVAL_REQUEST_BYTES: usize = 256 * 1024;
pub const MAX_APPROVAL_DECISION_BYTES: usize = 64 * 1024;
pub const MAX_APPROVAL_STATUS_DETAIL_BYTES: usize = 64 * 1024;
pub const MAX_ACTIVE_APPROVALS_PER_TURN: u32 = 32;
pub const MAX_ACTIVE_APPROVALS_GLOBAL: u64 = 1_024;
pub const MAX_DURABLE_APPROVALS: u64 = 32_768;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeStoreOperation {
    InitializeBeforePublish,
    MigrateSchemaBeforeCommit,
    MigrateSchemaAfterCommit,
    Inspect,
    PrepareMachineIdentityBeforeCommit,
    PrepareMachineIdentityAfterCommit,
    ActivateMachineIdentityBeforeCommit,
    ActivateMachineIdentityAfterCommit,
    PrepareMachineEnrollmentBeforeCommit,
    PrepareMachineEnrollmentAfterCommit,
    RecordValidatedEnrollmentResponseBeforeCommit,
    RecordValidatedEnrollmentResponseAfterCommit,
    ActivateMachineEnrollmentBeforeCommit,
    ActivateMachineEnrollmentAfterCommit,
    PrepareMachineRetirementBeforeCommit,
    PrepareMachineRetirementAfterCommit,
    RecordMachineRetirementTerminalBeforeCommit,
    RecordMachineRetirementTerminalAfterCommit,
    ConfirmMachinePurgeReadbackAbsentBeforeCommit,
    ConfirmMachinePurgeReadbackAbsentAfterCommit,
    RecordRootLostMachinePurgeBeforeCommit,
    RecordRootLostMachinePurgeAfterCommit,
    FinalizeMachineLocalDeletionBeforeCommit,
    FinalizeMachineLocalDeletionAfterCommit,
    ReplaceLocalDeletedEnrollmentBeforeCommit,
    ReplaceLocalDeletedEnrollmentAfterCommit,
    StreamNotificationReadback,
    RecordEnrollmentReceiptBeforeCommit,
    RecordEnrollmentReceiptAfterCommit,
    CreateConversationBeforeCommit,
    CreateConversationAfterCommit,
    ConfigureConversationBeforeCommit,
    ConfigureConversationAfterCommit,
    AcceptAdminUpgradeBeforeCommit,
    AcceptAdminUpgradeAfterCommit,
    FinalizeAdminUpgradeBeforeCommit,
    FinalizeAdminUpgradeAfterCommit,
    UpdateConversationMetadataBeforeCommit,
    UpdateConversationMetadataAfterCommit,
    MarkConversationRecoveryBlockedBeforeCommit,
    MarkConversationRecoveryBlockedAfterCommit,
    AcceptCommandBeforeCommit,
    AcceptCommandAfterCommit,
    StartCommandBeforeCommit,
    StartCommandAfterCommit,
    AppendExecutionEventBeforeCommit,
    AppendExecutionEventAfterCommit,
    ExpireCommandsBeforeCommit,
    ExpireCommandsAfterCommit,
    TerminateAcceptedCommandBeforeCommit,
    TerminateAcceptedCommandAfterCommit,
    TerminateStartedBeforeReleaseBeforeCommit,
    TerminateStartedBeforeReleaseAfterCommit,
    PersistFenceBeforeCommit,
    PersistFenceAfterCommit,
    AuthorizeExecutionReleaseBeforeCommit,
    AuthorizeExecutionReleaseAfterCommit,
    CompleteCommandBeforeCommit,
    CompleteCommandAfterCommit,
    BindAdapterStateBeforeCommit,
    BindAdapterStateAfterCommit,
    ImportNativeProjectionBeforeCommit,
    ImportNativeProjectionAfterCommit,
    ReconcileNativeProjectionBeforeCommit,
    ReconcileNativeProjectionAfterCommit,
    RetireNativeProjectionBeforeCommit,
    RetireNativeProjectionAfterCommit,
    ClaimNativeMetadataMutationBeforeCommit,
    ClaimNativeMetadataMutationAfterCommit,
    FailClaimedNativeMetadataMutationBeforeCommit,
    FailClaimedNativeMetadataMutationAfterCommit,
    MarkNativeMetadataMutationOutcomeUnknownBeforeCommit,
    MarkNativeMetadataMutationOutcomeUnknownAfterCommit,
    FinalizeNativeMetadataMutationReadbackBeforeCommit,
    FinalizeNativeMetadataMutationReadbackAfterCommit,
    PersistNativeMetadataEffectFenceBeforeCommit,
    PersistNativeMetadataEffectFenceAfterCommit,
    AuthorizeNativeMetadataEffectReleaseBeforeCommit,
    AuthorizeNativeMetadataEffectReleaseAfterCommit,
    FailUnreleasedNativeMetadataEffectBeforeCommit,
    FailUnreleasedNativeMetadataEffectAfterCommit,
    RegisterApprovalBeforeCommit,
    RegisterApprovalAfterCommit,
    ClaimApprovalBeforeCommit,
    ClaimApprovalAfterCommit,
    BeginApprovalAttemptBeforeCommit,
    BeginApprovalAttemptAfterCommit,
    MarkApprovalAppliedBeforeCommit,
    MarkApprovalAppliedAfterCommit,
    MarkApprovalDeliveryFailedBeforeCommit,
    MarkApprovalDeliveryFailedAfterCommit,
    RetryApprovalDeliveryBeforeCommit,
    RetryApprovalDeliveryAfterCommit,
    ExpireApprovalBeforeCommit,
    ExpireApprovalAfterCommit,
    StoreSnapshotBeforeCommit,
    StoreSnapshotAfterCommit,
    CreatePublicationStreamBeforeCommit,
    CreatePublicationStreamAfterCommit,
    RotatePublicationStreamBeforeCommit,
    RotatePublicationStreamAfterCommit,
    FreezePublicationBeforeCommit,
    FreezePublicationAfterCommit,
    CommitPublicationBeforeCommit,
    CommitPublicationAfterCommit,
    AcknowledgePublicationBeforeCommit,
    AcknowledgePublicationAfterCommit,
}

pub trait RuntimeStoreFaultInjector: Send + Sync {
    fn before_operation(&self, _operation: RuntimeStoreOperation) -> Result<(), RuntimeStoreError> {
        Ok(())
    }
}

#[derive(Debug)]
struct NoRuntimeStoreFaults;

impl RuntimeStoreFaultInjector for NoRuntimeStoreFaults {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeStoreLane {
    Normal,
    Safety,
    Read,
}

pub trait RuntimeClock: Send + Sync {
    fn now_ms(&self) -> Result<u64, RuntimeClockError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemRuntimeClock;

impl RuntimeClock for SystemRuntimeClock {
    fn now_ms(&self) -> Result<u64, RuntimeClockError> {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| RuntimeClockError::BeforeUnixEpoch)?;
        u64::try_from(duration.as_millis()).map_err(|_| RuntimeClockError::OutOfRange)
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum RuntimeClockError {
    #[error("system clock is before the Unix epoch")]
    BeforeUnixEpoch,
    #[error("system clock milliseconds do not fit in u64")]
    OutOfRange,
}

#[derive(Clone)]
pub struct RuntimeStoreConfig {
    pub storage_path: PathBuf,
    pub command_capacity: usize,
    pub conversation_capacity: u64,
    pub lane_byte_capacity: usize,
    pub busy_timeout_ms: u64,
    pub fault_injector: Arc<dyn RuntimeStoreFaultInjector>,
    pub id_source: Arc<Mutex<Box<dyn RuntimeIdSource>>>,
    pub capacity_probe: Arc<dyn RuntimeCapacityProbe>,
    pub clock: Arc<dyn RuntimeClock>,
}

impl RuntimeStoreConfig {
    #[must_use]
    pub fn new(storage_path: PathBuf) -> Self {
        Self {
            storage_path,
            command_capacity: DEFAULT_RUNTIME_STORE_COMMAND_CAPACITY,
            conversation_capacity: MAX_RUNTIME_CONVERSATIONS,
            lane_byte_capacity: DEFAULT_RUNTIME_STORE_LANE_BYTE_CAPACITY,
            busy_timeout_ms: DEFAULT_RUNTIME_BUSY_TIMEOUT_MS,
            fault_injector: Arc::new(NoRuntimeStoreFaults),
            id_source: Arc::new(Mutex::new(Box::new(OsRuntimeIdSource))),
            capacity_probe: Arc::new(SystemRuntimeCapacityProbe),
            clock: Arc::new(SystemRuntimeClock),
        }
    }

    #[must_use]
    pub fn with_command_capacity(mut self, command_capacity: usize) -> Self {
        self.command_capacity = command_capacity;
        self
    }

    #[must_use]
    pub fn with_conversation_capacity(mut self, conversation_capacity: u64) -> Self {
        self.conversation_capacity = conversation_capacity;
        self
    }

    #[must_use]
    pub fn with_lane_byte_capacity(mut self, lane_byte_capacity: usize) -> Self {
        self.lane_byte_capacity = lane_byte_capacity;
        self
    }

    #[must_use]
    pub fn with_fault_injector(
        mut self,
        fault_injector: Arc<dyn RuntimeStoreFaultInjector>,
    ) -> Self {
        self.fault_injector = fault_injector;
        self
    }

    #[must_use]
    pub fn with_id_source(mut self, id_source: impl RuntimeIdSource + 'static) -> Self {
        self.id_source = Arc::new(Mutex::new(Box::new(id_source)));
        self
    }

    #[must_use]
    pub fn with_capacity_probe(
        mut self,
        capacity_probe: impl RuntimeCapacityProbe + 'static,
    ) -> Self {
        self.capacity_probe = Arc::new(capacity_probe);
        self
    }

    #[must_use]
    pub fn with_clock(mut self, clock: impl RuntimeClock + 'static) -> Self {
        self.clock = Arc::new(clock);
        self
    }
}

impl std::fmt::Debug for RuntimeStoreConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RuntimeStoreConfig")
            .field("storage_path", &self.storage_path)
            .field("command_capacity", &self.command_capacity)
            .field("conversation_capacity", &self.conversation_capacity)
            .field("lane_byte_capacity", &self.lane_byte_capacity)
            .field("busy_timeout_ms", &self.busy_timeout_ms)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeStoreSnapshot {
    pub schema_family: String,
    pub schema_version: u32,
    pub schema_signature: [u8; 32],
    pub database_id: [u8; 16],
    pub key_generation: u32,
    pub table_names: Vec<String>,
    pub journal_mode: String,
    pub wal_autocheckpoint_pages: u64,
    pub synchronous: i64,
    pub foreign_keys: bool,
    pub busy_timeout_ms: u64,
    pub page_size_bytes: u64,
    pub page_count: u64,
    pub max_page_count: u64,
}

/// Runtime DB 中允许持久化的 machine identity 公共绑定。
///
/// 私钥 seed、HPKE IKM、StorageKEK、CounterGuard material 与 certificate
/// 都不属于该类型，也不得进入 `machine_identity_state`。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MachineIdentityBinding {
    pub root_key_id: [u8; 16],
    pub trust_epoch: u64,
    pub link_generation: u64,
    pub data_generation: u64,
    pub key_directory_revision: u64,
    pub root_public_key: [u8; 32],
    pub root_fingerprint: [u8; 32],
    pub machine_hpke_public_key: [u8; 32],
    pub machine_hpke_fingerprint: [u8; 32],
    pub link_sign_public_key: [u8; 32],
    pub link_sign_fingerprint: [u8; 32],
    pub data_sign_public_key: [u8; 32],
    pub data_sign_fingerprint: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MachineIdentityLifecycle {
    Preparing,
    Active,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MachineIdentityStateRecord {
    pub database_id: [u8; 16],
    pub lifecycle: MachineIdentityLifecycle,
    pub binding: MachineIdentityBinding,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PrepareMachineIdentityOutcome {
    Prepared { state: MachineIdentityStateRecord },
    Replayed { state: MachineIdentityStateRecord },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ActivateMachineIdentityOutcome {
    Activated { state: MachineIdentityStateRecord },
    Replayed { state: MachineIdentityStateRecord },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MachineRemoteLifecycle {
    EnrollmentPrepared,
    EnrollmentResponseValidated,
    Active,
    RetirePending,
    RelayCommitted,
    PurgeReadbackAbsent,
    LocalDeleted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MachineTrustResetKind {
    RootPresent,
    RootLost,
}

pub const MACHINE_CLEANUP_WITNESS_VERSION: u8 = 1;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Error)]
pub enum MachineCleanupWitnessError {
    #[error("machine cleanup witness required binding is all-zero: {0}")]
    ZeroBinding(&'static str),
}

#[derive(Clone, Eq, PartialEq)]
pub struct MachineCleanupWitnessV1 {
    reset_kind: MachineTrustResetKind,
    relay_server_id: agentdeck_protocol::relay_v2::RelayServerId,
    machine_route: agentdeck_protocol::relay_v2::MachineRouteId,
    root_key_id: agentdeck_protocol::relay_v2::RootKeyId,
    root_fingerprint: [u8; 32],
    trust_epoch: agentdeck_protocol::relay_v2::TrustEpoch,
    purge_proof_hash: [u8; 32],
}

impl MachineCleanupWitnessV1 {
    pub fn new(
        reset_kind: MachineTrustResetKind,
        relay_server_id: agentdeck_protocol::relay_v2::RelayServerId,
        machine_route: agentdeck_protocol::relay_v2::MachineRouteId,
        root_key_id: agentdeck_protocol::relay_v2::RootKeyId,
        root_fingerprint: [u8; 32],
        trust_epoch: agentdeck_protocol::relay_v2::TrustEpoch,
        purge_proof_hash: [u8; 32],
    ) -> Result<Self, MachineCleanupWitnessError> {
        for (value, field) in [
            (&relay_server_id.as_bytes()[..], "relayServerId"),
            (&machine_route.as_bytes()[..], "machineRoute"),
            (&root_key_id.as_bytes()[..], "rootKeyId"),
            (&root_fingerprint[..], "rootFingerprint"),
            (&purge_proof_hash[..], "purgeProofHash"),
        ] {
            if value.iter().all(|byte| *byte == 0) {
                return Err(MachineCleanupWitnessError::ZeroBinding(field));
            }
        }
        if trust_epoch.value() == 0 {
            return Err(MachineCleanupWitnessError::ZeroBinding("trustEpoch"));
        }
        Ok(Self {
            reset_kind,
            relay_server_id,
            machine_route,
            root_key_id,
            root_fingerprint,
            trust_epoch,
            purge_proof_hash,
        })
    }

    #[must_use]
    pub const fn reset_kind(&self) -> MachineTrustResetKind {
        self.reset_kind
    }

    #[must_use]
    pub const fn purge_proof_hash(&self) -> [u8; 32] {
        self.purge_proof_hash
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(139);
        bytes.extend_from_slice(b"AgentDeck/MachineCleanupWitnessV1\0");
        bytes.push(MACHINE_CLEANUP_WITNESS_VERSION);
        bytes.push(match self.reset_kind {
            MachineTrustResetKind::RootPresent => 0,
            MachineTrustResetKind::RootLost => 1,
        });
        bytes.extend_from_slice(self.relay_server_id.as_bytes());
        bytes.extend_from_slice(self.machine_route.as_bytes());
        bytes.extend_from_slice(self.root_key_id.as_bytes());
        bytes.extend_from_slice(&self.root_fingerprint);
        bytes.extend_from_slice(&self.trust_epoch.value().to_be_bytes());
        bytes.extend_from_slice(&self.purge_proof_hash);
        bytes
    }

    #[must_use]
    pub fn canonical_sha256(&self) -> [u8; 32] {
        Sha256::digest(self.canonical_bytes()).into()
    }
}

impl std::fmt::Debug for MachineCleanupWitnessV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("MachineCleanupWitnessV1([REDACTED])")
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MachineRemoteStateRecord {
    pub lifecycle: MachineRemoteLifecycle,
    pub relay_server_id: [u8; 16],
    pub machine_route: [u8; 16],
    pub root_key_id: [u8; 16],
    pub root_fingerprint: [u8; 32],
    pub trust_epoch: u64,
    pub request_hash: [u8; 32],
    pub response_hash: Option<[u8; 32]>,
    pub enrollment_receipt_hash: Option<[u8; 32]>,
    pub receipt_verify_key_hash: [u8; 32],
    pub sealed_state_bytes: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MachineEnrollmentConnectionMaterial {
    pub public_wss_url: String,
    pub relay_server_id: agentdeck_protocol::relay_v2::RelayServerId,
    pub receipt_verify_key: agentdeck_protocol::relay_v2::RelayReceiptVerifyKeyV1,
    pub spki_pins: Vec<agentdeck_protocol::relay_v2::Digest32>,
    pub expires_at_ms: u64,
}

/// Restart-safe enrollment owner。Prepared/Validated 的 code 只存在于 owned transient
/// request；该类型不实现 Clone，Debug 永远不展开 request、pin 或证书内容。
pub struct PreparedMachineEnrollmentState {
    pub record: MachineRemoteStateRecord,
    pub connection: MachineEnrollmentConnectionMaterial,
    pub request: agentdeck_protocol::relay_v2::MachineEnrollmentRequestV1,
}

pub struct ValidatedMachineEnrollmentState {
    pub record: MachineRemoteStateRecord,
    pub connection: MachineEnrollmentConnectionMaterial,
    pub request: agentdeck_protocol::relay_v2::MachineEnrollmentRequestV1,
    pub response: agentdeck_protocol::relay_v2::MachineEnrollmentResponseV1,
}

pub struct ActiveMachineEnrollmentState {
    pub record: MachineRemoteStateRecord,
    pub connection: MachineEnrollmentConnectionMaterial,
    pub binding: MachineIdentityBinding,
    pub link_cert: agentdeck_protocol::relay_v2::SignedCertificate,
    pub data_cert: agentdeck_protocol::relay_v2::SignedCertificate,
    /// sealed Prepared payload 的 canonical hash；用于显式 enroll retry 的 exact-input
    /// 比较，不回显 enrollment code。
    pub prepare_input_hash: [u8; 32],
    pub response: agentdeck_protocol::relay_v2::MachineEnrollmentResponseV1,
}

pub struct MachineRetirementRequestMaterial {
    pub retirement: agentdeck_protocol::relay_v2::frame::RetireMachine,
    pub canonical_bytes: Vec<u8>,
    pub canonical_hash: [u8; 32],
}

pub struct MachineRetirementTerminalMaterial {
    pub committed: agentdeck_protocol::relay_v2::frame::RetirementCommitted,
    pub canonical_frame_bytes: Vec<u8>,
    pub canonical_frame_hash: [u8; 32],
}

pub struct MachineRootLostPurgeMaterial {
    pub receipt: agentdeck_protocol::relay_v2::RelayAdminPurgeReceiptV1,
    pub canonical_bytes: Vec<u8>,
    pub canonical_hash: [u8; 32],
}

pub struct RetirePendingMachineEnrollmentState {
    pub record: MachineRemoteStateRecord,
    pub connection: MachineEnrollmentConnectionMaterial,
    pub binding: MachineIdentityBinding,
    pub link_cert: agentdeck_protocol::relay_v2::SignedCertificate,
    pub retirement: MachineRetirementRequestMaterial,
}

pub struct RelayCommittedMachineEnrollmentState {
    pub record: MachineRemoteStateRecord,
    pub retirement: MachineRetirementRequestMaterial,
    pub terminal: MachineRetirementTerminalMaterial,
}

pub enum MachinePurgeReadbackProof {
    RootPresent {
        retirement: MachineRetirementRequestMaterial,
        terminal: MachineRetirementTerminalMaterial,
    },
    RootLost {
        purge: MachineRootLostPurgeMaterial,
    },
}

pub struct PurgeReadbackAbsentMachineEnrollmentState {
    pub record: MachineRemoteStateRecord,
    /// 来自已认证 Store 上下文，不接受调用方自报；用于绑定本地密钥目录清理。
    pub database_id: [u8; 16],
    /// purge sealed payload 中保留的最后一个已认证 machine identity binding。
    pub binding: MachineIdentityBinding,
    pub reset_kind: MachineTrustResetKind,
    pub proof: MachinePurgeReadbackProof,
}

pub struct LocalDeletedMachineEnrollmentState {
    pub record: MachineRemoteStateRecord,
    pub reset_kind: MachineTrustResetKind,
    pub previous_prepare_input_hash: [u8; 32],
    pub purge_proof_hash: [u8; 32],
    pub cleanup_witness_hash: [u8; 32],
}

pub enum MachineEnrollmentState {
    EnrollmentPrepared(Box<PreparedMachineEnrollmentState>),
    EnrollmentResponseValidated(Box<ValidatedMachineEnrollmentState>),
    Active(Box<ActiveMachineEnrollmentState>),
    RetirePending(Box<RetirePendingMachineEnrollmentState>),
    RelayCommitted(Box<RelayCommittedMachineEnrollmentState>),
    PurgeReadbackAbsent(Box<PurgeReadbackAbsentMachineEnrollmentState>),
    LocalDeleted(Box<LocalDeletedMachineEnrollmentState>),
}

impl std::fmt::Debug for MachineEnrollmentState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = match self {
            Self::EnrollmentPrepared(_) => "enrollmentPrepared",
            Self::EnrollmentResponseValidated(_) => "enrollmentResponseValidated",
            Self::Active(_) => "active",
            Self::RetirePending(_) => "retirePending",
            Self::RelayCommitted(_) => "relayCommitted",
            Self::PurgeReadbackAbsent(_) => "purgeReadbackAbsent",
            Self::LocalDeleted(_) => "localDeleted",
        };
        formatter
            .debug_struct("MachineEnrollmentState")
            .field("state", &state)
            .field("material", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub enum PrepareMachineEnrollmentOutcome {
    Prepared { state: MachineEnrollmentState },
    Replayed { state: MachineEnrollmentState },
}

#[derive(Debug)]
pub enum RecordValidatedEnrollmentResponseOutcome {
    Recorded { state: MachineEnrollmentState },
    Replayed { state: MachineEnrollmentState },
}

#[derive(Debug)]
pub enum ActivateMachineEnrollmentOutcome {
    Activated { state: MachineEnrollmentState },
    Replayed { state: MachineEnrollmentState },
}

#[derive(Debug)]
pub enum PrepareMachineRetirementOutcome {
    Prepared { state: MachineEnrollmentState },
    Replayed { state: MachineEnrollmentState },
}

#[derive(Debug)]
pub enum RecordMachineRetirementTerminalOutcome {
    Recorded { state: MachineEnrollmentState },
    Replayed { state: MachineEnrollmentState },
}

#[derive(Debug)]
pub enum ConfirmMachinePurgeReadbackAbsentOutcome {
    Confirmed { state: MachineEnrollmentState },
    Replayed { state: MachineEnrollmentState },
}

#[derive(Debug)]
pub enum RecordRootLostMachinePurgeOutcome {
    Recorded { state: MachineEnrollmentState },
    Replayed { state: MachineEnrollmentState },
}

#[derive(Debug)]
pub enum FinalizeMachineLocalDeletionOutcome {
    Finalized { state: MachineEnrollmentState },
    Replayed { state: MachineEnrollmentState },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MachineEnrollmentReceiptRecord {
    pub relay_server_id: [u8; 16],
    pub machine_route: [u8; 16],
    pub root_fingerprint: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConversationLifecycle {
    Active,
    Archived,
    RecoveryBlocked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandState {
    Accepted,
    Started,
    Completed,
    Failed,
    Interrupted,
    Expired,
    Canceled,
    RevokedBeforeStart,
}

impl CommandState {
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        !matches!(self, Self::Accepted | Self::Started)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminalState {
    Completed,
    Failed,
    Interrupted,
    Canceled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueueScope {
    Conversation,
    GlobalCount,
    GlobalPayloadBytes,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigurationLimitScope {
    Conversation,
    GlobalCount,
    GlobalSealedBytes,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetadataMutationLimitScope {
    Conversation,
    GlobalCount,
    GlobalChargedBytes,
    Active,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeProjectionLimitScope {
    LiveConversations,
    PhysicalIdentities,
    NonliveIdentities,
    ChargedReferenceBytes,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdminCommandLimitScope {
    GlobalCount,
    Pending,
    ChargedBytes,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeCommitOperation {
    MigrateSchema,
    PrepareMachineIdentity,
    ActivateMachineIdentity,
    PrepareMachineEnrollment,
    RecordValidatedEnrollmentResponse,
    ActivateMachineEnrollment,
    PrepareMachineRetirement,
    RecordMachineRetirementTerminal,
    ConfirmMachinePurgeReadbackAbsent,
    RecordRootLostMachinePurge,
    FinalizeMachineLocalDeletion,
    ReplaceLocalDeletedEnrollment,
    RecordEnrollmentReceipt,
    CreateConversation,
    ConfigureConversation,
    AcceptAdminUpgrade,
    FinalizeAdminUpgrade,
    UpdateConversationMetadata,
    MarkConversationRecoveryBlocked,
    AcceptCommand,
    StartCommand,
    AppendExecutionEvent,
    ExpireCommands,
    TerminateAcceptedCommand,
    TerminateStartedBeforeRelease,
    PersistFence,
    AuthorizeExecutionRelease,
    CompleteCommand,
    BindAdapterState,
    ImportNativeProjection,
    ReconcileNativeProjection,
    RetireNativeProjection,
    ClaimNativeMetadataMutation,
    FailClaimedNativeMetadataMutation,
    MarkNativeMetadataMutationOutcomeUnknown,
    FinalizeNativeMetadataMutationReadback,
    PersistNativeMetadataEffectFence,
    AuthorizeNativeMetadataEffectRelease,
    FailUnreleasedNativeMetadataEffect,
    RegisterApproval,
    ClaimApproval,
    BeginApprovalAttempt,
    MarkApprovalApplied,
    MarkApprovalDeliveryFailed,
    RetryApprovalDelivery,
    ExpireApproval,
    StoreSnapshot,
    CreatePublicationStream,
    RotatePublicationStream,
    FreezePublication,
    CommitPublication,
    AcknowledgePublication,
}

#[derive(Clone, Eq, Hash, PartialEq)]
pub enum IdempotencyOwner {
    Local {
        machine_trust_domain: [u8; 32],
        uid: u32,
        client_installation_id: [u8; 16],
    },
    Remote {
        machine_trust_domain: [u8; 32],
        device_route: [u8; 16],
        device_sign_fingerprint: [u8; 32],
    },
}

impl std::fmt::Debug for IdempotencyOwner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("IdempotencyOwner([REDACTED])")
    }
}

/// Common catalog 中唯一允许持久化的中立 conversation 描述。
///
/// vendor resume reference、ThreadId/SessionId 与任意扩展字段都不能进入此类型；
/// store 只接受该类型并以固定字段顺序的 canonical JSON 加密落盘。
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConversationDescriptor {
    pub agent_kind: AgentKind,
    pub title: Option<String>,
    pub cwd: PathBuf,
}

impl std::fmt::Debug for ConversationDescriptor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConversationDescriptor")
            .field("agent_kind", &self.agent_kind)
            .field("title", &self.title.as_ref().map(|_| "[REDACTED]"))
            .field("cwd", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone)]
pub struct NewConversation {
    pub conversation_id: RuntimeId,
    pub adapter_state_key: RuntimeId,
    pub descriptor: ConversationDescriptor,
}

#[derive(Clone, Eq, PartialEq)]
pub struct ConversationRecord {
    pub conversation_id: RuntimeId,
    pub adapter_state_key: RuntimeId,
    pub catalog_revision: u64,
    pub command_high_water: Option<u64>,
    pub event_high_water: Option<u64>,
    pub accepted_command_count: u32,
    pub lifecycle: ConversationLifecycle,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
    pub descriptor: ConversationDescriptor,
}

impl std::fmt::Debug for ConversationRecord {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConversationRecord")
            .field("conversation_id", &self.conversation_id)
            .field("catalog_revision", &self.catalog_revision)
            .field("command_high_water", &self.command_high_water)
            .field("event_high_water", &self.event_high_water)
            .field("accepted_command_count", &self.accepted_command_count)
            .field("lifecycle", &self.lifecycle)
            .field("descriptor", &self.descriptor)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CreateConversationOutcome {
    Created { conversation: ConversationRecord },
    Replayed { conversation: ConversationRecord },
}

/// 把一个 conversation 持久化为 fail-closed recovery 状态的精确绑定。
///
/// Accepted 绑定只允许在副作用尚未开始时阻断队列；Started 绑定必须携带 exact
/// boot/nonce/fence readback，避免陈旧 actor 或 recovery plan 阻断另一个 execution。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryFenceBinding {
    pub command_id: RuntimeId,
    pub daemon_boot_id: RuntimeId,
    pub execution_nonce: Vec<u8>,
    pub process_group_id: i64,
    pub leader_pid: i64,
    pub leader_start_time: u64,
    pub release_authorized_at_ms: Option<u64>,
    pub payload_bytes: usize,
    pub payload_sha256: [u8; 32],
}

impl RecoveryFenceBinding {
    #[must_use]
    pub fn from_record(record: &ExecutionFenceRecord) -> Self {
        Self {
            command_id: record.command_id,
            daemon_boot_id: record.daemon_boot_id,
            execution_nonce: record.execution_nonce.clone(),
            process_group_id: record.process_group_id,
            leader_pid: record.leader_pid,
            leader_start_time: record.leader_start_time,
            release_authorized_at_ms: record.release_authorized_at_ms,
            payload_bytes: record.payload.len(),
            payload_sha256: Sha256::digest(&record.payload).into(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecoveryBlockedCommandBinding {
    Accepted {
        command_id: RuntimeId,
    },
    Started {
        command_id: RuntimeId,
        turn_id: RuntimeId,
        daemon_boot_id: RuntimeId,
        execution_nonce: Vec<u8>,
        fence: Option<Box<RecoveryFenceBinding>>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MarkConversationRecoveryBlocked {
    pub conversation_id: RuntimeId,
    pub expected_command: Option<RecoveryBlockedCommandBinding>,
}

#[derive(Clone)]
pub struct AcceptCommand {
    pub conversation_id: RuntimeId,
    pub owner: IdempotencyOwner,
    pub idempotency_key: String,
    pub expected_configuration_revision: u64,
    pub payload: Vec<u8>,
}

#[derive(Clone, Eq, PartialEq)]
pub struct CommandRecord {
    pub conversation_id: RuntimeId,
    pub command_id: RuntimeId,
    pub command_seq: u64,
    pub configuration_revision: u64,
    pub owner: IdempotencyOwner,
    pub state: CommandState,
    pub accepted_at_ms: u64,
    pub expires_at_ms: u64,
    pub retain_until_ms: u64,
    pub started_at_ms: Option<u64>,
    pub terminal_at_ms: Option<u64>,
    pub turn_id: Option<RuntimeId>,
    pub started_event_id: Option<RuntimeId>,
    pub terminal_event_id: Option<RuntimeId>,
    pub payload: Vec<u8>,
    pub result: Option<Vec<u8>>,
}

impl std::fmt::Debug for CommandRecord {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CommandRecord")
            .field("conversation_id", &self.conversation_id)
            .field("command_id", &self.command_id)
            .field("command_seq", &self.command_seq)
            .field("configuration_revision", &self.configuration_revision)
            .field("state", &self.state)
            .field("turn_id", &self.turn_id)
            .field("payload_bytes", &self.payload.len())
            .field(
                "result_bytes",
                &self.result.as_ref().map(std::vec::Vec::len),
            )
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AcceptOutcome {
    Accepted {
        command: CommandRecord,
        queue_position: u32,
    },
    Replayed {
        command: CommandRecord,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AcceptedTerminationReason {
    Canceled,
    RevokedBeforeStart,
}

impl AcceptedTerminationReason {
    #[must_use]
    pub const fn command_state(self) -> CommandState {
        match self {
            Self::Canceled => CommandState::Canceled,
            Self::RevokedBeforeStart => CommandState::RevokedBeforeStart,
        }
    }
}

#[derive(Clone)]
pub struct TerminateAcceptedCommand {
    pub conversation_id: RuntimeId,
    pub command_id: RuntimeId,
    pub expected_owner: IdempotencyOwner,
    pub reason: AcceptedTerminationReason,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TerminateAcceptedOutcome {
    Transitioned {
        command: CommandRecord,
        event: EventRecord,
    },
    Replayed {
        command: CommandRecord,
        event: EventRecord,
    },
    AlreadyStarted {
        command: CommandRecord,
    },
}

/// 已经 Started、但 gate release 尚未授权时的安全终止原因。
///
/// 只有 execution control 已确认整个 process group fenced 后才能调用对应 store
/// transaction；普通成功/失败 completion 仍走 `CompleteCommand`。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StartedBeforeReleaseTermination {
    Canceled,
    Interrupted,
}

impl StartedBeforeReleaseTermination {
    #[must_use]
    pub const fn terminal_state(self) -> TerminalState {
        match self {
            Self::Canceled => TerminalState::Canceled,
            Self::Interrupted => TerminalState::Interrupted,
        }
    }
}

#[derive(Clone)]
pub struct TerminateStartedBeforeRelease {
    pub conversation_id: RuntimeId,
    pub command_id: RuntimeId,
    pub turn_id: RuntimeId,
    pub daemon_boot_id: RuntimeId,
    pub execution_nonce: Vec<u8>,
    pub reason: StartedBeforeReleaseTermination,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TerminateStartedBeforeReleaseOutcome {
    Transitioned {
        command: CommandRecord,
        event: EventRecord,
    },
    Replayed {
        command: CommandRecord,
        event: EventRecord,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommandReceiptSelector {
    Command {
        conversation_id: RuntimeId,
        command_id: RuntimeId,
    },
    Idempotency {
        conversation_id: RuntimeId,
        idempotency_key: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueryCommandReceipt {
    pub expected_owner: IdempotencyOwner,
    pub selector: CommandReceiptSelector,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommandReceiptRecord {
    pub command_id: RuntimeId,
    pub configuration_revision: u64,
    pub state: CommandState,
    pub turn_id: Option<RuntimeId>,
}

#[derive(Clone)]
pub struct StartCommand {
    pub conversation_id: RuntimeId,
    pub command_id: RuntimeId,
    pub daemon_boot_id: RuntimeId,
    pub execution_nonce: Vec<u8>,
}

/// Store 已认证并冻结到 command pin 的 execution configuration。
///
/// 非零 revision 总是携带 exact configuration；revision zero 只表示迁移前
/// command，并且只能由 startup recovery 专用入口产生。该类型不进入 wire。
#[derive(Clone, Eq, PartialEq)]
pub enum CommandExecutionConfiguration {
    Pinned {
        configuration_revision: u64,
        configuration: ConversationConfiguration,
    },
    LegacyRevisionZero {
        agent_kind: AgentKind,
    },
}

impl CommandExecutionConfiguration {
    #[must_use]
    pub const fn configuration_revision(&self) -> u64 {
        match self {
            Self::Pinned {
                configuration_revision,
                ..
            } => *configuration_revision,
            Self::LegacyRevisionZero { .. } => 0,
        }
    }

    #[must_use]
    pub const fn configuration(&self) -> Option<&ConversationConfiguration> {
        match self {
            Self::Pinned { configuration, .. } => Some(configuration),
            Self::LegacyRevisionZero { .. } => None,
        }
    }

    #[must_use]
    pub const fn agent_kind(&self) -> AgentKind {
        match self {
            Self::Pinned { configuration, .. } => configuration.agent_kind(),
            Self::LegacyRevisionZero { agent_kind } => *agent_kind,
        }
    }
}

impl std::fmt::Debug for CommandExecutionConfiguration {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pinned {
                configuration_revision,
                configuration,
            } => formatter
                .debug_struct("PinnedExecutionConfiguration")
                .field("configuration_revision", configuration_revision)
                .field("agent_kind", &configuration.agent_kind())
                .finish_non_exhaustive(),
            Self::LegacyRevisionZero { agent_kind } => formatter
                .debug_struct("LegacyRevisionZeroExecutionConfiguration")
                .field("agent_kind", agent_kind)
                .finish(),
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ExecutionIntentRecord {
    pub command_id: RuntimeId,
    pub turn_id: RuntimeId,
    pub started_event_id: RuntimeId,
    pub daemon_boot_id: RuntimeId,
    pub execution_nonce: Vec<u8>,
    pub created_at_ms: u64,
    pub payload: Vec<u8>,
}

impl std::fmt::Debug for ExecutionIntentRecord {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExecutionIntentRecord")
            .field("command_id", &self.command_id)
            .field("turn_id", &self.turn_id)
            .field("started_event_id", &self.started_event_id)
            .field("daemon_boot_id", &self.daemon_boot_id)
            .field("execution_nonce", &"[REDACTED]")
            .field("payload_bytes", &self.payload.len())
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct EventRecord {
    pub conversation_id: RuntimeId,
    pub event_id: RuntimeId,
    pub event_seq: u64,
    pub command_id: Option<RuntimeId>,
    pub created_at_ms: u64,
    pub payload: Vec<u8>,
}

impl std::fmt::Debug for EventRecord {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EventRecord")
            .field("conversation_id", &self.conversation_id)
            .field("event_id", &self.event_id)
            .field("event_seq", &self.event_seq)
            .field("command_id", &self.command_id)
            .field("payload_bytes", &self.payload.len())
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StartOutcome {
    Started {
        command: CommandRecord,
        execution_configuration: CommandExecutionConfiguration,
        intent: ExecutionIntentRecord,
        event: EventRecord,
    },
    Replayed {
        command: CommandRecord,
        execution_configuration: CommandExecutionConfiguration,
        intent: ExecutionIntentRecord,
        event: EventRecord,
    },
}

#[derive(Clone)]
pub struct ExecutionFence {
    pub command_id: RuntimeId,
    pub daemon_boot_id: RuntimeId,
    pub execution_nonce: Vec<u8>,
    pub process_group_id: i64,
    pub leader_pid: i64,
    pub leader_start_time: u64,
    pub payload: Vec<u8>,
}

#[derive(Clone)]
pub struct AuthorizeExecutionRelease {
    pub command_id: RuntimeId,
    pub daemon_boot_id: RuntimeId,
    pub execution_nonce: Vec<u8>,
}

#[derive(Clone, Eq, PartialEq)]
pub struct ExecutionFenceRecord {
    pub command_id: RuntimeId,
    pub daemon_boot_id: RuntimeId,
    pub execution_nonce: Vec<u8>,
    pub process_group_id: i64,
    pub leader_pid: i64,
    pub leader_start_time: u64,
    pub release_authorized_at_ms: Option<u64>,
    pub payload: Vec<u8>,
}

impl std::fmt::Debug for ExecutionFenceRecord {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExecutionFenceRecord")
            .field("command_id", &self.command_id)
            .field("daemon_boot_id", &self.daemon_boot_id)
            .field("execution_nonce", &"[REDACTED]")
            .field("process_group_id", &self.process_group_id)
            .field("leader_pid", &self.leader_pid)
            .field("leader_start_time", &self.leader_start_time)
            .field("release_authorized_at_ms", &self.release_authorized_at_ms)
            .field("payload_bytes", &self.payload.len())
            .finish()
    }
}

/// 可写入 Failed terminal 的唯一脱敏 failure。
///
/// 该零载荷 allowlist 不接受 adapter 原始 message/code/diagnostic reference；新增失败语义必须先在
/// Runtime failure registry 与诊断文档中登记，再显式扩展这里。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SanitizedTerminalFailure {
    kind: SanitizedTerminalFailureKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SanitizedTerminalFailureKind {
    ExecutionFailed,
}

impl SanitizedTerminalFailure {
    #[must_use]
    pub const fn execution_failed() -> Self {
        Self {
            kind: SanitizedTerminalFailureKind::ExecutionFailed,
        }
    }

    #[must_use]
    pub(crate) const fn code(self) -> &'static str {
        match self.kind {
            SanitizedTerminalFailureKind::ExecutionFailed => {
                agentdeck_protocol::runtime::failure::DAEMON_RUNTIME_EXECUTION_FAILED
            }
        }
    }

    #[must_use]
    pub(crate) const fn message(self) -> &'static str {
        match self.kind {
            SanitizedTerminalFailureKind::ExecutionFailed => "agent execution failed",
        }
    }
}

/// command terminal 的唯一 typed 输入；wire event 与 sealed result 由 Store 构造。
#[derive(Clone)]
pub struct CommandTerminal {
    kind: CommandTerminalKind,
}

#[derive(Clone)]
enum CommandTerminalKind {
    Completed(TurnSummary),
    Failed(SanitizedTerminalFailure),
    Interrupted,
    Canceled,
}

impl CommandTerminal {
    #[must_use]
    pub const fn completed(summary: TurnSummary) -> Self {
        Self {
            kind: CommandTerminalKind::Completed(summary),
        }
    }

    #[must_use]
    pub const fn failed(failure: SanitizedTerminalFailure) -> Self {
        Self {
            kind: CommandTerminalKind::Failed(failure),
        }
    }

    #[must_use]
    pub const fn interrupted() -> Self {
        Self {
            kind: CommandTerminalKind::Interrupted,
        }
    }

    #[must_use]
    pub const fn canceled() -> Self {
        Self {
            kind: CommandTerminalKind::Canceled,
        }
    }

    #[must_use]
    pub const fn terminal_state(&self) -> TerminalState {
        match self.kind {
            CommandTerminalKind::Completed(_) => TerminalState::Completed,
            CommandTerminalKind::Failed(_) => TerminalState::Failed,
            CommandTerminalKind::Interrupted => TerminalState::Interrupted,
            CommandTerminalKind::Canceled => TerminalState::Canceled,
        }
    }

    #[must_use]
    pub(crate) const fn completed_summary(&self) -> Option<&TurnSummary> {
        match &self.kind {
            CommandTerminalKind::Completed(summary) => Some(summary),
            _ => None,
        }
    }

    #[must_use]
    pub(crate) const fn failure(&self) -> Option<SanitizedTerminalFailure> {
        match self.kind {
            CommandTerminalKind::Failed(failure) => Some(failure),
            _ => None,
        }
    }
}

impl std::fmt::Debug for CommandTerminal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CommandTerminal")
            .field("state", &self.terminal_state())
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
pub struct CompleteCommand {
    pub conversation_id: RuntimeId,
    pub command_id: RuntimeId,
    pub turn_id: RuntimeId,
    pub terminal: CommandTerminal,
}

/// startup recovery 专用 terminal mutation；除普通 command/turn CAS 外，还要求
/// readback 的 Started intent 与完整 fence/release 记录逐字段匹配第一遍计划。
#[derive(Clone)]
pub struct RecoverStartedCommand {
    pub completion: CompleteCommand,
    pub expected_started: RecoveryBlockedCommandBinding,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CompleteOutcome {
    Completed {
        command: CommandRecord,
        event: EventRecord,
    },
    Replayed {
        command: CommandRecord,
        event: EventRecord,
    },
}

#[allow(dead_code)] // P3.5 store/actor 接线在本 task 后续步骤完成。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ApprovalState {
    Pending,
    Claimed,
    Applying,
    Applied,
    DeliveryFailed,
    Expired,
}

#[allow(dead_code)] // P3.5 store/actor 接线在本 task 后续步骤完成。
impl ApprovalState {
    #[must_use]
    pub(crate) const fn is_active(self) -> bool {
        matches!(
            self,
            Self::Pending | Self::Claimed | Self::Applying | Self::DeliveryFailed
        )
    }

    #[must_use]
    pub(crate) const fn is_terminal(self) -> bool {
        matches!(self, Self::Applied | Self::Expired)
    }
}

/// approval request 与注册时 policy 的单一 canonical sealed payload。
#[allow(dead_code)] // P3.5 store/actor 接线在本 task 后续步骤完成。
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ApprovalRequestEnvelope {
    pub(crate) request: ActionRequest,
    pub(crate) policy: ApprovalPolicySnapshot,
}

impl std::fmt::Debug for ApprovalRequestEnvelope {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ApprovalRequestEnvelope")
            .field("request", &"[REDACTED]")
            .field("policy", &self.policy)
            .finish()
    }
}

#[allow(dead_code)] // P3.5 store/actor 接线在本 task 后续步骤完成。
#[derive(Clone)]
pub(crate) struct ApprovalRecord {
    pub(crate) approval_id: RuntimeId,
    pub(crate) conversation_id: RuntimeId,
    pub(crate) command_id: RuntimeId,
    pub(crate) turn_id: RuntimeId,
    pub(crate) state: ApprovalState,
    pub(crate) request: ActionRequest,
    pub(crate) policy: ApprovalPolicySnapshot,
    pub(crate) decision: Option<ActionDecision>,
    pub(crate) requested_at_ms: u64,
    pub(crate) deadline_at_ms: u64,
    pub(crate) claimed_at_ms: Option<u64>,
    pub(crate) state_changed_at_ms: u64,
    pub(crate) delivery_round: u32,
    pub(crate) attempts_in_round: u8,
    pub(crate) round_started_at_ms: Option<u64>,
    pub(crate) last_attempt_at_ms: Option<u64>,
    pub(crate) state_version: u64,
    pub(crate) last_event_id: RuntimeId,
    pub(crate) status_detail: Option<Vec<u8>>,
}

impl std::fmt::Debug for ApprovalRecord {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ApprovalRecord")
            .field("approval_id", &self.approval_id)
            .field("conversation_id", &self.conversation_id)
            .field("command_id", &self.command_id)
            .field("turn_id", &self.turn_id)
            .field("state", &self.state)
            .field("request", &"[REDACTED]")
            .field("decision", &self.decision.as_ref().map(|_| "[REDACTED]"))
            .field("requested_at_ms", &self.requested_at_ms)
            .field("deadline_at_ms", &self.deadline_at_ms)
            .field("delivery_round", &self.delivery_round)
            .field("attempts_in_round", &self.attempts_in_round)
            .field("state_version", &self.state_version)
            .field("last_event_id", &self.last_event_id)
            .field(
                "status_detail_bytes",
                &self.status_detail.as_ref().map(std::vec::Vec::len),
            )
            .finish()
    }
}

#[allow(dead_code)] // P3.5 store/actor 接线在本 task 后续步骤完成。
pub(crate) struct RegisterApproval {
    pub(crate) conversation_id: RuntimeId,
    pub(crate) command_id: RuntimeId,
    pub(crate) turn_id: RuntimeId,
    pub(crate) request: ActionRequest,
    pub(crate) policy: ApprovalPolicySnapshot,
}

#[allow(dead_code)] // P3.5 store/actor 接线在本 task 后续步骤完成。
#[derive(Clone, Debug)]
pub(crate) enum RegisterApprovalOutcome {
    Registered {
        approval: ApprovalRecord,
        event: EventRecord,
    },
    Replayed {
        approval: ApprovalRecord,
        event: EventRecord,
    },
}

#[allow(dead_code)] // P3.5 store/actor 接线在本 task 后续步骤完成。
pub(crate) struct ClaimApproval {
    pub(crate) conversation_id: RuntimeId,
    pub(crate) turn_id: RuntimeId,
    pub(crate) approval_id: RuntimeId,
    pub(crate) decision: ActionDecision,
    pub(crate) claimant_binding: ApprovalClaimantBinding,
}

#[allow(dead_code)] // P3.5 store/actor 接线在本 task 后续步骤完成。
pub(crate) struct BeginApprovalAttempt {
    pub(crate) approval_id: RuntimeId,
    pub(crate) delivery_round: u32,
    pub(crate) expected_attempts_in_round: u8,
}

/// daemon 私有的 delivery permit 结果。
///
/// `Permitted` 始终表示调用方必须消费一次 vendor delivery permit；
/// `replayed=true` 表示该 permit 来自 begin commit-unknown 的 exact retry，调用方尚未
/// 执行 vendor side effect，仍必须执行一次。single-flight actor 保证 permit 不会被并发消费。
#[allow(dead_code)] // P3.5 actor 接线在本 task 后续步骤完成。
#[derive(Clone, Debug)]
pub(crate) enum BeginApprovalAttemptOutcome {
    Permitted {
        approval: ApprovalRecord,
        event: Option<EventRecord>,
        replayed: bool,
    },
    AlreadyHandled {
        approval: ApprovalRecord,
    },
    ExpiredOrStale {
        approval: ApprovalRecord,
    },
}

#[allow(dead_code)] // P3.5 store/actor 接线在本 task 后续步骤完成。
pub(crate) struct MarkApprovalApplied {
    pub(crate) approval_id: RuntimeId,
    pub(crate) delivery_round: u32,
    pub(crate) attempt: u8,
}

#[allow(dead_code)] // P3.5 store/actor 接线在本 task 后续步骤完成。
pub(crate) struct MarkApprovalDeliveryFailed {
    pub(crate) approval_id: RuntimeId,
    pub(crate) delivery_round: u32,
    pub(crate) attempt: u8,
    pub(crate) status_detail: Vec<u8>,
}

#[allow(dead_code)] // P3.5 store/actor 接线在本 task 后续步骤完成。
pub(crate) struct RetryApprovalDelivery {
    pub(crate) conversation_id: RuntimeId,
    pub(crate) approval_id: RuntimeId,
}

#[allow(dead_code)] // P3.5 store/actor 接线在本 task 后续步骤完成。
pub(crate) struct ExpireApproval {
    pub(crate) conversation_id: RuntimeId,
    pub(crate) approval_id: RuntimeId,
}

#[allow(dead_code)] // P3.5 store/actor 接线在本 task 后续步骤完成。
#[derive(Clone, Debug)]
pub(crate) enum ApprovalMutationOutcome {
    Transitioned {
        approval: ApprovalRecord,
        event: EventRecord,
    },
    Replayed {
        approval: ApprovalRecord,
        event: Option<EventRecord>,
    },
    AlreadyHandled {
        approval: ApprovalRecord,
    },
    ExpiredOrStale {
        approval: ApprovalRecord,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StartedRecoveryRecord {
    pub command: CommandRecord,
    pub intent: ExecutionIntentRecord,
    pub event: EventRecord,
    pub fence: Option<ExecutionFenceRecord>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConversationRecoveryRecord {
    pub conversation: ConversationRecord,
    pub accepted: Vec<CommandRecord>,
    pub started: Option<StartedRecoveryRecord>,
}

/// 仅由 store 签发、供同一进程内 RuntimeCore 逐页回放的 opaque cursor。
///
/// 字段不公开，调用方只能原样重试或使用上一页返回的 next cursor；它不是 wire token。
#[derive(Clone, Eq, PartialEq)]
pub struct RecoveryCursor {
    pub(crate) scan_id: [u8; 16],
    pub(crate) after_catalog_revision: Option<u64>,
    pub(crate) after_conversation_id: Option<RuntimeId>,
}

impl std::fmt::Debug for RecoveryCursor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RecoveryCursor")
            .field("scan_id", &"[REDACTED]")
            .field("after_catalog_revision", &self.after_catalog_revision)
            .field("after_conversation_id", &self.after_conversation_id)
            .finish()
    }
}

/// 只有终页才会签发；显式 finish 之前 store 保持 Recovering 并拒绝所有 mutation。
#[derive(Clone, Eq, PartialEq)]
pub struct RecoveryCompletion {
    pub(crate) scan_id: [u8; 16],
    pub(crate) final_after_catalog_revision: Option<u64>,
    pub(crate) final_after_conversation_id: Option<RuntimeId>,
}

impl std::fmt::Debug for RecoveryCompletion {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RecoveryCompletion")
            .field("scan_id", &"[REDACTED]")
            .field(
                "final_after_catalog_revision",
                &self.final_after_catalog_revision,
            )
            .field(
                "final_after_conversation_id",
                &self.final_after_conversation_id,
            )
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryPage {
    pub conversation: Option<ConversationRecoveryRecord>,
    pub next_cursor: Option<RecoveryCursor>,
    pub completion: Option<RecoveryCompletion>,
}

/// 测试/诊断聚合类型；生产恢复 API 只返回 `RecoveryPage`，RuntimeCore 禁止全库 collect。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryState {
    pub conversations: Vec<ConversationRecord>,
    pub accepted: Vec<CommandRecord>,
    pub started: Vec<StartedRecoveryRecord>,
}

#[derive(Debug, Error)]
pub enum RuntimeStoreError {
    #[error("runtime store path must be absolute")]
    PathNotAbsolute,
    #[error("runtime store symbolic link is forbidden: {path}")]
    SymlinkRejected { path: PathBuf },
    #[error("runtime store path is not a regular file: {path}")]
    NotRegularFile { path: PathBuf },
    #[error("runtime store file has unsafe ownership, mode, or link count: {path}")]
    UnsafeFile { path: PathBuf },
    #[error("runtime schema version {found} is newer than supported version {supported}")]
    SchemaTooNew { found: u32, supported: u32 },
    #[error("runtime schema is unknown, incomplete, or corrupt")]
    UnknownOrCorruptSchema,
    #[error("runtime schema changed during read-only inspection")]
    SchemaInspectionRaced,
    #[error("runtime SQLite pragma {name} read back {actual}, expected {expected}")]
    PragmaMismatch {
        name: &'static str,
        expected: String,
        actual: String,
    },
    #[error("runtime store is already open in this process")]
    StoreAlreadyOpen,
    #[error("runtime enrollment rescue receipt conflicts with the existing root fingerprint")]
    RescueReceiptConflict,
    #[error("runtime machine identity state is missing")]
    MachineIdentityMissing,
    #[error("runtime machine identity binding conflicts with the authenticated singleton")]
    MachineIdentityConflict,
    #[error("runtime machine enrollment input conflicts with the authenticated lifecycle")]
    MachineRemoteConflict,
    #[error("runtime store {lane:?} lane is full")]
    WorkerBusy { lane: RuntimeStoreLane },
    #[error("runtime store worker stopped before replying")]
    WorkerStopped,
    #[error("runtime store watch incarnation entropy is unavailable")]
    WatchIncarnationEntropyUnavailable,
    #[error("runtime store worker did not shut down before its hard deadline")]
    ShutdownTimedOut,
    #[error("runtime store shutdown is already in progress")]
    ShutdownInProgress,
    #[error("runtime store is latched in safety-only mode after a capacity violation")]
    SafetyOnly,
    #[error(
        "runtime filesystem has {available_bytes} bytes available but requires {required_available_bytes} bytes"
    )]
    DiskLow {
        available_bytes: u64,
        required_available_bytes: u64,
    },
    #[error(
        "runtime database footprint would be {projected_footprint_bytes} bytes, above the {hard_limit_bytes} byte limit"
    )]
    StoreFull {
        projected_footprint_bytes: u64,
        hard_limit_bytes: u64,
    },
    #[error(
        "runtime database would require page {projected_page_count}, above max_page_count {max_page_count}"
    )]
    PageLimit {
        projected_page_count: u64,
        max_page_count: u64,
    },
    #[error(
        "runtime WAL checkpoint made only {checkpointed_frames} of {log_frames} frames reclaimable"
    )]
    CheckpointBlocked {
        log_frames: i64,
        checkpointed_frames: i64,
    },
    #[error("runtime capacity arithmetic overflow while calculating {field}")]
    CapacityArithmeticOverflow { field: &'static str },
    #[error("runtime SQLite page budget is invalid: {reason}")]
    InvalidCapacityBudget { reason: &'static str },
    #[error("runtime capacity observation failed: {0}")]
    CapacityProbe(#[from] RuntimeCapacityProbeError),
    #[error("runtime {expected} id has the wrong kind {actual}")]
    IdKindMismatch {
        expected: RuntimeIdKind,
        actual: RuntimeIdKind,
    },
    #[error("runtime conversation was not found")]
    ConversationNotFound,
    #[error("runtime conversation stable identity conflicts with an existing record")]
    ConversationConflict,
    #[error("runtime conversation catalog reached its hard limit")]
    ConversationLimit,
    #[error("runtime conversation configuration agent kind does not match its descriptor")]
    ConfigurationAgentMismatch,
    #[error("runtime conversation must be configured before accepting a command")]
    ConfigurationRequired,
    #[error(
        "runtime command expected a different configuration revision than current revision {current_configuration_revision}"
    )]
    ConfigurationConflict { current_configuration_revision: u64 },
    #[error("runtime configuration journal is full for {scope:?}")]
    ConfigurationLimit { scope: ConfigurationLimitScope },
    #[error("runtime command configuration pin journal reached its hard limit")]
    CommandConfigurationPinLimit,
    #[error("runtime metadata mutation ledger is full for {scope:?}")]
    MetadataMutationLimit { scope: MetadataMutationLimitScope },
    #[error("runtime native metadata mutation is still pending authenticated readback")]
    MetadataMutationPending,
    #[error("runtime native metadata mutation execution belongs to a later phase")]
    MetadataMutationUnsupported,
    #[error("runtime native projection store is full for {scope:?}")]
    NativeProjectionLimit { scope: NativeProjectionLimitScope },
    #[error("runtime admin command ledger is full for {scope:?}")]
    AdminCommandLimit { scope: AdminCommandLimitScope },
    #[error("runtime adapter state reference conflicts with the existing binding")]
    AdapterStateConflict,
    #[error("runtime adapter state key belongs to the other private namespace")]
    AdapterStateNamespaceMismatch,
    #[error("runtime command was not found")]
    CommandNotFound,
    #[error("runtime conversation does not support durable command admission")]
    CommandAdmissionUnsupported,
    #[error("runtime command idempotency key was reused with a different payload")]
    IdempotencyConflict,
    #[error("runtime command belongs to a different idempotency owner")]
    CommandOwnerMismatch,
    #[error("runtime command queue is full for {scope:?}")]
    QueueFull { scope: QueueScope },
    #[error("runtime payload exceeds the operation-specific limit")]
    PayloadTooLarge,
    #[error(
        "runtime recovery page would retain {projected_bytes} bytes, above the {limit_bytes} byte limit"
    )]
    RecoveryPageTooLarge {
        projected_bytes: u64,
        limit_bytes: u64,
    },
    #[error("runtime recovery scan is already in progress and blocks mutations")]
    RecoveryInProgress,
    #[error("runtime recovery scan is not active")]
    RecoveryNotActive,
    #[error("runtime recovery cursor or completion token is not the exact expected value")]
    InvalidRecoveryCursor,
    #[error("runtime recovery scan has not reached and accounted for its terminal page")]
    RecoveryNotReady,
    #[error("runtime requested backfill begins before the retained logical suffix")]
    BackfillNeedSnapshot,
    #[error("runtime requested backfill cursor is ahead of the target high-water")]
    BackfillCursorAhead,
    #[error("runtime backfill pin is missing, expired, or does not match the requested range")]
    InvalidBackfillPin,
    #[error("runtime publication stream requires a fresh snapshot before more rows can be frozen")]
    PublicationNeedsSnapshot,
    #[error("runtime publication generation, sequence, range, or blob hash does not match")]
    PublicationMismatch,
    #[error("runtime publication sender counter is exhausted and requires key/scope rotation")]
    PublicationCounterExhausted,
    #[error("runtime publication was already durably acknowledged and must not be resent")]
    PublicationAlreadyAcknowledged,
    #[error("runtime timestamp or derived deadline is outside SQLite i64 range")]
    TimeOutOfRange,
    #[error(
        "runtime clock regressed from persisted {persisted_ms} ms to observed {observed_ms} ms"
    )]
    ClockRegressed { persisted_ms: u64, observed_ms: u64 },
    #[error("runtime clock failed: {0}")]
    Clock(#[from] RuntimeClockError),
    #[error("runtime command state transition is invalid")]
    InvalidStateTransition,
    #[error("runtime command expired before it could start")]
    CommandExpired,
    #[error("runtime command is not the conversation queue head")]
    NotQueueHead,
    #[error("runtime start retry conflicts with the persisted execution intent")]
    StartConflict,
    #[error("runtime execution fence retry conflicts with the persisted fence")]
    FenceConflict,
    #[error("runtime execution fence is missing")]
    ExecutionFenceMissing,
    #[error("runtime execution release has not been durably authorized")]
    ExecutionReleaseMissing,
    #[error("runtime terminal retry conflicts with the persisted terminal result")]
    TerminalConflict,
    #[error("runtime execution event retry conflicts with the persisted event")]
    ExecutionEventConflict,
    #[error("runtime {operation:?} commit outcome is unknown; retry the identical operation")]
    CommitOutcomeUnknown { operation: RuntimeCommitOperation },
    #[error("runtime stable id generation failed: {0}")]
    IdGeneration(#[from] RuntimeIdError),
    #[error("runtime sequence allocation failed: {0}")]
    Sequence(#[from] SequenceError),
    #[error("runtime store configuration is invalid: {0}")]
    InvalidConfig(&'static str),
    #[error("runtime store I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("runtime store SQLite operation failed: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("runtime store encryption failed: {0}")]
    Cipher(#[from] CipherError),
}

impl RuntimeStoreError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::PathNotAbsolute
            | Self::SymlinkRejected { .. }
            | Self::NotRegularFile { .. }
            | Self::UnsafeFile { .. }
            | Self::InvalidConfig(_) => "daemon.runtime.store_invalid",
            Self::SchemaTooNew { .. }
            | Self::UnknownOrCorruptSchema
            | Self::SchemaInspectionRaced => "daemon.runtime.schema_incompatible",
            Self::PragmaMismatch { .. }
            | Self::StoreAlreadyOpen
            | Self::RescueReceiptConflict
            | Self::WorkerStopped
            | Self::WatchIncarnationEntropyUnavailable
            | Self::ShutdownTimedOut
            | Self::ShutdownInProgress
            | Self::CommitOutcomeUnknown { .. }
            | Self::CheckpointBlocked { .. }
            | Self::CapacityArithmeticOverflow { .. }
            | Self::InvalidCapacityBudget { .. }
            | Self::CapacityProbe(_)
            | Self::Clock(_)
            | Self::Io(_)
            | Self::Sqlite(_)
            | Self::Cipher(CipherError::ReadCapabilityClosed)
            | Self::Cipher(CipherError::ReadCapabilityPoisoned) => {
                "daemon.runtime.store_unavailable"
            }
            Self::SafetyOnly => "daemon.runtime.safety_only",
            Self::DiskLow { .. } => "daemon.runtime.disk_low",
            Self::StoreFull { .. } | Self::PageLimit { .. } => "daemon.runtime.store_full",
            Self::WorkerBusy { .. } => "daemon.runtime.store_busy",
            Self::RecoveryInProgress => "daemon.runtime.recovering",
            Self::Cipher(_) => "daemon.runtime.crypto_failed",
            Self::IdKindMismatch { .. }
            | Self::MachineIdentityMissing
            | Self::MachineIdentityConflict
            | Self::MachineRemoteConflict
            | Self::ConversationNotFound
            | Self::ConversationConflict
            | Self::ConfigurationAgentMismatch
            | Self::AdapterStateConflict
            | Self::AdapterStateNamespaceMismatch
            | Self::CommandNotFound
            | Self::CommandOwnerMismatch
            | Self::TimeOutOfRange
            | Self::ClockRegressed { .. }
            | Self::InvalidStateTransition
            | Self::NotQueueHead
            | Self::StartConflict
            | Self::FenceConflict
            | Self::ExecutionFenceMissing
            | Self::ExecutionReleaseMissing
            | Self::TerminalConflict
            | Self::ExecutionEventConflict
            | Self::RecoveryNotActive
            | Self::InvalidRecoveryCursor
            | Self::RecoveryNotReady
            | Self::BackfillCursorAhead
            | Self::InvalidBackfillPin
            | Self::PublicationMismatch
            | Self::IdGeneration(_)
            | Self::Sequence(_) => "daemon.runtime.invalid_state",
            Self::ConversationLimit => "daemon.runtime.actor_unavailable",
            Self::ConfigurationLimit { .. }
            | Self::CommandConfigurationPinLimit
            | Self::MetadataMutationLimit { .. }
            | Self::NativeProjectionLimit { .. }
            | Self::AdminCommandLimit { .. } => "daemon.runtime.store_full",
            Self::ConfigurationRequired => DAEMON_CONVERSATION_CONFIGURATION_REQUIRED,
            Self::ConfigurationConflict { .. } => DAEMON_CONVERSATION_CONFIGURATION_CONFLICT,
            Self::MetadataMutationPending => DAEMON_CONVERSATION_METADATA_MUTATION_PENDING,
            Self::MetadataMutationUnsupported | Self::CommandAdmissionUnsupported => {
                DAEMON_RUNTIME_FEATURE_UNAVAILABLE
            }
            Self::IdempotencyConflict => "daemon.command.idempotency_conflict",
            Self::QueueFull { .. } => "daemon.command.queue_full",
            Self::PayloadTooLarge => "daemon.payload.item_too_large",
            Self::RecoveryPageTooLarge { .. } => "daemon.runtime.recovery_too_large",
            Self::BackfillNeedSnapshot | Self::PublicationNeedsSnapshot => {
                "daemon.runtime.snapshot_required"
            }
            Self::PublicationAlreadyAcknowledged => "daemon.runtime.publication_acknowledged",
            Self::PublicationCounterExhausted => "daemon.runtime.publication_counter_exhausted",
            Self::CommandExpired => "daemon.command.queue_expired",
        }
    }
}
