//! Runtime 持久化层的平台无关内部模型。
//!
//! 这些类型不进入 RuntimeEnvelope wire；P3.4 RuntimeCore 负责把内部精确状态/
//! failure 映射成客户端可见 receipt 与 `RuntimeFailure`。

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use agentdeck_protocol::{ActionDecision, ActionRequest, AgentKind};
use serde::{Deserialize, Serialize};
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
/// Durable catalog 与恢复时 actor fan-out 的共同硬上界。
pub const MAX_RUNTIME_CONVERSATIONS: u64 = 1_024;
pub const MAX_COMMAND_PAYLOAD_BYTES: usize = 256 * 1024;
pub const MAX_CONVERSATION_DESCRIPTOR_BYTES: usize = 1024 * 1024;
pub const MAX_ADAPTER_STATE_REFERENCE_BYTES: usize = 4 * 1024;
pub const MAX_IDEMPOTENCY_KEY_BYTES: usize = 1024;
pub const MAX_EXECUTION_INTENT_BYTES: usize = 1024 * 1024;
pub const MAX_RUNTIME_EVENT_BYTES: usize = 64 * 1024 * 1024;
/// Accepted 终止事件必须落在每条 Accepted 已预留的 64 KiB safety tail 内。
pub const MAX_ACCEPTED_TERMINATION_EVENT_BYTES: usize = 32 * 1024;
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
    StreamNotificationReadback,
    RecordEnrollmentReceiptBeforeCommit,
    RecordEnrollmentReceiptAfterCommit,
    CreateConversationBeforeCommit,
    CreateConversationAfterCommit,
    AcceptCommandBeforeCommit,
    AcceptCommandAfterCommit,
    StartCommandBeforeCommit,
    StartCommandAfterCommit,
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
pub enum RuntimeCommitOperation {
    MigrateSchema,
    RecordEnrollmentReceipt,
    CreateConversation,
    AcceptCommand,
    StartCommand,
    ExpireCommands,
    TerminateAcceptedCommand,
    TerminateStartedBeforeRelease,
    PersistFence,
    AuthorizeExecutionRelease,
    CompleteCommand,
    BindAdapterState,
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
            .field("adapter_state_key", &self.adapter_state_key)
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

#[derive(Clone)]
pub struct AcceptCommand {
    pub conversation_id: RuntimeId,
    pub owner: IdempotencyOwner,
    pub idempotency_key: String,
    pub payload: Vec<u8>,
}

#[derive(Clone, Eq, PartialEq)]
pub struct CommandRecord {
    pub conversation_id: RuntimeId,
    pub command_id: RuntimeId,
    pub command_seq: u64,
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
    pub event_payload: Vec<u8>,
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
    pub terminal_payload: Vec<u8>,
    pub event_payload: Vec<u8>,
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
    pub state: CommandState,
    pub turn_id: Option<RuntimeId>,
}

#[derive(Clone)]
pub struct StartCommand {
    pub conversation_id: RuntimeId,
    pub command_id: RuntimeId,
    pub daemon_boot_id: RuntimeId,
    pub execution_nonce: Vec<u8>,
    pub intent_payload: Vec<u8>,
    pub event_payload: Vec<u8>,
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
        intent: ExecutionIntentRecord,
        event: EventRecord,
    },
    Replayed {
        command: CommandRecord,
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

#[derive(Clone)]
pub struct CompleteCommand {
    pub conversation_id: RuntimeId,
    pub command_id: RuntimeId,
    pub turn_id: RuntimeId,
    pub terminal_state: TerminalState,
    pub terminal_payload: Vec<u8>,
    pub event_payload: Vec<u8>,
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
    #[error("runtime adapter state reference conflicts with the existing binding")]
    AdapterStateConflict,
    #[error("runtime adapter state key belongs to the other private namespace")]
    AdapterStateNamespaceMismatch,
    #[error("runtime command was not found")]
    CommandNotFound,
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
            | Self::ConversationNotFound
            | Self::ConversationConflict
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
            | Self::RecoveryNotActive
            | Self::InvalidRecoveryCursor
            | Self::RecoveryNotReady
            | Self::BackfillCursorAhead
            | Self::InvalidBackfillPin
            | Self::PublicationMismatch
            | Self::IdGeneration(_)
            | Self::Sequence(_) => "daemon.runtime.invalid_state",
            Self::ConversationLimit => "daemon.runtime.actor_unavailable",
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
