//! Runtime SQLite journal：单 worker、严格 schema 与行级加密。

pub(crate) mod admission;
mod approval;
mod catalog;
pub mod cipher;
mod command_event;
mod configuration;
mod execution_event;
pub mod identity;
mod journal;
mod persisted_event;
mod publication;
pub mod queue;
mod recovery;
pub(crate) mod retention;
mod schema;
pub(crate) mod sequence;
mod snapshot;
pub(crate) use snapshot::decode_catalog_baseline;
mod sqlite;
mod stream;
mod worker;

use crate::runtime::events::SnapshotBuildPinCleanup;

pub use crate::runtime::model::{
    AcceptCommand, AcceptOutcome, AcceptedTerminationReason, AuthorizeExecutionRelease,
    CommandReceiptRecord, CommandReceiptSelector, CommandRecord, CommandState, CommandTerminal,
    CompleteCommand, CompleteOutcome, ConfigurationLimitScope, ConversationDescriptor,
    ConversationLifecycle, ConversationRecord, ConversationRecoveryRecord,
    CreateConversationOutcome, EventRecord, ExecutionFence, ExecutionFenceRecord,
    ExecutionIntentRecord, IdempotencyOwner, MAX_CONVERSATION_DESCRIPTOR_BYTES,
    MAX_RECOVERY_PAGE_RETAINED_BYTES, MAX_RUNTIME_CONVERSATIONS, MachineEnrollmentReceiptRecord,
    MarkConversationRecoveryBlocked, NewConversation, QueryCommandReceipt, QueueScope,
    RecoverStartedCommand, RecoveryBlockedCommandBinding, RecoveryCompletion, RecoveryCursor,
    RecoveryFenceBinding, RecoveryPage, RecoveryState, RuntimeClock, RuntimeClockError,
    RuntimeCommitOperation, RuntimeStoreConfig, RuntimeStoreError, RuntimeStoreFaultInjector,
    RuntimeStoreLane, RuntimeStoreOperation, RuntimeStoreSnapshot, SanitizedTerminalFailure,
    StartCommand, StartOutcome, StartedBeforeReleaseTermination, StartedRecoveryRecord,
    SystemRuntimeClock, TerminalState, TerminateAcceptedCommand, TerminateAcceptedOutcome,
    TerminateStartedBeforeRelease, TerminateStartedBeforeReleaseOutcome,
};
pub use configuration::{ConfigurationRecord, ConfigureConversation, ConfigureConversationOutcome};
pub use execution_event::{AppendExecutionEvent, AppendExecutionEventOutcome};
pub use identity::{RuntimeId, RuntimeIdKind, RuntimeIdSource};
pub use publication::{
    FreezePublicationRequest, FrozenPublication, PublicationAcknowledgement, PublicationBarrierCut,
    PublicationPayloadKind, PublicationScope, PublicationStreamRecord, PublicationStreamState,
    RotatePublicationStreamRequest,
};
pub use recovery::RuntimeRescueIndex;
pub use schema::{RUNTIME_CRYPTO_CONTEXT_VERSION, RUNTIME_SCHEMA_FAMILY, RUNTIME_SCHEMA_VERSION};
pub use snapshot::{ReadySnapshotReference, StoredConversationSnapshot};
pub(crate) use snapshot::{StoredCatalogSnapshot, catalog_materialization_peak_bound};
pub use stream::{
    RuntimeBackfillPageCompletion, RuntimeBackfillPin, RuntimeBackfillPlan, RuntimeBackfillTarget,
    RuntimeCatalogBackfillPage, RuntimeEventBackfillPage, RuntimeSnapshotBuildPin,
};
pub use worker::RuntimeStoreHandle;
pub(crate) use worker::{ClaudeCodeAdapterStateVault, CodexAdapterStateVault};

/// 已经通过 conversation row metadata MAC、descriptor AEAD open 与 canonical
/// re-encode 的 snapshot 上下文。该类型只在 daemon runtime 内流转，不进入 wire。
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AuthenticatedConversationSnapshotContext {
    pub(crate) conversation_id: RuntimeId,
    pub(crate) agent_kind: agentdeck_protocol::AgentKind,
    pub(crate) event_high_water: Option<u64>,
}

/// 已通过 SnapshotBuildInput exact binding 的唯一 production 写入能力。
/// 字段对 crate 外完全 opaque，且故意不实现 Clone。
pub struct PreparedConversationSnapshotWrite {
    pin: RuntimeSnapshotBuildPin,
    item_count: u64,
    canonical_payload: Vec<u8>,
    cleanup: SnapshotBuildPinCleanup,
}

impl std::fmt::Debug for PreparedConversationSnapshotWrite {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedConversationSnapshotWrite")
            .field("item_count", &self.item_count)
            .field("canonical_payload_bytes", &self.canonical_payload.len())
            .finish_non_exhaustive()
    }
}

impl PreparedConversationSnapshotWrite {
    pub(crate) fn new(
        pin: RuntimeSnapshotBuildPin,
        item_count: u64,
        canonical_payload: Vec<u8>,
        cleanup: SnapshotBuildPinCleanup,
    ) -> Self {
        Self {
            pin,
            item_count,
            canonical_payload,
            cleanup,
        }
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        RuntimeSnapshotBuildPin,
        u64,
        Vec<u8>,
        SnapshotBuildPinCleanup,
    ) {
        (
            self.pin,
            self.item_count,
            self.canonical_payload,
            self.cleanup,
        )
    }

    pub(crate) fn parts(&self) -> (&RuntimeSnapshotBuildPin, u64, &[u8]) {
        (&self.pin, self.item_count, &self.canonical_payload)
    }

    pub(crate) fn payload_capacity(&self) -> usize {
        self.canonical_payload.capacity()
    }
}

/// Snapshot store 失败时保留 exact opaque write，供调用方在 COMMIT outcome
/// unknown 后逐字节重放。reply channel 已丢失时无法证明 worker 是否仍持有该
/// write，此时 `into_retry_write()` 返回 `None`，调用方必须重新走 barrier。
pub struct StoreConversationSnapshotError {
    error: RuntimeStoreError,
    retry_write: Option<Box<PreparedConversationSnapshotWrite>>,
}

impl std::fmt::Debug for StoreConversationSnapshotError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StoreConversationSnapshotError")
            .field("error", &self.error)
            .field("has_retry_write", &self.retry_write.is_some())
            .finish()
    }
}

impl std::fmt::Display for StoreConversationSnapshotError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(formatter)
    }
}

impl std::error::Error for StoreConversationSnapshotError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

impl StoreConversationSnapshotError {
    pub(crate) fn with_retry_write(
        error: RuntimeStoreError,
        retry_write: PreparedConversationSnapshotWrite,
    ) -> Self {
        Self {
            error,
            retry_write: Some(Box::new(retry_write)),
        }
    }

    pub(crate) fn without_retry_write(error: RuntimeStoreError) -> Self {
        Self {
            error,
            retry_write: None,
        }
    }

    #[must_use]
    pub const fn error(&self) -> &RuntimeStoreError {
        &self.error
    }

    #[must_use]
    pub fn code(&self) -> &'static str {
        self.error.code()
    }

    #[must_use]
    pub fn into_retry_write(self) -> Option<PreparedConversationSnapshotWrite> {
        self.retry_write.map(|write| *write)
    }

    /// 将一次性调用链不准备重放的 store failure 压缩为小型错误。
    ///
    /// `retry_write` 可能携带接近 64 MiB 的 canonical payload 与 TEMP pin cleanup；
    /// subscription pump 只需要 failure code，必须在进入 terminal writer wait 前显式
    /// 丢弃该 payload，不能把它隐式保存在错误枚举里。
    pub(crate) fn into_error(self) -> RuntimeStoreError {
        let Self { error, retry_write } = self;
        drop(retry_write);
        error
    }
}

#[cfg(test)]
pub(crate) fn claude_code_adapter_state_vault_for_test(
    store: &RuntimeStoreHandle,
) -> ClaudeCodeAdapterStateVault {
    store.claude_code_adapter_state_vault()
}
