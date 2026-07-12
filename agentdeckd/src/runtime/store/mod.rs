//! Runtime SQLite journal：单 worker、严格 schema 与行级加密。

pub(crate) mod admission;
pub mod cipher;
pub mod identity;
mod journal;
pub mod queue;
mod recovery;
mod schema;
pub(crate) mod sequence;
mod sqlite;
mod worker;

pub use crate::runtime::model::{
    AcceptCommand, AcceptOutcome, AuthorizeExecutionRelease, CommandRecord, CommandState,
    CompleteCommand, CompleteOutcome, ConversationDescriptor, ConversationLifecycle,
    ConversationRecord, ConversationRecoveryRecord, EventRecord, ExecutionFence,
    ExecutionFenceRecord, ExecutionIntentRecord, IdempotencyOwner,
    MAX_CONVERSATION_DESCRIPTOR_BYTES, MAX_RECOVERY_PAGE_RETAINED_BYTES,
    MachineEnrollmentReceiptRecord, NewConversation, QueueScope, RecoveryCompletion,
    RecoveryCursor, RecoveryPage, RecoveryState, RuntimeClock, RuntimeClockError,
    RuntimeCommitOperation, RuntimeStoreConfig, RuntimeStoreError, RuntimeStoreFaultInjector,
    RuntimeStoreLane, RuntimeStoreOperation, RuntimeStoreSnapshot, StartCommand, StartOutcome,
    StartedRecoveryRecord, SystemRuntimeClock, TerminalState,
};
pub use identity::{RuntimeId, RuntimeIdKind, RuntimeIdSource};
pub use recovery::RuntimeRescueIndex;
pub use schema::{RUNTIME_CRYPTO_CONTEXT_VERSION, RUNTIME_SCHEMA_FAMILY, RUNTIME_SCHEMA_VERSION};
pub use worker::RuntimeStoreHandle;
pub(crate) use worker::{ClaudeCodeAdapterStateVault, CodexAdapterStateVault};

#[cfg(test)]
pub(crate) fn claude_code_adapter_state_vault_for_test(
    store: &RuntimeStoreHandle,
) -> ClaudeCodeAdapterStateVault {
    store.claude_code_adapter_state_vault()
}
