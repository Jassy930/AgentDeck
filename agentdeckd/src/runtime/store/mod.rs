//! Runtime SQLite journal：单 worker、严格 schema 与行级加密。

mod admin;
pub(crate) mod admission;
mod approval;
mod catalog;
pub mod cipher;
mod command_configuration;
mod command_event;
mod configuration;
mod conversation_activation;
pub(crate) mod directed_reply;
mod execution_event;
pub mod identity;
mod journal;
pub(crate) mod key_transition;
#[cfg(test)]
mod key_transition_tests;
mod machine_identity;
mod machine_remote;
mod metadata;
#[cfg(test)]
mod native_metadata_effect_tests;
mod native_projection;
#[cfg(test)]
mod native_projection_import_tests;
#[cfg(test)]
mod native_projection_lifecycle_tests;
#[allow(
    dead_code,
    reason = "P4 pairing coordinator consumes the S1 Store capability"
)]
pub(crate) mod pairing;
mod pairing_authorization;
pub(crate) mod transition_material;
#[allow(
    unused_imports,
    reason = "P4.4 RemoteLink 与 P4.5 publisher 在后续同阶段 slice 消费这些 capability"
)]
pub(crate) use pairing_authorization::{
    ActiveRemoteIngressProof, CurrentRemoteAuthorizationProof, RemoteCommandAuthorizationStatus,
    RemotePrincipalRegistration, RemoteReplyAuthorization,
};
mod pairing_delivery;
#[cfg(test)]
mod pairing_delivery_tests;
#[cfg(test)]
pub(crate) use pairing_delivery_tests::{
    active_authorization_store_for_test,
    active_authorization_store_with_pending_transition_for_test,
    active_authorization_store_with_permissions_for_test, matching_bootstrap_update_for_test,
    pending_new_device_transition_fixture_for_test,
    production_aligned_active_authorization_store_for_test, revoking_authorization_store_for_test,
    two_active_authorization_store_with_permissions_for_test,
};
pub(crate) mod pairing_grant;
mod pairing_grant_allocation;
#[cfg(test)]
mod pairing_grant_allocation_tests;
#[cfg(test)]
pub(crate) use pairing_grant_allocation_tests::complete_active_membership_transition;
mod pairing_grant_commit;
#[cfg(test)]
mod pairing_grant_commit_tests;
mod pairing_grant_renewal;
#[cfg(test)]
mod pairing_grant_tests;
#[cfg(test)]
pub(crate) use pairing_grant_tests::{
    complete_active_zero_cut_transition, complete_active_zero_cut_transition_with_counter_guard,
    grant_input_with as grant_input_with_for_test,
};
mod pairing_grant_tx;
pub(crate) use pairing_delivery::{
    AcknowledgePairResponseReceived, AcknowledgePairResponseReceivedOutcome,
};
mod pairing_revocation;
mod pairing_revocation_ack;
#[allow(
    unused_imports,
    reason = "G4 Store capability keeps the target projection nameable for later RemoteLink gates"
)]
pub(crate) use pairing_revocation::{
    BeginDeviceRevocation, BeginDeviceRevocationOutcome, DeviceRevocationRecovery,
    RevocationRecoveryPhase, RevocationTarget, RevocationTargetStatus,
};
pub(crate) use pairing_revocation_ack::{
    AcknowledgeOrphanGrantCommittedOutcome, AcknowledgeRevocationCommitted,
    AcknowledgeRevocationCommittedOutcome,
};
mod pairing_receipt_retention;
#[cfg(test)]
mod pairing_revocation_tests;
#[allow(
    unused_imports,
    reason = "startup/maintenance caller consumes the bounded receipt purge outcome"
)]
pub(crate) use pairing_receipt_retention::{PairingReceiptPurgeOutcome, PairingReceiptPurgePlan};
#[cfg(test)]
mod pairing_receipt_retention_tests;
pub(crate) use pairing_grant_allocation::GrantAllocationProjection;
#[allow(
    unused_imports,
    reason = "C5 coordinator consumes the frozen G2 Store API"
)]
pub(crate) use pairing_grant_commit::{
    AcknowledgeGrantCommitted, AcknowledgeGrantCommittedOutcome, GrantCommittedRecovery,
};
pub(crate) use pairing_grant_tx::{ConfirmPairingGrantOutcome, GrantPreparingRecovery};
pub(crate) mod pairing_terminal;
#[cfg(test)]
mod pairing_terminal_tests;
#[cfg(test)]
mod pairing_tests;
#[cfg(test)]
pub(crate) use pairing_tests::{RELAY as PAIRING_TEST_RELAY, make_active as make_active_for_test};
mod persisted_event;
pub(crate) mod publication;
pub mod queue;
mod recovery;
pub(crate) mod remote_counter;
pub(crate) use remote_counter::ActiveSenderCounterBinding;
pub(crate) mod remote_counter_guard_manifest;
#[cfg(test)]
mod remote_counter_guard_manifest_tests;
#[cfg(test)]
mod remote_counter_tests;
#[cfg(test)]
mod remote_ingress_tests;
pub(crate) mod remote_replay;
mod retired_key;
pub(crate) use pairing_grant::{RetiredKeyOwnerKind, RetiredSharedKeyOwner};
pub(crate) use retired_key::{RetiredKeyGcOutcome, RetiredKeyMutationOutcome};
pub(crate) mod retention;
#[cfg(test)]
mod retired_key_tests;
mod schema;
pub(crate) mod sequence;
mod snapshot;
pub(crate) use snapshot::decode_catalog_baseline;
mod sqlite;
pub(crate) use sqlite::read_authenticated_counter_guard_manifest_existing_only;
mod stream;
mod worker;

use crate::runtime::events::SnapshotBuildPinCleanup;

pub use crate::runtime::model::{
    AcceptCommand, AcceptOutcome, AcceptedTerminationReason, ActivateMachineEnrollmentOutcome,
    ActivateMachineIdentityOutcome, ActiveMachineEnrollmentState, AdminCommandLimitScope,
    AuthorizeExecutionRelease, CommandExecutionConfiguration, CommandReceiptRecord,
    CommandReceiptSelector, CommandRecord, CommandState, CommandTerminal, CompleteCommand,
    CompleteOutcome, ConfigurationLimitScope, ConfirmMachinePurgeReadbackAbsentOutcome,
    ConversationDescriptor, ConversationLifecycle, ConversationRecord, ConversationRecoveryRecord,
    CreateConversationOutcome, EventRecord, ExecutionFence, ExecutionFenceRecord,
    ExecutionIntentRecord, FinalizeMachineLocalDeletionOutcome, IdempotencyOwner,
    LocalDeletedMachineEnrollmentState, MAX_CONVERSATION_DESCRIPTOR_BYTES,
    MAX_NATIVE_NONLIVE_IDENTITIES, MAX_RECOVERY_PAGE_RETAINED_BYTES, MAX_RUNTIME_CONVERSATIONS,
    MAX_RUNTIME_LIVE_CONVERSATIONS, MAX_RUNTIME_PHYSICAL_CONVERSATIONS, MachineCleanupWitnessError,
    MachineCleanupWitnessV1, MachineEnrollmentConnectionMaterial, MachineEnrollmentReceiptRecord,
    MachineEnrollmentState, MachineIdentityBinding, MachineIdentityLifecycle,
    MachineIdentityStateRecord, MachinePurgeReadbackProof, MachineRemoteLifecycle,
    MachineRemoteStateRecord, MachineRetirementRequestMaterial, MachineRetirementTerminalMaterial,
    MachineRootLostPurgeMaterial, MachineTrustResetKind, MarkConversationRecoveryBlocked,
    NewConversation, PrepareMachineEnrollmentOutcome, PrepareMachineIdentityOutcome,
    PrepareMachineRetirementOutcome, PreparedMachineEnrollmentState,
    PurgeReadbackAbsentMachineEnrollmentState, QueryCommandReceipt, QueueScope,
    RecordMachineRetirementTerminalOutcome, RecordRootLostMachinePurgeOutcome,
    RecordValidatedEnrollmentResponseOutcome, RecoverStartedCommand, RecoveryBlockedCommandBinding,
    RecoveryCompletion, RecoveryCursor, RecoveryFenceBinding, RecoveryPage, RecoveryState,
    RelayCommittedMachineEnrollmentState, RetirePendingMachineEnrollmentState, RuntimeClock,
    RuntimeClockError, RuntimeCommitOperation, RuntimeStoreConfig, RuntimeStoreError,
    RuntimeStoreFaultInjector, RuntimeStoreLane, RuntimeStoreOperation, RuntimeStoreSnapshot,
    SanitizedTerminalFailure, StartCommand, StartOutcome, StartedBeforeReleaseTermination,
    StartedRecoveryRecord, SystemRuntimeClock, TerminalState, TerminateAcceptedCommand,
    TerminateAcceptedOutcome, TerminateStartedBeforeRelease, TerminateStartedBeforeReleaseOutcome,
    ValidatedMachineEnrollmentState,
};
pub use admin::{
    AcceptAdminUpgradeOutcome, AdminUpgradeCommand, AdminUpgradeRecoveryCursor,
    AdminUpgradeRecoveryPage, AdminUpgradeStatus, AdminUpgradeTerminalOutcome,
    FinalizeAdminUpgradeOutcome,
};
pub(crate) use configuration::MAX_CONFIGURATION_CANONICAL_BYTES;
pub use configuration::{ConfigurationRecord, ConfigureConversation, ConfigureConversationOutcome};
pub use execution_event::{AppendExecutionEvent, AppendExecutionEventOutcome};
pub use identity::{RuntimeId, RuntimeIdKind, RuntimeIdSource};
pub(crate) use machine_remote::prepare_input_hash_for_bundle as machine_enrollment_prepare_input_hash;
pub(crate) use metadata::{
    ClaimNativeMetadataMutationOutcome, NativeMetadataMutationClaim,
    NativeMetadataMutationReadback, NativeMetadataMutationStatus,
};
pub use metadata::{
    MetadataMutationRecord, UpdateConversationMetadataOutcome, UpdateManagedConversationMetadata,
};
#[cfg(test)]
pub(crate) use native_projection::PersistNativeMetadataEffectFenceOutcome;
pub(crate) use native_projection::{
    AuthorizeNativeMetadataEffectRelease, FailUnreleasedNativeMetadataEffect,
    NativeMetadataEffectFenceRecord, NativeMetadataEffectReleasePermit,
    NativeMetadataEffectUnreleasedCleanupAuthority, PersistNativeMetadataEffectFence,
};
pub(crate) use native_projection::{
    CompletedNativeProjectionGeneration, ImportNativeProjection, ImportNativeProjectionOutcome,
    NativeProjectionCandidateDisposition, NativeProjectionReconcileCursor,
    NativeProjectionReconcilePlan, NativeProjectionRetirementCursor,
    NativeProjectionRetirementPlan,
};
pub(crate) use publication::StreamBindingPermit;
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
pub(crate) use worker::{
    AuthorizedAcceptOutcome, ClaudeCodeAdapterStateVault, ClaudeCodeNativeProjectionStore,
    CodexAdapterStateVault, NativeHistoryIdentityError,
};

/// 已经通过 conversation row metadata MAC、descriptor AEAD open 与 canonical
/// re-encode 的 snapshot 上下文。该类型只在 daemon runtime 内流转，不进入 wire。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SnapshotOrigin {
    Managed,
    NativeProjected,
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct AuthenticatedConversationSnapshotContext {
    pub(crate) conversation_id: RuntimeId,
    pub(super) adapter_state_key: RuntimeId,
    pub(crate) agent_kind: agentdeck_protocol::AgentKind,
    pub(crate) catalog_revision: u64,
    pub(crate) command_high_water: Option<u64>,
    pub(crate) event_high_water: Option<u64>,
    pub(crate) origin: SnapshotOrigin,
}

impl std::fmt::Debug for AuthenticatedConversationSnapshotContext {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthenticatedConversationSnapshotContext")
            .field("conversation_id", &self.conversation_id)
            .field("agent_kind", &self.agent_kind)
            .field("catalog_revision", &self.catalog_revision)
            .field("command_high_water", &self.command_high_water)
            .field("event_high_water", &self.event_high_water)
            .field("origin", &self.origin)
            .finish_non_exhaustive()
    }
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
