//! 单 blocking worker 独占 Runtime SQLite connection 的 async handle。

use std::collections::HashMap;
use std::fmt;
use std::mem::size_of;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::Duration;

use agentdeck_protocol::runtime::{ConversationConfigurationState, RuntimeEvent};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot};
use zeroize::{Zeroize, Zeroizing};

use crate::runtime::adapter_state::AdapterStateNamespace;
use crate::runtime::backfill::{BarrierInput, plan_barrier};
use crate::runtime::connection::AuthorizationGuard;
use crate::runtime::events::{
    CatalogSnapshotSource, CommandStreamEffects, RegisterCaptureError, RegisterStreamBarrier,
    RelayCommittedCut, RuntimeStreamTarget, SnapshotBarrierSource, SnapshotBuildPinCleanup,
    SnapshotMaterializationSource, StoreCleanup, StoreCommitHub, StoreCommitHubError,
    StoreWatchToken, StreamBarrierRegistration,
};
use crate::runtime::model::{
    AcceptCommand, AcceptOutcome, ActivateMachineEnrollmentOutcome, ActivateMachineIdentityOutcome,
    ApprovalMutationOutcome, AuthorizeExecutionRelease, BeginApprovalAttempt,
    BeginApprovalAttemptOutcome, ClaimApproval, CommandReceiptRecord, CommandReceiptSelector,
    CompleteCommand, CompleteOutcome, ConfirmMachinePurgeReadbackAbsentOutcome, ConversationRecord,
    CreateConversationOutcome, ExecutionFence, ExecutionFenceRecord, ExpireApproval,
    FinalizeMachineLocalDeletionOutcome, MAX_ADAPTER_STATE_REFERENCE_BYTES,
    MAX_APPROVAL_STATUS_DETAIL_BYTES, MAX_COMMAND_PAYLOAD_BYTES, MAX_CONVERSATION_DESCRIPTOR_BYTES,
    MAX_CRITICAL_COMMAND_RECORD_BYTES, MAX_EXECUTION_FENCE_BYTES, MAX_EXECUTION_NONCE_BYTES,
    MAX_IDEMPOTENCY_KEY_BYTES, MAX_RUNTIME_BUSY_TIMEOUT_MS, MAX_RUNTIME_STORE_COMMAND_CAPACITY,
    MAX_RUNTIME_STORE_LANE_BYTE_CAPACITY, MachineEnrollmentReceiptRecord, MachineEnrollmentState,
    MachineIdentityBinding, MachineIdentityStateRecord, MachineTrustResetKind, MarkApprovalApplied,
    MarkApprovalDeliveryFailed, MarkConversationRecoveryBlocked, NewConversation,
    PrepareMachineEnrollmentOutcome, PrepareMachineIdentityOutcome,
    PrepareMachineRetirementOutcome, QueryCommandReceipt, RUNTIME_STORE_SHUTDOWN_GRACE_MS,
    RecordMachineRetirementTerminalOutcome, RecordRootLostMachinePurgeOutcome,
    RecordValidatedEnrollmentResponseOutcome, RecoveryCompletion, RecoveryCursor, RecoveryPage,
    RegisterApproval, RegisterApprovalOutcome, RetryApprovalDelivery, RuntimeStoreConfig,
    RuntimeStoreError, RuntimeStoreLane, RuntimeStoreOperation, RuntimeStoreSnapshot, StartCommand,
    StartOutcome, TerminateAcceptedCommand, TerminateAcceptedOutcome,
    TerminateStartedBeforeRelease, TerminateStartedBeforeReleaseOutcome,
};
use crate::runtime::read_pool::{
    DEFAULT_RUNTIME_READ_CONCURRENCY, MAX_RUNTIME_READ_PAGE_BYTES, ReadMemoryLease, ReadPool,
    ReadPoolError,
};
use crate::runtime::snapshot::SharedSnapshotBuildPermit;
use crate::security::{SecretBytes, StorageKek};

use super::cipher::RuntimeReadCryptoCapability;
use super::command_configuration::CommandStartProvenance;
use super::command_event::StartEventSource;
use super::configuration::{
    self, ConfigureConversation, ConfigureConversationOutcome, PreparedConfigurationRequest,
};
use super::execution_event::PreparedExecutionEvent;
use super::identity::{
    MAX_RUNTIME_ID_COLLISION_ATTEMPTS, RuntimeId, RuntimeIdError, RuntimeIdKind,
};
use super::metadata::{
    self, ClaimNativeMetadataMutationOutcome, NativeMetadataMutationClaim,
    NativeMetadataMutationReadback, NativeMetadataMutationRecoveryCursor,
    NativeMetadataMutationRecoveryPage, PreparedMetadataMutationRequest,
    UpdateConversationMetadataOutcome, UpdateManagedConversationMetadata,
};
use super::publication::{
    FreezePublicationRequest, FrozenPublication, PublicationAcknowledgement, PublicationBarrierCut,
    PublicationScope, PublicationStreamRecord, RotatePublicationStreamRequest,
};
use super::snapshot::{ReadySnapshotReference, StoredCatalogSnapshot, StoredConversationSnapshot};
use super::stream::{
    RuntimeBackfillPageCompletion, RuntimeBackfillPin, RuntimeBackfillPlan, RuntimeBackfillTarget,
    RuntimeCatalogBackfillPage, RuntimeEventBackfillPage, RuntimeSnapshotBuildPin,
};
use super::{
    AuthenticatedConversationSnapshotContext, PreparedConversationSnapshotWrite, SnapshotOrigin,
    StoreConversationSnapshotError, admin, approval, journal, machine_identity, machine_remote,
    native_projection, sqlite, stream,
};

mod stream_pipeline;
#[cfg(test)]
mod test_admission;
mod validation;

use validation::{memory_charge, validate_maximum, validate_nonempty_maximum};

#[cfg(test)]
use stream_pipeline::decision_requires_snapshot_source;
use stream_pipeline::{
    register_stream_barrier_on_worker, send_snapshot_build_pin_reply, send_stream_barrier_reply,
};

const LIFECYCLE_RUNNING: u8 = 0;
const LIFECYCLE_SHUTTING_DOWN: u8 = 1;
const LIFECYCLE_STOPPED: u8 = 2;

const IDENTITY_DERIVATION_ROOT_DOMAIN: &[u8] =
    b"agentdeck.runtime.storage-kek.identity-derivation.v1";
const CONVERSATION_ID_DOMAIN: &[u8] = b"agentdeck.runtime.conversation-id.v1";
const ADAPTER_STATE_KEY_DOMAIN: &[u8] = b"agentdeck.runtime.adapter-state-key.v1";
const NATIVE_PROJECTION_CONVERSATION_ID_DOMAIN: &[u8] =
    b"agentdeck.runtime.native-projection.conversation-id.v1";
const NATIVE_PROJECTION_ADAPTER_STATE_KEY_DOMAIN: &[u8] =
    b"agentdeck.runtime.native-projection.adapter-state-key.v1";
const NATIVE_PROJECTION_OBSERVATION_DOMAIN: &[u8] =
    b"agentdeck.runtime.native-projection.observation.v1";
const NATIVE_HISTORY_COMMAND_ID_DOMAIN: &[u8] = b"agentdeck.runtime.native-history.command-id.v1";
const NATIVE_HISTORY_ITEM_ID_DOMAIN: &[u8] = b"agentdeck.runtime.native-history.item-id.v1";
const NATIVE_HISTORY_ENTITY_ID_DOMAIN: &[u8] = b"agentdeck.runtime.native-history.entity-id.v1";
const MACHINE_TRUST_DOMAIN: &[u8] = b"agentdeck.runtime.machine-trust-domain.v1";

type HmacSha256 = Hmac<Sha256>;

/// 由 StorageKEK 域分离得到的稳定身份派生能力。
///
/// capability 不实现 `Debug`，克隆的 store handle 只共享同一份 `Arc`，不会复制
/// 裸密钥；最后一个 handle 销毁时固定 32-byte key 会清零。
struct RuntimeIdentityDerivationCapability {
    key: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum NativeHistoryIdentityError {
    #[error("native history identity input is invalid")]
    InvalidInput,
    #[error("native history identity derivation is unavailable")]
    Unavailable,
    #[error("native history identity derivation produced an invalid zero value")]
    ZeroIdentity,
}

impl RuntimeIdentityDerivationCapability {
    fn from_storage_kek(storage_kek: &StorageKek) -> Result<Self, RuntimeStoreError> {
        let mut mac = HmacSha256::new_from_slice(storage_kek.expose_secret()).map_err(|_| {
            RuntimeStoreError::InvalidConfig("runtime identity derivation root is unavailable")
        })?;
        update_length_prefixed(&mut mac, IDENTITY_DERIVATION_ROOT_DOMAIN)?;
        let mut digest = mac.finalize().into_bytes();
        let mut key = [0_u8; 32];
        key.copy_from_slice(&digest);
        digest.zeroize();
        if key == [0; 32] {
            key.zeroize();
            return Err(RuntimeStoreError::InvalidConfig(
                "runtime identity derivation root is invalid",
            ));
        }
        Ok(Self { key })
    }

    fn derive_start_identity(
        &self,
        owner: &crate::runtime::model::IdempotencyOwner,
        idempotency_key: &str,
    ) -> Result<(RuntimeId, RuntimeId), RuntimeStoreError> {
        let owner = Zeroizing::new(journal::canonical_owner_v1(owner));
        let conversation_id = self.derive_id(
            RuntimeIdKind::Conversation,
            CONVERSATION_ID_DOMAIN,
            owner.as_ref(),
            idempotency_key.as_bytes(),
        )?;
        let adapter_state_key = self.derive_id(
            RuntimeIdKind::AdapterState,
            ADAPTER_STATE_KEY_DOMAIN,
            owner.as_ref(),
            idempotency_key.as_bytes(),
        )?;
        Ok((conversation_id, adapter_state_key))
    }

    fn derive_machine_trust_domain(&self) -> Result<[u8; 32], RuntimeStoreError> {
        let mut mac = HmacSha256::new_from_slice(&self.key).map_err(|_| {
            RuntimeStoreError::InvalidConfig("runtime machine trust domain is unavailable")
        })?;
        update_length_prefixed(&mut mac, MACHINE_TRUST_DOMAIN)?;
        let mut digest = mac.finalize().into_bytes();
        let mut domain = [0_u8; 32];
        domain.copy_from_slice(&digest);
        digest.zeroize();
        if domain == [0; 32] {
            domain.zeroize();
            return Err(RuntimeStoreError::InvalidConfig(
                "runtime machine trust domain is invalid",
            ));
        }
        Ok(domain)
    }

    fn derive_native_history_command_id(
        &self,
        conversation_id: RuntimeId,
        turn_key: &[u8; 32],
    ) -> Result<RuntimeId, NativeHistoryIdentityError> {
        let bytes = self.derive_native_history_id_bytes(
            NATIVE_HISTORY_COMMAND_ID_DOMAIN,
            conversation_id,
            turn_key,
        )?;
        RuntimeId::from_bytes(RuntimeIdKind::Command, bytes)
            .map_err(|_| NativeHistoryIdentityError::ZeroIdentity)
    }

    fn derive_native_history_item_ids(
        &self,
        conversation_id: RuntimeId,
        item_key: &[u8; 32],
    ) -> Result<([u8; 16], [u8; 16]), NativeHistoryIdentityError> {
        let item_id = self.derive_native_history_id_bytes(
            NATIVE_HISTORY_ITEM_ID_DOMAIN,
            conversation_id,
            item_key,
        )?;
        let entity_id = self.derive_native_history_id_bytes(
            NATIVE_HISTORY_ENTITY_ID_DOMAIN,
            conversation_id,
            item_key,
        )?;
        Ok((item_id, entity_id))
    }

    fn derive_native_history_id_bytes(
        &self,
        domain: &[u8],
        conversation_id: RuntimeId,
        native_key: &[u8; 32],
    ) -> Result<[u8; 16], NativeHistoryIdentityError> {
        if conversation_id.kind() != RuntimeIdKind::Conversation || native_key == &[0; 32] {
            return Err(NativeHistoryIdentityError::InvalidInput);
        }
        let mut mac = HmacSha256::new_from_slice(&self.key)
            .map_err(|_| NativeHistoryIdentityError::Unavailable)?;
        update_length_prefixed(&mut mac, domain)
            .map_err(|_| NativeHistoryIdentityError::InvalidInput)?;
        update_length_prefixed(&mut mac, conversation_id.as_bytes())
            .map_err(|_| NativeHistoryIdentityError::InvalidInput)?;
        update_length_prefixed(&mut mac, native_key)
            .map_err(|_| NativeHistoryIdentityError::InvalidInput)?;
        // 固定 attempt=0 是当前 byte-stable 格式的一部分。实际截断碰撞由完整
        // read 的全域 alias 检查整批 fail-close，不能按集合顺序重试并改变旧 ID。
        mac.update(&[0]);
        let mut digest = mac.finalize().into_bytes();
        let bytes = truncate_native_history_digest(&digest)?;
        digest.zeroize();
        Ok(bytes)
    }

    fn derive_native_projection_material(
        &self,
        namespace: AdapterStateNamespace,
        private_reference: &[u8],
        scan_generation: &[u8; 16],
    ) -> Result<
        (
            Vec<super::native_projection::NativeProjectionIdentityCandidate>,
            [u8; 32],
        ),
        RuntimeStoreError,
    > {
        let mut candidates = Vec::with_capacity(MAX_RUNTIME_ID_COLLISION_ATTEMPTS);
        for attempt in 0..MAX_RUNTIME_ID_COLLISION_ATTEMPTS {
            let attempt = u8::try_from(attempt).map_err(|_| {
                RuntimeStoreError::InvalidConfig("native projection identity attempt overflow")
            })?;
            let conversation_id = self.derive_native_projection_id(
                RuntimeIdKind::Conversation,
                NATIVE_PROJECTION_CONVERSATION_ID_DOMAIN,
                namespace,
                private_reference,
                attempt,
            )?;
            let adapter_state_key = self.derive_native_projection_id(
                RuntimeIdKind::AdapterState,
                NATIVE_PROJECTION_ADAPTER_STATE_KEY_DOMAIN,
                namespace,
                private_reference,
                attempt,
            )?;
            if let (Some(conversation_id), Some(adapter_state_key)) =
                (conversation_id, adapter_state_key)
            {
                candidates.push(
                    super::native_projection::NativeProjectionIdentityCandidate {
                        conversation_id,
                        adapter_state_key,
                    },
                );
            }
        }
        if candidates.is_empty() {
            return Err(RuntimeIdError::CollisionExhausted {
                kind: RuntimeIdKind::Conversation,
                attempts: MAX_RUNTIME_ID_COLLISION_ATTEMPTS,
            }
            .into());
        }

        let mut mac = HmacSha256::new_from_slice(&self.key).map_err(|_| {
            RuntimeStoreError::InvalidConfig("native projection observation is unavailable")
        })?;
        update_length_prefixed(&mut mac, NATIVE_PROJECTION_OBSERVATION_DOMAIN)?;
        update_length_prefixed(&mut mac, namespace.origin_namespace().as_bytes())?;
        update_length_prefixed(&mut mac, private_reference)?;
        update_length_prefixed(&mut mac, scan_generation)?;
        let mut digest = mac.finalize().into_bytes();
        let mut observation_token = [0_u8; 32];
        observation_token.copy_from_slice(&digest);
        digest.zeroize();
        Ok((candidates, observation_token))
    }

    fn derive_native_projection_id(
        &self,
        kind: RuntimeIdKind,
        domain: &[u8],
        namespace: AdapterStateNamespace,
        private_reference: &[u8],
        attempt: u8,
    ) -> Result<Option<RuntimeId>, RuntimeStoreError> {
        let mut mac = HmacSha256::new_from_slice(&self.key).map_err(|_| {
            RuntimeStoreError::InvalidConfig("native projection identity is unavailable")
        })?;
        update_length_prefixed(&mut mac, domain)?;
        update_length_prefixed(&mut mac, namespace.origin_namespace().as_bytes())?;
        update_length_prefixed(&mut mac, private_reference)?;
        mac.update(&[attempt]);
        let mut digest = mac.finalize().into_bytes();
        let mut bytes = [0_u8; 16];
        bytes.copy_from_slice(&digest[..16]);
        digest.zeroize();
        match RuntimeId::from_bytes(kind, bytes) {
            Ok(id) => Ok(Some(id)),
            Err(RuntimeIdError::Zero { .. }) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    fn derive_id(
        &self,
        kind: RuntimeIdKind,
        domain: &[u8],
        owner: &[u8],
        idempotency_key: &[u8],
    ) -> Result<RuntimeId, RuntimeStoreError> {
        for attempt in 0..MAX_RUNTIME_ID_COLLISION_ATTEMPTS {
            let mut mac = HmacSha256::new_from_slice(&self.key).map_err(|_| {
                RuntimeStoreError::InvalidConfig("runtime identity derivation is unavailable")
            })?;
            update_length_prefixed(&mut mac, domain)?;
            update_length_prefixed(&mut mac, owner)?;
            update_length_prefixed(&mut mac, idempotency_key)?;
            mac.update(&[u8::try_from(attempt).map_err(|_| {
                RuntimeStoreError::InvalidConfig("runtime identity derivation attempt overflow")
            })?]);
            let mut digest = mac.finalize().into_bytes();
            let mut bytes = [0_u8; 16];
            bytes.copy_from_slice(&digest[..16]);
            digest.zeroize();
            if let Ok(id) = RuntimeId::from_bytes(kind, bytes) {
                return Ok(id);
            }
        }
        Err(RuntimeIdError::CollisionExhausted {
            kind,
            attempts: MAX_RUNTIME_ID_COLLISION_ATTEMPTS,
        }
        .into())
    }
}

fn truncate_native_history_digest(digest: &[u8]) -> Result<[u8; 16], NativeHistoryIdentityError> {
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(
        digest
            .get(..16)
            .ok_or(NativeHistoryIdentityError::InvalidInput)?,
    );
    if bytes == [0; 16] {
        Err(NativeHistoryIdentityError::ZeroIdentity)
    } else {
        Ok(bytes)
    }
}

#[cfg(test)]
mod native_history_identity_tests {
    use super::*;

    fn conversation(seed: u8) -> RuntimeId {
        RuntimeId::from_bytes(RuntimeIdKind::Conversation, [seed; 16])
            .expect("nonzero conversation")
    }

    #[test]
    fn storage_root_native_history_domains_are_stable_separate_and_conversation_bound() {
        let capability = RuntimeIdentityDerivationCapability { key: [0xa7; 32] };
        let first = capability
            .derive_native_history_command_id(conversation(1), &[0x11; 32])
            .expect("derive history command");
        let repeated = capability
            .derive_native_history_command_id(conversation(1), &[0x11; 32])
            .expect("repeat history command");
        let other_turn = capability
            .derive_native_history_command_id(conversation(1), &[0x12; 32])
            .expect("derive other turn");
        let other_conversation = capability
            .derive_native_history_command_id(conversation(2), &[0x11; 32])
            .expect("derive other conversation");
        let (item, entity) = capability
            .derive_native_history_item_ids(conversation(1), &[0x11; 32])
            .expect("derive item identities");

        assert_eq!(first, repeated);
        assert_ne!(first, other_turn);
        assert_ne!(first, other_conversation);
        assert_ne!(*first.as_bytes(), item);
        assert_ne!(*first.as_bytes(), entity);
        assert_ne!(item, entity);
    }

    #[test]
    fn native_history_zero_digest_and_invalid_input_fail_closed_without_debug_material() {
        assert_eq!(
            truncate_native_history_digest(&[0; 32]),
            Err(NativeHistoryIdentityError::ZeroIdentity)
        );
        let capability = RuntimeIdentityDerivationCapability { key: [0xa8; 32] };
        assert_eq!(
            capability.derive_native_history_command_id(conversation(1), &[0; 32]),
            Err(NativeHistoryIdentityError::InvalidInput)
        );
        assert!(!format!("{:?}", NativeHistoryIdentityError::ZeroIdentity).contains("a8"));
    }
}

impl Drop for RuntimeIdentityDerivationCapability {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

fn update_length_prefixed(mac: &mut HmacSha256, value: &[u8]) -> Result<(), RuntimeStoreError> {
    let length = u32::try_from(value.len()).map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
    mac.update(&length.to_be_bytes());
    mac.update(value);
    Ok(())
}

fn advance_native_projection_scan_epoch(source: &AtomicU64) -> Result<u64, RuntimeStoreError> {
    source
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
            current.checked_add(1)
        })
        .map(|previous| previous + 1)
        .map_err(|_| RuntimeStoreError::InvalidStateTransition)
}

pub(crate) struct StoreOpenLease;

pub(crate) fn claim_store_path(path: &Path) -> Result<Arc<StoreOpenLease>, RuntimeStoreError> {
    static OPEN_STORES: OnceLock<Mutex<HashMap<PathBuf, Weak<StoreOpenLease>>>> = OnceLock::new();
    let registry = OPEN_STORES.get_or_init(|| Mutex::new(HashMap::new()));
    let mut stores = registry
        .lock()
        .map_err(|_| RuntimeStoreError::WorkerStopped)?;
    stores.retain(|_, lease| lease.strong_count() > 0);
    if stores.get(path).and_then(Weak::upgrade).is_some() {
        return Err(RuntimeStoreError::StoreAlreadyOpen);
    }
    let lease = Arc::new(StoreOpenLease);
    stores.insert(path.to_path_buf(), Arc::downgrade(&lease));
    Ok(lease)
}

#[derive(Clone)]
pub struct RuntimeStoreHandle {
    normal_tx: mpsc::Sender<Queued<NormalCommand>>,
    safety_tx: mpsc::Sender<Queued<SafetyCommand>>,
    read_tx: mpsc::Sender<ReadCommand>,
    control_tx: mpsc::Sender<ControlCommand>,
    normal_budget: Arc<Semaphore>,
    safety_budget: Arc<Semaphore>,
    execution_event_build_permit: Arc<Semaphore>,
    lifecycle: Arc<AtomicU8>,
    interrupt: Arc<rusqlite::InterruptHandle>,
    read_pool: ReadPool,
    read_crypto: RuntimeReadCryptoCapability,
    database_id: [u8; 16],
    identity_derivation: Arc<RuntimeIdentityDerivationCapability>,
    native_projection_scan_epoch: Arc<AtomicU64>,
    shutdown_timeout: Duration,
}

/// Core 专用的 Accept 成功回执；authorization 只能在 durable outcome、
/// stream notification 与 Store reply 完成后交还 conversation actor。
pub(crate) struct AuthorizedAcceptOutcome {
    outcome: AcceptOutcome,
    authorization: AuthorizationGuard,
}

impl AuthorizedAcceptOutcome {
    pub(crate) fn into_parts(self) -> (AcceptOutcome, AuthorizationGuard) {
        (self.outcome, self.authorization)
    }
}

/// 固定绑定到 Codex 私有 namespace 的能力句柄。
///
/// adapter 只能拿到与自身类型对应的 vault；namespace 枚举和通用明文入口不跨出
/// runtime/store 边界。
#[derive(Clone, Debug)]
pub(crate) struct CodexAdapterStateVault {
    store: RuntimeStoreHandle,
}

impl CodexAdapterStateVault {
    pub(crate) async fn bind(
        &self,
        adapter_state_key: super::RuntimeId,
        state_reference: SecretBytes,
    ) -> Result<(), RuntimeStoreError> {
        self.store
            .bind_adapter_state(
                AdapterStateNamespace::Codex,
                adapter_state_key,
                state_reference,
            )
            .await
    }

    pub(crate) async fn resolve(
        &self,
        adapter_state_key: super::RuntimeId,
    ) -> Result<Option<SecretBytes>, RuntimeStoreError> {
        self.store
            .resolve_adapter_state(AdapterStateNamespace::Codex, adapter_state_key)
            .await
    }
}

/// 固定绑定到 Claude Code 私有 namespace 的能力句柄。
#[derive(Clone, Debug)]
pub(crate) struct ClaudeCodeAdapterStateVault {
    store: RuntimeStoreHandle,
}

/// 固定绑定到 Claude Code namespace 的 native history projection 能力。
///
/// 调用方不能选择 namespace，也不能取得通用明文 vault writer；所有导入都经单个
/// Store worker command 与一个 SQLite transaction 收口。
#[derive(Clone, Debug)]
pub(crate) struct ClaudeCodeNativeProjectionStore {
    store: RuntimeStoreHandle,
}

impl ClaudeCodeNativeProjectionStore {
    pub(crate) async fn import(
        &self,
        input: native_projection::ImportNativeProjection,
    ) -> Result<native_projection::ImportNativeProjectionOutcome, RuntimeStoreError> {
        self.store
            .import_native_projection(AdapterStateNamespace::ClaudeCode, input)
            .await
    }

    /// C-f 只能在消费 neutral `CompletedNativeProjectionScan` witness 后调用本入口；裸 generation
    /// 不进入 reconciliation plan/apply API。
    pub(crate) async fn accept_completed_scan(
        &self,
        completed: crate::agent::CompletedNativeProjectionScan,
    ) -> Result<Arc<native_projection::CompletedNativeProjectionGeneration>, RuntimeStoreError>
    {
        let (scan_generation, _inspected_candidates, _imported_candidates) = completed.into_parts();
        let epoch_source = self.store.native_projection_scan_epoch.clone();
        dispatch(
            &self.store.read_tx,
            &self.store.lifecycle,
            RuntimeStoreLane::Read,
            |reply| ReadCommand::AcceptCompletedNativeProjectionScan {
                namespace: AdapterStateNamespace::ClaudeCode,
                scan_generation,
                epoch_source,
                reply,
            },
        )
        .await?
    }

    pub(crate) async fn plan_completed_page(
        &self,
        completed: Arc<native_projection::CompletedNativeProjectionGeneration>,
        cursor: Option<native_projection::NativeProjectionReconcileCursor>,
    ) -> Result<native_projection::NativeProjectionReconcilePlan, RuntimeStoreError> {
        completed.ensure_epoch_source(&self.store.native_projection_scan_epoch)?;
        dispatch(
            &self.store.read_tx,
            &self.store.lifecycle,
            RuntimeStoreLane::Read,
            |reply| ReadCommand::PlanNativeProjectionReconciliation {
                completed,
                cursor,
                reply,
            },
        )
        .await?
    }

    pub(crate) async fn apply_completed_page(
        &self,
        plan: native_projection::NativeProjectionReconcilePlan,
        dispositions: Vec<native_projection::NativeProjectionCandidateDisposition>,
    ) -> Result<native_projection::ReconcileNativeProjectionOutcome, RuntimeStoreError> {
        plan.ensure_epoch_owner(&self.store.native_projection_scan_epoch)?;
        let disposition_capacity = dispositions
            .capacity()
            .checked_mul(size_of::<
                native_projection::NativeProjectionCandidateDisposition,
            >())
            .ok_or(RuntimeStoreError::PayloadTooLarge)?;
        let frozen_disposition_bytes = dispositions
            .len()
            .checked_mul(size_of::<
                native_projection::NativeProjectionCandidateDisposition,
            >())
            .ok_or(RuntimeStoreError::PayloadTooLarge)?;
        let charge = memory_charge(
            size_of::<NormalCommand>(),
            &[
                plan.retained_capacity()?,
                disposition_capacity,
                frozen_disposition_bytes,
            ],
        )?;
        dispatch_with_budget(
            &self.store.normal_tx,
            &self.store.normal_budget,
            &self.store.lifecycle,
            RuntimeStoreLane::Normal,
            charge,
            |reply| NormalCommand::ReconcileNativeProjection {
                plan,
                dispositions,
                reply,
            },
        )
        .await?
    }

    pub(crate) async fn plan_retirement_page(
        &self,
        cursor: Option<native_projection::NativeProjectionRetirementCursor>,
    ) -> Result<native_projection::NativeProjectionRetirementPlan, RuntimeStoreError> {
        dispatch(
            &self.store.read_tx,
            &self.store.lifecycle,
            RuntimeStoreLane::Read,
            |reply| ReadCommand::PlanNativeProjectionRetirement {
                namespace: AdapterStateNamespace::ClaudeCode,
                cursor,
                reply,
            },
        )
        .await?
    }

    pub(crate) async fn apply_retirement_page(
        &self,
        plan: native_projection::NativeProjectionRetirementPlan,
    ) -> Result<native_projection::RetireNativeProjectionOutcome, RuntimeStoreError> {
        let charge = memory_charge(size_of::<NormalCommand>(), &[plan.retained_capacity()?])?;
        dispatch_with_budget(
            &self.store.normal_tx,
            &self.store.normal_budget,
            &self.store.lifecycle,
            RuntimeStoreLane::Normal,
            charge,
            |reply| NormalCommand::RetireNativeProjection { plan, reply },
        )
        .await?
    }
}

impl ClaudeCodeAdapterStateVault {
    pub(crate) async fn bind(
        &self,
        adapter_state_key: super::RuntimeId,
        state_reference: SecretBytes,
    ) -> Result<(), RuntimeStoreError> {
        self.store
            .bind_adapter_state(
                AdapterStateNamespace::ClaudeCode,
                adapter_state_key,
                state_reference,
            )
            .await
    }

    pub(crate) async fn resolve(
        &self,
        adapter_state_key: super::RuntimeId,
    ) -> Result<Option<SecretBytes>, RuntimeStoreError> {
        self.store
            .resolve_adapter_state(AdapterStateNamespace::ClaudeCode, adapter_state_key)
            .await
    }
}

impl fmt::Debug for RuntimeStoreHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeStoreHandle")
            .finish_non_exhaustive()
    }
}

impl RuntimeStoreHandle {
    pub async fn open(
        config: RuntimeStoreConfig,
        storage_kek: StorageKek,
    ) -> Result<Self, RuntimeStoreError> {
        if config.command_capacity == 0
            || config.command_capacity > MAX_RUNTIME_STORE_COMMAND_CAPACITY
        {
            return Err(RuntimeStoreError::InvalidConfig(
                "command capacity must be between 1 and 1024",
            ));
        }
        if config.conversation_capacity == 0
            || config.conversation_capacity > crate::runtime::model::MAX_RUNTIME_CONVERSATIONS
        {
            return Err(RuntimeStoreError::InvalidConfig(
                "conversation capacity must be between 1 and 1024",
            ));
        }
        if config.busy_timeout_ms == 0 || config.busy_timeout_ms > MAX_RUNTIME_BUSY_TIMEOUT_MS {
            return Err(RuntimeStoreError::InvalidConfig(
                "busy timeout must be between 1 and 30000 milliseconds",
            ));
        }
        if config.lane_byte_capacity == 0
            || config.lane_byte_capacity > MAX_RUNTIME_STORE_LANE_BYTE_CAPACITY
        {
            return Err(RuntimeStoreError::InvalidConfig(
                "lane byte capacity must be between 1 and 268435456",
            ));
        }
        let shutdown_timeout = Duration::from_millis(
            config
                .busy_timeout_ms
                .saturating_add(RUNTIME_STORE_SHUTDOWN_GRACE_MS),
        );
        let normalized = sqlite::normalize_storage_path(&config.storage_path)?;
        let lease = claim_store_path(&normalized)?;
        let identity_derivation = Arc::new(RuntimeIdentityDerivationCapability::from_storage_kek(
            &storage_kek,
        )?);
        let native_projection_scan_epoch = Arc::new(AtomicU64::new(0));
        #[cfg(test)]
        let test_fd_permit = test_admission::acquire().await?;
        let (normal_tx, normal_rx) = mpsc::channel(config.command_capacity);
        let (safety_tx, safety_rx) = mpsc::channel(config.command_capacity);
        let (read_tx, read_rx) = mpsc::channel(config.command_capacity);
        let (control_tx, control_rx) = mpsc::channel(1);
        let normal_budget = Arc::new(Semaphore::new(config.lane_byte_capacity));
        let safety_budget = Arc::new(Semaphore::new(config.lane_byte_capacity));
        let execution_event_build_permit = Arc::new(Semaphore::new(1));
        let lifecycle = Arc::new(AtomicU8::new(LIFECYCLE_RUNNING));
        let worker_lifecycle = lifecycle.clone();
        let (ready_tx, ready_rx) = oneshot::channel();
        std::thread::Builder::new()
            .name("agentdeck-runtime-store".to_owned())
            .spawn(move || {
                run(
                    config,
                    storage_kek,
                    WorkerReceivers {
                        normal: normal_rx,
                        safety: safety_rx,
                        read: read_rx,
                        control: control_rx,
                        ready: ready_tx,
                    },
                    lease,
                    worker_lifecycle,
                    #[cfg(test)]
                    test_fd_permit,
                );
            })?;
        match ready_rx.await {
            Ok(Ok(ready)) => Ok(Self {
                normal_tx,
                safety_tx,
                read_tx,
                control_tx,
                normal_budget,
                safety_budget,
                execution_event_build_permit,
                lifecycle,
                interrupt: ready.interrupt,
                read_pool: ready.read_pool,
                read_crypto: ready.read_crypto,
                database_id: ready.database_id,
                identity_derivation,
                native_projection_scan_epoch,
                shutdown_timeout,
            }),
            Ok(Err(error)) => Err(error),
            Err(_) => Err(RuntimeStoreError::WorkerStopped),
        }
    }

    pub(in crate::runtime) fn machine_trust_domain(&self) -> Result<[u8; 32], RuntimeStoreError> {
        self.identity_derivation.derive_machine_trust_domain()
    }

    /// 只供 daemon-private machine re-enrollment 把新 Keychain guard 绑定到
    /// 已认证 Store 实例；不是 wire/database locator API。
    pub(crate) const fn authenticated_database_id(&self) -> [u8; 16] {
        self.database_id
    }

    pub(in crate::runtime) fn derive_native_history_command_id(
        &self,
        conversation_id: RuntimeId,
        turn_key: &[u8; 32],
    ) -> Result<RuntimeId, NativeHistoryIdentityError> {
        self.identity_derivation
            .derive_native_history_command_id(conversation_id, turn_key)
    }

    pub(in crate::runtime) fn derive_native_history_item_ids(
        &self,
        conversation_id: RuntimeId,
        item_key: &[u8; 32],
    ) -> Result<([u8; 16], [u8; 16]), NativeHistoryIdentityError> {
        self.identity_derivation
            .derive_native_history_item_ids(conversation_id, item_key)
    }

    #[cfg(test)]
    pub(super) fn native_projection_identity_candidates_for_test(
        &self,
        private_reference: &[u8],
        scan_generation: [u8; 16],
    ) -> Result<Vec<(RuntimeId, RuntimeId)>, RuntimeStoreError> {
        let (candidates, _observation_token) =
            self.identity_derivation.derive_native_projection_material(
                AdapterStateNamespace::ClaudeCode,
                private_reference,
                &scan_generation,
            )?;
        Ok(candidates
            .into_iter()
            .map(|candidate| (candidate.conversation_id, candidate.adapter_state_key))
            .collect())
    }

    pub(in crate::runtime) fn derive_start_identity(
        &self,
        owner: &crate::runtime::model::IdempotencyOwner,
        idempotency_key: &str,
    ) -> Result<(RuntimeId, RuntimeId), RuntimeStoreError> {
        if idempotency_key.is_empty() || idempotency_key.len() > MAX_IDEMPOTENCY_KEY_BYTES {
            return Err(RuntimeStoreError::InvalidConfig(
                "idempotency key must contain 1 to 1024 UTF-8 bytes",
            ));
        }
        self.identity_derivation
            .derive_start_identity(owner, idempotency_key)
    }

    pub async fn inspect(&self) -> Result<RuntimeStoreSnapshot, RuntimeStoreError> {
        dispatch(
            &self.read_tx,
            &self.lifecycle,
            RuntimeStoreLane::Read,
            |reply| ReadCommand::Inspect { reply },
        )
        .await?
    }

    pub async fn load_machine_identity_state(
        &self,
    ) -> Result<Option<MachineIdentityStateRecord>, RuntimeStoreError> {
        dispatch(
            &self.read_tx,
            &self.lifecycle,
            RuntimeStoreLane::Read,
            |reply| ReadCommand::LoadMachineIdentityState { reply },
        )
        .await?
    }

    pub async fn prepare_machine_identity(
        &self,
        binding: MachineIdentityBinding,
    ) -> Result<PrepareMachineIdentityOutcome, RuntimeStoreError> {
        dispatch_with_budget(
            &self.safety_tx,
            &self.safety_budget,
            &self.lifecycle,
            RuntimeStoreLane::Safety,
            memory_charge(size_of::<SafetyCommand>(), &[])?,
            |reply| SafetyCommand::PrepareMachineIdentity { binding, reply },
        )
        .await?
    }

    pub async fn activate_machine_identity(
        &self,
        binding: MachineIdentityBinding,
    ) -> Result<ActivateMachineIdentityOutcome, RuntimeStoreError> {
        dispatch_with_budget(
            &self.safety_tx,
            &self.safety_budget,
            &self.lifecycle,
            RuntimeStoreLane::Safety,
            memory_charge(size_of::<SafetyCommand>(), &[])?,
            |reply| SafetyCommand::ActivateMachineIdentity { binding, reply },
        )
        .await?
    }

    pub async fn load_machine_enrollment_state(
        &self,
    ) -> Result<Option<MachineEnrollmentState>, RuntimeStoreError> {
        dispatch(
            &self.read_tx,
            &self.lifecycle,
            RuntimeStoreLane::Read,
            |reply| ReadCommand::LoadMachineEnrollmentState { reply },
        )
        .await?
    }

    pub async fn prepare_machine_enrollment(
        &self,
        bundle: agentdeck_protocol::relay_v2::EnrollmentBundleV2,
        machine_route: agentdeck_protocol::relay_v2::MachineRouteId,
        binding: MachineIdentityBinding,
        link_cert: agentdeck_protocol::relay_v2::SignedCertificate,
        data_cert: agentdeck_protocol::relay_v2::SignedCertificate,
    ) -> Result<PrepareMachineEnrollmentOutcome, RuntimeStoreError> {
        let prepared =
            machine_remote::prepare_write(bundle, machine_route, binding, link_cert, data_cert)?;
        let retained = prepared.retained_capacity();
        dispatch_with_budget(
            &self.safety_tx,
            &self.safety_budget,
            &self.lifecycle,
            RuntimeStoreLane::Safety,
            memory_charge(size_of::<SafetyCommand>(), &[retained])?,
            |reply| SafetyCommand::PrepareMachineEnrollment {
                prepared: Box::new(prepared),
                reply,
            },
        )
        .await?
    }

    pub async fn record_validated_enrollment_response(
        &self,
        expected_request_hash: [u8; 32],
        response: agentdeck_protocol::relay_v2::MachineEnrollmentResponseV1,
    ) -> Result<RecordValidatedEnrollmentResponseOutcome, RuntimeStoreError> {
        let prepared = machine_remote::prepare_response_write(expected_request_hash, response)?;
        dispatch_with_budget(
            &self.safety_tx,
            &self.safety_budget,
            &self.lifecycle,
            RuntimeStoreLane::Safety,
            memory_charge(size_of::<SafetyCommand>(), &[])?,
            |reply| SafetyCommand::RecordValidatedEnrollmentResponse { prepared, reply },
        )
        .await?
    }

    pub async fn activate_machine_enrollment(
        &self,
        expected_request_hash: [u8; 32],
        expected_response_hash: [u8; 32],
    ) -> Result<ActivateMachineEnrollmentOutcome, RuntimeStoreError> {
        dispatch_with_budget(
            &self.safety_tx,
            &self.safety_budget,
            &self.lifecycle,
            RuntimeStoreLane::Safety,
            memory_charge(size_of::<SafetyCommand>(), &[])?,
            |reply| SafetyCommand::ActivateMachineEnrollment {
                expected_request_hash,
                expected_response_hash,
                reply,
            },
        )
        .await?
    }

    pub async fn prepare_machine_retirement(
        &self,
        retirement: agentdeck_protocol::relay_v2::frame::RetireMachine,
    ) -> Result<PrepareMachineRetirementOutcome, RuntimeStoreError> {
        let prepared = machine_remote::prepare_retirement_write(retirement)?;
        let retained = prepared.retained_capacity();
        dispatch_with_budget(
            &self.safety_tx,
            &self.safety_budget,
            &self.lifecycle,
            RuntimeStoreLane::Safety,
            memory_charge(size_of::<SafetyCommand>(), &[retained])?,
            |reply| SafetyCommand::PrepareMachineRetirement { prepared, reply },
        )
        .await?
    }

    pub async fn record_machine_retirement_terminal(
        &self,
        canonical_frame_bytes: Vec<u8>,
        canonical_frame_hash: [u8; 32],
    ) -> Result<RecordMachineRetirementTerminalOutcome, RuntimeStoreError> {
        let prepared =
            machine_remote::prepare_terminal_write(canonical_frame_bytes, canonical_frame_hash)?;
        let retained = prepared.retained_capacity();
        dispatch_with_budget(
            &self.safety_tx,
            &self.safety_budget,
            &self.lifecycle,
            RuntimeStoreLane::Safety,
            memory_charge(size_of::<SafetyCommand>(), &[retained])?,
            |reply| SafetyCommand::RecordMachineRetirementTerminal { prepared, reply },
        )
        .await?
    }

    pub async fn confirm_machine_purge_readback_absent(
        &self,
        canonical_frame_bytes: Vec<u8>,
        canonical_frame_hash: [u8; 32],
    ) -> Result<ConfirmMachinePurgeReadbackAbsentOutcome, RuntimeStoreError> {
        let prepared =
            machine_remote::prepare_terminal_write(canonical_frame_bytes, canonical_frame_hash)?;
        let retained = prepared.retained_capacity();
        dispatch_with_budget(
            &self.safety_tx,
            &self.safety_budget,
            &self.lifecycle,
            RuntimeStoreLane::Safety,
            memory_charge(size_of::<SafetyCommand>(), &[retained])?,
            |reply| SafetyCommand::ConfirmMachinePurgeReadbackAbsent { prepared, reply },
        )
        .await?
    }

    pub async fn record_root_lost_machine_purge(
        &self,
        receipt: agentdeck_protocol::relay_v2::RelayAdminPurgeReceiptV1,
    ) -> Result<RecordRootLostMachinePurgeOutcome, RuntimeStoreError> {
        let prepared = machine_remote::prepare_root_lost_purge_write(receipt)?;
        let retained = prepared.retained_capacity();
        dispatch_with_budget(
            &self.safety_tx,
            &self.safety_budget,
            &self.lifecycle,
            RuntimeStoreLane::Safety,
            memory_charge(size_of::<SafetyCommand>(), &[retained])?,
            |reply| SafetyCommand::RecordRootLostMachinePurge {
                prepared: Box::new(prepared),
                reply,
            },
        )
        .await?
    }

    pub async fn finalize_machine_local_deletion(
        &self,
        expected_reset_kind: MachineTrustResetKind,
        expected_purge_proof_hash: [u8; 32],
        cleanup_witness_hash: [u8; 32],
    ) -> Result<FinalizeMachineLocalDeletionOutcome, RuntimeStoreError> {
        dispatch_with_budget(
            &self.safety_tx,
            &self.safety_budget,
            &self.lifecycle,
            RuntimeStoreLane::Safety,
            memory_charge(size_of::<SafetyCommand>(), &[])?,
            |reply| SafetyCommand::FinalizeMachineLocalDeletion {
                expected_reset_kind,
                expected_purge_proof_hash,
                cleanup_witness_hash,
                reply,
            },
        )
        .await?
    }

    pub(in crate::runtime) fn codex_adapter_state_vault(&self) -> CodexAdapterStateVault {
        CodexAdapterStateVault {
            store: self.clone(),
        }
    }

    #[cfg(test)]
    pub(crate) fn codex_adapter_state_vault_for_test(&self) -> CodexAdapterStateVault {
        self.codex_adapter_state_vault()
    }

    pub(in crate::runtime) fn claude_code_adapter_state_vault(
        &self,
    ) -> ClaudeCodeAdapterStateVault {
        ClaudeCodeAdapterStateVault {
            store: self.clone(),
        }
    }

    pub(in crate::runtime) fn claude_code_native_projection_store(
        &self,
    ) -> ClaudeCodeNativeProjectionStore {
        ClaudeCodeNativeProjectionStore {
            store: self.clone(),
        }
    }

    async fn import_native_projection(
        &self,
        namespace: AdapterStateNamespace,
        input: native_projection::ImportNativeProjection,
    ) -> Result<native_projection::ImportNativeProjectionOutcome, RuntimeStoreError> {
        let native_projection::ImportNativeProjection {
            descriptor,
            default_configuration,
            private_reference,
            scan_generation,
        } = input;
        if descriptor.agent_kind != namespace.agent_kind() {
            return Err(RuntimeStoreError::AdapterStateNamespaceMismatch);
        }
        if scan_generation == [0; 16] {
            return Err(RuntimeStoreError::InvalidConfig(
                "native projection scan generation must not be zero",
            ));
        }
        let reference_len = private_reference.expose_secret().len();
        if !(native_projection::MIN_NATIVE_PRIVATE_REFERENCE_BYTES
            ..=native_projection::MAX_NATIVE_PRIVATE_REFERENCE_BYTES)
            .contains(&reference_len)
        {
            return Err(RuntimeStoreError::InvalidConfig(
                "native projection reference must contain 20 to 523 bytes",
            ));
        }
        let descriptor_bytes = journal::canonical_conversation_descriptor(&descriptor)?;
        validate_maximum(descriptor_bytes.len(), MAX_CONVERSATION_DESCRIPTOR_BYTES)?;
        let default_configuration = configuration::prepare_native_projector_configuration(
            namespace,
            default_configuration,
        )?;

        let mut canonical_reference = Vec::new();
        canonical_reference
            .try_reserve_exact(reference_len)
            .map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
        canonical_reference.extend_from_slice(private_reference.expose_secret());
        drop(private_reference);
        let private_reference_capacity = canonical_reference.capacity();
        let (identity_candidates, observation_token) = self
            .identity_derivation
            .derive_native_projection_material(namespace, &canonical_reference, &scan_generation)?;
        let prepared = native_projection::PreparedNativeProjectionImport {
            descriptor,
            descriptor_bytes,
            default_configuration,
            private_reference: SecretBytes::new(canonical_reference),
            private_reference_capacity,
            scan_generation,
            observation_token,
            identity_candidates,
        };
        let charge = memory_charge(size_of::<NormalCommand>(), &[prepared.retained_capacity()?])?;
        dispatch_with_budget(
            &self.normal_tx,
            &self.normal_budget,
            &self.lifecycle,
            RuntimeStoreLane::Normal,
            charge,
            |reply| NormalCommand::ImportNativeProjection {
                prepared,
                epoch_source: self.native_projection_scan_epoch.clone(),
                reply,
            },
        )
        .await?
    }

    pub async fn record_machine_enrollment_receipt(
        &self,
        receipt: MachineEnrollmentReceiptRecord,
    ) -> Result<MachineEnrollmentReceiptRecord, RuntimeStoreError> {
        dispatch_with_budget(
            &self.safety_tx,
            &self.safety_budget,
            &self.lifecycle,
            RuntimeStoreLane::Safety,
            memory_charge(size_of::<SafetyCommand>(), &[])?,
            |reply| SafetyCommand::RecordEnrollmentReceipt { receipt, reply },
        )
        .await?
    }

    pub async fn create_conversation(
        &self,
        input: NewConversation,
    ) -> Result<ConversationRecord, RuntimeStoreError> {
        match self.create_conversation_idempotent(input).await? {
            CreateConversationOutcome::Created { conversation }
            | CreateConversationOutcome::Replayed { conversation } => Ok(conversation),
        }
    }

    pub async fn create_conversation_idempotent(
        &self,
        input: NewConversation,
    ) -> Result<CreateConversationOutcome, RuntimeStoreError> {
        let descriptor_bytes = journal::canonical_conversation_descriptor(&input.descriptor)?;
        validate_maximum(descriptor_bytes.len(), MAX_CONVERSATION_DESCRIPTOR_BYTES)?;
        let charge = memory_charge(
            size_of::<NormalCommand>(),
            &[
                input.descriptor.title.as_ref().map_or(0, String::capacity),
                input.descriptor.cwd.capacity(),
                descriptor_bytes.capacity(),
            ],
        )?;
        dispatch_with_budget(
            &self.normal_tx,
            &self.normal_budget,
            &self.lifecycle,
            RuntimeStoreLane::Normal,
            charge,
            |reply| NormalCommand::CreateConversation {
                input,
                descriptor_bytes,
                reply,
            },
        )
        .await?
    }

    pub async fn configure_conversation(
        &self,
        input: ConfigureConversation,
    ) -> Result<ConfigureConversationOutcome, RuntimeStoreError> {
        self.configure_conversation_inner(input, None).await
    }

    /// 威胁场景：transport caller 在已入队的 Configure COMMIT 前被取消时，
    /// caller 栈上的授权会提前释放，使 revoke 与 durable mutation 失去顺序保证。
    pub(crate) async fn configure_conversation_authorized(
        &self,
        input: ConfigureConversation,
        authorization: AuthorizationGuard,
    ) -> Result<ConfigureConversationOutcome, RuntimeStoreError> {
        self.configure_conversation_inner(input, Some(authorization))
            .await
    }

    async fn configure_conversation_inner(
        &self,
        input: ConfigureConversation,
        authorization: Option<AuthorizationGuard>,
    ) -> Result<ConfigureConversationOutcome, RuntimeStoreError> {
        let prepared = configuration::prepare_configuration_request(input)?;
        let charge = memory_charge(size_of::<NormalCommand>(), &[prepared.retained_capacity()?])?;
        dispatch_with_budget(
            &self.normal_tx,
            &self.normal_budget,
            &self.lifecycle,
            RuntimeStoreLane::Normal,
            charge,
            |reply| NormalCommand::ConfigureConversation {
                prepared,
                authorization,
                reply,
            },
        )
        .await?
    }

    pub async fn accept_admin_upgrade(
        &self,
        request: agentdeck_protocol::runtime::StageUpgradeRequest,
    ) -> Result<admin::AcceptAdminUpgradeOutcome, RuntimeStoreError> {
        let prepared = admin::prepare_admin_upgrade_request(request)?;
        let charge = memory_charge(size_of::<NormalCommand>(), &[prepared.retained_capacity()])?;
        dispatch_with_budget(
            &self.normal_tx,
            &self.normal_budget,
            &self.lifecycle,
            RuntimeStoreLane::Normal,
            charge,
            |reply| NormalCommand::AcceptAdminUpgrade { prepared, reply },
        )
        .await?
    }

    pub async fn query_admin_upgrade(
        &self,
        request: agentdeck_protocol::runtime::StageUpgradeRequest,
    ) -> Result<Option<admin::AdminUpgradeCommand>, RuntimeStoreError> {
        let prepared = admin::prepare_admin_upgrade_request(request)?;
        let charge = memory_charge(size_of::<NormalCommand>(), &[prepared.retained_capacity()])?;
        dispatch_with_budget(
            &self.normal_tx,
            &self.normal_budget,
            &self.lifecycle,
            RuntimeStoreLane::Normal,
            charge,
            |reply| NormalCommand::QueryAdminUpgrade { prepared, reply },
        )
        .await?
    }

    pub async fn active_started_command_count(&self) -> Result<u32, RuntimeStoreError> {
        dispatch_with_budget(
            &self.normal_tx,
            &self.normal_budget,
            &self.lifecycle,
            RuntimeStoreLane::Normal,
            memory_charge(size_of::<NormalCommand>(), &[])?,
            |reply| NormalCommand::ActiveStartedCommandCount { reply },
        )
        .await?
    }

    pub async fn finalize_admin_upgrade(
        &self,
        command: admin::AdminUpgradeCommand,
        terminal: admin::AdminUpgradeTerminalOutcome,
    ) -> Result<admin::FinalizeAdminUpgradeOutcome, RuntimeStoreError> {
        let retained = match &terminal {
            admin::AdminUpgradeTerminalOutcome::Completed => 0,
            admin::AdminUpgradeTerminalOutcome::Failed { failure } => failure
                .code
                .capacity()
                .checked_add(failure.message.capacity())
                .and_then(|value| {
                    value.checked_add(failure.diagnostic_ref.as_ref().map_or(0, String::capacity))
                })
                .ok_or(RuntimeStoreError::PayloadTooLarge)?,
        };
        dispatch_with_budget(
            &self.safety_tx,
            &self.safety_budget,
            &self.lifecycle,
            RuntimeStoreLane::Safety,
            memory_charge(size_of::<SafetyCommand>(), &[retained])?,
            |reply| SafetyCommand::FinalizeAdminUpgrade {
                command,
                terminal,
                reply,
            },
        )
        .await?
    }

    pub async fn load_pending_admin_upgrades(
        &self,
        cursor: Option<admin::AdminUpgradeRecoveryCursor>,
    ) -> Result<admin::AdminUpgradeRecoveryPage, RuntimeStoreError> {
        dispatch(
            &self.read_tx,
            &self.lifecycle,
            RuntimeStoreLane::Read,
            |reply| ReadCommand::LoadPendingAdminUpgrades { cursor, reply },
        )
        .await?
    }

    pub async fn update_managed_conversation_metadata(
        &self,
        input: UpdateManagedConversationMetadata,
    ) -> Result<UpdateConversationMetadataOutcome, RuntimeStoreError> {
        self.update_managed_conversation_metadata_inner(input, None)
            .await
    }

    pub(crate) async fn update_managed_conversation_metadata_authorized(
        &self,
        input: UpdateManagedConversationMetadata,
        authorization: AuthorizationGuard,
    ) -> Result<UpdateConversationMetadataOutcome, RuntimeStoreError> {
        self.update_managed_conversation_metadata_inner(input, Some(authorization))
            .await
    }

    async fn update_managed_conversation_metadata_inner(
        &self,
        input: UpdateManagedConversationMetadata,
        authorization: Option<AuthorizationGuard>,
    ) -> Result<UpdateConversationMetadataOutcome, RuntimeStoreError> {
        let prepared = metadata::prepare_metadata_mutation_request(input)?;
        let charge = memory_charge(size_of::<NormalCommand>(), &[prepared.retained_capacity()?])?;
        dispatch_with_budget(
            &self.normal_tx,
            &self.normal_budget,
            &self.lifecycle,
            RuntimeStoreLane::Normal,
            charge,
            |reply| NormalCommand::UpdateConversationMetadata {
                prepared,
                authorization,
                reply,
            },
        )
        .await?
    }

    pub(in crate::runtime) async fn claim_native_conversation_metadata(
        &self,
        input: UpdateManagedConversationMetadata,
    ) -> Result<ClaimNativeMetadataMutationOutcome, RuntimeStoreError> {
        let prepared = metadata::prepare_metadata_mutation_request(input)?;
        let charge = memory_charge(size_of::<NormalCommand>(), &[prepared.retained_capacity()?])?;
        dispatch_with_budget(
            &self.normal_tx,
            &self.normal_budget,
            &self.lifecycle,
            RuntimeStoreLane::Normal,
            charge,
            |reply| NormalCommand::ClaimNativeMetadataMutation { prepared, reply },
        )
        .await?
    }

    pub(in crate::runtime) async fn fail_claimed_native_metadata_mutation(
        &self,
        mutation: NativeMetadataMutationClaim,
        failure: agentdeck_protocol::runtime::RuntimeFailure,
    ) -> Result<UpdateConversationMetadataOutcome, RuntimeStoreError> {
        let charge = memory_charge(
            size_of::<SafetyCommand>(),
            &[
                failure.code.capacity(),
                failure.message.capacity(),
                failure.diagnostic_ref.as_ref().map_or(0, String::capacity),
            ],
        )?;
        dispatch_with_budget(
            &self.safety_tx,
            &self.safety_budget,
            &self.lifecycle,
            RuntimeStoreLane::Safety,
            charge,
            |reply| SafetyCommand::FailClaimedNativeMetadataMutation {
                mutation,
                failure,
                reply,
            },
        )
        .await?
    }

    pub(in crate::runtime) async fn mark_native_metadata_mutation_outcome_unknown(
        &self,
        mutation: NativeMetadataMutationClaim,
    ) -> Result<NativeMetadataMutationClaim, RuntimeStoreError> {
        dispatch_with_budget(
            &self.safety_tx,
            &self.safety_budget,
            &self.lifecycle,
            RuntimeStoreLane::Safety,
            memory_charge(size_of::<SafetyCommand>(), &[])?,
            |reply| SafetyCommand::MarkNativeMetadataMutationOutcomeUnknown { mutation, reply },
        )
        .await?
    }

    pub(in crate::runtime) async fn finalize_native_metadata_mutation_readback(
        &self,
        mutation: NativeMetadataMutationClaim,
        readback: NativeMetadataMutationReadback,
    ) -> Result<UpdateConversationMetadataOutcome, RuntimeStoreError> {
        let retained = match &readback {
            NativeMetadataMutationReadback::Applied { observed_title } => {
                observed_title.as_ref().map_or(0, String::capacity)
            }
            NativeMetadataMutationReadback::Failed { failure } => failure
                .code
                .capacity()
                .checked_add(failure.message.capacity())
                .and_then(|value| {
                    value.checked_add(failure.diagnostic_ref.as_ref().map_or(0, String::capacity))
                })
                .ok_or(RuntimeStoreError::PayloadTooLarge)?,
            NativeMetadataMutationReadback::Inconclusive => 0,
        };
        dispatch_with_budget(
            &self.safety_tx,
            &self.safety_budget,
            &self.lifecycle,
            RuntimeStoreLane::Safety,
            memory_charge(size_of::<SafetyCommand>(), &[retained])?,
            |reply| SafetyCommand::FinalizeNativeMetadataMutationReadback {
                mutation,
                readback,
                reply,
            },
        )
        .await?
    }

    pub(in crate::runtime) async fn load_active_native_metadata_mutations(
        &self,
        cursor: Option<NativeMetadataMutationRecoveryCursor>,
    ) -> Result<NativeMetadataMutationRecoveryPage, RuntimeStoreError> {
        dispatch(
            &self.read_tx,
            &self.lifecycle,
            RuntimeStoreLane::Read,
            |reply| ReadCommand::LoadActiveNativeMetadataMutations { cursor, reply },
        )
        .await?
    }

    pub(in crate::runtime) async fn load_native_metadata_effect_recovery_record(
        &self,
        mutation: NativeMetadataMutationClaim,
    ) -> Result<native_projection::NativeMetadataEffectRecoveryRecord, RuntimeStoreError> {
        dispatch(
            &self.read_tx,
            &self.lifecycle,
            RuntimeStoreLane::Read,
            |reply| ReadCommand::LoadNativeMetadataEffectRecoveryRecord { mutation, reply },
        )
        .await?
    }

    pub(in crate::runtime) async fn persist_native_metadata_effect_fence(
        &self,
        input: native_projection::PersistNativeMetadataEffectFence,
    ) -> Result<native_projection::PersistNativeMetadataEffectFenceOutcome, RuntimeStoreError> {
        let native_projection::PersistNativeMetadataEffectFence {
            mutation,
            daemon_boot_id,
            effect_nonce,
            effect_spec,
            process,
        } = input;
        let effect_nonce =
            exact_bounded_secret_vec(effect_nonce, native_projection::MAX_EFFECT_NONCE_BYTES)?;
        let effect_spec =
            exact_bounded_secret_vec(effect_spec, native_projection::MAX_EFFECT_SPEC_BYTES)?;
        let charge = memory_charge(
            size_of::<SafetyCommand>(),
            &[
                mutation.retained_capacity(),
                effect_nonce.capacity(),
                effect_spec.capacity(),
            ],
        )?;
        let input = native_projection::PersistNativeMetadataEffectFence {
            mutation,
            daemon_boot_id,
            effect_nonce,
            effect_spec,
            process,
        };
        dispatch_with_budget(
            &self.safety_tx,
            &self.safety_budget,
            &self.lifecycle,
            RuntimeStoreLane::Safety,
            charge,
            |reply| SafetyCommand::PersistNativeMetadataEffectFence { input, reply },
        )
        .await?
    }

    pub(in crate::runtime) async fn authorize_native_metadata_effect_release(
        &self,
        input: native_projection::AuthorizeNativeMetadataEffectRelease,
    ) -> Result<native_projection::AuthorizeNativeMetadataEffectReleaseOutcome, RuntimeStoreError>
    {
        let native_projection::AuthorizeNativeMetadataEffectRelease {
            mutation,
            daemon_boot_id,
            effect_nonce,
            release_token_commitment,
        } = input;
        let effect_nonce =
            exact_bounded_secret_vec(effect_nonce, native_projection::MAX_EFFECT_NONCE_BYTES)?;
        let charge = memory_charge(
            size_of::<SafetyCommand>(),
            &[mutation.retained_capacity(), effect_nonce.capacity()],
        )?;
        let input = native_projection::AuthorizeNativeMetadataEffectRelease {
            mutation,
            daemon_boot_id,
            effect_nonce,
            release_token_commitment,
        };
        dispatch_with_budget(
            &self.safety_tx,
            &self.safety_budget,
            &self.lifecycle,
            RuntimeStoreLane::Safety,
            charge,
            |reply| SafetyCommand::AuthorizeNativeMetadataEffectRelease { input, reply },
        )
        .await?
    }

    pub(in crate::runtime) async fn fail_unreleased_native_metadata_effect(
        &self,
        input: native_projection::FailUnreleasedNativeMetadataEffect,
    ) -> Result<UpdateConversationMetadataOutcome, RuntimeStoreError> {
        let native_projection::FailUnreleasedNativeMetadataEffect {
            cleanup_authority,
            mutation,
            daemon_boot_id,
            effect_nonce,
            effect_spec,
            process,
            failure,
        } = input;
        let effect_nonce =
            exact_bounded_secret_vec(effect_nonce, native_projection::MAX_EFFECT_NONCE_BYTES)?;
        let effect_spec =
            exact_bounded_secret_vec(effect_spec, native_projection::MAX_EFFECT_SPEC_BYTES)?;
        let retained_failure = failure
            .code
            .capacity()
            .checked_add(failure.message.capacity())
            .and_then(|value| {
                value.checked_add(failure.diagnostic_ref.as_ref().map_or(0, String::capacity))
            })
            .ok_or(RuntimeStoreError::PayloadTooLarge)?;
        let charge = memory_charge(
            size_of::<SafetyCommand>(),
            &[
                mutation.retained_capacity(),
                effect_nonce.capacity(),
                effect_spec.capacity(),
                retained_failure,
            ],
        )?;
        let input = native_projection::FailUnreleasedNativeMetadataEffect {
            cleanup_authority,
            mutation,
            daemon_boot_id,
            effect_nonce,
            effect_spec,
            process,
            failure,
        };
        dispatch_with_budget(
            &self.safety_tx,
            &self.safety_budget,
            &self.lifecycle,
            RuntimeStoreLane::Safety,
            charge,
            |reply| SafetyCommand::FailUnreleasedNativeMetadataEffect { input, reply },
        )
        .await?
    }

    async fn bind_adapter_state(
        &self,
        namespace: AdapterStateNamespace,
        adapter_state_key: super::RuntimeId,
        state_reference: SecretBytes,
    ) -> Result<(), RuntimeStoreError> {
        if state_reference.expose_secret().is_empty()
            || state_reference.expose_secret().len() > MAX_ADAPTER_STATE_REFERENCE_BYTES
        {
            return Err(RuntimeStoreError::InvalidConfig(
                "adapter state reference must contain 1 to 4096 bytes",
            ));
        }
        // SecretBytes 不暴露原 Vec capacity；先复制到本调用自有的 exact-reserve
        // buffer 并立即销毁调用方 allocation，避免 short-len/huge-capacity 绕过
        // normal lane retained-allocation 预算。
        let mut canonical_reference = Vec::new();
        canonical_reference
            .try_reserve_exact(state_reference.expose_secret().len())
            .map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
        canonical_reference.extend_from_slice(state_reference.expose_secret());
        drop(state_reference);
        let retained_capacity = canonical_reference.capacity();
        let state_reference = SecretBytes::new(canonical_reference);
        let charge = memory_charge(size_of::<NormalCommand>(), &[retained_capacity])?;
        dispatch_with_budget(
            &self.normal_tx,
            &self.normal_budget,
            &self.lifecycle,
            RuntimeStoreLane::Normal,
            charge,
            |reply| NormalCommand::BindAdapterState {
                namespace,
                adapter_state_key,
                state_reference,
                reply,
            },
        )
        .await?
    }

    async fn resolve_adapter_state(
        &self,
        namespace: AdapterStateNamespace,
        adapter_state_key: super::RuntimeId,
    ) -> Result<Option<SecretBytes>, RuntimeStoreError> {
        dispatch(
            &self.read_tx,
            &self.lifecycle,
            RuntimeStoreLane::Read,
            |reply| ReadCommand::ResolveAdapterState {
                namespace,
                adapter_state_key,
                reply,
            },
        )
        .await?
    }

    pub async fn accept_command(
        &self,
        input: AcceptCommand,
    ) -> Result<AcceptOutcome, RuntimeStoreError> {
        let charge = accept_command_memory_charge(&input)?;
        dispatch_with_budget(
            &self.normal_tx,
            &self.normal_budget,
            &self.lifecycle,
            RuntimeStoreLane::Normal,
            charge,
            |reply| NormalCommand::AcceptCommand {
                input,
                reply: AcceptCommandReply::Direct(reply),
            },
        )
        .await?
    }

    /// Core transport caller 的 authorization 必须转移进 Store queue；即使 caller 或
    /// prompt worker 在入队后被取消，guard 也会覆盖 durable mutation 与通知。
    pub(crate) async fn accept_command_authorized(
        &self,
        input: AcceptCommand,
        authorization: AuthorizationGuard,
    ) -> Result<AuthorizedAcceptOutcome, RuntimeStoreError> {
        let charge = accept_command_memory_charge(&input)?;
        dispatch_with_budget(
            &self.normal_tx,
            &self.normal_budget,
            &self.lifecycle,
            RuntimeStoreLane::Normal,
            charge,
            |reply| NormalCommand::AcceptCommand {
                input,
                reply: AcceptCommandReply::Authorized {
                    authorization,
                    reply,
                },
            },
        )
        .await?
    }

    pub(in crate::runtime) async fn register_approval(
        &self,
        input: RegisterApproval,
    ) -> Result<RegisterApprovalOutcome, RuntimeStoreError> {
        let charge = memory_charge(
            size_of::<NormalCommand>(),
            &[
                input.request.request_id.capacity(),
                input.request.summary.capacity(),
            ],
        )?;
        dispatch_with_budget(
            &self.normal_tx,
            &self.normal_budget,
            &self.lifecycle,
            RuntimeStoreLane::Normal,
            charge,
            |reply| NormalCommand::RegisterApproval { input, reply },
        )
        .await?
    }

    pub(in crate::runtime) async fn claim_approval(
        &self,
        input: ClaimApproval,
    ) -> Result<ApprovalMutationOutcome, RuntimeStoreError> {
        let charge = memory_charge(
            size_of::<NormalCommand>(),
            &[
                input.decision.request_id.capacity(),
                input.claimant_binding.as_bytes().len(),
            ],
        )?;
        dispatch_with_budget(
            &self.normal_tx,
            &self.normal_budget,
            &self.lifecycle,
            RuntimeStoreLane::Normal,
            charge,
            |reply| NormalCommand::ClaimApproval { input, reply },
        )
        .await?
    }

    pub(in crate::runtime) async fn begin_approval_attempt(
        &self,
        input: BeginApprovalAttempt,
    ) -> Result<BeginApprovalAttemptOutcome, RuntimeStoreError> {
        let charge = memory_charge(size_of::<NormalCommand>(), &[])?;
        dispatch_with_budget(
            &self.normal_tx,
            &self.normal_budget,
            &self.lifecycle,
            RuntimeStoreLane::Normal,
            charge,
            |reply| NormalCommand::BeginApprovalAttempt { input, reply },
        )
        .await?
    }

    pub(in crate::runtime) async fn mark_approval_applied(
        &self,
        input: MarkApprovalApplied,
    ) -> Result<ApprovalMutationOutcome, RuntimeStoreError> {
        let charge = memory_charge(size_of::<SafetyCommand>(), &[])?;
        dispatch_with_budget(
            &self.safety_tx,
            &self.safety_budget,
            &self.lifecycle,
            RuntimeStoreLane::Safety,
            charge,
            |reply| SafetyCommand::MarkApprovalApplied { input, reply },
        )
        .await?
    }

    pub(in crate::runtime) async fn mark_approval_delivery_failed(
        &self,
        input: MarkApprovalDeliveryFailed,
    ) -> Result<ApprovalMutationOutcome, RuntimeStoreError> {
        validate_nonempty_maximum(&input.status_detail, MAX_APPROVAL_STATUS_DETAIL_BYTES)?;
        let charge = memory_charge(
            size_of::<SafetyCommand>(),
            &[input.status_detail.capacity()],
        )?;
        dispatch_with_budget(
            &self.safety_tx,
            &self.safety_budget,
            &self.lifecycle,
            RuntimeStoreLane::Safety,
            charge,
            |reply| SafetyCommand::MarkApprovalDeliveryFailed { input, reply },
        )
        .await?
    }

    pub(in crate::runtime) async fn retry_approval_delivery(
        &self,
        input: RetryApprovalDelivery,
    ) -> Result<ApprovalMutationOutcome, RuntimeStoreError> {
        let charge = memory_charge(size_of::<NormalCommand>(), &[])?;
        dispatch_with_budget(
            &self.normal_tx,
            &self.normal_budget,
            &self.lifecycle,
            RuntimeStoreLane::Normal,
            charge,
            |reply| NormalCommand::RetryApprovalDelivery { input, reply },
        )
        .await?
    }

    pub(in crate::runtime) async fn expire_approval(
        &self,
        input: ExpireApproval,
    ) -> Result<ApprovalMutationOutcome, RuntimeStoreError> {
        let charge = memory_charge(size_of::<SafetyCommand>(), &[])?;
        dispatch_with_budget(
            &self.safety_tx,
            &self.safety_budget,
            &self.lifecycle,
            RuntimeStoreLane::Safety,
            charge,
            |reply| SafetyCommand::ExpireApproval { input, reply },
        )
        .await?
    }

    pub async fn terminate_accepted_command(
        &self,
        input: TerminateAcceptedCommand,
    ) -> Result<TerminateAcceptedOutcome, RuntimeStoreError> {
        let charge = memory_charge(
            size_of::<SafetyCommand>(),
            &[MAX_CRITICAL_COMMAND_RECORD_BYTES],
        )?;
        dispatch_with_budget(
            &self.safety_tx,
            &self.safety_budget,
            &self.lifecycle,
            RuntimeStoreLane::Safety,
            charge,
            |reply| SafetyCommand::TerminateAccepted { input, reply },
        )
        .await?
    }

    pub async fn terminate_started_before_release(
        &self,
        input: TerminateStartedBeforeRelease,
    ) -> Result<TerminateStartedBeforeReleaseOutcome, RuntimeStoreError> {
        validate_nonempty_maximum(&input.execution_nonce, MAX_EXECUTION_NONCE_BYTES)?;
        let charge = memory_charge(
            size_of::<SafetyCommand>(),
            &[
                input.execution_nonce.capacity(),
                MAX_CRITICAL_COMMAND_RECORD_BYTES,
                MAX_CRITICAL_COMMAND_RECORD_BYTES,
            ],
        )?;
        dispatch_with_budget(
            &self.safety_tx,
            &self.safety_budget,
            &self.lifecycle,
            RuntimeStoreLane::Safety,
            charge,
            |reply| SafetyCommand::TerminateStartedBeforeRelease { input, reply },
        )
        .await?
    }

    pub async fn query_command_receipt(
        &self,
        input: QueryCommandReceipt,
    ) -> Result<CommandReceiptRecord, RuntimeStoreError> {
        if let CommandReceiptSelector::Idempotency {
            idempotency_key, ..
        } = &input.selector
            && (idempotency_key.is_empty() || idempotency_key.len() > MAX_IDEMPOTENCY_KEY_BYTES)
        {
            return Err(RuntimeStoreError::InvalidConfig(
                "idempotency key must contain 1 to 1024 UTF-8 bytes",
            ));
        }
        dispatch(
            &self.read_tx,
            &self.lifecycle,
            RuntimeStoreLane::Read,
            |reply| ReadCommand::QueryCommandReceipt { input, reply },
        )
        .await?
    }

    pub async fn persist_execution_fence(
        &self,
        input: ExecutionFence,
    ) -> Result<ExecutionFenceRecord, RuntimeStoreError> {
        validate_nonempty_maximum(&input.execution_nonce, MAX_EXECUTION_NONCE_BYTES)?;
        validate_maximum(input.payload.len(), MAX_EXECUTION_FENCE_BYTES)?;
        let charge = memory_charge(
            size_of::<SafetyCommand>(),
            &[input.execution_nonce.capacity(), input.payload.capacity()],
        )?;
        dispatch_with_budget(
            &self.safety_tx,
            &self.safety_budget,
            &self.lifecycle,
            RuntimeStoreLane::Safety,
            charge,
            |reply| SafetyCommand::PersistFence { input, reply },
        )
        .await?
    }

    pub async fn authorize_execution_release(
        &self,
        input: AuthorizeExecutionRelease,
    ) -> Result<ExecutionFenceRecord, RuntimeStoreError> {
        validate_nonempty_maximum(&input.execution_nonce, MAX_EXECUTION_NONCE_BYTES)?;
        let charge = memory_charge(
            size_of::<SafetyCommand>(),
            &[input.execution_nonce.capacity()],
        )?;
        dispatch_with_budget(
            &self.safety_tx,
            &self.safety_budget,
            &self.lifecycle,
            RuntimeStoreLane::Safety,
            charge,
            |reply| SafetyCommand::AuthorizeRelease { input, reply },
        )
        .await?
    }

    pub async fn complete_command_with_event(
        &self,
        input: CompleteCommand,
    ) -> Result<CompleteOutcome, RuntimeStoreError> {
        let charge = memory_charge(
            size_of::<SafetyCommand>(),
            &[MAX_CRITICAL_COMMAND_RECORD_BYTES; 2],
        )?;
        dispatch_with_budget(
            &self.safety_tx,
            &self.safety_budget,
            &self.lifecycle,
            RuntimeStoreLane::Safety,
            charge,
            |reply| SafetyCommand::CompleteCommand { input, reply },
        )
        .await?
    }

    pub async fn recover_started_command_with_event(
        &self,
        input: super::RecoverStartedCommand,
    ) -> Result<CompleteOutcome, RuntimeStoreError> {
        let retained = recovery_binding_retained_allocations(&input.expected_started);
        let charge = memory_charge(
            size_of::<SafetyCommand>(),
            &[
                MAX_CRITICAL_COMMAND_RECORD_BYTES,
                MAX_CRITICAL_COMMAND_RECORD_BYTES,
                retained[0],
                retained[1],
                retained[2],
            ],
        )?;
        dispatch_with_budget(
            &self.safety_tx,
            &self.safety_budget,
            &self.lifecycle,
            RuntimeStoreLane::Safety,
            charge,
            |reply| SafetyCommand::RecoverStartedCommand { input, reply },
        )
        .await?
    }

    pub async fn mark_conversation_recovery_blocked(
        &self,
        input: MarkConversationRecoveryBlocked,
    ) -> Result<ConversationRecord, RuntimeStoreError> {
        let retained = input
            .expected_command
            .as_ref()
            .map(recovery_binding_retained_allocations)
            .unwrap_or([0; 3]);
        let charge = memory_charge(size_of::<SafetyCommand>(), &retained)?;
        dispatch_with_budget(
            &self.safety_tx,
            &self.safety_budget,
            &self.lifecycle,
            RuntimeStoreLane::Safety,
            charge,
            |reply| SafetyCommand::MarkConversationRecoveryBlocked { input, reply },
        )
        .await?
    }

    /// 校验全库、先清扫过期 Accepted，再冻结本次 recovery catalog high-water。
    ///
    /// begin reply 丢失且尚未读取任何页时，重复调用会返回同一 opaque cursor。
    pub async fn begin_recovery_scan(&self) -> Result<RecoveryCursor, RuntimeStoreError> {
        dispatch(
            &self.read_tx,
            &self.lifecycle,
            RuntimeStoreLane::Read,
            |reply| ReadCommand::BeginRecoveryScan { reply },
        )
        .await?
    }

    pub(crate) async fn begin_recovery_verification_scan(
        &self,
    ) -> Result<RecoveryCursor, RuntimeStoreError> {
        dispatch(
            &self.read_tx,
            &self.lifecycle,
            RuntimeStoreLane::Read,
            |reply| ReadCommand::BeginRecoveryVerificationScan { reply },
        )
        .await?
    }

    /// 每次只物化一个 conversation；只能原样重试当前页或使用上一页返回的 cursor。
    pub async fn load_recovery_page(
        &self,
        cursor: RecoveryCursor,
    ) -> Result<RecoveryPage, RuntimeStoreError> {
        dispatch(
            &self.read_tx,
            &self.lifecycle,
            RuntimeStoreLane::Read,
            |reply| ReadCommand::LoadRecoveryPage { cursor, reply },
        )
        .await?
    }

    /// RuntimeCore 已消费终页后显式完成扫描；此前所有 durable mutation 均 fail-closed。
    pub async fn finish_recovery_scan(
        &self,
        completion: RecoveryCompletion,
    ) -> Result<(), RuntimeStoreError> {
        dispatch(
            &self.read_tx,
            &self.lifecycle,
            RuntimeStoreLane::Read,
            |reply| ReadCommand::FinishRecoveryScan { completion, reply },
        )
        .await?
    }

    /// 成功回执只在 connection、row keys 和 path lease 全部释放后发送。
    ///
    /// `ShutdownTimedOut` 只表示调用方未在 deadline 前观察到该回执；worker 仍处于
    /// shutting-down，资源继续由 worker 持有，直到 `run` 真正退出。
    pub async fn shutdown(self) -> Result<(), RuntimeStoreError> {
        match self.lifecycle.compare_exchange(
            LIFECYCLE_RUNNING,
            LIFECYCLE_SHUTTING_DOWN,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {}
            Err(LIFECYCLE_SHUTTING_DOWN) => return Err(RuntimeStoreError::ShutdownInProgress),
            Err(_) => return Err(RuntimeStoreError::WorkerStopped),
        }
        self.interrupt.interrupt();
        let (reply, result) = oneshot::channel();
        self.control_tx
            .try_send(ControlCommand::Shutdown { reply })
            .map_err(|_| RuntimeStoreError::WorkerStopped)?;
        await_shutdown_quiescence(result, self.shutdown_timeout).await
    }
}

/// 计算 recovery binding 随 SafetyCommand 一起留在队列中的全部堆分配。
///
/// 威胁场景：攻击者或异常恢复记录把大 capacity nonce 放进 boxed fence；若只计算
/// 外层 binding nonce，它可以绕过 safety-lane byte cap，并让队列实际内存超过门禁。
fn recovery_binding_retained_allocations(
    binding: &super::RecoveryBlockedCommandBinding,
) -> [usize; 3] {
    match binding {
        super::RecoveryBlockedCommandBinding::Started {
            execution_nonce,
            fence,
            ..
        } => {
            let fence = fence.as_deref();
            [
                execution_nonce.capacity(),
                fence.map_or(0, |_| size_of::<super::RecoveryFenceBinding>()),
                fence.map_or(0, |fence| fence.execution_nonce.capacity()),
            ]
        }
        super::RecoveryBlockedCommandBinding::Accepted { .. } => [0; 3],
    }
}

#[cfg(test)]
mod recovery_binding_memory_tests {
    use super::*;

    fn nonce_with_capacity(capacity: usize, value: u8) -> Vec<u8> {
        let mut nonce = Vec::with_capacity(capacity);
        nonce.push(value);
        nonce
    }

    #[test]
    fn boxed_fence_charge_includes_object_and_both_nonce_allocations() {
        // 威胁场景：异常记录让 fence 内部 nonce 的 capacity 远大于长度；计费必须覆盖
        // Box heap object 与内外两份 nonce，而不是只看外层 Vec。
        let outer_nonce = nonce_with_capacity(17, 0x11);
        let fence_nonce = nonce_with_capacity(4_097, 0x12);
        let binding = super::super::RecoveryBlockedCommandBinding::Started {
            command_id: RuntimeId::from_bytes(RuntimeIdKind::Command, [0x21; 16])
                .expect("valid command id"),
            turn_id: RuntimeId::from_bytes(RuntimeIdKind::Turn, [0x22; 16]).expect("valid turn id"),
            daemon_boot_id: RuntimeId::from_bytes(RuntimeIdKind::DaemonBoot, [0x23; 16])
                .expect("valid daemon boot id"),
            execution_nonce: outer_nonce,
            fence: Some(Box::new(super::super::RecoveryFenceBinding {
                command_id: RuntimeId::from_bytes(RuntimeIdKind::Command, [0x21; 16])
                    .expect("valid fence command id"),
                daemon_boot_id: RuntimeId::from_bytes(RuntimeIdKind::DaemonBoot, [0x23; 16])
                    .expect("valid fence boot id"),
                execution_nonce: fence_nonce,
                process_group_id: 4_201,
                leader_pid: 4_201,
                leader_start_time: 77,
                release_authorized_at_ms: Some(88),
                payload_bytes: 32,
                payload_sha256: [0x24; 32],
            })),
        };

        let super::super::RecoveryBlockedCommandBinding::Started {
            execution_nonce,
            fence: Some(fence),
            ..
        } = &binding
        else {
            unreachable!()
        };
        assert_eq!(
            recovery_binding_retained_allocations(&binding),
            [
                execution_nonce.capacity(),
                size_of::<super::super::RecoveryFenceBinding>(),
                fence.execution_nonce.capacity(),
            ]
        );
    }

    #[test]
    fn accepted_or_unfenced_binding_has_no_hidden_box_charge() {
        let accepted = super::super::RecoveryBlockedCommandBinding::Accepted {
            command_id: RuntimeId::from_bytes(RuntimeIdKind::Command, [0x31; 16])
                .expect("valid accepted command id"),
        };
        assert_eq!(recovery_binding_retained_allocations(&accepted), [0; 3]);

        let unfenced = super::super::RecoveryBlockedCommandBinding::Started {
            command_id: RuntimeId::from_bytes(RuntimeIdKind::Command, [0x32; 16])
                .expect("valid command id"),
            turn_id: RuntimeId::from_bytes(RuntimeIdKind::Turn, [0x33; 16]).expect("valid turn id"),
            daemon_boot_id: RuntimeId::from_bytes(RuntimeIdKind::DaemonBoot, [0x34; 16])
                .expect("valid daemon boot id"),
            execution_nonce: nonce_with_capacity(19, 0x35),
            fence: None,
        };
        let super::super::RecoveryBlockedCommandBinding::Started {
            execution_nonce, ..
        } = &unfenced
        else {
            unreachable!()
        };
        assert_eq!(
            recovery_binding_retained_allocations(&unfenced),
            [execution_nonce.capacity(), 0, 0]
        );
    }
}

/// 只为 shutdown 调用方设置等待上界；deadline 到达不会改变 worker 生命周期，
/// 也不会取消 dedicated store worker 自己持有的 finalizer。worker 会继续等待 read
/// pool quiesce，随后关闭 read crypto；SQLite connection、row keys 与 path lease 在此
/// 之前都保持有效，即使调用方 Tokio runtime 已销毁也不受影响。
async fn await_shutdown_quiescence(
    result: oneshot::Receiver<()>,
    timeout: Duration,
) -> Result<(), RuntimeStoreError> {
    match tokio::time::timeout(timeout, result).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(_)) => Err(RuntimeStoreError::WorkerStopped),
        Err(_) => Err(RuntimeStoreError::ShutdownTimedOut),
    }
}

fn accept_command_memory_charge(input: &AcceptCommand) -> Result<u32, RuntimeStoreError> {
    if input.idempotency_key.is_empty() || input.idempotency_key.len() > MAX_IDEMPOTENCY_KEY_BYTES {
        return Err(RuntimeStoreError::InvalidConfig(
            "idempotency key must contain 1 to 1024 UTF-8 bytes",
        ));
    }
    validate_maximum(input.payload.len(), MAX_COMMAND_PAYLOAD_BYTES)?;
    memory_charge(
        size_of::<NormalCommand>(),
        &[input.idempotency_key.capacity(), input.payload.capacity()],
    )
}

async fn dispatch<T, C>(
    sender: &mpsc::Sender<C>,
    lifecycle: &AtomicU8,
    lane: RuntimeStoreLane,
    build: impl FnOnce(oneshot::Sender<T>) -> C,
) -> Result<T, RuntimeStoreError> {
    ensure_running(lifecycle)?;
    let (reply, result) = oneshot::channel();
    sender
        .try_send(build(reply))
        .map_err(|error| map_try_send(error, lane))?;
    result.await.map_err(|_| RuntimeStoreError::WorkerStopped)
}

fn map_read_pool_error(error: ReadPoolError) -> RuntimeStoreError {
    match error {
        ReadPoolError::Busy => RuntimeStoreError::WorkerBusy {
            lane: RuntimeStoreLane::Read,
        },
        ReadPoolError::Closed | ReadPoolError::WorkerStopped => RuntimeStoreError::WorkerStopped,
        ReadPoolError::Sqlite(error) => RuntimeStoreError::Sqlite(error),
        ReadPoolError::Operation(error) => error,
        ReadPoolError::InvalidCapacity
        | ReadPoolError::CapacityUnavailable
        | ReadPoolError::SqliteNotConfigured
        | ReadPoolError::PageBudgetOutOfRange
        | ReadPoolError::PragmaMismatch => {
            RuntimeStoreError::InvalidConfig("runtime read-only WAL pool is unavailable")
        }
    }
}

async fn dispatch_with_budget<T, C>(
    sender: &mpsc::Sender<Queued<C>>,
    budget: &Arc<Semaphore>,
    lifecycle: &AtomicU8,
    lane: RuntimeStoreLane,
    memory_bytes: u32,
    build: impl FnOnce(oneshot::Sender<T>) -> C,
) -> Result<T, RuntimeStoreError> {
    ensure_running(lifecycle)?;
    let permit = budget
        .clone()
        .try_acquire_many_owned(memory_bytes)
        .map_err(|error| match error {
            tokio::sync::TryAcquireError::NoPermits => RuntimeStoreError::WorkerBusy { lane },
            tokio::sync::TryAcquireError::Closed => RuntimeStoreError::WorkerStopped,
        })?;
    let (reply, result) = oneshot::channel();
    sender
        .try_send(Queued {
            command: build(reply),
            memory_permit: permit,
        })
        .map_err(|error| map_try_send(error, lane))?;
    result.await.map_err(|_| RuntimeStoreError::WorkerStopped)
}

fn ensure_running(lifecycle: &AtomicU8) -> Result<(), RuntimeStoreError> {
    match lifecycle.load(Ordering::Acquire) {
        LIFECYCLE_RUNNING => Ok(()),
        LIFECYCLE_SHUTTING_DOWN => Err(RuntimeStoreError::ShutdownInProgress),
        _ => Err(RuntimeStoreError::WorkerStopped),
    }
}

fn map_try_send<T>(
    error: mpsc::error::TrySendError<T>,
    lane: RuntimeStoreLane,
) -> RuntimeStoreError {
    match error {
        mpsc::error::TrySendError::Full(_) => RuntimeStoreError::WorkerBusy { lane },
        mpsc::error::TrySendError::Closed(_) => RuntimeStoreError::WorkerStopped,
    }
}

fn exact_bounded_secret_vec(
    mut value: Vec<u8>,
    maximum: usize,
) -> Result<Vec<u8>, RuntimeStoreError> {
    validate_nonempty_maximum(&value, maximum)?;
    let mut exact = Vec::new();
    exact
        .try_reserve_exact(value.len())
        .map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
    exact.extend_from_slice(&value);
    value.zeroize();
    Ok(exact)
}

struct Queued<C> {
    command: C,
    memory_permit: OwnedSemaphorePermit,
}

enum AcceptCommandReply {
    Direct(oneshot::Sender<Result<AcceptOutcome, RuntimeStoreError>>),
    Authorized {
        authorization: AuthorizationGuard,
        reply: oneshot::Sender<Result<AuthorizedAcceptOutcome, RuntimeStoreError>>,
    },
}

impl AcceptCommandReply {
    fn send(self, result: Result<AcceptOutcome, RuntimeStoreError>) {
        match self {
            Self::Direct(reply) => {
                let _ = reply.send(result);
            }
            Self::Authorized {
                authorization,
                reply,
            } => match result {
                Ok(outcome) => {
                    let _ = reply.send(Ok(AuthorizedAcceptOutcome {
                        outcome,
                        authorization,
                    }));
                }
                Err(error) => {
                    let _ = reply.send(Err(error));
                    drop(authorization);
                }
            },
        }
    }
}

enum NormalCommand {
    ImportNativeProjection {
        prepared: native_projection::PreparedNativeProjectionImport,
        epoch_source: Arc<AtomicU64>,
        reply: oneshot::Sender<
            Result<native_projection::ImportNativeProjectionOutcome, RuntimeStoreError>,
        >,
    },
    ReconcileNativeProjection {
        plan: native_projection::NativeProjectionReconcilePlan,
        dispositions: Vec<native_projection::NativeProjectionCandidateDisposition>,
        reply: oneshot::Sender<
            Result<native_projection::ReconcileNativeProjectionOutcome, RuntimeStoreError>,
        >,
    },
    RetireNativeProjection {
        plan: native_projection::NativeProjectionRetirementPlan,
        reply: oneshot::Sender<
            Result<native_projection::RetireNativeProjectionOutcome, RuntimeStoreError>,
        >,
    },
    CreateConversation {
        input: NewConversation,
        descriptor_bytes: zeroize::Zeroizing<Vec<u8>>,
        reply: oneshot::Sender<Result<CreateConversationOutcome, RuntimeStoreError>>,
    },
    ConfigureConversation {
        prepared: PreparedConfigurationRequest,
        authorization: Option<AuthorizationGuard>,
        reply: oneshot::Sender<Result<ConfigureConversationOutcome, RuntimeStoreError>>,
    },
    AcceptAdminUpgrade {
        prepared: admin::PreparedAdminUpgradeRequest,
        reply: oneshot::Sender<Result<admin::AcceptAdminUpgradeOutcome, RuntimeStoreError>>,
    },
    QueryAdminUpgrade {
        prepared: admin::PreparedAdminUpgradeRequest,
        reply: oneshot::Sender<Result<Option<admin::AdminUpgradeCommand>, RuntimeStoreError>>,
    },
    ActiveStartedCommandCount {
        reply: oneshot::Sender<Result<u32, RuntimeStoreError>>,
    },
    UpdateConversationMetadata {
        prepared: PreparedMetadataMutationRequest,
        authorization: Option<AuthorizationGuard>,
        reply: oneshot::Sender<Result<UpdateConversationMetadataOutcome, RuntimeStoreError>>,
    },
    ClaimNativeMetadataMutation {
        prepared: PreparedMetadataMutationRequest,
        reply: oneshot::Sender<Result<ClaimNativeMetadataMutationOutcome, RuntimeStoreError>>,
    },
    AcceptCommand {
        input: AcceptCommand,
        reply: AcceptCommandReply,
    },
    StartCommand {
        input: StartCommand,
        event_source: StartEventSource,
        start_provenance: CommandStartProvenance,
        reply: oneshot::Sender<Result<StartOutcome, RuntimeStoreError>>,
    },
    AppendExecutionEvent {
        input: PreparedExecutionEvent,
        reply: oneshot::Sender<Result<super::AppendExecutionEventOutcome, RuntimeStoreError>>,
    },
    BindAdapterState {
        namespace: AdapterStateNamespace,
        adapter_state_key: super::RuntimeId,
        state_reference: SecretBytes,
        reply: oneshot::Sender<Result<(), RuntimeStoreError>>,
    },
    RegisterApproval {
        input: RegisterApproval,
        reply: oneshot::Sender<Result<RegisterApprovalOutcome, RuntimeStoreError>>,
    },
    ClaimApproval {
        input: ClaimApproval,
        reply: oneshot::Sender<Result<ApprovalMutationOutcome, RuntimeStoreError>>,
    },
    BeginApprovalAttempt {
        input: BeginApprovalAttempt,
        reply: oneshot::Sender<Result<BeginApprovalAttemptOutcome, RuntimeStoreError>>,
    },
    RetryApprovalDelivery {
        input: RetryApprovalDelivery,
        reply: oneshot::Sender<Result<ApprovalMutationOutcome, RuntimeStoreError>>,
    },
    StoreConversationSnapshot {
        write: PreparedConversationSnapshotWrite,
        build_permit: Option<SharedSnapshotBuildPermit>,
        reply: oneshot::Sender<Result<StoredConversationSnapshot, StoreConversationSnapshotError>>,
    },
    PreflightCatalogSnapshotRefresh {
        source: Option<super::snapshot::ReadySnapshotReference>,
        frozen_base: agentdeck_protocol::runtime::StreamCursor,
        reply: oneshot::Sender<
            Result<super::snapshot::CatalogSnapshotRefreshPreflight, RuntimeStoreError>,
        >,
    },
    RefreshCatalogSnapshot {
        source: Option<super::snapshot::ReadySnapshotReference>,
        frozen_base: agentdeck_protocol::runtime::StreamCursor,
        build_permit: SharedSnapshotBuildPermit,
        reply: oneshot::Sender<Result<super::snapshot::ReadySnapshotReference, RuntimeStoreError>>,
    },
    CreatePublicationStream {
        publication_stream_id: [u8; 16],
        scope: PublicationScope,
        stream_route: [u8; 16],
        generation: [u8; 16],
        reply: oneshot::Sender<Result<PublicationStreamRecord, RuntimeStoreError>>,
    },
    RotatePublicationStream {
        request: RotatePublicationStreamRequest,
        reply: oneshot::Sender<Result<PublicationStreamRecord, RuntimeStoreError>>,
    },
    FreezePublication {
        request: FreezePublicationRequest,
        reply: oneshot::Sender<Result<FrozenPublication, RuntimeStoreError>>,
    },
}

enum SafetyCommand {
    PrepareMachineIdentity {
        binding: MachineIdentityBinding,
        reply: oneshot::Sender<Result<PrepareMachineIdentityOutcome, RuntimeStoreError>>,
    },
    ActivateMachineIdentity {
        binding: MachineIdentityBinding,
        reply: oneshot::Sender<Result<ActivateMachineIdentityOutcome, RuntimeStoreError>>,
    },
    PrepareMachineEnrollment {
        prepared: Box<machine_remote::PreparedMachineEnrollmentWrite>,
        reply: oneshot::Sender<Result<PrepareMachineEnrollmentOutcome, RuntimeStoreError>>,
    },
    RecordValidatedEnrollmentResponse {
        prepared: machine_remote::ValidatedEnrollmentResponseWrite,
        reply: oneshot::Sender<Result<RecordValidatedEnrollmentResponseOutcome, RuntimeStoreError>>,
    },
    ActivateMachineEnrollment {
        expected_request_hash: [u8; 32],
        expected_response_hash: [u8; 32],
        reply: oneshot::Sender<Result<ActivateMachineEnrollmentOutcome, RuntimeStoreError>>,
    },
    PrepareMachineRetirement {
        prepared: machine_remote::PreparedMachineRetirementWrite,
        reply: oneshot::Sender<Result<PrepareMachineRetirementOutcome, RuntimeStoreError>>,
    },
    RecordMachineRetirementTerminal {
        prepared: machine_remote::PreparedRetirementTerminalWrite,
        reply: oneshot::Sender<Result<RecordMachineRetirementTerminalOutcome, RuntimeStoreError>>,
    },
    ConfirmMachinePurgeReadbackAbsent {
        prepared: machine_remote::PreparedRetirementTerminalWrite,
        reply: oneshot::Sender<Result<ConfirmMachinePurgeReadbackAbsentOutcome, RuntimeStoreError>>,
    },
    RecordRootLostMachinePurge {
        prepared: Box<machine_remote::PreparedRootLostPurgeWrite>,
        reply: oneshot::Sender<Result<RecordRootLostMachinePurgeOutcome, RuntimeStoreError>>,
    },
    FinalizeMachineLocalDeletion {
        expected_reset_kind: MachineTrustResetKind,
        expected_purge_proof_hash: [u8; 32],
        cleanup_witness_hash: [u8; 32],
        reply: oneshot::Sender<Result<FinalizeMachineLocalDeletionOutcome, RuntimeStoreError>>,
    },
    RecordEnrollmentReceipt {
        receipt: MachineEnrollmentReceiptRecord,
        reply: oneshot::Sender<Result<MachineEnrollmentReceiptRecord, RuntimeStoreError>>,
    },
    FinalizeAdminUpgrade {
        command: admin::AdminUpgradeCommand,
        terminal: admin::AdminUpgradeTerminalOutcome,
        reply: oneshot::Sender<Result<admin::FinalizeAdminUpgradeOutcome, RuntimeStoreError>>,
    },
    PersistFence {
        input: ExecutionFence,
        reply: oneshot::Sender<Result<ExecutionFenceRecord, RuntimeStoreError>>,
    },
    AuthorizeRelease {
        input: AuthorizeExecutionRelease,
        reply: oneshot::Sender<Result<ExecutionFenceRecord, RuntimeStoreError>>,
    },
    PersistNativeMetadataEffectFence {
        input: native_projection::PersistNativeMetadataEffectFence,
        reply: oneshot::Sender<
            Result<native_projection::PersistNativeMetadataEffectFenceOutcome, RuntimeStoreError>,
        >,
    },
    AuthorizeNativeMetadataEffectRelease {
        input: native_projection::AuthorizeNativeMetadataEffectRelease,
        reply: oneshot::Sender<
            Result<
                native_projection::AuthorizeNativeMetadataEffectReleaseOutcome,
                RuntimeStoreError,
            >,
        >,
    },
    FailUnreleasedNativeMetadataEffect {
        input: native_projection::FailUnreleasedNativeMetadataEffect,
        reply: oneshot::Sender<Result<UpdateConversationMetadataOutcome, RuntimeStoreError>>,
    },
    CompleteCommand {
        input: CompleteCommand,
        reply: oneshot::Sender<Result<CompleteOutcome, RuntimeStoreError>>,
    },
    RecoverStartedCommand {
        input: super::RecoverStartedCommand,
        reply: oneshot::Sender<Result<CompleteOutcome, RuntimeStoreError>>,
    },
    MarkConversationRecoveryBlocked {
        input: MarkConversationRecoveryBlocked,
        reply: oneshot::Sender<Result<ConversationRecord, RuntimeStoreError>>,
    },
    FailClaimedNativeMetadataMutation {
        mutation: NativeMetadataMutationClaim,
        failure: agentdeck_protocol::runtime::RuntimeFailure,
        reply: oneshot::Sender<Result<UpdateConversationMetadataOutcome, RuntimeStoreError>>,
    },
    MarkNativeMetadataMutationOutcomeUnknown {
        mutation: NativeMetadataMutationClaim,
        reply: oneshot::Sender<Result<NativeMetadataMutationClaim, RuntimeStoreError>>,
    },
    FinalizeNativeMetadataMutationReadback {
        mutation: NativeMetadataMutationClaim,
        readback: NativeMetadataMutationReadback,
        reply: oneshot::Sender<Result<UpdateConversationMetadataOutcome, RuntimeStoreError>>,
    },
    TerminateAccepted {
        input: TerminateAcceptedCommand,
        reply: oneshot::Sender<Result<TerminateAcceptedOutcome, RuntimeStoreError>>,
    },
    TerminateStartedBeforeRelease {
        input: TerminateStartedBeforeRelease,
        reply: oneshot::Sender<Result<TerminateStartedBeforeReleaseOutcome, RuntimeStoreError>>,
    },
    MarkApprovalApplied {
        input: MarkApprovalApplied,
        reply: oneshot::Sender<Result<ApprovalMutationOutcome, RuntimeStoreError>>,
    },
    MarkApprovalDeliveryFailed {
        input: MarkApprovalDeliveryFailed,
        reply: oneshot::Sender<Result<ApprovalMutationOutcome, RuntimeStoreError>>,
    },
    ExpireApproval {
        input: ExpireApproval,
        reply: oneshot::Sender<Result<ApprovalMutationOutcome, RuntimeStoreError>>,
    },
    AcknowledgePublicationCommit {
        publication_stream_id: [u8; 16],
        generation: [u8; 16],
        stream_seq: u64,
        blob_sha256: [u8; 32],
        reply: oneshot::Sender<Result<PublicationBarrierCut, RuntimeStoreError>>,
    },
    AcknowledgePublicationDelivery {
        publication_stream_id: [u8; 16],
        generation: [u8; 16],
        stream_seq: u64,
        blob_sha256: [u8; 32],
        reply: oneshot::Sender<Result<PublicationAcknowledgement, RuntimeStoreError>>,
    },
}

enum ReadCommand {
    Inspect {
        reply: oneshot::Sender<Result<RuntimeStoreSnapshot, RuntimeStoreError>>,
    },
    LoadMachineIdentityState {
        reply: oneshot::Sender<Result<Option<MachineIdentityStateRecord>, RuntimeStoreError>>,
    },
    LoadMachineEnrollmentState {
        reply: oneshot::Sender<Result<Option<MachineEnrollmentState>, RuntimeStoreError>>,
    },
    LoadPendingAdminUpgrades {
        cursor: Option<admin::AdminUpgradeRecoveryCursor>,
        reply: oneshot::Sender<Result<admin::AdminUpgradeRecoveryPage, RuntimeStoreError>>,
    },
    AcceptCompletedNativeProjectionScan {
        namespace: AdapterStateNamespace,
        scan_generation: [u8; 16],
        epoch_source: Arc<AtomicU64>,
        reply: oneshot::Sender<
            Result<Arc<native_projection::CompletedNativeProjectionGeneration>, RuntimeStoreError>,
        >,
    },
    PlanNativeProjectionReconciliation {
        completed: Arc<native_projection::CompletedNativeProjectionGeneration>,
        cursor: Option<native_projection::NativeProjectionReconcileCursor>,
        reply: oneshot::Sender<
            Result<native_projection::NativeProjectionReconcilePlan, RuntimeStoreError>,
        >,
    },
    PlanNativeProjectionRetirement {
        namespace: AdapterStateNamespace,
        cursor: Option<native_projection::NativeProjectionRetirementCursor>,
        reply: oneshot::Sender<
            Result<native_projection::NativeProjectionRetirementPlan, RuntimeStoreError>,
        >,
    },
    BeginRecoveryScan {
        reply: oneshot::Sender<Result<RecoveryCursor, RuntimeStoreError>>,
    },
    BeginRecoveryVerificationScan {
        reply: oneshot::Sender<Result<RecoveryCursor, RuntimeStoreError>>,
    },
    LoadRecoveryPage {
        cursor: RecoveryCursor,
        reply: oneshot::Sender<Result<RecoveryPage, RuntimeStoreError>>,
    },
    FinishRecoveryScan {
        completion: RecoveryCompletion,
        reply: oneshot::Sender<Result<(), RuntimeStoreError>>,
    },
    ResolveAdapterState {
        namespace: AdapterStateNamespace,
        adapter_state_key: super::RuntimeId,
        reply: oneshot::Sender<Result<Option<SecretBytes>, RuntimeStoreError>>,
    },
    LoadActiveNativeMetadataMutations {
        cursor: Option<NativeMetadataMutationRecoveryCursor>,
        reply: oneshot::Sender<Result<NativeMetadataMutationRecoveryPage, RuntimeStoreError>>,
    },
    LoadNativeMetadataEffectRecoveryRecord {
        mutation: NativeMetadataMutationClaim,
        reply: oneshot::Sender<
            Result<native_projection::NativeMetadataEffectRecoveryRecord, RuntimeStoreError>,
        >,
    },
    QueryCommandReceipt {
        input: QueryCommandReceipt,
        reply: oneshot::Sender<Result<CommandReceiptRecord, RuntimeStoreError>>,
    },
    LoadPendingPublicationStreams {
        reply: oneshot::Sender<Result<Vec<[u8; 16]>, RuntimeStoreError>>,
    },
    RegisterStreamBarrier {
        request: RegisterStreamBarrier,
        reply: oneshot::Sender<Result<StreamBarrierRegistration, RuntimeStoreError>>,
    },
    ReleaseStreamWatch {
        token: StoreWatchToken,
        reply: oneshot::Sender<bool>,
    },
    AcquireBackfillPin {
        target: RuntimeBackfillTarget,
        after: Option<u64>,
        reply: oneshot::Sender<Result<stream_pipeline::ManagedBackfillPlan, RuntimeStoreError>>,
    },
    PrepareBackfillPage {
        pin: RuntimeBackfillPin,
        after: Option<u64>,
        reply: oneshot::Sender<Result<stream::RuntimeBackfillReadPlan, RuntimeStoreError>>,
    },
    ValidateBackfillPage {
        completion: RuntimeBackfillPageCompletion,
        reply: oneshot::Sender<Result<(), RuntimeStoreError>>,
    },
    CompleteBackfillPage {
        completion: RuntimeBackfillPageCompletion,
        reply: oneshot::Sender<Result<(), RuntimeStoreError>>,
    },
    ReleaseBackfillPin {
        pin_id: [u8; 16],
        reply: oneshot::Sender<Result<(), RuntimeStoreError>>,
    },
    AcquireSnapshotBuildPin {
        conversation_id: super::RuntimeId,
        reply: oneshot::Sender<Result<SnapshotMaterializationSource, RuntimeStoreError>>,
    },
    ReleaseSnapshotBuildPin {
        pin: RuntimeSnapshotBuildPin,
        reply: oneshot::Sender<Result<(), RuntimeStoreError>>,
    },
    #[cfg(test)]
    ActiveSnapshotBuildPinCountForTest {
        reply: oneshot::Sender<Result<u64, RuntimeStoreError>>,
    },
    LoadAuthenticatedConversationSnapshotContext {
        conversation_id: super::RuntimeId,
        reply: oneshot::Sender<Result<AuthenticatedConversationSnapshotContext, RuntimeStoreError>>,
    },
    LoadConfigurationStateAtEventCursor {
        conversation_id: super::RuntimeId,
        base_event_seq: Option<u64>,
        reply: oneshot::Sender<Result<ConversationConfigurationState, RuntimeStoreError>>,
    },
    PrepareAuthenticatedSnapshotBuildContext {
        pin: RuntimeSnapshotBuildPin,
        reply: oneshot::Sender<Result<AuthenticatedConversationSnapshotContext, RuntimeStoreError>>,
    },
}

enum ControlCommand {
    Shutdown { reply: oneshot::Sender<()> },
}

struct WorkerReceivers {
    normal: mpsc::Receiver<Queued<NormalCommand>>,
    safety: mpsc::Receiver<Queued<SafetyCommand>>,
    read: mpsc::Receiver<ReadCommand>,
    control: mpsc::Receiver<ControlCommand>,
    ready: oneshot::Sender<Result<RuntimeStoreReady, RuntimeStoreError>>,
}

struct RuntimeStoreReady {
    interrupt: Arc<rusqlite::InterruptHandle>,
    read_pool: ReadPool,
    read_crypto: RuntimeReadCryptoCapability,
    database_id: [u8; 16],
}

fn run(
    config: RuntimeStoreConfig,
    storage_kek: StorageKek,
    receivers: WorkerReceivers,
    lease: Arc<StoreOpenLease>,
    lifecycle: Arc<AtomicU8>,
    #[cfg(test)] test_fd_permit: OwnedSemaphorePermit,
) {
    let WorkerReceivers {
        normal: mut normal_commands,
        safety: mut safety_commands,
        read: mut read_commands,
        control: mut controls,
        ready,
    } = receivers;
    // 威胁场景：初始化 after-COMMIT fault 已向 caller 返回 unknown outcome，但 worker 仍持有
    // path lease；caller 立即按原输入 reopen 时会被误报 StoreAlreadyOpen，无法收敛到已提交状态。
    // 初始化放在独立 scope，保证所有 SQLite/read 资源先 drop，再释放 lease 并发送 ready error。
    let initialized: Result<_, RuntimeStoreError> = (|| {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .map_err(|_| {
                RuntimeStoreError::InvalidConfig("failed to initialize runtime store worker")
            })?;
        let state = sqlite::open(&config, storage_kek)?;
        // Drop 不能阻塞调用线程，因此 watch 与 TEMP pin 共用 unbounded cleanup queue。
        // 它由 biased select 在业务 lane 前优先 drain；cleanup capability 均不可由外部伪造。
        let (cleanup_tx, cleanups) = mpsc::unbounded_channel();
        let commit_hub = store_commit_hub_from_entropy(cleanup_tx.clone(), |incarnation| {
            getrandom::fill(incarnation).map_err(|_| ())
        })?;
        let interrupt = Arc::new(state.connection.get_interrupt_handle());
        let read_crypto = state.key_bundle.read_only_capability();
        let read_pool = ReadPool::open_sqlite(
            &state.storage_path,
            DEFAULT_RUNTIME_READ_CONCURRENCY,
            config.busy_timeout_ms,
        )
        .map_err(|_| {
            RuntimeStoreError::InvalidConfig("failed to initialize runtime read-only WAL pool")
        })?;
        Ok((
            runtime,
            state,
            cleanup_tx,
            cleanups,
            commit_hub,
            interrupt,
            read_crypto,
            read_pool,
        ))
    })();
    let (
        runtime,
        mut state,
        cleanup_tx,
        mut cleanups,
        mut commit_hub,
        interrupt,
        read_crypto,
        read_pool,
    ) = match initialized {
        Ok(initialized) => initialized,
        Err(error) => {
            drop(lease);
            lifecycle.store(LIFECYCLE_STOPPED, Ordering::Release);
            let _ = ready.send(Err(error));
            return;
        }
    };
    if ready
        .send(Ok(RuntimeStoreReady {
            interrupt,
            read_pool: read_pool.clone(),
            read_crypto: read_crypto.clone(),
            database_id: state.database_id,
        }))
        .is_err()
    {
        return;
    }

    let shutdown_reply = runtime.block_on(async {
        let mut control_open = true;
        let mut safety_open = true;
        let mut read_open = true;
        let mut normal_open = true;
        loop {
            if !control_open && !safety_open && !read_open && !normal_open {
                break None;
            }
            tokio::select! {
                biased;
                control = controls.recv(), if control_open => {
                    match control {
                        Some(ControlCommand::Shutdown { reply }) => break Some(reply),
                        None => control_open = false,
                    }
                }
                Some(cleanup) = cleanups.recv() => {
                    apply_store_cleanup(&state, &mut commit_hub, cleanup);
                }
                command = safety_commands.recv(), if safety_open => {
                    match command {
                        Some(command) => handle_safety(command, &mut state, &config, &mut commit_hub),
                        None => safety_open = false,
                    }
                }
                command = read_commands.recv(), if read_open => {
                    match command {
                        Some(command) => handle_read(command, &mut state, &config, &mut commit_hub, &cleanup_tx),
                        None => read_open = false,
                    }
                }
                command = normal_commands.recv(), if normal_open => {
                    match command {
                        Some(command) => handle_normal(command, &mut state, &config, &mut commit_hub),
                        None => normal_open = false,
                    }
                }
            }
        }
    });

    normal_commands.close();
    safety_commands.close();
    read_commands.close();
    while normal_commands.try_recv().is_ok() {}
    while safety_commands.try_recv().is_ok() {}
    while read_commands.try_recv().is_ok() {}
    controls.close();
    cleanups.close();
    while let Ok(cleanup) = cleanups.try_recv() {
        apply_store_cleanup(&state, &mut commit_hub, cleanup);
    }
    drop(commit_hub);
    while cleanups.try_recv().is_ok() {}
    drop(cleanups);
    // Finalization lives on the dedicated store thread/runtime, never on an arbitrary caller
    // runtime. This makes caller timeout, future cancellation, and caller runtime teardown mere
    // observation failures: cleanup still waits for every active read before zeroizing its keys.
    runtime.block_on(read_pool.close_and_wait());
    read_crypto.close();
    drop(state);
    drop(lease);
    #[cfg(test)]
    drop(test_fd_permit);
    lifecycle.store(LIFECYCLE_STOPPED, Ordering::Release);
    if let Some(reply) = shutdown_reply {
        let _ = reply.send(());
    }
}

fn store_commit_hub_from_entropy<E>(
    cleanup_tx: mpsc::UnboundedSender<StoreCleanup>,
    fill_incarnation: impl FnOnce(&mut [u8; 16]) -> Result<(), E>,
) -> Result<StoreCommitHub, RuntimeStoreError> {
    let mut incarnation = [0_u8; 16];
    fill_incarnation(&mut incarnation)
        .map_err(|_| RuntimeStoreError::WatchIncarnationEntropyUnavailable)?;
    // 保留 127 bit OS entropy，同时构造性排除全零 incarnation。
    incarnation[0] |= 0x80;
    Ok(StoreCommitHub::with_cleanup_sender_and_incarnation(
        cleanup_tx,
        incarnation,
    ))
}

fn apply_store_cleanup(
    state: &sqlite::RuntimeSqlite,
    commit_hub: &mut StoreCommitHub,
    cleanup: StoreCleanup,
) {
    match cleanup {
        StoreCleanup::Watch(token) => {
            let _ = commit_hub.release(&token);
        }
        StoreCleanup::BackfillPin(pin_id) => {
            if stream::release_backfill_pin(state, pin_id).is_err() {
                crate::diag::log(
                    "runtime_backfill_pin_cleanup_failed",
                    "backfill pin Drop cleanup failed",
                );
            }
        }
        StoreCleanup::SnapshotBuildPin(pin) => {
            if stream::release_snapshot_build_pin(state, &pin).is_err() {
                crate::diag::log(
                    "runtime_snapshot_build_pin_cleanup_failed",
                    "snapshot build pin Drop cleanup failed",
                );
            }
        }
    }
}

fn handle_normal(
    queued: Queued<NormalCommand>,
    state: &mut sqlite::RuntimeSqlite,
    config: &RuntimeStoreConfig,
    commit_hub: &mut StoreCommitHub,
) {
    let Queued {
        command,
        memory_permit,
    } = queued;
    if state.recovery_scan.is_some() {
        match command {
            NormalCommand::ImportNativeProjection { reply, .. } => {
                let _ = reply.send(Err(RuntimeStoreError::RecoveryInProgress));
            }
            NormalCommand::ReconcileNativeProjection { reply, .. } => {
                let _ = reply.send(Err(RuntimeStoreError::RecoveryInProgress));
            }
            NormalCommand::RetireNativeProjection { reply, .. } => {
                let _ = reply.send(Err(RuntimeStoreError::RecoveryInProgress));
            }
            NormalCommand::CreateConversation { reply, .. } => {
                let _ = reply.send(Err(RuntimeStoreError::RecoveryInProgress));
            }
            NormalCommand::ConfigureConversation {
                authorization,
                reply,
                ..
            } => {
                let _ = reply.send(Err(RuntimeStoreError::RecoveryInProgress));
                drop(authorization);
            }
            NormalCommand::AcceptAdminUpgrade { reply, .. } => {
                let _ = reply.send(Err(RuntimeStoreError::RecoveryInProgress));
            }
            NormalCommand::QueryAdminUpgrade { reply, .. } => {
                let _ = reply.send(Err(RuntimeStoreError::RecoveryInProgress));
            }
            NormalCommand::ActiveStartedCommandCount { reply } => {
                let _ = reply.send(Err(RuntimeStoreError::RecoveryInProgress));
            }
            NormalCommand::UpdateConversationMetadata {
                authorization,
                reply,
                ..
            } => {
                let _ = reply.send(Err(RuntimeStoreError::RecoveryInProgress));
                drop(authorization);
            }
            NormalCommand::ClaimNativeMetadataMutation { reply, .. } => {
                let _ = reply.send(Err(RuntimeStoreError::RecoveryInProgress));
            }
            NormalCommand::AcceptCommand { reply, .. } => {
                reply.send(Err(RuntimeStoreError::RecoveryInProgress));
            }
            NormalCommand::StartCommand { reply, .. } => {
                let _ = reply.send(Err(RuntimeStoreError::RecoveryInProgress));
            }
            NormalCommand::AppendExecutionEvent { reply, .. } => {
                let _ = reply.send(Err(RuntimeStoreError::RecoveryInProgress));
            }
            NormalCommand::BindAdapterState { reply, .. } => {
                let _ = reply.send(Err(RuntimeStoreError::RecoveryInProgress));
            }
            NormalCommand::RegisterApproval { reply, .. } => {
                let _ = reply.send(Err(RuntimeStoreError::RecoveryInProgress));
            }
            NormalCommand::ClaimApproval { reply, .. } => {
                let _ = reply.send(Err(RuntimeStoreError::RecoveryInProgress));
            }
            NormalCommand::BeginApprovalAttempt { reply, .. } => {
                let _ = reply.send(Err(RuntimeStoreError::RecoveryInProgress));
            }
            NormalCommand::RetryApprovalDelivery { reply, .. } => {
                let _ = reply.send(Err(RuntimeStoreError::RecoveryInProgress));
            }
            NormalCommand::StoreConversationSnapshot {
                write,
                build_permit,
                reply,
            } => {
                let _ = reply.send(Err(StoreConversationSnapshotError::with_retry_write(
                    RuntimeStoreError::RecoveryInProgress,
                    write,
                )));
                drop(build_permit);
            }
            NormalCommand::PreflightCatalogSnapshotRefresh { reply, .. } => {
                let _ = reply.send(Err(RuntimeStoreError::RecoveryInProgress));
            }
            NormalCommand::RefreshCatalogSnapshot {
                build_permit,
                reply,
                ..
            } => {
                let _ = reply.send(Err(RuntimeStoreError::RecoveryInProgress));
                drop(build_permit);
            }
            NormalCommand::CreatePublicationStream { reply, .. } => {
                let _ = reply.send(Err(RuntimeStoreError::RecoveryInProgress));
            }
            NormalCommand::RotatePublicationStream { reply, .. } => {
                let _ = reply.send(Err(RuntimeStoreError::RecoveryInProgress));
            }
            NormalCommand::FreezePublication { reply, .. } => {
                let _ = reply.send(Err(RuntimeStoreError::RecoveryInProgress));
            }
        }
        drop(memory_permit);
        return;
    }
    match command {
        NormalCommand::ImportNativeProjection {
            prepared,
            epoch_source,
            reply,
        } => {
            let mut effects = CommandStreamEffects::default();
            // 与 plan/apply 共享 dedicated worker 线性化顺序；先执行的 import 使旧
            // completed generation 失效，先执行的 apply 则可安全先提交。
            let result = advance_native_projection_scan_epoch(&epoch_source).and_then(|_| {
                native_projection::import_native_projection(state, config, prepared, &mut effects)
            });
            let result = notify_after_durable_outcome(result, state, config, commit_hub, &effects);
            let _ = reply.send(result);
        }
        NormalCommand::ReconcileNativeProjection {
            plan,
            dispositions,
            reply,
        } => {
            let mut effects = CommandStreamEffects::default();
            let result = native_projection::reconcile_native_projection_page(
                state,
                config,
                plan,
                dispositions,
                &mut effects,
            );
            let result = notify_after_durable_outcome(result, state, config, commit_hub, &effects);
            let _ = reply.send(result);
        }
        NormalCommand::RetireNativeProjection { plan, reply } => {
            let mut effects = CommandStreamEffects::default();
            let result =
                native_projection::retire_native_projection_page(state, config, plan, &mut effects);
            let result = notify_after_durable_outcome(result, state, config, commit_hub, &effects);
            let _ = reply.send(result);
        }
        NormalCommand::CreateConversation {
            input,
            descriptor_bytes,
            reply,
        } => {
            let mut effects = CommandStreamEffects::default();
            let result =
                journal::create_conversation(state, config, input, descriptor_bytes, &mut effects);
            let result = notify_after_durable_outcome(result, state, config, commit_hub, &effects);
            let _ = reply.send(result);
        }
        NormalCommand::ConfigureConversation {
            prepared,
            authorization,
            reply,
        } => {
            let mut effects = CommandStreamEffects::default();
            let result =
                configuration::configure_conversation(state, config, prepared, &mut effects);
            let result = notify_after_durable_outcome(result, state, config, commit_hub, &effects);
            let _ = reply.send(result);
            drop(authorization);
        }
        NormalCommand::AcceptAdminUpgrade { prepared, reply } => {
            let _ = reply.send(admin::accept_admin_upgrade(state, config, prepared));
        }
        NormalCommand::QueryAdminUpgrade { prepared, reply } => {
            let _ = reply.send(admin::query_admin_upgrade(state, &prepared));
        }
        NormalCommand::ActiveStartedCommandCount { reply } => {
            let _ = reply.send(admin::active_started_command_count(state));
        }
        NormalCommand::UpdateConversationMetadata {
            prepared,
            authorization,
            reply,
        } => {
            let mut effects = CommandStreamEffects::default();
            let result = metadata::update_managed_conversation_metadata(
                state,
                config,
                prepared,
                &mut effects,
            );
            let result = notify_after_durable_outcome(result, state, config, commit_hub, &effects);
            let _ = reply.send(result);
            drop(authorization);
        }
        NormalCommand::ClaimNativeMetadataMutation { prepared, reply } => {
            let mut effects = CommandStreamEffects::default();
            let result =
                metadata::claim_native_conversation_metadata(state, config, prepared, &mut effects);
            let result = notify_after_durable_outcome(result, state, config, commit_hub, &effects);
            let _ = reply.send(result);
        }
        NormalCommand::AcceptCommand { input, reply } => {
            let mut effects = CommandStreamEffects::default();
            let result = journal::accept_command(state, config, input, &mut effects);
            let result = notify_after_durable_outcome(result, state, config, commit_hub, &effects);
            reply.send(result);
        }
        NormalCommand::StartCommand {
            input,
            event_source,
            start_provenance,
            reply,
        } => {
            let mut effects = CommandStreamEffects::default();
            let result = journal::mark_started_with_event(
                state,
                config,
                input,
                event_source,
                start_provenance,
                &mut effects,
            );
            let result = notify_after_durable_outcome(result, state, config, commit_hub, &effects);
            let _ = reply.send(result);
        }
        NormalCommand::AppendExecutionEvent { input, reply } => {
            let mut effects = CommandStreamEffects::default();
            let result = journal::append_execution_event(state, config, input, &mut effects);
            let result = notify_after_durable_outcome(result, state, config, commit_hub, &effects);
            let _ = reply.send(result);
        }
        NormalCommand::BindAdapterState {
            namespace,
            adapter_state_key,
            state_reference,
            reply,
        } => {
            let _ = reply.send(journal::bind_adapter_state(
                state,
                config,
                namespace,
                adapter_state_key,
                state_reference,
            ));
        }
        NormalCommand::RegisterApproval { input, reply } => {
            let mut effects = CommandStreamEffects::default();
            let result = approval::register_approval(state, config, input, &mut effects);
            let result = notify_after_durable_outcome(result, state, config, commit_hub, &effects);
            let _ = reply.send(result);
        }
        NormalCommand::ClaimApproval { input, reply } => {
            let mut effects = CommandStreamEffects::default();
            let result = approval::claim_approval(state, config, input, &mut effects);
            let result = notify_after_durable_outcome(result, state, config, commit_hub, &effects);
            let _ = reply.send(result);
        }
        NormalCommand::BeginApprovalAttempt { input, reply } => {
            let mut effects = CommandStreamEffects::default();
            let result = approval::begin_approval_attempt(state, config, input, &mut effects);
            let result = notify_after_durable_outcome(result, state, config, commit_hub, &effects);
            let _ = reply.send(result);
        }
        NormalCommand::RetryApprovalDelivery { input, reply } => {
            let mut effects = CommandStreamEffects::default();
            let result = approval::retry_approval_delivery(state, config, input, &mut effects);
            let result = notify_after_durable_outcome(result, state, config, commit_hub, &effects);
            let _ = reply.send(result);
        }
        NormalCommand::StoreConversationSnapshot {
            write,
            build_permit,
            reply,
        } => {
            let result = match config.clock.now_ms().map_err(RuntimeStoreError::from) {
                Ok(now) => super::snapshot::store_conversation_snapshot(state, config, write, now),
                Err(error) => Err(StoreConversationSnapshotError::with_retry_write(
                    error, write,
                )),
            };
            let _ = reply.send(result);
            drop(build_permit);
        }
        NormalCommand::PreflightCatalogSnapshotRefresh {
            source,
            frozen_base,
            reply,
        } => {
            let _ = reply.send(super::snapshot::preflight_catalog_snapshot_refresh(
                state,
                source.as_ref(),
                frozen_base,
            ));
        }
        NormalCommand::RefreshCatalogSnapshot {
            source,
            frozen_base,
            build_permit,
            reply,
        } => {
            let _ = reply.send(super::snapshot::refresh_catalog_snapshot(
                state,
                config,
                source.as_ref(),
                frozen_base,
            ));
            drop(build_permit);
        }
        NormalCommand::CreatePublicationStream {
            publication_stream_id,
            scope,
            stream_route,
            generation,
            reply,
        } => {
            let result = config
                .clock
                .now_ms()
                .map_err(RuntimeStoreError::from)
                .and_then(|now| {
                    super::publication::create_publication_stream(
                        state,
                        config,
                        publication_stream_id,
                        scope,
                        stream_route,
                        generation,
                        now,
                    )
                });
            let _ = reply.send(result);
        }
        NormalCommand::RotatePublicationStream { request, reply } => {
            let result = config
                .clock
                .now_ms()
                .map_err(RuntimeStoreError::from)
                .and_then(|now| {
                    super::publication::rotate_publication_stream(state, config, request, now)
                });
            let _ = reply.send(result);
        }
        NormalCommand::FreezePublication { request, reply } => {
            let result = config
                .clock
                .now_ms()
                .map_err(RuntimeStoreError::from)
                .and_then(|now| {
                    super::publication::freeze_publication(state, config, request, now)
                });
            let _ = reply.send(result);
        }
    }
    drop(memory_permit);
}

fn handle_safety(
    queued: Queued<SafetyCommand>,
    state: &mut sqlite::RuntimeSqlite,
    config: &RuntimeStoreConfig,
    commit_hub: &mut StoreCommitHub,
) {
    let Queued {
        command,
        memory_permit,
    } = queued;
    if state.recovery_scan.is_some() {
        match command {
            SafetyCommand::PrepareMachineIdentity { reply, .. } => {
                let _ = reply.send(Err(RuntimeStoreError::RecoveryInProgress));
            }
            SafetyCommand::ActivateMachineIdentity { reply, .. } => {
                let _ = reply.send(Err(RuntimeStoreError::RecoveryInProgress));
            }
            SafetyCommand::PrepareMachineEnrollment { reply, .. } => {
                let _ = reply.send(Err(RuntimeStoreError::RecoveryInProgress));
            }
            SafetyCommand::RecordValidatedEnrollmentResponse { reply, .. } => {
                let _ = reply.send(Err(RuntimeStoreError::RecoveryInProgress));
            }
            SafetyCommand::ActivateMachineEnrollment { reply, .. } => {
                let _ = reply.send(Err(RuntimeStoreError::RecoveryInProgress));
            }
            SafetyCommand::PrepareMachineRetirement { reply, .. } => {
                let _ = reply.send(Err(RuntimeStoreError::RecoveryInProgress));
            }
            SafetyCommand::RecordMachineRetirementTerminal { reply, .. } => {
                let _ = reply.send(Err(RuntimeStoreError::RecoveryInProgress));
            }
            SafetyCommand::ConfirmMachinePurgeReadbackAbsent { reply, .. } => {
                let _ = reply.send(Err(RuntimeStoreError::RecoveryInProgress));
            }
            SafetyCommand::RecordRootLostMachinePurge { reply, .. } => {
                let _ = reply.send(Err(RuntimeStoreError::RecoveryInProgress));
            }
            SafetyCommand::FinalizeMachineLocalDeletion { reply, .. } => {
                let _ = reply.send(Err(RuntimeStoreError::RecoveryInProgress));
            }
            SafetyCommand::RecordEnrollmentReceipt { reply, .. } => {
                let _ = reply.send(Err(RuntimeStoreError::RecoveryInProgress));
            }
            SafetyCommand::FinalizeAdminUpgrade { reply, .. } => {
                let _ = reply.send(Err(RuntimeStoreError::RecoveryInProgress));
            }
            SafetyCommand::PersistFence { reply, .. } => {
                let _ = reply.send(Err(RuntimeStoreError::RecoveryInProgress));
            }
            SafetyCommand::AuthorizeRelease { reply, .. } => {
                let _ = reply.send(Err(RuntimeStoreError::RecoveryInProgress));
            }
            SafetyCommand::PersistNativeMetadataEffectFence { reply, .. } => {
                let _ = reply.send(Err(RuntimeStoreError::RecoveryInProgress));
            }
            SafetyCommand::AuthorizeNativeMetadataEffectRelease { reply, .. } => {
                let _ = reply.send(Err(RuntimeStoreError::RecoveryInProgress));
            }
            SafetyCommand::FailUnreleasedNativeMetadataEffect { reply, .. } => {
                let _ = reply.send(Err(RuntimeStoreError::RecoveryInProgress));
            }
            SafetyCommand::CompleteCommand { reply, .. } => {
                let _ = reply.send(Err(RuntimeStoreError::RecoveryInProgress));
            }
            SafetyCommand::RecoverStartedCommand { reply, .. } => {
                let _ = reply.send(Err(RuntimeStoreError::RecoveryInProgress));
            }
            SafetyCommand::MarkConversationRecoveryBlocked { reply, .. } => {
                let _ = reply.send(Err(RuntimeStoreError::RecoveryInProgress));
            }
            SafetyCommand::FailClaimedNativeMetadataMutation { reply, .. } => {
                let _ = reply.send(Err(RuntimeStoreError::RecoveryInProgress));
            }
            SafetyCommand::MarkNativeMetadataMutationOutcomeUnknown { reply, .. } => {
                let _ = reply.send(Err(RuntimeStoreError::RecoveryInProgress));
            }
            SafetyCommand::FinalizeNativeMetadataMutationReadback { reply, .. } => {
                let _ = reply.send(Err(RuntimeStoreError::RecoveryInProgress));
            }
            SafetyCommand::TerminateAccepted { reply, .. } => {
                let _ = reply.send(Err(RuntimeStoreError::RecoveryInProgress));
            }
            SafetyCommand::TerminateStartedBeforeRelease { reply, .. } => {
                let _ = reply.send(Err(RuntimeStoreError::RecoveryInProgress));
            }
            SafetyCommand::MarkApprovalApplied { reply, .. } => {
                let _ = reply.send(Err(RuntimeStoreError::RecoveryInProgress));
            }
            SafetyCommand::MarkApprovalDeliveryFailed { reply, .. } => {
                let _ = reply.send(Err(RuntimeStoreError::RecoveryInProgress));
            }
            SafetyCommand::ExpireApproval { reply, .. } => {
                let _ = reply.send(Err(RuntimeStoreError::RecoveryInProgress));
            }
            SafetyCommand::AcknowledgePublicationCommit { reply, .. } => {
                let _ = reply.send(Err(RuntimeStoreError::RecoveryInProgress));
            }
            SafetyCommand::AcknowledgePublicationDelivery { reply, .. } => {
                let _ = reply.send(Err(RuntimeStoreError::RecoveryInProgress));
            }
        }
        drop(memory_permit);
        return;
    }
    match command {
        SafetyCommand::PrepareMachineIdentity { binding, reply } => {
            let _ = reply.send(machine_identity::prepare_machine_identity(
                state, config, binding,
            ));
        }
        SafetyCommand::ActivateMachineIdentity { binding, reply } => {
            let _ = reply.send(machine_identity::activate_machine_identity(
                state, config, binding,
            ));
        }
        SafetyCommand::PrepareMachineEnrollment { prepared, reply } => {
            let _ = reply.send(machine_remote::prepare_machine_enrollment(
                state, config, *prepared,
            ));
        }
        SafetyCommand::RecordValidatedEnrollmentResponse { prepared, reply } => {
            let _ = reply.send(machine_remote::record_validated_enrollment_response(
                state, config, prepared,
            ));
        }
        SafetyCommand::ActivateMachineEnrollment {
            expected_request_hash,
            expected_response_hash,
            reply,
        } => {
            let _ = reply.send(machine_remote::activate_machine_enrollment(
                state,
                config,
                expected_request_hash,
                expected_response_hash,
            ));
        }
        SafetyCommand::PrepareMachineRetirement { prepared, reply } => {
            let _ = reply.send(machine_remote::prepare_machine_retirement(
                state, config, prepared,
            ));
        }
        SafetyCommand::RecordMachineRetirementTerminal { prepared, reply } => {
            let _ = reply.send(machine_remote::record_machine_retirement_terminal(
                state, config, prepared,
            ));
        }
        SafetyCommand::ConfirmMachinePurgeReadbackAbsent { prepared, reply } => {
            let _ = reply.send(machine_remote::confirm_machine_purge_readback_absent(
                state, config, prepared,
            ));
        }
        SafetyCommand::RecordRootLostMachinePurge { prepared, reply } => {
            let _ = reply.send(machine_remote::record_root_lost_machine_purge(
                state, config, *prepared,
            ));
        }
        SafetyCommand::FinalizeMachineLocalDeletion {
            expected_reset_kind,
            expected_purge_proof_hash,
            cleanup_witness_hash,
            reply,
        } => {
            let _ = reply.send(machine_remote::finalize_machine_local_deletion(
                state,
                config,
                expected_reset_kind,
                expected_purge_proof_hash,
                cleanup_witness_hash,
            ));
        }
        SafetyCommand::RecordEnrollmentReceipt { receipt, reply } => {
            let _ = reply.send(sqlite::record_machine_enrollment_receipt(
                state, config, receipt,
            ));
        }
        SafetyCommand::FinalizeAdminUpgrade {
            command,
            terminal,
            reply,
        } => {
            let _ = reply.send(admin::finalize_admin_upgrade(
                state, config, command, terminal,
            ));
        }
        SafetyCommand::PersistFence { input, reply } => {
            let _ = reply.send(journal::persist_execution_fence(state, config, input));
        }
        SafetyCommand::AuthorizeRelease { input, reply } => {
            let _ = reply.send(journal::authorize_execution_release(state, config, input));
        }
        SafetyCommand::PersistNativeMetadataEffectFence { input, reply } => {
            let _ = reply.send(native_projection::persist_native_metadata_effect_fence(
                state, config, input,
            ));
        }
        SafetyCommand::AuthorizeNativeMetadataEffectRelease { input, reply } => {
            let _ = reply.send(native_projection::authorize_native_metadata_effect_release(
                state, config, input,
            ));
        }
        SafetyCommand::FailUnreleasedNativeMetadataEffect { input, reply } => {
            let mut effects = CommandStreamEffects::default();
            let result = native_projection::fail_unreleased_native_metadata_effect(
                state,
                config,
                input,
                &mut effects,
            );
            let result = notify_after_durable_outcome(result, state, config, commit_hub, &effects);
            let _ = reply.send(result);
        }
        SafetyCommand::CompleteCommand { input, reply } => {
            let mut effects = CommandStreamEffects::default();
            let result = journal::complete_command_with_event(state, config, input, &mut effects);
            let result = notify_after_durable_outcome(result, state, config, commit_hub, &effects);
            let _ = reply.send(result);
        }
        SafetyCommand::RecoverStartedCommand { input, reply } => {
            let mut effects = CommandStreamEffects::default();
            let result =
                journal::recover_started_command_with_event(state, config, input, &mut effects);
            let result = notify_after_durable_outcome(result, state, config, commit_hub, &effects);
            let _ = reply.send(result);
        }
        SafetyCommand::MarkConversationRecoveryBlocked { input, reply } => {
            let _ = reply.send(journal::mark_conversation_recovery_blocked(
                state, config, input,
            ));
        }
        SafetyCommand::FailClaimedNativeMetadataMutation {
            mutation,
            failure,
            reply,
        } => {
            let mut effects = CommandStreamEffects::default();
            let result = metadata::fail_claimed_native_metadata_mutation(
                state,
                config,
                mutation,
                failure,
                &mut effects,
            );
            let result = notify_after_durable_outcome(result, state, config, commit_hub, &effects);
            let _ = reply.send(result);
        }
        SafetyCommand::MarkNativeMetadataMutationOutcomeUnknown { mutation, reply } => {
            let _ = reply.send(metadata::mark_native_metadata_mutation_outcome_unknown(
                state, config, mutation,
            ));
        }
        SafetyCommand::FinalizeNativeMetadataMutationReadback {
            mutation,
            readback,
            reply,
        } => {
            let mut effects = CommandStreamEffects::default();
            let result = metadata::finalize_native_metadata_mutation_readback(
                state,
                config,
                mutation,
                readback,
                &mut effects,
            );
            let result = notify_after_durable_outcome(result, state, config, commit_hub, &effects);
            let _ = reply.send(result);
        }
        SafetyCommand::TerminateAccepted { input, reply } => {
            let mut effects = CommandStreamEffects::default();
            let result = journal::terminate_accepted_command(state, config, input, &mut effects);
            let result = notify_after_durable_outcome(result, state, config, commit_hub, &effects);
            let _ = reply.send(result);
        }
        SafetyCommand::TerminateStartedBeforeRelease { input, reply } => {
            let mut effects = CommandStreamEffects::default();
            let result =
                journal::terminate_started_before_release(state, config, input, &mut effects);
            let result = notify_after_durable_outcome(result, state, config, commit_hub, &effects);
            let _ = reply.send(result);
        }
        SafetyCommand::MarkApprovalApplied { input, reply } => {
            let mut effects = CommandStreamEffects::default();
            let result = approval::mark_approval_applied(state, config, input, &mut effects);
            let result = notify_after_durable_outcome(result, state, config, commit_hub, &effects);
            let _ = reply.send(result);
        }
        SafetyCommand::MarkApprovalDeliveryFailed { input, reply } => {
            let mut effects = CommandStreamEffects::default();
            let result =
                approval::mark_approval_delivery_failed(state, config, input, &mut effects);
            let result = notify_after_durable_outcome(result, state, config, commit_hub, &effects);
            let _ = reply.send(result);
        }
        SafetyCommand::ExpireApproval { input, reply } => {
            let mut effects = CommandStreamEffects::default();
            let result = approval::expire_approval(state, config, input, &mut effects);
            let result = notify_after_durable_outcome(result, state, config, commit_hub, &effects);
            let _ = reply.send(result);
        }
        SafetyCommand::AcknowledgePublicationCommit {
            publication_stream_id,
            generation,
            stream_seq,
            blob_sha256,
            reply,
        } => {
            let result = config
                .clock
                .now_ms()
                .map_err(RuntimeStoreError::from)
                .and_then(|now| {
                    super::publication::acknowledge_publication_commit(
                        state,
                        config,
                        publication_stream_id,
                        generation,
                        stream_seq,
                        blob_sha256,
                        now,
                    )
                });
            let _ = reply.send(result);
        }
        SafetyCommand::AcknowledgePublicationDelivery {
            publication_stream_id,
            generation,
            stream_seq,
            blob_sha256,
            reply,
        } => {
            let result = config
                .clock
                .now_ms()
                .map_err(RuntimeStoreError::from)
                .and_then(|now| {
                    super::publication::acknowledge_publication_delivery(
                        state,
                        config,
                        publication_stream_id,
                        generation,
                        stream_seq,
                        blob_sha256,
                        now,
                    )
                });
            let _ = reply.send(result);
        }
    }
    drop(memory_permit);
}

fn handle_read(
    command: ReadCommand,
    state: &mut sqlite::RuntimeSqlite,
    config: &RuntimeStoreConfig,
    commit_hub: &mut StoreCommitHub,
    cleanup_tx: &mpsc::UnboundedSender<StoreCleanup>,
) {
    match command {
        ReadCommand::Inspect { reply } => {
            let result = config
                .fault_injector
                .before_operation(RuntimeStoreOperation::Inspect)
                .and_then(|()| sqlite::snapshot(&state.connection, config.busy_timeout_ms));
            let _ = reply.send(result);
        }
        ReadCommand::LoadMachineIdentityState { reply } => {
            let _ = reply.send(machine_identity::load_machine_identity_state(
                &state.connection,
                &state.key_bundle,
                state.database_id,
            ));
        }
        ReadCommand::LoadMachineEnrollmentState { reply } => {
            let _ = reply.send(machine_remote::load_machine_enrollment_state(
                &state.connection,
                &state.key_bundle,
                state.database_id,
            ));
        }
        ReadCommand::LoadPendingAdminUpgrades { cursor, reply } => {
            let _ = reply.send(admin::load_pending_admin_upgrades(
                &state.connection,
                &state.key_bundle,
                state.database_id,
                cursor,
            ));
        }
        ReadCommand::AcceptCompletedNativeProjectionScan {
            namespace,
            scan_generation,
            epoch_source,
            reply,
        } => {
            let result = if state.recovery_scan.is_some() {
                Err(RuntimeStoreError::RecoveryInProgress)
            } else {
                advance_native_projection_scan_epoch(&epoch_source).and_then(|scan_epoch| {
                    config
                        .clock
                        .now_ms()
                        .map_err(RuntimeStoreError::from)
                        .and_then(|completed_at_ms| {
                            native_projection::completed_native_projection_generation(
                                state.database_id,
                                namespace,
                                scan_generation,
                                completed_at_ms,
                                scan_epoch,
                                epoch_source,
                            )
                            .map(Arc::new)
                        })
                })
            };
            let _ = reply.send(result);
        }
        ReadCommand::PlanNativeProjectionReconciliation {
            completed,
            cursor,
            reply,
        } => {
            let result = if state.recovery_scan.is_some() {
                Err(RuntimeStoreError::RecoveryInProgress)
            } else {
                config
                    .clock
                    .now_ms()
                    .map_err(RuntimeStoreError::from)
                    .and_then(|planned_at_ms| {
                        native_projection::plan_native_projection_reconciliation_page(
                            &state.connection,
                            &state.key_bundle,
                            state.database_id,
                            completed.as_ref(),
                            cursor,
                            planned_at_ms,
                        )
                    })
            };
            let _ = reply.send(result);
        }
        ReadCommand::PlanNativeProjectionRetirement {
            namespace,
            cursor,
            reply,
        } => {
            let result = if state.recovery_scan.is_some() {
                Err(RuntimeStoreError::RecoveryInProgress)
            } else {
                let cutoff = cursor.map_or_else(
                    || config.clock.now_ms().map_err(RuntimeStoreError::from),
                    |value| Ok(value.cutoff_ms()),
                );
                cutoff.and_then(|cutoff_ms| {
                    native_projection::plan_native_projection_retirement_page(
                        &state.connection,
                        &state.key_bundle,
                        state.database_id,
                        namespace,
                        cutoff_ms,
                        cursor,
                    )
                })
            };
            let _ = reply.send(result);
        }
        ReadCommand::BeginRecoveryScan { reply } => {
            let mut effects = CommandStreamEffects::default();
            let result = journal::begin_recovery_scan(state, config, &mut effects);
            let result = notify_after_durable_outcome(result, state, config, commit_hub, &effects);
            let _ = reply.send(result);
        }
        ReadCommand::BeginRecoveryVerificationScan { reply } => {
            let mut effects = CommandStreamEffects::default();
            let result = journal::begin_recovery_verification_scan(state, config, &mut effects);
            let result = notify_after_durable_outcome(result, state, config, commit_hub, &effects);
            let _ = reply.send(result);
        }
        ReadCommand::LoadRecoveryPage { cursor, reply } => {
            let _ = reply.send(journal::load_recovery_page(state, cursor));
        }
        ReadCommand::FinishRecoveryScan { completion, reply } => {
            let _ = reply.send(journal::finish_recovery_scan(state, completion));
        }
        ReadCommand::ResolveAdapterState {
            namespace,
            adapter_state_key,
            reply,
        } => {
            let _ = reply.send(journal::resolve_adapter_state(
                state,
                namespace,
                adapter_state_key,
            ));
        }
        ReadCommand::LoadActiveNativeMetadataMutations { cursor, reply } => {
            let _ = reply.send(metadata::load_active_native_metadata_mutations(
                &state.connection,
                &state.key_bundle,
                state.database_id,
                cursor,
            ));
        }
        ReadCommand::LoadNativeMetadataEffectRecoveryRecord { mutation, reply } => {
            let _ = reply.send(
                native_projection::load_native_metadata_effect_recovery_record(
                    &state.connection,
                    &state.key_bundle,
                    state.database_id,
                    &mutation,
                ),
            );
        }
        ReadCommand::QueryCommandReceipt { input, reply } => {
            let _ = reply.send(journal::query_command_receipt(state, input));
        }
        ReadCommand::LoadPendingPublicationStreams { reply } => {
            let _ = reply.send(super::publication::load_pending_publication_stream_ids(
                &state.connection,
                &state.key_bundle,
                state.database_id,
            ));
        }
        ReadCommand::RegisterStreamBarrier { request, reply } => {
            let result = register_stream_barrier_on_worker(state, config, commit_hub, request);
            send_stream_barrier_reply(reply, result, state, commit_hub);
        }
        ReadCommand::ReleaseStreamWatch { token, reply } => {
            let _ = reply.send(commit_hub.release(&token));
        }
        ReadCommand::AcquireBackfillPin {
            target,
            after,
            reply,
        } => {
            let result = config
                .clock
                .now_ms()
                .map_err(RuntimeStoreError::from)
                .and_then(|now| stream::acquire_backfill_pin(state, target, after, now));
            stream_pipeline::send_backfill_pin_reply(reply, result, cleanup_tx);
        }
        ReadCommand::PrepareBackfillPage { pin, after, reply } => {
            let result = config
                .clock
                .now_ms()
                .map_err(RuntimeStoreError::from)
                .and_then(|now| stream::prepare_backfill_page(state, &pin, after, now));
            let _ = reply.send(result);
        }
        ReadCommand::ValidateBackfillPage { completion, reply } => {
            let result = config
                .clock
                .now_ms()
                .map_err(RuntimeStoreError::from)
                .and_then(|now| stream::validate_backfill_page(state, &completion, now));
            let _ = reply.send(result);
        }
        ReadCommand::CompleteBackfillPage { completion, reply } => {
            let result = config
                .clock
                .now_ms()
                .map_err(RuntimeStoreError::from)
                .and_then(|now| stream::complete_backfill_page(state, &completion, now));
            let _ = reply.send(result);
        }
        ReadCommand::ReleaseBackfillPin { pin_id, reply } => {
            let _ = reply.send(stream::release_backfill_pin(state, pin_id));
        }
        ReadCommand::AcquireSnapshotBuildPin {
            conversation_id,
            reply,
        } => {
            let result = config
                .clock
                .now_ms()
                .map_err(RuntimeStoreError::from)
                .and_then(|now| {
                    let context = journal::load_authenticated_conversation_snapshot_context(
                        &state.connection,
                        &state.key_bundle,
                        state.database_id,
                        conversation_id,
                    )?;
                    let pin = stream::acquire_snapshot_build_pin_at(
                        &state.connection,
                        conversation_id,
                        context.event_high_water,
                        now,
                    )?;
                    Ok(match context.origin {
                        SnapshotOrigin::Managed => SnapshotBarrierSource::Build(pin),
                        SnapshotOrigin::NativeProjected => SnapshotBarrierSource::Dynamic(pin),
                    })
                });
            send_snapshot_build_pin_reply(reply, result, state, commit_hub, cleanup_tx);
        }
        ReadCommand::ReleaseSnapshotBuildPin { pin, reply } => {
            let _ = reply.send(stream::release_snapshot_build_pin(state, &pin));
        }
        #[cfg(test)]
        ReadCommand::ActiveSnapshotBuildPinCountForTest { reply } => {
            let _ = reply.send(stream::active_snapshot_build_pin_count(state));
        }
        ReadCommand::LoadAuthenticatedConversationSnapshotContext {
            conversation_id,
            reply,
        } => {
            let _ = reply.send(journal::load_authenticated_conversation_snapshot_context(
                &state.connection,
                &state.key_bundle,
                state.database_id,
                conversation_id,
            ));
        }
        ReadCommand::LoadConfigurationStateAtEventCursor {
            conversation_id,
            base_event_seq,
            reply,
        } => {
            let _ = reply.send(configuration::load_configuration_state_at_event_cursor(
                &state.connection,
                &state.key_bundle,
                state.database_id,
                conversation_id,
                base_event_seq,
            ));
        }
        ReadCommand::PrepareAuthenticatedSnapshotBuildContext { pin, reply } => {
            let result = config
                .clock
                .now_ms()
                .map_err(RuntimeStoreError::from)
                .and_then(|now_ms| {
                    stream::validate_snapshot_build_pin(&state.connection, &pin, now_ms)?;
                    let context = journal::load_authenticated_conversation_snapshot_context(
                        &state.connection,
                        &state.key_bundle,
                        state.database_id,
                        pin.conversation_id(),
                    )?;
                    if pin.base_event_seq() > context.event_high_water {
                        return Err(RuntimeStoreError::InvalidStateTransition);
                    }
                    Ok(context)
                });
            let _ = reply.send(result);
        }
    }
}

/// mutation 的 Result 不能作为 COMMIT 事实源。这里只处理 transaction 已 promote 的
/// exact durable-possible effects，并且仅在目标仍有 watcher 时做 authenticated readback。
/// 单目标 readback 失败关闭该 bucket，但不改变原 mutation outcome 或阻断其他目标。
fn notify_after_durable_outcome<T>(
    result: Result<T, RuntimeStoreError>,
    state: &sqlite::RuntimeSqlite,
    config: &RuntimeStoreConfig,
    commit_hub: &mut StoreCommitHub,
    effects: &CommandStreamEffects,
) -> Result<T, RuntimeStoreError> {
    if effects.is_empty() {
        return result;
    }
    for target in effects.targets() {
        if !commit_hub.has_watchers(target) {
            continue;
        }
        match config
            .fault_injector
            .before_operation(RuntimeStoreOperation::StreamNotificationReadback)
            .and_then(|()| stream::load_authenticated_target_cut(state, target))
        {
            Ok(cut) => {
                commit_hub.notify_committed(target, cut.high_water);
            }
            Err(_) => {
                commit_hub.fail_closed(target);
                let target_kind = match target {
                    RuntimeStreamTarget::Catalog => "catalog",
                    RuntimeStreamTarget::Conversation(_) => "conversation",
                };
                crate::diag::log("runtime_stream_notification_readback_failed", target_kind);
            }
        }
    }
    result
}

mod critical_command;
mod execution_event;

#[cfg(test)]
mod oversized_event_page_tests;

#[cfg(test)]
mod stream_barrier_reply_tests;

#[cfg(test)]
mod shutdown_tests;
