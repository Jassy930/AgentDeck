//! Runtime-owned native metadata side-effect coordinator.
//!
//! Adapter 只能准备 effect spec 与做 authenticated readback；本模块独占 claim、
//! current-binary exec-gate、durable fence/release、exact process-group cleanup 与 Store
//! finalize。release 之后任何不确定性都先 fencing，再 readback，且 startup 永不 spawn。

#[cfg(test)]
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use agentdeck_protocol::AgentKind;
use agentdeck_protocol::runtime::{ConversationMetadataMutation, RuntimeFailure};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::task::JoinHandle;

use crate::agent::{
    AdapterStateHandle, NativeMetadataEffectError, NativeMetadataEffectRequest,
    NativeMetadataEffectSpec, NativeMetadataReadback,
};
use crate::exec_gate::{
    ExecGateError, GateBinding, GatedChildIo, GatedChildRelease, GatedChildSpawnError,
    NativeGatedChildOwner, NativeMetadataGatedChild,
};
use crate::runtime::process_identity::{
    ProcessGroupController, ProcessIdentity, ProcessObservation, ProcessSignal,
    SystemProcessGroupController,
};
use crate::runtime::router::AgentRouter;
use crate::runtime::store::{
    AuthorizeNativeMetadataEffectRelease, ClaimNativeMetadataMutationOutcome,
    FailUnreleasedNativeMetadataEffect, NativeMetadataEffectFenceRecord,
    NativeMetadataEffectUnreleasedCleanupAuthority, NativeMetadataMutationClaim,
    NativeMetadataMutationReadback, NativeMetadataMutationStatus, PersistNativeMetadataEffectFence,
    RuntimeId, RuntimeIdKind, RuntimeStoreError, RuntimeStoreHandle, SnapshotOrigin,
    UpdateConversationMetadataOutcome, UpdateManagedConversationMetadata,
};

const EFFECT_NONCE_BYTES: usize = 32;
const EFFECT_COMPLETION_TIMEOUT: Duration = Duration::from_secs(30);
const TERM_GRACE: Duration = Duration::from_secs(2);
const KILL_GRACE: Duration = Duration::from_secs(2);
const OWNER_JOIN_GRACE: Duration = Duration::from_secs(5);

const FAILURE_PREPARE: &str = "daemon.conversation.native_metadata_prepare_failed";
const FAILURE_GATE: &str = "daemon.conversation.native_metadata_gate_failed";
const FAILURE_UNRELEASED: &str = "daemon.conversation.native_metadata_unreleased";
const FAILURE_RECOVERY: &str = "daemon.conversation.native_metadata_recovered_unreleased";

#[derive(Debug)]
pub(crate) enum NativeMutationOutcome {
    Store(UpdateConversationMetadataOutcome),
    Rejected(RuntimeFailure),
    OutcomeUnknown { conversation_id: RuntimeId },
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct NativeMetadataRecoveryReport {
    pub(crate) claimed_failed: u64,
    pub(crate) unreleased_failed: u64,
    pub(crate) released_applied: u64,
    pub(crate) released_unknown: u64,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum NativeMutationCoordinatorError {
    #[error("native metadata Store operation failed: {0}")]
    Store(#[from] RuntimeStoreError),
    #[error("native metadata exec-gate spawn failed: {0}")]
    GateSpawn(#[from] GatedChildSpawnError),
    #[error("native metadata exec-gate operation failed: {0}")]
    Gate(#[from] ExecGateError),
    #[error("native metadata adapter context is invalid")]
    InvalidContext,
    #[error("native metadata effect nonce entropy is unavailable")]
    Entropy,
    #[error("native metadata process group could not be fenced")]
    Fence,
    #[error("native metadata gate owner could not be reaped")]
    Owner,
}

#[derive(Clone)]
pub(crate) struct NativeMutationCoordinator {
    store: RuntimeStoreHandle,
    router: Arc<dyn NativeMetadataRouter>,
    daemon_boot_id: RuntimeId,
    processes: Arc<dyn ProcessGroupController>,
    effect_mode: NativeMetadataEffectMode,
    #[cfg(test)]
    gate_binary: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NativeMetadataEffectMode {
    PostMvpGated,
    #[cfg(test)]
    SyntheticTest,
}

#[async_trait::async_trait]
trait NativeMetadataRouter: Send + Sync + 'static {
    async fn prepare(
        &self,
        agent_kind: AgentKind,
        request: &NativeMetadataEffectRequest,
    ) -> Result<NativeMetadataEffectSpec, NativeMetadataEffectError>;

    async fn readback(
        &self,
        agent_kind: AgentKind,
        request: &NativeMetadataEffectRequest,
    ) -> Result<NativeMetadataReadback, NativeMetadataEffectError>;
}

#[async_trait::async_trait]
impl NativeMetadataRouter for AgentRouter {
    async fn prepare(
        &self,
        agent_kind: AgentKind,
        request: &NativeMetadataEffectRequest,
    ) -> Result<NativeMetadataEffectSpec, NativeMetadataEffectError> {
        self.prepare_native_metadata_effect(agent_kind, request)
            .await
    }

    async fn readback(
        &self,
        agent_kind: AgentKind,
        request: &NativeMetadataEffectRequest,
    ) -> Result<NativeMetadataReadback, NativeMetadataEffectError> {
        self.readback_native_metadata_effect(agent_kind, request)
            .await
    }
}

impl NativeMutationCoordinator {
    pub(crate) fn new(
        store: RuntimeStoreHandle,
        router: Arc<AgentRouter>,
        daemon_boot_id: RuntimeId,
    ) -> Result<Self, NativeMutationCoordinatorError> {
        if daemon_boot_id.kind() != RuntimeIdKind::DaemonBoot {
            return Err(NativeMutationCoordinatorError::InvalidContext);
        }
        Ok(Self {
            store,
            router,
            daemon_boot_id,
            processes: Arc::new(SystemProcessGroupController),
            effect_mode: NativeMetadataEffectMode::PostMvpGated,
            #[cfg(test)]
            gate_binary: None,
        })
    }

    #[cfg(test)]
    fn for_test(
        store: RuntimeStoreHandle,
        router: Arc<dyn NativeMetadataRouter>,
        daemon_boot_id: RuntimeId,
        processes: Arc<dyn ProcessGroupController>,
    ) -> Self {
        Self {
            store,
            router,
            daemon_boot_id,
            processes,
            effect_mode: NativeMetadataEffectMode::SyntheticTest,
            gate_binary: None,
        }
    }

    #[cfg(test)]
    fn for_test_with_gate_binary(
        store: RuntimeStoreHandle,
        router: Arc<dyn NativeMetadataRouter>,
        daemon_boot_id: RuntimeId,
        processes: Arc<dyn ProcessGroupController>,
        gate_binary: PathBuf,
    ) -> Self {
        Self {
            store,
            router,
            daemon_boot_id,
            processes,
            effect_mode: NativeMetadataEffectMode::SyntheticTest,
            gate_binary: Some(gate_binary),
        }
    }

    pub(crate) async fn execute(
        &self,
        input: UpdateManagedConversationMetadata,
    ) -> Result<NativeMutationOutcome, NativeMutationCoordinatorError> {
        let mutation = input.mutation.clone();
        if !matches!(
            &mutation,
            ConversationMetadataMutation::Rename { title: Some(_) }
        ) {
            return Ok(NativeMutationOutcome::Rejected(RuntimeFailure::new(
                "daemon.conversation.metadata_unsupported",
                "native conversation metadata mutation is unsupported",
            )));
        }
        if self.effect_mode == NativeMetadataEffectMode::PostMvpGated {
            return Ok(NativeMutationOutcome::Rejected(RuntimeFailure::new(
                "daemon.conversation.metadata_unsupported",
                "live native metadata mutation is post-MVP gated",
            )));
        }

        let claimed = self.store.claim_native_conversation_metadata(input).await?;
        let claim = match claimed {
            ClaimNativeMetadataMutationOutcome::Replayed { outcome } => {
                return Ok(NativeMutationOutcome::Store(outcome));
            }
            ClaimNativeMetadataMutationOutcome::Claimed { mutation } => mutation,
        };
        let (agent_kind, request) = self.effect_request_from_claim(&claim).await?;
        let spec = match self.router.prepare(agent_kind, &request).await {
            Ok(spec) => spec,
            Err(error) => {
                return self
                    .fail_claimed(claim, adapter_failure(FAILURE_PREPARE, error))
                    .await;
            }
        };
        let effect_spec = match NativeMetadataGatedChild::canonical_effect_spec(&spec) {
            Ok(effect_spec) => effect_spec,
            Err(_) => {
                return self
                    .fail_claimed(
                        claim,
                        RuntimeFailure::new(FAILURE_PREPARE, "native effect spec is invalid"),
                    )
                    .await;
            }
        };
        let effect_nonce = match fresh_effect_nonce() {
            Ok(nonce) => nonce,
            Err(_) => {
                return self
                    .fail_claimed(
                        claim,
                        RuntimeFailure::new(FAILURE_PREPARE, "effect nonce entropy unavailable"),
                    )
                    .await;
            }
        };
        let binding = GateBinding::NativeMetadata {
            conversation_id: claim.conversation_id(),
            idempotency_token: *claim.idempotency_token(),
        };
        let mut gate = match self
            .spawn_effect_gate(binding, effect_nonce.clone(), &spec)
            .await
        {
            Ok(gate) => gate,
            Err(error) if error.permits_clean_prepare_failure() => {
                return self
                    .fail_claimed(
                        claim,
                        RuntimeFailure::new(FAILURE_GATE, "native exec gate did not start"),
                    )
                    .await;
            }
            Err(error) => return Err(error.into()),
        };
        let process = gate.process_identity();
        let commitment = *gate.release_token_commitment();
        let io = match gate.take_io() {
            Ok(io) => io,
            Err(error) => {
                let (release, owner) = start_gate_owner(gate, self.processes.clone());
                drop(release);
                fence_and_join(
                    self.processes.as_ref(),
                    process,
                    owner,
                    FenceMode::TerminateThenKill,
                )
                .await?;
                return self
                    .fail_claimed(claim, RuntimeFailure::new(FAILURE_GATE, error.to_string()))
                    .await;
            }
        };
        let (release, owner) = start_gate_owner(gate, self.processes.clone());

        let persisted = match self
            .store
            .persist_native_metadata_effect_fence(PersistNativeMetadataEffectFence {
                mutation: claim.clone(),
                daemon_boot_id: self.daemon_boot_id,
                effect_nonce: effect_nonce.clone(),
                effect_spec: effect_spec.clone(),
                process,
            })
            .await
        {
            Ok(outcome) => outcome,
            Err(RuntimeStoreError::CommitOutcomeUnknown { .. }) => {
                match self
                    .store
                    .persist_native_metadata_effect_fence(PersistNativeMetadataEffectFence {
                        mutation: claim.clone(),
                        daemon_boot_id: self.daemon_boot_id,
                        effect_nonce: effect_nonce.clone(),
                        effect_spec: effect_spec.clone(),
                        process,
                    })
                    .await
                {
                    Ok(outcome) => outcome,
                    Err(error) => {
                        // 首次 commit outcome unknown 后，第二次错误不能再把 gate owner
                        // 交给 Drop 隐式处理：fence 可能已持久化，也可能仍是 Claimed。
                        // 先证明唯一 child/group 清洁，再保留非 terminal 状态给 recovery
                        // 依 durable truth 分流，绝不猜测并终态化。
                        drop(io);
                        drop(release);
                        fence_and_join(
                            self.processes.as_ref(),
                            process,
                            owner,
                            FenceMode::TerminateThenKill,
                        )
                        .await?;
                        return Err(error.into());
                    }
                }
            }
            Err(error) => {
                drop(io);
                drop(release);
                fence_and_join(
                    self.processes.as_ref(),
                    process,
                    owner,
                    FenceMode::TerminateThenKill,
                )
                .await?;
                return self
                    .fail_claimed(
                        claim,
                        RuntimeFailure::new(
                            FAILURE_GATE,
                            format!("native effect fence was not persisted: {error}"),
                        ),
                    )
                    .await;
            }
        };
        if let Err(error) = validate_persisted_fence(
            &persisted.fence,
            binding,
            self.daemon_boot_id,
            &effect_nonce,
            &effect_spec,
            process,
        ) {
            drop(io);
            let _authority = cleanup_unreleased_live(
                persisted.unreleased_cleanup_authority,
                release,
                owner,
                self.processes.as_ref(),
                process,
            )
            .await?;
            return Err(error);
        }

        let authorized = match self
            .store
            .authorize_native_metadata_effect_release(AuthorizeNativeMetadataEffectRelease {
                mutation: persisted.mutation.clone(),
                daemon_boot_id: self.daemon_boot_id,
                effect_nonce: effect_nonce.clone(),
                release_token_commitment: commitment,
            })
            .await
        {
            Ok(outcome) => outcome,
            Err(RuntimeStoreError::CommitOutcomeUnknown { .. }) => {
                match self
                    .store
                    .authorize_native_metadata_effect_release(
                        AuthorizeNativeMetadataEffectRelease {
                            mutation: persisted.mutation.clone(),
                            daemon_boot_id: self.daemon_boot_id,
                            effect_nonce: effect_nonce.clone(),
                            release_token_commitment: commitment,
                        },
                    )
                    .await
                {
                    Ok(outcome) => outcome,
                    Err(error) => {
                        // 授权首次 outcome unknown 后不能使用 unreleased authority：durable
                        // 状态也可能已经是 released。保持 gate blocked，先 exact cleanup，
                        // 再让 startup recovery 从 Store 真相决定 unreleased/released 路径。
                        drop(io);
                        drop(release);
                        let _uncertain_authority = persisted.unreleased_cleanup_authority;
                        fence_and_join(
                            self.processes.as_ref(),
                            process,
                            owner,
                            FenceMode::TerminateThenKill,
                        )
                        .await?;
                        return Err(error.into());
                    }
                }
            }
            Err(_) => {
                drop(io);
                let authority = cleanup_unreleased_live(
                    persisted.unreleased_cleanup_authority,
                    release,
                    owner,
                    self.processes.as_ref(),
                    process,
                )
                .await?;
                let outcome = self
                    .store
                    .fail_unreleased_native_metadata_effect(FailUnreleasedNativeMetadataEffect {
                        cleanup_authority: authority,
                        mutation: persisted.mutation,
                        daemon_boot_id: self.daemon_boot_id,
                        effect_nonce,
                        effect_spec,
                        process,
                        failure: RuntimeFailure::new(
                            FAILURE_UNRELEASED,
                            "native effect release was not authorized",
                        ),
                    })
                    .await?;
                return Ok(NativeMutationOutcome::Store(outcome));
            }
        };
        let _invalidated_authority = persisted.unreleased_cleanup_authority;
        let released_mutation = authorized.mutation;
        let release_result = release.release_native_metadata(authorized.permit).await;
        let effect_completed = if release_result.is_ok() {
            wait_effect_io(io).await
        } else {
            drop(io);
            false
        };
        let fence_mode = if effect_completed {
            FenceMode::Kill
        } else {
            FenceMode::TerminateThenKill
        };
        if fence_and_join(self.processes.as_ref(), process, owner, fence_mode)
            .await
            .is_err()
        {
            let _ = self
                .store
                .mark_native_metadata_mutation_outcome_unknown(released_mutation)
                .await;
            return Err(NativeMutationCoordinatorError::Fence);
        }
        self.resolve_released(agent_kind, request, released_mutation)
            .await
    }

    async fn spawn_effect_gate(
        &self,
        binding: GateBinding,
        effect_nonce: Vec<u8>,
        spec: &NativeMetadataEffectSpec,
    ) -> Result<NativeMetadataGatedChild, GatedChildSpawnError> {
        #[cfg(test)]
        if let Some(binary) = self.gate_binary.as_deref() {
            return NativeMetadataGatedChild::spawn_with_binary(
                binary,
                binding,
                self.daemon_boot_id,
                effect_nonce,
                spec,
            )
            .await;
        }
        NativeMetadataGatedChild::spawn_current(binding, self.daemon_boot_id, effect_nonce, spec)
            .await
    }

    pub(crate) async fn recover(
        &self,
    ) -> Result<NativeMetadataRecoveryReport, NativeMutationCoordinatorError> {
        let mut report = NativeMetadataRecoveryReport::default();
        let mut cursor = None;
        loop {
            let page = self
                .store
                .load_active_native_metadata_mutations(cursor)
                .await?;
            for mutation in page.mutations().iter().cloned() {
                let record = self
                    .store
                    .load_native_metadata_effect_recovery_record(mutation)
                    .await?;
                match record.mutation.status() {
                    NativeMetadataMutationStatus::Claimed => {
                        self.store
                            .fail_claimed_native_metadata_mutation(
                                record.mutation,
                                RuntimeFailure::new(
                                    FAILURE_RECOVERY,
                                    "native effect was never prepared before restart",
                                ),
                            )
                            .await?;
                        report.claimed_failed += 1;
                    }
                    NativeMetadataMutationStatus::Applying
                        if record
                            .fence
                            .as_ref()
                            .is_some_and(|fence| fence.release_authorized_at_ms().is_none()) =>
                    {
                        let fence = record
                            .fence
                            .ok_or(NativeMutationCoordinatorError::InvalidContext)?;
                        let authority = record
                            .unreleased_cleanup_authority
                            .ok_or(NativeMutationCoordinatorError::InvalidContext)?;
                        let authority = cleanup_unreleased_recovery(
                            authority,
                            self.processes.as_ref(),
                            fence.process(),
                        )
                        .await?;
                        self.store
                            .fail_unreleased_native_metadata_effect(
                                FailUnreleasedNativeMetadataEffect {
                                    cleanup_authority: authority,
                                    mutation: record.mutation,
                                    daemon_boot_id: fence.daemon_boot_id(),
                                    effect_nonce: fence.effect_nonce().to_vec(),
                                    effect_spec: fence.effect_spec().to_vec(),
                                    process: fence.process(),
                                    failure: RuntimeFailure::new(
                                        FAILURE_RECOVERY,
                                        "unreleased native effect was fenced during restart",
                                    ),
                                },
                            )
                            .await?;
                        report.unreleased_failed += 1;
                    }
                    NativeMetadataMutationStatus::Applying
                    | NativeMetadataMutationStatus::OutcomeUnknown => {
                        let fence = record
                            .fence
                            .ok_or(NativeMutationCoordinatorError::InvalidContext)?;
                        if fence.release_authorized_at_ms().is_none()
                            || fence.release_token_commitment().is_none()
                            || record.unreleased_cleanup_authority.is_some()
                        {
                            return Err(NativeMutationCoordinatorError::InvalidContext);
                        }
                        fence_exact_group(
                            self.processes.as_ref(),
                            fence.process(),
                            FenceMode::TerminateThenKill,
                        )
                        .await?;
                        let (agent_kind, request) =
                            self.effect_request_from_claim(&record.mutation).await?;
                        match self
                            .resolve_released(agent_kind, request, record.mutation)
                            .await?
                        {
                            NativeMutationOutcome::Store(_) => report.released_applied += 1,
                            NativeMutationOutcome::OutcomeUnknown { .. } => {
                                report.released_unknown += 1;
                            }
                            NativeMutationOutcome::Rejected(_) => {
                                return Err(NativeMutationCoordinatorError::InvalidContext);
                            }
                        }
                    }
                }
            }
            cursor = page.next_cursor();
            if cursor.is_none() {
                return Ok(report);
            }
        }
    }

    async fn effect_request(
        &self,
        claim: &NativeMetadataMutationClaim,
        mutation: ConversationMetadataMutation,
    ) -> Result<(AgentKind, NativeMetadataEffectRequest), NativeMutationCoordinatorError> {
        let context = self
            .store
            .load_authenticated_conversation_snapshot_context(claim.conversation_id())
            .await?;
        if context.origin != SnapshotOrigin::NativeProjected {
            return Err(NativeMutationCoordinatorError::InvalidContext);
        }
        let adapter_state = AdapterStateHandle::new(context.adapter_state_key)
            .map_err(|_| NativeMutationCoordinatorError::InvalidContext)?;
        Ok((
            context.agent_kind,
            NativeMetadataEffectRequest::new(adapter_state, mutation),
        ))
    }

    async fn effect_request_from_claim(
        &self,
        claim: &NativeMetadataMutationClaim,
    ) -> Result<(AgentKind, NativeMetadataEffectRequest), NativeMutationCoordinatorError> {
        self.effect_request(
            claim,
            ConversationMetadataMutation::Rename {
                title: claim.requested_title().map(str::to_owned),
            },
        )
        .await
    }

    async fn fail_claimed(
        &self,
        claim: NativeMetadataMutationClaim,
        failure: RuntimeFailure,
    ) -> Result<NativeMutationOutcome, NativeMutationCoordinatorError> {
        let outcome = self
            .store
            .fail_claimed_native_metadata_mutation(claim, failure)
            .await?;
        Ok(NativeMutationOutcome::Store(outcome))
    }

    async fn resolve_released(
        &self,
        agent_kind: AgentKind,
        request: NativeMetadataEffectRequest,
        mutation: NativeMetadataMutationClaim,
    ) -> Result<NativeMutationOutcome, NativeMutationCoordinatorError> {
        match self.router.readback(agent_kind, &request).await {
            Ok(NativeMetadataReadback::Applied) => {
                let readback = NativeMetadataMutationReadback::Applied {
                    observed_title: mutation.requested_title().map(str::to_owned),
                };
                let outcome = match self
                    .store
                    .finalize_native_metadata_mutation_readback(mutation.clone(), readback.clone())
                    .await
                {
                    Ok(outcome) => outcome,
                    Err(RuntimeStoreError::CommitOutcomeUnknown { .. }) => {
                        self.store
                            .finalize_native_metadata_mutation_readback(mutation, readback)
                            .await?
                    }
                    Err(error) => return Err(error.into()),
                };
                Ok(NativeMutationOutcome::Store(outcome))
            }
            Ok(NativeMetadataReadback::Unknown) | Err(_) => {
                let conversation_id = mutation.conversation_id();
                match self
                    .store
                    .mark_native_metadata_mutation_outcome_unknown(mutation.clone())
                    .await
                {
                    Ok(_) => {}
                    Err(RuntimeStoreError::CommitOutcomeUnknown { .. }) => {
                        self.store
                            .mark_native_metadata_mutation_outcome_unknown(mutation)
                            .await?;
                    }
                    Err(error) => return Err(error.into()),
                }
                Ok(NativeMutationOutcome::OutcomeUnknown { conversation_id })
            }
        }
    }
}

fn adapter_failure(code: &'static str, error: NativeMetadataEffectError) -> RuntimeFailure {
    RuntimeFailure::new(code, format!("native metadata adapter failed: {error}"))
}

fn fresh_effect_nonce() -> Result<Vec<u8>, NativeMutationCoordinatorError> {
    let mut nonce = vec![0_u8; EFFECT_NONCE_BYTES];
    getrandom::fill(&mut nonce).map_err(|_| NativeMutationCoordinatorError::Entropy)?;
    if nonce.iter().all(|byte| *byte == 0) {
        return Err(NativeMutationCoordinatorError::Entropy);
    }
    Ok(nonce)
}

fn validate_persisted_fence(
    fence: &NativeMetadataEffectFenceRecord,
    binding: GateBinding,
    daemon_boot_id: RuntimeId,
    effect_nonce: &[u8],
    effect_spec: &[u8],
    process: ProcessIdentity,
) -> Result<(), NativeMutationCoordinatorError> {
    let GateBinding::NativeMetadata {
        conversation_id,
        idempotency_token,
    } = binding
    else {
        return Err(NativeMutationCoordinatorError::InvalidContext);
    };
    if fence.conversation_id() != conversation_id
        || fence.idempotency_token() != &idempotency_token
        || fence.daemon_boot_id() != daemon_boot_id
        || fence.effect_nonce() != effect_nonce
        || fence.effect_spec() != effect_spec
        || fence.process() != process
        || fence.release_authorized_at_ms().is_some()
        || fence.release_token_commitment().is_some()
    {
        return Err(NativeMutationCoordinatorError::InvalidContext);
    }
    Ok(())
}

struct GateOwnerTask {
    task: Option<JoinHandle<Result<(), ExecGateError>>>,
}

impl GateOwnerTask {
    async fn join(mut self) -> Result<(), NativeMutationCoordinatorError> {
        self.join_with_grace(OWNER_JOIN_GRACE).await
    }

    async fn join_with_grace(
        &mut self,
        grace: Duration,
    ) -> Result<(), NativeMutationCoordinatorError> {
        let task = self
            .task
            .take()
            .ok_or(NativeMutationCoordinatorError::Owner)?;
        let mut task = task;
        match tokio::time::timeout(grace, &mut task).await {
            Ok(Ok(Ok(()))) => Ok(()),
            Ok(_) => Err(NativeMutationCoordinatorError::Owner),
            Err(_) => {
                // JoinHandle drop 会 detach task；超时时必须先显式 abort，再等待
                // cancellation 完成，让 task 内唯一 NativeGatedChildOwner 当场 Drop，
                // 触发 exact group kill，并把 std Child waiter 留给既有 OS reaper。
                task.abort();
                let _ = task.await;
                Err(NativeMutationCoordinatorError::Owner)
            }
        }
    }
}

impl Drop for GateOwnerTask {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

fn start_gate_owner(
    gate: NativeMetadataGatedChild,
    processes: Arc<dyn ProcessGroupController>,
) -> (GatedChildRelease, GateOwnerTask) {
    let (release, mut owner): (GatedChildRelease, NativeGatedChildOwner) = gate.into_owner_parts();
    let task = tokio::spawn(async move {
        owner
            .wait_and_verify_group_exit(processes.as_ref(), KILL_GRACE)
            .await
            .map(|_| ())
    });
    (release, GateOwnerTask { task: Some(task) })
}

async fn cleanup_unreleased_live(
    authority: NativeMetadataEffectUnreleasedCleanupAuthority,
    release: GatedChildRelease,
    owner: GateOwnerTask,
    processes: &dyn ProcessGroupController,
    process: ProcessIdentity,
) -> Result<NativeMetadataEffectUnreleasedCleanupAuthority, NativeMutationCoordinatorError> {
    drop(release);
    fence_and_join(processes, process, owner, FenceMode::TerminateThenKill).await?;
    Ok(authority)
}

async fn cleanup_unreleased_recovery(
    authority: NativeMetadataEffectUnreleasedCleanupAuthority,
    processes: &dyn ProcessGroupController,
    process: ProcessIdentity,
) -> Result<NativeMetadataEffectUnreleasedCleanupAuthority, NativeMutationCoordinatorError> {
    fence_exact_group(processes, process, FenceMode::TerminateThenKill).await?;
    Ok(authority)
}

async fn wait_effect_io(io: GatedChildIo) -> bool {
    let GatedChildIo {
        stdin,
        stdout,
        stderr,
    } = io;
    drop(stdin);
    tokio::time::timeout(EFFECT_COMPLETION_TIMEOUT, async move {
        tokio::try_join!(drain(stdout), drain(stderr)).map(|_| ())
    })
    .await
    .is_ok_and(|result| result.is_ok())
}

async fn drain(mut reader: impl AsyncRead + Unpin) -> std::io::Result<()> {
    let mut buffer = [0_u8; 8 * 1024];
    while reader.read(&mut buffer).await? != 0 {}
    Ok(())
}

#[derive(Clone, Copy)]
enum FenceMode {
    Kill,
    TerminateThenKill,
}

async fn fence_and_join(
    processes: &dyn ProcessGroupController,
    process: ProcessIdentity,
    owner: GateOwnerTask,
    mode: FenceMode,
) -> Result<(), NativeMutationCoordinatorError> {
    let (fenced, joined) = tokio::join!(fence_exact_group(processes, process, mode), owner.join());
    fenced?;
    joined
}

async fn fence_exact_group(
    processes: &dyn ProcessGroupController,
    process: ProcessIdentity,
    mode: FenceMode,
) -> Result<(), NativeMutationCoordinatorError> {
    match processes.probe(process).await {
        Ok(ProcessObservation::Exited) => return Ok(()),
        Ok(ProcessObservation::ExactAlive) => {}
        Ok(ProcessObservation::Unknown) => {
            return require_exited(processes.wait_for_exit(process, KILL_GRACE).await);
        }
        Ok(ProcessObservation::IdentityMismatch) | Err(_) => {
            return Err(NativeMutationCoordinatorError::Fence);
        }
    }
    if matches!(mode, FenceMode::TerminateThenKill) {
        processes
            .signal(process, ProcessSignal::Terminate)
            .await
            .map_err(|_| NativeMutationCoordinatorError::Fence)?;
        match processes.wait_for_exit(process, TERM_GRACE).await {
            Ok(ProcessObservation::Exited) => return Ok(()),
            Ok(ProcessObservation::ExactAlive) => {}
            Ok(ProcessObservation::Unknown) => {
                return require_exited(processes.wait_for_exit(process, KILL_GRACE).await);
            }
            Ok(ProcessObservation::IdentityMismatch) | Err(_) => {
                return Err(NativeMutationCoordinatorError::Fence);
            }
        }
    }
    processes
        .signal(process, ProcessSignal::Kill)
        .await
        .map_err(|_| NativeMutationCoordinatorError::Fence)?;
    require_exited(processes.wait_for_exit(process, KILL_GRACE).await)
}

fn require_exited(
    observation: Result<ProcessObservation, crate::runtime::process_identity::ProcessControlError>,
) -> Result<(), NativeMutationCoordinatorError> {
    if matches!(observation, Ok(ProcessObservation::Exited)) {
        Ok(())
    } else {
        Err(NativeMutationCoordinatorError::Fence)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::ffi::OsString;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

    use agentdeck_protocol::ClaudeCodePermissionMode;
    use agentdeck_protocol::runtime::{
        ClaudeCodeConversationConfiguration, ConversationConfiguration, VendorConfigurationSnapshot,
    };
    use rusqlite::Connection;

    use crate::runtime::model::{ConversationDescriptor, RuntimeStoreConfig};
    use crate::runtime::process_identity::ProcessControlError;
    use crate::runtime::store::{
        IdempotencyOwner, ImportNativeProjection, ImportNativeProjectionOutcome,
    };
    use crate::security::{MemoryKeyStore, SecretBytes, StorageKek, load_or_create_storage_kek};

    static NEXT_ROOT: AtomicU64 = AtomicU64::new(1);

    struct DropSignal(Arc<AtomicBool>);

    impl Drop for DropSignal {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn gate_owner_timeout_aborts_and_joins_instead_of_detaching() {
        let dropped = Arc::new(AtomicBool::new(false));
        let task_dropped = Arc::clone(&dropped);
        let task = tokio::spawn(async move {
            let _drop_signal = DropSignal(task_dropped);
            std::future::pending::<()>().await;
            #[allow(unreachable_code)]
            Ok(())
        });
        let mut owner = GateOwnerTask { task: Some(task) };

        assert!(matches!(
            owner.join_with_grace(Duration::from_millis(10)).await,
            Err(NativeMutationCoordinatorError::Owner)
        ));
        assert!(
            dropped.load(Ordering::SeqCst),
            "timed-out owner task must be canceled and dropped before join returns"
        );
        assert!(owner.task.is_none());
    }

    struct TestRoot {
        path: PathBuf,
        keys: MemoryKeyStore,
    }

    impl TestRoot {
        fn new(label: &str) -> Self {
            let path = Path::new("/tmp").join(format!(
                "agentdeck-native-coordinator-{label}-{}-{}",
                std::process::id(),
                NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir(&path).expect("create native coordinator root");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                    .expect("secure native coordinator root");
            }
            Self {
                path,
                keys: MemoryKeyStore::new(),
            }
        }

        fn database(&self) -> PathBuf {
            self.path.join("runtime.db")
        }

        fn storage_kek(&self) -> StorageKek {
            load_or_create_storage_kek(&self.keys, &self.path.join("key-state.db"))
                .expect("load native coordinator StorageKEK")
        }

        async fn open(&self) -> RuntimeStoreHandle {
            RuntimeStoreHandle::open(RuntimeStoreConfig::new(self.database()), self.storage_kek())
                .await
                .expect("open native coordinator Store")
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    struct FakeRouter {
        prepare_calls: AtomicUsize,
        readback_calls: AtomicUsize,
        readback: NativeMetadataReadback,
    }

    #[async_trait::async_trait]
    impl NativeMetadataRouter for FakeRouter {
        async fn prepare(
            &self,
            _agent_kind: AgentKind,
            _request: &NativeMetadataEffectRequest,
        ) -> Result<NativeMetadataEffectSpec, NativeMetadataEffectError> {
            self.prepare_calls.fetch_add(1, Ordering::SeqCst);
            NativeMetadataEffectSpec::new("/usr/bin/true", std::iter::empty::<OsString>(), "/tmp")
        }

        async fn readback(
            &self,
            _agent_kind: AgentKind,
            _request: &NativeMetadataEffectRequest,
        ) -> Result<NativeMetadataReadback, NativeMetadataEffectError> {
            self.readback_calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.readback)
        }
    }

    #[derive(Default)]
    struct ExitedProcesses {
        probes: AtomicUsize,
        signals: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl ProcessGroupController for ExitedProcesses {
        async fn probe(
            &self,
            _identity: ProcessIdentity,
        ) -> Result<ProcessObservation, ProcessControlError> {
            self.probes.fetch_add(1, Ordering::SeqCst);
            Ok(ProcessObservation::Exited)
        }

        async fn signal(
            &self,
            _identity: ProcessIdentity,
            _signal: ProcessSignal,
        ) -> Result<(), ProcessControlError> {
            self.signals.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        async fn wait_for_exit(
            &self,
            _identity: ProcessIdentity,
            _timeout: Duration,
        ) -> Result<ProcessObservation, ProcessControlError> {
            Ok(ProcessObservation::Exited)
        }
    }

    fn configuration() -> ConversationConfiguration {
        ConversationConfiguration::new(VendorConfigurationSnapshot::ClaudeCode(
            ClaudeCodeConversationConfiguration::new(
                ClaudeCodePermissionMode::Default,
                None,
                None,
                None,
            )
            .expect("valid native coordinator config"),
        ))
    }

    async fn import_native(store: &RuntimeStoreHandle) -> RuntimeId {
        let outcome = store
            .claude_code_native_projection_store()
            .import(ImportNativeProjection {
                descriptor: ConversationDescriptor {
                    agent_kind: AgentKind::ClaudeCode,
                    title: Some("before".to_owned()),
                    cwd: PathBuf::new(),
                },
                default_configuration: configuration(),
                private_reference: SecretBytes::new(b"coordinator-native-ref-v1".to_vec()),
                scan_generation: [0x41; 16],
            })
            .await
            .expect("import native coordinator projection");
        match outcome {
            ImportNativeProjectionOutcome::Imported { conversation, .. }
            | ImportNativeProjectionOutcome::Replayed { conversation, .. }
            | ImportNativeProjectionOutcome::Reobserved { conversation, .. }
            | ImportNativeProjectionOutcome::Reappeared { conversation, .. } => {
                conversation.conversation_id
            }
        }
    }

    fn request(conversation_id: RuntimeId, key: &str) -> UpdateManagedConversationMetadata {
        UpdateManagedConversationMetadata {
            conversation_id,
            owner: IdempotencyOwner::Local {
                machine_trust_domain: [0x51; 32],
                uid: 501,
                client_installation_id: [0x52; 16],
            },
            idempotency_key: key.to_owned(),
            expected_entry_revision: 0,
            mutation: ConversationMetadataMutation::Rename {
                title: Some("after".to_owned()),
            },
        }
    }

    async fn claim(
        store: &RuntimeStoreHandle,
        request: UpdateManagedConversationMetadata,
    ) -> NativeMetadataMutationClaim {
        match store
            .claim_native_conversation_metadata(request)
            .await
            .expect("claim native coordinator mutation")
        {
            ClaimNativeMetadataMutationOutcome::Claimed { mutation } => mutation,
            ClaimNativeMetadataMutationOutcome::Replayed { .. } => {
                panic!("fresh coordinator claim unexpectedly replayed")
            }
        }
    }

    fn coordinator(
        store: RuntimeStoreHandle,
        router: Arc<FakeRouter>,
        processes: Arc<ExitedProcesses>,
        boot: RuntimeId,
    ) -> NativeMutationCoordinator {
        NativeMutationCoordinator::for_test(store, router, boot, processes)
    }

    fn synthetic_gate_wrapper(root: &TestRoot) -> PathBuf {
        let test_binary = std::env::current_exe().expect("resolve native coordinator test binary");
        let quoted_binary = format!("'{}'", test_binary.to_string_lossy().replace('\'', "'\\''"));
        let wrapper = root.path.join("synthetic-exec-gate-wrapper.sh");
        fs::write(
            &wrapper,
            format!(
                "#!/bin/sh\nexec {quoted_binary} 'runtime::native_metadata::tests::synthetic_exec_gate_child' --exact --ignored --nocapture\n"
            ),
        )
        .expect("write synthetic exec-gate wrapper");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o700))
                .expect("secure synthetic exec-gate wrapper");
        }
        wrapper
    }

    #[test]
    #[ignore = "spawned only by the harmless synthetic current-binary gate roundtrip"]
    fn synthetic_exec_gate_child() {
        crate::exec_gate::run_from_private_fd().expect("run synthetic child exec gate");
    }

    #[tokio::test]
    async fn production_coordinator_keeps_live_vendor_effect_post_mvp_gated() {
        let root = TestRoot::new("production-effect-gated");
        let store = root.open().await;
        let conversation_id = import_native(&store).await;
        let router = Arc::new(AgentRouter::with_runtime_store(store.clone()));
        let boot = RuntimeId::from_bytes(RuntimeIdKind::DaemonBoot, [0x5F; 16]).unwrap();
        let coordinator = NativeMutationCoordinator::new(store.clone(), router, boot)
            .expect("construct production native metadata coordinator");

        let outcome = coordinator
            .execute(request(conversation_id, "production-gated"))
            .await
            .expect("production gate returns a typed rejection");
        match outcome {
            NativeMutationOutcome::Rejected(failure) => {
                assert_eq!(failure.code, "daemon.conversation.metadata_unsupported");
                assert!(failure.message.contains("post-MVP gated"));
            }
            other => {
                panic!("production coordinator must not execute live vendor effect: {other:?}")
            }
        }
        let connection =
            Connection::open(root.database()).expect("open production-gated evidence database");
        let mutation_rows: i64 = connection
            .query_row("SELECT COUNT(*) FROM metadata_mutation_ledger", [], |row| {
                row.get(0)
            })
            .expect("read production-gated metadata ledger");
        let fence_rows: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM native_metadata_effect_fences",
                [],
                |row| row.get(0),
            )
            .expect("read production-gated effect fences");
        assert_eq!((mutation_rows, fence_rows), (0, 0));
        drop(connection);

        store
            .shutdown()
            .await
            .expect("shutdown production-gated Store");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn synthetic_current_binary_gate_roundtrip_applies_once_and_replays_without_respawn() {
        let root = TestRoot::new("synthetic-gate-roundtrip");
        let store = root.open().await;
        let conversation_id = import_native(&store).await;
        let retry = request(conversation_id, "synthetic-gate-roundtrip");
        let router = Arc::new(FakeRouter {
            prepare_calls: AtomicUsize::new(0),
            readback_calls: AtomicUsize::new(0),
            readback: NativeMetadataReadback::Applied,
        });
        let boot = RuntimeId::from_bytes(RuntimeIdKind::DaemonBoot, [0x60; 16]).unwrap();
        let coordinator = NativeMutationCoordinator::for_test_with_gate_binary(
            store.clone(),
            router.clone(),
            boot,
            Arc::new(SystemProcessGroupController),
            synthetic_gate_wrapper(&root),
        );

        let first = coordinator
            .execute(retry.clone())
            .await
            .expect("synthetic current-binary gate completes");
        assert!(matches!(
            first,
            NativeMutationOutcome::Store(UpdateConversationMetadataOutcome::Applied {
                mutation
            }) if mutation.conversation_id == conversation_id && mutation.entry_revision == 1
        ));
        assert_eq!(router.prepare_calls.load(Ordering::SeqCst), 1);
        assert_eq!(router.readback_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            Connection::open(root.database())
                .expect("open synthetic gate evidence")
                .query_row(
                    "SELECT COUNT(*) FROM native_metadata_effect_fences",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .expect("count synthetic released fence"),
            1
        );

        let replay = coordinator
            .execute(retry)
            .await
            .expect("synthetic metadata replay");
        assert!(matches!(
            replay,
            NativeMutationOutcome::Store(UpdateConversationMetadataOutcome::Replayed {
                mutation
            }) if mutation.conversation_id == conversation_id && mutation.entry_revision == 1
        ));
        assert_eq!(router.prepare_calls.load(Ordering::SeqCst), 1);
        assert_eq!(router.readback_calls.load(Ordering::SeqCst), 1);

        store
            .shutdown()
            .await
            .expect("shutdown synthetic gate Store");
    }

    #[tokio::test]
    async fn startup_claimed_clean_fails_without_adapter_or_spawn() {
        let root = TestRoot::new("claimed-recovery");
        let store = root.open().await;
        let conversation_id = import_native(&store).await;
        let retry = request(conversation_id, "claimed");
        claim(&store, retry.clone()).await;
        store.shutdown().await.expect("shutdown claimed Store");

        let reopened = root.open().await;
        let router = Arc::new(FakeRouter {
            prepare_calls: AtomicUsize::new(0),
            readback_calls: AtomicUsize::new(0),
            readback: NativeMetadataReadback::Applied,
        });
        let processes = Arc::new(ExitedProcesses::default());
        let boot = RuntimeId::from_bytes(RuntimeIdKind::DaemonBoot, [0x61; 16]).unwrap();
        let report = coordinator(reopened.clone(), router.clone(), processes.clone(), boot)
            .recover()
            .await
            .expect("recover claimed mutation");
        assert_eq!(report.claimed_failed, 1);
        assert_eq!(router.prepare_calls.load(Ordering::SeqCst), 0);
        assert_eq!(router.readback_calls.load(Ordering::SeqCst), 0);
        assert_eq!(processes.probes.load(Ordering::SeqCst), 0);
        assert!(matches!(
            reopened
                .claim_native_conversation_metadata(retry)
                .await
                .expect("replay claimed recovery terminal"),
            ClaimNativeMetadataMutationOutcome::Replayed {
                outcome: UpdateConversationMetadataOutcome::Failed { .. }
            }
        ));
        reopened.shutdown().await.expect("shutdown reopened Store");
    }

    #[tokio::test]
    async fn startup_unreleased_consumes_recovery_authority_only_after_exact_absence() {
        let root = TestRoot::new("unreleased-recovery");
        let store = root.open().await;
        let conversation_id = import_native(&store).await;
        let retry = request(conversation_id, "unreleased");
        let mutation = claim(&store, retry.clone()).await;
        let boot = RuntimeId::from_bytes(RuntimeIdKind::DaemonBoot, [0x62; 16]).unwrap();
        let process = ProcessIdentity::new(60_001, 60_001, 7).unwrap();
        store
            .persist_native_metadata_effect_fence(PersistNativeMetadataEffectFence {
                mutation,
                daemon_boot_id: boot,
                effect_nonce: b"unreleased-recovery-nonce".to_vec(),
                effect_spec: b"unreleased-recovery-spec".to_vec(),
                process,
            })
            .await
            .expect("persist unreleased recovery fence");
        store.shutdown().await.expect("shutdown unreleased Store");

        let reopened = root.open().await;
        let router = Arc::new(FakeRouter {
            prepare_calls: AtomicUsize::new(0),
            readback_calls: AtomicUsize::new(0),
            readback: NativeMetadataReadback::Applied,
        });
        let processes = Arc::new(ExitedProcesses::default());
        let report = coordinator(reopened.clone(), router.clone(), processes.clone(), boot)
            .recover()
            .await
            .expect("recover unreleased mutation");
        assert_eq!(report.unreleased_failed, 1);
        assert_eq!(processes.probes.load(Ordering::SeqCst), 1);
        assert_eq!(processes.signals.load(Ordering::SeqCst), 0);
        assert_eq!(router.prepare_calls.load(Ordering::SeqCst), 0);
        assert_eq!(router.readback_calls.load(Ordering::SeqCst), 0);
        assert!(matches!(
            reopened
                .claim_native_conversation_metadata(retry)
                .await
                .expect("replay unreleased recovery terminal"),
            ClaimNativeMetadataMutationOutcome::Replayed {
                outcome: UpdateConversationMetadataOutcome::Failed { .. }
            }
        ));
        reopened.shutdown().await.expect("shutdown reopened Store");
    }

    #[tokio::test]
    async fn startup_released_fences_then_readbacks_and_never_prepares_or_spawns() {
        let root = TestRoot::new("released-recovery");
        let store = root.open().await;
        let conversation_id = import_native(&store).await;
        let mutation = claim(&store, request(conversation_id, "released")).await;
        let boot = RuntimeId::from_bytes(RuntimeIdKind::DaemonBoot, [0x63; 16]).unwrap();
        let process = ProcessIdentity::new(60_002, 60_002, 8).unwrap();
        let persisted = store
            .persist_native_metadata_effect_fence(PersistNativeMetadataEffectFence {
                mutation,
                daemon_boot_id: boot,
                effect_nonce: b"released-recovery-nonce".to_vec(),
                effect_spec: b"released-recovery-spec".to_vec(),
                process,
            })
            .await
            .expect("persist released recovery fence");
        store
            .authorize_native_metadata_effect_release(AuthorizeNativeMetadataEffectRelease {
                mutation: persisted.mutation,
                daemon_boot_id: boot,
                effect_nonce: b"released-recovery-nonce".to_vec(),
                release_token_commitment: [0x64; 32],
            })
            .await
            .expect("authorize released recovery fence");
        store.shutdown().await.expect("shutdown released Store");

        let reopened = root.open().await;
        let router = Arc::new(FakeRouter {
            prepare_calls: AtomicUsize::new(0),
            readback_calls: AtomicUsize::new(0),
            readback: NativeMetadataReadback::Applied,
        });
        let processes = Arc::new(ExitedProcesses::default());
        let report = coordinator(reopened.clone(), router.clone(), processes.clone(), boot)
            .recover()
            .await
            .expect("recover released mutation");
        assert_eq!(report.released_applied, 1);
        assert_eq!(report.released_unknown, 0);
        assert_eq!(processes.probes.load(Ordering::SeqCst), 1);
        assert_eq!(router.prepare_calls.load(Ordering::SeqCst), 0);
        assert_eq!(router.readback_calls.load(Ordering::SeqCst), 1);
        reopened.shutdown().await.expect("shutdown released reopen");
    }
}
