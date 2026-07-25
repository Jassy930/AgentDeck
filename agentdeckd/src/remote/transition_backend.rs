//! Production key-transition backend：只复用既有 Runtime Store、CounterGuard 与
//! `PublicationDriveHandle`，不创建第二个 Relay client/read loop。

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use agentdeck_crypto::{AeadSendingKey, SenderCounter, seal_symmetric};
use agentdeck_protocol::e2ee::{
    E2EE_FORMAT_VERSION, KeyControlV1, OuterContextV1, OuterFrameKind, SignedSealedBlobV1,
};
use agentdeck_protocol::relay_v2::{
    MachineRouteId, RELAY_PROTOCOL_VERSION, StreamGenerationId, StreamRouteId,
};
use async_trait::async_trait;

use crate::runtime::publication::{PublicationDispatchError, PublicationDriveReport};
use crate::runtime::store::identity::{RuntimeId, RuntimeIdKind};
use crate::runtime::store::key_transition::{
    FrozenKeyUpdate, KeyTransitionRecovery, KeyTransitionStreamCut, KeyTransitionStreamScope,
    RemoteTransitionIngressClass,
};
use crate::runtime::store::publication::{
    DirectoryAdvanceJournalIdentity, EpochBarrierJournalIdentity, SharedJournalIdentity,
    SharedPublicationPreflight, SharedPublicationPreflightRequest, SharedPublicationStreamProposal,
    SharedPublicationTransactionBinding, TransactionSharedKeyAxes,
};
use crate::runtime::store::{
    PublicationPayloadKind, PublicationScope, RuntimeStoreError, RuntimeStoreHandle,
};
use crate::security::KeyStore;

use super::counter::CounterScope;
use super::identity::OwnedKeyStoreCounterGuardBackend;
use super::publication_transport::{PublicationDriveError, PublicationDriveHandle};
use super::publisher::{
    PublicationError, SignedPublicationCoordinator, SignedPublicationError,
    SignedPublicationRequest,
};
use super::transition::{
    AuthenticatedCommittedStreamCut, DirectoryAdvancePublicationRequest,
    DirectoryAdvancePublicationTarget, EpochBarrierPublicationRequest,
    EpochBarrierPublicationTarget, ExactDirectoryAdvanceCommit, ExactEpochBarrierCommit,
    TransitionAnchor, TransitionBackend, TransitionCatalogStream, TransitionCoordinatorError,
    TransitionMaterial, TransitionRecipientMaterial,
};
use super::transport::MachineDataAuthority;

const MAX_TRANSITION_DRIVE_ROUNDS: usize = 1_026;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PublicationProgressWait {
    None,
    RetryTimer,
    Reconnect,
}

/// 后台 transition owner 只自动重试已经有严格 exact-retry 契约的 Store 暂态。
/// 其余 I/O、crypto、schema、capacity 与 safety-only 错误都必须锁存 LocalBlocked。
pub(super) const fn store_error_allows_transition_retry(error: &RuntimeStoreError) -> bool {
    matches!(
        error,
        RuntimeStoreError::WorkerBusy { .. } | RuntimeStoreError::CommitOutcomeUnknown { .. }
    )
}

fn map_transition_store_error(error: RuntimeStoreError) -> TransitionCoordinatorError {
    if store_error_allows_transition_retry(&error) {
        TransitionCoordinatorError::ProgressPending
    } else {
        TransitionCoordinatorError::BackendRejected
    }
}

pub(super) fn map_publication_drive_progress_error(
    error: PublicationDriveError,
) -> TransitionCoordinatorError {
    match error {
        PublicationDriveError::Dispatch(PublicationDispatchError::Store(error)) => {
            map_transition_store_error(error)
        }
        PublicationDriveError::RecoveryOffline => TransitionCoordinatorError::ProgressPending,
        PublicationDriveError::Dispatch(_)
        | PublicationDriveError::Closed
        | PublicationDriveError::TaskFailed
        | PublicationDriveError::ShutdownTimedOut
        | PublicationDriveError::RecoveryStalled
        | PublicationDriveError::RecoveryExhausted
        | PublicationDriveError::RecoveryCancelled
        | PublicationDriveError::RecoveryTimedOut => TransitionCoordinatorError::BackendRejected,
    }
}

const fn publication_report_progress_wait(
    report: &PublicationDriveReport,
) -> PublicationProgressWait {
    if report.offline {
        PublicationProgressWait::Reconnect
    } else if report.outcome_unknown > 0
        || report.commit_pending > 0
        || report.transient_store_busy > 0
    {
        PublicationProgressWait::RetryTimer
    } else {
        PublicationProgressWait::None
    }
}

/// Store/Keychain/network owner 之间的 production adapter。raw ADGK2 只在 Store
/// transaction-bound sealer 中短暂出现；本结构不缓存 canonical transition 或业务 state。
pub(crate) struct RuntimeStoreTransitionBackend {
    store: RuntimeStoreHandle,
    guard: Arc<OwnedKeyStoreCounterGuardBackend>,
    drive: PublicationDriveHandle,
    authority: MachineDataAuthority,
    machine_route: MachineRouteId,
    trust_domain: [u8; 32],
    reconnect_waiting: AtomicBool,
}

impl RuntimeStoreTransitionBackend {
    pub(crate) fn new(
        store: RuntimeStoreHandle,
        key_store: Arc<dyn KeyStore>,
        machine_route: MachineRouteId,
        authority: MachineDataAuthority,
        drive: PublicationDriveHandle,
    ) -> Result<Self, TransitionCoordinatorError> {
        if machine_route.as_bytes() == &[0; 16] {
            return Err(TransitionCoordinatorError::MaterialMismatch);
        }
        let trust_domain = store
            .machine_trust_domain()
            .map_err(map_transition_store_error)?;
        if trust_domain == [0; 32] {
            return Err(TransitionCoordinatorError::MaterialMismatch);
        }
        Ok(Self {
            store,
            guard: Arc::new(OwnedKeyStoreCounterGuardBackend::new(key_store)),
            authority,
            drive,
            machine_route,
            trust_domain,
            reconnect_waiting: AtomicBool::new(false),
        })
    }

    pub(crate) const fn authority(&self) -> &MachineDataAuthority {
        &self.authority
    }

    /// coordinator 的公开错误类型保持 transport-neutral；唯一 owner 在每次 attempt
    /// 开始前清除本地分类位，并在 `ProgressPending` 返回后读取它，以区分“只能等
    /// authenticated generation replacement”与“允许 exact timer retry”。
    pub(super) fn begin_progress_attempt(&self) {
        self.reconnect_waiting.store(false, Ordering::Release);
    }

    pub(super) fn take_reconnect_waiting(&self) -> bool {
        self.reconnect_waiting.swap(false, Ordering::AcqRel)
    }

    fn map_publication_progress_error(
        &self,
        error: PublicationDriveError,
    ) -> TransitionCoordinatorError {
        if matches!(error, PublicationDriveError::RecoveryOffline) {
            self.reconnect_waiting.store(true, Ordering::Release);
        }
        map_publication_drive_progress_error(error)
    }

    fn classify_publication_report(
        &self,
        report: &PublicationDriveReport,
    ) -> PublicationProgressWait {
        let wait = publication_report_progress_wait(report);
        if wait == PublicationProgressWait::Reconnect {
            self.reconnect_waiting.store(true, Ordering::Release);
        }
        wait
    }

    async fn reload_exact(
        &self,
        operation_id: [u8; 16],
    ) -> Result<KeyTransitionRecovery, TransitionCoordinatorError> {
        let recovery = self
            .store
            .load_active_key_transition()
            .await
            .map_err(map_transition_store_error)?
            .ok_or(TransitionCoordinatorError::ExactReadbackMismatch)?;
        if recovery.transition.operation_id != operation_id {
            return Err(TransitionCoordinatorError::ExactReadbackMismatch);
        }
        Ok(recovery)
    }

    async fn acknowledged_target(
        &self,
        request: &EpochBarrierPublicationRequest,
        publication_id: [u8; 16],
    ) -> Result<EpochBarrierPublicationTarget, TransitionCoordinatorError> {
        let stream = self
            .store
            .load_publication_stream_record(request.publication_stream_id)
            .await
            .map_err(map_transition_store_error)?;
        if stream.publication_stream_id != request.publication_stream_id
            || stream.stream_route != request.stream_route
            || stream.generation != request.generation
            || stream.acknowledged_high_water != Some(request.barrier_sequence)
            || stream.last_acknowledged_publication_id != Some(publication_id)
            || stream.last_acknowledged_blob_hash.is_none()
            || stream
                .committed_high_water
                .is_none_or(|committed| committed < request.barrier_sequence)
        {
            return Err(TransitionCoordinatorError::ExactReadbackMismatch);
        }
        Ok(target_from_request(
            request,
            stream
                .last_acknowledged_blob_hash
                .expect("checked acknowledged barrier hash"),
        ))
    }

    async fn exact_commit_observed(
        &self,
        target: EpochBarrierPublicationTarget,
    ) -> Result<bool, TransitionCoordinatorError> {
        validate_target_shape(target)?;
        let stream = self
            .store
            .load_publication_stream_record(target.publication_stream_id)
            .await
            .map_err(map_transition_store_error)?;
        if stream.publication_stream_id != target.publication_stream_id
            || stream.stream_route != target.stream_route
            || stream.generation != target.generation
        {
            return Err(TransitionCoordinatorError::BarrierMismatch);
        }
        if let Some(frozen) = self
            .store
            .load_frozen_publication(epoch_barrier_publication_id(target))
            .await
            .map_err(map_transition_store_error)?
        {
            if frozen.publication_stream_id != target.publication_stream_id
                || frozen.stream_route != target.stream_route
                || frozen.generation != target.generation
                || frozen.stream_seq != target.stream_seq
                || frozen.blob_sha256 != target.sealed_blob_sha256
                || frozen.payload_kind != PublicationPayloadKind::Control
            {
                return Err(TransitionCoordinatorError::BarrierMismatch);
            }
        } else if stream.acknowledged_high_water != Some(target.stream_seq)
            || stream.last_acknowledged_publication_id != Some(epoch_barrier_publication_id(target))
            || stream.last_acknowledged_blob_hash != Some(target.sealed_blob_sha256)
        {
            return Err(TransitionCoordinatorError::BarrierMismatch);
        }
        let committed = stream.committed_high_water == Some(target.stream_seq)
            && stream.last_committed_blob_hash == Some(target.sealed_blob_sha256);
        Ok(committed)
    }

    async fn acknowledged_directory_advance_target(
        &self,
        request: &DirectoryAdvancePublicationRequest,
        publication_id: [u8; 16],
    ) -> Result<DirectoryAdvancePublicationTarget, TransitionCoordinatorError> {
        let stream = self
            .store
            .load_publication_stream_record(request.publication_stream_id)
            .await
            .map_err(map_transition_store_error)?;
        let stream_seq = stream
            .acknowledged_high_water
            .ok_or(TransitionCoordinatorError::ExactReadbackMismatch)?;
        let blob_sha256 = stream
            .last_acknowledged_blob_hash
            .ok_or(TransitionCoordinatorError::ExactReadbackMismatch)?;
        if stream.publication_stream_id != request.publication_stream_id
            || stream.stream_route != request.stream_route
            || stream.generation != request.generation
            || stream.last_acknowledged_publication_id != Some(publication_id)
            || stream.committed_high_water != Some(stream_seq)
            || stream.last_committed_blob_hash != Some(blob_sha256)
            || stream.committed_inner_cursor != stream.acknowledged_inner_cursor
            || stream.last_acknowledged_request_digest.is_none()
        {
            return Err(TransitionCoordinatorError::ExactReadbackMismatch);
        }
        Ok(directory_target_from_request(
            request,
            stream_seq,
            blob_sha256,
        ))
    }

    async fn directory_advance_commit_observed(
        &self,
        target: DirectoryAdvancePublicationTarget,
    ) -> Result<bool, TransitionCoordinatorError> {
        validate_directory_target_shape(target)?;
        let publication_id = directory_advance_publication_id(target);
        let stream = self
            .store
            .load_publication_stream_record(target.publication_stream_id)
            .await
            .map_err(map_transition_store_error)?;
        if stream.publication_stream_id != target.publication_stream_id
            || stream.stream_route != target.stream_route
            || stream.generation != target.generation
        {
            return Err(TransitionCoordinatorError::BarrierMismatch);
        }
        if let Some(frozen) = self
            .store
            .load_frozen_publication(publication_id)
            .await
            .map_err(map_transition_store_error)?
        {
            if frozen.publication_stream_id != target.publication_stream_id
                || frozen.stream_route != target.stream_route
                || frozen.generation != target.generation
                || frozen.stream_seq != target.stream_seq
                || frozen.blob_sha256 != target.sealed_blob_sha256
                || frozen.payload_kind != PublicationPayloadKind::Control
                || frozen.inner_after.is_some()
                || frozen.inner_through.is_some()
            {
                return Err(TransitionCoordinatorError::BarrierMismatch);
            }
        } else if stream.acknowledged_high_water != Some(target.stream_seq)
            || stream.last_acknowledged_publication_id != Some(publication_id)
            || stream.last_acknowledged_blob_hash != Some(target.sealed_blob_sha256)
            || stream.committed_inner_cursor != stream.acknowledged_inner_cursor
            || stream.last_acknowledged_request_digest.is_none()
        {
            return Err(TransitionCoordinatorError::BarrierMismatch);
        }
        Ok(stream.committed_high_water == Some(target.stream_seq)
            && stream.last_committed_blob_hash == Some(target.sealed_blob_sha256))
    }

    async fn drive_until_cuts_committed(
        &self,
        operation_id: [u8; 16],
    ) -> Result<Vec<AuthenticatedCommittedStreamCut>, TransitionCoordinatorError> {
        self.drive
            .discover_pending()
            .await
            .map_err(|error| self.map_publication_progress_error(error))?;
        for _ in 0..MAX_TRANSITION_DRIVE_ROUNDS {
            match self
                .store
                .load_transition_committed_cuts(operation_id)
                .await
            {
                Ok(cuts) => {
                    return Ok(cuts
                        .into_iter()
                        .map(|cut| AuthenticatedCommittedStreamCut {
                            scope: cut.scope,
                            publication_stream_id: cut.publication_stream_id,
                            stream_route: cut.stream_route,
                            generation: cut.generation,
                            reserved_outer_cursor: cut.reserved_outer_cursor,
                            committed_outer_cursor: cut.committed_outer_cursor,
                            committed_inner_cursor: cut.committed_inner_cursor,
                        })
                        .collect());
                }
                Err(RuntimeStoreError::PublicationNeedsSnapshot) => {
                    return Err(TransitionCoordinatorError::SnapshotRequired);
                }
                // `PublicationMismatch` is also the authenticated representation of
                // reserved-but-not-yet-COMMIT old outbox. Give the unique dispatcher one
                // bounded round; zero progress becomes non-retryable UncommittedCut below.
                Err(RuntimeStoreError::PublicationMismatch) => {}
                Err(error) => return Err(map_transition_store_error(error)),
            }
            let report = self
                .drive
                .drive_round()
                .await
                .map_err(|error| self.map_publication_progress_error(error))?;
            match self.classify_publication_report(&report) {
                PublicationProgressWait::RetryTimer | PublicationProgressWait::Reconnect => {
                    return Err(TransitionCoordinatorError::ProgressPending);
                }
                PublicationProgressWait::None => {}
            }
            if report.loaded == 0 && report.committed == 0 {
                return Err(TransitionCoordinatorError::UncommittedCut);
            }
        }
        Err(TransitionCoordinatorError::UncommittedCut)
    }
}

#[async_trait]
impl TransitionBackend for RuntimeStoreTransitionBackend {
    async fn load_transition_material(
        &self,
    ) -> Result<Option<TransitionMaterial>, TransitionCoordinatorError> {
        let projection = self
            .store
            .load_transition_material_projection()
            .await
            .map_err(map_transition_store_error)?;
        projection
            .map(|projection| {
                if projection.anchor.machine_route != self.machine_route
                    || projection.anchor.machine_trust_domain != self.trust_domain
                {
                    return Err(TransitionCoordinatorError::MaterialMismatch);
                }
                Ok(TransitionMaterial {
                    recovery: projection.recovery,
                    global_keys: projection.global_keys,
                    anchor: TransitionAnchor {
                        relay_server_id: projection.anchor.relay_server_id,
                        machine_route: projection.anchor.machine_route,
                        root_key_id: projection.anchor.root_key_id,
                        trust_epoch: projection.anchor.trust_epoch,
                        machine_trust_domain: projection.anchor.machine_trust_domain,
                    },
                    recipients: projection
                        .recipients
                        .into_iter()
                        .map(|recipient| TransitionRecipientMaterial {
                            recipient: recipient.recipient,
                            relay_grant: recipient.relay_grant,
                            authorization: recipient.authorization,
                            authorization_revision: recipient.authorization_revision,
                        })
                        .collect(),
                    activation_catalog_stream: projection.activation_catalog_stream.map(|stream| {
                        TransitionCatalogStream {
                            publication_stream_id: stream.publication_stream_id,
                            stream_route: stream.stream_route,
                            generation: stream.generation,
                        }
                    }),
                })
            })
            .transpose()
    }

    async fn freeze_key_updates_exact(
        &self,
        operation_id: [u8; 16],
        updates: Vec<FrozenKeyUpdate>,
    ) -> Result<KeyTransitionRecovery, TransitionCoordinatorError> {
        self.store
            .freeze_key_updates(operation_id, updates)
            .await
            .map_err(map_transition_store_error)?;
        self.reload_exact(operation_id).await
    }

    async fn drive_old_key_outbox_to_committed(
        &self,
        operation_id: [u8; 16],
    ) -> Result<Vec<AuthenticatedCommittedStreamCut>, TransitionCoordinatorError> {
        self.drive_until_cuts_committed(operation_id).await
    }

    async fn freeze_key_barriers_exact(
        &self,
        operation_id: [u8; 16],
        cuts: Vec<KeyTransitionStreamCut>,
    ) -> Result<KeyTransitionRecovery, TransitionCoordinatorError> {
        self.store
            .freeze_key_barriers(operation_id, cuts)
            .await
            .map_err(map_transition_store_error)?;
        self.reload_exact(operation_id).await
    }

    async fn freeze_epoch_barrier(
        &self,
        request: EpochBarrierPublicationRequest,
    ) -> Result<EpochBarrierPublicationTarget, TransitionCoordinatorError> {
        validate_barrier_request(&request)?;
        let identity = journal_identity(&request);
        let publication_id = identity.publication_id();
        let scope = publication_scope(request.scope)?;
        let preflight_request = SharedPublicationPreflightRequest {
            publication_id,
            scope,
            inner_after: None,
            inner_through: None,
            payload_kind: PublicationPayloadKind::Control,
            journal_identity: SharedJournalIdentity::EpochBarrier(identity),
            canonical_item_bytes: request.canonical_control.clone(),
        };
        let preflight = self
            .store
            .preflight_shared_publication(
                preflight_request.clone(),
                SharedPublicationStreamProposal {
                    publication_stream_id: request.publication_stream_id,
                    stream_route: request.stream_route,
                    generation: request.generation,
                },
            )
            .await
            .map_err(map_transition_store_error)?;
        let (key_directory_revision, key_id, existing_target) = match preflight {
            SharedPublicationPreflight::AlreadyHandled => {
                return self.acknowledged_target(&request, publication_id).await;
            }
            SharedPublicationPreflight::RotationRequired(_) => {
                // EpochBarrier identity 已冻结旧 generation/cut；这里不得像普通 business
                // publisher 一样原地旋转后改写 barrier axes。上层必须先 materialize 覆盖
                // snapshot，并以新的 authenticated transition cut 重试。
                return Err(TransitionCoordinatorError::SnapshotRequired);
            }
            SharedPublicationPreflight::Frozen {
                publication_stream_id,
                generation,
                stream_seq,
                blob_sha256,
                key_directory_revision,
                key_id,
            } => {
                let target = target_from_request(&request, blob_sha256);
                if publication_stream_id != request.publication_stream_id
                    || generation != request.generation
                    || stream_seq != request.barrier_sequence
                    || key_directory_revision != request.expected_key_directory_revision
                    || key_id != request.expected_key_id
                {
                    return Err(TransitionCoordinatorError::ExactReadbackMismatch);
                }
                (key_directory_revision, key_id, Some(target))
            }
            SharedPublicationPreflight::Fresh {
                publication_stream_id,
                generation,
                key_directory_revision,
                key_id,
            } => {
                if publication_stream_id != request.publication_stream_id
                    || generation != request.generation
                    || key_directory_revision != request.expected_key_directory_revision
                    || key_id != request.expected_key_id
                {
                    return Err(TransitionCoordinatorError::ExactReadbackMismatch);
                }
                (key_directory_revision, key_id, None)
            }
        };
        let counter_scope = CounterScope::publication(
            self.trust_domain,
            request.expected_key_id,
            request.publication_stream_id,
        )
        .map_err(|_| TransitionCoordinatorError::MaterialMismatch)?;
        let signed_request = SignedPublicationRequest {
            publication_id,
            publication_stream_id: request.publication_stream_id,
            machine_route: self.machine_route,
            generation: StreamGenerationId::from_bytes(request.generation),
            key_directory_revision,
            key_id,
            counter_scope,
            inner_after: None,
            inner_through: None,
            payload_kind: PublicationPayloadKind::Control,
            sealer_retained_bytes: request.canonical_control.capacity(),
        };
        let binding = SharedPublicationTransactionBinding {
            request: preflight_request,
            expected_key_directory_revision: key_directory_revision,
            expected_key_id: key_id,
        };
        let machine_route = self.machine_route;
        let authority = self.authority.clone();
        let sealing_request = request.clone();
        let frozen = match SignedPublicationCoordinator::new(&self.store, self.guard.as_ref())
            .freeze_shared_signed(signed_request, binding, move |axes, shared| {
                seal_epoch_barrier(
                    machine_route,
                    &authority,
                    &sealing_request,
                    axes.stream_route(),
                    axes.generation(),
                    axes.stream_seq(),
                    axes.sender_counter(),
                    shared,
                )
            })
            .await
        {
            Ok(frozen) => frozen,
            Err(SignedPublicationError::Store(
                RuntimeStoreError::PublicationAlreadyAcknowledged,
            )) => return self.acknowledged_target(&request, publication_id).await,
            Err(SignedPublicationError::Store(error)) => {
                return Err(map_transition_store_error(error));
            }
            Err(_) => return Err(TransitionCoordinatorError::BackendRejected),
        };
        let target = target_from_request(&request, frozen.blob_sha256);
        if frozen.publication_id != publication_id
            || frozen.publication_stream_id != request.publication_stream_id
            || frozen.stream_route != request.stream_route
            || frozen.generation != request.generation
            || frozen.stream_seq != request.barrier_sequence
            || frozen.payload_kind != PublicationPayloadKind::Control
            || existing_target.is_some_and(|existing| existing != target)
        {
            return Err(TransitionCoordinatorError::ExactReadbackMismatch);
        }
        Ok(target)
    }

    async fn drive_epoch_barrier_to_exact_commit(
        &self,
        target: EpochBarrierPublicationTarget,
    ) -> Result<ExactEpochBarrierCommit, TransitionCoordinatorError> {
        if self.exact_commit_observed(target).await? {
            return Ok(ExactEpochBarrierCommit { target });
        }
        self.drive
            .notify_frozen_stream(target.publication_stream_id)
            .await
            .map_err(|error| self.map_publication_progress_error(error))?;
        for _ in 0..MAX_TRANSITION_DRIVE_ROUNDS {
            let report = self
                .drive
                .drive_round()
                .await
                .map_err(|error| self.map_publication_progress_error(error))?;
            if self.exact_commit_observed(target).await? {
                return Ok(ExactEpochBarrierCommit { target });
            }
            match self.classify_publication_report(&report) {
                PublicationProgressWait::RetryTimer | PublicationProgressWait::Reconnect => {
                    return Err(TransitionCoordinatorError::ProgressPending);
                }
                PublicationProgressWait::None => {}
            }
            if report.loaded == 0 && report.committed == 0 {
                return Err(TransitionCoordinatorError::UncommittedCut);
            }
        }
        Err(TransitionCoordinatorError::UncommittedCut)
    }

    async fn freeze_directory_advance(
        &self,
        request: DirectoryAdvancePublicationRequest,
    ) -> Result<DirectoryAdvancePublicationTarget, TransitionCoordinatorError> {
        validate_directory_advance_request(&request)?;
        let identity = directory_journal_identity(&request);
        let publication_id = identity.publication_id();
        let preflight_request = SharedPublicationPreflightRequest {
            publication_id,
            scope: PublicationScope::Catalog,
            inner_after: None,
            inner_through: None,
            payload_kind: PublicationPayloadKind::Control,
            journal_identity: SharedJournalIdentity::DirectoryAdvance(identity),
            canonical_item_bytes: request.canonical_control.clone(),
        };
        let preflight = self
            .store
            .preflight_shared_publication(
                preflight_request.clone(),
                SharedPublicationStreamProposal {
                    publication_stream_id: request.publication_stream_id,
                    stream_route: request.stream_route,
                    generation: request.generation,
                },
            )
            .await
            .map_err(map_transition_store_error)?;
        let (current_revision, key_id, existing_target) = match preflight {
            SharedPublicationPreflight::AlreadyHandled => {
                return self
                    .acknowledged_directory_advance_target(&request, publication_id)
                    .await;
            }
            SharedPublicationPreflight::RotationRequired(_) => {
                return Err(TransitionCoordinatorError::SnapshotRequired);
            }
            SharedPublicationPreflight::Frozen {
                publication_stream_id,
                generation,
                stream_seq,
                blob_sha256,
                key_directory_revision,
                key_id,
            } => {
                let target = directory_target_from_request(&request, stream_seq, blob_sha256);
                if publication_stream_id != request.publication_stream_id
                    || generation != request.generation
                    || key_directory_revision != request.from_revision
                    || key_id != request.expected_key_id
                {
                    return Err(TransitionCoordinatorError::ExactReadbackMismatch);
                }
                (request.to_revision, key_id, Some(target))
            }
            SharedPublicationPreflight::Fresh {
                publication_stream_id,
                generation,
                key_directory_revision,
                key_id,
            } => {
                if publication_stream_id != request.publication_stream_id
                    || generation != request.generation
                    || key_directory_revision != request.to_revision
                    || key_id != request.expected_key_id
                {
                    return Err(TransitionCoordinatorError::ExactReadbackMismatch);
                }
                (key_directory_revision, key_id, None)
            }
        };
        let counter_scope = CounterScope::publication(
            self.trust_domain,
            request.expected_key_id,
            request.publication_stream_id,
        )
        .map_err(|_| TransitionCoordinatorError::MaterialMismatch)?;
        let signed_request = SignedPublicationRequest {
            publication_id,
            publication_stream_id: request.publication_stream_id,
            machine_route: self.machine_route,
            generation: StreamGenerationId::from_bytes(request.generation),
            // Endpoint 仍持有 predecessor Catalog binding；header 必须保持可解密。
            key_directory_revision: request.from_revision,
            key_id,
            counter_scope,
            inner_after: None,
            inner_through: None,
            payload_kind: PublicationPayloadKind::Control,
            sealer_retained_bytes: request.canonical_control.capacity(),
        };
        let binding = SharedPublicationTransactionBinding {
            request: preflight_request,
            expected_key_directory_revision: current_revision,
            expected_key_id: key_id,
        };
        let machine_route = self.machine_route;
        let authority = self.authority.clone();
        let sealing_request = request.clone();
        let frozen = match SignedPublicationCoordinator::new(&self.store, self.guard.as_ref())
            .freeze_shared_signed(signed_request, binding, move |axes, shared| {
                seal_directory_advance(
                    machine_route,
                    &authority,
                    &sealing_request,
                    axes.stream_route(),
                    axes.generation(),
                    axes.stream_seq(),
                    axes.sender_counter(),
                    shared,
                )
            })
            .await
        {
            Ok(frozen) => frozen,
            Err(SignedPublicationError::Store(
                RuntimeStoreError::PublicationAlreadyAcknowledged,
            )) => {
                return self
                    .acknowledged_directory_advance_target(&request, publication_id)
                    .await;
            }
            Err(SignedPublicationError::Store(error)) => {
                return Err(map_transition_store_error(error));
            }
            Err(_) => return Err(TransitionCoordinatorError::BackendRejected),
        };
        let target = directory_target_from_request(&request, frozen.stream_seq, frozen.blob_sha256);
        if frozen.publication_id != publication_id
            || frozen.publication_stream_id != request.publication_stream_id
            || frozen.stream_route != request.stream_route
            || frozen.generation != request.generation
            || frozen.payload_kind != PublicationPayloadKind::Control
            || frozen.inner_after.is_some()
            || frozen.inner_through.is_some()
            || existing_target.is_some_and(|existing| existing != target)
        {
            return Err(TransitionCoordinatorError::ExactReadbackMismatch);
        }
        Ok(target)
    }

    async fn drive_directory_advance_to_exact_commit(
        &self,
        target: DirectoryAdvancePublicationTarget,
    ) -> Result<ExactDirectoryAdvanceCommit, TransitionCoordinatorError> {
        if self.directory_advance_commit_observed(target).await? {
            return Ok(ExactDirectoryAdvanceCommit { target });
        }
        self.drive
            .notify_frozen_stream(target.publication_stream_id)
            .await
            .map_err(|error| self.map_publication_progress_error(error))?;
        for _ in 0..MAX_TRANSITION_DRIVE_ROUNDS {
            let report = self
                .drive
                .drive_round()
                .await
                .map_err(|error| self.map_publication_progress_error(error))?;
            if self.directory_advance_commit_observed(target).await? {
                return Ok(ExactDirectoryAdvanceCommit { target });
            }
            match self.classify_publication_report(&report) {
                PublicationProgressWait::RetryTimer | PublicationProgressWait::Reconnect => {
                    return Err(TransitionCoordinatorError::ProgressPending);
                }
                PublicationProgressWait::None => {}
            }
            if report.loaded == 0 && report.committed == 0 {
                return Err(TransitionCoordinatorError::UncommittedCut);
            }
        }
        Err(TransitionCoordinatorError::UncommittedCut)
    }

    async fn mark_key_barriers_committed_exact(
        &self,
        operation_id: [u8; 16],
    ) -> Result<KeyTransitionRecovery, TransitionCoordinatorError> {
        self.store
            .mark_key_barriers_committed(operation_id)
            .await
            .map_err(map_transition_store_error)?;
        self.reload_exact(operation_id).await
    }

    async fn check_business_ingress_allowed(&self) -> Result<(), TransitionCoordinatorError> {
        // coordinator 到达 BarriersCommitted 时只能证明控制面可用；普通业务仍由
        // active-transition fence 拒绝，直到 required ACK 释放唯一 active slot。
        self.store
            .check_remote_transition_ingress(RemoteTransitionIngressClass::ControlPlaneReady)
            .await
            .map_err(|_| TransitionCoordinatorError::BusinessFenced)
    }
}

fn journal_identity(request: &EpochBarrierPublicationRequest) -> EpochBarrierJournalIdentity {
    EpochBarrierJournalIdentity {
        operation_id: request.operation_id,
        scope: request.scope,
        publication_stream_id: request.publication_stream_id,
        stream_route: request.stream_route,
        generation: request.generation,
        barrier_sequence: request.barrier_sequence,
        key_directory_revision: request.expected_key_directory_revision,
        key_id: request.expected_key_id,
        barrier_sha256: request.barrier_sha256,
    }
}

fn directory_journal_identity(
    request: &DirectoryAdvancePublicationRequest,
) -> DirectoryAdvanceJournalIdentity {
    DirectoryAdvanceJournalIdentity {
        operation_id: request.operation_id,
        publication_stream_id: request.publication_stream_id,
        stream_route: request.stream_route,
        generation: request.generation,
        from_revision: request.from_revision,
        to_revision: request.to_revision,
        key_id: request.expected_key_id,
        control_sha256: request.control_sha256,
    }
}

fn publication_scope(
    scope: KeyTransitionStreamScope,
) -> Result<PublicationScope, TransitionCoordinatorError> {
    match scope {
        KeyTransitionStreamScope::Catalog => Ok(PublicationScope::Catalog),
        KeyTransitionStreamScope::Conversation(conversation_id) => {
            Ok(PublicationScope::Conversation(
                RuntimeId::from_bytes(RuntimeIdKind::Conversation, conversation_id)
                    .map_err(|_| TransitionCoordinatorError::MaterialMismatch)?,
            ))
        }
    }
}

fn validate_barrier_request(
    request: &EpochBarrierPublicationRequest,
) -> Result<(), TransitionCoordinatorError> {
    let control = KeyControlV1::from_canonical_bytes(&request.canonical_control)
        .map_err(|_| TransitionCoordinatorError::MaterialMismatch)?;
    let KeyControlV1::EpochBarrier {
        stream_route,
        barrier,
        ..
    } = control
    else {
        return Err(TransitionCoordinatorError::MaterialMismatch);
    };
    if request.operation_id == [0; 16]
        || request.publication_stream_id == [0; 16]
        || request.stream_route == [0; 16]
        || request.generation == [0; 16]
        || request.expected_key_directory_revision == 0
        || request.expected_key_id.epoch == 0
        || request.barrier_sha256 == [0; 32]
        || stream_route.as_bytes() != &request.stream_route
        || barrier != request.barrier
        || barrier
            .canonical_sha256()
            .map_err(|_| TransitionCoordinatorError::MaterialMismatch)?
            != request.barrier_sha256
    {
        return Err(TransitionCoordinatorError::MaterialMismatch);
    }
    Ok(())
}

fn validate_directory_advance_request(
    request: &DirectoryAdvancePublicationRequest,
) -> Result<(), TransitionCoordinatorError> {
    let control = KeyControlV1::from_canonical_bytes(&request.canonical_control)
        .map_err(|_| TransitionCoordinatorError::MaterialMismatch)?;
    let KeyControlV1::DirectoryRevisionAdvance { ref advance, .. } = control else {
        return Err(TransitionCoordinatorError::MaterialMismatch);
    };
    if request.operation_id == [0; 16]
        || request.publication_stream_id == [0; 16]
        || request.stream_route == [0; 16]
        || request.generation == [0; 16]
        || request.from_revision == 0
        || request.from_revision.checked_add(1) != Some(request.to_revision)
        || request.expected_key_id.purpose != agentdeck_protocol::e2ee::KeyPurpose::Catalog
        || request.expected_key_id.epoch == 0
        || request.control_sha256 == [0; 32]
        || *advance != request.advance
        || advance.from_key_directory_revision.value() != request.from_revision
        || advance.to_key_directory_revision.value() != request.to_revision
        || control
            .canonical_sha256()
            .map_err(|_| TransitionCoordinatorError::MaterialMismatch)?
            != request.control_sha256
    {
        return Err(TransitionCoordinatorError::MaterialMismatch);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn seal_epoch_barrier(
    machine_route: MachineRouteId,
    authority: &MachineDataAuthority,
    request: &EpochBarrierPublicationRequest,
    stream_route: StreamRouteId,
    generation: StreamGenerationId,
    stream_seq: u64,
    sender_counter: u64,
    shared: TransactionSharedKeyAxes,
) -> Result<Vec<u8>, PublicationError> {
    if stream_route.as_bytes() != &request.stream_route
        || generation.as_bytes() != &request.generation
        || stream_seq != request.barrier_sequence
        || shared.key_directory_revision != request.expected_key_directory_revision
        || shared.key_id != request.expected_key_id
    {
        return Err(PublicationError::InvalidAxes);
    }
    let frame_kind = match request.scope {
        KeyTransitionStreamScope::Catalog => OuterFrameKind::CatalogPublish,
        KeyTransitionStreamScope::Conversation(_) => OuterFrameKind::ConversationPublish,
    };
    let context = OuterContextV1 {
        frame_kind,
        relay_protocol_version: RELAY_PROTOCOL_VERSION,
        e2ee_format_version: E2EE_FORMAT_VERSION,
        machine_route: Some(machine_route),
        device_route: None,
        stream_route: Some(stream_route),
        request_route: None,
        pair_route: None,
        stream_generation: Some(generation),
        stream_cursor: None,
        stream_seq: Some(stream_seq),
        message_key_epoch: shared.key_id.epoch,
    };
    let control = KeyControlV1::from_canonical_bytes(&request.canonical_control)
        .map_err(|_| PublicationError::InvalidAxes)?;
    let key = AeadSendingKey::with_derived_nonce_prefix(
        shared.key_id,
        shared.key_id.epoch,
        shared.key_directory_revision,
        shared.key,
    );
    let unsigned = seal_symmetric(
        &key,
        &context,
        control.sealed_payload_kind(),
        &request.canonical_control,
        SenderCounter(sender_counter),
    )
    .map_err(|_| PublicationError::InvalidAxes)?;
    let signed = authority
        .sign_sealed(unsigned, &context)
        .map_err(|_| PublicationError::InvalidAxes)?;
    if signed.inner.key_id != request.expected_key_id
        || signed.inner.key_epoch != request.expected_key_id.epoch
        || signed.inner.key_directory_revision != request.expected_key_directory_revision
    {
        return Err(PublicationError::InvalidAxes);
    }
    let wire = signed.to_wire_bytes();
    SignedSealedBlobV1::from_wire_bytes(&wire).map_err(|_| PublicationError::InvalidAxes)?;
    Ok(wire)
}

#[allow(clippy::too_many_arguments)]
fn seal_directory_advance(
    machine_route: MachineRouteId,
    authority: &MachineDataAuthority,
    request: &DirectoryAdvancePublicationRequest,
    stream_route: StreamRouteId,
    generation: StreamGenerationId,
    stream_seq: u64,
    sender_counter: u64,
    shared: TransactionSharedKeyAxes,
) -> Result<Vec<u8>, PublicationError> {
    if stream_route.as_bytes() != &request.stream_route
        || generation.as_bytes() != &request.generation
        || shared.key_directory_revision != request.to_revision
        || shared.key_id != request.expected_key_id
    {
        return Err(PublicationError::InvalidAxes);
    }
    let context = OuterContextV1 {
        frame_kind: OuterFrameKind::CatalogPublish,
        relay_protocol_version: RELAY_PROTOCOL_VERSION,
        e2ee_format_version: E2EE_FORMAT_VERSION,
        machine_route: Some(machine_route),
        device_route: None,
        stream_route: Some(stream_route),
        request_route: None,
        pair_route: None,
        stream_generation: Some(generation),
        stream_cursor: None,
        stream_seq: Some(stream_seq),
        message_key_epoch: shared.key_id.epoch,
    };
    let control = KeyControlV1::from_canonical_bytes(&request.canonical_control)
        .map_err(|_| PublicationError::InvalidAxes)?;
    let key = AeadSendingKey::with_derived_nonce_prefix(
        shared.key_id,
        shared.key_id.epoch,
        request.from_revision,
        shared.key,
    );
    let unsigned = seal_symmetric(
        &key,
        &context,
        control.sealed_payload_kind(),
        &request.canonical_control,
        SenderCounter(sender_counter),
    )
    .map_err(|_| PublicationError::InvalidAxes)?;
    let signed = authority
        .sign_sealed(unsigned, &context)
        .map_err(|_| PublicationError::InvalidAxes)?;
    if signed.inner.key_id != request.expected_key_id
        || signed.inner.key_epoch != request.expected_key_id.epoch
        || signed.inner.key_directory_revision != request.from_revision
    {
        return Err(PublicationError::InvalidAxes);
    }
    let wire = signed.to_wire_bytes();
    SignedSealedBlobV1::from_wire_bytes(&wire).map_err(|_| PublicationError::InvalidAxes)?;
    Ok(wire)
}

fn target_from_request(
    request: &EpochBarrierPublicationRequest,
    sealed_blob_sha256: [u8; 32],
) -> EpochBarrierPublicationTarget {
    EpochBarrierPublicationTarget {
        class: super::publisher::PublicationClass::EpochBarrier,
        operation_id: request.operation_id,
        scope: request.scope,
        publication_stream_id: request.publication_stream_id,
        stream_route: request.stream_route,
        generation: request.generation,
        stream_seq: request.barrier_sequence,
        key_id: request.expected_key_id,
        key_directory_revision: request.expected_key_directory_revision,
        barrier_sha256: request.barrier_sha256,
        sealed_blob_sha256,
    }
}

fn directory_target_from_request(
    request: &DirectoryAdvancePublicationRequest,
    stream_seq: u64,
    sealed_blob_sha256: [u8; 32],
) -> DirectoryAdvancePublicationTarget {
    DirectoryAdvancePublicationTarget {
        class: super::publisher::PublicationClass::DirectoryRevisionAdvance,
        operation_id: request.operation_id,
        publication_stream_id: request.publication_stream_id,
        stream_route: request.stream_route,
        generation: request.generation,
        stream_seq,
        from_revision: request.from_revision,
        to_revision: request.to_revision,
        key_id: request.expected_key_id,
        control_sha256: request.control_sha256,
        sealed_blob_sha256,
    }
}

fn validate_directory_target_shape(
    target: DirectoryAdvancePublicationTarget,
) -> Result<(), TransitionCoordinatorError> {
    if target.class != super::publisher::PublicationClass::DirectoryRevisionAdvance
        || target.operation_id == [0; 16]
        || target.publication_stream_id == [0; 16]
        || target.stream_route == [0; 16]
        || target.generation == [0; 16]
        || target.from_revision == 0
        || target.from_revision.checked_add(1) != Some(target.to_revision)
        || target.key_id.purpose != agentdeck_protocol::e2ee::KeyPurpose::Catalog
        || target.key_id.epoch == 0
        || target.control_sha256 == [0; 32]
        || target.sealed_blob_sha256 == [0; 32]
    {
        return Err(TransitionCoordinatorError::BarrierMismatch);
    }
    Ok(())
}

fn directory_advance_publication_id(target: DirectoryAdvancePublicationTarget) -> [u8; 16] {
    DirectoryAdvanceJournalIdentity {
        operation_id: target.operation_id,
        publication_stream_id: target.publication_stream_id,
        stream_route: target.stream_route,
        generation: target.generation,
        from_revision: target.from_revision,
        to_revision: target.to_revision,
        key_id: target.key_id,
        control_sha256: target.control_sha256,
    }
    .publication_id()
}

fn validate_target_shape(
    target: EpochBarrierPublicationTarget,
) -> Result<(), TransitionCoordinatorError> {
    if target.class != super::publisher::PublicationClass::EpochBarrier
        || target.operation_id == [0; 16]
        || target.publication_stream_id == [0; 16]
        || target.stream_route == [0; 16]
        || target.generation == [0; 16]
        || target.key_directory_revision == 0
        || target.key_id.epoch == 0
        || target.barrier_sha256 == [0; 32]
        || target.sealed_blob_sha256 == [0; 32]
    {
        return Err(TransitionCoordinatorError::BarrierMismatch);
    }
    Ok(())
}

fn epoch_barrier_publication_id(target: EpochBarrierPublicationTarget) -> [u8; 16] {
    EpochBarrierJournalIdentity {
        operation_id: target.operation_id,
        scope: target.scope,
        publication_stream_id: target.publication_stream_id,
        stream_route: target.stream_route,
        generation: target.generation,
        barrier_sequence: target.stream_seq,
        key_directory_revision: target.key_directory_revision,
        key_id: target.key_id,
        barrier_sha256: target.barrier_sha256,
    }
    .publication_id()
}

#[cfg(test)]
mod retry_classification_tests {
    use super::*;
    use crate::runtime::store::RuntimeStoreLane;

    #[test]
    fn publication_retry_classification_is_explicit_and_fail_closed() {
        for error in [
            PublicationDriveError::RecoveryOffline,
            PublicationDriveError::Dispatch(PublicationDispatchError::Store(
                RuntimeStoreError::WorkerBusy {
                    lane: RuntimeStoreLane::Normal,
                },
            )),
        ] {
            assert_eq!(
                map_publication_drive_progress_error(error),
                TransitionCoordinatorError::ProgressPending
            );
        }

        for error in [
            // `RecoveryStalled` 同时覆盖 terminal dispatcher state 与持续无进展，
            // 原因不够窄，不能被后台 owner 当成明确可恢复的网络暂态。
            PublicationDriveError::RecoveryStalled,
            PublicationDriveError::RecoveryExhausted,
            PublicationDriveError::Closed,
            PublicationDriveError::Dispatch(PublicationDispatchError::Store(
                RuntimeStoreError::SafetyOnly,
            )),
        ] {
            assert_eq!(
                map_publication_drive_progress_error(error),
                TransitionCoordinatorError::BackendRejected
            );
        }
    }

    #[test]
    fn publication_reports_distinguish_reconnect_wait_from_timer_retry() {
        assert_eq!(
            publication_report_progress_wait(
                &crate::runtime::publication::PublicationDriveReport {
                    offline: true,
                    ..crate::runtime::publication::PublicationDriveReport::default()
                }
            ),
            PublicationProgressWait::Reconnect
        );
        for report in [
            crate::runtime::publication::PublicationDriveReport {
                outcome_unknown: 1,
                ..crate::runtime::publication::PublicationDriveReport::default()
            },
            crate::runtime::publication::PublicationDriveReport {
                commit_pending: 1,
                ..crate::runtime::publication::PublicationDriveReport::default()
            },
            crate::runtime::publication::PublicationDriveReport {
                transient_store_busy: 1,
                ..crate::runtime::publication::PublicationDriveReport::default()
            },
        ] {
            assert_eq!(
                publication_report_progress_wait(&report),
                PublicationProgressWait::RetryTimer
            );
        }
        assert_eq!(
            publication_report_progress_wait(
                &crate::runtime::publication::PublicationDriveReport::default()
            ),
            PublicationProgressWait::None
        );
    }
}
