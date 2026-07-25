//! P4.5 membership key transition 的 authenticated material 与发布协调器。
//!
//! 本模块只持一次 Store readback 快照；canonical transition、key state、outbox 与 ACK
//! 仍由 Runtime Store 持有。production manager 在 publication recovery 后安装唯一 coordinator。

use std::sync::Arc;

use agentdeck_crypto::{HpkePublicKey, SecretAeadKey};
use agentdeck_protocol::e2ee::{
    DeviceAuthorizationV1, DirectoryRevisionAdvanceV1, E2EE_FORMAT_VERSION, EpochBarrierV1,
    KeyControlV1, KeyDirectoryEntry, KeyId, KeyPurpose, KeyUpdateInfoV1, KeyUpdateSetV1,
    KeyUpdateV1, OuterContextV1, OuterFrameKind,
};
use agentdeck_protocol::relay_v2::{
    KeyDirectoryRevision, MachineRouteId, RELAY_PROTOCOL_VERSION, RelayGrant, RelayServerId,
    RootKeyId, StreamGenerationId, StreamRouteId, TrustEpoch,
};
use agentdeck_protocol::runtime::identity::ConversationId;
use agentdeck_protocol::runtime::{RUNTIME_PROTOCOL_VERSION, RuntimeInnerCursor, StreamCursor};
use async_trait::async_trait;

use crate::runtime::store::identity::{RuntimeId, RuntimeIdKind};
use crate::runtime::store::key_transition::{
    FrozenKeyUpdate, KeyTransitionOperation, KeyTransitionPhase, KeyTransitionRecovery,
    KeyTransitionStreamCut, KeyTransitionStreamScope, KeyTransitionTarget, KeyUpdateLifecycle,
};
use crate::runtime::store::pairing_grant::GlobalKeyStateV1;

use super::publisher::PublicationClass;
use super::transport::MachineDataAuthority;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TransitionAnchor {
    pub(crate) relay_server_id: RelayServerId,
    pub(crate) machine_route: MachineRouteId,
    pub(crate) root_key_id: RootKeyId,
    pub(crate) trust_epoch: TrustEpoch,
    pub(crate) machine_trust_domain: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TransitionRecipientMaterial {
    pub(crate) recipient: crate::runtime::store::key_transition::KeyTransitionRecipient,
    pub(crate) relay_grant: RelayGrant,
    pub(crate) authorization: DeviceAuthorizationV1,
    pub(crate) authorization_revision: KeyDirectoryRevision,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TransitionCatalogStream {
    pub(crate) publication_stream_id: [u8; 16],
    pub(crate) stream_route: [u8; 16],
    pub(crate) generation: [u8; 16],
}

#[derive(Clone)]
pub(crate) struct TransitionMaterial {
    pub(crate) recovery: KeyTransitionRecovery,
    pub(crate) global_keys: Arc<GlobalKeyStateV1>,
    pub(crate) anchor: TransitionAnchor,
    pub(crate) recipients: Vec<TransitionRecipientMaterial>,
    pub(crate) activation_catalog_stream: Option<TransitionCatalogStream>,
}

pub(crate) trait KeyUpdateAuthority: Send + Sync {
    fn seal_key_directory_entry(
        &self,
        recipient: &HpkePublicKey,
        info: &KeyUpdateInfoV1,
        context: &OuterContextV1,
        key: &SecretAeadKey,
    ) -> Result<KeyDirectoryEntry, TransitionCoordinatorError>;

    fn sign_key_update(
        &self,
        info: &KeyUpdateInfoV1,
        context: &OuterContextV1,
        update: KeyUpdateV1,
    ) -> Result<KeyUpdateV1, TransitionCoordinatorError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum TransitionCoordinatorError {
    #[error("authenticated transition material does not agree")]
    MaterialMismatch,
    #[error("key update cryptographic authority rejected the request")]
    CryptographicAuthority,
    #[error("transition Store backend rejected an authenticated operation")]
    BackendRejected,
    #[error("Relay or an explicitly transient Store operation cannot make transition progress yet")]
    ProgressPending,
    #[error("Store readback did not preserve the exact frozen transition bytes")]
    ExactReadbackMismatch,
    #[error("epoch barrier input is not the exact authenticated Relay-COMMIT cut")]
    UncommittedCut,
    #[error("epoch barrier publication or COMMIT readback changed an exact axis")]
    BarrierMismatch,
    #[error("ordinary business publication remains fenced by the transition")]
    BusinessFenced,
    #[error("epoch barrier stream requires a covered snapshot and generation rotation")]
    SnapshotRequired,
}

impl TransitionCoordinatorError {
    #[must_use]
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::MaterialMismatch => "daemon.remote.transition.material_mismatch",
            Self::CryptographicAuthority => "daemon.remote.transition.crypto_rejected",
            Self::BackendRejected => "daemon.remote.transition.backend_rejected",
            Self::ProgressPending => "daemon.remote.transition.progress_pending",
            Self::ExactReadbackMismatch => "daemon.remote.transition.readback_mismatch",
            Self::UncommittedCut => "daemon.remote.transition.cut_uncommitted",
            Self::BarrierMismatch => "daemon.remote.transition.barrier_mismatch",
            Self::BusinessFenced => "daemon.remote.transition.business_fenced",
            Self::SnapshotRequired => "daemon.remote.transition.snapshot_required",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AuthenticatedCommittedStreamCut {
    pub(crate) scope: KeyTransitionStreamScope,
    pub(crate) publication_stream_id: [u8; 16],
    pub(crate) stream_route: [u8; 16],
    pub(crate) generation: [u8; 16],
    pub(crate) reserved_outer_cursor: Option<u64>,
    pub(crate) committed_outer_cursor: Option<u64>,
    pub(crate) committed_inner_cursor: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EpochBarrierPublicationRequest {
    pub(crate) operation_id: [u8; 16],
    pub(crate) scope: KeyTransitionStreamScope,
    pub(crate) publication_stream_id: [u8; 16],
    pub(crate) stream_route: [u8; 16],
    pub(crate) generation: [u8; 16],
    pub(crate) barrier_sequence: u64,
    pub(crate) expected_key_id: KeyId,
    pub(crate) expected_key_directory_revision: u64,
    pub(crate) barrier: EpochBarrierV1,
    pub(crate) canonical_control: Vec<u8>,
    pub(crate) barrier_sha256: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct EpochBarrierPublicationTarget {
    pub(crate) class: PublicationClass,
    pub(crate) operation_id: [u8; 16],
    pub(crate) scope: KeyTransitionStreamScope,
    pub(crate) publication_stream_id: [u8; 16],
    pub(crate) stream_route: [u8; 16],
    pub(crate) generation: [u8; 16],
    pub(crate) stream_seq: u64,
    pub(crate) key_id: KeyId,
    pub(crate) key_directory_revision: u64,
    pub(crate) barrier_sha256: [u8; 32],
    pub(crate) sealed_blob_sha256: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ExactEpochBarrierCommit {
    pub(crate) target: EpochBarrierPublicationTarget,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DirectoryAdvancePublicationRequest {
    pub(crate) operation_id: [u8; 16],
    pub(crate) publication_stream_id: [u8; 16],
    pub(crate) stream_route: [u8; 16],
    pub(crate) generation: [u8; 16],
    pub(crate) from_revision: u64,
    pub(crate) to_revision: u64,
    pub(crate) expected_key_id: KeyId,
    pub(crate) advance: DirectoryRevisionAdvanceV1,
    pub(crate) canonical_control: Vec<u8>,
    pub(crate) control_sha256: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DirectoryAdvancePublicationTarget {
    pub(crate) class: PublicationClass,
    pub(crate) operation_id: [u8; 16],
    pub(crate) publication_stream_id: [u8; 16],
    pub(crate) stream_route: [u8; 16],
    pub(crate) generation: [u8; 16],
    pub(crate) stream_seq: u64,
    pub(crate) from_revision: u64,
    pub(crate) to_revision: u64,
    pub(crate) key_id: KeyId,
    pub(crate) control_sha256: [u8; 32],
    pub(crate) sealed_blob_sha256: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ExactDirectoryAdvanceCommit {
    pub(crate) target: DirectoryAdvancePublicationTarget,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TransitionAdvance {
    NoActiveTransition,
    AwaitingKeyRotation,
    UpdatesFrozen {
        recipient_count: usize,
    },
    /// EpochBarrier 已由 Relay 精确 COMMIT，控制面可以接收 KeySync/ACK；active
    /// transition 仍在时普通业务必须继续 fenced。
    ControlPlaneReady {
        barrier_count: usize,
    },
}

/// Store/Relay 的窄 production seam。实现方必须从 authenticated Store 取 material，
/// 并把 freeze + readback、Relay COMMIT + readback 各自保持为 exact operation。
#[async_trait]
pub(crate) trait TransitionBackend: Send + Sync {
    async fn load_transition_material(
        &self,
    ) -> Result<Option<TransitionMaterial>, TransitionCoordinatorError>;

    async fn freeze_key_updates_exact(
        &self,
        operation_id: [u8; 16],
        updates: Vec<FrozenKeyUpdate>,
    ) -> Result<KeyTransitionRecovery, TransitionCoordinatorError>;

    async fn drive_old_key_outbox_to_committed(
        &self,
        operation_id: [u8; 16],
    ) -> Result<Vec<AuthenticatedCommittedStreamCut>, TransitionCoordinatorError>;

    async fn freeze_key_barriers_exact(
        &self,
        operation_id: [u8; 16],
        cuts: Vec<KeyTransitionStreamCut>,
    ) -> Result<KeyTransitionRecovery, TransitionCoordinatorError>;

    /// 专用 EpochBarrier 入口；不得复用 generic Control journal identity。
    async fn freeze_epoch_barrier(
        &self,
        request: EpochBarrierPublicationRequest,
    ) -> Result<EpochBarrierPublicationTarget, TransitionCoordinatorError>;

    async fn drive_epoch_barrier_to_exact_commit(
        &self,
        target: EpochBarrierPublicationTarget,
    ) -> Result<ExactEpochBarrierCommit, TransitionCoordinatorError>;

    async fn freeze_directory_advance(
        &self,
        request: DirectoryAdvancePublicationRequest,
    ) -> Result<DirectoryAdvancePublicationTarget, TransitionCoordinatorError>;

    async fn drive_directory_advance_to_exact_commit(
        &self,
        target: DirectoryAdvancePublicationTarget,
    ) -> Result<ExactDirectoryAdvanceCommit, TransitionCoordinatorError>;

    async fn mark_key_barriers_committed_exact(
        &self,
        operation_id: [u8; 16],
    ) -> Result<KeyTransitionRecovery, TransitionCoordinatorError>;

    async fn check_business_ingress_allowed(&self) -> Result<(), TransitionCoordinatorError>;
}

pub(crate) struct TransitionCoordinator<'a, B: ?Sized, A: ?Sized> {
    backend: &'a B,
    authority: &'a A,
}

impl<'a, B, A> TransitionCoordinator<'a, B, A>
where
    B: TransitionBackend + ?Sized,
    A: KeyUpdateAuthority + ?Sized,
{
    #[must_use]
    pub(crate) const fn new(backend: &'a B, authority: &'a A) -> Self {
        Self { backend, authority }
    }

    pub(crate) async fn advance_once(
        &self,
    ) -> Result<TransitionAdvance, TransitionCoordinatorError> {
        let Some(material) = self.backend.load_transition_material().await? else {
            return Ok(TransitionAdvance::NoActiveTransition);
        };
        let operation_id = material.recovery.transition.operation_id;
        match material.recovery.transition.phase {
            KeyTransitionPhase::DrainingOld => {
                // membership/conversation transaction 已把 authenticated global 与
                // authorization directory 原子推进到 `to_revision`；仍待 bootstrap
                // recovery 完成的是 Keychain guard 及 identity/remote binding CAS。
                // 因此这里只验证新目录快照并等待 finalize，绝不按旧 revision
                // 生成 update 或触碰 publication。
                validate_material_common(&material, material.recovery.transition.to_revision)?;
                Ok(TransitionAdvance::AwaitingKeyRotation)
            }
            KeyTransitionPhase::RotatedPreparingUpdates => {
                let updates = build_frozen_key_updates(&material, self.authority)?;
                let expected = updates.clone();
                let readback = self
                    .backend
                    .freeze_key_updates_exact(operation_id, updates)
                    .await?;
                validate_update_freeze_readback(&material, &expected, &readback)?;
                Ok(TransitionAdvance::UpdatesFrozen {
                    recipient_count: expected.len(),
                })
            }
            KeyTransitionPhase::UpdatesFrozen => {
                validate_post_rotation_material(&material)?;
                validate_existing_updates(&material.recovery)?;
                // first-device Add 不能仅凭 recipients==target 推断 zero-cut；Store
                // authenticated stream directory 可能已含本机 conversation/history。
                // 统一读回 required committed cuts，只有真实空目录才走 zero-cut。
                let committed = self
                    .backend
                    .drive_old_key_outbox_to_committed(operation_id)
                    .await?;
                let (cuts, requests) = build_barriers_from_committed(&material, &committed)?;
                let readback = self
                    .backend
                    .freeze_key_barriers_exact(operation_id, cuts.clone())
                    .await?;
                validate_barrier_freeze_readback(&material, &cuts, &readback)?;
                let mut frozen_material = material.clone();
                frozen_material.recovery = readback.clone();
                self.publish_frozen_barriers(&frozen_material, &readback, requests)
                    .await
            }
            KeyTransitionPhase::BarriersFrozen => {
                validate_post_rotation_material(&material)?;
                validate_existing_updates(&material.recovery)?;
                let requests = build_barriers_from_frozen(&material)?;
                self.publish_frozen_barriers(&material, &material.recovery, requests)
                    .await
            }
            KeyTransitionPhase::BarriersCommitted => {
                validate_post_rotation_material(&material)?;
                validate_existing_updates(&material.recovery)?;
                validate_frozen_barrier_set(&material)?;
                self.backend.check_business_ingress_allowed().await?;
                Ok(TransitionAdvance::ControlPlaneReady {
                    barrier_count: material.recovery.transition.cuts.len(),
                })
            }
            KeyTransitionPhase::Complete => Err(TransitionCoordinatorError::BackendRejected),
        }
    }

    async fn publish_frozen_barriers(
        &self,
        material: &TransitionMaterial,
        frozen: &KeyTransitionRecovery,
        requests: Vec<EpochBarrierPublicationRequest>,
    ) -> Result<TransitionAdvance, TransitionCoordinatorError> {
        if frozen.transition.phase != KeyTransitionPhase::BarriersFrozen
            || requests.len() != frozen.transition.cuts.len()
        {
            return Err(TransitionCoordinatorError::ExactReadbackMismatch);
        }
        for request in requests {
            let target = self.backend.freeze_epoch_barrier(request.clone()).await?;
            validate_barrier_target(&request, target)?;
            let committed = self
                .backend
                .drive_epoch_barrier_to_exact_commit(target)
                .await?;
            if committed.target != target {
                return Err(TransitionCoordinatorError::BarrierMismatch);
            }
        }
        if frozen.transition.operation == KeyTransitionOperation::ActivateConversation {
            let request = build_directory_advance_request(frozen, material)?;
            let target = self
                .backend
                .freeze_directory_advance(request.clone())
                .await?;
            validate_directory_advance_target(&request, target)?;
            let committed = self
                .backend
                .drive_directory_advance_to_exact_commit(target)
                .await?;
            if committed.target != target {
                return Err(TransitionCoordinatorError::BarrierMismatch);
            }
        }
        let committed = self
            .backend
            .mark_key_barriers_committed_exact(frozen.transition.operation_id)
            .await?;
        if committed.transition.phase != KeyTransitionPhase::BarriersCommitted
            || committed.transition.operation_id != frozen.transition.operation_id
            || committed.transition.to_revision != frozen.transition.to_revision
            || committed.transition.recipients != frozen.transition.recipients
            || committed.transition.cuts != frozen.transition.cuts
            || committed.updates != frozen.updates
        {
            return Err(TransitionCoordinatorError::ExactReadbackMismatch);
        }
        self.backend.check_business_ingress_allowed().await?;
        Ok(TransitionAdvance::ControlPlaneReady {
            barrier_count: frozen.transition.cuts.len(),
        })
    }
}

fn validate_directory_advance_target(
    request: &DirectoryAdvancePublicationRequest,
    target: DirectoryAdvancePublicationTarget,
) -> Result<(), TransitionCoordinatorError> {
    if target.class != PublicationClass::DirectoryRevisionAdvance
        || target.operation_id != request.operation_id
        || target.publication_stream_id != request.publication_stream_id
        || target.stream_route != request.stream_route
        || target.generation != request.generation
        || target.from_revision != request.from_revision
        || target.to_revision != request.to_revision
        || target.key_id != request.expected_key_id
        || target.control_sha256 != request.control_sha256
        || target.sealed_blob_sha256 == [0; 32]
    {
        return Err(TransitionCoordinatorError::BarrierMismatch);
    }
    Ok(())
}

fn build_directory_advance_request(
    frozen: &KeyTransitionRecovery,
    material: &TransitionMaterial,
) -> Result<DirectoryAdvancePublicationRequest, TransitionCoordinatorError> {
    if frozen.transition.operation != KeyTransitionOperation::ActivateConversation
        || frozen.transition.phase != KeyTransitionPhase::BarriersFrozen
        || !frozen.transition.cuts.is_empty()
        || material.recovery != *frozen
    {
        return Err(TransitionCoordinatorError::MaterialMismatch);
    }
    let stream = material
        .activation_catalog_stream
        .ok_or(TransitionCoordinatorError::MaterialMismatch)?;
    let mut catalog_keys = material
        .global_keys
        .current_shared_keys()
        .map_err(|_| TransitionCoordinatorError::MaterialMismatch)?
        .into_iter()
        .filter(|view| view.purpose == KeyPurpose::Catalog && view.stream_route.is_none());
    let catalog = catalog_keys
        .next()
        .ok_or(TransitionCoordinatorError::MaterialMismatch)?;
    if catalog.epoch == 0 || catalog_keys.next().is_some() {
        return Err(TransitionCoordinatorError::MaterialMismatch);
    }
    let expected_key_id = KeyId {
        purpose: KeyPurpose::Catalog,
        epoch: catalog.epoch,
    };
    let advance = DirectoryRevisionAdvanceV1 {
        from_key_directory_revision: KeyDirectoryRevision::new(frozen.transition.from_revision),
        to_key_directory_revision: KeyDirectoryRevision::new(frozen.transition.to_revision),
    };
    advance
        .validate()
        .map_err(|_| TransitionCoordinatorError::MaterialMismatch)?;
    let control = KeyControlV1::directory_revision_advance(advance.clone());
    let canonical_control = control
        .canonical_bytes()
        .map_err(|_| TransitionCoordinatorError::MaterialMismatch)?;
    let control_sha256 = control
        .canonical_sha256()
        .map_err(|_| TransitionCoordinatorError::MaterialMismatch)?;
    Ok(DirectoryAdvancePublicationRequest {
        operation_id: frozen.transition.operation_id,
        publication_stream_id: stream.publication_stream_id,
        stream_route: stream.stream_route,
        generation: stream.generation,
        from_revision: frozen.transition.from_revision,
        to_revision: frozen.transition.to_revision,
        expected_key_id,
        advance,
        canonical_control,
        control_sha256,
    })
}

fn validate_barrier_target(
    request: &EpochBarrierPublicationRequest,
    target: EpochBarrierPublicationTarget,
) -> Result<(), TransitionCoordinatorError> {
    if target.class != PublicationClass::EpochBarrier
        || target.operation_id != request.operation_id
        || target.scope != request.scope
        || target.publication_stream_id != request.publication_stream_id
        || target.stream_route != request.stream_route
        || target.generation != request.generation
        || target.stream_seq != request.barrier_sequence
        || target.key_id != request.expected_key_id
        || target.key_directory_revision != request.expected_key_directory_revision
        || target.barrier_sha256 != request.barrier_sha256
        || target.sealed_blob_sha256 == [0; 32]
    {
        return Err(TransitionCoordinatorError::BarrierMismatch);
    }
    Ok(())
}

pub(crate) fn build_frozen_key_updates(
    material: &TransitionMaterial,
    authority: &(impl KeyUpdateAuthority + ?Sized),
) -> Result<Vec<FrozenKeyUpdate>, TransitionCoordinatorError> {
    validate_update_material(material)?;
    let revision = KeyDirectoryRevision::new(material.recovery.transition.to_revision);
    let mut frozen = Vec::with_capacity(material.recipients.len());
    for recipient in &material.recipients {
        let device_route = recipient.relay_grant.device_route;
        let hpke = HpkePublicKey::from_bytes(&recipient.authorization.device_hpke_pubkey.0)
            .map_err(|_| TransitionCoordinatorError::MaterialMismatch)?;
        let views = material
            .global_keys
            .install_directory_view(device_route)
            .map_err(|_| TransitionCoordinatorError::MaterialMismatch)?;
        validate_complete_directory_views(material.global_keys.as_ref(), &views)?;
        let mut updates = Vec::with_capacity(views.len());
        for view in views {
            let info = KeyUpdateInfoV1 {
                e2ee_format_version: E2EE_FORMAT_VERSION,
                runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
                relay_server_id: material.anchor.relay_server_id,
                machine_route: material.anchor.machine_route,
                device_route,
                stream_route: view.stream_route,
                grant_serial: recipient.relay_grant.grant_serial,
                root_trust_epoch: material.anchor.trust_epoch,
                key_directory_revision: revision,
                key_purpose: view.purpose,
                key_epoch: view.epoch,
            };
            let context = key_update_context(&info);
            let entry = authority.seal_key_directory_entry(&hpke, &info, &context, &view.key)?;
            entry
                .validate_for_info(&info)
                .map_err(|_| TransitionCoordinatorError::CryptographicAuthority)?;
            let signed = authority.sign_key_update(
                &info,
                &context,
                KeyUpdateV1 {
                    key_directory_revision: revision,
                    key_id: entry.key_id,
                    device_route: entry.device_route,
                    stream_route: entry.stream_route,
                    enc: entry.enc,
                    wrapped_key: entry.wrapped_key,
                    signature: agentdeck_protocol::relay_v2::Ed25519Signature([0; 64]),
                },
            )?;
            signed
                .validate()
                .map_err(|_| TransitionCoordinatorError::CryptographicAuthority)?;
            if signed.key_directory_revision != revision
                || signed.device_route != device_route
                || signed.key_id
                    != (KeyId {
                        purpose: info.key_purpose,
                        epoch: info.key_epoch,
                    })
                || signed.stream_route != info.stream_route
            {
                return Err(TransitionCoordinatorError::CryptographicAuthority);
            }
            updates.push(signed);
        }
        let update_set = KeyUpdateSetV1 {
            key_directory_revision: revision,
            device_route,
            updates,
        };
        let canonical_update_set = update_set
            .canonical_bytes()
            .map_err(|_| TransitionCoordinatorError::MaterialMismatch)?;
        frozen.push(FrozenKeyUpdate {
            recipient: recipient.recipient,
            key_revision: revision.value(),
            canonical_update_set,
        });
    }
    Ok(frozen)
}

fn validate_update_freeze_readback(
    material: &TransitionMaterial,
    expected: &[FrozenKeyUpdate],
    readback: &KeyTransitionRecovery,
) -> Result<(), TransitionCoordinatorError> {
    if !same_transition_axes(&material.recovery, readback)
        || readback.transition.phase != KeyTransitionPhase::UpdatesFrozen
        || !readback.transition.cuts.is_empty()
        || readback.transition.update_count != expected.len() as u64
        || readback.updates.len() != expected.len()
    {
        return Err(TransitionCoordinatorError::ExactReadbackMismatch);
    }
    for (expected, stored) in expected.iter().zip(&readback.updates) {
        let bootstrap_ack = readback
            .transition
            .bootstrap_install_proof
            .as_ref()
            .filter(|proof| {
                proof.binding.device_route == stored.recipient.device_route
                    && proof.binding.grant_serial == stored.recipient.grant_serial
                    && proof.binding.key_revision == stored.key_revision
            });
        if stored.operation_id != readback.transition.operation_id
            || stored.recipient != expected.recipient
            || stored.key_revision != expected.key_revision
            || stored.canonical_update_set != expected.canonical_update_set
            || !stored.stream_applied_acks.is_empty()
            || match bootstrap_ack {
                Some(_) => {
                    // receipt 后到时目标可能已由经过 DeviceSign 验证的普通
                    // KeyUpdateAck 先行 Acked；Store 会保留该 ACK。coordinator
                    // 这里只接受 authenticated readback 中的非空 Acked 形态，
                    // slot/proof lineage 由 Store 完整性校验负责。
                    stored.lifecycle != KeyUpdateLifecycle::Acked
                        || stored.canonical_ack.as_ref().is_none_or(Vec::is_empty)
                }
                None => {
                    stored.lifecycle != KeyUpdateLifecycle::Frozen || stored.canonical_ack.is_some()
                }
            }
        {
            return Err(TransitionCoordinatorError::ExactReadbackMismatch);
        }
    }
    validate_existing_updates(readback)
}

fn validate_existing_updates(
    recovery: &KeyTransitionRecovery,
) -> Result<(), TransitionCoordinatorError> {
    if recovery.transition.update_count != recovery.updates.len() as u64
        || recovery.updates.len() != recovery.transition.recipients.len()
    {
        return Err(TransitionCoordinatorError::ExactReadbackMismatch);
    }
    for (recipient, update) in recovery.transition.recipients.iter().zip(&recovery.updates) {
        let set = KeyUpdateSetV1::from_canonical_bytes(&update.canonical_update_set)
            .map_err(|_| TransitionCoordinatorError::ExactReadbackMismatch)?;
        let ack_shape = match update.lifecycle {
            KeyUpdateLifecycle::Frozen => update.canonical_ack.is_none(),
            KeyUpdateLifecycle::Acked => update
                .canonical_ack
                .as_ref()
                .is_some_and(|canonical| !canonical.is_empty()),
            KeyUpdateLifecycle::Cancelled => false,
        };
        if update.operation_id != recovery.transition.operation_id
            || update.recipient != *recipient
            || update.key_revision != recovery.transition.to_revision
            || set.key_directory_revision.value() != update.key_revision
            || set.device_route.as_bytes() != &recipient.device_route
            || !ack_shape
            || (recovery.transition.phase != KeyTransitionPhase::BarriersCommitted
                && !update.stream_applied_acks.is_empty())
        {
            return Err(TransitionCoordinatorError::ExactReadbackMismatch);
        }
    }
    Ok(())
}

fn same_transition_axes(expected: &KeyTransitionRecovery, actual: &KeyTransitionRecovery) -> bool {
    expected.transition.operation_id == actual.transition.operation_id
        && expected.transition.operation == actual.transition.operation
        && expected.transition.target == actual.transition.target
        && expected.transition.from_revision == actual.transition.from_revision
        && expected.transition.to_revision == actual.transition.to_revision
        && expected.transition.terminal == actual.transition.terminal
        && expected.transition.recipients == actual.transition.recipients
        && expected.transition.bootstrap_install_proof == actual.transition.bootstrap_install_proof
        && expected.transition.created_at_ms == actual.transition.created_at_ms
}

fn build_barriers_from_committed(
    material: &TransitionMaterial,
    committed: &[AuthenticatedCommittedStreamCut],
) -> Result<
    (
        Vec<KeyTransitionStreamCut>,
        Vec<EpochBarrierPublicationRequest>,
    ),
    TransitionCoordinatorError,
> {
    if committed.is_empty() {
        return if zero_cut_transition_allowed(&material.recovery.transition) {
            Ok((Vec::new(), Vec::new()))
        } else {
            Err(TransitionCoordinatorError::UncommittedCut)
        };
    }
    let mut expected = required_shared_barrier_axes(material)?;
    if committed.len() != expected.len() {
        return Err(TransitionCoordinatorError::UncommittedCut);
    }
    let mut cuts = Vec::with_capacity(committed.len());
    let mut requests = Vec::with_capacity(committed.len());
    let mut previous = None;
    for committed in committed {
        validate_committed_cut_shape(committed, &mut previous)?;
        let axis = take_matching_axis(&mut expected, committed.scope, committed.stream_route)?;
        let (cut, request) = barrier_from_committed(
            material.recovery.transition.operation_id,
            material.recovery.transition.to_revision,
            *committed,
            axis,
        )?;
        cuts.push(cut);
        requests.push(request);
    }
    if !expected.is_empty() {
        return Err(TransitionCoordinatorError::UncommittedCut);
    }
    Ok((cuts, requests))
}

fn validate_barrier_freeze_readback(
    material: &TransitionMaterial,
    expected: &[KeyTransitionStreamCut],
    readback: &KeyTransitionRecovery,
) -> Result<(), TransitionCoordinatorError> {
    if !same_transition_axes(&material.recovery, readback)
        || readback.transition.phase != KeyTransitionPhase::BarriersFrozen
        || readback.transition.cuts != expected
        || readback.transition.update_count != material.recovery.transition.update_count
        || readback.updates != material.recovery.updates
    {
        return Err(TransitionCoordinatorError::ExactReadbackMismatch);
    }
    validate_existing_updates(readback)
}

fn build_barriers_from_frozen(
    material: &TransitionMaterial,
) -> Result<Vec<EpochBarrierPublicationRequest>, TransitionCoordinatorError> {
    if material.recovery.transition.phase != KeyTransitionPhase::BarriersFrozen {
        return Err(TransitionCoordinatorError::ExactReadbackMismatch);
    }
    if material.recovery.transition.cuts.is_empty() {
        return if zero_cut_transition_allowed(&material.recovery.transition) {
            Ok(Vec::new())
        } else {
            Err(TransitionCoordinatorError::ExactReadbackMismatch)
        };
    }
    let mut expected = required_shared_barrier_axes(material)?;
    if material.recovery.transition.cuts.len() != expected.len() {
        return Err(TransitionCoordinatorError::ExactReadbackMismatch);
    }
    let mut previous = None;
    let mut requests = Vec::with_capacity(material.recovery.transition.cuts.len());
    for stored in &material.recovery.transition.cuts {
        let committed = AuthenticatedCommittedStreamCut {
            scope: stored.scope,
            publication_stream_id: stored.publication_stream_id,
            stream_route: stored.stream_route,
            generation: stored.generation,
            reserved_outer_cursor: stored.relay_committed_outer,
            committed_outer_cursor: stored.relay_committed_outer,
            committed_inner_cursor: stored.relay_committed_inner,
        };
        validate_committed_cut_shape(&committed, &mut previous)
            .map_err(|_| TransitionCoordinatorError::ExactReadbackMismatch)?;
        let axis = take_matching_axis(&mut expected, stored.scope, stored.stream_route)
            .map_err(|_| TransitionCoordinatorError::ExactReadbackMismatch)?;
        let (rebuilt, request) = barrier_from_committed(
            material.recovery.transition.operation_id,
            material.recovery.transition.to_revision,
            committed,
            axis,
        )
        .map_err(|_| TransitionCoordinatorError::ExactReadbackMismatch)?;
        if rebuilt != *stored {
            return Err(TransitionCoordinatorError::ExactReadbackMismatch);
        }
        requests.push(request);
    }
    if !expected.is_empty() {
        return Err(TransitionCoordinatorError::ExactReadbackMismatch);
    }
    Ok(requests)
}

fn validate_frozen_barrier_set(
    material: &TransitionMaterial,
) -> Result<(), TransitionCoordinatorError> {
    let mut frozen = material.clone();
    frozen.recovery.transition.phase = KeyTransitionPhase::BarriersFrozen;
    build_barriers_from_frozen(&frozen).map(|_| ())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SharedBarrierAxis {
    purpose: KeyPurpose,
    stream_route: Option<StreamRouteId>,
    new_epoch: u64,
}

fn required_shared_barrier_axes(
    material: &TransitionMaterial,
) -> Result<Vec<SharedBarrierAxis>, TransitionCoordinatorError> {
    let mut axes = material
        .global_keys
        .current_shared_keys()
        .map_err(|_| TransitionCoordinatorError::MaterialMismatch)?
        .into_iter()
        .filter(|view| {
            match (
                material.recovery.transition.operation,
                material.recovery.transition.target,
            ) {
                (KeyTransitionOperation::Renew, _) => view.purpose == KeyPurpose::Catalog,
                (
                    KeyTransitionOperation::CounterRecovery,
                    KeyTransitionTarget::Conversation { stream_route, .. },
                ) => {
                    let target = StreamRouteId::from_bytes(stream_route);
                    view.stream_route == Some(target)
                        || (view.purpose == KeyPurpose::Catalog
                            && !material
                                .global_keys
                                .active_conversation_routes()
                                .contains(&target))
                }
                (KeyTransitionOperation::CounterRecovery, KeyTransitionTarget::Device(_)) => false,
                _ => true,
            }
        })
        .map(|view| SharedBarrierAxis {
            purpose: view.purpose,
            stream_route: view.stream_route,
            new_epoch: view.epoch,
        })
        .collect::<Vec<_>>();
    axes.sort_by_key(|axis| (purpose_rank(axis.purpose), stream_bytes(axis.stream_route)));
    if axes.is_empty() {
        return Err(TransitionCoordinatorError::MaterialMismatch);
    }
    Ok(axes)
}

fn validate_committed_cut_shape(
    cut: &AuthenticatedCommittedStreamCut,
    previous: &mut Option<(KeyTransitionStreamScope, [u8; 16])>,
) -> Result<(), TransitionCoordinatorError> {
    let identity = (cut.scope, cut.publication_stream_id);
    if cut.publication_stream_id == [0; 16]
        || cut.stream_route == [0; 16]
        || cut.generation == [0; 16]
        || matches!(cut.scope, KeyTransitionStreamScope::Conversation(id) if id == [0; 16])
        || cut.reserved_outer_cursor != cut.committed_outer_cursor
        || previous.is_some_and(|value| value >= identity)
    {
        return Err(TransitionCoordinatorError::UncommittedCut);
    }
    *previous = Some(identity);
    Ok(())
}

fn take_matching_axis(
    expected: &mut Vec<SharedBarrierAxis>,
    scope: KeyTransitionStreamScope,
    stream_route: [u8; 16],
) -> Result<SharedBarrierAxis, TransitionCoordinatorError> {
    let identity = match scope {
        KeyTransitionStreamScope::Catalog => (KeyPurpose::Catalog, None),
        KeyTransitionStreamScope::Conversation(_) => (
            KeyPurpose::ConversationDek,
            Some(StreamRouteId::from_bytes(stream_route)),
        ),
    };
    let index = expected
        .iter()
        .position(|axis| (axis.purpose, axis.stream_route) == identity)
        .ok_or(TransitionCoordinatorError::UncommittedCut)?;
    Ok(expected.remove(index))
}

fn barrier_from_committed(
    operation_id: [u8; 16],
    key_directory_revision: u64,
    committed: AuthenticatedCommittedStreamCut,
    axis: SharedBarrierAxis,
) -> Result<(KeyTransitionStreamCut, EpochBarrierPublicationRequest), TransitionCoordinatorError> {
    if key_directory_revision == 0 || axis.new_epoch == 0 {
        return Err(TransitionCoordinatorError::UncommittedCut);
    }
    let stream_cursor = StreamCursor::from_high_water(committed.committed_outer_cursor);
    let barrier_sequence = stream_cursor
        .checked_next()
        .map_err(|_| TransitionCoordinatorError::UncommittedCut)?;
    if barrier_sequence == u64::MAX {
        return Err(TransitionCoordinatorError::UncommittedCut);
    }
    let inner_cursor = tagged_inner_cursor(committed.scope, committed.committed_inner_cursor)?;
    // 首个 remote member 可以为已有本机 stream 建立 `0 -> 1` barrier；0 仅是
    // “此前不存在 shared sender key”的 sentinel，不会派生旧 sender scope。
    let old_epoch = axis.new_epoch - 1;
    let barrier = EpochBarrierV1 {
        stream_generation: StreamGenerationId::from_bytes(committed.generation),
        stream_cursor,
        inner_cursor,
        old_epoch,
        new_epoch: axis.new_epoch,
        key_directory_revision: KeyDirectoryRevision::new(key_directory_revision),
    };
    barrier
        .validate()
        .map_err(|_| TransitionCoordinatorError::UncommittedCut)?;
    let barrier_sha256 = barrier
        .canonical_sha256()
        .map_err(|_| TransitionCoordinatorError::UncommittedCut)?;
    let control = KeyControlV1::epoch_barrier(
        StreamRouteId::from_bytes(committed.stream_route),
        barrier.clone(),
    );
    let canonical_control = control
        .canonical_bytes()
        .map_err(|_| TransitionCoordinatorError::UncommittedCut)?;
    let cut = KeyTransitionStreamCut {
        scope: committed.scope,
        publication_stream_id: committed.publication_stream_id,
        stream_route: committed.stream_route,
        generation: committed.generation,
        relay_committed_outer: committed.committed_outer_cursor,
        relay_committed_inner: committed.committed_inner_cursor,
        barrier_sequence,
        old_epoch,
        new_epoch: axis.new_epoch,
        epoch_barrier_sha256: barrier_sha256,
    };
    let request = EpochBarrierPublicationRequest {
        operation_id,
        scope: committed.scope,
        publication_stream_id: committed.publication_stream_id,
        stream_route: committed.stream_route,
        generation: committed.generation,
        barrier_sequence,
        expected_key_id: KeyId {
            purpose: axis.purpose,
            epoch: axis.new_epoch,
        },
        expected_key_directory_revision: key_directory_revision,
        barrier,
        canonical_control,
        barrier_sha256,
    };
    Ok((cut, request))
}

fn tagged_inner_cursor(
    scope: KeyTransitionStreamScope,
    inner: Option<u64>,
) -> Result<RuntimeInnerCursor, TransitionCoordinatorError> {
    let cursor = StreamCursor::from_high_water(inner);
    match scope {
        KeyTransitionStreamScope::Catalog => Ok(RuntimeInnerCursor::Catalog { cursor }),
        KeyTransitionStreamScope::Conversation(conversation_id) => {
            let conversation_id =
                RuntimeId::from_bytes(RuntimeIdKind::Conversation, conversation_id)
                    .map_err(|_| TransitionCoordinatorError::UncommittedCut)?;
            Ok(RuntimeInnerCursor::Conversation {
                conversation_id: ConversationId::new(conversation_id.to_canonical_string()),
                cursor,
            })
        }
    }
}

fn zero_cut_transition_allowed(
    transition: &crate::runtime::store::key_transition::KeyTransitionRecord,
) -> bool {
    match transition.operation {
        KeyTransitionOperation::Add => matches!(
            transition.target,
            KeyTransitionTarget::Device(target) if transition.recipients.as_slice() == [target]
        ),
        KeyTransitionOperation::Renew => false,
        KeyTransitionOperation::Revoke => transition.recipients.is_empty(),
        KeyTransitionOperation::ActivateConversation => true,
        KeyTransitionOperation::CounterRecovery => {
            matches!(transition.target, KeyTransitionTarget::Device(_))
        }
    }
}

fn validate_update_material(
    material: &TransitionMaterial,
) -> Result<(), TransitionCoordinatorError> {
    let transition = &material.recovery.transition;
    if transition.phase != KeyTransitionPhase::RotatedPreparingUpdates
        || transition.terminal.is_some()
        || !transition.cuts.is_empty()
        || transition.update_count != 0
        || !material.recovery.updates.is_empty()
    {
        return Err(TransitionCoordinatorError::MaterialMismatch);
    }
    validate_material_common(material, transition.to_revision)
}

fn validate_post_rotation_material(
    material: &TransitionMaterial,
) -> Result<(), TransitionCoordinatorError> {
    if material.recovery.transition.phase == KeyTransitionPhase::DrainingOld
        || material.recovery.transition.phase == KeyTransitionPhase::Complete
        || material.recovery.transition.terminal.is_some()
    {
        return Err(TransitionCoordinatorError::MaterialMismatch);
    }
    validate_material_common(material, material.recovery.transition.to_revision)
}

fn validate_material_common(
    material: &TransitionMaterial,
    current_revision: u64,
) -> Result<(), TransitionCoordinatorError> {
    let transition = &material.recovery.transition;
    if transition.operation_id == [0; 16]
        || transition.from_revision.checked_add(1) != Some(transition.to_revision)
        || transition.to_revision == 0
        || current_revision == 0
        || material.global_keys.revision().value() != current_revision
        || material.anchor.relay_server_id.as_bytes() == &[0; 16]
        || material.anchor.machine_route.as_bytes() == &[0; 16]
        || material.anchor.root_key_id.as_bytes() == &[0; 16]
        || material.anchor.trust_epoch.value() == 0
        || material.anchor.machine_trust_domain == [0; 32]
        || material.recipients.len() != transition.recipients.len()
        || (transition.operation == KeyTransitionOperation::ActivateConversation)
            != material.activation_catalog_stream.is_some()
        || !valid_operation_target(transition.operation, transition.target)
    {
        return Err(TransitionCoordinatorError::MaterialMismatch);
    }
    let expected_revision = KeyDirectoryRevision::new(current_revision);
    let mut previous = None;
    for (expected, recipient) in transition.recipients.iter().zip(&material.recipients) {
        if recipient.recipient != *expected
            || previous.is_some_and(|value| value >= recipient.recipient)
            || recipient.recipient.device_route == [0; 16]
            || recipient.recipient.grant_serial == 0
            || recipient.authorization_revision != expected_revision
            || recipient.relay_grant.machine_route != material.anchor.machine_route
            || recipient.relay_grant.device_route.as_bytes() != &recipient.recipient.device_route
            || recipient.relay_grant.grant_serial.value() != recipient.recipient.grant_serial
            || recipient.relay_grant.root_key_id != material.anchor.root_key_id
            || recipient.relay_grant.trust_epoch != material.anchor.trust_epoch
            || recipient
                .authorization
                .validate_for_grant(&recipient.relay_grant)
                .is_err()
            || material
                .global_keys
                .install_directory_view(recipient.relay_grant.device_route)
                .is_err()
            || HpkePublicKey::from_bytes(&recipient.authorization.device_hpke_pubkey.0).is_err()
        {
            return Err(TransitionCoordinatorError::MaterialMismatch);
        }
        previous = Some(recipient.recipient);
    }
    Ok(())
}

fn valid_operation_target(operation: KeyTransitionOperation, target: KeyTransitionTarget) -> bool {
    match (operation, target) {
        (
            KeyTransitionOperation::Add
            | KeyTransitionOperation::Renew
            | KeyTransitionOperation::Revoke,
            KeyTransitionTarget::Device(recipient),
        ) => recipient.device_route != [0; 16] && recipient.grant_serial != 0,
        (
            KeyTransitionOperation::ActivateConversation,
            KeyTransitionTarget::Conversation {
                conversation_id,
                stream_route,
            },
        ) => conversation_id != [0; 16] && stream_route != [0; 16],
        (KeyTransitionOperation::CounterRecovery, KeyTransitionTarget::Device(recipient)) => {
            recipient.device_route != [0; 16] && recipient.grant_serial != 0
        }
        (
            KeyTransitionOperation::CounterRecovery,
            KeyTransitionTarget::Conversation {
                conversation_id,
                stream_route,
            },
        ) => conversation_id != [0; 16] && stream_route != [0; 16],
        _ => false,
    }
}

fn validate_complete_directory_views(
    global: &GlobalKeyStateV1,
    views: &[crate::runtime::store::pairing_grant::BootstrapKeyView],
) -> Result<(), TransitionCoordinatorError> {
    let active_routes = global.active_conversation_routes();
    if views.len() != active_routes.len() + 3 {
        return Err(TransitionCoordinatorError::MaterialMismatch);
    }
    let mut catalog = 0_usize;
    let mut command = 0_usize;
    let mut reply = 0_usize;
    let mut conversations = Vec::with_capacity(active_routes.len());
    let mut previous = None;
    for view in views {
        let identity = (purpose_rank(view.purpose), stream_bytes(view.stream_route));
        if view.epoch == 0 || previous.is_some_and(|value| value >= identity) {
            return Err(TransitionCoordinatorError::MaterialMismatch);
        }
        previous = Some(identity);
        match (view.purpose, view.stream_route) {
            (KeyPurpose::Catalog, None) => catalog += 1,
            (KeyPurpose::ConversationDek, Some(route)) => conversations.push(route),
            (KeyPurpose::DeviceCommandTx, None) => command += 1,
            (KeyPurpose::DeviceReplyTx, None) => reply += 1,
            _ => return Err(TransitionCoordinatorError::MaterialMismatch),
        }
    }
    if catalog != 1 || command != 1 || reply != 1 || conversations != active_routes {
        return Err(TransitionCoordinatorError::MaterialMismatch);
    }
    Ok(())
}

const fn purpose_rank(purpose: KeyPurpose) -> u8 {
    match purpose {
        KeyPurpose::Catalog => 0,
        KeyPurpose::ConversationDek => 1,
        KeyPurpose::DeviceCommandTx => 2,
        KeyPurpose::DeviceReplyTx => 3,
    }
}

fn stream_bytes(route: Option<StreamRouteId>) -> [u8; 16] {
    route.map_or([0; 16], |value| *value.as_bytes())
}

fn key_update_context(info: &KeyUpdateInfoV1) -> OuterContextV1 {
    OuterContextV1 {
        frame_kind: OuterFrameKind::KeyUpdate,
        relay_protocol_version: RELAY_PROTOCOL_VERSION,
        e2ee_format_version: E2EE_FORMAT_VERSION,
        machine_route: Some(info.machine_route),
        device_route: Some(info.device_route),
        stream_route: info.stream_route,
        request_route: None,
        pair_route: None,
        stream_generation: None,
        stream_cursor: None,
        stream_seq: None,
        message_key_epoch: info.key_epoch,
    }
}

impl KeyUpdateAuthority for MachineDataAuthority {
    fn seal_key_directory_entry(
        &self,
        recipient: &HpkePublicKey,
        info: &KeyUpdateInfoV1,
        context: &OuterContextV1,
        key: &SecretAeadKey,
    ) -> Result<KeyDirectoryEntry, TransitionCoordinatorError> {
        MachineDataAuthority::seal_key_directory_entry(self, recipient, info, context, key)
            .map_err(|_| TransitionCoordinatorError::CryptographicAuthority)
    }

    fn sign_key_update(
        &self,
        info: &KeyUpdateInfoV1,
        context: &OuterContextV1,
        update: KeyUpdateV1,
    ) -> Result<KeyUpdateV1, TransitionCoordinatorError> {
        MachineDataAuthority::sign_key_update(self, info, context, update)
            .map_err(|_| TransitionCoordinatorError::CryptographicAuthority)
    }
}
