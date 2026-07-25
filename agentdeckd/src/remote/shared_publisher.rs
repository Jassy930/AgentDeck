//! Runtime shared stream 到 signed Relay publication 的规范化入口。
//!
//! 同一 canonical `CatalogDelta` / `RuntimeEvent` 可能同时写向多个远端
//! connection；各 connection 的 `RuntimeEnvelope.messageId` 是易失关联值，不能进入
//! durable publication identity。这里先把 stream item 规范化为稳定 messageId 与 exact
//! Runtime bytes，再把一次性 transaction sealer 交给 authenticated backend。backend
//! 负责唯一 Active scope、当前 ADGK2 key/revision、CounterGuard 与 Store freeze 的同事务
//! 复核；Relay COMMIT 只推进外层 cut，本模块必须等 exact local ACK tombstone 已由
//! backend 读回后才能返回成功。

use std::sync::Arc;

use agentdeck_crypto::{AeadSendingKey, SecretAeadKey, SenderCounter, seal_symmetric};
use agentdeck_protocol::e2ee::{
    E2EE_FORMAT_VERSION, KeyId, KeyPurpose, OuterContextV1, SignedSealedBlobV1,
    UnsignedSealedBlobV1,
};
use agentdeck_protocol::relay_v2::{
    MachineRouteId, RELAY_PROTOCOL_VERSION, StreamGenerationId, StreamRouteId,
};
use agentdeck_protocol::runtime::RuntimeTransferCarrierV1;
use async_trait::async_trait;

use crate::runtime::events::RuntimeStreamTarget;
use crate::runtime::publication::PublicationDriveReport;
#[cfg(test)]
use crate::runtime::store::PublicationPayloadKind;
use crate::runtime::store::publication::{
    SharedPublicationPreflight, SharedPublicationPreflightRequest, SharedPublicationStreamProposal,
    SharedPublicationTransactionBinding,
};
use crate::runtime::store::{
    PublicationScope, PublicationStreamRecord, PublicationStreamState,
    RotatePublicationStreamRequest, RuntimeStoreError, RuntimeStoreHandle,
};

use super::counter::{CounterGuardBackend, CounterScope};
use super::link::{RemoteLinkError, RemoteStreamPublisher};
use super::publication_transport::{PublicationDriveError, PublicationDriveHandle};
use super::publisher::{
    PublicationError, SignedPublicationCoordinator, SignedPublicationError,
    SignedPublicationRequest,
};
use super::transport::{
    MachineDataAuthority, MachinePublicationHandle, MachineStreamRegistrationOutcome,
};

mod canonical;

use canonical::CanonicalSharedPublication;
#[cfg(test)]
use canonical::STABLE_MESSAGE_ID_PREFIX;

/// authenticated directory 的硬上界为 1,025 streams；多 stream 公平轮转不能假设
/// 一轮恰好选中本 stream，因此允许覆盖完整目录的一次有界轮转。
const MAX_EXACT_COMMIT_DRIVE_ROUNDS: usize = 1_026;

/// backend 在唯一 Store transaction 内认证并分配的全部 seal 轴。raw key 不进入
/// publisher identity，也不由 Relay/adapter 持有。
pub(crate) struct TransactionSharedPublicationAxes {
    pub(crate) publication_stream_id: [u8; 16],
    pub(crate) stream_route: StreamRouteId,
    pub(crate) generation: StreamGenerationId,
    pub(crate) stream_seq: u64,
    pub(crate) key_directory_revision: u64,
    pub(crate) key_id: KeyId,
    pub(crate) sender_counter: u64,
    pub(crate) key: SecretAeadKey,
}

/// `self: Box<Self>` 保证 backend 每次 freeze 最多消费一次 transaction sealer。
pub(crate) trait TransactionSharedPublicationSealer: Send + 'static {
    fn seal_once(
        self: Box<Self>,
        axes: TransactionSharedPublicationAxes,
    ) -> Result<Vec<u8>, SharedPublisherError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ExactSharedPublicationTarget {
    publication_id: [u8; 16],
    publication_stream_id: [u8; 16],
    generation: [u8; 16],
    stream_seq: u64,
    blob_sha256: [u8; 32],
}

impl ExactSharedPublicationTarget {
    pub(crate) fn validate(self) -> Result<Self, SharedPublisherError> {
        if self.publication_id == [0; 16]
            || self.publication_stream_id == [0; 16]
            || self.generation == [0; 16]
            || self.blob_sha256 == [0; 32]
        {
            return Err(SharedPublisherError::BackendRejected);
        }
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SharedFreezeOutcome {
    /// authenticated ACK tombstone + matching inner cut 已证明该 item 完成；不得再 reserve/seal。
    AlreadyHandled,
    Frozen(ExactSharedPublicationTarget),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg(test)]
pub(crate) enum ExactCommitStatus {
    Pending,
    Committed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ExactDeliveryStatus {
    Pending,
    Acknowledged,
}

/// Runtime Store 的窄 production seam。实现必须在 counter reserve 前识别 authenticated
/// ACK tombstone，并在 freeze transaction 内重查唯一 Active scope、generation、ADGK2
/// revision/key epoch；不能只信调用前的 read snapshot。
#[async_trait]
pub(crate) trait SharedPublicationBackend: Send + Sync {
    async fn freeze_canonical(
        &self,
        request: CanonicalSharedPublication,
        sealer: Box<dyn TransactionSharedPublicationSealer>,
    ) -> Result<SharedFreezeOutcome, SharedPublisherError>;

    #[cfg(test)]
    async fn exact_commit_status(
        &self,
        target: ExactSharedPublicationTarget,
    ) -> Result<ExactCommitStatus, SharedPublisherError>;

    /// Relay COMMIT 只证明外层 cut；publisher 只有在 exact local ACK 已删除
    /// frozen row 并留下 authenticated tombstone 后才能向 Runtime writer 返回成功。
    async fn exact_delivery_status(
        &self,
        target: ExactSharedPublicationTarget,
    ) -> Result<ExactDeliveryStatus, SharedPublisherError>;
}

/// production RuntimeStore adapter。构造时固定同一 authenticated Store、CounterGuard
/// backend 与 machine route；manager 后续只需把该实例装入 `SharedStreamPublisher`。
pub(crate) struct RuntimeStoreSharedPublicationBackend<B: CounterGuardBackend> {
    store: RuntimeStoreHandle,
    guard: Arc<B>,
    machine_route: MachineRouteId,
    trust_domain: [u8; 32],
}

impl<B: CounterGuardBackend> RuntimeStoreSharedPublicationBackend<B> {
    pub(crate) fn new(
        store: RuntimeStoreHandle,
        guard: Arc<B>,
        machine_route: MachineRouteId,
    ) -> Result<Self, SharedPublisherError> {
        if machine_route.as_bytes() == &[0; 16] {
            return Err(SharedPublisherError::InvalidSealAxes);
        }
        let trust_domain = store
            .machine_trust_domain()
            .map_err(|_| SharedPublisherError::BackendRejected)?;
        Ok(Self {
            store,
            guard,
            machine_route,
            trust_domain,
        })
    }

    fn proposal() -> Result<SharedPublicationStreamProposal, SharedPublisherError> {
        fn random_nonzero() -> Result<[u8; 16], SharedPublisherError> {
            let mut value = [0_u8; 16];
            getrandom::fill(&mut value).map_err(|_| SharedPublisherError::BackendRejected)?;
            value[0] |= 0x80;
            Ok(value)
        }
        Ok(SharedPublicationStreamProposal {
            publication_stream_id: random_nonzero()?,
            stream_route: random_nonzero()?,
            generation: random_nonzero()?,
        })
    }
}

/// generation rollover 只暴露 authenticated Store 已有的两个原子入口，便于把
/// "preflight → exact rotation → 同 canonical request 再 preflight" 固定成一个可测试
/// production 状态机。一次性 sealer 不进入这个 seam。
#[async_trait]
trait SharedPublicationRotationStore: Send + Sync {
    async fn preflight(
        &self,
        request: SharedPublicationPreflightRequest,
        proposal: SharedPublicationStreamProposal,
    ) -> Result<SharedPublicationPreflight, RuntimeStoreError>;

    async fn rotate(
        &self,
        request: RotatePublicationStreamRequest,
    ) -> Result<PublicationStreamRecord, RuntimeStoreError>;
}

#[async_trait]
impl SharedPublicationRotationStore for RuntimeStoreHandle {
    async fn preflight(
        &self,
        request: SharedPublicationPreflightRequest,
        proposal: SharedPublicationStreamProposal,
    ) -> Result<SharedPublicationPreflight, RuntimeStoreError> {
        self.preflight_shared_publication(request, proposal).await
    }

    async fn rotate(
        &self,
        request: RotatePublicationStreamRequest,
    ) -> Result<PublicationStreamRecord, RuntimeStoreError> {
        self.rotate_publication_stream(request).await
    }
}

async fn preflight_with_generation_rotation<S: SharedPublicationRotationStore>(
    store: &S,
    request: SharedPublicationPreflightRequest,
    proposal: SharedPublicationStreamProposal,
) -> Result<SharedPublicationPreflight, SharedPublisherError> {
    let first = store
        .preflight(request.clone(), proposal)
        .await
        .map_err(|_| SharedPublisherError::BackendRejected)?;
    let SharedPublicationPreflight::RotationRequired(rotation) = first else {
        return Ok(first);
    };

    let rotated = store.rotate(rotation).await.map_err(|error| match error {
        RuntimeStoreError::PublicationNeedsSnapshot => SharedPublisherError::SnapshotRequired,
        RuntimeStoreError::PublicationMismatch => SharedPublisherError::GenerationRotationBlocked,
        _ => SharedPublisherError::BackendRejected,
    })?;
    if rotated.publication_stream_id != rotation.publication_stream_id
        || rotated.generation == rotation.expected_generation
        || rotated.state != PublicationStreamState::Active
        || rotated.rotation_serial == 0
    {
        return Err(SharedPublisherError::BackendRejected);
    }

    match store
        .preflight(request, proposal)
        .await
        .map_err(|_| SharedPublisherError::BackendRejected)?
    {
        SharedPublicationPreflight::RotationRequired(_) => {
            Err(SharedPublisherError::GenerationRotationBlocked)
        }
        ready => Ok(ready),
    }
}

#[async_trait]
impl<B: CounterGuardBackend> SharedPublicationBackend for RuntimeStoreSharedPublicationBackend<B> {
    async fn freeze_canonical(
        &self,
        request: CanonicalSharedPublication,
        sealer: Box<dyn TransactionSharedPublicationSealer>,
    ) -> Result<SharedFreezeOutcome, SharedPublisherError> {
        let preflight_request = SharedPublicationPreflightRequest {
            publication_id: request.publication_id,
            scope: request.scope,
            inner_after: request.inner_after,
            inner_through: request.inner_through,
            payload_kind: request.payload_kind,
            journal_identity: request.journal_identity,
            canonical_item_bytes: request.canonical_item_bytes.as_ref().to_vec(),
        };
        // Rotation 在 transaction sealer 进入 SignedPublicationCoordinator 前完成；缺少
        // exact ready snapshot、未 ACK outbox 或 rotation identity 分叉都不会 reserve
        // CounterGuard，也不会消费 canonical request 的一次性 sealer。
        let preflight = preflight_with_generation_rotation(
            &self.store,
            preflight_request.clone(),
            Self::proposal()?,
        )
        .await?;
        let (publication_stream_id, generation, key_directory_revision, key_id, existing_target) =
            match preflight {
                SharedPublicationPreflight::AlreadyHandled => {
                    return Ok(SharedFreezeOutcome::AlreadyHandled);
                }
                SharedPublicationPreflight::RotationRequired(_) => {
                    return Err(SharedPublisherError::GenerationRotationBlocked);
                }
                SharedPublicationPreflight::Frozen {
                    publication_stream_id,
                    generation,
                    stream_seq,
                    blob_sha256,
                    key_directory_revision,
                    key_id,
                } => (
                    publication_stream_id,
                    generation,
                    key_directory_revision,
                    key_id,
                    Some(ExactSharedPublicationTarget {
                        publication_id: request.publication_id,
                        publication_stream_id,
                        generation,
                        stream_seq,
                        blob_sha256,
                    }),
                ),
                SharedPublicationPreflight::Fresh {
                    publication_stream_id,
                    generation,
                    key_directory_revision,
                    key_id,
                } => (
                    publication_stream_id,
                    generation,
                    key_directory_revision,
                    key_id,
                    None,
                ),
            };
        let counter_scope =
            CounterScope::publication(self.trust_domain, key_id, publication_stream_id)
                .map_err(|_| SharedPublisherError::BackendRejected)?;
        let signed_request = SignedPublicationRequest {
            publication_id: request.publication_id,
            publication_stream_id,
            machine_route: self.machine_route,
            generation: StreamGenerationId::from_bytes(generation),
            key_directory_revision,
            key_id,
            counter_scope,
            inner_after: request.inner_after,
            inner_through: request.inner_through,
            payload_kind: request.payload_kind,
            sealer_retained_bytes: request.canonical_runtime_bytes.len(),
        };
        let binding = SharedPublicationTransactionBinding {
            request: preflight_request,
            expected_key_directory_revision: key_directory_revision,
            expected_key_id: key_id,
        };
        let frozen = match SignedPublicationCoordinator::new(&self.store, self.guard.as_ref())
            .freeze_shared_signed(signed_request, binding, move |axes, shared_key| {
                sealer
                    .seal_once(TransactionSharedPublicationAxes {
                        publication_stream_id,
                        stream_route: axes.stream_route(),
                        generation: axes.generation(),
                        stream_seq: axes.stream_seq(),
                        key_directory_revision: shared_key.key_directory_revision,
                        key_id: shared_key.key_id,
                        sender_counter: axes.sender_counter(),
                        key: shared_key.key,
                    })
                    .map_err(|_| PublicationError::InvalidAxes)
            })
            .await
        {
            Ok(frozen) => frozen,
            // delivery ACK 可以在线性化 preflight 之后、freeze transaction 取得
            // BEGIN IMMEDIATE 之前完成。Store 对 exact tombstone 返回这个 typed
            // outcome，且保证一次性 sealer 尚未被消费；它等价于 preflight 的
            // AlreadyHandled，不能泛化为失败后重试并再次 reserve/seal。
            Err(error) => return normalize_freeze_error(error),
        };
        let target = ExactSharedPublicationTarget {
            publication_id: frozen.publication_id,
            publication_stream_id: frozen.publication_stream_id,
            generation: frozen.generation,
            stream_seq: frozen.stream_seq,
            blob_sha256: frozen.blob_sha256,
        };
        if existing_target.is_some_and(|existing| existing != target) {
            return Err(SharedPublisherError::BackendRejected);
        }
        Ok(SharedFreezeOutcome::Frozen(target))
    }

    #[cfg(test)]
    async fn exact_commit_status(
        &self,
        target: ExactSharedPublicationTarget,
    ) -> Result<ExactCommitStatus, SharedPublisherError> {
        let target = target.validate()?;
        let frozen = self
            .store
            .load_frozen_publication(target.publication_id)
            .await
            .map_err(|_| SharedPublisherError::BackendRejected)?;
        let Some(frozen) = frozen else {
            // delivery ACK 会删除 exact outbox row。authenticated stream ACK cut 仍按
            // generation/seq 单调且逐项推进；最新 ACK 恰为 target 时还必须逐字匹配
            // publicationId/hash，更高 ACK 则证明所有较低 seq 已经 exact ACK。
            let stream = self
                .store
                .load_publication_stream_record(target.publication_stream_id)
                .await
                .map_err(|_| SharedPublisherError::BackendRejected)?;
            let acknowledged = stream
                .acknowledged_high_water
                .filter(|acknowledged| *acknowledged >= target.stream_seq)
                .ok_or(SharedPublisherError::BackendRejected)?;
            if stream.generation != target.generation
                || stream
                    .committed_high_water
                    .is_none_or(|committed| committed < target.stream_seq)
                || (acknowledged == target.stream_seq
                    && (stream.last_acknowledged_publication_id != Some(target.publication_id)
                        || stream.last_acknowledged_blob_hash != Some(target.blob_sha256)))
            {
                return Err(SharedPublisherError::BackendRejected);
            }
            return Ok(ExactCommitStatus::Committed);
        };
        if frozen.publication_stream_id != target.publication_stream_id
            || frozen.generation != target.generation
            || frozen.stream_seq != target.stream_seq
            || frozen.blob_sha256 != target.blob_sha256
        {
            return Err(SharedPublisherError::BackendRejected);
        }
        let cut = self
            .store
            .load_publication_barrier(target.publication_stream_id)
            .await
            .map_err(|_| SharedPublisherError::BackendRejected)?;
        if cut.generation != target.generation {
            return Err(SharedPublisherError::BackendRejected);
        }
        Ok(
            if cut
                .committed_outer_cursor
                .is_some_and(|seq| seq >= target.stream_seq)
                && frozen.inner_through.is_none_or(|through| {
                    cut.committed_inner_cursor.is_some_and(|cut| cut >= through)
                })
            {
                ExactCommitStatus::Committed
            } else {
                ExactCommitStatus::Pending
            },
        )
    }

    async fn exact_delivery_status(
        &self,
        target: ExactSharedPublicationTarget,
    ) -> Result<ExactDeliveryStatus, SharedPublisherError> {
        let target = target.validate()?;
        let frozen = self
            .store
            .load_frozen_publication(target.publication_id)
            .await
            .map_err(|_| SharedPublisherError::BackendRejected)?;
        if let Some(frozen) = frozen {
            if frozen.publication_stream_id != target.publication_stream_id
                || frozen.generation != target.generation
                || frozen.stream_seq != target.stream_seq
                || frozen.blob_sha256 != target.blob_sha256
            {
                return Err(SharedPublisherError::BackendRejected);
            }
            return Ok(ExactDeliveryStatus::Pending);
        }
        let stream = self
            .store
            .load_publication_stream_record(target.publication_stream_id)
            .await
            .map_err(|_| SharedPublisherError::BackendRejected)?;
        let acknowledged = stream
            .acknowledged_high_water
            .filter(|acknowledged| *acknowledged >= target.stream_seq)
            .ok_or(SharedPublisherError::BackendRejected)?;
        if stream.generation != target.generation
            || stream
                .committed_high_water
                .is_none_or(|committed| committed < target.stream_seq)
            || (acknowledged == target.stream_seq
                && (stream.last_acknowledged_publication_id != Some(target.publication_id)
                    || stream.last_acknowledged_blob_hash != Some(target.blob_sha256)))
        {
            return Err(SharedPublisherError::BackendRejected);
        }
        Ok(ExactDeliveryStatus::Acknowledged)
    }
}

fn normalize_freeze_error(
    error: SignedPublicationError,
) -> Result<SharedFreezeOutcome, SharedPublisherError> {
    match error {
        SignedPublicationError::Store(
            crate::runtime::store::RuntimeStoreError::PublicationAlreadyAcknowledged,
        ) => Ok(SharedFreezeOutcome::AlreadyHandled),
        SignedPublicationError::Store(
            crate::runtime::store::RuntimeStoreError::PublicationNeedsSnapshot,
        ) => Err(SharedPublisherError::SnapshotRequired),
        SignedPublicationError::RetireKey => Err(SharedPublisherError::CounterRetired),
        _ => Err(SharedPublisherError::BackendRejected),
    }
}

/// 只适配既有唯一 `PublicationDriveOwner` 的 handle；不得创建第二 client/read loop。
#[async_trait]
pub(crate) trait SharedPublicationDrive: Send + Sync {
    async fn notify_frozen_stream(
        &self,
        publication_stream_id: [u8; 16],
    ) -> Result<(), SharedPublisherError>;

    async fn drive_round(&self) -> Result<PublicationDriveReport, SharedPublisherError>;

    async fn notify_reconnected(&self) -> Result<(), SharedPublisherError> {
        Ok(())
    }

    async fn recover_pending(&self) -> Result<(), SharedPublisherError> {
        self.notify_reconnected().await
    }
}

#[async_trait]
impl SharedPublicationDrive for PublicationDriveHandle {
    async fn notify_frozen_stream(
        &self,
        publication_stream_id: [u8; 16],
    ) -> Result<(), SharedPublisherError> {
        PublicationDriveHandle::notify_frozen_stream(self, publication_stream_id)
            .await
            .map_err(map_publication_drive_error)
    }

    async fn drive_round(&self) -> Result<PublicationDriveReport, SharedPublisherError> {
        PublicationDriveHandle::drive_round(self)
            .await
            .map_err(map_publication_drive_error)
    }

    async fn notify_reconnected(&self) -> Result<(), SharedPublisherError> {
        PublicationDriveHandle::notify_reconnected(self)
            .await
            .map_err(map_publication_drive_error)
    }

    async fn recover_pending(&self) -> Result<(), SharedPublisherError> {
        PublicationDriveHandle::recover_pending(self)
            .await
            .map_err(map_publication_drive_error)
    }
}

fn map_publication_drive_error(error: PublicationDriveError) -> SharedPublisherError {
    crate::diag::log(
        "remote_publication_drive_failure",
        &format!("error={error}"),
    );
    SharedPublisherError::DriveUnavailable
}

pub(crate) trait SharedPublicationSigner: Send + Sync {
    fn sign_sealed(
        &self,
        unsigned: UnsignedSealedBlobV1,
        context: &OuterContextV1,
    ) -> Result<SignedSealedBlobV1, SharedPublisherError>;
}

impl SharedPublicationSigner for MachineDataAuthority {
    fn sign_sealed(
        &self,
        unsigned: UnsignedSealedBlobV1,
        context: &OuterContextV1,
    ) -> Result<SignedSealedBlobV1, SharedPublisherError> {
        MachineDataAuthority::sign_sealed(self, unsigned, context)
            .map_err(|_| SharedPublisherError::MachineDataSigningFailed)
    }
}

struct SharedTransactionSealer {
    machine_route: MachineRouteId,
    request: CanonicalSharedPublication,
    signer: Arc<dyn SharedPublicationSigner>,
}

impl TransactionSharedPublicationSealer for SharedTransactionSealer {
    fn seal_once(
        self: Box<Self>,
        axes: TransactionSharedPublicationAxes,
    ) -> Result<Vec<u8>, SharedPublisherError> {
        if axes.publication_stream_id == [0; 16]
            || axes.stream_route.as_bytes() == &[0; 16]
            || axes.generation.as_bytes() == &[0; 16]
            || axes.key_directory_revision == 0
            || axes.key_id.epoch == 0
        {
            return Err(SharedPublisherError::InvalidSealAxes);
        }
        let expected_purpose = match self.request.scope {
            PublicationScope::Catalog => KeyPurpose::Catalog,
            PublicationScope::Conversation(_) => KeyPurpose::ConversationDek,
        };
        if axes.key_id.purpose != expected_purpose {
            return Err(SharedPublisherError::KeyPurposeMismatch);
        }
        let context = OuterContextV1 {
            frame_kind: self.request.frame_kind,
            relay_protocol_version: RELAY_PROTOCOL_VERSION,
            e2ee_format_version: E2EE_FORMAT_VERSION,
            machine_route: Some(self.machine_route),
            device_route: None,
            stream_route: Some(axes.stream_route),
            request_route: None,
            pair_route: None,
            stream_generation: Some(axes.generation),
            // Publish outer 只公开 streamSeq，不公开 inner cursor。把 H 放进 AAD 会让
            // 接收端在验签/AEAD open 前无法重建 context；H 只留在密文与 authenticated outbox。
            stream_cursor: None,
            stream_seq: Some(axes.stream_seq),
            message_key_epoch: axes.key_id.epoch,
        };
        let key = AeadSendingKey::with_derived_nonce_prefix(
            axes.key_id,
            axes.key_id.epoch,
            axes.key_directory_revision,
            axes.key,
        );
        let unsigned = seal_symmetric(
            &key,
            &context,
            self.request.sealed_payload_kind,
            self.request.canonical_runtime_bytes.as_ref(),
            SenderCounter(axes.sender_counter),
        )
        .map_err(|_| SharedPublisherError::EncryptionFailed)?;
        let signed = self.signer.sign_sealed(unsigned, &context)?;
        if signed.inner.key_id != axes.key_id
            || signed.inner.key_epoch != axes.key_id.epoch
            || signed.inner.key_directory_revision != axes.key_directory_revision
        {
            return Err(SharedPublisherError::MachineDataSigningFailed);
        }
        let wire = signed.to_wire_bytes();
        SignedSealedBlobV1::from_wire_bytes(&wire)
            .map_err(|_| SharedPublisherError::MachineDataSigningFailed)?;
        Ok(wire)
    }
}

/// RemoteLink 安装的 shared publisher。它不持 canonical Runtime state，只持 Store
/// backend、MachineDataSign capability 与既有 drive owner 的窄 handle。
pub(crate) struct SharedStreamPublisher {
    machine_route: MachineRouteId,
    backend: Arc<dyn SharedPublicationBackend>,
    drive: Arc<dyn SharedPublicationDrive>,
    signer: Arc<dyn SharedPublicationSigner>,
    subscription: Option<SubscriptionStreamProvisioner>,
}

struct SubscriptionStreamProvisioner {
    store: RuntimeStoreHandle,
    registration: MachinePublicationHandle,
}

impl SubscriptionStreamProvisioner {
    async fn prepare(&self, target: RuntimeStreamTarget) -> Result<(), SharedPublisherError> {
        let scope = match target {
            RuntimeStreamTarget::Catalog => PublicationScope::Catalog,
            RuntimeStreamTarget::Conversation(conversation_id) => {
                PublicationScope::Conversation(conversation_id)
            }
        };
        let stream = self
            .store
            .ensure_subscription_publication_stream(scope)
            .await
            .map_err(|error| match error {
                RuntimeStoreError::PublicationNeedsSnapshot => {
                    SharedPublisherError::SnapshotRequired
                }
                _ => SharedPublisherError::BackendRejected,
            })?;
        match self
            .registration
            .register_stream_exact(
                StreamRouteId::from_bytes(stream.stream_route),
                StreamGenerationId::from_bytes(stream.generation),
            )
            .await
            .map_err(|_| SharedPublisherError::StreamRegistrationFailed)?
        {
            MachineStreamRegistrationOutcome::Registered { .. } => Ok(()),
            MachineStreamRegistrationOutcome::OutcomeUnknown => {
                Err(SharedPublisherError::StreamRegistrationOutcomeUnknown)
            }
            MachineStreamRegistrationOutcome::Offline => Err(SharedPublisherError::RelayOffline),
        }
    }
}

impl SharedStreamPublisher {
    pub(crate) fn new(
        machine_route: MachineRouteId,
        backend: Arc<dyn SharedPublicationBackend>,
        drive: Arc<dyn SharedPublicationDrive>,
        signer: Arc<dyn SharedPublicationSigner>,
    ) -> Result<Self, SharedPublisherError> {
        if machine_route.as_bytes() == &[0; 16] {
            return Err(SharedPublisherError::InvalidSealAxes);
        }
        Ok(Self {
            machine_route,
            backend,
            drive,
            signer,
            subscription: None,
        })
    }

    pub(crate) fn with_subscription_provisioning(
        mut self,
        store: RuntimeStoreHandle,
        registration: MachinePublicationHandle,
    ) -> Result<Self, SharedPublisherError> {
        if registration.machine_route() != self.machine_route {
            return Err(SharedPublisherError::InvalidSealAxes);
        }
        self.subscription = Some(SubscriptionStreamProvisioner {
            store,
            registration,
        });
        Ok(self)
    }

    pub(crate) async fn publish_runtime_bytes(
        &self,
        runtime_bytes: Arc<[u8]>,
    ) -> Result<(), SharedPublisherError> {
        let request = CanonicalSharedPublication::parse(runtime_bytes)?;
        self.publish_canonical(request).await
    }

    pub(crate) async fn publish_transfer_carrier(
        &self,
        carrier: RuntimeTransferCarrierV1,
    ) -> Result<(), SharedPublisherError> {
        let request = CanonicalSharedPublication::parse_transfer(carrier)?;
        self.publish_canonical(request).await
    }

    async fn publish_canonical(
        &self,
        request: CanonicalSharedPublication,
    ) -> Result<(), SharedPublisherError> {
        let sealer = Box::new(SharedTransactionSealer {
            machine_route: self.machine_route,
            request: request.clone(),
            signer: Arc::clone(&self.signer),
        });
        let target = match self.backend.freeze_canonical(request, sealer).await? {
            SharedFreezeOutcome::AlreadyHandled => return Ok(()),
            SharedFreezeOutcome::Frozen(target) => target.validate()?,
        };
        if self.backend.exact_delivery_status(target).await? == ExactDeliveryStatus::Acknowledged {
            return Ok(());
        }
        self.drive
            .notify_frozen_stream(target.publication_stream_id)
            .await?;

        for _ in 0..MAX_EXACT_COMMIT_DRIVE_ROUNDS {
            let report = self.drive.drive_round().await?;
            if self.backend.exact_delivery_status(target).await?
                == ExactDeliveryStatus::Acknowledged
            {
                return Ok(());
            }
            if report.offline {
                return Err(SharedPublisherError::RelayOffline);
            }
            if report.outcome_unknown > 0
                || report.commit_pending > 0
                || report.transient_store_busy > 0
            {
                return Err(SharedPublisherError::CommitOutcomeUnknown);
            }
            if report.loaded == 0 && report.committed == 0 {
                return Err(SharedPublisherError::ExactCommitNotObserved);
            }
        }
        Err(SharedPublisherError::DriveRoundsExhausted)
    }
}

#[async_trait]
impl RemoteStreamPublisher for SharedStreamPublisher {
    fn admission_ready(&self) -> bool {
        true
    }

    async fn prepare_subscription(
        &self,
        target: RuntimeStreamTarget,
    ) -> Result<(), RemoteLinkError> {
        let subscription = self
            .subscription
            .as_ref()
            .ok_or(SharedPublisherError::StreamRegistrationUnavailable)
            .map_err(remote_link_error)?;
        subscription
            .prepare(target)
            .await
            .map_err(remote_link_error)
    }

    async fn publish_exact(&self, runtime_bytes: Arc<[u8]>) -> Result<(), RemoteLinkError> {
        self.publish_runtime_bytes(runtime_bytes)
            .await
            .map_err(remote_link_error)
    }

    async fn publish_transfer_exact(
        &self,
        carrier: RuntimeTransferCarrierV1,
    ) -> Result<(), RemoteLinkError> {
        self.publish_transfer_carrier(carrier)
            .await
            .map_err(remote_link_error)
    }

    async fn notify_reconnected(&self) -> Result<(), RemoteLinkError> {
        self.drive
            .recover_pending()
            .await
            .map_err(|_| RemoteLinkError::StreamPublishFailed)?;
        Ok(())
    }
}

fn remote_link_error(error: SharedPublisherError) -> RemoteLinkError {
    crate::diag::log(
        "remote_stream_publisher_failure",
        &format!("code={}", error.code()),
    );
    match error {
        SharedPublisherError::CounterRetired => RemoteLinkError::CounterRetired,
        _ => RemoteLinkError::StreamPublishFailed,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum SharedPublisherError {
    #[error("Runtime envelope is invalid")]
    InvalidRuntimeEnvelope,
    #[error("shared publisher accepts Runtime Stream items only")]
    NotSharedStreamItem,
    #[error("PairingPending is local-only and cannot enter shared publication")]
    PairingPendingIsLocalOnly,
    #[error("TransferPart requires a durable transfer publication assembler")]
    TransferRequiresDurableAssembler,
    #[error("shared publication durable identity is invalid")]
    InvalidDurableIdentity,
    #[error("shared publication canonical encoding failed")]
    CanonicalEncodingFailed,
    #[error("shared publication transaction axes are invalid")]
    InvalidSealAxes,
    #[error("shared publication key purpose does not match its scope")]
    KeyPurposeMismatch,
    #[error("shared publication encryption failed")]
    EncryptionFailed,
    #[error("MachineDataSign failed or returned mismatched output")]
    MachineDataSigningFailed,
    #[error("authenticated shared publication backend rejected the request")]
    BackendRejected,
    #[error("shared publication generation requires an authenticated ready snapshot")]
    SnapshotRequired,
    #[error("shared publication generation rotation is blocked by pending or mismatched state")]
    GenerationRotationBlocked,
    #[error("shared publication counter scope is durably retired")]
    CounterRetired,
    #[error("publication drive owner is unavailable")]
    DriveUnavailable,
    #[error("subscription stream registration is not installed")]
    StreamRegistrationUnavailable,
    #[error("subscription stream registration failed")]
    StreamRegistrationFailed,
    #[error("subscription stream registration outcome is unknown")]
    StreamRegistrationOutcomeUnknown,
    #[error("Relay publication outcome is unknown")]
    CommitOutcomeUnknown,
    #[error("Relay is offline")]
    RelayOffline,
    #[error("exact Relay COMMIT was not observed")]
    ExactCommitNotObserved,
    #[error("exact Relay COMMIT drive exhausted its bounded fair rounds")]
    DriveRoundsExhausted,
}

impl SharedPublisherError {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::InvalidRuntimeEnvelope => "daemon.remote.publisher.runtime_invalid",
            Self::NotSharedStreamItem => "daemon.remote.publisher.stream_required",
            Self::PairingPendingIsLocalOnly => "daemon.remote.publisher.pairing_local_only",
            Self::TransferRequiresDurableAssembler => {
                "daemon.remote.publisher.transfer_assembler_required"
            }
            Self::InvalidDurableIdentity => "daemon.remote.publisher.identity_invalid",
            Self::CanonicalEncodingFailed => "daemon.remote.publisher.canonical_failed",
            Self::InvalidSealAxes => "daemon.remote.publisher.axes_invalid",
            Self::KeyPurposeMismatch => "daemon.remote.publisher.key_purpose_mismatch",
            Self::EncryptionFailed => "daemon.remote.publisher.encryption_failed",
            Self::MachineDataSigningFailed => "daemon.remote.publisher.machine_sign_failed",
            Self::BackendRejected => "daemon.remote.publisher.backend_rejected",
            Self::SnapshotRequired => "daemon.remote.publisher.snapshot_required",
            Self::GenerationRotationBlocked => "daemon.remote.publisher.rotation_blocked",
            Self::CounterRetired => "daemon.remote.counter.retired",
            Self::DriveUnavailable => "daemon.remote.publisher.drive_unavailable",
            Self::StreamRegistrationUnavailable => {
                "daemon.remote.publisher.stream_registration_unavailable"
            }
            Self::StreamRegistrationFailed => "daemon.remote.publisher.stream_registration_failed",
            Self::StreamRegistrationOutcomeUnknown => {
                "daemon.remote.publisher.stream_registration_unknown"
            }
            Self::CommitOutcomeUnknown => "daemon.remote.publisher.commit_unknown",
            Self::RelayOffline => "daemon.remote.publisher.relay_offline",
            Self::ExactCommitNotObserved => "daemon.remote.publisher.commit_not_observed",
            Self::DriveRoundsExhausted => "daemon.remote.publisher.drive_exhausted",
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use agentdeck_crypto::{VerifyingKey, sha256, verify_sealed};
    use agentdeck_protocol::e2ee::{
        AuthorizationCapabilityV1, AuthorizationPermissionV1, OuterFrameKind, UnsignedSealedBlobV1,
    };
    use agentdeck_protocol::relay_v2::auth::Ed25519Signature;
    use agentdeck_protocol::relay_v2::{RelayServerId, SignedCertificate};
    use agentdeck_protocol::runtime::catalog::{CatalogChange, CatalogDelta, ConversationEntry};
    use agentdeck_protocol::runtime::event::{RuntimeEvent, RuntimeEventBody};
    use agentdeck_protocol::runtime::identity::{
        CommandId, ConversationId, EventId, MessageId, PairingId, TransferId, TurnId,
    };
    use agentdeck_protocol::runtime::{
        CodexConversationConfiguration, ConversationConfiguration, MAX_PART_BYTES, PendingPairing,
        RUNTIME_PROTOCOL_VERSION, RuntimeEnvelope, RuntimeMessage, RuntimeStreamItem,
        TransferEnvelope, VendorConfigurationSnapshot,
    };
    use agentdeck_protocol::{CodexApprovalPolicy, CodexReasoningEffort, CodexSandboxMode};
    use async_trait::async_trait;
    use tokio::sync::Notify;

    use super::*;
    use crate::remote::bootstrap::machine_pairing_anchor_for_test;
    use crate::remote::counter::{COUNTER_BLOCK_SIZE, CounterGuardBackend};
    use crate::remote::identity::{KeyStoreCounterGuardBackend, OwnedKeyStoreCounterGuardBackend};
    use crate::remote::publication_transport::tests::open_owner_with_transport_for_test;
    use crate::remote::transport::tests::{
        MachineDataAuthorityOwnerLease, machine_data_authority_for_transition_test,
    };
    use crate::runtime::model::{
        ConversationDescriptor, IdempotencyOwner, MachineEnrollmentState, MachineIdentityBinding,
        NewConversation, RuntimeClock, RuntimeClockError, RuntimeStoreConfig,
        RuntimeStoreFaultInjector, RuntimeStoreOperation,
    };
    use crate::runtime::publication::{
        PublicationCommitReceipt, PublicationDispatchKey, PublicationTransport,
        PublicationTransportOutcome,
    };
    use crate::runtime::store::identity::{RuntimeId, RuntimeIdKind};
    use crate::runtime::store::{
        ActiveSenderCounterBinding, ConfigureConversation, ConfigureConversationOutcome,
        FrozenPublication, RetiredKeyOwnerKind, RetiredSharedKeyOwner, RuntimeBackfillPlan,
        RuntimeBackfillTarget, RuntimeStoreError, RuntimeStoreHandle,
        active_authorization_store_for_test,
        complete_active_zero_cut_transition_with_counter_guard,
        production_aligned_active_authorization_store_for_test,
    };
    use crate::runtime::transfer_identity::{DurableStreamSource, DurableStreamTransferIdentity};
    use crate::security::{KeyStore, MemoryKeyStore, load_or_create_storage_kek};

    const CONVERSATION: &str = "11111111-2222-4333-8444-555555555555";

    const MACHINE_DATA_SIGN_SEED: [u8; 32] = [0x43; 32];

    #[derive(Clone, Copy, Debug)]
    enum ProductionSharedCrashClass {
        Catalog,
        ConversationEvent,
    }

    impl ProductionSharedCrashClass {
        const fn label(self) -> &'static str {
            match self {
                Self::Catalog => "catalog",
                Self::ConversationEvent => "conversation-event",
            }
        }

        const fn expected_frame_kind(self) -> OuterFrameKind {
            match self {
                Self::Catalog => OuterFrameKind::CatalogPublish,
                Self::ConversationEvent => OuterFrameKind::ConversationPublish,
            }
        }

        const fn expected_key_purpose(self) -> KeyPurpose {
            match self {
                Self::Catalog => KeyPurpose::Catalog,
                Self::ConversationEvent => KeyPurpose::ConversationDek,
            }
        }
    }

    #[derive(Clone, Copy)]
    struct ProductionCrashClock;

    impl RuntimeClock for ProductionCrashClock {
        fn now_ms(&self) -> Result<u64, RuntimeClockError> {
            Ok(1_800_000_000_100)
        }
    }

    #[derive(Debug)]
    struct ProductionSharedCrashOnce {
        target: RuntimeStoreOperation,
        armed: AtomicBool,
    }

    impl ProductionSharedCrashOnce {
        fn new(target: RuntimeStoreOperation) -> Self {
            Self {
                target,
                armed: AtomicBool::new(true),
            }
        }
    }

    impl RuntimeStoreFaultInjector for ProductionSharedCrashOnce {
        fn before_operation(
            &self,
            operation: RuntimeStoreOperation,
        ) -> Result<(), RuntimeStoreError> {
            if operation == self.target && self.armed.swap(false, Ordering::SeqCst) {
                return Err(RuntimeStoreError::WorkerStopped);
            }
            Ok(())
        }
    }

    struct ProductionSharedCrashFixture {
        _root: tempfile::TempDir,
        database: std::path::PathBuf,
        keys: Arc<MemoryKeyStore>,
        store: RuntimeStoreHandle,
        runtime_bytes: Arc<[u8]>,
        canonical: CanonicalSharedPublication,
        relay_server_id: RelayServerId,
        machine_route: MachineRouteId,
        binding: MachineIdentityBinding,
        data_certificate: SignedCertificate,
    }

    impl ProductionSharedCrashFixture {
        fn machine_data_authority(&self) -> (MachineDataAuthority, MachineDataAuthorityOwnerLease) {
            machine_data_authority_for_transition_test(
                machine_pairing_anchor_for_test(
                    self.relay_server_id,
                    self.machine_route,
                    &self.binding,
                    self.data_certificate.clone(),
                ),
                MACHINE_DATA_SIGN_SEED,
            )
        }

        fn counter_guard(&self) -> Arc<OwnedKeyStoreCounterGuardBackend> {
            let key_store: Arc<dyn KeyStore> = self.keys.clone();
            Arc::new(OwnedKeyStoreCounterGuardBackend::new(key_store))
        }

        fn backend(
            &self,
            store: &RuntimeStoreHandle,
        ) -> Arc<RuntimeStoreSharedPublicationBackend<OwnedKeyStoreCounterGuardBackend>> {
            Arc::new(
                RuntimeStoreSharedPublicationBackend::new(
                    store.clone(),
                    self.counter_guard(),
                    self.machine_route,
                )
                .expect("construct production shared crash backend"),
            )
        }

        async fn reopen(&self) -> RuntimeStoreHandle {
            self.reopen_with_config(
                RuntimeStoreConfig::new(self.database.clone()).with_clock(ProductionCrashClock),
            )
            .await
        }

        async fn reopen_with_config(&self, config: RuntimeStoreConfig) -> RuntimeStoreHandle {
            let storage_kek = load_or_create_storage_kek(self.keys.as_ref(), &self.database)
                .expect("reload production shared crash StorageKEK");
            RuntimeStoreHandle::open(config, storage_kek)
                .await
                .expect("reopen production shared crash Store")
        }
    }

    async fn production_shared_crash_fixture(
        class: ProductionSharedCrashClass,
        cut: &str,
    ) -> ProductionSharedCrashFixture {
        let root = tempfile::tempdir().expect("create production shared crash root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
                .expect("secure production shared crash root");
        }
        let database = root.path().join(format!("{}-{cut}.db", class.label()));
        let keys = Arc::new(MemoryKeyStore::new());
        let counter_key_store: Arc<dyn KeyStore> = keys.clone();
        let transition_guard = OwnedKeyStoreCounterGuardBackend::new(counter_key_store);
        let storage_kek = load_or_create_storage_kek(keys.as_ref(), &database)
            .expect("create production shared crash StorageKEK");
        let store = production_aligned_active_authorization_store_for_test(
            &database,
            storage_kek,
            vec![
                AuthorizationCapabilityV1::Catalog,
                AuthorizationCapabilityV1::Conversation,
            ],
            vec![
                AuthorizationPermissionV1::CatalogRead,
                AuthorizationPermissionV1::ConversationRead,
            ],
        )
        .await;
        store
            .ensure_remote_catalog_publication_after_transition()
            .await
            .expect("ensure production shared crash Catalog carrier");
        let conversation_id = RuntimeId::from_bytes(RuntimeIdKind::Conversation, [0xb1; 16])
            .expect("production shared crash conversation id");
        let descriptor = ConversationDescriptor {
            agent_kind: agentdeck_protocol::AgentKind::Codex,
            title: Some(format!("production crash {}", class.label())),
            cwd: std::path::PathBuf::from("/tmp/agentdeck-production-shared-crash"),
        };
        let created = store
            .create_conversation(NewConversation {
                conversation_id,
                adapter_state_key: RuntimeId::from_bytes(RuntimeIdKind::AdapterState, [0xb2; 16])
                    .expect("production shared crash adapter state"),
                descriptor: descriptor.clone(),
            })
            .await
            .expect("create production shared crash conversation");
        complete_active_zero_cut_transition_with_counter_guard(&store, &transition_guard).await;

        let item = match class {
            ProductionSharedCrashClass::Catalog => RuntimeStreamItem::CatalogDelta(CatalogDelta {
                catalog_revision: created.catalog_revision,
                changes: vec![CatalogChange::Upserted {
                    entry: ConversationEntry {
                        conversation_id: ConversationId::new(conversation_id.to_canonical_string()),
                        agent_kind: descriptor.agent_kind,
                        title: descriptor.title,
                        cwd: Some(descriptor.cwd),
                        last_active_ms: created.updated_at_ms,
                        archived: false,
                        entry_revision: 0,
                    },
                }],
            }),
            ProductionSharedCrashClass::ConversationEvent => {
                let configuration = ConversationConfiguration::new(
                    VendorConfigurationSnapshot::Codex(CodexConversationConfiguration::new(
                        CodexApprovalPolicy::OnRequest,
                        CodexSandboxMode::WorkspaceWrite,
                        CodexReasoningEffort::Medium,
                    )),
                );
                assert!(matches!(
                    store
                        .configure_conversation(ConfigureConversation {
                            conversation_id,
                            owner: IdempotencyOwner::Local {
                                machine_trust_domain: store
                                    .machine_trust_domain()
                                    .expect("production shared crash trust domain"),
                                uid: 501,
                                client_installation_id: [0xb3; 16],
                            },
                            idempotency_key: "production-shared-crash-event".to_owned(),
                            expected_configuration_revision: 0,
                            configuration,
                        })
                        .await
                        .expect("append production shared crash event"),
                    ConfigureConversationOutcome::Applied { .. }
                ));
                let plan = store
                    .acquire_backfill_pin(
                        RuntimeBackfillTarget::Conversation(conversation_id),
                        None,
                    )
                    .await
                    .expect("pin production shared crash event");
                let RuntimeBackfillPlan::Pinned(pin) = plan else {
                    panic!("fresh event must require a pinned backfill page")
                };
                let page = store
                    .load_event_backfill_page(pin.clone(), None)
                    .await
                    .expect("load exact production shared crash event");
                assert_eq!(page.events.len(), 1);
                let event = page.events[0].clone();
                drop(page);
                store
                    .release_backfill_pin(pin.pin_id)
                    .await
                    .expect("release production shared crash event pin");
                RuntimeStreamItem::Event(event)
            }
        };
        let runtime_bytes = runtime_bytes(
            &format!("production-shared-crash-{}-{cut}", class.label()),
            item,
        );
        let canonical = CanonicalSharedPublication::parse(runtime_bytes.clone())
            .expect("parse production shared crash publication");
        assert_eq!(canonical.frame_kind, class.expected_frame_kind());
        let Some(MachineEnrollmentState::Active(active)) = store
            .load_machine_enrollment_state()
            .await
            .expect("load production shared crash enrollment")
        else {
            panic!("production shared crash machine must remain active")
        };
        let machine_route = MachineRouteId::from_bytes(active.record.machine_route);
        ProductionSharedCrashFixture {
            _root: root,
            database,
            keys,
            store,
            runtime_bytes,
            canonical,
            relay_server_id: active.connection.relay_server_id,
            machine_route,
            binding: active.binding,
            data_certificate: active.data_cert,
        }
    }

    struct CountingMachineDataSigner {
        authority: MachineDataAuthority,
        calls: Arc<AtomicUsize>,
        signed_blobs: Option<Arc<Mutex<Vec<Vec<u8>>>>>,
    }

    impl SharedPublicationSigner for CountingMachineDataSigner {
        fn sign_sealed(
            &self,
            unsigned: UnsignedSealedBlobV1,
            context: &OuterContextV1,
        ) -> Result<SignedSealedBlobV1, SharedPublisherError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let signed = MachineDataAuthority::sign_sealed(&self.authority, unsigned, context)
                .map_err(|_| SharedPublisherError::MachineDataSigningFailed)?;
            if let Some(blobs) = &self.signed_blobs {
                blobs
                    .lock()
                    .expect("record production MachineData signed blob")
                    .push(signed.to_wire_bytes());
            }
            Ok(signed)
        }
    }

    struct CrashBeforeMachineDataSeal {
        sender_counter: Arc<AtomicU64>,
    }

    impl TransactionSharedPublicationSealer for CrashBeforeMachineDataSeal {
        fn seal_once(
            self: Box<Self>,
            axes: TransactionSharedPublicationAxes,
        ) -> Result<Vec<u8>, SharedPublisherError> {
            self.sender_counter
                .store(axes.sender_counter, Ordering::SeqCst);
            Err(SharedPublisherError::MachineDataSigningFailed)
        }
    }

    #[derive(Clone, Copy)]
    enum RecordingRelayPlan {
        Commit,
        OutcomeUnknown,
    }

    struct RecordingPublicationTransport {
        plan: RecordingRelayPlan,
        sent: Mutex<Vec<(PublicationDispatchKey, Vec<u8>)>>,
    }

    impl RecordingPublicationTransport {
        fn new(plan: RecordingRelayPlan) -> Self {
            Self {
                plan,
                sent: Mutex::new(Vec::new()),
            }
        }

        fn sent_blobs(&self) -> Vec<Vec<u8>> {
            self.sent
                .lock()
                .expect("production shared crash transport lock")
                .iter()
                .map(|(_, blob)| blob.clone())
                .collect()
        }
    }

    #[async_trait]
    impl PublicationTransport for RecordingPublicationTransport {
        async fn publish(&self, publication: FrozenPublication) -> PublicationTransportOutcome {
            let key = PublicationDispatchKey::from(&publication);
            self.sent
                .lock()
                .expect("record production shared crash publication")
                .push((key, publication.blob));
            match self.plan {
                RecordingRelayPlan::Commit => {
                    PublicationTransportOutcome::Committed(PublicationCommitReceipt { key })
                }
                RecordingRelayPlan::OutcomeUnknown => PublicationTransportOutcome::OutcomeUnknown,
            }
        }
    }

    fn counting_machine_data_signer(
        fixture: &ProductionSharedCrashFixture,
        calls: Arc<AtomicUsize>,
    ) -> (
        Arc<dyn SharedPublicationSigner>,
        MachineDataAuthorityOwnerLease,
    ) {
        let (authority, lease) = fixture.machine_data_authority();
        (
            Arc::new(CountingMachineDataSigner {
                authority,
                calls,
                signed_blobs: None,
            }),
            lease,
        )
    }

    fn recording_machine_data_signer(
        fixture: &ProductionSharedCrashFixture,
        calls: Arc<AtomicUsize>,
        signed_blobs: Arc<Mutex<Vec<Vec<u8>>>>,
    ) -> (
        Arc<dyn SharedPublicationSigner>,
        MachineDataAuthorityOwnerLease,
    ) {
        let (authority, lease) = fixture.machine_data_authority();
        (
            Arc::new(CountingMachineDataSigner {
                authority,
                calls,
                signed_blobs: Some(signed_blobs),
            }),
            lease,
        )
    }

    fn production_shared_publisher(
        fixture: &ProductionSharedCrashFixture,
        store: &RuntimeStoreHandle,
        drive: PublicationDriveHandle,
        signer: Arc<dyn SharedPublicationSigner>,
    ) -> SharedStreamPublisher {
        SharedStreamPublisher::new(
            fixture.machine_route,
            fixture.backend(store),
            Arc::new(drive),
            signer,
        )
        .expect("construct production shared crash publisher")
    }

    async fn exact_frozen_blob(
        store: &RuntimeStoreHandle,
        fixture: &ProductionSharedCrashFixture,
    ) -> FrozenPublication {
        store
            .load_frozen_publication(fixture.canonical.publication_id)
            .await
            .expect("load production shared crash publication")
            .expect("production shared crash publication is frozen")
    }

    async fn audit_production_shared_sender_counters(
        store: &RuntimeStoreHandle,
        guard: &OwnedKeyStoreCounterGuardBackend,
    ) {
        let trust_domain = store
            .machine_trust_domain()
            .expect("audit production shared crash trust domain");
        let coordinator = SignedPublicationCoordinator::new(store, guard);
        for binding in store
            .load_active_sender_counter_bindings()
            .await
            .expect("load production shared sender inventory")
        {
            let ActiveSenderCounterBinding::SharedPublication {
                publication_stream_id,
                key_id,
            } = binding
            else {
                continue;
            };
            let scope = CounterScope::publication(trust_domain, key_id, publication_stream_id)
                .expect("derive production shared sender scope");
            coordinator
                .audit_sender_scope(scope, key_id)
                .await
                .expect("production startup reconciles shared CounterGuard scope");
        }
    }

    fn assert_real_machine_data_signature(
        class: ProductionSharedCrashClass,
        fixture: &ProductionSharedCrashFixture,
        publication: &FrozenPublication,
    ) {
        assert_real_machine_data_signature_for_axes(
            class,
            fixture,
            &publication.blob,
            publication.stream_route,
            publication.generation,
            publication.stream_seq,
        );
    }

    fn assert_real_machine_data_signature_for_axes(
        class: ProductionSharedCrashClass,
        fixture: &ProductionSharedCrashFixture,
        blob: &[u8],
        stream_route: [u8; 16],
        generation: [u8; 16],
        stream_seq: u64,
    ) -> u64 {
        let signed = SignedSealedBlobV1::from_wire_bytes(blob)
            .expect("decode production MachineData signed blob");
        assert_eq!(signed.inner.key_id.purpose, class.expected_key_purpose());
        let sender_counter = u64::from_be_bytes(
            signed.inner.nonce[4..]
                .try_into()
                .expect("MachineData nonce has a fixed counter suffix"),
        );
        let context = OuterContextV1 {
            frame_kind: class.expected_frame_kind(),
            relay_protocol_version: RELAY_PROTOCOL_VERSION,
            e2ee_format_version: E2EE_FORMAT_VERSION,
            machine_route: Some(fixture.machine_route),
            device_route: None,
            stream_route: Some(StreamRouteId::from_bytes(stream_route)),
            request_route: None,
            pair_route: None,
            stream_generation: Some(StreamGenerationId::from_bytes(generation)),
            stream_cursor: None,
            stream_seq: Some(stream_seq),
            message_key_epoch: signed.inner.key_id.epoch,
        };
        let verifying_key = VerifyingKey::from_bytes(&fixture.binding.data_sign_public_key)
            .expect("production MachineData verifying key");
        verify_sealed(signed, &verifying_key, &context)
            .expect("production MachineData signature verifies");
        sender_counter
    }

    async fn assert_acknowledged_machine_data_blob(
        class: ProductionSharedCrashClass,
        fixture: &ProductionSharedCrashFixture,
        store: &RuntimeStoreHandle,
        blob: &[u8],
    ) -> u64 {
        let (publication_stream_id, key_id) = store
            .load_active_sender_counter_bindings()
            .await
            .expect("load acknowledged production shared sender inventory")
            .into_iter()
            .find_map(|binding| match binding {
                ActiveSenderCounterBinding::SharedPublication {
                    publication_stream_id,
                    key_id,
                } if key_id.purpose == class.expected_key_purpose() => {
                    Some((publication_stream_id, key_id))
                }
                _ => None,
            })
            .expect("acknowledged production shared sender binding");
        let stream = store
            .load_publication_stream_record(publication_stream_id)
            .await
            .expect("load acknowledged production shared stream");
        let stream_seq = stream
            .acknowledged_high_water
            .expect("acknowledged publication has an outer high-water");
        assert_eq!(stream.committed_high_water, Some(stream_seq));
        assert_eq!(
            stream.last_acknowledged_publication_id,
            Some(fixture.canonical.publication_id)
        );
        assert_eq!(stream.last_acknowledged_blob_hash, Some(sha256(blob)));
        assert_eq!(stream.last_committed_blob_hash, Some(sha256(blob)));
        let sender_counter = assert_real_machine_data_signature_for_axes(
            class,
            fixture,
            blob,
            stream.stream_route,
            stream.generation,
            stream_seq,
        );
        let counter = store
            .load_remote_counter_record(
                stream
                    .counter_scope_token
                    .expect("acknowledged shared stream keeps its counter scope"),
                key_id,
            )
            .await
            .expect("load acknowledged shared counter record");
        assert!(counter.reserved_end > sender_counter);
        sender_counter
    }

    #[derive(Clone)]
    struct StoredPublication {
        request: CanonicalSharedPublication,
        target: ExactSharedPublicationTarget,
        blob: Vec<u8>,
    }

    struct FakeState {
        stored: HashMap<[u8; 16], StoredPublication>,
        acknowledged: HashSet<[u8; 16]>,
        committed: HashSet<[u8; 16]>,
        freeze_calls: usize,
        seal_calls: usize,
        drive_rounds: usize,
        commit_after_round: usize,
        purpose_override: Option<KeyPurpose>,
    }

    impl FakeState {
        fn new(commit_after_round: usize) -> Self {
            Self {
                stored: HashMap::new(),
                acknowledged: HashSet::new(),
                committed: HashSet::new(),
                freeze_calls: 0,
                seal_calls: 0,
                drive_rounds: 0,
                commit_after_round,
                purpose_override: None,
            }
        }
    }

    struct FakeBackend {
        state: Arc<Mutex<FakeState>>,
    }

    #[async_trait]
    impl SharedPublicationBackend for FakeBackend {
        async fn freeze_canonical(
            &self,
            request: CanonicalSharedPublication,
            sealer: Box<dyn TransactionSharedPublicationSealer>,
        ) -> Result<SharedFreezeOutcome, SharedPublisherError> {
            let mut state = self.state.lock().expect("fake backend state");
            state.freeze_calls += 1;
            if state.acknowledged.contains(&request.publication_id) {
                return Ok(SharedFreezeOutcome::AlreadyHandled);
            }
            if let Some(existing) = state.stored.get(&request.publication_id) {
                assert_eq!(&existing.request, &request, "stable request must be exact");
                return Ok(SharedFreezeOutcome::Frozen(existing.target));
            }
            let expected_purpose = match request.scope {
                PublicationScope::Catalog => KeyPurpose::Catalog,
                PublicationScope::Conversation(_) => KeyPurpose::ConversationDek,
            };
            let purpose = state.purpose_override.unwrap_or(expected_purpose);
            let publication_stream_id = match request.scope {
                PublicationScope::Catalog => [0x31; 16],
                PublicationScope::Conversation(_) => [0x32; 16],
            };
            let blob = sealer.seal_once(TransactionSharedPublicationAxes {
                publication_stream_id,
                stream_route: StreamRouteId::from_bytes([0x33; 16]),
                generation: StreamGenerationId::from_bytes([0x34; 16]),
                stream_seq: 7,
                key_directory_revision: 9,
                key_id: KeyId { purpose, epoch: 4 },
                sender_counter: 1_024,
                key: SecretAeadKey::from_bytes([0x35; 32]),
            })?;
            state.seal_calls += 1;
            let target = ExactSharedPublicationTarget {
                publication_id: request.publication_id,
                publication_stream_id,
                generation: [0x34; 16],
                stream_seq: 7,
                blob_sha256: sha256(&blob),
            };
            state.stored.insert(
                request.publication_id,
                StoredPublication {
                    request,
                    target,
                    blob,
                },
            );
            Ok(SharedFreezeOutcome::Frozen(target))
        }

        async fn exact_commit_status(
            &self,
            target: ExactSharedPublicationTarget,
        ) -> Result<ExactCommitStatus, SharedPublisherError> {
            let state = self.state.lock().expect("fake backend state");
            let stored = state
                .stored
                .get(&target.publication_id)
                .ok_or(SharedPublisherError::BackendRejected)?;
            if stored.target != target {
                return Err(SharedPublisherError::BackendRejected);
            }
            Ok(if state.committed.contains(&target.publication_id) {
                ExactCommitStatus::Committed
            } else {
                ExactCommitStatus::Pending
            })
        }

        async fn exact_delivery_status(
            &self,
            target: ExactSharedPublicationTarget,
        ) -> Result<ExactDeliveryStatus, SharedPublisherError> {
            let state = self.state.lock().expect("fake backend state");
            let stored = state
                .stored
                .get(&target.publication_id)
                .ok_or(SharedPublisherError::BackendRejected)?;
            if stored.target != target {
                return Err(SharedPublisherError::BackendRejected);
            }
            Ok(if state.acknowledged.contains(&target.publication_id) {
                ExactDeliveryStatus::Acknowledged
            } else {
                ExactDeliveryStatus::Pending
            })
        }
    }

    struct FakeDrive {
        state: Arc<Mutex<FakeState>>,
        gate: Option<Arc<Notify>>,
    }

    #[async_trait]
    impl SharedPublicationDrive for FakeDrive {
        async fn notify_frozen_stream(
            &self,
            publication_stream_id: [u8; 16],
        ) -> Result<(), SharedPublisherError> {
            if publication_stream_id == [0; 16] {
                return Err(SharedPublisherError::DriveUnavailable);
            }
            Ok(())
        }

        async fn drive_round(&self) -> Result<PublicationDriveReport, SharedPublisherError> {
            if let Some(gate) = &self.gate {
                gate.notified().await;
            }
            let mut state = self.state.lock().expect("fake drive state");
            state.drive_rounds += 1;
            let mut report = PublicationDriveReport {
                loaded: 1,
                ..PublicationDriveReport::default()
            };
            if state.drive_rounds >= state.commit_after_round {
                let ids = state.stored.keys().copied().collect::<Vec<_>>();
                state.committed.extend(ids.iter().copied());
                state.acknowledged.extend(ids);
                report.committed = 1;
            }
            Ok(report)
        }

        async fn notify_reconnected(&self) -> Result<(), SharedPublisherError> {
            Ok(())
        }
    }

    struct FakeSigner {
        calls: AtomicUsize,
    }

    impl FakeSigner {
        fn new() -> Self {
            Self {
                calls: AtomicUsize::new(0),
            }
        }
    }

    impl SharedPublicationSigner for FakeSigner {
        fn sign_sealed(
            &self,
            unsigned: UnsignedSealedBlobV1,
            _context: &OuterContextV1,
        ) -> Result<SignedSealedBlobV1, SharedPublisherError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(unsigned.attach_signature(Ed25519Signature([0x71; 64])))
        }
    }

    struct ContextRecordingSigner {
        context: Mutex<Option<OuterContextV1>>,
    }

    impl SharedPublicationSigner for ContextRecordingSigner {
        fn sign_sealed(
            &self,
            unsigned: UnsignedSealedBlobV1,
            context: &OuterContextV1,
        ) -> Result<SignedSealedBlobV1, SharedPublisherError> {
            *self.context.lock().expect("recording signer context") = Some(context.clone());
            Ok(unsigned.attach_signature(Ed25519Signature([0x72; 64])))
        }
    }

    fn publisher(
        state: Arc<Mutex<FakeState>>,
        gate: Option<Arc<Notify>>,
        signer: Arc<FakeSigner>,
    ) -> SharedStreamPublisher {
        SharedStreamPublisher::new(
            MachineRouteId::from_bytes([0x21; 16]),
            Arc::new(FakeBackend {
                state: Arc::clone(&state),
            }),
            Arc::new(FakeDrive { state, gate }),
            signer,
        )
        .expect("valid shared publisher")
    }

    #[derive(Clone, Copy)]
    enum FakeRotationOutcome {
        Covered,
        SnapshotMissing,
        PendingOutbox,
    }

    struct FakeRotationStore {
        rotation: RotatePublicationStreamRequest,
        outcome: FakeRotationOutcome,
        preflights: Mutex<Vec<SharedPublicationPreflightRequest>>,
        rotations: AtomicUsize,
    }

    impl FakeRotationStore {
        fn new(outcome: FakeRotationOutcome) -> Self {
            Self {
                rotation: RotatePublicationStreamRequest {
                    publication_stream_id: [0x41; 16],
                    expected_generation: [0x42; 16],
                },
                outcome,
                preflights: Mutex::new(Vec::new()),
                rotations: AtomicUsize::new(0),
            }
        }
    }

    #[async_trait]
    impl SharedPublicationRotationStore for FakeRotationStore {
        async fn preflight(
            &self,
            request: SharedPublicationPreflightRequest,
            _proposal: SharedPublicationStreamProposal,
        ) -> Result<SharedPublicationPreflight, RuntimeStoreError> {
            let mut calls = self.preflights.lock().expect("rotation preflight calls");
            calls.push(request);
            if calls.len() == 1 {
                Ok(SharedPublicationPreflight::RotationRequired(self.rotation))
            } else {
                Ok(SharedPublicationPreflight::Fresh {
                    publication_stream_id: self.rotation.publication_stream_id,
                    generation: [0x43; 16],
                    key_directory_revision: 7,
                    key_id: KeyId {
                        purpose: KeyPurpose::Catalog,
                        epoch: 3,
                    },
                })
            }
        }

        async fn rotate(
            &self,
            request: RotatePublicationStreamRequest,
        ) -> Result<PublicationStreamRecord, RuntimeStoreError> {
            self.rotations.fetch_add(1, Ordering::SeqCst);
            assert_eq!(
                request, self.rotation,
                "rotation identity must remain exact"
            );
            match self.outcome {
                FakeRotationOutcome::SnapshotMissing => {
                    return Err(RuntimeStoreError::PublicationNeedsSnapshot);
                }
                FakeRotationOutcome::PendingOutbox => {
                    return Err(RuntimeStoreError::PublicationMismatch);
                }
                FakeRotationOutcome::Covered => {}
            }
            Ok(PublicationStreamRecord {
                publication_stream_id: request.publication_stream_id,
                scope: PublicationScope::Catalog,
                stream_route: [0x44; 16],
                generation: [0x43; 16],
                counter_scope_token: Some([0x45; 32]),
                sender_counter_high_water: Some(1_024),
                reserved_high_water: None,
                committed_high_water: None,
                committed_inner_cursor: None,
                last_committed_blob_hash: None,
                acknowledged_high_water: None,
                acknowledged_inner_cursor: None,
                last_acknowledged_blob_hash: None,
                last_acknowledged_publication_id: Some([0x46; 16]),
                last_acknowledged_request_digest: Some([0x47; 32]),
                last_rotation_request_digest: Some([0x48; 32]),
                rotation_serial: 1,
                state: PublicationStreamState::Active,
                created_at_ms: 1,
                updated_at_ms: 2,
            })
        }
    }

    fn runtime_bytes(message_id: &str, item: RuntimeStreamItem) -> Arc<[u8]> {
        Arc::from(
            RuntimeEnvelope {
                version: RUNTIME_PROTOCOL_VERSION,
                message_id: MessageId::new(message_id),
                body: RuntimeMessage::Stream(item),
            }
            .to_json_bytes_checked()
            .expect("valid Runtime stream envelope"),
        )
    }

    fn catalog(revision: u64) -> RuntimeStreamItem {
        RuntimeStreamItem::CatalogDelta(CatalogDelta {
            catalog_revision: revision,
            changes: Vec::new(),
        })
    }

    fn preflight_request(
        canonical: &CanonicalSharedPublication,
    ) -> SharedPublicationPreflightRequest {
        SharedPublicationPreflightRequest {
            publication_id: canonical.publication_id,
            scope: canonical.scope,
            inner_after: canonical.inner_after,
            inner_through: canonical.inner_through,
            payload_kind: canonical.payload_kind,
            journal_identity: canonical.journal_identity,
            canonical_item_bytes: canonical.canonical_item_bytes.as_ref().to_vec(),
        }
    }

    #[tokio::test]
    async fn production_preflight_rotates_once_with_the_same_canonical_request() {
        let canonical = CanonicalSharedPublication::parse(runtime_bytes("rotation", catalog(7)))
            .expect("canonical rotation request");
        let request = preflight_request(&canonical);
        let proposal = SharedPublicationStreamProposal {
            publication_stream_id: [0x51; 16],
            stream_route: [0x52; 16],
            generation: [0x53; 16],
        };
        let store = FakeRotationStore::new(FakeRotationOutcome::Covered);

        let ready = preflight_with_generation_rotation(&store, request.clone(), proposal)
            .await
            .expect("covered generation rotates before freeze");
        let SharedPublicationPreflight::Fresh {
            publication_stream_id,
            generation,
            ..
        } = ready
        else {
            panic!("covered rotation must return a fresh generation: {ready:?}");
        };
        assert_eq!(publication_stream_id, [0x41; 16]);
        assert_eq!(generation, [0x43; 16]);
        assert_eq!(store.rotations.load(Ordering::SeqCst), 1);
        assert_eq!(
            store
                .preflights
                .lock()
                .expect("preflight history")
                .as_slice(),
            &[request.clone(), request],
            "rotation must retry the byte-exact canonical Store request"
        );
    }

    #[tokio::test]
    async fn generation_rotation_fails_typed_before_any_freeze_when_snapshot_or_ack_is_missing() {
        let canonical = CanonicalSharedPublication::parse(runtime_bytes("blocked", catalog(8)))
            .expect("canonical blocked rotation request");
        let request = preflight_request(&canonical);
        let proposal = SharedPublicationStreamProposal {
            publication_stream_id: [0x54; 16],
            stream_route: [0x55; 16],
            generation: [0x56; 16],
        };

        for (outcome, expected) in [
            (
                FakeRotationOutcome::SnapshotMissing,
                SharedPublisherError::SnapshotRequired,
            ),
            (
                FakeRotationOutcome::PendingOutbox,
                SharedPublisherError::GenerationRotationBlocked,
            ),
        ] {
            let store = FakeRotationStore::new(outcome);
            assert_eq!(
                preflight_with_generation_rotation(&store, request.clone(), proposal).await,
                Err(expected)
            );
            assert_eq!(store.rotations.load(Ordering::SeqCst), 1);
            assert_eq!(
                store.preflights.lock().expect("blocked preflight").len(),
                1,
                "failure must return before a second preflight or transaction sealer"
            );
        }
        assert_eq!(
            SharedPublisherError::SnapshotRequired.code(),
            "daemon.remote.publisher.snapshot_required"
        );
        assert_eq!(
            SharedPublisherError::GenerationRotationBlocked.code(),
            "daemon.remote.publisher.rotation_blocked"
        );
    }

    fn conversation_event(seq: u64) -> RuntimeStreamItem {
        RuntimeStreamItem::Event(
            RuntimeEvent::new(
                ConversationId::new(CONVERSATION),
                EventId::new(format!("66666666-7777-4888-8999-{seq:012}")),
                seq,
                Some(CommandId::new("command-1")),
                None,
                None,
                RuntimeEventBody::TurnInterrupted {
                    turn_id: TurnId::new("turn-1"),
                },
            )
            .expect("valid canonical event"),
        )
    }

    #[tokio::test]
    async fn random_envelope_message_id_does_not_change_publication_identity_or_blob() {
        let state = Arc::new(Mutex::new(FakeState::new(1)));
        let signer = Arc::new(FakeSigner::new());
        let publisher = publisher(Arc::clone(&state), None, Arc::clone(&signer));

        publisher
            .publish_runtime_bytes(runtime_bytes("connection-a-random", catalog(17)))
            .await
            .expect("first publish commits");
        publisher
            .publish_runtime_bytes(runtime_bytes("connection-b-random", catalog(17)))
            .await
            .expect("second connection reuses committed publication");

        let state = state.lock().expect("read fake state");
        assert_eq!(state.freeze_calls, 2);
        assert_eq!(state.seal_calls, 1, "exact retry must not reseal");
        assert_eq!(state.stored.len(), 1);
        assert_eq!(signer.calls.load(Ordering::SeqCst), 1);
        let stored = state.stored.values().next().expect("one stored row");
        let canonical: RuntimeEnvelope =
            serde_json::from_slice(stored.request.canonical_runtime_bytes.as_ref())
                .expect("decode canonical envelope");
        assert!(
            canonical
                .message_id
                .as_str()
                .starts_with(STABLE_MESSAGE_ID_PREFIX)
        );
        assert_ne!(canonical.message_id.as_str(), "connection-a-random");
        assert!(!stored.blob.is_empty());
    }

    #[tokio::test]
    async fn publication_aad_is_reconstructable_from_relay_visible_outer_axes() {
        let state = Arc::new(Mutex::new(FakeState::new(1)));
        let signer = Arc::new(ContextRecordingSigner {
            context: Mutex::new(None),
        });
        let publisher = SharedStreamPublisher::new(
            MachineRouteId::from_bytes([0x21; 16]),
            Arc::new(FakeBackend {
                state: Arc::clone(&state),
            }),
            Arc::new(FakeDrive { state, gate: None }),
            signer.clone(),
        )
        .expect("valid shared publisher");

        publisher
            .publish_runtime_bytes(runtime_bytes("outer-context", catalog(18)))
            .await
            .expect("catalog publication commits");
        let context = signer
            .context
            .lock()
            .expect("read recording signer context")
            .clone()
            .expect("publication was signed");
        assert_eq!(context.stream_seq, Some(7));
        assert_eq!(context.stream_cursor, None);
    }

    #[test]
    fn conversation_event_identity_binds_conversation_event_id_seq_and_canonical_bytes() {
        let first =
            CanonicalSharedPublication::parse(runtime_bytes("random-a", conversation_event(3)))
                .expect("canonicalize event");
        let repeated =
            CanonicalSharedPublication::parse(runtime_bytes("random-b", conversation_event(3)))
                .expect("canonicalize repeated event");
        let next =
            CanonicalSharedPublication::parse(runtime_bytes("random-c", conversation_event(4)))
                .expect("canonicalize next event");

        assert_eq!(first.publication_id, repeated.publication_id);
        assert_eq!(
            first.canonical_runtime_bytes,
            repeated.canonical_runtime_bytes
        );
        assert_ne!(first.publication_id, next.publication_id);
        assert_eq!(first.inner_after, Some(2));
        assert_eq!(first.inner_through, Some(3));
        assert!(matches!(first.scope, PublicationScope::Conversation(_)));
    }

    #[test]
    fn compact_transfer_publication_holds_inner_cursor_until_final_and_binds_exact_part() {
        let payload = vec![0x5c; MAX_PART_BYTES + 1];
        let identity = DurableStreamTransferIdentity::from_stream_metadata(
            DurableStreamSource::Catalog {
                first_revision: 17,
                through_revision: 17,
            },
            u64::try_from(payload.len()).expect("fixture length fits u64"),
            sha256(&payload),
        )
        .expect("bounded durable stream metadata");
        let first_carrier = identity
            .carrier_for_part(&payload, 0)
            .expect("canonical first compact part");
        let final_carrier = identity
            .carrier_for_part(&payload, 1)
            .expect("canonical final compact part");
        let first = CanonicalSharedPublication::parse_transfer(first_carrier.clone())
            .expect("canonicalize non-final part");
        let final_part = CanonicalSharedPublication::parse_transfer(final_carrier)
            .expect("canonicalize final part");
        assert_eq!(first.payload_kind, PublicationPayloadKind::Control);
        assert_eq!((first.inner_after, first.inner_through), (None, None));
        assert_eq!(final_part.payload_kind, PublicationPayloadKind::Catalog);
        assert_eq!(final_part.inner_after, Some(16));
        assert_eq!(final_part.inner_through, Some(17));
        assert_ne!(first.publication_id, final_part.publication_id);

        let mut changed_raw = first_carrier;
        changed_raw.transfer.part[0] ^= 0xff;
        let changed = CanonicalSharedPublication::parse_transfer(changed_raw)
            .expect("metadata-valid changed raw part canonicalizes to a distinct request");
        assert_ne!(first.publication_id, changed.publication_id);
        assert_ne!(
            first.canonical_runtime_bytes,
            changed.canonical_runtime_bytes
        );
    }

    #[tokio::test]
    async fn compact_transfer_retry_reuses_stable_identity_and_frozen_blob_without_reseal() {
        let state = Arc::new(Mutex::new(FakeState::new(1)));
        let signer = Arc::new(FakeSigner::new());
        let publisher = publisher(Arc::clone(&state), None, Arc::clone(&signer));
        let item = catalog(23);
        let RuntimeStreamItem::CatalogDelta(delta) = &item else {
            unreachable!("catalog helper")
        };
        let payload = serde_json::to_vec(delta).expect("canonical catalog source payload");
        let identity = DurableStreamTransferIdentity::for_stream_source(
            DurableStreamSource::Catalog {
                first_revision: 23,
                through_revision: 23,
            },
            &item,
            &payload,
        )
        .expect("durable compact identity");
        let carrier = identity
            .carrier_for_part(&payload, 0)
            .expect("single compact part");

        publisher
            .publish_transfer_carrier(carrier.clone())
            .await
            .expect("first transfer publication commits");
        publisher
            .publish_transfer_carrier(carrier)
            .await
            .expect("retry reuses exact committed publication");

        let state = state.lock().expect("read transfer retry state");
        assert_eq!(state.freeze_calls, 2);
        assert_eq!(state.seal_calls, 1);
        assert_eq!(state.stored.len(), 1);
        assert_eq!(signer.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn pairing_pending_and_transfer_part_fail_close_before_backend_or_counter() {
        let state = Arc::new(Mutex::new(FakeState::new(1)));
        let signer = Arc::new(FakeSigner::new());
        let publisher = publisher(Arc::clone(&state), None, signer);
        let pending = RuntimeStreamItem::PairingPending(PendingPairing {
            pairing_id: PairingId::new("pending-1"),
            request_hash: [0x41; 32],
            device_sign_fingerprint: [0x42; 32],
            requested_at_ms: 1,
            expires_at_ms: 2,
        });
        assert_eq!(
            publisher
                .publish_runtime_bytes(runtime_bytes("pending", pending))
                .await,
            Err(SharedPublisherError::PairingPendingIsLocalOnly)
        );
        assert_eq!(
            SharedPublisherError::PairingPendingIsLocalOnly.code(),
            "daemon.remote.publisher.pairing_local_only"
        );

        let transfer = RuntimeStreamItem::TransferPart(
            TransferEnvelope::new_json(
                TransferId::new("transfer-1"),
                0,
                1,
                sha256(&[0x51]),
                1,
                vec![0x51],
            )
            .expect("valid transfer part"),
        );
        assert_eq!(
            publisher
                .publish_runtime_bytes(runtime_bytes("transfer", transfer))
                .await,
            Err(SharedPublisherError::TransferRequiresDurableAssembler)
        );
        assert_eq!(
            SharedPublisherError::TransferRequiresDurableAssembler.code(),
            "daemon.remote.publisher.transfer_assembler_required"
        );
        let state = state.lock().expect("read rejected state");
        assert_eq!(state.freeze_calls, 0);
        assert_eq!(state.seal_calls, 0);
    }

    #[tokio::test]
    async fn acknowledged_tombstone_returns_before_new_sealer_or_drive() {
        let state = Arc::new(Mutex::new(FakeState::new(1)));
        let signer = Arc::new(FakeSigner::new());
        let bytes = runtime_bytes("already-acked", catalog(21));
        let canonical = CanonicalSharedPublication::parse(Arc::clone(&bytes))
            .expect("canonical acknowledged item");
        state
            .lock()
            .expect("mark acknowledged")
            .acknowledged
            .insert(canonical.publication_id);
        let publisher = publisher(Arc::clone(&state), None, Arc::clone(&signer));

        publisher
            .publish_runtime_bytes(bytes)
            .await
            .expect("authenticated AlreadyHandled is success");
        let state = state.lock().expect("read acknowledged state");
        assert_eq!(state.freeze_calls, 1);
        assert_eq!(state.seal_calls, 0);
        assert_eq!(state.drive_rounds, 0);
        assert_eq!(signer.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn acknowledgement_linearized_after_preflight_is_already_handled_without_reseal() {
        assert_eq!(
            normalize_freeze_error(SignedPublicationError::Store(
                crate::runtime::store::RuntimeStoreError::PublicationAlreadyAcknowledged,
            )),
            Ok(SharedFreezeOutcome::AlreadyHandled)
        );
        assert_eq!(
            normalize_freeze_error(SignedPublicationError::Publication(
                PublicationError::InvalidAxes,
            )),
            Err(SharedPublisherError::BackendRejected)
        );
        assert_eq!(
            normalize_freeze_error(SignedPublicationError::Store(
                crate::runtime::store::RuntimeStoreError::PublicationNeedsSnapshot,
            )),
            Err(SharedPublisherError::SnapshotRequired),
            "first MAX-1 discovery must request a typed retry before any reseal"
        );
        assert_eq!(
            normalize_freeze_error(SignedPublicationError::RetireKey),
            Err(SharedPublisherError::CounterRetired),
            "typed counter retirement must not collapse into BackendRejected"
        );
        assert_eq!(
            remote_link_error(SharedPublisherError::CounterRetired).code(),
            "daemon.remote.counter.retired"
        );
    }

    #[tokio::test]
    async fn runtime_ack_waits_for_exact_relay_commit_and_fairly_drives_multiple_rounds() {
        let state = Arc::new(Mutex::new(FakeState::new(3)));
        let signer = Arc::new(FakeSigner::new());
        let gate = Arc::new(Notify::new());
        let publisher = Arc::new(publisher(
            Arc::clone(&state),
            Some(Arc::clone(&gate)),
            signer,
        ));
        let task = tokio::spawn({
            let publisher = Arc::clone(&publisher);
            async move {
                publisher
                    .publish_runtime_bytes(runtime_bytes("held", catalog(31)))
                    .await
            }
        });

        tokio::time::timeout(std::time::Duration::from_millis(250), async {
            loop {
                if state.lock().expect("observe freeze").seal_calls == 1 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("publisher reaches frozen state");
        assert!(
            !task.is_finished(),
            "freeze + notify must not ACK RuntimeCore"
        );
        gate.notify_one();
        tokio::task::yield_now().await;
        assert!(
            !task.is_finished(),
            "one fair round need not select the target"
        );
        gate.notify_one();
        tokio::task::yield_now().await;
        assert!(
            !task.is_finished(),
            "two fair rounds may still precede target"
        );
        gate.notify_one();
        task.await
            .expect("publisher task joins")
            .expect("third round observes exact commit");
        assert_eq!(state.lock().expect("read rounds").drive_rounds, 3);
    }

    #[tokio::test]
    async fn catalog_cannot_be_sealed_with_conversation_key() {
        let state = Arc::new(Mutex::new(FakeState::new(1)));
        state.lock().expect("override purpose").purpose_override =
            Some(KeyPurpose::ConversationDek);
        let publisher = publisher(Arc::clone(&state), None, Arc::new(FakeSigner::new()));
        assert_eq!(
            publisher
                .publish_runtime_bytes(runtime_bytes("wrong-key", catalog(41)))
                .await,
            Err(SharedPublisherError::KeyPurposeMismatch)
        );
        assert_eq!(state.lock().expect("read mismatch state").seal_calls, 0);
    }

    #[tokio::test]
    async fn production_store_backend_freezes_current_adgk2_and_reads_exact_commit_and_ack() {
        let temp = tempfile::tempdir().expect("shared backend tempdir");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700))
                .expect("secure shared backend tempdir");
        }
        let store = active_authorization_store_for_test(&temp.path().join("runtime.db")).await;
        let counter_store = MemoryKeyStore::new();
        let guard = Arc::new(KeyStoreCounterGuardBackend::new(&counter_store));
        store
            .ensure_remote_catalog_publication_after_transition()
            .await
            .expect("ensure shared backend production Catalog carrier");
        let conversation_id = RuntimeId::from_bytes(RuntimeIdKind::Conversation, [0x61; 16])
            .expect("conversation id");
        let descriptor = ConversationDescriptor {
            agent_kind: agentdeck_protocol::AgentKind::Codex,
            title: Some("shared production backend".to_owned()),
            cwd: std::path::PathBuf::from("/tmp/shared-production-backend"),
        };
        let first = store
            .create_conversation(NewConversation {
                conversation_id,
                adapter_state_key: RuntimeId::from_bytes(RuntimeIdKind::AdapterState, [0x62; 16])
                    .expect("adapter state key"),
                descriptor: descriptor.clone(),
            })
            .await
            .expect("create immutable catalog journal row");
        complete_active_zero_cut_transition_with_counter_guard(&store, guard.as_ref()).await;
        let second_conversation_id = RuntimeId::from_bytes(RuntimeIdKind::Conversation, [0x63; 16])
            .expect("second conversation id");
        let second_descriptor = ConversationDescriptor {
            agent_kind: agentdeck_protocol::AgentKind::ClaudeCode,
            title: Some("shared catalog range tail".to_owned()),
            cwd: std::path::PathBuf::from("/tmp/shared-catalog-range-tail"),
        };
        let second = store
            .create_conversation(NewConversation {
                conversation_id: second_conversation_id,
                adapter_state_key: RuntimeId::from_bytes(RuntimeIdKind::AdapterState, [0x64; 16])
                    .expect("second adapter state key"),
                descriptor: second_descriptor.clone(),
            })
            .await
            .expect("create contiguous catalog journal tail");
        complete_active_zero_cut_transition_with_counter_guard(&store, guard.as_ref()).await;
        let key_directory_revision = store
            .load_global_key_state()
            .await
            .expect("load shared publication key directory")
            .expect("active authorization owns a key directory")
            .revision()
            .value();
        assert_eq!(
            second.catalog_revision,
            first.catalog_revision + 1,
            "fixture keeps a later immutable revision while publishing the stream head"
        );
        let item = RuntimeStreamItem::CatalogDelta(CatalogDelta {
            catalog_revision: first.catalog_revision,
            changes: vec![CatalogChange::Upserted {
                entry: ConversationEntry {
                    conversation_id: ConversationId::new(conversation_id.to_canonical_string()),
                    agent_kind: descriptor.agent_kind,
                    title: descriptor.title.clone(),
                    cwd: Some(descriptor.cwd.clone()),
                    last_active_ms: first.updated_at_ms,
                    archived: false,
                    entry_revision: 0,
                },
            }],
        });
        let canonical = CanonicalSharedPublication::parse(runtime_bytes("volatile", item))
            .expect("canonical shared catalog item");
        let machine_route = MachineRouteId::from_bytes([0x71; 16]);
        let backend = RuntimeStoreSharedPublicationBackend::new(
            store.clone(),
            Arc::clone(&guard),
            machine_route,
        )
        .expect("production backend");
        let signer = Arc::new(FakeSigner::new());
        let mut forged = canonical.clone();
        let mut forged_item: RuntimeStreamItem =
            serde_json::from_slice(forged.canonical_item_bytes.as_ref())
                .expect("decode canonical item for valid forgery");
        let RuntimeStreamItem::CatalogDelta(delta) = &mut forged_item else {
            panic!("catalog fixture")
        };
        let CatalogChange::Upserted { entry } = &mut delta.changes[0] else {
            panic!("upsert fixture")
        };
        entry.title = Some("forged volatile envelope".to_owned());
        forged.canonical_item_bytes =
            Arc::from(serde_json::to_vec(&forged_item).expect("encode valid but non-journal item"));
        let forged_sealer = Box::new(SharedTransactionSealer {
            machine_route,
            request: forged.clone(),
            signer: signer.clone(),
        });
        assert_eq!(
            backend.freeze_canonical(forged, forged_sealer).await,
            Err(SharedPublisherError::BackendRejected),
            "volatile Runtime envelope cannot override immutable journal bytes"
        );
        assert_eq!(signer.calls.load(Ordering::SeqCst), 0);
        let preflight = store
            .preflight_shared_publication(
                SharedPublicationPreflightRequest {
                    publication_id: canonical.publication_id,
                    scope: canonical.scope,
                    inner_after: canonical.inner_after,
                    inner_through: canonical.inner_through,
                    payload_kind: canonical.payload_kind,
                    journal_identity: canonical.journal_identity,
                    canonical_item_bytes: canonical.canonical_item_bytes.as_ref().to_vec(),
                },
                SharedPublicationStreamProposal {
                    publication_stream_id: [0x72; 16],
                    stream_route: [0x73; 16],
                    generation: [0x74; 16],
                },
            )
            .await
            .expect("authenticated Store preflight");
        assert!(matches!(
            preflight,
            SharedPublicationPreflight::Fresh { .. }
        ));
        let freeze = |request: CanonicalSharedPublication| {
            let sealer = Box::new(SharedTransactionSealer {
                machine_route,
                request: request.clone(),
                signer: signer.clone(),
            });
            async { backend.freeze_canonical(request, sealer).await }
        };

        let target = match freeze(canonical.clone())
            .await
            .expect("freeze shared publication")
        {
            SharedFreezeOutcome::Frozen(target) => target,
            SharedFreezeOutcome::AlreadyHandled => panic!("fresh item cannot be acknowledged"),
        };
        assert_eq!(signer.calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            backend.exact_commit_status(target).await,
            Ok(ExactCommitStatus::Pending)
        );
        assert_eq!(
            backend.exact_delivery_status(target).await,
            Ok(ExactDeliveryStatus::Pending),
            "freeze alone is not an exact local ACK"
        );
        let mut wrong_target = target;
        wrong_target.blob_sha256[0] ^= 0xff;
        assert_eq!(
            backend.exact_commit_status(wrong_target).await,
            Err(SharedPublisherError::BackendRejected),
            "commit readback must bind publication/stream/generation/seq/hash"
        );
        let frozen = store
            .load_frozen_publication(target.publication_id)
            .await
            .expect("load exact frozen")
            .expect("frozen row");
        let signed = SignedSealedBlobV1::from_wire_bytes(&frozen.blob).expect("signed blob");
        assert_eq!(signed.inner.key_id.purpose, KeyPurpose::Catalog);
        assert_eq!(
            signed.inner.key_directory_revision, key_directory_revision,
            "publication must bind the post-activation authenticated directory revision"
        );
        let publication_owner = RetiredSharedKeyOwner::new(
            RetiredKeyOwnerKind::Publication,
            target.publication_id,
            KeyPurpose::Catalog,
            None,
            signed.inner.key_id.epoch,
        )
        .expect("valid publication retention owner");
        assert!(
            store
                .load_global_key_state()
                .await
                .expect("load ADGK2 after signed freeze")
                .expect("signed freeze requires ADGK2")
                .has_retention_owner_for_test(publication_owner),
            "freeze transaction must acquire the owner while the shared key is current"
        );
        store
            .acknowledge_publication_commit(
                target.publication_stream_id,
                target.generation,
                target.stream_seq,
                target.blob_sha256,
            )
            .await
            .expect("advance exact Relay committed cut");
        assert!(
            store
                .load_global_key_state()
                .await
                .expect("load ADGK2 after Relay COMMIT")
                .expect("ADGK2 remains present")
                .has_retention_owner_for_test(publication_owner),
            "Relay COMMIT is not a device delivery ACK and must retain the shared key"
        );
        assert_eq!(
            backend.exact_commit_status(target).await,
            Ok(ExactCommitStatus::Committed)
        );
        assert_eq!(
            backend.exact_delivery_status(target).await,
            Ok(ExactDeliveryStatus::Pending),
            "Relay COMMIT alone must not satisfy publisher success"
        );

        let scope = CounterScope::publication(
            store.machine_trust_domain().expect("trust domain"),
            signed.inner.key_id,
            target.publication_stream_id,
        )
        .expect("counter scope");
        assert_eq!(
            store
                .load_remote_counter_guard_cleanup_manifest()
                .await
                .expect("load authenticated publication guard manifest"),
            vec![(scope.token(), true)]
        );
        let guard_before = guard.load_guard(&scope).expect("load stable guard");
        let repeated = freeze(canonical.clone()).await.expect("exact frozen retry");
        assert_eq!(repeated, SharedFreezeOutcome::Frozen(target));
        assert_eq!(
            store
                .load_remote_counter_guard_cleanup_manifest()
                .await
                .expect("exact retry keeps one materialized manifest entry"),
            vec![(scope.token(), true)]
        );
        assert_eq!(
            signer.calls.load(Ordering::SeqCst),
            1,
            "retry must not reseal"
        );
        store
            .acknowledge_publication_delivery(
                target.publication_stream_id,
                target.generation,
                target.stream_seq,
                target.blob_sha256,
            )
            .await
            .expect("persist authenticated ACK tombstone");
        assert!(
            !store
                .load_global_key_state()
                .await
                .expect("load ADGK2 after delivery ACK")
                .expect("ADGK2 remains present")
                .has_retention_owner_for_test(publication_owner),
            "delivery ACK must atomically release the publication owner"
        );
        assert_eq!(
            backend.exact_commit_status(target).await,
            Ok(ExactCommitStatus::Committed),
            "exact COMMIT readback must survive ACK deletion of the outbox row"
        );
        assert_eq!(
            backend.exact_delivery_status(target).await,
            Ok(ExactDeliveryStatus::Acknowledged),
            "authenticated tombstone is the exact publisher success boundary"
        );
        let mut acknowledged_wrong_target = target;
        acknowledged_wrong_target.blob_sha256[0] ^= 0xff;
        assert_eq!(
            backend.exact_commit_status(acknowledged_wrong_target).await,
            Err(SharedPublisherError::BackendRejected),
            "ACK tombstone must keep binding the exact blob hash"
        );
        assert_eq!(
            freeze(canonical).await,
            Ok(SharedFreezeOutcome::AlreadyHandled)
        );
        assert_eq!(
            guard.load_guard(&scope).expect("reload guard"),
            guard_before
        );
        assert_eq!(
            signer.calls.load(Ordering::SeqCst),
            1,
            "ACK must precede seal"
        );
        store
            .shutdown()
            .await
            .expect("shutdown shared backend Store");
    }

    #[tokio::test]
    async fn production_store_transfer_rejects_gap_and_forgery_then_freezes_control_before_final_cursor()
     {
        let temp = tempfile::tempdir().expect("shared transfer backend tempdir");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700))
                .expect("secure shared transfer tempdir");
        }
        let store = active_authorization_store_for_test(&temp.path().join("runtime.db")).await;
        let counter_store = MemoryKeyStore::new();
        let guard = Arc::new(KeyStoreCounterGuardBackend::new(&counter_store));
        store
            .ensure_remote_catalog_publication_after_transition()
            .await
            .expect("ensure shared transfer production Catalog carrier");
        let mut changes = Vec::new();
        let mut first_revision = None;
        let mut through_revision = 0_u64;
        for seed in 0x81_u8..=0x84 {
            let conversation_id = RuntimeId::from_bytes(RuntimeIdKind::Conversation, [seed; 16])
                .expect("large catalog conversation id");
            let descriptor = ConversationDescriptor {
                agent_kind: agentdeck_protocol::AgentKind::Codex,
                title: Some(format!("{seed:02x}-{}", "x".repeat(900 * 1024))),
                cwd: std::path::PathBuf::from(format!("/tmp/shared-transfer-{seed:02x}")),
            };
            let created = store
                .create_conversation(NewConversation {
                    conversation_id,
                    adapter_state_key: RuntimeId::from_bytes(
                        RuntimeIdKind::AdapterState,
                        [seed.wrapping_add(0x10); 16],
                    )
                    .expect("large catalog adapter state key"),
                    descriptor: descriptor.clone(),
                })
                .await
                .expect("create large immutable catalog row");
            complete_active_zero_cut_transition_with_counter_guard(&store, guard.as_ref()).await;
            first_revision.get_or_insert(created.catalog_revision);
            through_revision = created.catalog_revision;
            changes.push(CatalogChange::Upserted {
                entry: ConversationEntry {
                    conversation_id: ConversationId::new(conversation_id.to_canonical_string()),
                    agent_kind: descriptor.agent_kind,
                    title: descriptor.title,
                    cwd: Some(descriptor.cwd),
                    last_active_ms: created.updated_at_ms,
                    archived: false,
                    entry_revision: 0,
                },
            });
        }
        let first_revision = first_revision.expect("at least one catalog revision");
        let delta = CatalogDelta {
            catalog_revision: through_revision,
            changes,
        };
        let payload = serde_json::to_vec(&delta).expect("encode multi-part catalog source");
        assert!(payload.len() > MAX_PART_BYTES);
        let identity = DurableStreamTransferIdentity::from_stream_metadata(
            DurableStreamSource::Catalog {
                first_revision,
                through_revision,
            },
            u64::try_from(payload.len()).expect("payload length fits u64"),
            sha256(&payload),
        )
        .expect("bounded durable stream metadata");
        assert_eq!(identity.part_count().expect("part count"), 2);
        let first_carrier = identity
            .carrier_for_part(&payload, 0)
            .expect("first catalog carrier");
        let final_carrier = identity
            .carrier_for_part(&payload, 1)
            .expect("final catalog carrier");
        let first = CanonicalSharedPublication::parse_transfer(first_carrier.clone())
            .expect("canonical first publication");
        let final_part = CanonicalSharedPublication::parse_transfer(final_carrier)
            .expect("canonical final publication");

        let machine_route = MachineRouteId::from_bytes([0x85; 16]);
        let backend = RuntimeStoreSharedPublicationBackend::new(
            store.clone(),
            Arc::clone(&guard),
            machine_route,
        )
        .expect("production transfer backend");
        let signer = Arc::new(FakeSigner::new());
        let freeze = |request: CanonicalSharedPublication| {
            let sealer = Box::new(SharedTransactionSealer {
                machine_route,
                request: request.clone(),
                signer: signer.clone(),
            });
            async { backend.freeze_canonical(request, sealer).await }
        };

        assert_eq!(
            freeze(final_part.clone()).await,
            Err(SharedPublisherError::BackendRejected),
            "part 1 cannot freeze before exact part 0"
        );
        assert_eq!(signer.calls.load(Ordering::SeqCst), 0);

        let first_target = match freeze(first.clone())
            .await
            .expect("freeze authenticated first part")
        {
            SharedFreezeOutcome::Frozen(target) => target,
            SharedFreezeOutcome::AlreadyHandled => panic!("fresh first part cannot be ACKed"),
        };
        let frozen_first = store
            .load_frozen_publication(first_target.publication_id)
            .await
            .expect("load first part")
            .expect("frozen first part");
        assert_eq!(frozen_first.payload_kind, PublicationPayloadKind::Control);
        assert_eq!(
            (frozen_first.inner_after, frozen_first.inner_through),
            (None, None)
        );
        assert_eq!(signer.calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            freeze(first.clone()).await,
            Ok(SharedFreezeOutcome::Frozen(first_target)),
            "exact retry must read the frozen row"
        );
        assert_eq!(signer.calls.load(Ordering::SeqCst), 1, "retry resealed");

        let mut forged_carrier = first_carrier;
        forged_carrier.transfer.part[0] ^= 0xff;
        let forged = CanonicalSharedPublication::parse_transfer(forged_carrier)
            .expect("metadata-valid forged carrier");
        assert_eq!(
            freeze(forged).await,
            Err(SharedPublisherError::BackendRejected),
            "valid ADRT1 bytes cannot override the authenticated journal slice"
        );
        assert_eq!(signer.calls.load(Ordering::SeqCst), 1);

        let final_target = match freeze(final_part.clone())
            .await
            .expect("freeze authenticated final part")
        {
            SharedFreezeOutcome::Frozen(target) => target,
            SharedFreezeOutcome::AlreadyHandled => panic!("fresh final part cannot be ACKed"),
        };
        let frozen_final = store
            .load_frozen_publication(final_target.publication_id)
            .await
            .expect("load final part")
            .expect("frozen final part");
        assert_eq!(frozen_final.payload_kind, PublicationPayloadKind::Catalog);
        assert_eq!(frozen_final.inner_after, first_revision.checked_sub(1));
        assert_eq!(frozen_final.inner_through, Some(through_revision));
        assert_eq!(signer.calls.load(Ordering::SeqCst), 2);
        assert_eq!(
            freeze(final_part).await,
            Ok(SharedFreezeOutcome::Frozen(final_target))
        );
        assert_eq!(
            signer.calls.load(Ordering::SeqCst),
            2,
            "final retry resealed"
        );
        store.shutdown().await.expect("shutdown transfer Store");
    }

    #[tokio::test]
    async fn production_signed_catalog_and_event_restart_after_reserve_before_seal_once() {
        for class in [
            ProductionSharedCrashClass::Catalog,
            ProductionSharedCrashClass::ConversationEvent,
        ] {
            let fixture = production_shared_crash_fixture(class, "pre-seal").await;
            let first_counter = Arc::new(AtomicU64::new(u64::MAX));
            let backend = fixture.backend(&fixture.store);
            assert_eq!(
                backend
                    .freeze_canonical(
                        fixture.canonical.clone(),
                        Box::new(CrashBeforeMachineDataSeal {
                            sender_counter: first_counter.clone(),
                        }),
                    )
                    .await,
                Err(SharedPublisherError::BackendRejected),
                "{} reserve 后、MachineData seal 前退出必须回滚 DB freeze",
                class.label()
            );
            let abandoned_counter = first_counter.load(Ordering::SeqCst);
            assert_ne!(abandoned_counter, u64::MAX);
            assert!(
                fixture
                    .store
                    .load_frozen_publication(fixture.canonical.publication_id)
                    .await
                    .expect("read pre-seal rollback")
                    .is_none(),
                "{} pre-seal cut 不能留下伪 frozen blob",
                class.label()
            );
            fixture
                .store
                .clone()
                .shutdown()
                .await
                .expect("shutdown pre-seal production Store");

            let reopened = fixture.reopen().await;
            let startup_guard = fixture.counter_guard();
            audit_production_shared_sender_counters(&reopened, startup_guard.as_ref()).await;
            let transport = Arc::new(RecordingPublicationTransport::new(
                RecordingRelayPlan::Commit,
            ));
            let owner = open_owner_with_transport_for_test(reopened.clone(), transport.clone())
                .await
                .expect("open pre-seal recovery publication owner");
            let signing_calls = Arc::new(AtomicUsize::new(0));
            let (signer, _authority_lease) =
                counting_machine_data_signer(&fixture, signing_calls.clone());
            let publisher =
                production_shared_publisher(&fixture, &reopened, owner.handle(), signer);
            publisher
                .publish_runtime_bytes(fixture.runtime_bytes.clone())
                .await
                .expect("restart seals and commits the canonical publication");
            assert_eq!(
                signing_calls.load(Ordering::SeqCst),
                1,
                "{} restart 后只能执行唯一一次真实 MachineData seal",
                class.label()
            );
            let sent = transport.sent_blobs();
            assert_eq!(sent.len(), 1);
            let sender_counter =
                assert_acknowledged_machine_data_blob(class, &fixture, &reopened, &sent[0]).await;
            assert!(
                sender_counter
                    >= abandoned_counter
                        .checked_add(COUNTER_BLOCK_SIZE)
                        .expect("abandoned CounterGuard block has a successor"),
                "{} restart 必须跳过 crash 前 Pending block",
                class.label()
            );
            assert!(
                reopened
                    .load_frozen_publication(fixture.canonical.publication_id)
                    .await
                    .expect("read acknowledged pre-seal retry")
                    .is_none(),
                "{} successful local ACK must remove the frozen outbox row",
                class.label()
            );

            drop(publisher);
            owner
                .shutdown()
                .await
                .expect("shutdown pre-seal recovery publication owner");
            reopened
                .shutdown()
                .await
                .expect("shutdown pre-seal recovered Store");
        }
    }

    #[tokio::test]
    async fn production_signed_catalog_and_event_computed_seal_before_freeze_commit_is_ephemeral() {
        for class in [
            ProductionSharedCrashClass::Catalog,
            ProductionSharedCrashClass::ConversationEvent,
        ] {
            let fixture = production_shared_crash_fixture(class, "computed-pre-commit").await;
            fixture
                .store
                .clone()
                .shutdown()
                .await
                .expect("shutdown setup Store before installing freeze fault");
            let faulted = fixture
                .reopen_with_config(
                    RuntimeStoreConfig::new(fixture.database.clone())
                        .with_clock(ProductionCrashClock)
                        .with_fault_injector(Arc::new(ProductionSharedCrashOnce::new(
                            RuntimeStoreOperation::FreezePublicationBeforeCommit,
                        ))),
                )
                .await;
            let first_transport = Arc::new(RecordingPublicationTransport::new(
                RecordingRelayPlan::Commit,
            ));
            let first_owner =
                open_owner_with_transport_for_test(faulted.clone(), first_transport.clone())
                    .await
                    .expect("open computed pre-COMMIT publication owner");
            let signing_calls = Arc::new(AtomicUsize::new(0));
            let signed_blobs = Arc::new(Mutex::new(Vec::new()));
            let (first_signer, _first_authority_lease) = recording_machine_data_signer(
                &fixture,
                signing_calls.clone(),
                signed_blobs.clone(),
            );
            let first_publisher =
                production_shared_publisher(&fixture, &faulted, first_owner.handle(), first_signer);
            assert_eq!(
                first_publisher
                    .publish_runtime_bytes(fixture.runtime_bytes.clone())
                    .await,
                Err(SharedPublisherError::BackendRejected),
                "{} seal 已计算但 freeze transaction 未 COMMIT 时不形成 durable publication",
                class.label()
            );
            assert_eq!(signing_calls.load(Ordering::SeqCst), 1);
            let first_blob = signed_blobs
                .lock()
                .expect("read computed pre-COMMIT signed blob")[0]
                .clone();
            let first_nonce = SignedSealedBlobV1::from_wire_bytes(&first_blob)
                .expect("decode computed pre-COMMIT signed blob")
                .inner
                .nonce;
            let first_counter = u64::from_be_bytes(
                first_nonce[4..]
                    .try_into()
                    .expect("MachineData nonce has a fixed counter suffix"),
            );
            assert!(
                faulted
                    .load_frozen_publication(fixture.canonical.publication_id)
                    .await
                    .expect("read rolled-back computed publication")
                    .is_none(),
                "{} 未 COMMIT transaction 不能留下 frozen row",
                class.label()
            );
            assert!(first_transport.sent_blobs().is_empty());

            drop(first_publisher);
            first_owner
                .shutdown()
                .await
                .expect("shutdown computed pre-COMMIT publication owner");
            faulted
                .shutdown()
                .await
                .expect("shutdown computed pre-COMMIT Store");

            let reopened = fixture.reopen().await;
            let startup_guard = fixture.counter_guard();
            audit_production_shared_sender_counters(&reopened, startup_guard.as_ref()).await;
            let retry_transport = Arc::new(RecordingPublicationTransport::new(
                RecordingRelayPlan::Commit,
            ));
            let retry_owner =
                open_owner_with_transport_for_test(reopened.clone(), retry_transport.clone())
                    .await
                    .expect("open computed pre-COMMIT retry owner");
            let (retry_signer, _retry_authority_lease) = recording_machine_data_signer(
                &fixture,
                signing_calls.clone(),
                signed_blobs.clone(),
            );
            let retry_publisher = production_shared_publisher(
                &fixture,
                &reopened,
                retry_owner.handle(),
                retry_signer,
            );
            retry_publisher
                .publish_runtime_bytes(fixture.runtime_bytes.clone())
                .await
                .expect("restart skips abandoned block and creates the durable publication");
            assert_eq!(
                signing_calls.load(Ordering::SeqCst),
                2,
                "{} pre-COMMIT computed seal 可在新 counter block 重新计算一次",
                class.label()
            );
            let recorded = signed_blobs
                .lock()
                .expect("read production computed and durable blobs")
                .clone();
            assert_eq!(recorded.len(), 2);
            assert_ne!(
                recorded[0],
                recorded[1],
                "{} 新 counter block 必须产生不同 signed blob",
                class.label()
            );
            assert_eq!(retry_transport.sent_blobs(), vec![recorded[1].clone()]);
            let sender_counter =
                assert_acknowledged_machine_data_blob(class, &fixture, &reopened, &recorded[1])
                    .await;
            assert!(
                sender_counter
                    >= first_counter
                        .checked_add(COUNTER_BLOCK_SIZE)
                        .expect("computed pre-COMMIT block has a successor"),
                "{} restart 必须整体跳过未 COMMIT publication 的 counter block",
                class.label()
            );
            assert!(
                reopened
                    .load_frozen_publication(fixture.canonical.publication_id)
                    .await
                    .expect("read acknowledged computed retry")
                    .is_none()
            );

            drop(retry_publisher);
            retry_owner
                .shutdown()
                .await
                .expect("shutdown computed pre-COMMIT retry owner");
            reopened
                .shutdown()
                .await
                .expect("shutdown computed pre-COMMIT recovered Store");
        }
    }

    #[tokio::test]
    async fn production_signed_catalog_and_event_unknown_restarts_with_exact_blob_without_reseal() {
        for class in [
            ProductionSharedCrashClass::Catalog,
            ProductionSharedCrashClass::ConversationEvent,
        ] {
            let fixture = production_shared_crash_fixture(class, "relay-unknown").await;
            let signing_calls = Arc::new(AtomicUsize::new(0));
            let first_transport = Arc::new(RecordingPublicationTransport::new(
                RecordingRelayPlan::OutcomeUnknown,
            ));
            let first_owner =
                open_owner_with_transport_for_test(fixture.store.clone(), first_transport.clone())
                    .await
                    .expect("open unknown-outcome publication owner");
            let (first_signer, _first_authority_lease) =
                counting_machine_data_signer(&fixture, signing_calls.clone());
            let first_publisher = production_shared_publisher(
                &fixture,
                &fixture.store,
                first_owner.handle(),
                first_signer,
            );
            assert_eq!(
                first_publisher
                    .publish_runtime_bytes(fixture.runtime_bytes.clone())
                    .await,
                Err(SharedPublisherError::CommitOutcomeUnknown),
                "{} Relay 结果 unknown 不能冒充 COMMIT",
                class.label()
            );
            assert_eq!(signing_calls.load(Ordering::SeqCst), 1);
            let frozen_before = exact_frozen_blob(&fixture.store, &fixture).await;
            assert_real_machine_data_signature(class, &fixture, &frozen_before);
            assert_eq!(
                first_transport.sent_blobs(),
                vec![frozen_before.blob.clone()]
            );

            drop(first_publisher);
            first_owner
                .shutdown()
                .await
                .expect("shutdown unknown-outcome publication owner");
            fixture
                .store
                .clone()
                .shutdown()
                .await
                .expect("shutdown unknown-outcome Store");

            let reopened = fixture.reopen().await;
            let retry_transport = Arc::new(RecordingPublicationTransport::new(
                RecordingRelayPlan::Commit,
            ));
            let retry_owner =
                open_owner_with_transport_for_test(reopened.clone(), retry_transport.clone())
                    .await
                    .expect("open unknown-outcome retry owner");
            let (retry_signer, _retry_authority_lease) =
                counting_machine_data_signer(&fixture, signing_calls.clone());
            let retry_publisher = production_shared_publisher(
                &fixture,
                &reopened,
                retry_owner.handle(),
                retry_signer,
            );
            retry_publisher
                .publish_runtime_bytes(fixture.runtime_bytes.clone())
                .await
                .expect("unknown Relay result retries exact frozen publication");
            assert_eq!(
                signing_calls.load(Ordering::SeqCst),
                1,
                "{} outcome-unknown restart 不得重新 seal",
                class.label()
            );
            assert_eq!(
                retry_transport.sent_blobs(),
                vec![frozen_before.blob.clone()],
                "{} retry 必须逐字复用第一次发送的 signed blob",
                class.label()
            );
            assert_acknowledged_machine_data_blob(class, &fixture, &reopened, &frozen_before.blob)
                .await;
            assert!(
                reopened
                    .load_frozen_publication(fixture.canonical.publication_id)
                    .await
                    .expect("read acknowledged outcome-unknown retry")
                    .is_none()
            );

            drop(retry_publisher);
            retry_owner
                .shutdown()
                .await
                .expect("shutdown unknown-outcome retry owner");
            reopened
                .shutdown()
                .await
                .expect("shutdown unknown-outcome recovered Store");
        }
    }

    #[tokio::test]
    async fn production_signed_catalog_and_event_ack_crash_windows_finish_without_reseal_or_resend()
    {
        for class in [
            ProductionSharedCrashClass::Catalog,
            ProductionSharedCrashClass::ConversationEvent,
        ] {
            for operation in [
                RuntimeStoreOperation::AcknowledgePublicationBeforeCommit,
                RuntimeStoreOperation::AcknowledgePublicationAfterCommit,
            ] {
                let cut = match operation {
                    RuntimeStoreOperation::AcknowledgePublicationBeforeCommit => {
                        "post-relay-commit-pre-local-ack"
                    }
                    RuntimeStoreOperation::AcknowledgePublicationAfterCommit => {
                        "post-local-ack-result-unknown"
                    }
                    _ => unreachable!(),
                };
                let fixture = production_shared_crash_fixture(class, cut).await;
                fixture
                    .store
                    .clone()
                    .shutdown()
                    .await
                    .expect("shutdown ACK crash setup Store");
                let faulted = fixture
                    .reopen_with_config(
                        RuntimeStoreConfig::new(fixture.database.clone())
                            .with_clock(ProductionCrashClock)
                            .with_fault_injector(Arc::new(ProductionSharedCrashOnce::new(
                                operation,
                            ))),
                    )
                    .await;
                let signing_calls = Arc::new(AtomicUsize::new(0));
                let backend = fixture.backend(&faulted);
                let (first_signer, _first_authority_lease) =
                    counting_machine_data_signer(&fixture, signing_calls.clone());
                let target = match backend
                    .freeze_canonical(
                        fixture.canonical.clone(),
                        Box::new(SharedTransactionSealer {
                            machine_route: fixture.machine_route,
                            request: fixture.canonical.clone(),
                            signer: first_signer,
                        }),
                    )
                    .await
                    .expect("freeze exact ACK crash publication")
                {
                    SharedFreezeOutcome::Frozen(target) => target,
                    SharedFreezeOutcome::AlreadyHandled => {
                        panic!("fresh ACK crash publication cannot already be acknowledged")
                    }
                };
                let frozen_before_drive = exact_frozen_blob(&faulted, &fixture).await;
                assert_real_machine_data_signature(class, &fixture, &frozen_before_drive);
                assert_eq!(signing_calls.load(Ordering::SeqCst), 1);

                let first_transport = Arc::new(RecordingPublicationTransport::new(
                    RecordingRelayPlan::Commit,
                ));
                let first_owner =
                    open_owner_with_transport_for_test(faulted.clone(), first_transport.clone())
                        .await
                        .expect("open ACK crash publication owner");
                let first_drive_result = first_owner.handle().drive_round().await;
                let first_sent = first_transport.sent_blobs();
                assert_eq!(first_sent.len(), 1);
                assert_eq!(first_sent[0], frozen_before_drive.blob);

                match operation {
                    RuntimeStoreOperation::AcknowledgePublicationBeforeCommit => {
                        assert!(
                            first_drive_result.is_err(),
                            "{} {cut} must stop after the rolled-back local ACK",
                            class.label()
                        );
                        let frozen = exact_frozen_blob(&faulted, &fixture).await;
                        assert_eq!(frozen.blob, first_sent[0]);
                        assert_eq!(
                            backend.exact_commit_status(target).await,
                            Ok(ExactCommitStatus::Committed),
                            "Relay COMMIT must survive the rolled-back local ACK"
                        );
                        assert_eq!(
                            backend.exact_delivery_status(target).await,
                            Ok(ExactDeliveryStatus::Pending),
                            "rolled-back local ACK must retain the exact frozen row"
                        );
                    }
                    RuntimeStoreOperation::AcknowledgePublicationAfterCommit => {
                        let report = first_drive_result
                            .expect("post-COMMIT local ACK uncertainty remains retryable");
                        assert_eq!(report.committed, 0);
                        assert_eq!(report.commit_pending, 1);
                        assert!(
                            faulted
                                .load_frozen_publication(fixture.canonical.publication_id)
                                .await
                                .expect("read post-ACK unknown outbox")
                                .is_none()
                        );
                        assert_acknowledged_machine_data_blob(
                            class,
                            &fixture,
                            &faulted,
                            &first_sent[0],
                        )
                        .await;
                        assert_eq!(
                            backend.exact_delivery_status(target).await,
                            Ok(ExactDeliveryStatus::Acknowledged),
                            "durable local ACK tombstone resolves the uncertain return"
                        );
                    }
                    _ => unreachable!(),
                }

                first_owner
                    .shutdown()
                    .await
                    .expect("shutdown ACK crash publication owner");
                drop(backend);
                faulted.shutdown().await.expect("shutdown ACK crash Store");

                let reopened = fixture.reopen().await;
                let retry_transport = Arc::new(RecordingPublicationTransport::new(
                    RecordingRelayPlan::Commit,
                ));
                let retry_owner =
                    open_owner_with_transport_for_test(reopened.clone(), retry_transport.clone())
                        .await
                        .expect("open ACK crash retry owner");
                let (retry_signer, _retry_authority_lease) =
                    counting_machine_data_signer(&fixture, signing_calls.clone());
                let retry_publisher = production_shared_publisher(
                    &fixture,
                    &reopened,
                    retry_owner.handle(),
                    retry_signer,
                );
                retry_publisher
                    .publish_runtime_bytes(fixture.runtime_bytes.clone())
                    .await
                    .expect("ACK crash retry finishes from authenticated readback");
                assert_eq!(
                    signing_calls.load(Ordering::SeqCst),
                    1,
                    "{} {cut} restart must not reseal",
                    class.label()
                );
                assert!(
                    retry_transport.sent_blobs().is_empty(),
                    "{} {cut} restart must finish local ACK without Relay resend",
                    class.label()
                );
                assert_acknowledged_machine_data_blob(class, &fixture, &reopened, &first_sent[0])
                    .await;
                assert!(
                    reopened
                        .load_frozen_publication(fixture.canonical.publication_id)
                        .await
                        .expect("read acknowledged ACK crash retry")
                        .is_none()
                );

                drop(retry_publisher);
                retry_owner
                    .shutdown()
                    .await
                    .expect("shutdown ACK crash retry owner");
                reopened
                    .shutdown()
                    .await
                    .expect("shutdown ACK crash recovered Store");
            }
        }
    }
}
