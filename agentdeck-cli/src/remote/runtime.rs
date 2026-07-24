//! Persistent remote Runtime command transport.
//!
//! 本模块只把已配对 machine 的 typed crypto capability 与 Relay `Send`/`Reply`
//! transport 组合起来；Relay 的 `RouteAccepted` 仅是传输状态，业务成功只来自经完整
//! 验证且已 durable terminal 的 daemon typed reply。

#![cfg(unix)]

use std::collections::{HashMap, HashSet};
use std::convert::Infallible;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use agentdeck_crypto::rand_core::{CryptoRng, TryCryptoRng, TryRng};
use agentdeck_crypto::{CryptoError, sha256};
use agentdeck_protocol::ActionDecision;
use agentdeck_protocol::e2ee::{
    DirectoryCurrentV1, E2eeError, KeyControlV1, KeyUpdateAckV1, REMOTE_CRYPTO_BAD_CIPHERTEXT,
    REMOTE_CRYPTO_BAD_SENDER_SIGNATURE, REMOTE_CRYPTO_COUNTER_REPLAY,
    REMOTE_CRYPTO_KEY_EPOCH_MISSING, REMOTE_CRYPTO_KEY_REVISION_ROLLBACK,
    REMOTE_CRYPTO_NONCE_REUSE, SealedPayloadKind, SealedPayloadV1, StreamBindingV1,
};
use agentdeck_protocol::relay_v2::frame::{
    AcceptedRef, Ack as RelayAck, SealedBlob, Send as RelaySend, Subscribe as RelaySubscribe,
    Unsubscribe as RelayUnsubscribe,
};
use agentdeck_protocol::relay_v2::{
    CodecError, DeviceRouteId, GrantSerial as RelayGrantSerial, KeyDirectoryRevision,
    MAX_FRAME_BYTES, OpaqueRouteFrame, RELAY_PROTOCOL_VERSION, RelayFrameBody, RequestRouteId,
    StreamGenerationId, StreamRouteId, decode, encode,
};
use agentdeck_protocol::runtime::command::{CatalogRequest, RevokeRequest, RevokeTarget};
use agentdeck_protocol::runtime::identity::{
    ApprovalId, CatalogPageCursor, GrantSerial as RuntimeGrantSerial, MessageId, TransferId, TurnId,
};
use agentdeck_protocol::runtime::{
    ApprovalDeliveryState, ApprovalReceipt, BackfillChunk, CatalogSnapshot, CommandReceipt,
    ConversationId, ConversationSnapshot, MAX_RUNTIME_JSON_FRAME_BYTES, RUNTIME_PROTOCOL_VERSION,
    RevocationReceipt, RuntimeEnvelope, RuntimeFailure, RuntimeInnerCursor, RuntimeMessage,
    RuntimeReply, RuntimeStreamItem, RuntimeSyncComplete, RuntimeTransferCarrierError,
    RuntimeTransferCarrierV1, RuntimeTransferChannel, SendPromptRequest, StreamCursor,
    SubscriptionReceipt, TRANSFER_TTL_MS, TransferError, TransferProgress, TransferReassembler,
};
use agentdeck_relay_client::RelayClientError;
use async_trait::async_trait;
use thiserror::Error;
use tokio::time::Instant;
use uuid::Uuid;
use zeroize::Zeroize;

use super::key_sync::{
    DurableKeySyncStateV1, FrozenKeySyncSendV1, KeySyncCoordinationStatus, KeySyncError,
    SignedHigherRevisionObservationV1,
};
use super::paired_machine::{
    AuthorizedRuntimeRequest, OpaqueRuntimeState, OpenedPairedMachine, PairedPromotionError,
    VerifiedDirectedReply, VerifiedRevocationTerminal, VerifiedStreamPublish,
};
use super::stream_state::{
    DurableStreamBindingV1, StreamDirectApplyMode, StreamPublishDisposition,
};

const EXCHANGE_MAGIC: &[u8; 4] = b"ADRX";
const LEGACY_EXCHANGE_VERSION: u16 = 1;
const PRE_SUBSCRIPTION_EXCHANGE_VERSION: u16 = 2;
const EXCHANGE_VERSION: u16 = 3;
const EXCHANGE_PENDING: u8 = 0;
const EXCHANGE_TERMINAL: u8 = 1;
const REPLAY_MAGIC: &[u8; 4] = b"ADRW";
const REPLAY_VERSION: u16 = 1;
const MAX_REPLAY_WINDOWS: usize = 4_096;
const MAX_REPLAY_ENTRIES: usize = 4_096;
const MAX_PENDING_KEY_UPDATE_ACK_ROUTES: usize = 8;
const MAX_PENDING_KEY_SYNC_ROUTES: usize = 8;
const MAX_PENDING_KEY_SYNC_ACCEPTANCES_PER_ROUTE: usize = 8;
const KEY_SYNC_RECOVERY_ACK_TIMEOUT_MS: u64 = 5_000;
const CATALOG_INTENT_DOMAIN: &[u8] = b"AgentDeck/RemoteCatalogIntentV1\0";
const INTENT_DOMAIN: &[u8] = b"AgentDeck/RemotePromptIntentV1\0";
const RESOLVE_APPROVAL_INTENT_DOMAIN: &[u8] = b"AgentDeck/RemoteResolveApprovalIntentV1\0";
const RETRY_APPROVAL_INTENT_DOMAIN: &[u8] = b"AgentDeck/RemoteRetryApprovalIntentV1\0";
const REVOKE_SELF_INTENT_DOMAIN: &[u8] = b"AgentDeck/RemoteRevokeSelfIntentV1\0";
const SUBSCRIBE_INTENT_DOMAIN: &[u8] = b"AgentDeck/RemoteSubscribeIntentV1\0";
const MUTATION_RNG_DOMAIN: &[u8] = b"AgentDeck/RemoteRuntimeMutationRngV1\0";

/// Remote Runtime 对 Relay transport 的最小需求；transport 不解析或伪造业务回执。
#[async_trait]
pub trait RemoteRuntimeTransport: Send {
    async fn send(&mut self, frame: ExactRelayFrame) -> Result<(), RemoteRuntimeTransportError>;

    async fn recv(&mut self) -> Result<Option<ReceivedRuntimeFrame>, RemoteRuntimeTransportError>;

    /// 等待 transport-owned I/O task 收口；默认用于无后台任务的 automatic fake。
    async fn shutdown(&mut self) {}
}

/// transport 交给 Runtime 的未信任 Relay frame 与原始 binary payload。
///
/// 构造本身不授予 exact-wire 信任；Runtime 必须在读取 body、计算 hash 或执行任何 durable
/// mutation 前同时验证协议版本以及 `encode(frame) == canonical_bytes`。公开构造器用于
/// transport adapter 与 library harness，`Debug` 永远不暴露 frame 或 payload。
#[derive(PartialEq, Eq)]
pub struct ReceivedRuntimeFrame {
    frame: OpaqueRouteFrame,
    canonical_bytes: Vec<u8>,
}

impl ReceivedRuntimeFrame {
    #[must_use]
    pub fn from_untrusted_parts(frame: OpaqueRouteFrame, canonical_bytes: Vec<u8>) -> Self {
        Self {
            frame,
            canonical_bytes,
        }
    }

    #[must_use]
    pub const fn frame(&self) -> &OpaqueRouteFrame {
        &self.frame
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    #[must_use]
    pub fn into_parts(self) -> (OpaqueRouteFrame, Vec<u8>) {
        (self.frame, self.canonical_bytes)
    }
}

impl std::fmt::Debug for ReceivedRuntimeFrame {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ReceivedRuntimeFrame([REDACTED])")
    }
}

/// 已由 Runtime durable state 冻结并通过严格 Relay codec 校验的逐字节发送单元。
///
/// 构造器保持私有，transport 只能把 [`Self::as_bytes`] 返回的同一字节串交给
/// WebSocket writer，不能重新编码 `OpaqueRouteFrame` 后冒充 exact retry。
pub struct ExactRelayFrame {
    bytes: Vec<u8>,
}

impl std::fmt::Debug for ExactRelayFrame {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExactRelayFrame")
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

impl ExactRelayFrame {
    fn from_frozen(bytes: Vec<u8>) -> Result<Self, CodecError> {
        let _ = decode(&bytes)?;
        Ok(Self { bytes })
    }

    #[cfg(test)]
    pub(super) fn from_frozen_for_test(bytes: Vec<u8>) -> Result<Self, CodecError> {
        Self::from_frozen(bytes)
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

/// Relay transport 层失败。
#[derive(Debug, Error)]
pub enum RemoteRuntimeTransportError {
    #[error(transparent)]
    Relay(#[from] RelayClientError),
    #[error("remote runtime transport failed: {0}")]
    Failed(String),
}

/// 一次 remote prompt 的 terminal daemon 回执及独立 transport acceptance 观测。
#[derive(Debug)]
pub struct RemotePromptOutcome {
    route_accepted: bool,
    receipt: CommandReceipt,
}

/// 一页 authenticated catalog snapshot 及独立 transport acceptance 观测。
#[derive(Debug)]
pub struct RemoteCatalogPageOutcome {
    route_accepted: bool,
    snapshot: CatalogSnapshot,
}

/// 完整 subscription bootstrap 的 authenticated 结果。
///
/// Runtime 本地 generation 只存在于 `subscription`/`sync_complete`；`binding` 中的
/// generation 属于 Relay publication，两条版本轴不得比较或互相推导。
#[derive(Debug)]
pub struct RemoteSubscriptionBootstrap {
    route_accepted: bool,
    subscription: SubscriptionReceipt,
    sync_complete: RuntimeSyncComplete,
    binding: StreamBindingV1,
}

/// 已完成 MachineDataSign/replay/AEAD/Runtime canonical 校验并按 inner cursor 连续归约的
/// subscription bootstrap 内容。CLI reducer 必须只消费这里的值，不能从 Relay transport
/// 或未验证 payload 自行拼接状态。
#[derive(Clone)]
pub enum RemoteSubscriptionBootstrapItem {
    CatalogSnapshot(CatalogSnapshot),
    ConversationSnapshot(ConversationSnapshot),
    Backfill(BackfillChunk),
}

/// 单个 authenticated live stream frame 的业务结果。Relay replay/control terminal 与
/// Runtime reducer apply 保持显式区分；`AppliedDuplicate` 只表示本地 durable cut 已包含该
/// publication，调用方仍已重新发送 cumulative ACK。
#[derive(Debug)]
pub enum RemoteStreamFrameOutcome {
    Applied(Box<RuntimeStreamItem>),
    AuthenticatedOverlap,
    AppliedDuplicate,
    Gap {
        need_stream_seq: u64,
        oldest_stream_seq: u64,
    },
    ReplayComplete {
        current_cursor: StreamCursor,
    },
    /// 已签名的未知更高 directory revision 已触发 bounded KeySync；这只是本地协调状态，
    /// 不表示 daemon 已接收、更不表示任何 Runtime command 成功。
    KeySyncPending {
        attempt: u8,
    },
    /// Relay 只确认 KeySync `Send` 进入有界 writer；ADKS 保持 durable active，直到后续
    /// authenticated key-control response 完成安装状态机。
    KeySyncRouteAccepted {
        attempt: u8,
    },
    /// Device 已完整安装并 durable readback exact UpdateSet，且先发送了绑定该安装的 ACK。
    /// `next_attempt` 仅表示更高目标 revision 仍需 bounded probe；它不是 daemon ACK。
    KeyUpdateInstalled {
        key_directory_revision: u64,
        next_attempt: Option<u8>,
    },
    /// Relay 只确认 KeyUpdateAck `Send` 进入有界 writer；durable ACK basis 不会因此清除。
    KeyUpdateAckRouteAccepted {
        key_directory_revision: u64,
    },
}

/// subscription bootstrap 的 clone-and-swap reducer 契约。
///
/// Runtime 先 clone 当前 reducer，再把全部 authenticated snapshot/backfill 应用到 clone；
/// clone 的 cursor 必须精确等于 `SyncComplete.innerCursor`。只有 staged reducer 完整成功后
/// 才会持久化 inner HWM、替换调用方 reducer 并发送 Relay Subscribe/Ack。
pub trait RemoteSubscriptionReducer: Clone {
    fn inner_cursor(&self) -> &RuntimeInnerCursor;

    fn apply(&mut self, item: &RemoteSubscriptionBootstrapItem) -> Result<(), RemoteRuntimeError>;

    /// 应用一条已经完成 Publish signature/replay/AEAD/canonical 验证、且相对 durable
    /// `inner_observed` exact-next 的 live item。Runtime 只在 clone 上调用，并在 cursor
    /// 精确到达预期 cut、durable state COMMIT 后 swap 回调用方。
    fn apply_live(&mut self, item: &RuntimeStreamItem) -> Result<(), RemoteRuntimeError>;
}

impl RemoteSubscriptionBootstrap {
    #[must_use]
    pub const fn route_accepted(&self) -> bool {
        self.route_accepted
    }

    #[must_use]
    pub const fn subscription(&self) -> &SubscriptionReceipt {
        &self.subscription
    }

    #[must_use]
    pub const fn sync_complete(&self) -> &RuntimeSyncComplete {
        &self.sync_complete
    }

    #[must_use]
    pub const fn binding(&self) -> &StreamBindingV1 {
        &self.binding
    }
}

impl RemoteCatalogPageOutcome {
    #[must_use]
    pub const fn route_accepted(&self) -> bool {
        self.route_accepted
    }

    #[must_use]
    pub const fn snapshot(&self) -> &CatalogSnapshot {
        &self.snapshot
    }

    pub(super) fn into_parts(self) -> (bool, CatalogSnapshot) {
        (self.route_accepted, self.snapshot)
    }
}

impl RemotePromptOutcome {
    #[must_use]
    pub const fn route_accepted(&self) -> bool {
        self.route_accepted
    }

    #[must_use]
    pub const fn receipt(&self) -> &CommandReceipt {
        &self.receipt
    }
}

/// 一次 remote approval 的 terminal daemon 回执及独立 transport acceptance 观测。
#[derive(Debug)]
pub struct RemoteApprovalOutcome {
    route_accepted: bool,
    receipt: ApprovalReceipt,
}

/// root-signed Relay terminal 已验证且本机 paired material 已完成 cleanup 的撤销结果。
#[derive(Debug)]
pub struct RemoteRevocationOutcome {
    route_accepted: bool,
    receipt: RevocationReceipt,
}

impl RemoteRevocationOutcome {
    #[must_use]
    pub const fn route_accepted(&self) -> bool {
        self.route_accepted
    }

    #[must_use]
    pub const fn receipt(&self) -> &RevocationReceipt {
        &self.receipt
    }
}

impl RemoteApprovalOutcome {
    #[must_use]
    pub const fn route_accepted(&self) -> bool {
        self.route_accepted
    }

    #[must_use]
    pub const fn receipt(&self) -> &ApprovalReceipt {
        &self.receipt
    }
}

/// Remote Runtime 编排失败；任何错误都不是 command success。
#[derive(Debug, Error)]
pub enum RemoteRuntimeError {
    #[error("paired remote state rejected runtime operation")]
    Paired(#[from] PairedPromotionError),
    #[error("remote runtime transport failed")]
    Transport(#[from] RemoteRuntimeTransportError),
    #[error("Relay frame codec failed")]
    RelayCodec(#[from] CodecError),
    #[error("runtime JSON encoding failed")]
    Json(#[from] serde_json::Error),
    #[error("remote runtime entropy source is unavailable")]
    EntropyUnavailable,
    #[error("another durable remote intent is still pending")]
    PendingIntentConflict,
    #[error("authenticated daemon rejected the remote request: {0:?}")]
    DaemonFailure(RuntimeFailure),
    #[error("transport closed before an authenticated daemon receipt")]
    OutcomeUnknown,
    #[error("remote reply is not correlated or has an invalid shape: {0}")]
    InvalidReply(&'static str),
    #[error("remote compact transfer carrier is invalid")]
    TransferCarrier(#[source] RuntimeTransferCarrierError),
    #[error("remote transfer reassembly failed")]
    Transfer(#[from] TransferError),
    #[error("authenticated reply replay tuple was rejected")]
    ReplayRejected,
    #[error("authenticated stream counter is stale or not admissible")]
    CounterReplay,
    #[error("authenticated stream reused a nonce with a different ciphertext")]
    NonceReuse,
    #[error("durable remote runtime state has an invalid canonical encoding")]
    InvalidDurableState,
}

impl RemoteRuntimeError {
    #[must_use]
    pub fn code(&self) -> &str {
        match self {
            Self::Paired(PairedPromotionError::Crypto(CryptoError::BadSignature)) => {
                REMOTE_CRYPTO_BAD_SENDER_SIGNATURE
            }
            Self::Paired(PairedPromotionError::Crypto(CryptoError::BadCiphertext)) => {
                REMOTE_CRYPTO_BAD_CIPHERTEXT
            }
            Self::Paired(PairedPromotionError::Crypto(CryptoError::E2ee(
                E2eeError::KeyEpochMissing,
            ))) => REMOTE_CRYPTO_KEY_EPOCH_MISSING,
            Self::Paired(PairedPromotionError::Crypto(CryptoError::E2ee(
                E2eeError::KeyRevisionRollback,
            ))) => REMOTE_CRYPTO_KEY_REVISION_ROLLBACK,
            Self::Paired(error) => error.code(),
            Self::Transport(RemoteRuntimeTransportError::Relay(error)) => error.code(),
            Self::Transport(RemoteRuntimeTransportError::Failed(_)) => {
                "remote.runtime.transport_failed"
            }
            Self::RelayCodec(_) => "remote.runtime.relay_frame_invalid",
            Self::Json(_) | Self::InvalidReply(_) | Self::TransferCarrier(_) => {
                "remote.runtime.reply_invalid"
            }
            Self::EntropyUnavailable => "remote.runtime.entropy_unavailable",
            Self::PendingIntentConflict => "remote.runtime.pending_intent_conflict",
            Self::DaemonFailure(failure) => failure.code.as_str(),
            Self::OutcomeUnknown => "remote.runtime.outcome_unknown",
            Self::Transfer(error) => error.code(),
            Self::ReplayRejected => "remote.runtime.replay_rejected",
            Self::CounterReplay => REMOTE_CRYPTO_COUNTER_REPLAY,
            Self::NonceReuse => REMOTE_CRYPTO_NONCE_REUSE,
            Self::InvalidDurableState => "remote.runtime.state_invalid",
        }
    }
}

/// 持有同一 machine 独占 lease 的 remote Runtime command 编排器。
///
/// 字段声明顺序是 drop 顺序：先关闭 transport，再最后释放 machine lease/capability。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PendingKeySyncRoute {
    attempt: u8,
    outstanding_acceptances: usize,
}

fn request_route_is_owned(
    request_route: RequestRouteId,
    pending_key_update_ack_routes: &HashMap<RequestRouteId, KeyDirectoryRevision>,
    pending_key_sync_routes: &HashMap<RequestRouteId, PendingKeySyncRoute>,
    active_key_sync_route: Option<RequestRouteId>,
    pending_exchange_route: Option<RequestRouteId>,
) -> bool {
    pending_key_update_ack_routes.contains_key(&request_route)
        || pending_key_sync_routes.contains_key(&request_route)
        || active_key_sync_route == Some(request_route)
        || pending_exchange_route == Some(request_route)
}

pub struct RemoteRuntime<'a, T> {
    transport: T,
    machine: OpenedPairedMachine<'a>,
    pending_key_update_ack_routes: HashMap<RequestRouteId, KeyDirectoryRevision>,
    pending_key_sync_routes: HashMap<RequestRouteId, PendingKeySyncRoute>,
}

impl<'a, T> RemoteRuntime<'a, T>
where
    T: RemoteRuntimeTransport,
{
    #[must_use]
    pub fn new(machine: OpenedPairedMachine<'a>, transport: T) -> Self {
        Self {
            transport,
            machine,
            pending_key_update_ack_routes: HashMap::new(),
            pending_key_sync_routes: HashMap::new(),
        }
    }

    async fn recv_with_transfer_deadline(
        &mut self,
        active: &HashMap<TransferId, Instant>,
    ) -> Result<Option<ReceivedRuntimeFrame>, RemoteRuntimeError> {
        let Some(deadline) = active
            .values()
            .map(|started| *started + Duration::from_millis(TRANSFER_TTL_MS))
            .min()
        else {
            return Ok(self.transport.recv().await?);
        };
        match tokio::time::timeout_at(deadline, self.transport.recv()).await {
            Ok(received) => Ok(received?),
            Err(_) => Err(TransferError::Expired.into()),
        }
    }

    /// 显式等待 transport shutdown，随后按字段顺序先销毁 transport、再释放 device lease。
    pub async fn shutdown(mut self) {
        self.transport.shutdown().await;
    }

    /// 请求一页 catalog；小页接受 authenticated JSON，大页接受
    /// message-bound ADRT1 Reply 分片并在完整重组后才持久化 terminal。
    pub async fn catalog_page<R: CryptoRng>(
        &mut self,
        page_cursor: Option<CatalogPageCursor>,
        rng: &mut R,
    ) -> Result<RemoteCatalogPageOutcome, RemoteRuntimeError> {
        let operation = DirectedOperation::Catalog {
            page_cursor: page_cursor.clone(),
        };
        let exchange = self
            .directed_exchange(DirectedRequestPlan::catalog(page_cursor)?, rng)
            .await;
        let outcome = match exchange {
            Ok(exchange) => directed_receipt_outcome(exchange)?,
            Err(error @ RemoteRuntimeError::DaemonFailure(_)) => {
                self.consume_catalog_terminal(&operation)?;
                return Err(error);
            }
            Err(error) => return Err(error),
        };
        let DirectedReceipt::Catalog(snapshot) = outcome.receipt else {
            return Err(RemoteRuntimeError::InvalidDurableState);
        };
        // Catalog 是 read-only query，不以 request payload 提供幂等身份。terminal 只在
        // persist→return 的 crash 窗口保留；一旦本次调用消费到 authenticated 结果就
        // durable 清除，下一次相同 Catalog(None) 必须重新查询，不能永久读旧快照。
        if outcome.terminal_persisted {
            self.consume_catalog_terminal(&operation)?;
        }
        Ok(RemoteCatalogPageOutcome {
            route_accepted: outcome.route_accepted,
            snapshot,
        })
    }

    /// 恢复上次进程留下的只读 Catalog pending。
    ///
    /// 首页 pending 的 authenticated 结果仍可直接作为本次完整 listing 的第一页；后续页
    /// pending 必须先逐字节重试并消费 terminal，再由调用方从 `Catalog(None)` 建立新的完整
    /// frozen listing。其他 mutation pending 不能被只读查询覆盖。
    pub(super) async fn resume_pending_catalog_page<R: CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Result<Option<RemoteCatalogPageOutcome>, RemoteRuntimeError> {
        let existing = self
            .machine
            .opaque_runtime_state()
            .exchange()
            .map(decode_exchange)
            .transpose()?;
        let CatalogPendingRecovery::Resume(page_cursor) = catalog_pending_recovery(existing)?
        else {
            return Ok(None);
        };
        let is_first_page = page_cursor.is_none();
        let outcome = self.catalog_page(page_cursor, rng).await?;
        Ok(is_first_page.then_some(outcome))
    }

    /// 建立一个 Runtime subscription bootstrap。所有 directed snapshot/backfill（包括
    /// compact transfer）先进入 clone reducer；只有 reducer 精确到达 SyncComplete cut 且
    /// `StreamBindingV1` 完整验证后，才原子写入 binding/inner HWM、swap reducer，并发送
    /// Relay `Subscribe`/可选 `Ack`。
    ///
    /// 成功路径不持久化 bootstrap 明文或缺明文的 terminal。若进程在 state commit 后、
    /// control send 前退出，冷启动必须从自己的空 reducer 发起新 snapshot，并替换旧 target
    /// binding；不能只恢复 controls 后跳过未持久化的 transcript。
    pub async fn subscribe<R, D>(
        &mut self,
        inner_cursor: RuntimeInnerCursor,
        reducer: &mut D,
        rng: &mut R,
    ) -> Result<RemoteSubscriptionBootstrap, RemoteRuntimeError>
    where
        R: CryptoRng,
        D: RemoteSubscriptionReducer,
    {
        if reducer.inner_cursor() != &inner_cursor {
            return Err(RemoteRuntimeError::InvalidDurableState);
        }
        let plan = DirectedRequestPlan::subscribe(inner_cursor.clone())?;
        let operation = plan.operation.clone();
        let existing = self
            .machine
            .opaque_runtime_state()
            .exchange()
            .map(decode_exchange)
            .transpose()?;
        let pending =
            match select_exchange_start(existing, plan, |plan| self.prepare_pending(plan, rng))? {
                ExchangeStart::Pending(pending) => pending,
                ExchangeStart::Terminal(DirectedReceipt::Failure(failure)) => {
                    self.consume_subscription_failure_terminal(&operation)?;
                    return Err(RemoteRuntimeError::DaemonFailure(failure));
                }
                ExchangeStart::Terminal(_) => {
                    return Err(RemoteRuntimeError::InvalidDurableState);
                }
            };

        self.reject_quarantined_current_reply_scope()?;
        let pending_send = decode_pending_send(&pending, self.machine.device_route())?;
        self.transport
            .send(ExactRelayFrame::from_frozen(pending.exact_send.clone())?)
            .await?;

        let mut tracker = SubscriptionBootstrapTracker::new(inner_cursor, reducer)?;
        let mut route_accepted = false;
        let transfer_started_at = Instant::now();
        let mut reply_transfers = TransferReassembler::new();
        let mut active_reply_transfers = HashMap::new();
        let mut processed_signed_blobs = HashSet::new();
        loop {
            let Some(received) = self
                .recv_with_transfer_deadline(&active_reply_transfers)
                .await?
            else {
                return Err(RemoteRuntimeError::OutcomeUnknown);
            };
            validate_received_runtime_frame(&received)?;
            let reply_frame_hash = sha256(received.canonical_bytes());
            let frame = received.frame();
            match &frame.body {
                RelayFrameBody::RouteAccepted(accepted) => {
                    let AcceptedRef::Request { request_route } = accepted.accepted else {
                        return Err(RemoteRuntimeError::InvalidReply(
                            "RouteAccepted does not match the pending subscription",
                        ));
                    };
                    if request_route == pending.request_route {
                        route_accepted = true;
                    } else if self
                        .consume_key_control_route_accepted(request_route)
                        .is_none()
                    {
                        return Err(RemoteRuntimeError::InvalidReply(
                            "RouteAccepted does not match the pending subscription",
                        ));
                    }
                }
                RelayFrameBody::Reply(reply) => {
                    if reply.device_route != self.machine.device_route()
                        || reply.request_route != pending.request_route
                    {
                        return Err(RemoteRuntimeError::InvalidReply(
                            "subscription Reply outer route does not match the pending request",
                        ));
                    }
                    let candidate = self.machine.verify_directed_reply(
                        pending.request_route,
                        &pending_send.sealed_blob.0,
                        &reply.sealed_blob.0,
                    )?;
                    let signed_blob_hash = candidate.signed_blob_hash();
                    self.admit_reply_replay(&candidate)?;
                    if processed_signed_blobs.contains(&signed_blob_hash) {
                        continue;
                    }
                    let opened = self
                        .machine
                        .open_verified_directed_reply(&pending_send.sealed_blob.0, candidate)?;

                    if opened.payload_kind == SealedPayloadKind::KeyUpdate {
                        if !active_reply_transfers.is_empty() {
                            return Err(RemoteRuntimeError::InvalidReply(
                                "StreamBinding arrived while a bootstrap transfer is incomplete",
                            ));
                        }
                        let control =
                            KeyControlV1::from_canonical_bytes(&opened.payload).map_err(|_| {
                                RemoteRuntimeError::InvalidReply(
                                    "subscription terminal is not canonical key control",
                                )
                            })?;
                        let KeyControlV1::StreamBinding { binding, .. } = control else {
                            return Err(RemoteRuntimeError::InvalidReply(
                                "subscription terminal is not a StreamBinding",
                            ));
                        };
                        let progress = tracker.finish(route_accepted, &binding)?;
                        let applied_inner = progress.sync_complete.inner_cursor.clone();
                        let mut mutation_rng = SystemMutationRng::new()?;
                        // staged reducer 已完整应用全部 bootstrap 内容；只有此后才能在同一
                        // paired-state transaction 中推进 inner HWM。成功 exchange 不留
                        // “无明文 reducer 却可恢复”的 durable terminal：冷启动必须重新
                        // snapshot，而不是从旧 SyncComplete 跳过内容。
                        let installed = self.machine.commit_subscription_bootstrap(
                            binding,
                            applied_inner,
                            &mut mutation_rng,
                        )?;
                        let binding = installed.binding().clone();
                        let (outcome, staged_reducer) =
                            progress.into_outcome_and_reducer(binding.clone());
                        *reducer = staged_reducer;
                        self.send_stream_binding_controls(&installed).await?;
                        return Ok(outcome);
                    }

                    if opened.payload_kind == SealedPayloadKind::TransferPart {
                        let carrier = RuntimeTransferCarrierV1::decode(&opened.payload)
                            .map_err(map_transfer_carrier_error)?;
                        if carrier.channel != RuntimeTransferChannel::Reply {
                            return Err(RemoteRuntimeError::InvalidReply(
                                "subscription transfer carrier is not on the Reply channel",
                            ));
                        }
                        if carrier.message_id != pending.message_id {
                            return Err(RemoteRuntimeError::InvalidReply(
                                "subscription transfer messageId does not match the pending request",
                            ));
                        }
                        let transfer_id = carrier.transfer.transfer_id.clone();
                        let now_ms = u64::try_from(transfer_started_at.elapsed().as_millis())
                            .unwrap_or(u64::MAX);
                        match reply_transfers.accept(
                            RuntimeTransferChannel::Reply,
                            carrier.transfer,
                            now_ms,
                        )? {
                            TransferProgress::InProgress { .. } => {
                                active_reply_transfers
                                    .entry(transfer_id)
                                    .or_insert_with(Instant::now);
                                processed_signed_blobs.insert(signed_blob_hash);
                                continue;
                            }
                            TransferProgress::AlreadyComplete => {
                                return Err(RemoteRuntimeError::InvalidReply(
                                    "subscription transfer completed more than once",
                                ));
                            }
                            TransferProgress::Complete(payload) => {
                                active_reply_transfers.remove(&transfer_id);
                                let (payload_kind, reply) =
                                    decode_subscription_transfer(tracker.requested(), &payload)?;
                                tracker.accept_runtime_reply(payload_kind, reply)?;
                                processed_signed_blobs.insert(signed_blob_hash);
                                continue;
                            }
                        }
                    }

                    if opened.payload.len() >= MAX_RUNTIME_JSON_FRAME_BYTES {
                        return Err(RemoteRuntimeError::InvalidReply(
                            "Runtime subscription reply exceeds the JSON frame limit",
                        ));
                    }
                    let envelope = canonical_json::<RuntimeEnvelope>(&opened.payload).ok_or(
                        RemoteRuntimeError::InvalidReply(
                            "Runtime reply is not one canonical JSON envelope",
                        ),
                    )?;
                    if envelope.message_id != pending.message_id {
                        return Err(RemoteRuntimeError::InvalidReply(
                            "Runtime subscription messageId does not match the pending request",
                        ));
                    }
                    let RuntimeMessage::Reply(reply) = envelope.body else {
                        return Err(RemoteRuntimeError::InvalidReply(
                            "Runtime subscription envelope is not a reply",
                        ));
                    };
                    if let RuntimeReply::Failure(failure) = reply {
                        if opened.payload_kind != SealedPayloadKind::CommandReceipt {
                            return Err(RemoteRuntimeError::InvalidReply(
                                "Runtime subscription failure has the wrong payload kind",
                            ));
                        }
                        let receipt = DirectedReceipt::Failure(failure.clone());
                        self.persist_terminal(&pending, reply_frame_hash, &receipt)?;
                        self.consume_subscription_failure_terminal(&pending.operation)?;
                        return Err(RemoteRuntimeError::DaemonFailure(failure));
                    }
                    if matches!(reply, RuntimeReply::SyncComplete(_))
                        && !active_reply_transfers.is_empty()
                    {
                        return Err(RemoteRuntimeError::InvalidReply(
                            "SyncComplete arrived while a bootstrap transfer is incomplete",
                        ));
                    }
                    tracker.accept_runtime_reply(opened.payload_kind, reply)?;
                    processed_signed_blobs.insert(signed_blob_hash);
                }
                _ => {
                    return Err(RemoteRuntimeError::InvalidReply(
                        "unexpected Relay frame while awaiting subscription bootstrap",
                    ));
                }
            }
        }
    }

    /// 接收并处理一个 subscription-owned Relay frame。Publish 在进入 reducer 前固定走：
    /// canonical Relay outer → route/generation/key/AAD/signature → durable replay admission →
    /// AEAD/canonical Runtime stream → clone reducer → durable outer/inner → reducer swap → ACK。
    pub async fn receive_stream_frame<D>(
        &mut self,
        reducer: &mut D,
    ) -> Result<RemoteStreamFrameOutcome, RemoteRuntimeError>
    where
        D: RemoteSubscriptionReducer,
    {
        let received = self
            .transport
            .recv()
            .await?
            .ok_or(RemoteRuntimeError::OutcomeUnknown)?;
        validate_received_runtime_frame(&received)?;
        let (frame, _) = received.into_parts();
        match frame.body {
            RelayFrameBody::Publish(publish) => {
                let durable =
                    self.stream_binding_for_route(publish.stream_route, publish.generation)?;
                if reducer.inner_cursor() != durable.inner_applied() {
                    return Err(RemoteRuntimeError::InvalidDurableState);
                }
                let candidate = self.machine.verify_stream_publish(&durable, &publish)?;
                let candidate = match candidate {
                    VerifiedStreamPublish::Current(candidate) => *candidate,
                    VerifiedStreamPublish::Higher(candidate) => {
                        return self
                            .coordinate_key_sync((*candidate).into_observation())
                            .await;
                    }
                };
                let stream_seq = candidate.stream_seq();
                let (admitted, disposition) = durable
                    .admit_publish(
                        candidate.stream_seq(),
                        candidate.counter(),
                        candidate.ciphertext_sha256(),
                    )
                    .map_err(|_| RemoteRuntimeError::CounterReplay)?;
                let admitted = if admitted == durable {
                    durable
                } else {
                    let mut mutation_rng = SystemMutationRng::new()?;
                    self.machine.commit_stream_state_transition(
                        &durable,
                        &admitted,
                        &mut mutation_rng,
                    )?
                };
                match disposition {
                    StreamPublishDisposition::NonceReuseQuarantined => {
                        return Err(RemoteRuntimeError::NonceReuse);
                    }
                    StreamPublishDisposition::AppliedDuplicate => {
                        self.send_stream_ack(&admitted).await?;
                        return Ok(RemoteStreamFrameOutcome::AppliedDuplicate);
                    }
                    StreamPublishDisposition::Fresh
                    | StreamPublishDisposition::PendingDuplicate => {}
                }

                let opened = self.machine.open_verified_stream_publish(candidate)?;
                let (item, observed_after) = decode_direct_stream_item(admitted.binding(), opened)?;
                let mode = admitted.direct_apply_mode(&observed_after).map_err(|_| {
                    RemoteRuntimeError::InvalidReply(
                        "live stream item is not exact-next for the durable inner cut",
                    )
                })?;
                let staged_reducer = if mode == StreamDirectApplyMode::Apply {
                    let mut staged = reducer.clone();
                    staged.apply_live(&item)?;
                    if staged.inner_cursor() != &observed_after {
                        return Err(RemoteRuntimeError::InvalidReply(
                            "live reducer did not reach the exact authenticated inner cut",
                        ));
                    }
                    Some(staged)
                } else {
                    None
                };
                let (committed, committed_mode) = admitted
                    .commit_direct_publish(stream_seq, observed_after)
                    .map_err(|_| RemoteRuntimeError::InvalidDurableState)?;
                if committed_mode != mode {
                    return Err(RemoteRuntimeError::InvalidDurableState);
                }
                let mut mutation_rng = SystemMutationRng::new()?;
                let committed = self.machine.commit_stream_state_transition(
                    &admitted,
                    &committed,
                    &mut mutation_rng,
                )?;
                if let Some(staged) = staged_reducer {
                    *reducer = staged;
                }
                self.send_stream_ack(&committed).await?;
                match committed_mode {
                    StreamDirectApplyMode::Overlap => {
                        Ok(RemoteStreamFrameOutcome::AuthenticatedOverlap)
                    }
                    StreamDirectApplyMode::Apply => {
                        Ok(RemoteStreamFrameOutcome::Applied(Box::new(item)))
                    }
                }
            }
            RelayFrameBody::Gap(gap) => {
                let durable = self.stream_binding_for_route(gap.stream_route, gap.generation)?;
                durable
                    .validate_gap(gap.need_stream_seq, gap.oldest_stream_seq)
                    .map_err(|_| {
                        RemoteRuntimeError::InvalidReply(
                            "Relay Gap does not match the exact durable stream cut",
                        )
                    })?;
                Ok(RemoteStreamFrameOutcome::Gap {
                    need_stream_seq: gap.need_stream_seq,
                    oldest_stream_seq: gap.oldest_stream_seq,
                })
            }
            RelayFrameBody::ReplayComplete(complete) => {
                let durable =
                    self.stream_binding_for_route(complete.stream_route, complete.generation)?;
                durable
                    .validate_replay_complete(complete.current_cursor)
                    .map_err(|_| {
                        RemoteRuntimeError::InvalidReply(
                            "Relay ReplayComplete does not match the exact durable stream cut",
                        )
                    })?;
                let cleared = durable
                    .clear_retired_subscriptions_after_replay_barrier(
                        complete.stream_route,
                        complete.generation,
                        complete.current_cursor,
                    )
                    .map_err(|_| RemoteRuntimeError::InvalidDurableState)?;
                if cleared != durable {
                    let mut mutation_rng = SystemMutationRng::new()?;
                    self.machine.commit_stream_state_transition(
                        &durable,
                        &cleared,
                        &mut mutation_rng,
                    )?;
                }
                Ok(RemoteStreamFrameOutcome::ReplayComplete {
                    current_cursor: complete.current_cursor,
                })
            }
            RelayFrameBody::Reply(reply) => self.handle_key_sync_reply(reply).await,
            RelayFrameBody::RouteAccepted(accepted) => {
                let AcceptedRef::Request { request_route } = accepted.accepted else {
                    return Err(RemoteRuntimeError::InvalidReply(
                        "KeySync RouteAccepted must reference its request route",
                    ));
                };
                self.consume_key_control_route_accepted(request_route)
                    .ok_or(RemoteRuntimeError::InvalidReply(
                        "KeySync RouteAccepted does not match a sent control request",
                    ))
            }
            _ => Err(RemoteRuntimeError::InvalidReply(
                "unexpected Relay frame on the live stream ingress",
            )),
        }
    }

    async fn handle_key_sync_reply(
        &mut self,
        reply: agentdeck_protocol::relay_v2::frame::Reply,
    ) -> Result<RemoteStreamFrameOutcome, RemoteRuntimeError> {
        // Outer route/device 必须在 signature、replay admission 与任何 durable mutation 前
        // 精确关联 active ADKS attempt；错误 route 不能消耗 replay/counter 或安装状态。
        let state = self
            .machine
            .durable_key_sync_state()?
            .ok_or(RemoteRuntimeError::InvalidDurableState)?;
        let active = state.active_send().ok_or(RemoteRuntimeError::InvalidReply(
            "KeySync Reply has no active durable request",
        ))?;
        if reply.device_route != self.machine.device_route()
            || reply.request_route != active.request_route()
        {
            return Err(RemoteRuntimeError::InvalidReply(
                "KeySync Reply does not match the active request route",
            ));
        }
        let request = active.request().clone();
        let candidate = self.machine.verify_key_sync_reply(
            &request,
            reply.request_route,
            &reply.sealed_blob.0,
        )?;
        let reply_directory_revision = candidate.directory_revision();
        self.admit_reply_replay(&candidate)?;
        let opened = self
            .machine
            .open_verified_key_sync_reply(&request, candidate)?;
        if opened.payload_kind != SealedPayloadKind::KeyUpdate {
            return Err(RemoteRuntimeError::InvalidReply(
                "KeySync Reply payload kind is not KeyUpdate",
            ));
        }
        let control = KeyControlV1::from_canonical_bytes(&opened.payload).map_err(|_| {
            RemoteRuntimeError::InvalidReply("KeySync Reply control is not canonical")
        })?;
        let now_ms = unix_time_ms()?;
        match control {
            KeyControlV1::UpdateSet { update_set, .. } => {
                if reply_directory_revision != request.requested_key_directory_revision.value() {
                    return Err(RemoteRuntimeError::InvalidReply(
                        "UpdateSet Reply is not sealed at the requested revision",
                    ));
                }
                let handoff = state
                    .into_update_set_handoff(now_ms, reply.request_route, update_set)
                    .map_err(key_sync_reply_error)?;
                let prepared = self.machine.prepare_key_update_install(handoff, now_ms)?;
                let mut mutation_rng = SystemMutationRng::new()?;
                let committed = self
                    .machine
                    .commit_key_update_install(prepared, &mut mutation_rng)?;
                let committed_state = committed.key_sync_state().clone();
                let revision = committed.ack_basis().key_directory_revision();
                let ack = committed.ack().clone();

                // ACK 的 CounterGuard reservation、seal 与 transport Send 必须先完成；只有
                // 此后才能冻结/提交下一次 probe，避免 restart 观察到“已继续但未 ACK”。
                self.send_key_update_ack(&ack).await?;
                let next_attempt = self.continue_key_sync_after_ack(committed_state).await?;
                Ok(RemoteStreamFrameOutcome::KeyUpdateInstalled {
                    key_directory_revision: revision.value(),
                    next_attempt,
                })
            }
            KeyControlV1::DirectoryCurrent { status, .. } => {
                if reply_directory_revision != request.known_key_directory_revision.value() {
                    return Err(RemoteRuntimeError::InvalidReply(
                        "DirectoryCurrent Reply is not sealed at the known revision",
                    ));
                }
                self.retry_after_directory_current(state, reply.request_route, status, now_ms)
                    .await
            }
            KeyControlV1::EpochBarrier { .. } | KeyControlV1::StreamBinding { .. } => {
                Err(RemoteRuntimeError::InvalidReply(
                    "KeySync Reply carries an unrelated key-control variant",
                ))
            }
        }
    }

    async fn retry_after_directory_current(
        &mut self,
        state: DurableKeySyncStateV1,
        reply_request_route: RequestRouteId,
        status: DirectoryCurrentV1,
        now_ms: u64,
    ) -> Result<RemoteStreamFrameOutcome, RemoteRuntimeError> {
        let request = state
            .next_retry_request_after_directory_current(now_ms, reply_request_route, &status)
            .map_err(key_sync_reply_error)?;
        let mut mutation_rng = SystemMutationRng::new()?;
        let reservation = self
            .machine
            .reserve_command_counter_block(&mut mutation_rng)?;
        let request_route = RequestRouteId::from_bytes(random_nonzero::<16, _>(&mut mutation_rng)?);
        self.ensure_new_key_sync_route_available(request_route)?;
        let signed = self
            .machine
            .seal_key_sync_request(request_route, &request, reservation)?;
        let exact_send = self.encode_key_control_send(request_route, signed)?;
        let frozen =
            FrozenKeySyncSendV1::new(request, exact_send).map_err(key_sync_runtime_error)?;
        let mut replacement = state.clone();
        replacement
            .retry_after_directory_current(now_ms, reply_request_route, &status, frozen)
            .map_err(key_sync_reply_error)?;
        let committed = self
            .machine
            .commit_key_sync_state_transition(Some(&state), Some(&replacement), &mut mutation_rng)?
            .ok_or(RemoteRuntimeError::InvalidDurableState)?;
        let active = committed
            .active_send()
            .ok_or(RemoteRuntimeError::InvalidDurableState)?;
        let attempt = committed.attempt();
        self.send_key_sync_probe(active, attempt).await?;
        Ok(RemoteStreamFrameOutcome::KeySyncPending { attempt })
    }

    /// 重启后根据 durable completion basis 重新封装 canonical ACK。新的 requestRoute 与
    /// CounterGuard reservation 只改变 carrier，不改变 ACK body；RouteAccepted 不清 basis。
    pub async fn resume_pending_key_update_ack(&mut self) -> Result<(), RemoteRuntimeError> {
        let state = self
            .machine
            .durable_key_sync_state()?
            .ok_or(RemoteRuntimeError::InvalidDurableState)?;
        let basis = state
            .latest_completed_ack_basis()
            .ok_or(RemoteRuntimeError::InvalidDurableState)?;
        let ack = self.machine.key_update_ack_from_basis(basis)?;
        self.send_key_update_ack(&ack).await?;
        self.continue_key_sync_after_ack(state).await?;
        Ok(())
    }

    /// production 建连后的 bounded KeySync 冷恢复。Resolved install 先重封 ACK；
    /// AwaitingProbe/Active 在同一 ACK 之后冻结或逐字节重发 durable probe，并在把 runtime
    /// 交给业务前消费本轮 ACK/probe 的 RouteAccepted 与 authenticated KeySync Reply。
    /// 其他 frame 一律 fail-close，避免 control frame 串入下一条业务 exchange。
    pub async fn recover_durable_key_sync(&mut self) -> Result<(), RemoteRuntimeError> {
        let Some(state) = self.machine.durable_key_sync_state()? else {
            return Ok(());
        };
        if let Some(basis) = state.latest_completed_ack_basis() {
            let ack = self.machine.key_update_ack_from_basis(basis)?;
            self.send_key_update_ack(&ack).await?;
        }

        match state.status() {
            KeySyncCoordinationStatus::Resolved => {}
            KeySyncCoordinationStatus::Exhausted => {
                return Err(key_sync_runtime_error(KeySyncError::Exhausted));
            }
            KeySyncCoordinationStatus::Active => {
                let now_ms = unix_time_ms()?;
                let active = state
                    .active_retry_at(now_ms)
                    .map_err(key_sync_runtime_error)?;
                self.send_key_sync_probe(active, state.attempt()).await?;
            }
            KeySyncCoordinationStatus::AwaitingProbe => {
                self.continue_key_sync_after_ack(state).await?;
            }
        }

        self.pump_durable_key_sync_recovery().await
    }

    async fn pump_durable_key_sync_recovery(&mut self) -> Result<(), RemoteRuntimeError> {
        let mut resolved_ack_deadline = None;
        loop {
            let state = self
                .machine
                .durable_key_sync_state()?
                .ok_or(RemoteRuntimeError::InvalidDurableState)?;
            let (deadline, timeout_error) = match state.status() {
                KeySyncCoordinationStatus::Resolved => {
                    if self.pending_key_update_ack_routes.is_empty()
                        && self.pending_key_sync_routes.is_empty()
                    {
                        return Ok(());
                    }
                    let deadline = *resolved_ack_deadline.get_or_insert_with(|| {
                        Instant::now() + Duration::from_millis(KEY_SYNC_RECOVERY_ACK_TIMEOUT_MS)
                    });
                    (deadline, RemoteRuntimeError::OutcomeUnknown)
                }
                KeySyncCoordinationStatus::Active => {
                    let now_ms = unix_time_ms()?;
                    state
                        .active_retry_at(now_ms)
                        .map_err(key_sync_runtime_error)?;
                    let remaining_ms = state
                        .deadline_at_ms()
                        .checked_sub(now_ms)
                        .ok_or_else(|| key_sync_runtime_error(KeySyncError::Exhausted))?;
                    let deadline = Instant::now()
                        .checked_add(Duration::from_millis(remaining_ms))
                        .ok_or(RemoteRuntimeError::InvalidDurableState)?;
                    (deadline, key_sync_runtime_error(KeySyncError::Exhausted))
                }
                KeySyncCoordinationStatus::AwaitingProbe => {
                    return Err(RemoteRuntimeError::InvalidDurableState);
                }
                KeySyncCoordinationStatus::Exhausted => {
                    return Err(key_sync_runtime_error(KeySyncError::Exhausted));
                }
            };

            let received = match tokio::time::timeout_at(deadline, self.transport.recv()).await {
                Ok(received) => received?,
                Err(_) => return Err(timeout_error),
            }
            .ok_or(RemoteRuntimeError::OutcomeUnknown)?;
            validate_received_runtime_frame(&received)?;
            let (frame, _) = received.into_parts();
            match frame.body {
                RelayFrameBody::RouteAccepted(accepted) => {
                    let AcceptedRef::Request { request_route } = accepted.accepted else {
                        return Err(RemoteRuntimeError::InvalidReply(
                            "KeySync recovery RouteAccepted must reference a request route",
                        ));
                    };
                    if self
                        .consume_key_control_route_accepted(request_route)
                        .is_none()
                    {
                        return Err(RemoteRuntimeError::InvalidReply(
                            "KeySync recovery received an unrelated RouteAccepted",
                        ));
                    }
                }
                RelayFrameBody::Reply(reply) => {
                    self.handle_key_sync_reply(reply).await?;
                    let next_state = self
                        .machine
                        .durable_key_sync_state()?
                        .ok_or(RemoteRuntimeError::InvalidDurableState)?;
                    if next_state.status() == KeySyncCoordinationStatus::Resolved {
                        resolved_ack_deadline = None;
                    }
                }
                _ => {
                    return Err(RemoteRuntimeError::InvalidReply(
                        "unexpected Relay frame during KeySync cold recovery",
                    ));
                }
            }
        }
    }

    fn durable_pending_exchange_route(&self) -> Result<Option<RequestRouteId>, RemoteRuntimeError> {
        let exchange = self
            .machine
            .opaque_runtime_state()
            .exchange()
            .map(decode_exchange)
            .transpose()?;
        Ok(match exchange {
            Some(DurableExchange::Pending(pending)) => Some(pending.request_route),
            Some(DurableExchange::Terminal(_)) | None => None,
        })
    }

    fn fresh_request_route_in_use(
        &self,
        request_route: RequestRouteId,
    ) -> Result<bool, RemoteRuntimeError> {
        let active_key_sync_route = self
            .machine
            .durable_key_sync_state()?
            .and_then(|state| state.active_send().map(FrozenKeySyncSendV1::request_route));
        Ok(request_route_is_owned(
            request_route,
            &self.pending_key_update_ack_routes,
            &self.pending_key_sync_routes,
            active_key_sync_route,
            self.durable_pending_exchange_route()?,
        ))
    }

    fn ensure_fresh_request_route_available(
        &self,
        request_route: RequestRouteId,
    ) -> Result<(), RemoteRuntimeError> {
        if self.fresh_request_route_in_use(request_route)? {
            return Err(RemoteRuntimeError::EntropyUnavailable);
        }
        Ok(())
    }

    fn ensure_new_key_sync_route_available(
        &self,
        request_route: RequestRouteId,
    ) -> Result<(), RemoteRuntimeError> {
        self.ensure_fresh_request_route_available(request_route)?;
        if self.pending_key_sync_routes.len() >= MAX_PENDING_KEY_SYNC_ROUTES {
            return Err(RemoteRuntimeError::PendingIntentConflict);
        }
        Ok(())
    }

    fn preflight_key_sync_probe_send(
        &self,
        active: &FrozenKeySyncSendV1,
        attempt: u8,
    ) -> Result<(), RemoteRuntimeError> {
        if active.request().attempt != attempt
            || self
                .machine
                .durable_key_sync_state()?
                .and_then(|state| state.active_send().map(FrozenKeySyncSendV1::request_route))
                != Some(active.request_route())
        {
            return Err(RemoteRuntimeError::InvalidDurableState);
        }
        if self
            .pending_key_update_ack_routes
            .contains_key(&active.request_route())
            || self.durable_pending_exchange_route()? == Some(active.request_route())
        {
            return Err(RemoteRuntimeError::PendingIntentConflict);
        }
        match self.pending_key_sync_routes.get(&active.request_route()) {
            Some(pending) => {
                if pending.attempt != attempt {
                    return Err(RemoteRuntimeError::InvalidDurableState);
                }
                if pending.outstanding_acceptances >= MAX_PENDING_KEY_SYNC_ACCEPTANCES_PER_ROUTE {
                    return Err(RemoteRuntimeError::PendingIntentConflict);
                }
            }
            None if self.pending_key_sync_routes.len() >= MAX_PENDING_KEY_SYNC_ROUTES => {
                return Err(RemoteRuntimeError::PendingIntentConflict);
            }
            None => {}
        }
        Ok(())
    }

    fn register_successful_key_sync_probe_send(
        &mut self,
        request_route: RequestRouteId,
        attempt: u8,
    ) {
        if let Some(pending) = self.pending_key_sync_routes.get_mut(&request_route) {
            debug_assert_eq!(pending.attempt, attempt);
            debug_assert!(
                pending.outstanding_acceptances < MAX_PENDING_KEY_SYNC_ACCEPTANCES_PER_ROUTE
            );
            pending.outstanding_acceptances += 1;
        } else {
            debug_assert!(self.pending_key_sync_routes.len() < MAX_PENDING_KEY_SYNC_ROUTES);
            self.pending_key_sync_routes.insert(
                request_route,
                PendingKeySyncRoute {
                    attempt,
                    outstanding_acceptances: 1,
                },
            );
        }
    }

    async fn send_key_sync_probe(
        &mut self,
        active: &FrozenKeySyncSendV1,
        attempt: u8,
    ) -> Result<(), RemoteRuntimeError> {
        self.preflight_key_sync_probe_send(active, attempt)?;
        let request_route = active.request_route();
        let exact_send = ExactRelayFrame::from_frozen(active.exact_send_bytes().to_vec())?;
        self.transport.send(exact_send).await?;
        self.register_successful_key_sync_probe_send(request_route, attempt);
        Ok(())
    }

    async fn send_key_update_ack(
        &mut self,
        ack: &KeyUpdateAckV1,
    ) -> Result<RequestRouteId, RemoteRuntimeError> {
        if self.pending_key_update_ack_routes.len() >= MAX_PENDING_KEY_UPDATE_ACK_ROUTES {
            return Err(RemoteRuntimeError::PendingIntentConflict);
        }
        let mut mutation_rng = SystemMutationRng::new()?;
        let reservation = self
            .machine
            .reserve_command_counter_block(&mut mutation_rng)?;
        let request_route = RequestRouteId::from_bytes(random_nonzero::<16, _>(&mut mutation_rng)?);
        self.ensure_fresh_request_route_available(request_route)?;
        let signed = self
            .machine
            .seal_key_update_ack(request_route, ack, reservation)?;
        let exact_send = self.encode_key_control_send(request_route, signed)?;
        self.transport
            .send(ExactRelayFrame::from_frozen(exact_send)?)
            .await?;
        self.pending_key_update_ack_routes
            .insert(request_route, ack.key_directory_revision);
        Ok(request_route)
    }

    fn consume_key_control_route_accepted(
        &mut self,
        request_route: RequestRouteId,
    ) -> Option<RemoteStreamFrameOutcome> {
        if let Some(revision) = self.pending_key_update_ack_routes.remove(&request_route) {
            return Some(RemoteStreamFrameOutcome::KeyUpdateAckRouteAccepted {
                key_directory_revision: revision.value(),
            });
        }
        let pending = self.pending_key_sync_routes.get_mut(&request_route)?;
        let attempt = pending.attempt;
        pending.outstanding_acceptances -= 1;
        if pending.outstanding_acceptances == 0 {
            self.pending_key_sync_routes.remove(&request_route);
        }
        Some(RemoteStreamFrameOutcome::KeySyncRouteAccepted { attempt })
    }

    /// ACK Send 完成后恢复 bounded continuation。AwaitingProbe 先使用新 command key reserve
    /// counter，再冻结并 CAS ADKS，最后发送；已冻结的 Active probe 只做 exact retry。
    async fn continue_key_sync_after_ack(
        &mut self,
        state: DurableKeySyncStateV1,
    ) -> Result<Option<u8>, RemoteRuntimeError> {
        match state.status() {
            KeySyncCoordinationStatus::Resolved => Ok(None),
            KeySyncCoordinationStatus::Exhausted => {
                Err(key_sync_runtime_error(KeySyncError::Exhausted))
            }
            KeySyncCoordinationStatus::Active => {
                let now_ms = unix_time_ms()?;
                let active = state
                    .active_retry_at(now_ms)
                    .map_err(key_sync_runtime_error)?;
                let attempt = state.attempt();
                self.send_key_sync_probe(active, attempt).await?;
                Ok(Some(attempt))
            }
            KeySyncCoordinationStatus::AwaitingProbe => {
                let now_ms = unix_time_ms()?;
                let request = state
                    .next_request_at(now_ms)
                    .map_err(key_sync_runtime_error)?;
                let mut mutation_rng = SystemMutationRng::new()?;
                let reservation = self
                    .machine
                    .reserve_command_counter_block(&mut mutation_rng)?;
                let request_route =
                    RequestRouteId::from_bytes(random_nonzero::<16, _>(&mut mutation_rng)?);
                self.ensure_new_key_sync_route_available(request_route)?;
                let signed =
                    self.machine
                        .seal_key_sync_request(request_route, &request, reservation)?;
                let exact_send = self.encode_key_control_send(request_route, signed)?;
                let frozen = FrozenKeySyncSendV1::new(request, exact_send)
                    .map_err(key_sync_runtime_error)?;
                let mut replacement = state.clone();
                replacement
                    .freeze_next_probe(now_ms, frozen)
                    .map_err(key_sync_runtime_error)?;
                let committed = self
                    .machine
                    .commit_key_sync_state_transition(
                        Some(&state),
                        Some(&replacement),
                        &mut mutation_rng,
                    )?
                    .ok_or(RemoteRuntimeError::InvalidDurableState)?;
                let active = committed
                    .active_send()
                    .ok_or(RemoteRuntimeError::InvalidDurableState)?;
                let attempt = committed.attempt();
                self.send_key_sync_probe(active, attempt).await?;
                Ok(Some(attempt))
            }
        }
    }

    fn encode_key_control_send(
        &self,
        request_route: RequestRouteId,
        sealed_blob: Vec<u8>,
    ) -> Result<Vec<u8>, RemoteRuntimeError> {
        let exact_send = encode(&OpaqueRouteFrame {
            version: RELAY_PROTOCOL_VERSION,
            body: RelayFrameBody::Send(RelaySend {
                device_route: self.machine.device_route(),
                request_route,
                sealed_blob: SealedBlob(sealed_blob),
            }),
        });
        let _ = decode(&exact_send)?;
        Ok(exact_send)
    }

    async fn coordinate_key_sync(
        &mut self,
        observation: SignedHigherRevisionObservationV1,
    ) -> Result<RemoteStreamFrameOutcome, RemoteRuntimeError> {
        let now_ms = unix_time_ms()?;
        let current = self.machine.durable_key_sync_state()?;
        let committed = if let Some(current) = current {
            match current.status() {
                KeySyncCoordinationStatus::AwaitingProbe => {
                    if current.observation() != &observation {
                        return Err(RemoteRuntimeError::InvalidReply(
                            "higher-revision publication conflicts with pending KeySync continuation",
                        ));
                    }
                    self.resume_pending_key_update_ack().await?;
                    let resumed = self
                        .machine
                        .durable_key_sync_state()?
                        .ok_or(RemoteRuntimeError::InvalidDurableState)?;
                    let active = resumed
                        .active_send()
                        .ok_or(RemoteRuntimeError::InvalidDurableState)?;
                    return Ok(RemoteStreamFrameOutcome::KeySyncPending {
                        attempt: active.request().attempt,
                    });
                }
                KeySyncCoordinationStatus::Resolved
                    if current.observation() == &observation =>
                {
                    let revision = current
                        .latest_completed_ack_basis()
                        .ok_or(RemoteRuntimeError::InvalidDurableState)?
                        .key_directory_revision();
                    // 同一 higher Publish 在 barrier/apply 前重放，只触发 canonical ACK
                    // 重封；不能重置 30 秒窗口或伪造一轮新的 KeySync。
                    self.resume_pending_key_update_ack().await?;
                    return Ok(RemoteStreamFrameOutcome::KeyUpdateInstalled {
                        key_directory_revision: revision.value(),
                        next_attempt: None,
                    });
                }
                KeySyncCoordinationStatus::Resolved => {
                    // 新 signed observation 是唯一允许 supersede Resolved ADKS 的输入。
                    // 先只读验证，随后必须先重发旧 ACK；只有 ACK Send 成功后，才允许
                    // durable 冻结从刚安装 revision 出发的新 attempt-1 probe。
                    current
                        .next_cycle_request(&observation, now_ms)
                        .map_err(key_sync_runtime_error)?;
                    self.resume_pending_key_update_ack().await?;
                    let started_at_ms = unix_time_ms()?;
                    let request = current
                        .next_cycle_request(&observation, started_at_ms)
                        .map_err(key_sync_runtime_error)?;
                    let mut mutation_rng = SystemMutationRng::new()?;
                    let reservation = self
                        .machine
                        .reserve_command_counter_block(&mut mutation_rng)?;
                    let request_route =
                        RequestRouteId::from_bytes(random_nonzero::<16, _>(&mut mutation_rng)?);
                    self.ensure_new_key_sync_route_available(request_route)?;
                    let signed = self.machine.seal_key_sync_request(
                        request_route,
                        &request,
                        reservation,
                    )?;
                    let exact_send = self.encode_key_control_send(request_route, signed)?;
                    let frozen = FrozenKeySyncSendV1::new(request, exact_send)
                        .map_err(key_sync_runtime_error)?;
                    let replacement = current
                        .start_next_cycle(observation, started_at_ms, frozen)
                        .map_err(key_sync_runtime_error)?;
                    self.machine.commit_key_sync_state_transition(
                        Some(&current),
                        Some(&replacement),
                        &mut mutation_rng,
                    )?
                }
                KeySyncCoordinationStatus::Exhausted => {
                    return Err(key_sync_runtime_error(KeySyncError::Exhausted));
                }
                KeySyncCoordinationStatus::Active => {
                    if current.latest_completed_ack_basis().is_some() {
                        if current.observation() != &observation {
                            return Err(RemoteRuntimeError::InvalidReply(
                                "higher-revision publication conflicts with a frozen KeySync continuation",
                            ));
                        }
                        // Crash may happen after install/new-cycle CAS but before either ACK or
                        // frozen probe reaches transport. Durable completion/retained basis must
                        // be re-ACKed first; only then exact-retry the already frozen probe.
                        self.resume_pending_key_update_ack().await?;
                        return Ok(RemoteStreamFrameOutcome::KeySyncPending {
                            attempt: current.attempt(),
                        });
                    }
                    let mut replacement = current.clone();
                    replacement
                        .observe_again(&observation, now_ms)
                        .map_err(key_sync_runtime_error)?;
                    let mut mutation_rng = SystemMutationRng::new()?;
                    self.machine.commit_key_sync_state_transition(
                        Some(&current),
                        Some(&replacement),
                        &mut mutation_rng,
                    )?
                }
            }
        } else {
            // CounterGuard 的 durable high-water 必须先于 requestRoute、seal/freeze 与 ADKS。
            // 此后任一失败只允许跳过整个 reservation block，绝不回退或复用 counter。
            let mut mutation_rng = SystemMutationRng::new()?;
            let reservation = self
                .machine
                .reserve_command_counter_block(&mut mutation_rng)?;
            let request = observation
                .request_for_attempt(1)
                .map_err(key_sync_runtime_error)?;
            let request_route =
                RequestRouteId::from_bytes(random_nonzero::<16, _>(&mut mutation_rng)?);
            self.ensure_new_key_sync_route_available(request_route)?;
            let signed =
                self.machine
                    .seal_key_sync_request(request_route, &request, reservation)?;
            let exact_send = encode(&OpaqueRouteFrame {
                version: RELAY_PROTOCOL_VERSION,
                body: RelayFrameBody::Send(RelaySend {
                    device_route: self.machine.device_route(),
                    request_route,
                    sealed_blob: SealedBlob(signed),
                }),
            });
            let _ = decode(&exact_send)?;
            let frozen =
                FrozenKeySyncSendV1::new(request, exact_send).map_err(key_sync_runtime_error)?;
            let replacement = DurableKeySyncStateV1::start(observation, now_ms, frozen)
                .map_err(key_sync_runtime_error)?;
            self.machine.commit_key_sync_state_transition(
                None,
                Some(&replacement),
                &mut mutation_rng,
            )?
        }
        .ok_or(RemoteRuntimeError::InvalidDurableState)?;
        let active = committed
            .active_send()
            .ok_or(RemoteRuntimeError::InvalidDurableState)?;
        let attempt = committed.attempt();
        self.send_key_sync_probe(active, attempt).await?;
        Ok(RemoteStreamFrameOutcome::KeySyncPending { attempt })
    }

    /// 发送或精确重试一个 prompt，直到得到 authenticated daemon receipt 或非成功错误。
    pub async fn prompt<R: CryptoRng>(
        &mut self,
        request: SendPromptRequest,
        rng: &mut R,
    ) -> Result<RemotePromptOutcome, RemoteRuntimeError> {
        let outcome = directed_receipt_outcome(
            self.directed_exchange(DirectedRequestPlan::prompt(request)?, rng)
                .await?,
        )?;
        let DirectedReceipt::Command(receipt) = outcome.receipt else {
            return Err(RemoteRuntimeError::InvalidDurableState);
        };
        Ok(RemotePromptOutcome {
            route_accepted: outcome.route_accepted,
            receipt,
        })
    }

    /// 提交 first-wins approval 决定；只有匹配的 authenticated ApprovalReceipt 才完成。
    pub async fn resolve_approval<R: CryptoRng>(
        &mut self,
        conversation_id: ConversationId,
        turn_id: TurnId,
        approval_id: ApprovalId,
        decision: ActionDecision,
        rng: &mut R,
    ) -> Result<RemoteApprovalOutcome, RemoteRuntimeError> {
        let outcome = directed_receipt_outcome(
            self.directed_exchange(
                DirectedRequestPlan::resolve_approval(
                    conversation_id,
                    turn_id,
                    approval_id,
                    decision,
                )?,
                rng,
            )
            .await?,
        )?;
        let DirectedReceipt::Approval(receipt) = outcome.receipt else {
            return Err(RemoteRuntimeError::InvalidDurableState);
        };
        Ok(RemoteApprovalOutcome {
            route_accepted: outcome.route_accepted,
            receipt,
        })
    }

    /// 重试 daemon 已 durable claim 的同一 approval 决定，不允许携带替换决定。
    pub async fn retry_approval<R: CryptoRng>(
        &mut self,
        conversation_id: ConversationId,
        approval_id: ApprovalId,
        rng: &mut R,
    ) -> Result<RemoteApprovalOutcome, RemoteRuntimeError> {
        let outcome = directed_receipt_outcome(
            self.directed_exchange(
                DirectedRequestPlan::retry_approval(conversation_id, approval_id)?,
                rng,
            )
            .await?,
        )?;
        let DirectedReceipt::Approval(receipt) = outcome.receipt else {
            return Err(RemoteRuntimeError::InvalidDurableState);
        };
        Ok(RemoteApprovalOutcome {
            route_accepted: outcome.route_accepted,
            receipt,
        })
    }

    /// 逐字节发送或恢复同一 self-revoke intent，并消费整个 Runtime capability。
    ///
    /// authenticated daemon `RevocationReceipt::Committed` 只说明 daemon 已观察到 Relay
    /// COMMIT，不是本机删 key 的授权，也不会覆盖 durable pending Send。只有 active
    /// connection 收到的 exact MachineRoot-signed `RevocationCommitted` 才能触发 cleanup。
    /// 所有返回路径都先等待 transport shutdown；成功路径再显式 drop transport，最后消费
    /// paired machine 完成 crash-safe cleanup。
    pub async fn revoke_self<R: CryptoRng>(
        mut self,
        rng: &mut R,
    ) -> Result<RemoteRevocationOutcome, RemoteRuntimeError> {
        let expected_grant_serial = self.machine.grant_serial();
        let result = match DirectedRequestPlan::revoke_self(expected_grant_serial) {
            Ok(plan) => self.directed_exchange(plan, rng).await,
            Err(error) => Err(error),
        };
        self.transport.shutdown().await;

        let DirectedExchangeResult::RevocationTerminal {
            route_accepted,
            terminal,
        } = result?
        else {
            return Err(RemoteRuntimeError::InvalidDurableState);
        };
        let grant_serial = terminal.grant_serial();
        if grant_serial != expected_grant_serial {
            return Err(RemoteRuntimeError::InvalidReply(
                "revocation terminal grant serial does not match the paired machine",
            ));
        }

        let Self {
            transport, machine, ..
        } = self;
        drop(transport);
        machine.commit_revocation_cleanup(terminal)?;
        Ok(RemoteRevocationOutcome {
            route_accepted,
            receipt: RevocationReceipt::Committed {
                grant_serial: RuntimeGrantSerial::new(grant_serial.value()),
            },
        })
    }

    async fn directed_exchange<R: CryptoRng>(
        &mut self,
        plan: DirectedRequestPlan,
        rng: &mut R,
    ) -> Result<DirectedExchangeResult, RemoteRuntimeError> {
        let existing = self
            .machine
            .opaque_runtime_state()
            .exchange()
            .map(decode_exchange)
            .transpose()?;
        let pending =
            match select_exchange_start(existing, plan, |plan| self.prepare_pending(plan, rng))? {
                ExchangeStart::Pending(pending) => pending,
                ExchangeStart::Terminal(receipt) => {
                    return directed_outcome(false, receipt).map(DirectedExchangeResult::Receipt);
                }
            };

        self.reject_quarantined_current_reply_scope()?;
        let pending_send = decode_pending_send(&pending, self.machine.device_route())?;

        // Durable pending 保存的是完整 Relay codec bytes；每次发送都从 exact bytes 解码，
        // 避免重启后重新 seal/sign 或重建任一随机字段。
        self.transport
            .send(ExactRelayFrame::from_frozen(pending.exact_send.clone())?)
            .await?;

        let mut route_accepted = false;
        let transfer_started_at = Instant::now();
        let mut reply_transfers = TransferReassembler::new();
        let mut active_reply_transfers = HashMap::new();
        loop {
            let Some(received) = self
                .recv_with_transfer_deadline(&active_reply_transfers)
                .await?
            else {
                return Err(RemoteRuntimeError::OutcomeUnknown);
            };
            validate_received_runtime_frame(&received)?;
            let reply_frame_hash = sha256(received.canonical_bytes());
            let frame = received.frame();
            match &frame.body {
                RelayFrameBody::RouteAccepted(accepted) => {
                    let AcceptedRef::Request { request_route } = accepted.accepted else {
                        return Err(RemoteRuntimeError::InvalidReply(
                            "RouteAccepted does not match the pending request",
                        ));
                    };
                    if request_route == pending.request_route {
                        route_accepted = true;
                    } else if self
                        .consume_key_control_route_accepted(request_route)
                        .is_none()
                    {
                        return Err(RemoteRuntimeError::InvalidReply(
                            "RouteAccepted does not match the pending request",
                        ));
                    }
                }
                RelayFrameBody::Reply(reply) => {
                    if reply.device_route != self.machine.device_route()
                        || reply.request_route != pending.request_route
                    {
                        return Err(RemoteRuntimeError::InvalidReply(
                            "Reply outer route does not match the pending request",
                        ));
                    }
                    let candidate = self.machine.verify_directed_reply(
                        pending.request_route,
                        &pending_send.sealed_blob.0,
                        &reply.sealed_blob.0,
                    )?;

                    // MachineDataSign 成功后、AEAD 前 durable consume replay tuple。即使后续
                    // ciphertext/tag 失败，同 counter 的另一 signed ciphertext 也不能重试。
                    self.admit_reply_replay(&candidate)?;
                    let opened = self
                        .machine
                        .open_verified_directed_reply(&pending_send.sealed_blob.0, candidate)?;
                    if opened.payload_kind == SealedPayloadKind::TransferPart {
                        if !matches!(pending.operation, DirectedOperation::Catalog { .. }) {
                            return Err(RemoteRuntimeError::InvalidReply(
                                "directed transfer reply does not match the pending request",
                            ));
                        }
                        let carrier = RuntimeTransferCarrierV1::decode(&opened.payload)
                            .map_err(map_transfer_carrier_error)?;
                        if carrier.channel != RuntimeTransferChannel::Reply {
                            return Err(RemoteRuntimeError::InvalidReply(
                                "directed transfer carrier is not on the Reply channel",
                            ));
                        }
                        if carrier.message_id != pending.message_id {
                            return Err(RemoteRuntimeError::InvalidReply(
                                "directed transfer messageId does not match the pending request",
                            ));
                        }
                        let transfer_id = carrier.transfer.transfer_id.clone();
                        let now_ms = u64::try_from(transfer_started_at.elapsed().as_millis())
                            .unwrap_or(u64::MAX);
                        match reply_transfers.accept(
                            RuntimeTransferChannel::Reply,
                            carrier.transfer,
                            now_ms,
                        )? {
                            TransferProgress::InProgress { .. } => {
                                active_reply_transfers
                                    .entry(transfer_id)
                                    .or_insert_with(Instant::now);
                                continue;
                            }
                            TransferProgress::AlreadyComplete => {
                                return Err(RemoteRuntimeError::InvalidReply(
                                    "directed transfer completed more than once",
                                ));
                            }
                            TransferProgress::Complete(payload) => {
                                active_reply_transfers.remove(&transfer_id);
                                let catalog_payload_len = payload.len();
                                let snapshot = canonical_json::<CatalogSnapshot>(&payload).ok_or(
                                    RemoteRuntimeError::InvalidReply(
                                        "Catalog transfer is not one canonical snapshot",
                                    ),
                                )?;
                                let validated = pending.operation.validate_reply(
                                    SealedPayloadKind::CatalogSnapshot,
                                    RuntimeReply::Catalog(snapshot),
                                )?;
                                let ValidatedDirectedReply::Terminal(receipt) = validated else {
                                    return Err(RemoteRuntimeError::InvalidReply(
                                        "Catalog transfer did not produce a terminal reply",
                                    ));
                                };
                                let terminal_persisted = self
                                    .persist_or_clear_large_catalog_terminal(
                                        &pending,
                                        reply_frame_hash,
                                        &receipt,
                                        Some(catalog_payload_len),
                                    )?;
                                return directed_outcome_with_persistence(
                                    route_accepted,
                                    receipt,
                                    terminal_persisted,
                                )
                                .map(DirectedExchangeResult::Receipt);
                            }
                        }
                    }
                    if !pending
                        .operation
                        .accepts_json_payload_kind(opened.payload_kind)
                    {
                        return Err(RemoteRuntimeError::InvalidReply(
                            "directed reply payload kind does not match the pending request",
                        ));
                    }
                    if opened.payload.len() >= MAX_RUNTIME_JSON_FRAME_BYTES {
                        return Err(RemoteRuntimeError::InvalidReply(
                            "Runtime reply exceeds the JSON frame limit",
                        ));
                    }
                    let envelope = canonical_json::<RuntimeEnvelope>(&opened.payload).ok_or(
                        RemoteRuntimeError::InvalidReply(
                            "Runtime reply is not one canonical JSON envelope",
                        ),
                    )?;
                    if envelope.message_id != pending.message_id {
                        return Err(RemoteRuntimeError::InvalidReply(
                            "Runtime messageId does not match the pending request",
                        ));
                    }
                    let RuntimeMessage::Reply(reply) = envelope.body else {
                        return Err(RemoteRuntimeError::InvalidReply(
                            "Runtime envelope is not a reply",
                        ));
                    };
                    match pending
                        .operation
                        .validate_reply(opened.payload_kind, reply)?
                    {
                        ValidatedDirectedReply::Terminal(receipt) => {
                            let terminal_persisted = self.persist_or_clear_large_catalog_terminal(
                                &pending,
                                reply_frame_hash,
                                &receipt,
                                None,
                            )?;
                            return directed_outcome_with_persistence(
                                route_accepted,
                                receipt,
                                terminal_persisted,
                            )
                            .map(DirectedExchangeResult::Receipt);
                        }
                        ValidatedDirectedReply::SelfRevocationCommitted => {}
                    }
                }
                RelayFrameBody::RevocationCommitted(_)
                    if matches!(pending.operation, DirectedOperation::RevokeSelf { .. }) =>
                {
                    let terminal = self
                        .machine
                        .verify_revocation_terminal(frame, received.canonical_bytes())?;
                    return Ok(DirectedExchangeResult::RevocationTerminal {
                        route_accepted,
                        terminal,
                    });
                }
                _ => {
                    return Err(RemoteRuntimeError::InvalidReply(
                        "unexpected Relay frame while awaiting command receipt",
                    ));
                }
            }
        }
    }

    async fn send_stream_binding_controls(
        &mut self,
        durable: &DurableStreamBindingV1,
    ) -> Result<(), RemoteRuntimeError> {
        let binding = durable.binding();
        let outer_applied = durable.outer_applied();
        for retired in durable.retired_subscriptions() {
            let unsubscribe = OpaqueRouteFrame {
                version: RELAY_PROTOCOL_VERSION,
                body: RelayFrameBody::Unsubscribe(RelayUnsubscribe {
                    stream_route: retired.stream_route(),
                    generation: retired.stream_generation(),
                }),
            };
            let unsubscribe = encode(&unsubscribe);
            let _ = decode(&unsubscribe)?;
            self.transport
                .send(ExactRelayFrame::from_frozen(unsubscribe)?)
                .await?;
        }
        let subscribe = OpaqueRouteFrame {
            version: RELAY_PROTOCOL_VERSION,
            body: RelayFrameBody::Subscribe(RelaySubscribe {
                stream_route: binding.stream_route,
                generation: binding.stream_generation,
                cursor: outer_applied,
            }),
        };
        let subscribe = encode(&subscribe);
        let _ = decode(&subscribe)?;
        self.transport
            .send(ExactRelayFrame::from_frozen(subscribe)?)
            .await?;

        if matches!(outer_applied, StreamCursor::At(_)) {
            self.send_stream_ack(durable).await?;
        }
        Ok(())
    }

    fn stream_binding_for_route(
        &self,
        stream_route: StreamRouteId,
        generation: StreamGenerationId,
    ) -> Result<DurableStreamBindingV1, RemoteRuntimeError> {
        let mut matching = self
            .machine
            .durable_stream_bindings()?
            .into_iter()
            .filter(|state| {
                state.binding().stream_route == stream_route
                    && state.binding().stream_generation == generation
            });
        let durable = matching.next().ok_or(RemoteRuntimeError::InvalidReply(
            "stream frame route/generation is not an installed durable binding",
        ))?;
        if matching.next().is_some() {
            return Err(RemoteRuntimeError::InvalidDurableState);
        }
        Ok(durable)
    }

    async fn send_stream_ack(
        &mut self,
        durable: &DurableStreamBindingV1,
    ) -> Result<(), RemoteRuntimeError> {
        let StreamCursor::At(up_to_seq) = durable.outer_applied() else {
            return Err(RemoteRuntimeError::InvalidDurableState);
        };
        let binding = durable.binding();
        let ack = OpaqueRouteFrame {
            version: RELAY_PROTOCOL_VERSION,
            body: RelayFrameBody::Ack(RelayAck {
                stream_route: binding.stream_route,
                generation: binding.stream_generation,
                up_to_seq,
            }),
        };
        let ack = encode(&ack);
        let _ = decode(&ack)?;
        self.transport
            .send(ExactRelayFrame::from_frozen(ack)?)
            .await?;
        let mut mutation_rng = SystemMutationRng::new()?;
        let _ = self
            .machine
            .commit_stream_ack(durable, up_to_seq, &mut mutation_rng)?;
        Ok(())
    }

    fn prepare_pending<R: CryptoRng>(
        &mut self,
        plan: DirectedRequestPlan,
        rng: &mut R,
    ) -> Result<PendingExchange, RemoteRuntimeError> {
        let request_route = RequestRouteId::from_bytes(random_nonzero::<16, _>(rng)?);
        self.ensure_fresh_request_route_available(request_route)?;
        let message_id = MessageId::new(
            Uuid::from_bytes(random_nonzero::<16, _>(rng)?)
                .hyphenated()
                .to_string(),
        );
        let reservation = self.machine.reserve_command_counter_block(rng)?;
        let signed = self.machine.seal_runtime_request(
            request_route,
            message_id.clone(),
            plan.request,
            reservation,
        )?;
        let frame = OpaqueRouteFrame {
            version: RELAY_PROTOCOL_VERSION,
            body: RelayFrameBody::Send(RelaySend {
                device_route: self.machine.device_route(),
                request_route,
                sealed_blob: SealedBlob(signed),
            }),
        };
        let exact_send = encode(&frame);
        // 编码后立即走严格 decoder，确保只把 canonical production frame 冻结进 durable state。
        let _ = decode(&exact_send)?;
        let pending = PendingExchange {
            operation: plan.operation,
            intent_hash: plan.intent_hash,
            message_id,
            request_route,
            exact_send,
        };
        self.persist_exchange(DurableExchange::Pending(pending.clone()))?;
        Ok(pending)
    }

    fn admit_reply_replay(
        &mut self,
        candidate: &VerifiedDirectedReply,
    ) -> Result<(), RemoteRuntimeError> {
        let (current_key_epoch, _current_directory_revision) =
            self.machine.directed_reply_scope()?;
        let replay_revision_ceiling = candidate.replay_revision_ceiling();
        if candidate.key_epoch() != current_key_epoch
            || candidate.directory_revision() == 0
            || candidate.directory_revision() > replay_revision_ceiling
        {
            return Err(RemoteRuntimeError::ReplayRejected);
        }
        let current = self.machine.opaque_runtime_state();
        let mut windows = current
            .replay_windows()
            .iter()
            .map(|bytes| decode_replay_window(bytes))
            .collect::<Result<Vec<_>, _>>()?;
        if windows.len() > MAX_REPLAY_WINDOWS {
            return Err(RemoteRuntimeError::InvalidDurableState);
        }
        let matching = windows
            .iter()
            .enumerate()
            .filter_map(|(index, window)| {
                (window.key_epoch == candidate.key_epoch()).then_some(index)
            })
            .collect::<Vec<_>>();
        if matching.len() > 1 {
            return Err(RemoteRuntimeError::InvalidDurableState);
        }
        let hash = candidate.signed_blob_hash();
        let mut revision_high_water_advanced = false;
        let admission = if let Some(index) = matching.first().copied() {
            let previous_revision = windows[index].directory_revision;
            if previous_revision > replay_revision_ceiling {
                return Err(RemoteRuntimeError::InvalidDurableState);
            }
            let admission = windows[index].observe_at_revision(
                replay_revision_ceiling,
                candidate.counter(),
                hash,
            )?;
            revision_high_water_advanced = windows[index].directory_revision != previous_revision;
            admission
        } else {
            if windows.len() >= MAX_REPLAY_WINDOWS {
                return Err(RemoteRuntimeError::ReplayRejected);
            }
            windows.push(ReplayWindow {
                key_epoch: candidate.key_epoch(),
                directory_revision: replay_revision_ceiling,
                nonce_reuse_quarantined: false,
                entries: vec![ReplayEntry {
                    counter: candidate.counter(),
                    signed_blob_hash: hash,
                }],
            });
            ReplayAdmission::Fresh
        };
        if admission == ReplayAdmission::ExactDuplicate && !revision_high_water_advanced {
            return Ok(());
        }
        let encoded = windows.iter().map(encode_replay_window).collect();
        self.replace_runtime_state(
            current.exchange().map(ToOwned::to_owned),
            encoded,
            current.stream_cursors().to_vec(),
        )?;
        match admission {
            ReplayAdmission::Fresh => Ok(()),
            ReplayAdmission::NonceReuse => Err(RemoteRuntimeError::NonceReuse),
            ReplayAdmission::ExactDuplicate => Ok(()),
        }
    }

    fn reject_quarantined_current_reply_scope(&self) -> Result<(), RemoteRuntimeError> {
        let (key_epoch, directory_revision) = self.machine.directed_reply_scope()?;
        let mut windows = Vec::new();
        for bytes in self.machine.opaque_runtime_state().replay_windows() {
            windows.push(decode_replay_window(bytes)?);
        }
        validate_current_reply_replay_scope(&windows, key_epoch, directory_revision)
    }

    fn persist_terminal(
        &mut self,
        pending: &PendingExchange,
        reply_frame_hash: [u8; 32],
        receipt: &DirectedReceipt,
    ) -> Result<(), RemoteRuntimeError> {
        self.persist_exchange(DurableExchange::Terminal(TerminalExchange {
            operation: pending.operation.clone(),
            intent_hash: pending.intent_hash,
            message_id: pending.message_id.clone(),
            request_route: pending.request_route,
            request_frame_hash: sha256(&pending.exact_send),
            reply_frame_hash,
            receipt: receipt.clone(),
        }))
    }

    /// Compact Catalog 页可达 64 MiB，而 paired opaque-state 单字段与 durable exchange
    /// terminal 都故意更小。只读大页完成完整认证与 canonical decode 后清掉 exact pending
    /// 再返回；进程若在清理前退出会 exact retry，清理后退出则由下次调用重新查询，不把
    /// 超界 plaintext 写成一个之后无法打开的 paired state。
    fn persist_or_clear_large_catalog_terminal(
        &mut self,
        pending: &PendingExchange,
        reply_frame_hash: [u8; 32],
        receipt: &DirectedReceipt,
        compact_catalog_payload_len: Option<usize>,
    ) -> Result<bool, RemoteRuntimeError> {
        // `DirectedReceipt` adds a small tagged wrapper around CatalogSnapshot. Keep a
        // conservative margin so every persisted terminal remains decodable without allocating
        // another copy of a potentially 64 MiB compact payload merely to measure that wrapper.
        let oversized_catalog = matches!(receipt, DirectedReceipt::Catalog(_))
            && compact_catalog_payload_len
                .is_some_and(|len| len > MAX_RUNTIME_JSON_FRAME_BYTES.saturating_sub(128));
        if oversized_catalog {
            self.clear_exact_pending(pending)?;
            Ok(false)
        } else {
            self.persist_terminal(pending, reply_frame_hash, receipt)?;
            Ok(true)
        }
    }

    fn clear_exact_pending(
        &mut self,
        expected: &PendingExchange,
    ) -> Result<(), RemoteRuntimeError> {
        let current = self.machine.opaque_runtime_state();
        let exchange = current
            .exchange()
            .ok_or(RemoteRuntimeError::InvalidDurableState)
            .and_then(decode_exchange)?;
        let DurableExchange::Pending(pending) = exchange else {
            return Err(RemoteRuntimeError::InvalidDurableState);
        };
        if pending.operation != expected.operation
            || pending.intent_hash != expected.intent_hash
            || pending.message_id != expected.message_id
            || pending.request_route != expected.request_route
            || pending.exact_send != expected.exact_send
        {
            return Err(RemoteRuntimeError::InvalidDurableState);
        }
        self.replace_runtime_state(
            None,
            current.replay_windows().to_vec(),
            current.stream_cursors().to_vec(),
        )
    }

    fn persist_exchange(&mut self, exchange: DurableExchange) -> Result<(), RemoteRuntimeError> {
        let current = self.machine.opaque_runtime_state();
        self.replace_runtime_state(
            Some(encode_exchange(&exchange)?),
            current.replay_windows().to_vec(),
            current.stream_cursors().to_vec(),
        )
    }

    fn consume_catalog_terminal(
        &mut self,
        expected: &DirectedOperation,
    ) -> Result<(), RemoteRuntimeError> {
        let current = self.machine.opaque_runtime_state();
        let terminal = current
            .exchange()
            .ok_or(RemoteRuntimeError::InvalidDurableState)
            .and_then(decode_exchange)?;
        let DurableExchange::Terminal(terminal) = terminal else {
            return Err(RemoteRuntimeError::InvalidDurableState);
        };
        if &terminal.operation != expected
            || !matches!(
                terminal.receipt,
                DirectedReceipt::Catalog(_) | DirectedReceipt::Failure(_)
            )
        {
            return Err(RemoteRuntimeError::InvalidDurableState);
        }
        self.replace_runtime_state(
            None,
            current.replay_windows().to_vec(),
            current.stream_cursors().to_vec(),
        )
    }

    fn consume_subscription_failure_terminal(
        &mut self,
        expected: &DirectedOperation,
    ) -> Result<(), RemoteRuntimeError> {
        let current = self.machine.opaque_runtime_state();
        let terminal = current
            .exchange()
            .ok_or(RemoteRuntimeError::InvalidDurableState)
            .and_then(decode_exchange)?;
        let DurableExchange::Terminal(terminal) = terminal else {
            return Err(RemoteRuntimeError::InvalidDurableState);
        };
        if &terminal.operation != expected
            || !matches!(terminal.operation, DirectedOperation::Subscribe { .. })
            || !matches!(terminal.receipt, DirectedReceipt::Failure(_))
        {
            return Err(RemoteRuntimeError::InvalidDurableState);
        }
        self.replace_runtime_state(
            None,
            current.replay_windows().to_vec(),
            current.stream_cursors().to_vec(),
        )
    }

    fn replace_runtime_state(
        &mut self,
        exchange: Option<Vec<u8>>,
        replay_windows: Vec<Vec<u8>>,
        stream_cursors: Vec<Vec<u8>>,
    ) -> Result<(), RemoteRuntimeError> {
        let replacement = OpaqueRuntimeState::new(exchange, replay_windows, stream_cursors);
        let mut mutation_rng = SystemMutationRng::new()?;
        let _ = self
            .machine
            .replace_opaque_runtime_state(&replacement, &mut mutation_rng)?;
        Ok(())
    }
}

struct DirectedRequestPlan {
    operation: DirectedOperation,
    intent_hash: [u8; 32],
    request: AuthorizedRuntimeRequest,
}

impl DirectedRequestPlan {
    fn subscribe(inner_cursor: RuntimeInnerCursor) -> Result<Self, RemoteRuntimeError> {
        validate_inner_cursor(&inner_cursor)?;
        let wire = agentdeck_protocol::runtime::RuntimeRequest::Subscribe {
            inner_cursor: inner_cursor.clone(),
        };
        Ok(Self {
            operation: DirectedOperation::Subscribe {
                inner_cursor: inner_cursor.clone(),
            },
            intent_hash: runtime_request_intent_hash(SUBSCRIBE_INTENT_DOMAIN, &wire)?,
            request: AuthorizedRuntimeRequest::Subscribe(inner_cursor),
        })
    }

    fn catalog(page_cursor: Option<CatalogPageCursor>) -> Result<Self, RemoteRuntimeError> {
        let request = CatalogRequest { page_cursor };
        let wire = agentdeck_protocol::runtime::RuntimeRequest::Catalog(request.clone());
        Ok(Self {
            operation: DirectedOperation::Catalog {
                page_cursor: request.page_cursor.clone(),
            },
            intent_hash: runtime_request_intent_hash(CATALOG_INTENT_DOMAIN, &wire)?,
            request: AuthorizedRuntimeRequest::Catalog(request),
        })
    }

    fn prompt(request: SendPromptRequest) -> Result<Self, RemoteRuntimeError> {
        Ok(Self {
            operation: DirectedOperation::Prompt {
                expected_configuration_revision: request.expected_configuration_revision,
            },
            intent_hash: prompt_intent_hash(&request)?,
            request: AuthorizedRuntimeRequest::SendPrompt(request),
        })
    }

    fn resolve_approval(
        conversation_id: ConversationId,
        turn_id: TurnId,
        approval_id: ApprovalId,
        decision: ActionDecision,
    ) -> Result<Self, RemoteRuntimeError> {
        let wire = agentdeck_protocol::runtime::RuntimeRequest::ResolveApproval {
            conversation_id: conversation_id.clone(),
            turn_id: turn_id.clone(),
            approval_id: approval_id.clone(),
            decision: decision.clone(),
        };
        Ok(Self {
            operation: DirectedOperation::ResolveApproval {
                approval_id: approval_id.clone(),
            },
            intent_hash: runtime_request_intent_hash(RESOLVE_APPROVAL_INTENT_DOMAIN, &wire)?,
            request: AuthorizedRuntimeRequest::ResolveApproval {
                conversation_id,
                turn_id,
                approval_id,
                decision,
            },
        })
    }

    fn retry_approval(
        conversation_id: ConversationId,
        approval_id: ApprovalId,
    ) -> Result<Self, RemoteRuntimeError> {
        let wire = agentdeck_protocol::runtime::RuntimeRequest::RetryApproval {
            conversation_id: conversation_id.clone(),
            approval_id: approval_id.clone(),
        };
        Ok(Self {
            operation: DirectedOperation::RetryApproval {
                conversation_id: conversation_id.clone(),
                approval_id: approval_id.clone(),
                attempt: 1,
            },
            intent_hash: retry_approval_intent_hash(&wire, 1)?,
            request: AuthorizedRuntimeRequest::RetryApproval {
                conversation_id,
                approval_id,
            },
        })
    }

    fn revoke_self(grant_serial: RelayGrantSerial) -> Result<Self, RemoteRuntimeError> {
        if grant_serial == RelayGrantSerial::ZERO {
            return Err(RemoteRuntimeError::InvalidDurableState);
        }
        let wire = agentdeck_protocol::runtime::RuntimeRequest::Revoke(RevokeRequest {
            target: RevokeTarget::SelfDevice,
        });
        Ok(Self {
            operation: DirectedOperation::RevokeSelf { grant_serial },
            intent_hash: runtime_request_intent_hash(REVOKE_SELF_INTENT_DOMAIN, &wire)?,
            request: AuthorizedRuntimeRequest::RevokeSelf,
        })
    }

    /// `RetryApproval` 的 durable attempt 只在前一轮已有 authenticated terminal 后递增。
    /// outcome-unknown 的 pending 则沿用原 attempt，从而继续逐字节重发同一 frozen frame。
    fn align_retry_attempt(
        mut self,
        existing: Option<&DurableExchange>,
    ) -> Result<Self, RemoteRuntimeError> {
        let DirectedOperation::RetryApproval {
            conversation_id,
            approval_id,
            ..
        } = &self.operation
        else {
            return Ok(self);
        };
        let conversation_id = conversation_id.clone();
        let approval_id = approval_id.clone();
        let same_retry = |operation: &DirectedOperation| match operation {
            DirectedOperation::RetryApproval {
                conversation_id: stored_conversation,
                approval_id: stored_approval,
                ..
            } => stored_conversation == &conversation_id && stored_approval == &approval_id,
            DirectedOperation::Subscribe { .. }
            | DirectedOperation::Catalog { .. }
            | DirectedOperation::Prompt { .. }
            | DirectedOperation::ResolveApproval { .. }
            | DirectedOperation::RevokeSelf { .. } => false,
        };
        let attempt = match existing {
            Some(DurableExchange::Pending(pending)) if same_retry(&pending.operation) => {
                pending.operation.retry_attempt()?
            }
            Some(DurableExchange::Terminal(terminal)) if same_retry(&terminal.operation) => {
                terminal
                    .operation
                    .retry_attempt()?
                    .checked_add(1)
                    .ok_or(RemoteRuntimeError::InvalidDurableState)?
            }
            Some(DurableExchange::Pending(_)) | Some(DurableExchange::Terminal(_)) | None => 1,
        };
        let wire = agentdeck_protocol::runtime::RuntimeRequest::RetryApproval {
            conversation_id: conversation_id.clone(),
            approval_id: approval_id.clone(),
        };
        self.operation = DirectedOperation::RetryApproval {
            conversation_id,
            approval_id,
            attempt,
        };
        self.intent_hash = retry_approval_intent_hash(&wire, attempt)?;
        Ok(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum DirectedOperation {
    Subscribe {
        inner_cursor: RuntimeInnerCursor,
    },
    Catalog {
        page_cursor: Option<CatalogPageCursor>,
    },
    Prompt {
        expected_configuration_revision: u64,
    },
    ResolveApproval {
        approval_id: ApprovalId,
    },
    RetryApproval {
        conversation_id: ConversationId,
        approval_id: ApprovalId,
        attempt: u64,
    },
    RevokeSelf {
        grant_serial: RelayGrantSerial,
    },
}

impl DirectedOperation {
    fn accepts_json_payload_kind(&self, payload_kind: SealedPayloadKind) -> bool {
        match self {
            Self::Subscribe { .. } => matches!(
                payload_kind,
                SealedPayloadKind::CatalogSnapshot
                    | SealedPayloadKind::ConversationSnapshot
                    | SealedPayloadKind::BackfillChunk
                    | SealedPayloadKind::CommandReceipt
                    | SealedPayloadKind::KeyUpdate
                    | SealedPayloadKind::TransferPart
            ),
            Self::Catalog { .. } => matches!(
                payload_kind,
                SealedPayloadKind::CatalogSnapshot | SealedPayloadKind::CommandReceipt
            ),
            Self::Prompt { .. }
            | Self::ResolveApproval { .. }
            | Self::RetryApproval { .. }
            | Self::RevokeSelf { .. } => payload_kind == SealedPayloadKind::CommandReceipt,
        }
    }

    fn validate_reply(
        &self,
        payload_kind: SealedPayloadKind,
        reply: RuntimeReply,
    ) -> Result<ValidatedDirectedReply, RemoteRuntimeError> {
        match (self, reply) {
            (_, RuntimeReply::Failure(failure))
                if payload_kind == SealedPayloadKind::CommandReceipt =>
            {
                Ok(ValidatedDirectedReply::Terminal(DirectedReceipt::Failure(
                    failure,
                )))
            }
            (Self::Catalog { page_cursor }, RuntimeReply::Catalog(snapshot))
                if payload_kind == SealedPayloadKind::CatalogSnapshot
                    && snapshot.current_page_cursor() == page_cursor.as_ref() =>
            {
                Ok(ValidatedDirectedReply::Terminal(DirectedReceipt::Catalog(
                    snapshot,
                )))
            }
            (Self::Subscribe { .. }, _) => Err(RemoteRuntimeError::InvalidReply(
                "subscription replies require the multi-receipt state machine",
            )),
            (
                Self::Prompt {
                    expected_configuration_revision,
                },
                RuntimeReply::Command(receipt),
            ) if receipt_matches_expected_revision(&receipt, *expected_configuration_revision) => {
                Ok(ValidatedDirectedReply::Terminal(DirectedReceipt::Command(
                    receipt,
                )))
            }
            (Self::Prompt { .. }, RuntimeReply::Command(_)) => {
                Err(RemoteRuntimeError::InvalidReply(
                    "CommandReceipt configuration revision does not match the request",
                ))
            }
            (Self::ResolveApproval { approval_id }, RuntimeReply::Approval(receipt))
                if approval_receipt_id(&receipt) == approval_id =>
            {
                Ok(ValidatedDirectedReply::Terminal(DirectedReceipt::Approval(
                    receipt,
                )))
            }
            (Self::RetryApproval { approval_id, .. }, RuntimeReply::Approval(receipt))
                if approval_receipt_id(&receipt) == approval_id
                    && retry_approval_receipt_is_allowed(&receipt) =>
            {
                Ok(ValidatedDirectedReply::Terminal(DirectedReceipt::Approval(
                    receipt,
                )))
            }
            (
                Self::RevokeSelf { grant_serial },
                RuntimeReply::Revocation(RevocationReceipt::Committed {
                    grant_serial: committed,
                }),
            ) if committed.0 == grant_serial.value() => {
                Ok(ValidatedDirectedReply::SelfRevocationCommitted)
            }
            (
                Self::RevokeSelf { .. },
                RuntimeReply::Revocation(RevocationReceipt::Failed { failure }),
            ) => Ok(ValidatedDirectedReply::Terminal(DirectedReceipt::Failure(
                failure,
            ))),
            (Self::RevokeSelf { .. }, RuntimeReply::Revocation(_)) => {
                Err(RemoteRuntimeError::InvalidReply(
                    "RevocationReceipt grant serial does not match the paired machine",
                ))
            }
            (
                Self::ResolveApproval { .. } | Self::RetryApproval { .. },
                RuntimeReply::Approval(_),
            ) => Err(RemoteRuntimeError::InvalidReply(
                "ApprovalReceipt is not allowed for the request or approvalId does not match",
            )),
            (Self::Prompt { .. }, _) => Err(RemoteRuntimeError::InvalidReply(
                "Runtime reply is not CommandReceipt",
            )),
            (Self::Catalog { .. }, _) => Err(RemoteRuntimeError::InvalidReply(
                "Runtime reply is not a CatalogSnapshot with the expected payload kind",
            )),
            (Self::ResolveApproval { .. } | Self::RetryApproval { .. }, _) => Err(
                RemoteRuntimeError::InvalidReply("Runtime reply is not ApprovalReceipt"),
            ),
            (Self::RevokeSelf { .. }, _) => Err(RemoteRuntimeError::InvalidReply(
                "Runtime reply is not RevocationReceipt",
            )),
        }
    }

    fn stored_receipt_matches(&self, receipt: &DirectedReceipt) -> bool {
        match (self, receipt) {
            (Self::Subscribe { .. }, DirectedReceipt::Failure(_)) => true,
            (Self::Catalog { page_cursor }, DirectedReceipt::Catalog(snapshot)) => {
                snapshot.current_page_cursor() == page_cursor.as_ref()
            }
            (
                Self::Prompt {
                    expected_configuration_revision,
                },
                DirectedReceipt::Command(receipt),
            ) => receipt_matches_expected_revision(receipt, *expected_configuration_revision),
            (Self::ResolveApproval { approval_id }, DirectedReceipt::Approval(receipt)) => {
                approval_receipt_id(receipt) == approval_id
            }
            (Self::RetryApproval { approval_id, .. }, DirectedReceipt::Approval(receipt)) => {
                approval_receipt_id(receipt) == approval_id
                    && retry_approval_receipt_is_allowed(receipt)
            }
            (
                Self::RevokeSelf { .. },
                DirectedReceipt::Catalog(_)
                | DirectedReceipt::Command(_)
                | DirectedReceipt::Approval(_),
            ) => false,
            (Self::Catalog { .. }, DirectedReceipt::Command(_) | DirectedReceipt::Approval(_)) => {
                false
            }
            (
                Self::Prompt { .. } | Self::ResolveApproval { .. } | Self::RetryApproval { .. },
                DirectedReceipt::Catalog(_),
            ) => false,
            (Self::Subscribe { .. }, _) => false,
            (_, DirectedReceipt::Failure(_)) => true,
            _ => false,
        }
    }

    fn retry_attempt(&self) -> Result<u64, RemoteRuntimeError> {
        match self {
            Self::RetryApproval { attempt, .. } if *attempt > 0 => Ok(*attempt),
            Self::RetryApproval { .. } => Err(RemoteRuntimeError::InvalidDurableState),
            Self::Catalog { .. }
            | Self::Subscribe { .. }
            | Self::Prompt { .. }
            | Self::ResolveApproval { .. }
            | Self::RevokeSelf { .. } => Err(RemoteRuntimeError::InvalidDurableState),
        }
    }
}

enum ValidatedDirectedReply {
    Terminal(DirectedReceipt),
    SelfRevocationCommitted,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", content = "receipt", rename_all = "camelCase")]
enum DirectedReceipt {
    Catalog(CatalogSnapshot),
    Command(CommandReceipt),
    Approval(ApprovalReceipt),
    Failure(RuntimeFailure),
}

struct SubscriptionBootstrapProgress<D> {
    route_accepted: bool,
    subscription: SubscriptionReceipt,
    sync_complete: RuntimeSyncComplete,
    staged_reducer: D,
}

impl<D> SubscriptionBootstrapProgress<D> {
    fn into_outcome_and_reducer(
        self,
        binding: StreamBindingV1,
    ) -> (RemoteSubscriptionBootstrap, D) {
        (
            RemoteSubscriptionBootstrap {
                route_accepted: self.route_accepted,
                subscription: self.subscription,
                sync_complete: self.sync_complete,
                binding,
            },
            self.staged_reducer,
        )
    }
}

struct SubscriptionBootstrapTracker<D> {
    requested: RuntimeInnerCursor,
    delivered: RuntimeInnerCursor,
    subscription: Option<SubscriptionReceipt>,
    staged_reducer: D,
    catalog_snapshot_base: Option<StreamCursor>,
    catalog_page_chain: CatalogPageChain,
    conversation_snapshot_seen: bool,
    backfill_started: bool,
    sync_complete: Option<RuntimeSyncComplete>,
}

enum CatalogPageChain {
    NotStarted,
    Expect(CatalogPageCursor),
    Complete,
}

impl<D> SubscriptionBootstrapTracker<D>
where
    D: RemoteSubscriptionReducer,
{
    fn new(requested: RuntimeInnerCursor, reducer: &D) -> Result<Self, RemoteRuntimeError> {
        validate_inner_cursor(&requested)?;
        if reducer.inner_cursor() != &requested {
            return Err(RemoteRuntimeError::InvalidDurableState);
        }
        Ok(Self {
            delivered: requested.clone(),
            requested,
            subscription: None,
            staged_reducer: reducer.clone(),
            catalog_snapshot_base: None,
            catalog_page_chain: CatalogPageChain::NotStarted,
            conversation_snapshot_seen: false,
            backfill_started: false,
            sync_complete: None,
        })
    }

    const fn requested(&self) -> &RuntimeInnerCursor {
        &self.requested
    }

    fn accept_runtime_reply(
        &mut self,
        payload_kind: SealedPayloadKind,
        reply: RuntimeReply,
    ) -> Result<(), RemoteRuntimeError> {
        if self.sync_complete.is_some() {
            return Err(RemoteRuntimeError::InvalidReply(
                "Runtime subscription emitted data after SyncComplete",
            ));
        }
        match reply {
            RuntimeReply::Subscription(receipt)
                if payload_kind == SealedPayloadKind::CommandReceipt
                    && self.subscription.is_none() =>
            {
                if !matches!(receipt, SubscriptionReceipt::Subscribed { .. }) {
                    return Err(RemoteRuntimeError::InvalidReply(
                        "Runtime subscription did not return Subscribed",
                    ));
                }
                self.subscription = Some(receipt);
                Ok(())
            }
            RuntimeReply::Catalog(snapshot)
                if payload_kind == SealedPayloadKind::CatalogSnapshot =>
            {
                self.require_subscribed()?;
                let current_page_matches = match &self.catalog_page_chain {
                    CatalogPageChain::NotStarted => snapshot.current_page_cursor().is_none(),
                    CatalogPageChain::Expect(expected) => {
                        snapshot.current_page_cursor() == Some(expected)
                    }
                    CatalogPageChain::Complete => false,
                };
                if self.backfill_started
                    || !current_page_matches
                    || self
                        .catalog_snapshot_base
                        .is_some_and(|base| base != snapshot.base_catalog_cursor)
                {
                    return Err(RemoteRuntimeError::InvalidReply(
                        "Catalog snapshot pages are incomplete or out of order",
                    ));
                }
                let RuntimeInnerCursor::Catalog { cursor: delivered } = &self.delivered else {
                    return Err(RemoteRuntimeError::InvalidReply(
                        "Catalog snapshot crossed the requested subscription target",
                    ));
                };
                if cursor_cmp(snapshot.base_catalog_cursor, *delivered).is_lt() {
                    return Err(RemoteRuntimeError::InvalidReply(
                        "Catalog snapshot moved the inner cursor backwards",
                    ));
                }
                let next = RuntimeInnerCursor::Catalog {
                    cursor: snapshot.base_catalog_cursor,
                };
                self.catalog_page_chain = match snapshot.next_page_cursor().cloned() {
                    Some(next) => CatalogPageChain::Expect(next),
                    None => CatalogPageChain::Complete,
                };
                self.catalog_snapshot_base = Some(snapshot.base_catalog_cursor);
                self.apply_item(
                    RemoteSubscriptionBootstrapItem::CatalogSnapshot(snapshot),
                    next,
                )
            }
            RuntimeReply::Snapshot(snapshot)
                if payload_kind == SealedPayloadKind::ConversationSnapshot =>
            {
                self.require_subscribed()?;
                if self.conversation_snapshot_seen || self.backfill_started {
                    return Err(RemoteRuntimeError::InvalidReply(
                        "Conversation snapshot is duplicated or follows backfill",
                    ));
                }
                let RuntimeInnerCursor::Conversation {
                    conversation_id,
                    cursor: delivered,
                } = &self.delivered
                else {
                    return Err(RemoteRuntimeError::InvalidReply(
                        "Conversation snapshot crossed the requested subscription target",
                    ));
                };
                if snapshot.conversation_id != *conversation_id
                    || cursor_cmp(snapshot.base_event_cursor, *delivered).is_lt()
                {
                    return Err(RemoteRuntimeError::InvalidReply(
                        "Conversation snapshot does not extend the requested target",
                    ));
                }
                let next = RuntimeInnerCursor::Conversation {
                    conversation_id: conversation_id.clone(),
                    cursor: snapshot.base_event_cursor,
                };
                self.conversation_snapshot_seen = true;
                self.apply_item(
                    RemoteSubscriptionBootstrapItem::ConversationSnapshot(snapshot),
                    next,
                )
            }
            RuntimeReply::Backfill(chunk) if payload_kind == SealedPayloadKind::BackfillChunk => {
                self.require_subscribed()?;
                if !matches!(&self.catalog_page_chain, CatalogPageChain::NotStarted)
                    || self.conversation_snapshot_seen
                {
                    return Err(RemoteRuntimeError::InvalidReply(
                        "Backfill cannot be mixed with a snapshot bootstrap",
                    ));
                }
                let next = self.next_after_backfill(&chunk)?;
                self.backfill_started = true;
                self.apply_item(RemoteSubscriptionBootstrapItem::Backfill(chunk), next)
            }
            RuntimeReply::SyncComplete(sync)
                if payload_kind == SealedPayloadKind::CommandReceipt =>
            {
                if matches!(&self.catalog_page_chain, CatalogPageChain::Expect(_)) {
                    return Err(RemoteRuntimeError::InvalidReply(
                        "SyncComplete arrived before the final Catalog snapshot page",
                    ));
                }
                let initial_snapshot_seen = match &self.requested {
                    RuntimeInnerCursor::Catalog { .. } => self.catalog_snapshot_base.is_some(),
                    RuntimeInnerCursor::Conversation { .. } => self.conversation_snapshot_seen,
                };
                if inner_cursor_value(&self.requested) == StreamCursor::BeforeFirst
                    && !initial_snapshot_seen
                {
                    return Err(RemoteRuntimeError::InvalidReply(
                        "BeforeFirst subscription completed without its required snapshot",
                    ));
                }
                let subscription = self.require_subscribed()?;
                let SubscriptionReceipt::Subscribed { stream_generation } = subscription else {
                    return Err(RemoteRuntimeError::InvalidReply(
                        "Runtime subscription receipt is not Subscribed",
                    ));
                };
                if sync.stream_generation != *stream_generation
                    || sync.key_directory_revision == 0
                    || sync.stream_cursor.checked_next().is_err()
                    || sync.inner_cursor != self.delivered
                    || self.staged_reducer.inner_cursor() != &sync.inner_cursor
                    || !same_inner_target(&self.requested, &sync.inner_cursor)
                {
                    return Err(RemoteRuntimeError::InvalidReply(
                        "SyncComplete does not match the subscription bootstrap",
                    ));
                }
                validate_inner_cursor(&sync.inner_cursor)?;
                self.sync_complete = Some(sync);
                Ok(())
            }
            RuntimeReply::Subscription(_) => Err(RemoteRuntimeError::InvalidReply(
                "Runtime subscription receipt is duplicated or has the wrong payload kind",
            )),
            RuntimeReply::Catalog(_)
            | RuntimeReply::Snapshot(_)
            | RuntimeReply::Backfill(_)
            | RuntimeReply::SyncComplete(_) => Err(RemoteRuntimeError::InvalidReply(
                "Runtime subscription reply has the wrong payload kind",
            )),
            _ => Err(RemoteRuntimeError::InvalidReply(
                "Runtime subscription received an unrelated reply",
            )),
        }
    }

    fn next_after_backfill(
        &self,
        chunk: &BackfillChunk,
    ) -> Result<RuntimeInnerCursor, RemoteRuntimeError> {
        match (chunk, &self.delivered) {
            (BackfillChunk::Catalog { range, .. }, RuntimeInnerCursor::Catalog { cursor })
                if range.after() == *cursor =>
            {
                Ok(RuntimeInnerCursor::Catalog {
                    cursor: range.through(),
                })
            }
            (
                BackfillChunk::Conversation {
                    conversation_id,
                    range,
                    ..
                },
                RuntimeInnerCursor::Conversation {
                    conversation_id: expected,
                    cursor,
                },
            ) if conversation_id == expected && range.after() == *cursor => {
                Ok(RuntimeInnerCursor::Conversation {
                    conversation_id: expected.clone(),
                    cursor: range.through(),
                })
            }
            _ => Err(RemoteRuntimeError::InvalidReply(
                "Backfill does not continue the requested subscription target",
            )),
        }
    }

    fn apply_item(
        &mut self,
        item: RemoteSubscriptionBootstrapItem,
        next: RuntimeInnerCursor,
    ) -> Result<(), RemoteRuntimeError> {
        self.staged_reducer.apply(&item)?;
        if self.staged_reducer.inner_cursor() != &next {
            return Err(RemoteRuntimeError::InvalidReply(
                "subscription reducer did not apply the complete canonical item",
            ));
        }
        self.delivered = next;
        Ok(())
    }

    fn require_subscribed(&self) -> Result<&SubscriptionReceipt, RemoteRuntimeError> {
        self.subscription
            .as_ref()
            .ok_or(RemoteRuntimeError::InvalidReply(
                "Runtime subscription data arrived before Subscribed",
            ))
    }

    fn finish(
        self,
        route_accepted: bool,
        binding: &StreamBindingV1,
    ) -> Result<SubscriptionBootstrapProgress<D>, RemoteRuntimeError> {
        let subscription = self.subscription.ok_or(RemoteRuntimeError::InvalidReply(
            "StreamBinding arrived before Subscribed",
        ))?;
        let sync_complete = self.sync_complete.ok_or(RemoteRuntimeError::InvalidReply(
            "StreamBinding arrived before SyncComplete",
        ))?;
        validate_subscription_binding(&self.requested, &sync_complete, binding)?;
        Ok(SubscriptionBootstrapProgress {
            route_accepted,
            subscription,
            sync_complete,
            staged_reducer: self.staged_reducer,
        })
    }
}

fn decode_subscription_transfer(
    requested: &RuntimeInnerCursor,
    payload: &[u8],
) -> Result<(SealedPayloadKind, RuntimeReply), RemoteRuntimeError> {
    let snapshot = match requested {
        RuntimeInnerCursor::Catalog { .. } => {
            canonical_json::<CatalogSnapshot>(payload).map(|snapshot| {
                (
                    SealedPayloadKind::CatalogSnapshot,
                    RuntimeReply::Catalog(snapshot),
                )
            })
        }
        RuntimeInnerCursor::Conversation { .. } => canonical_json::<ConversationSnapshot>(payload)
            .map(|snapshot| {
                (
                    SealedPayloadKind::ConversationSnapshot,
                    RuntimeReply::Snapshot(snapshot),
                )
            }),
    };
    let backfill = canonical_json::<BackfillChunk>(payload).map(|chunk| {
        (
            SealedPayloadKind::BackfillChunk,
            RuntimeReply::Backfill(chunk),
        )
    });
    match (snapshot, backfill) {
        (Some(reply), None) | (None, Some(reply)) => Ok(reply),
        (None, None) | (Some(_), Some(_)) => Err(RemoteRuntimeError::InvalidReply(
            "subscription transfer is not one exact canonical snapshot or backfill payload",
        )),
    }
}

fn canonical_json<T>(payload: &[u8]) -> Option<T>
where
    T: serde::de::DeserializeOwned + serde::Serialize,
{
    let value = serde_json::from_slice::<T>(payload).ok()?;
    let mut comparator = CanonicalJsonComparator::new(payload);
    serde_json::to_writer(&mut comparator, &value).ok()?;
    comparator.is_exact().then_some(value)
}

struct CanonicalJsonComparator<'a> {
    expected: &'a [u8],
    offset: usize,
    matches: bool,
}

impl<'a> CanonicalJsonComparator<'a> {
    const fn new(expected: &'a [u8]) -> Self {
        Self {
            expected,
            offset: 0,
            matches: true,
        }
    }

    fn is_exact(&self) -> bool {
        self.matches && self.offset == self.expected.len()
    }
}

impl std::io::Write for CanonicalJsonComparator<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let Some(end) = self.offset.checked_add(bytes.len()) else {
            self.matches = false;
            return Ok(bytes.len());
        };
        if self.expected.get(self.offset..end) != Some(bytes) {
            self.matches = false;
        }
        self.offset = end;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn validate_inner_cursor(cursor: &RuntimeInnerCursor) -> Result<(), RemoteRuntimeError> {
    match cursor {
        RuntimeInnerCursor::Catalog { cursor } => cursor
            .checked_next()
            .map(|_| ())
            .map_err(|_| RemoteRuntimeError::InvalidDurableState),
        RuntimeInnerCursor::Conversation {
            conversation_id,
            cursor,
        } if !conversation_id.as_str().is_empty()
            && conversation_id.as_str().len() <= 1_024
            && !conversation_id.as_str().as_bytes().contains(&0) =>
        {
            cursor
                .checked_next()
                .map(|_| ())
                .map_err(|_| RemoteRuntimeError::InvalidDurableState)
        }
        RuntimeInnerCursor::Conversation { .. } => Err(RemoteRuntimeError::InvalidDurableState),
    }
}

fn validate_subscription_binding(
    requested: &RuntimeInnerCursor,
    sync: &RuntimeSyncComplete,
    binding: &StreamBindingV1,
) -> Result<(), RemoteRuntimeError> {
    binding
        .validate()
        .map_err(|_| RemoteRuntimeError::InvalidReply("StreamBinding is invalid"))?;
    if !same_inner_target(requested, &binding.inner_cursor)
        || !same_inner_target(requested, &sync.inner_cursor)
        || binding.stream_cursor != sync.stream_cursor
        || binding.key_directory_revision.value() != sync.key_directory_revision
        || cursor_cmp(
            inner_cursor_value(&binding.inner_cursor),
            inner_cursor_value(requested),
        )
        .is_lt()
        || cursor_cmp(
            inner_cursor_value(&sync.inner_cursor),
            inner_cursor_value(&binding.inner_cursor),
        )
        .is_lt()
    {
        return Err(RemoteRuntimeError::InvalidReply(
            "StreamBinding does not match the completed subscription",
        ));
    }
    Ok(())
}

fn same_inner_target(left: &RuntimeInnerCursor, right: &RuntimeInnerCursor) -> bool {
    match (left, right) {
        (RuntimeInnerCursor::Catalog { .. }, RuntimeInnerCursor::Catalog { .. }) => true,
        (
            RuntimeInnerCursor::Conversation {
                conversation_id: left,
                ..
            },
            RuntimeInnerCursor::Conversation {
                conversation_id: right,
                ..
            },
        ) => left == right,
        _ => false,
    }
}

fn inner_cursor_value(cursor: &RuntimeInnerCursor) -> StreamCursor {
    match cursor {
        RuntimeInnerCursor::Catalog { cursor }
        | RuntimeInnerCursor::Conversation { cursor, .. } => *cursor,
    }
}

fn cursor_cmp(left: StreamCursor, right: StreamCursor) -> std::cmp::Ordering {
    match (left, right) {
        (StreamCursor::BeforeFirst, StreamCursor::BeforeFirst) => std::cmp::Ordering::Equal,
        (StreamCursor::BeforeFirst, StreamCursor::At(_)) => std::cmp::Ordering::Less,
        (StreamCursor::At(_), StreamCursor::BeforeFirst) => std::cmp::Ordering::Greater,
        (StreamCursor::At(left), StreamCursor::At(right)) => left.cmp(&right),
    }
}

struct DirectedOutcome {
    route_accepted: bool,
    receipt: DirectedReceipt,
    terminal_persisted: bool,
}

enum DirectedExchangeResult {
    Receipt(DirectedOutcome),
    RevocationTerminal {
        route_accepted: bool,
        terminal: VerifiedRevocationTerminal,
    },
}

fn directed_receipt_outcome(
    result: DirectedExchangeResult,
) -> Result<DirectedOutcome, RemoteRuntimeError> {
    match result {
        DirectedExchangeResult::Receipt(outcome) => Ok(outcome),
        DirectedExchangeResult::RevocationTerminal { .. } => Err(RemoteRuntimeError::InvalidReply(
            "unexpected revocation terminal for the active runtime operation",
        )),
    }
}

fn validate_received_runtime_frame(
    received: &ReceivedRuntimeFrame,
) -> Result<(), RemoteRuntimeError> {
    if received.frame().version != RELAY_PROTOCOL_VERSION
        || encode(received.frame()).as_slice() != received.canonical_bytes()
    {
        return Err(RemoteRuntimeError::InvalidReply(
            "Relay frame is not the exact supported canonical wire payload",
        ));
    }
    Ok(())
}

fn decode_direct_stream_item(
    binding: &StreamBindingV1,
    opened: SealedPayloadV1,
) -> Result<(RuntimeStreamItem, RuntimeInnerCursor), RemoteRuntimeError> {
    if opened.payload.len() >= MAX_RUNTIME_JSON_FRAME_BYTES {
        return Err(RemoteRuntimeError::InvalidReply(
            "live Runtime stream payload exceeds the JSON frame limit",
        ));
    }
    let envelope = canonical_json::<RuntimeEnvelope>(&opened.payload).ok_or(
        RemoteRuntimeError::InvalidReply(
            "live Runtime stream payload is not one canonical JSON envelope",
        ),
    )?;
    let RuntimeMessage::Stream(item) = envelope.body else {
        return Err(RemoteRuntimeError::InvalidReply(
            "live Runtime envelope is not a stream item",
        ));
    };
    let observed_after = match (&binding.inner_cursor, opened.payload_kind, &item) {
        (
            RuntimeInnerCursor::Catalog { .. },
            SealedPayloadKind::CatalogDelta,
            RuntimeStreamItem::CatalogDelta(delta),
        ) => RuntimeInnerCursor::Catalog {
            cursor: StreamCursor::At(delta.catalog_revision),
        },
        (
            RuntimeInnerCursor::Conversation {
                conversation_id, ..
            },
            SealedPayloadKind::ConversationEvent,
            RuntimeStreamItem::Event(event),
        ) if &event.conversation_id == conversation_id => RuntimeInnerCursor::Conversation {
            conversation_id: conversation_id.clone(),
            cursor: StreamCursor::At(event.event_seq),
        },
        (_, SealedPayloadKind::TransferPart, RuntimeStreamItem::TransferPart(_)) => {
            return Err(RemoteRuntimeError::InvalidReply(
                "live TransferPart requires the durable transfer ingress",
            ));
        }
        _ => {
            return Err(RemoteRuntimeError::InvalidReply(
                "live payload kind/item/target does not match the durable binding",
            ));
        }
    };
    Ok((item, observed_after))
}

fn map_transfer_carrier_error(error: RuntimeTransferCarrierError) -> RemoteRuntimeError {
    match error {
        RuntimeTransferCarrierError::Transfer(error) => RemoteRuntimeError::Transfer(error),
        error => RemoteRuntimeError::TransferCarrier(error),
    }
}

fn directed_outcome(
    route_accepted: bool,
    receipt: DirectedReceipt,
) -> Result<DirectedOutcome, RemoteRuntimeError> {
    directed_outcome_with_persistence(route_accepted, receipt, true)
}

fn directed_outcome_with_persistence(
    route_accepted: bool,
    receipt: DirectedReceipt,
    terminal_persisted: bool,
) -> Result<DirectedOutcome, RemoteRuntimeError> {
    match receipt {
        DirectedReceipt::Failure(failure) => Err(RemoteRuntimeError::DaemonFailure(failure)),
        receipt => Ok(DirectedOutcome {
            route_accepted,
            receipt,
            terminal_persisted,
        }),
    }
}

#[derive(Clone)]
struct PendingExchange {
    operation: DirectedOperation,
    intent_hash: [u8; 32],
    message_id: MessageId,
    request_route: RequestRouteId,
    exact_send: Vec<u8>,
}

fn decode_pending_send(
    pending: &PendingExchange,
    expected_device_route: DeviceRouteId,
) -> Result<RelaySend, RemoteRuntimeError> {
    let decoded = decode(&pending.exact_send)?;
    let RelayFrameBody::Send(send) = decoded.body else {
        return Err(RemoteRuntimeError::InvalidDurableState);
    };
    if decoded.version != RELAY_PROTOCOL_VERSION
        || send.device_route != expected_device_route
        || send.request_route != pending.request_route
    {
        return Err(RemoteRuntimeError::InvalidDurableState);
    }
    Ok(send)
}

struct TerminalExchange {
    operation: DirectedOperation,
    intent_hash: [u8; 32],
    message_id: MessageId,
    request_route: RequestRouteId,
    request_frame_hash: [u8; 32],
    reply_frame_hash: [u8; 32],
    receipt: DirectedReceipt,
}

enum DurableExchange {
    Pending(PendingExchange),
    Terminal(TerminalExchange),
}

#[derive(Debug, Eq, PartialEq)]
enum CatalogPendingRecovery {
    None,
    Resume(Option<CatalogPageCursor>),
}

fn catalog_pending_recovery(
    existing: Option<DurableExchange>,
) -> Result<CatalogPendingRecovery, RemoteRuntimeError> {
    match existing {
        Some(DurableExchange::Pending(PendingExchange {
            operation: DirectedOperation::Catalog { page_cursor },
            ..
        })) => Ok(CatalogPendingRecovery::Resume(page_cursor)),
        Some(DurableExchange::Pending(_)) => Err(RemoteRuntimeError::PendingIntentConflict),
        Some(DurableExchange::Terminal(_)) | None => Ok(CatalogPendingRecovery::None),
    }
}

enum ExchangeStart {
    Pending(PendingExchange),
    Terminal(DirectedReceipt),
}

fn select_exchange_start<F>(
    existing: Option<DurableExchange>,
    plan: DirectedRequestPlan,
    prepare: F,
) -> Result<ExchangeStart, RemoteRuntimeError>
where
    F: FnOnce(DirectedRequestPlan) -> Result<PendingExchange, RemoteRuntimeError>,
{
    let plan = plan.align_retry_attempt(existing.as_ref())?;
    match existing {
        Some(DurableExchange::Pending(pending))
            if pending.intent_hash == plan.intent_hash && pending.operation == plan.operation =>
        {
            Ok(ExchangeStart::Pending(pending))
        }
        Some(DurableExchange::Pending(_)) => Err(RemoteRuntimeError::PendingIntentConflict),
        Some(DurableExchange::Terminal(terminal))
            if terminal.intent_hash == plan.intent_hash && terminal.operation == plan.operation =>
        {
            Ok(ExchangeStart::Terminal(terminal.receipt))
        }
        Some(DurableExchange::Terminal(_)) | None => prepare(plan).map(ExchangeStart::Pending),
    }
}

#[derive(Clone, Copy)]
struct ReplayEntry {
    counter: u64,
    signed_blob_hash: [u8; 32],
}

struct ReplayWindow {
    key_epoch: u64,
    directory_revision: u64,
    nonce_reuse_quarantined: bool,
    entries: Vec<ReplayEntry>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReplayAdmission {
    ExactDuplicate,
    Fresh,
    NonceReuse,
}

impl ReplayWindow {
    /// DeviceReplyTx 在 same-epoch rewrap 时保留同一 raw key 与 nonce prefix，因此 replay
    /// window 也必须跨 directory revision 原地延续。调用方只传入已完整审计的 current
    /// revision，因此可跨多次 rewrap 单调推进；由 durable pending request 完整验签关联的
    /// 旧 reply 只增加 tuple，绝不降低 revision high-water。按 revision 新建窗口会让相同
    /// counter 的不同 ciphertext 绕过 quarantine。
    fn observe_at_revision(
        &mut self,
        directory_revision: u64,
        counter: u64,
        signed_blob_hash: [u8; 32],
    ) -> Result<ReplayAdmission, RemoteRuntimeError> {
        if directory_revision == 0 {
            return Err(RemoteRuntimeError::ReplayRejected);
        }
        if directory_revision > self.directory_revision {
            self.directory_revision = directory_revision;
        }
        self.observe(counter, signed_blob_hash)
    }

    /// 与 `agentdeck_crypto::replay::ReplayWindow` 相同的 numerical window 语义；额外把
    /// tuple 保持为可 durable encode 的排序列表。
    fn observe(
        &mut self,
        counter: u64,
        signed_blob_hash: [u8; 32],
    ) -> Result<ReplayAdmission, RemoteRuntimeError> {
        if self.nonce_reuse_quarantined {
            return Err(RemoteRuntimeError::ReplayRejected);
        }
        let high_water = self
            .entries
            .last()
            .ok_or(RemoteRuntimeError::InvalidDurableState)?
            .counter;
        let floor = high_water.saturating_sub(MAX_REPLAY_ENTRIES as u64 - 1);
        if counter < floor {
            return Err(RemoteRuntimeError::ReplayRejected);
        }
        match self
            .entries
            .binary_search_by_key(&counter, |entry| entry.counter)
        {
            Ok(index) if self.entries[index].signed_blob_hash == signed_blob_hash => {
                Ok(ReplayAdmission::ExactDuplicate)
            }
            Ok(_) => {
                self.nonce_reuse_quarantined = true;
                Ok(ReplayAdmission::NonceReuse)
            }
            Err(mut index) => {
                if counter > high_water {
                    let next_floor = counter.saturating_sub(MAX_REPLAY_ENTRIES as u64 - 1);
                    self.entries.retain(|entry| entry.counter >= next_floor);
                    index = self.entries.len();
                }
                if self.entries.len() >= MAX_REPLAY_ENTRIES {
                    return Err(RemoteRuntimeError::InvalidDurableState);
                }
                self.entries.insert(
                    index,
                    ReplayEntry {
                        counter,
                        signed_blob_hash,
                    },
                );
                Ok(ReplayAdmission::Fresh)
            }
        }
    }
}

fn validate_current_reply_replay_scope(
    windows: &[ReplayWindow],
    key_epoch: u64,
    current_directory_revision: u64,
) -> Result<(), RemoteRuntimeError> {
    let mut matching = None;
    for window in windows
        .iter()
        .filter(|window| window.key_epoch == key_epoch)
    {
        if matching.replace(()).is_some() {
            return Err(RemoteRuntimeError::InvalidDurableState);
        }
        if window.directory_revision == 0 || window.directory_revision > current_directory_revision
        {
            return Err(RemoteRuntimeError::InvalidDurableState);
        }
        if window.nonce_reuse_quarantined {
            return Err(RemoteRuntimeError::ReplayRejected);
        }
    }
    Ok(())
}

fn receipt_matches_expected_revision(receipt: &CommandReceipt, expected: u64) -> bool {
    match receipt {
        CommandReceipt::Accepted {
            configuration_revision,
            ..
        }
        | CommandReceipt::Replayed {
            configuration_revision,
            ..
        } => *configuration_revision == expected,
        CommandReceipt::Failed { .. } => true,
    }
}

fn approval_receipt_id(receipt: &ApprovalReceipt) -> &ApprovalId {
    match receipt {
        ApprovalReceipt::Claimed { approval_id }
        | ApprovalReceipt::Applied { approval_id }
        | ApprovalReceipt::AlreadyHandled { approval_id, .. }
        | ApprovalReceipt::DeliveryFailed { approval_id }
        | ApprovalReceipt::Expired { approval_id } => approval_id,
    }
}

fn retry_approval_receipt_is_allowed(receipt: &ApprovalReceipt) -> bool {
    match receipt {
        ApprovalReceipt::Applied { .. }
        | ApprovalReceipt::DeliveryFailed { .. }
        | ApprovalReceipt::Expired { .. } => true,
        ApprovalReceipt::AlreadyHandled { state, .. } => matches!(
            state,
            ApprovalDeliveryState::Claimed
                | ApprovalDeliveryState::Applying
                | ApprovalDeliveryState::Expired
        ),
        ApprovalReceipt::Claimed { .. } => false,
    }
}

fn prompt_intent_hash(request: &SendPromptRequest) -> Result<[u8; 32], RemoteRuntimeError> {
    let request_bytes = serde_json::to_vec(request)?;
    intent_hash(INTENT_DOMAIN, &request_bytes)
}

fn runtime_request_intent_hash(
    domain: &[u8],
    request: &agentdeck_protocol::runtime::RuntimeRequest,
) -> Result<[u8; 32], RemoteRuntimeError> {
    intent_hash(domain, &serde_json::to_vec(request)?)
}

fn retry_approval_intent_hash(
    request: &agentdeck_protocol::runtime::RuntimeRequest,
    attempt: u64,
) -> Result<[u8; 32], RemoteRuntimeError> {
    if attempt == 0 {
        return Err(RemoteRuntimeError::InvalidDurableState);
    }
    let request_bytes = serde_json::to_vec(request)?;
    let mut attempt_bound = Vec::with_capacity(8 + request_bytes.len());
    attempt_bound.extend_from_slice(&attempt.to_be_bytes());
    attempt_bound.extend_from_slice(&request_bytes);
    intent_hash(RETRY_APPROVAL_INTENT_DOMAIN, &attempt_bound)
}

fn intent_hash(domain: &[u8], request_bytes: &[u8]) -> Result<[u8; 32], RemoteRuntimeError> {
    let mut preimage = Vec::with_capacity(domain.len() + 8 + request_bytes.len());
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(&RELAY_PROTOCOL_VERSION.to_be_bytes());
    preimage.extend_from_slice(&RUNTIME_PROTOCOL_VERSION.to_be_bytes());
    preimage.extend_from_slice(
        &u32::try_from(request_bytes.len())
            .map_err(|_| RemoteRuntimeError::InvalidDurableState)?
            .to_be_bytes(),
    );
    preimage.extend_from_slice(request_bytes);
    Ok(sha256(&preimage))
}

fn unix_time_ms() -> Result<u64, RemoteRuntimeError> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| RemoteRuntimeError::InvalidDurableState)?;
    u64::try_from(elapsed.as_millis()).map_err(|_| RemoteRuntimeError::InvalidDurableState)
}

fn key_sync_runtime_error(error: KeySyncError) -> RemoteRuntimeError {
    if error.public_code() == Some(REMOTE_CRYPTO_KEY_EPOCH_MISSING) {
        RemoteRuntimeError::Paired(PairedPromotionError::Crypto(CryptoError::E2ee(
            E2eeError::KeyEpochMissing,
        )))
    } else {
        RemoteRuntimeError::InvalidDurableState
    }
}

fn key_sync_reply_error(error: KeySyncError) -> RemoteRuntimeError {
    match error {
        KeySyncError::ResponseConflict => RemoteRuntimeError::InvalidReply(
            "authenticated KeySync response does not match the active request",
        ),
        KeySyncError::Exhausted => key_sync_runtime_error(error),
        KeySyncError::InvalidCanonical
        | KeySyncError::TooLarge
        | KeySyncError::ObservationConflict
        | KeySyncError::ClockRollback => RemoteRuntimeError::InvalidDurableState,
    }
}

fn random_nonzero<const N: usize, R: CryptoRng>(
    rng: &mut R,
) -> Result<[u8; N], RemoteRuntimeError> {
    let mut bytes = [0_u8; N];
    rng.try_fill_bytes(&mut bytes)
        .map_err(|_| RemoteRuntimeError::EntropyUnavailable)?;
    if bytes.iter().all(|byte| *byte == 0) {
        return Err(RemoteRuntimeError::EntropyUnavailable);
    }
    Ok(bytes)
}

fn encode_exchange(exchange: &DurableExchange) -> Result<Vec<u8>, RemoteRuntimeError> {
    let mut output = Vec::new();
    output.extend_from_slice(EXCHANGE_MAGIC);
    output.extend_from_slice(&EXCHANGE_VERSION.to_be_bytes());
    match exchange {
        DurableExchange::Pending(value) => {
            output.push(EXCHANGE_PENDING);
            encode_operation(&mut output, &value.operation)?;
            output.extend_from_slice(&value.intent_hash);
            put_short_bytes(&mut output, value.message_id.as_str().as_bytes())?;
            output.extend_from_slice(value.request_route.as_bytes());
            put_bytes(&mut output, &value.exact_send)?;
        }
        DurableExchange::Terminal(value) => {
            output.push(EXCHANGE_TERMINAL);
            encode_operation(&mut output, &value.operation)?;
            output.extend_from_slice(&value.intent_hash);
            put_short_bytes(&mut output, value.message_id.as_str().as_bytes())?;
            output.extend_from_slice(value.request_route.as_bytes());
            output.extend_from_slice(&value.request_frame_hash);
            output.extend_from_slice(&value.reply_frame_hash);
            put_bytes(&mut output, &serde_json::to_vec(&value.receipt)?)?;
        }
    }
    Ok(output)
}

fn decode_exchange(bytes: &[u8]) -> Result<DurableExchange, RemoteRuntimeError> {
    let mut reader = Reader::new(bytes);
    if reader.fixed::<4>()? != *EXCHANGE_MAGIC {
        return Err(RemoteRuntimeError::InvalidDurableState);
    }
    let version = reader.u16()?;
    if !matches!(
        version,
        LEGACY_EXCHANGE_VERSION | PRE_SUBSCRIPTION_EXCHANGE_VERSION | EXCHANGE_VERSION
    ) {
        return Err(RemoteRuntimeError::InvalidDurableState);
    }
    let tag = reader.u8()?;
    let current_operation = if version != LEGACY_EXCHANGE_VERSION {
        Some(decode_operation(&mut reader, version)?)
    } else {
        None
    };
    let intent_hash = reader.fixed::<32>()?;
    let message_raw = reader.short_bytes()?;
    let message_text =
        std::str::from_utf8(message_raw).map_err(|_| RemoteRuntimeError::InvalidDurableState)?;
    let message_id = MessageId::new(message_text);
    if !message_id.is_valid_wire_value() {
        return Err(RemoteRuntimeError::InvalidDurableState);
    }
    let request_route_bytes = reader.fixed::<16>()?;
    if request_route_bytes.iter().all(|byte| *byte == 0) {
        return Err(RemoteRuntimeError::InvalidDurableState);
    }
    let request_route = RequestRouteId::from_bytes(request_route_bytes);
    let operation = match current_operation {
        Some(operation) => operation,
        None => DirectedOperation::Prompt {
            expected_configuration_revision: reader.u64()?,
        },
    };
    let exchange = match tag {
        EXCHANGE_PENDING => {
            let exact_send = reader.bytes(MAX_FRAME_BYTES - 1)?.to_vec();
            let decoded = decode(&exact_send)?;
            let RelayFrameBody::Send(send) = decoded.body else {
                return Err(RemoteRuntimeError::InvalidDurableState);
            };
            if decoded.version != RELAY_PROTOCOL_VERSION || send.request_route != request_route {
                return Err(RemoteRuntimeError::InvalidDurableState);
            }
            DurableExchange::Pending(PendingExchange {
                operation,
                intent_hash,
                message_id,
                request_route,
                exact_send,
            })
        }
        EXCHANGE_TERMINAL => {
            let request_frame_hash = reader.fixed::<32>()?;
            let reply_frame_hash = reader.fixed::<32>()?;
            let receipt_bytes = reader.bytes(MAX_RUNTIME_JSON_FRAME_BYTES - 1)?;
            let receipt = if version == LEGACY_EXCHANGE_VERSION {
                let receipt: CommandReceipt = serde_json::from_slice(receipt_bytes)?;
                if serde_json::to_vec(&receipt)?.as_slice() != receipt_bytes {
                    return Err(RemoteRuntimeError::InvalidDurableState);
                }
                DirectedReceipt::Command(receipt)
            } else {
                let receipt: DirectedReceipt = serde_json::from_slice(receipt_bytes)?;
                if serde_json::to_vec(&receipt)?.as_slice() != receipt_bytes {
                    return Err(RemoteRuntimeError::InvalidDurableState);
                }
                receipt
            };
            if !operation.stored_receipt_matches(&receipt) {
                return Err(RemoteRuntimeError::InvalidDurableState);
            }
            DurableExchange::Terminal(TerminalExchange {
                operation,
                intent_hash,
                message_id,
                request_route,
                request_frame_hash,
                reply_frame_hash,
                receipt,
            })
        }
        _ => return Err(RemoteRuntimeError::InvalidDurableState),
    };
    reader.finish()?;
    Ok(exchange)
}

fn encode_operation(
    output: &mut Vec<u8>,
    operation: &DirectedOperation,
) -> Result<(), RemoteRuntimeError> {
    match operation {
        DirectedOperation::Subscribe { inner_cursor } => {
            output.push(5);
            let canonical = serde_json::to_vec(inner_cursor)?;
            put_bytes(output, &canonical)?;
        }
        DirectedOperation::Catalog { page_cursor } => {
            output.push(4);
            match page_cursor {
                Some(page_cursor) => {
                    output.push(1);
                    put_bytes(output, page_cursor.as_str().as_bytes())?;
                }
                None => output.push(0),
            }
        }
        DirectedOperation::Prompt {
            expected_configuration_revision,
        } => {
            output.push(0);
            output.extend_from_slice(&expected_configuration_revision.to_be_bytes());
        }
        DirectedOperation::ResolveApproval { approval_id } => {
            output.push(1);
            put_short_bytes(output, approval_id.as_str().as_bytes())?;
        }
        DirectedOperation::RetryApproval {
            conversation_id,
            approval_id,
            attempt,
        } => {
            output.push(2);
            put_short_bytes(output, conversation_id.as_str().as_bytes())?;
            put_short_bytes(output, approval_id.as_str().as_bytes())?;
            output.extend_from_slice(&attempt.to_be_bytes());
        }
        DirectedOperation::RevokeSelf { grant_serial } => {
            output.push(3);
            output.extend_from_slice(&grant_serial.value().to_be_bytes());
        }
    }
    Ok(())
}

fn decode_operation(
    reader: &mut Reader<'_>,
    exchange_version: u16,
) -> Result<DirectedOperation, RemoteRuntimeError> {
    match reader.u8()? {
        0 => Ok(DirectedOperation::Prompt {
            expected_configuration_revision: reader.u64()?,
        }),
        1 => {
            let raw = reader.short_bytes()?;
            let value =
                std::str::from_utf8(raw).map_err(|_| RemoteRuntimeError::InvalidDurableState)?;
            let approval_id = ApprovalId::new(value);
            Ok(DirectedOperation::ResolveApproval { approval_id })
        }
        2 => {
            let conversation_raw = reader.short_bytes()?;
            let conversation = std::str::from_utf8(conversation_raw)
                .map_err(|_| RemoteRuntimeError::InvalidDurableState)?;
            let approval_raw = reader.short_bytes()?;
            let approval = std::str::from_utf8(approval_raw)
                .map_err(|_| RemoteRuntimeError::InvalidDurableState)?;
            let attempt = reader.u64()?;
            if attempt == 0 {
                return Err(RemoteRuntimeError::InvalidDurableState);
            }
            Ok(DirectedOperation::RetryApproval {
                conversation_id: ConversationId::new(conversation),
                approval_id: ApprovalId::new(approval),
                attempt,
            })
        }
        3 => {
            let grant_serial = RelayGrantSerial::new(reader.u64()?);
            if grant_serial == RelayGrantSerial::ZERO {
                return Err(RemoteRuntimeError::InvalidDurableState);
            }
            Ok(DirectedOperation::RevokeSelf { grant_serial })
        }
        4 => {
            let page_cursor = match reader.u8()? {
                0 => None,
                1 => {
                    let raw = reader.bytes(MAX_RUNTIME_JSON_FRAME_BYTES - 1)?;
                    let value = std::str::from_utf8(raw)
                        .map_err(|_| RemoteRuntimeError::InvalidDurableState)?;
                    Some(CatalogPageCursor::new(value))
                }
                _ => return Err(RemoteRuntimeError::InvalidDurableState),
            };
            Ok(DirectedOperation::Catalog { page_cursor })
        }
        5 if exchange_version == EXCHANGE_VERSION => {
            let raw = reader.bytes(MAX_RUNTIME_JSON_FRAME_BYTES - 1)?;
            let inner_cursor: RuntimeInnerCursor = serde_json::from_slice(raw)?;
            if serde_json::to_vec(&inner_cursor)?.as_slice() != raw {
                return Err(RemoteRuntimeError::InvalidDurableState);
            }
            validate_inner_cursor(&inner_cursor)?;
            Ok(DirectedOperation::Subscribe { inner_cursor })
        }
        _ => Err(RemoteRuntimeError::InvalidDurableState),
    }
}

fn encode_replay_window(window: &ReplayWindow) -> Vec<u8> {
    let mut output = Vec::with_capacity(27 + window.entries.len() * 40);
    output.extend_from_slice(REPLAY_MAGIC);
    output.extend_from_slice(&REPLAY_VERSION.to_be_bytes());
    output.extend_from_slice(&window.key_epoch.to_be_bytes());
    output.extend_from_slice(&window.directory_revision.to_be_bytes());
    output.push(u8::from(window.nonce_reuse_quarantined));
    output.extend_from_slice(&(window.entries.len() as u32).to_be_bytes());
    for entry in &window.entries {
        output.extend_from_slice(&entry.counter.to_be_bytes());
        output.extend_from_slice(&entry.signed_blob_hash);
    }
    output
}

fn decode_replay_window(bytes: &[u8]) -> Result<ReplayWindow, RemoteRuntimeError> {
    let mut reader = Reader::new(bytes);
    if reader.fixed::<4>()? != *REPLAY_MAGIC || reader.u16()? != REPLAY_VERSION {
        return Err(RemoteRuntimeError::InvalidDurableState);
    }
    let key_epoch = reader.u64()?;
    let directory_revision = reader.u64()?;
    let nonce_reuse_quarantined = match reader.u8()? {
        0 => false,
        1 => true,
        _ => return Err(RemoteRuntimeError::InvalidDurableState),
    };
    let count = reader.u32()? as usize;
    if key_epoch == 0 || directory_revision == 0 || count == 0 || count > MAX_REPLAY_ENTRIES {
        return Err(RemoteRuntimeError::InvalidDurableState);
    }
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let entry = ReplayEntry {
            counter: reader.u64()?,
            signed_blob_hash: reader.fixed::<32>()?,
        };
        if entry.signed_blob_hash.iter().all(|byte| *byte == 0)
            || entries
                .last()
                .is_some_and(|previous: &ReplayEntry| previous.counter >= entry.counter)
        {
            return Err(RemoteRuntimeError::InvalidDurableState);
        }
        entries.push(entry);
    }
    reader.finish()?;
    let high_water = entries
        .last()
        .ok_or(RemoteRuntimeError::InvalidDurableState)?
        .counter;
    let floor = high_water.saturating_sub(MAX_REPLAY_ENTRIES as u64 - 1);
    if entries.first().is_some_and(|entry| entry.counter < floor) {
        return Err(RemoteRuntimeError::InvalidDurableState);
    }
    Ok(ReplayWindow {
        key_epoch,
        directory_revision,
        nonce_reuse_quarantined,
        entries,
    })
}

fn put_short_bytes(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), RemoteRuntimeError> {
    let len = u16::try_from(bytes.len()).map_err(|_| RemoteRuntimeError::InvalidDurableState)?;
    if len == 0 {
        return Err(RemoteRuntimeError::InvalidDurableState);
    }
    output.extend_from_slice(&len.to_be_bytes());
    output.extend_from_slice(bytes);
    Ok(())
}

fn put_bytes(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), RemoteRuntimeError> {
    let len = u32::try_from(bytes.len()).map_err(|_| RemoteRuntimeError::InvalidDurableState)?;
    if len == 0 {
        return Err(RemoteRuntimeError::InvalidDurableState);
    }
    output.extend_from_slice(&len.to_be_bytes());
    output.extend_from_slice(bytes);
    Ok(())
}

struct Reader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], RemoteRuntimeError> {
        let end = self
            .cursor
            .checked_add(len)
            .ok_or(RemoteRuntimeError::InvalidDurableState)?;
        let value = self
            .bytes
            .get(self.cursor..end)
            .ok_or(RemoteRuntimeError::InvalidDurableState)?;
        self.cursor = end;
        Ok(value)
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], RemoteRuntimeError> {
        self.take(N)?
            .try_into()
            .map_err(|_| RemoteRuntimeError::InvalidDurableState)
    }

    fn u8(&mut self) -> Result<u8, RemoteRuntimeError> {
        Ok(self.fixed::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, RemoteRuntimeError> {
        Ok(u16::from_be_bytes(self.fixed()?))
    }

    fn u32(&mut self) -> Result<u32, RemoteRuntimeError> {
        Ok(u32::from_be_bytes(self.fixed()?))
    }

    fn u64(&mut self) -> Result<u64, RemoteRuntimeError> {
        Ok(u64::from_be_bytes(self.fixed()?))
    }

    fn short_bytes(&mut self) -> Result<&'a [u8], RemoteRuntimeError> {
        let len = self.u16()? as usize;
        if len == 0 {
            return Err(RemoteRuntimeError::InvalidDurableState);
        }
        self.take(len)
    }

    fn bytes(&mut self, max: usize) -> Result<&'a [u8], RemoteRuntimeError> {
        let len = self.u32()? as usize;
        if len == 0 || len > max {
            return Err(RemoteRuntimeError::InvalidDurableState);
        }
        self.take(len)
    }

    fn finish(self) -> Result<(), RemoteRuntimeError> {
        if self.cursor == self.bytes.len() {
            Ok(())
        } else {
            Err(RemoteRuntimeError::InvalidDurableState)
        }
    }
}

/// OS entropy 只在 durable opaque-state mutation 前取一次 seed；随后提供 hpke rand_core
/// 所需的 infallible CryptoRng。caller RNG 因而不会被 retry/replay/terminal 写入消费。
struct SystemMutationRng {
    seed: [u8; 32],
    counter: u64,
    block: [u8; 32],
    offset: usize,
}

impl SystemMutationRng {
    fn new() -> Result<Self, RemoteRuntimeError> {
        let mut seed = [0_u8; 32];
        getrandom::fill(&mut seed).map_err(|_| RemoteRuntimeError::EntropyUnavailable)?;
        if seed.iter().all(|byte| *byte == 0) {
            return Err(RemoteRuntimeError::EntropyUnavailable);
        }
        Ok(Self {
            seed,
            counter: 0,
            block: [0; 32],
            offset: 32,
        })
    }

    fn fill(&mut self, output: &mut [u8]) {
        for byte in output {
            if self.offset == self.block.len() {
                let mut preimage = Vec::with_capacity(MUTATION_RNG_DOMAIN.len() + 40);
                preimage.extend_from_slice(MUTATION_RNG_DOMAIN);
                preimage.extend_from_slice(&self.seed);
                preimage.extend_from_slice(&self.counter.to_be_bytes());
                self.block = sha256(&preimage);
                self.counter = self.counter.wrapping_add(1);
                self.offset = 0;
            }
            *byte = self.block[self.offset];
            self.offset += 1;
        }
    }
}

impl Drop for SystemMutationRng {
    fn drop(&mut self) {
        self.seed.zeroize();
        self.block.zeroize();
    }
}

impl TryRng for SystemMutationRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0; 4];
        self.fill(&mut bytes);
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0; 8];
        self.fill(&mut bytes);
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, output: &mut [u8]) -> Result<(), Self::Error> {
        self.fill(output);
        Ok(())
    }
}

impl TryCryptoRng for SystemMutationRng {}

#[cfg(test)]
mod tests {
    use super::*;

    struct PanicEntropy;

    impl TryRng for PanicEntropy {
        type Error = Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            panic!("legacy pending recovery must not consume caller entropy")
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            panic!("legacy pending recovery must not consume caller entropy")
        }

        fn try_fill_bytes(&mut self, _output: &mut [u8]) -> Result<(), Self::Error> {
            panic!("legacy pending recovery must not consume caller entropy")
        }
    }

    impl TryCryptoRng for PanicEntropy {}

    fn tuple_hash(counter: u64) -> [u8; 32] {
        sha256(&counter.to_be_bytes())
    }

    fn prompt_plan() -> DirectedRequestPlan {
        DirectedRequestPlan::prompt(SendPromptRequest {
            conversation_id: ConversationId::new("conversation-legacy-prompt"),
            idempotency_key: agentdeck_protocol::runtime::IdempotencyKey::new(
                "legacy-prompt-intent",
            ),
            expected_configuration_revision: 9,
            prompt: agentdeck_protocol::runtime::PromptPayload::new("legacy pending fixture")
                .expect("bounded prompt"),
        })
        .expect("prompt plan")
    }

    fn pending_exchange(operation: DirectedOperation) -> DurableExchange {
        DurableExchange::Pending(PendingExchange {
            operation,
            intent_hash: [0x11; 32],
            message_id: MessageId::new("pending-catalog-recovery"),
            request_route: RequestRouteId::from_bytes([0x22; 16]),
            exact_send: vec![0x33],
        })
    }

    fn legacy_prompt_terminal_bytes(
        receipt: &CommandReceipt,
        expected_configuration_revision: u64,
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(EXCHANGE_MAGIC);
        bytes.extend_from_slice(&LEGACY_EXCHANGE_VERSION.to_be_bytes());
        bytes.push(EXCHANGE_TERMINAL);
        bytes.extend_from_slice(&[0x11; 32]);
        put_short_bytes(&mut bytes, b"legacy-prompt-message").unwrap();
        bytes.extend_from_slice(&[0x22; 16]);
        bytes.extend_from_slice(&expected_configuration_revision.to_be_bytes());
        bytes.extend_from_slice(&[0x33; 32]);
        bytes.extend_from_slice(&[0x44; 32]);
        put_bytes(&mut bytes, &serde_json::to_vec(receipt).unwrap()).unwrap();
        bytes
    }

    #[test]
    fn runtime_field_order_keeps_transport_drop_before_machine_lease() {
        let source = include_str!("runtime.rs");
        let declaration = source
            .split("pub struct RemoteRuntime<'a, T> {")
            .nth(1)
            .and_then(|suffix| suffix.split('}').next())
            .expect("RemoteRuntime declaration");
        let transport = declaration.find("transport: T").expect("transport field");
        let machine = declaration
            .find("machine: OpenedPairedMachine")
            .expect("machine lease field");
        assert!(
            transport < machine,
            "Rust drops struct fields in declaration order"
        );
    }

    #[test]
    fn request_route_owner_guard_covers_business_and_key_control_namespaces() {
        let owned = RequestRouteId::from_bytes([0x41; 16]);
        let other = RequestRouteId::from_bytes([0x42; 16]);
        let mut ack_routes = HashMap::new();
        let mut probe_routes = HashMap::new();

        assert!(!request_route_is_owned(
            owned,
            &ack_routes,
            &probe_routes,
            None,
            None,
        ));
        ack_routes.insert(owned, KeyDirectoryRevision::new(7));
        assert!(request_route_is_owned(
            owned,
            &ack_routes,
            &probe_routes,
            None,
            None,
        ));
        ack_routes.clear();

        probe_routes.insert(
            owned,
            PendingKeySyncRoute {
                attempt: 2,
                outstanding_acceptances: 1,
            },
        );
        assert!(request_route_is_owned(
            owned,
            &ack_routes,
            &probe_routes,
            None,
            None,
        ));
        probe_routes.clear();

        assert!(request_route_is_owned(
            owned,
            &ack_routes,
            &probe_routes,
            Some(owned),
            None,
        ));
        assert!(request_route_is_owned(
            owned,
            &ack_routes,
            &probe_routes,
            None,
            Some(owned),
        ));
        assert!(!request_route_is_owned(
            other,
            &ack_routes,
            &probe_routes,
            Some(owned),
            Some(owned),
        ));
    }

    #[test]
    fn catalog_startup_recovers_only_the_exact_pending_catalog_operation() {
        assert_eq!(
            catalog_pending_recovery(None).expect("empty exchange"),
            CatalogPendingRecovery::None
        );
        assert_eq!(
            catalog_pending_recovery(Some(pending_exchange(DirectedOperation::Catalog {
                page_cursor: None,
            })))
            .expect("pending first page"),
            CatalogPendingRecovery::Resume(None)
        );

        let cursor = CatalogPageCursor::new("opaque-restart-cursor");
        assert_eq!(
            catalog_pending_recovery(Some(pending_exchange(DirectedOperation::Catalog {
                page_cursor: Some(cursor.clone()),
            })))
            .expect("pending later page"),
            CatalogPendingRecovery::Resume(Some(cursor))
        );

        assert!(matches!(
            catalog_pending_recovery(Some(pending_exchange(prompt_plan().operation))),
            Err(RemoteRuntimeError::PendingIntentConflict)
        ));
        assert_eq!(
            catalog_pending_recovery(Some(DurableExchange::Terminal(TerminalExchange {
                operation: DirectedOperation::Catalog { page_cursor: None },
                intent_hash: [0x44; 32],
                message_id: MessageId::new("terminal-catalog-recovery"),
                request_route: RequestRouteId::from_bytes([0x55; 16]),
                request_frame_hash: [0x66; 32],
                reply_frame_hash: [0x77; 32],
                receipt: DirectedReceipt::Failure(RuntimeFailure::new(
                    "daemon.catalog.fixture",
                    "terminal fixture",
                )),
            })))
            .expect("terminal is not pending"),
            CatalogPendingRecovery::None
        );
    }

    #[test]
    fn catalog_reply_and_durable_terminal_bind_the_exact_requested_page_cursor() {
        let requested = CatalogPageCursor::new("catalog-requested-page");
        let operation = DirectedOperation::Catalog {
            page_cursor: Some(requested.clone()),
        };
        let matching = CatalogSnapshot::new(StreamCursor::At(1), Vec::new(), Some(requested), None)
            .expect("bounded matching Catalog page");
        assert!(
            operation
                .validate_reply(
                    SealedPayloadKind::CatalogSnapshot,
                    RuntimeReply::Catalog(matching),
                )
                .is_ok()
        );

        let mismatched = CatalogSnapshot::new(StreamCursor::At(1), Vec::new(), None, None)
            .expect("bounded mismatched Catalog page");
        assert!(matches!(
            operation.validate_reply(
                SealedPayloadKind::CatalogSnapshot,
                RuntimeReply::Catalog(mismatched.clone()),
            ),
            Err(RemoteRuntimeError::InvalidReply(_))
        ));

        let encoded = encode_exchange(&DurableExchange::Terminal(TerminalExchange {
            operation,
            intent_hash: [0x81; 32],
            message_id: MessageId::new("catalog-cursor-terminal"),
            request_route: RequestRouteId::from_bytes([0x82; 16]),
            request_frame_hash: [0x83; 32],
            reply_frame_hash: [0x84; 32],
            receipt: DirectedReceipt::Catalog(mismatched),
        }))
        .expect("encode deliberately mismatched durable terminal");
        assert!(matches!(
            decode_exchange(&encoded),
            Err(RemoteRuntimeError::InvalidDurableState)
        ));
    }

    #[test]
    fn resolve_and_retry_operations_and_intent_hashes_are_domain_separated() {
        let conversation_id = ConversationId::new("conversation-domain-separation");
        let approval_id = ApprovalId::new("approval-domain-separation");
        let resolve = DirectedRequestPlan::resolve_approval(
            conversation_id.clone(),
            TurnId::new("turn-domain-separation"),
            approval_id.clone(),
            ActionDecision {
                request_id: "request-domain-separation".to_owned(),
                decision: agentdeck_protocol::ActionDecisionKind::Approve,
                persist: false,
            },
        )
        .expect("resolve plan");
        let retry =
            DirectedRequestPlan::retry_approval(conversation_id.clone(), approval_id.clone())
                .expect("retry plan");

        assert_ne!(resolve.operation, retry.operation);
        assert_ne!(resolve.intent_hash, retry.intent_hash);

        let first_retry_hash = retry.intent_hash;
        let terminal = DurableExchange::Terminal(TerminalExchange {
            operation: retry.operation,
            intent_hash: first_retry_hash,
            message_id: MessageId::new("retry-attempt-one"),
            request_route: RequestRouteId::from_bytes([0x31; 16]),
            request_frame_hash: [0x32; 32],
            reply_frame_hash: [0x33; 32],
            receipt: DirectedReceipt::Approval(ApprovalReceipt::DeliveryFailed {
                approval_id: approval_id.clone(),
            }),
        });
        let second_retry = DirectedRequestPlan::retry_approval(conversation_id, approval_id)
            .expect("second retry plan")
            .align_retry_attempt(Some(&terminal))
            .expect("terminal advances retry attempt");
        assert!(matches!(
            second_retry.operation,
            DirectedOperation::RetryApproval { attempt: 2, .. }
        ));
        assert_ne!(first_retry_hash, second_retry.intent_hash);
    }

    #[test]
    fn retry_approval_receipt_allowlist_matches_daemon_retry_shapes() {
        let approval_id = ApprovalId::new("approval-retry-allowlist");
        let already_handled = |state| ApprovalReceipt::AlreadyHandled {
            approval_id: approval_id.clone(),
            decision: agentdeck_protocol::ActionDecisionKind::Approve,
            state,
        };

        for allowed in [
            ApprovalReceipt::Applied {
                approval_id: approval_id.clone(),
            },
            ApprovalReceipt::DeliveryFailed {
                approval_id: approval_id.clone(),
            },
            ApprovalReceipt::Expired {
                approval_id: approval_id.clone(),
            },
            already_handled(ApprovalDeliveryState::Claimed),
            already_handled(ApprovalDeliveryState::Applying),
            already_handled(ApprovalDeliveryState::Expired),
        ] {
            assert!(retry_approval_receipt_is_allowed(&allowed));
        }
        for rejected in [
            ApprovalReceipt::Claimed {
                approval_id: approval_id.clone(),
            },
            already_handled(ApprovalDeliveryState::Applied),
            already_handled(ApprovalDeliveryState::DeliveryFailed),
        ] {
            assert!(!retry_approval_receipt_is_allowed(&rejected));
        }
    }

    #[test]
    fn legacy_v1_prompt_pending_reuses_exact_frame_without_consuming_entropy() {
        let plan = prompt_plan();
        let request_route = RequestRouteId::from_bytes([0x22; 16]);
        let exact_send = encode(&OpaqueRouteFrame {
            version: RELAY_PROTOCOL_VERSION,
            body: RelayFrameBody::Send(RelaySend {
                device_route: agentdeck_protocol::relay_v2::DeviceRouteId::from_bytes([0x23; 16]),
                request_route,
                sealed_blob: SealedBlob(vec![0x24; 32]),
            }),
        });
        let mut bytes = Vec::new();
        bytes.extend_from_slice(EXCHANGE_MAGIC);
        bytes.extend_from_slice(&LEGACY_EXCHANGE_VERSION.to_be_bytes());
        bytes.push(EXCHANGE_PENDING);
        bytes.extend_from_slice(&plan.intent_hash);
        put_short_bytes(&mut bytes, b"legacy-prompt-message").unwrap();
        bytes.extend_from_slice(request_route.as_bytes());
        bytes.extend_from_slice(&9_u64.to_be_bytes());
        put_bytes(&mut bytes, &exact_send).unwrap();

        let decoded = decode_exchange(&bytes).expect("legacy pending fixture");
        let start = select_exchange_start(Some(decoded), plan, |_| {
            let mut panic_entropy = PanicEntropy;
            let _ = random_nonzero::<16, _>(&mut panic_entropy)?;
            Err(RemoteRuntimeError::InvalidDurableState)
        })
        .expect("legacy pending resumes without preparing a new frame");
        let ExchangeStart::Pending(pending) = start else {
            panic!("legacy pending must remain pending")
        };
        assert_eq!(pending.request_route, request_route);
        assert_eq!(pending.exact_send, exact_send);
    }

    #[test]
    fn legacy_v1_prompt_terminals_bind_accepted_and_replayed_to_revision() {
        let receipts = [
            CommandReceipt::Accepted {
                command_id: agentdeck_protocol::runtime::identity::CommandId::new(
                    "legacy-accepted",
                ),
                queue_position: 2,
                configuration_revision: 9,
            },
            CommandReceipt::Replayed {
                command_id: agentdeck_protocol::runtime::identity::CommandId::new(
                    "legacy-replayed",
                ),
                configuration_revision: 9,
            },
            CommandReceipt::Failed {
                failure: RuntimeFailure::new("daemon.legacy.fixture", "legacy terminal fixture"),
            },
        ];

        for receipt in receipts {
            let bytes = legacy_prompt_terminal_bytes(&receipt, 9);
            let DurableExchange::Terminal(decoded) = decode_exchange(&bytes).unwrap() else {
                panic!("legacy terminal must stay terminal")
            };
            assert_eq!(
                decoded.operation,
                DirectedOperation::Prompt {
                    expected_configuration_revision: 9,
                }
            );
            assert!(matches!(
                decoded.receipt,
                DirectedReceipt::Command(decoded_receipt) if decoded_receipt == receipt
            ));
        }

        assert!(matches!(
            decode_exchange(&legacy_prompt_terminal_bytes(
                &CommandReceipt::Accepted {
                    command_id: agentdeck_protocol::runtime::identity::CommandId::new(
                        "legacy-wrong-revision"
                    ),
                    queue_position: 1,
                    configuration_revision: 9,
                },
                10,
            )),
            Err(RemoteRuntimeError::InvalidDurableState)
        ));
    }

    #[test]
    fn pre_subscription_v2_terminal_remains_compatible_and_rejects_noncanonical_json() {
        let receipt = DirectedReceipt::Command(CommandReceipt::Accepted {
            command_id: agentdeck_protocol::runtime::identity::CommandId::new(
                "current-v2-canonical",
            ),
            queue_position: 1,
            configuration_revision: 9,
        });
        let exchange = DurableExchange::Terminal(TerminalExchange {
            operation: DirectedOperation::Prompt {
                expected_configuration_revision: 9,
            },
            intent_hash: [0x51; 32],
            message_id: MessageId::new("current-v2-terminal"),
            request_route: RequestRouteId::from_bytes([0x52; 16]),
            request_frame_hash: [0x53; 32],
            reply_frame_hash: [0x54; 32],
            receipt,
        });
        let mut canonical = encode_exchange(&exchange).expect("canonical v3 terminal");
        canonical[4..6].copy_from_slice(&PRE_SUBSCRIPTION_EXCHANGE_VERSION.to_be_bytes());
        assert!(matches!(
            decode_exchange(&canonical),
            Ok(DurableExchange::Terminal(_))
        ));

        let canonical_receipt = serde_json::to_vec(match &exchange {
            DurableExchange::Terminal(terminal) => &terminal.receipt,
            DurableExchange::Pending(_) => unreachable!("terminal fixture"),
        })
        .unwrap();
        let receipt_start = canonical.len() - canonical_receipt.len();
        let receipt_len_start = receipt_start - 4;
        let mut noncanonical = canonical;
        noncanonical.insert(receipt_start + 1, b' ');
        let noncanonical_len = u32::try_from(canonical_receipt.len() + 1).unwrap();
        noncanonical[receipt_len_start..receipt_start]
            .copy_from_slice(&noncanonical_len.to_be_bytes());

        assert!(matches!(
            decode_exchange(&noncanonical),
            Err(RemoteRuntimeError::InvalidDurableState)
        ));
    }

    #[test]
    fn pre_subscription_v2_rejects_v3_subscribe_pending_and_terminal_downgrades() {
        let operation = DirectedOperation::Subscribe {
            inner_cursor: RuntimeInnerCursor::Catalog {
                cursor: StreamCursor::BeforeFirst,
            },
        };
        let request_route = RequestRouteId::from_bytes([0x61; 16]);
        let exact_send = encode(&OpaqueRouteFrame {
            version: RELAY_PROTOCOL_VERSION,
            body: RelayFrameBody::Send(RelaySend {
                device_route: agentdeck_protocol::relay_v2::DeviceRouteId::from_bytes([0x62; 16]),
                request_route,
                sealed_blob: SealedBlob(vec![0x63; 32]),
            }),
        });
        let exchanges = [
            DurableExchange::Pending(PendingExchange {
                operation: operation.clone(),
                intent_hash: [0x64; 32],
                message_id: MessageId::new("subscribe-v3-pending"),
                request_route,
                exact_send,
            }),
            DurableExchange::Terminal(TerminalExchange {
                operation,
                intent_hash: [0x65; 32],
                message_id: MessageId::new("subscribe-v3-terminal"),
                request_route,
                request_frame_hash: [0x66; 32],
                reply_frame_hash: [0x67; 32],
                receipt: DirectedReceipt::Failure(RuntimeFailure::new(
                    "daemon.subscribe.fixture",
                    "subscription terminal fixture",
                )),
            }),
        ];
        for exchange in exchanges {
            let mut downgraded = encode_exchange(&exchange).expect("canonical v3 subscribe");
            downgraded[4..6].copy_from_slice(&PRE_SUBSCRIPTION_EXCHANGE_VERSION.to_be_bytes());
            assert!(matches!(
                decode_exchange(&downgraded),
                Err(RemoteRuntimeError::InvalidDurableState)
            ));
        }
    }

    #[test]
    fn replay_window_slides_by_numeric_floor_without_bricking_the_epoch() {
        let mut window = ReplayWindow {
            key_epoch: 7,
            directory_revision: 4,
            nonce_reuse_quarantined: false,
            entries: vec![ReplayEntry {
                counter: 0,
                signed_blob_hash: tuple_hash(0),
            }],
        };
        for counter in 1..=MAX_REPLAY_ENTRIES as u64 {
            assert_eq!(
                window.observe(counter, tuple_hash(counter)).unwrap(),
                ReplayAdmission::Fresh
            );
        }

        assert_eq!(window.entries.len(), MAX_REPLAY_ENTRIES);
        assert_eq!(window.entries.first().unwrap().counter, 1);
        assert_eq!(window.entries.last().unwrap().counter, 4_096);
        assert_eq!(
            window.observe(1, tuple_hash(1)).unwrap(),
            ReplayAdmission::ExactDuplicate
        );
        assert!(matches!(
            window.observe(0, tuple_hash(0)),
            Err(RemoteRuntimeError::ReplayRejected)
        ));
        assert!(matches!(
            window.observe(1, [0x55; 32]),
            Ok(ReplayAdmission::NonceReuse)
        ));
        assert!(matches!(
            window.observe(4_097, tuple_hash(4_097)),
            Err(RemoteRuntimeError::ReplayRejected)
        ));
    }

    #[test]
    fn replay_window_accepts_unseen_out_of_order_counter_above_floor() {
        let mut window = ReplayWindow {
            key_epoch: 7,
            directory_revision: 4,
            nonce_reuse_quarantined: false,
            entries: vec![ReplayEntry {
                counter: 5_000,
                signed_blob_hash: tuple_hash(5_000),
            }],
        };
        assert_eq!(
            window.observe(4_999, tuple_hash(4_999)).unwrap(),
            ReplayAdmission::Fresh
        );
        assert_eq!(window.entries[0].counter, 4_999);
        assert_eq!(window.entries[1].counter, 5_000);
    }

    #[test]
    fn replay_window_quarantines_nonce_reuse_across_exact_next_revision() {
        let mut window = ReplayWindow {
            key_epoch: 7,
            directory_revision: 4,
            nonce_reuse_quarantined: false,
            entries: vec![ReplayEntry {
                counter: 9,
                signed_blob_hash: tuple_hash(9),
            }],
        };

        assert_eq!(
            window
                .observe_at_revision(5, 9, [0x55; 32])
                .expect("exact-next revision shares the same nonce domain"),
            ReplayAdmission::NonceReuse
        );
        assert_eq!(window.directory_revision, 5);
        assert!(window.nonce_reuse_quarantined);
        assert_eq!(window.entries.len(), 1);
        assert!(matches!(
            window.observe_at_revision(5, 10, tuple_hash(10)),
            Err(RemoteRuntimeError::ReplayRejected)
        ));
    }

    #[test]
    fn replay_window_exact_duplicate_is_idempotent_and_verified_gap_advances_high_water() {
        let mut window = ReplayWindow {
            key_epoch: 7,
            directory_revision: 4,
            nonce_reuse_quarantined: false,
            entries: vec![ReplayEntry {
                counter: 9,
                signed_blob_hash: tuple_hash(9),
            }],
        };
        let before = encode_replay_window(&window);
        assert_eq!(
            window
                .observe_at_revision(4, 9, tuple_hash(9))
                .expect("exact duplicate is admissible"),
            ReplayAdmission::ExactDuplicate
        );
        assert_eq!(encode_replay_window(&window), before);
        assert_eq!(
            window
                .observe_at_revision(6, 10, tuple_hash(10))
                .expect("audited current revision may advance over multiple rewraps"),
            ReplayAdmission::Fresh
        );
        assert_eq!(window.directory_revision, 6);
    }

    #[test]
    fn replay_window_observes_correlated_predecessor_without_lowering_revision_high_water() {
        let mut window = ReplayWindow {
            key_epoch: 7,
            directory_revision: 6,
            nonce_reuse_quarantined: false,
            entries: vec![ReplayEntry {
                counter: 9,
                signed_blob_hash: tuple_hash(9),
            }],
        };
        assert_eq!(
            window
                .observe_at_revision(4, 10, tuple_hash(10))
                .expect("verified pending request may correlate a predecessor reply"),
            ReplayAdmission::Fresh
        );
        assert_eq!(window.directory_revision, 6);
        assert_eq!(
            window
                .observe_at_revision(4, 10, tuple_hash(10))
                .expect("exact predecessor duplicate remains idempotent"),
            ReplayAdmission::ExactDuplicate
        );
        assert_eq!(
            window
                .observe_at_revision(4, 10, [0x55; 32])
                .expect("predecessor nonce reuse must quarantine the shared domain"),
            ReplayAdmission::NonceReuse
        );
        assert_eq!(window.directory_revision, 6);
        assert!(window.nonce_reuse_quarantined);
    }

    #[test]
    fn current_reply_scope_carries_predecessor_quarantine_across_same_epoch_rewrap() {
        let predecessor = ReplayWindow {
            key_epoch: 7,
            directory_revision: 4,
            nonce_reuse_quarantined: true,
            entries: vec![ReplayEntry {
                counter: 9,
                signed_blob_hash: tuple_hash(9),
            }],
        };
        assert!(matches!(
            validate_current_reply_replay_scope(&[predecessor], 7, 5),
            Err(RemoteRuntimeError::ReplayRejected)
        ));
    }

    #[test]
    fn current_reply_scope_accepts_any_predecessor_and_rejects_zero_future_or_duplicates() {
        let window = |revision| ReplayWindow {
            key_epoch: 7,
            directory_revision: revision,
            nonce_reuse_quarantined: false,
            entries: vec![ReplayEntry {
                counter: revision,
                signed_blob_hash: tuple_hash(revision),
            }],
        };
        assert!(validate_current_reply_replay_scope(&[window(3)], 7, 5).is_ok());
        assert!(validate_current_reply_replay_scope(&[window(4)], 7, 5).is_ok());
        assert!(validate_current_reply_replay_scope(&[window(5)], 7, 5).is_ok());
        for invalid in [vec![window(0)], vec![window(6)], vec![window(4), window(5)]] {
            assert!(matches!(
                validate_current_reply_replay_scope(&invalid, 7, 5),
                Err(RemoteRuntimeError::InvalidDurableState)
            ));
        }
    }
}
