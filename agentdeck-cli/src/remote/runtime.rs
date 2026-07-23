//! Persistent remote Runtime command transport.
//!
//! 本模块只把已配对 machine 的 typed crypto capability 与 Relay `Send`/`Reply`
//! transport 组合起来；Relay 的 `RouteAccepted` 仅是传输状态，业务成功只来自经完整
//! 验证且已 durable terminal 的 daemon typed reply。

#![cfg(unix)]

use std::convert::Infallible;

use agentdeck_crypto::rand_core::{CryptoRng, TryCryptoRng, TryRng};
use agentdeck_crypto::sha256;
use agentdeck_protocol::ActionDecision;
use agentdeck_protocol::e2ee::SealedPayloadKind;
use agentdeck_protocol::relay_v2::frame::{AcceptedRef, SealedBlob, Send as RelaySend};
use agentdeck_protocol::relay_v2::{
    CodecError, GrantSerial as RelayGrantSerial, MAX_FRAME_BYTES, OpaqueRouteFrame,
    RELAY_PROTOCOL_VERSION, RelayFrameBody, RequestRouteId, decode, encode,
};
use agentdeck_protocol::runtime::command::{CatalogRequest, RevokeRequest, RevokeTarget};
use agentdeck_protocol::runtime::identity::{
    ApprovalId, CatalogPageCursor, GrantSerial as RuntimeGrantSerial, MessageId, TurnId,
};
use agentdeck_protocol::runtime::{
    ApprovalDeliveryState, ApprovalReceipt, CatalogSnapshot, CommandReceipt, ConversationId,
    MAX_RUNTIME_JSON_FRAME_BYTES, RUNTIME_PROTOCOL_VERSION, RevocationReceipt, RuntimeEnvelope,
    RuntimeFailure, RuntimeMessage, RuntimeReply, SendPromptRequest,
};
use agentdeck_relay_client::RelayClientError;
use async_trait::async_trait;
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroize;

use super::paired_machine::{
    AuthorizedRuntimeRequest, OpaqueRuntimeState, OpenedPairedMachine, PairedPromotionError,
    VerifiedDirectedReply, VerifiedRevocationTerminal,
};

const EXCHANGE_MAGIC: &[u8; 4] = b"ADRX";
const LEGACY_EXCHANGE_VERSION: u16 = 1;
const EXCHANGE_VERSION: u16 = 2;
const EXCHANGE_PENDING: u8 = 0;
const EXCHANGE_TERMINAL: u8 = 1;
const REPLAY_MAGIC: &[u8; 4] = b"ADRW";
const REPLAY_VERSION: u16 = 1;
const MAX_REPLAY_WINDOWS: usize = 4_096;
const MAX_REPLAY_ENTRIES: usize = 4_096;
const CATALOG_INTENT_DOMAIN: &[u8] = b"AgentDeck/RemoteCatalogIntentV1\0";
const INTENT_DOMAIN: &[u8] = b"AgentDeck/RemotePromptIntentV1\0";
const RESOLVE_APPROVAL_INTENT_DOMAIN: &[u8] = b"AgentDeck/RemoteResolveApprovalIntentV1\0";
const RETRY_APPROVAL_INTENT_DOMAIN: &[u8] = b"AgentDeck/RemoteRetryApprovalIntentV1\0";
const REVOKE_SELF_INTENT_DOMAIN: &[u8] = b"AgentDeck/RemoteRevokeSelfIntentV1\0";
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

impl RemoteCatalogPageOutcome {
    #[must_use]
    pub const fn route_accepted(&self) -> bool {
        self.route_accepted
    }

    #[must_use]
    pub const fn snapshot(&self) -> &CatalogSnapshot {
        &self.snapshot
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
    #[error("catalog compact transfer replies are not supported by this runtime slice")]
    TransferUnsupported,
    #[error("authenticated reply replay tuple was rejected")]
    ReplayRejected,
    #[error("durable remote runtime state has an invalid canonical encoding")]
    InvalidDurableState,
}

/// 持有同一 machine 独占 lease 的 remote Runtime command 编排器。
///
/// 字段声明顺序是 drop 顺序：先关闭 transport，再最后释放 machine lease/capability。
pub struct RemoteRuntime<'a, T> {
    transport: T,
    machine: OpenedPairedMachine<'a>,
}

impl<'a, T> RemoteRuntime<'a, T>
where
    T: RemoteRuntimeTransport,
{
    #[must_use]
    pub const fn new(machine: OpenedPairedMachine<'a>, transport: T) -> Self {
        Self { transport, machine }
    }

    /// 显式等待 transport shutdown，随后按字段顺序先销毁 transport、再释放 device lease。
    pub async fn shutdown(mut self) {
        self.transport.shutdown().await;
    }

    /// 请求一页 catalog；A1 只接受未分片的 authenticated `CatalogSnapshot`。
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
        self.consume_catalog_terminal(&operation)?;
        Ok(RemoteCatalogPageOutcome {
            route_accepted: outcome.route_accepted,
            snapshot,
        })
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

        let Self { transport, machine } = self;
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

        // Durable pending 保存的是完整 Relay codec bytes；每次发送都从 exact bytes 解码，
        // 避免重启后重新 seal/sign 或重建任一随机字段。
        self.transport
            .send(ExactRelayFrame::from_frozen(pending.exact_send.clone())?)
            .await?;

        let mut route_accepted = false;
        loop {
            let Some(received) = self.transport.recv().await? else {
                return Err(RemoteRuntimeError::OutcomeUnknown);
            };
            validate_received_runtime_frame(&received)?;
            let reply_frame_hash = sha256(received.canonical_bytes());
            let frame = received.frame();
            match &frame.body {
                RelayFrameBody::RouteAccepted(accepted) => match accepted.accepted {
                    AcceptedRef::Request { request_route }
                        if request_route == pending.request_route =>
                    {
                        route_accepted = true;
                    }
                    _ => {
                        return Err(RemoteRuntimeError::InvalidReply(
                            "RouteAccepted does not match the pending request",
                        ));
                    }
                },
                RelayFrameBody::Reply(reply) => {
                    if reply.device_route != self.machine.device_route()
                        || reply.request_route != pending.request_route
                    {
                        return Err(RemoteRuntimeError::InvalidReply(
                            "Reply outer route does not match the pending request",
                        ));
                    }
                    let candidate = self
                        .machine
                        .verify_directed_reply(pending.request_route, &reply.sealed_blob.0)?;

                    // MachineDataSign 成功后、AEAD 前 durable consume replay tuple。即使后续
                    // ciphertext/tag 失败，同 counter 的另一 signed ciphertext 也不能重试。
                    self.admit_reply_replay(&candidate)?;
                    let opened = self.machine.open_verified_directed_reply(candidate)?;
                    if opened.payload_kind == SealedPayloadKind::TransferPart {
                        if matches!(pending.operation, DirectedOperation::Catalog { .. }) {
                            return Err(RemoteRuntimeError::TransferUnsupported);
                        }
                        return Err(RemoteRuntimeError::InvalidReply(
                            "directed transfer reply does not match the pending request",
                        ));
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
                    let envelope: RuntimeEnvelope = serde_json::from_slice(&opened.payload)?;
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
                            self.persist_terminal(&pending, reply_frame_hash, &receipt)?;
                            return directed_outcome(route_accepted, receipt)
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

    fn prepare_pending<R: CryptoRng>(
        &mut self,
        plan: DirectedRequestPlan,
        rng: &mut R,
    ) -> Result<PendingExchange, RemoteRuntimeError> {
        let request_route = RequestRouteId::from_bytes(random_nonzero::<16, _>(rng)?);
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
        let current = self.machine.opaque_runtime_state();
        let mut windows = current
            .replay_windows()
            .iter()
            .map(|bytes| decode_replay_window(bytes))
            .collect::<Result<Vec<_>, _>>()?;
        if windows.len() > MAX_REPLAY_WINDOWS {
            return Err(RemoteRuntimeError::InvalidDurableState);
        }
        let scope_matches = |window: &&ReplayWindow| {
            window.key_epoch == candidate.key_epoch()
                && window.directory_revision == candidate.directory_revision()
        };
        let matching = windows.iter().filter(scope_matches).count();
        if matching > 1 {
            return Err(RemoteRuntimeError::InvalidDurableState);
        }
        let hash = candidate.signed_blob_hash();
        let admission = if let Some(window) = windows.iter_mut().find(|window| {
            window.key_epoch == candidate.key_epoch()
                && window.directory_revision == candidate.directory_revision()
        }) {
            window.observe(candidate.counter(), hash)?
        } else {
            if windows.len() >= MAX_REPLAY_WINDOWS {
                return Err(RemoteRuntimeError::ReplayRejected);
            }
            windows.push(ReplayWindow {
                key_epoch: candidate.key_epoch(),
                directory_revision: candidate.directory_revision(),
                nonce_reuse_quarantined: false,
                entries: vec![ReplayEntry {
                    counter: candidate.counter(),
                    signed_blob_hash: hash,
                }],
            });
            ReplayAdmission::Fresh
        };
        if admission == ReplayAdmission::ExactDuplicate {
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
            ReplayAdmission::NonceReuse => Err(RemoteRuntimeError::ReplayRejected),
            ReplayAdmission::ExactDuplicate => unreachable!("exact duplicate returned above"),
        }
    }

    fn reject_quarantined_current_reply_scope(&self) -> Result<(), RemoteRuntimeError> {
        let (key_epoch, directory_revision) = self.machine.directed_reply_scope()?;
        let mut matching = 0_usize;
        for bytes in self.machine.opaque_runtime_state().replay_windows() {
            let window = decode_replay_window(bytes)?;
            if window.key_epoch == key_epoch && window.directory_revision == directory_revision {
                matching += 1;
                if window.nonce_reuse_quarantined {
                    return Err(RemoteRuntimeError::ReplayRejected);
                }
            }
        }
        if matching > 1 {
            return Err(RemoteRuntimeError::InvalidDurableState);
        }
        Ok(())
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
            DirectedOperation::Catalog { .. }
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
            (Self::Catalog { .. }, RuntimeReply::Catalog(snapshot))
                if payload_kind == SealedPayloadKind::CatalogSnapshot =>
            {
                Ok(ValidatedDirectedReply::Terminal(DirectedReceipt::Catalog(
                    snapshot,
                )))
            }
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
            (Self::Catalog { .. }, DirectedReceipt::Catalog(_)) => true,
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
            (_, DirectedReceipt::Failure(_)) => true,
            _ => false,
        }
    }

    fn retry_attempt(&self) -> Result<u64, RemoteRuntimeError> {
        match self {
            Self::RetryApproval { attempt, .. } if *attempt > 0 => Ok(*attempt),
            Self::RetryApproval { .. } => Err(RemoteRuntimeError::InvalidDurableState),
            Self::Catalog { .. }
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

struct DirectedOutcome {
    route_accepted: bool,
    receipt: DirectedReceipt,
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

fn directed_outcome(
    route_accepted: bool,
    receipt: DirectedReceipt,
) -> Result<DirectedOutcome, RemoteRuntimeError> {
    match receipt {
        DirectedReceipt::Failure(failure) => Err(RemoteRuntimeError::DaemonFailure(failure)),
        receipt => Ok(DirectedOutcome {
            route_accepted,
            receipt,
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
    if !matches!(version, LEGACY_EXCHANGE_VERSION | EXCHANGE_VERSION) {
        return Err(RemoteRuntimeError::InvalidDurableState);
    }
    let tag = reader.u8()?;
    let current_operation = if version == EXCHANGE_VERSION {
        Some(decode_operation(&mut reader)?)
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

fn decode_operation(reader: &mut Reader<'_>) -> Result<DirectedOperation, RemoteRuntimeError> {
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
    fn current_v2_terminal_rejects_noncanonical_receipt_json() {
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
        let canonical = encode_exchange(&exchange).expect("canonical v2 terminal");
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
}
