//! Persistent remote Runtime command transport.
//!
//! 本模块只把已配对 machine 的 typed crypto capability 与 Relay `Send`/`Reply`
//! transport 组合起来；Relay 的 `RouteAccepted` 仅是传输状态，业务成功只来自经完整
//! 验证且已 durable terminal 的 daemon `CommandReceipt`。

#![cfg(unix)]

use std::convert::Infallible;

use agentdeck_crypto::rand_core::{CryptoRng, TryCryptoRng, TryRng};
use agentdeck_crypto::sha256;
use agentdeck_protocol::e2ee::SealedPayloadKind;
use agentdeck_protocol::relay_v2::frame::{AcceptedRef, SealedBlob, Send as RelaySend};
use agentdeck_protocol::relay_v2::{
    CodecError, MAX_FRAME_BYTES, OpaqueRouteFrame, RELAY_PROTOCOL_VERSION, RelayFrameBody,
    RequestRouteId, decode, encode,
};
use agentdeck_protocol::runtime::identity::MessageId;
use agentdeck_protocol::runtime::{
    CommandReceipt, MAX_RUNTIME_JSON_FRAME_BYTES, RUNTIME_PROTOCOL_VERSION, RuntimeEnvelope,
    RuntimeMessage, RuntimeReply, SendPromptRequest,
};
use agentdeck_relay_client::RelayClientError;
use async_trait::async_trait;
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroize;

use super::paired_machine::{
    OpaqueRuntimeState, OpenedPairedMachine, PairedPromotionError, VerifiedDirectedReply,
};

const EXCHANGE_MAGIC: &[u8; 4] = b"ADRX";
const EXCHANGE_VERSION: u16 = 1;
const EXCHANGE_PENDING: u8 = 0;
const EXCHANGE_TERMINAL: u8 = 1;
const REPLAY_MAGIC: &[u8; 4] = b"ADRW";
const REPLAY_VERSION: u16 = 1;
const MAX_REPLAY_WINDOWS: usize = 4_096;
const MAX_REPLAY_ENTRIES: usize = 4_096;
const INTENT_DOMAIN: &[u8] = b"AgentDeck/RemotePromptIntentV1\0";
const MUTATION_RNG_DOMAIN: &[u8] = b"AgentDeck/RemoteRuntimeMutationRngV1\0";

/// Remote Runtime 对 Relay transport 的最小需求；transport 不解析或伪造业务回执。
#[async_trait]
pub trait RemoteRuntimeTransport: Send {
    async fn send(&mut self, frame: ExactRelayFrame) -> Result<(), RemoteRuntimeTransportError>;

    async fn recv(&mut self) -> Result<Option<OpaqueRouteFrame>, RemoteRuntimeTransportError>;

    /// 等待 transport-owned I/O task 收口；默认用于无后台任务的 automatic fake。
    async fn shutdown(&mut self) {}
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
    #[error("another durable prompt intent is still pending")]
    PendingIntentConflict,
    #[error("transport closed before an authenticated daemon receipt")]
    OutcomeUnknown,
    #[error("remote reply is not correlated or has an invalid shape: {0}")]
    InvalidReply(&'static str),
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

    /// 发送或精确重试一个 prompt，直到得到 authenticated daemon receipt 或非成功错误。
    pub async fn prompt<R: CryptoRng>(
        &mut self,
        request: SendPromptRequest,
        rng: &mut R,
    ) -> Result<RemotePromptOutcome, RemoteRuntimeError> {
        let intent_hash = prompt_intent_hash(&request)?;
        let existing = self
            .machine
            .opaque_runtime_state()
            .exchange()
            .map(decode_exchange)
            .transpose()?;

        let pending = match existing {
            Some(DurableExchange::Pending(pending)) if pending.intent_hash == intent_hash => {
                pending
            }
            Some(DurableExchange::Pending(_)) => {
                return Err(RemoteRuntimeError::PendingIntentConflict);
            }
            Some(DurableExchange::Terminal(terminal)) if terminal.intent_hash == intent_hash => {
                return Ok(RemotePromptOutcome {
                    route_accepted: false,
                    receipt: terminal.receipt,
                });
            }
            Some(DurableExchange::Terminal(_)) | None => {
                self.prepare_pending(intent_hash, request, rng)?
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
            let Some(frame) = self.transport.recv().await? else {
                return Err(RemoteRuntimeError::OutcomeUnknown);
            };
            if frame.version != RELAY_PROTOCOL_VERSION {
                return Err(RemoteRuntimeError::InvalidReply(
                    "unsupported Relay protocol version",
                ));
            }
            let reply_frame_hash = sha256(&encode(&frame));
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
                    if opened.payload_kind != SealedPayloadKind::CommandReceipt {
                        return Err(RemoteRuntimeError::InvalidReply(
                            "directed reply is not a command receipt",
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
                    let RuntimeMessage::Reply(RuntimeReply::Command(receipt)) = envelope.body
                    else {
                        return Err(RemoteRuntimeError::InvalidReply(
                            "Runtime reply is not CommandReceipt",
                        ));
                    };
                    if !receipt_matches_expected_revision(
                        &receipt,
                        pending.expected_configuration_revision,
                    ) {
                        return Err(RemoteRuntimeError::InvalidReply(
                            "CommandReceipt configuration revision does not match the request",
                        ));
                    }
                    self.persist_terminal(&pending, reply_frame_hash, &receipt)?;
                    return Ok(RemotePromptOutcome {
                        route_accepted,
                        receipt,
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
        intent_hash: [u8; 32],
        request: SendPromptRequest,
        rng: &mut R,
    ) -> Result<PendingExchange, RemoteRuntimeError> {
        let expected_configuration_revision = request.expected_configuration_revision;
        let request_route = RequestRouteId::from_bytes(random_nonzero::<16, _>(rng)?);
        let message_id = MessageId::new(
            Uuid::from_bytes(random_nonzero::<16, _>(rng)?)
                .hyphenated()
                .to_string(),
        );
        let reservation = self.machine.reserve_command_counter_block(rng)?;
        let signed = self.machine.seal_runtime_prompt(
            request_route,
            message_id.clone(),
            request,
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
            intent_hash,
            message_id,
            request_route,
            expected_configuration_revision,
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
        receipt: &CommandReceipt,
    ) -> Result<(), RemoteRuntimeError> {
        self.persist_exchange(DurableExchange::Terminal(TerminalExchange {
            intent_hash: pending.intent_hash,
            message_id: pending.message_id.clone(),
            request_route: pending.request_route,
            expected_configuration_revision: pending.expected_configuration_revision,
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

#[derive(Clone)]
struct PendingExchange {
    intent_hash: [u8; 32],
    message_id: MessageId,
    request_route: RequestRouteId,
    expected_configuration_revision: u64,
    exact_send: Vec<u8>,
}

struct TerminalExchange {
    intent_hash: [u8; 32],
    message_id: MessageId,
    request_route: RequestRouteId,
    expected_configuration_revision: u64,
    request_frame_hash: [u8; 32],
    reply_frame_hash: [u8; 32],
    receipt: CommandReceipt,
}

enum DurableExchange {
    Pending(PendingExchange),
    Terminal(TerminalExchange),
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

fn prompt_intent_hash(request: &SendPromptRequest) -> Result<[u8; 32], RemoteRuntimeError> {
    let request_bytes = serde_json::to_vec(request)?;
    let mut preimage = Vec::with_capacity(INTENT_DOMAIN.len() + 8 + request_bytes.len());
    preimage.extend_from_slice(INTENT_DOMAIN);
    preimage.extend_from_slice(&RELAY_PROTOCOL_VERSION.to_be_bytes());
    preimage.extend_from_slice(&RUNTIME_PROTOCOL_VERSION.to_be_bytes());
    preimage.extend_from_slice(
        &u32::try_from(request_bytes.len())
            .map_err(|_| RemoteRuntimeError::InvalidDurableState)?
            .to_be_bytes(),
    );
    preimage.extend_from_slice(&request_bytes);
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
            output.extend_from_slice(&value.intent_hash);
            put_short_bytes(&mut output, value.message_id.as_str().as_bytes())?;
            output.extend_from_slice(value.request_route.as_bytes());
            output.extend_from_slice(&value.expected_configuration_revision.to_be_bytes());
            put_bytes(&mut output, &value.exact_send)?;
        }
        DurableExchange::Terminal(value) => {
            output.push(EXCHANGE_TERMINAL);
            output.extend_from_slice(&value.intent_hash);
            put_short_bytes(&mut output, value.message_id.as_str().as_bytes())?;
            output.extend_from_slice(value.request_route.as_bytes());
            output.extend_from_slice(&value.expected_configuration_revision.to_be_bytes());
            output.extend_from_slice(&value.request_frame_hash);
            output.extend_from_slice(&value.reply_frame_hash);
            put_bytes(&mut output, &serde_json::to_vec(&value.receipt)?)?;
        }
    }
    Ok(output)
}

fn decode_exchange(bytes: &[u8]) -> Result<DurableExchange, RemoteRuntimeError> {
    let mut reader = Reader::new(bytes);
    if reader.fixed::<4>()? != *EXCHANGE_MAGIC || reader.u16()? != EXCHANGE_VERSION {
        return Err(RemoteRuntimeError::InvalidDurableState);
    }
    let tag = reader.u8()?;
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
    let expected_configuration_revision = reader.u64()?;
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
                intent_hash,
                message_id,
                request_route,
                expected_configuration_revision,
                exact_send,
            })
        }
        EXCHANGE_TERMINAL => {
            let request_frame_hash = reader.fixed::<32>()?;
            let reply_frame_hash = reader.fixed::<32>()?;
            let receipt_bytes = reader.bytes(MAX_RUNTIME_JSON_FRAME_BYTES - 1)?;
            let receipt: CommandReceipt = serde_json::from_slice(receipt_bytes)?;
            if !receipt_matches_expected_revision(&receipt, expected_configuration_revision) {
                return Err(RemoteRuntimeError::InvalidDurableState);
            }
            DurableExchange::Terminal(TerminalExchange {
                intent_hash,
                message_id,
                request_route,
                expected_configuration_revision,
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

    fn tuple_hash(counter: u64) -> [u8; 32] {
        sha256(&counter.to_be_bytes())
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
