//! Runtime snapshot/backfill 的 JSON/UDS `TransferPart` egress。
//!
//! 威胁场景：大 snapshot/backfill 若一次塞入 1 MiB envelope 会失败或挤爆 writer，
//! 所以这里按 raw JSON <= 700 KiB 分片，并逐 part 等待真实 transport flush receipt
//! 后才推进；取消与 absolute deadline 不会因已完成一个 part 而续期。

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use agentdeck_protocol::runtime::identity::{MessageId, TransferId};
use agentdeck_protocol::runtime::{
    MAX_JSON_PART_BYTES, MAX_JSON_TRANSFER_PARTS, MAX_PART_BYTES, MAX_TRANSFER_BYTES,
    MAX_TRANSFER_PARTS, RUNTIME_PROTOCOL_VERSION, RuntimeEnvelope, RuntimeMessage, RuntimeReply,
    RuntimeStreamItem, RuntimeTransferCarrierV1, RuntimeTransferChannel, TransferEnvelope,
    TransferError,
};
use sha2::{Digest, Sha256};
use tokio::sync::Notify;
use tokio::time::Instant;

use super::super::connection::{
    ConnectionError, ConnectionFramingProfile, ConnectionId, ConnectionRegistry,
    EncodedRuntimeFrame,
};

/// 受 JSON carrier 的 part 数与 raw part 上限共同约束的真实 payload 上限。
pub(crate) const MAX_JSON_TRANSFER_PAYLOAD_BYTES: usize = MAX_TRANSFER_BYTES as usize;

#[derive(Debug)]
struct CancellationState {
    cancelled: AtomicBool,
    changed: Notify,
}

/// reply pump、unsubscribe 与 disconnect 共享的取消 capability。
#[derive(Clone, Debug)]
pub(crate) struct TransferEgressControl {
    absolute_deadline: Option<Instant>,
    cancellation: Arc<CancellationState>,
}

impl TransferEgressControl {
    /// deadline 必须由 barrier 建立时一次计算；本类型没有“从当前时刻续期”接口。
    pub(crate) fn new(absolute_deadline: Instant) -> Self {
        Self {
            absolute_deadline: Some(absolute_deadline),
            cancellation: Arc::new(CancellationState {
                cancelled: AtomicBool::new(false),
                changed: Notify::new(),
            }),
        }
    }

    pub(crate) fn cancel(&self) {
        if !self.cancellation.cancelled.swap(true, Ordering::AcqRel) {
            self.cancellation.changed.notify_waiters();
        }
    }

    pub(crate) fn is_cancelled(&self) -> bool {
        self.cancellation.cancelled.load(Ordering::Acquire)
    }

    pub(crate) fn without_deadline(&self) -> Self {
        Self {
            absolute_deadline: None,
            cancellation: self.cancellation.clone(),
        }
    }

    pub(crate) fn absolute_deadline(&self) -> Option<Instant> {
        self.absolute_deadline
    }

    pub(crate) async fn cancelled(&self) {
        loop {
            if self.is_cancelled() {
                return;
            }
            let changed = self.cancellation.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.is_cancelled() {
                return;
            }
            changed.await;
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum TransferEgressErrorKind {
    #[error("transfer identity is empty or exceeds its UTF-8 wire bound")]
    InvalidIdentity,
    #[error("transfer cannot be represented by the selected bounded carrier profile")]
    TooLarge,
    #[error("transfer egress was cancelled")]
    Cancelled,
    #[error("transfer egress reached its absolute deadline")]
    Expired,
    #[error("runtime transfer frame encoding failed: {0}")]
    Frame(#[source] ConnectionError),
    #[error("runtime paced writer reservation failed: {0}")]
    Reserve(#[source] ConnectionError),
    #[error("runtime paced writer commit failed: {0}")]
    Commit(#[source] ConnectionError),
    #[error("runtime transport flush failed: {0}")]
    Flush(#[source] ConnectionError),
    #[error("transfer part construction failed: {0}")]
    Transfer(#[source] TransferError),
}

/// `flushed_parts` 只统计 transport 已 ACK 的 part；当前未 ACK part 可能已交给 socket，
/// 因此调用方失败后不得发送 `SyncComplete`，也不能把错误解释成“客户端完全未见”。
#[derive(Debug, thiserror::Error)]
#[error("transfer egress failed after {flushed_parts} flushed parts: {kind}")]
pub(crate) struct TransferEgressError {
    kind: TransferEgressErrorKind,
    flushed_parts: u32,
}

impl TransferEgressError {
    #[cfg(test)]
    pub(crate) fn kind(&self) -> &TransferEgressErrorKind {
        &self.kind
    }

    pub(crate) fn flushed_parts(&self) -> u32 {
        self.flushed_parts
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TransferEgressReport {
    pub(crate) part_count: u32,
    pub(crate) total_bytes: u64,
    pub(crate) total_sha256: [u8; 32],
}

fn json_transfer_part_count(payload_bytes: usize) -> Result<u32, TransferEgressErrorKind> {
    if payload_bytes > MAX_JSON_TRANSFER_PAYLOAD_BYTES {
        return Err(TransferEgressErrorKind::TooLarge);
    }
    let count = payload_bytes.max(1).div_ceil(MAX_JSON_PART_BYTES);
    let count = u32::try_from(count).map_err(|_| TransferEgressErrorKind::TooLarge)?;
    if count == 0 || count > MAX_JSON_TRANSFER_PARTS {
        Err(TransferEgressErrorKind::TooLarge)
    } else {
        Ok(count)
    }
}

fn compact_transfer_part_count(payload_bytes: usize) -> Result<u32, TransferEgressErrorKind> {
    if payload_bytes > MAX_TRANSFER_BYTES as usize {
        return Err(TransferEgressErrorKind::TooLarge);
    }
    let count = payload_bytes.max(1).div_ceil(MAX_PART_BYTES);
    let count = u32::try_from(count).map_err(|_| TransferEgressErrorKind::TooLarge)?;
    if count == 0 || count > MAX_TRANSFER_PARTS {
        Err(TransferEgressErrorKind::TooLarge)
    } else {
        Ok(count)
    }
}

/// 按 connection 安装时声明的中立 framing capability 选择 Stream transfer carrier。
/// local UDS 保持 JSON/700 KiB；MachineLink 使用 ADRT1/3.5 MiB。普通 Runtime JSON
/// 始终只能经 `EncodedRuntimeFrame::from_envelope`，不能借此入口放宽 1 MiB gate。
pub(crate) async fn send_stream_transfer(
    connections: &ConnectionRegistry,
    connection_id: ConnectionId,
    message_id: MessageId,
    transfer_id: TransferId,
    payload: &[u8],
    control: &TransferEgressControl,
) -> Result<TransferEgressReport, TransferEgressError> {
    match connections
        .framing_profile(connection_id)
        .map_err(|error| failed(TransferEgressErrorKind::Reserve(error), 0))?
    {
        ConnectionFramingProfile::JsonRuntime => {
            send_json_transfer(
                connections,
                connection_id,
                message_id,
                transfer_id,
                RuntimeTransferChannel::Stream,
                payload,
                control,
            )
            .await
        }
        ConnectionFramingProfile::CompactTransfer => {
            send_compact_transfer(
                connections,
                connection_id,
                message_id,
                transfer_id,
                RuntimeTransferChannel::Stream,
                payload,
                control,
            )
            .await
        }
    }
}

/// 按 connection framing capability 选择 directed Reply transfer carrier。
/// local UDS 保持 JSON/94-part，MachineLink 使用 ADRT1/64-part；两者都不改变
/// canonical reply payload bytes 或 message identity。
pub(crate) async fn send_reply_transfer(
    connections: &ConnectionRegistry,
    connection_id: ConnectionId,
    message_id: MessageId,
    transfer_id: TransferId,
    payload: &[u8],
    control: &TransferEgressControl,
) -> Result<TransferEgressReport, TransferEgressError> {
    match connections
        .framing_profile(connection_id)
        .map_err(|error| failed(TransferEgressErrorKind::Reserve(error), 0))?
    {
        ConnectionFramingProfile::JsonRuntime => {
            send_json_transfer(
                connections,
                connection_id,
                message_id,
                transfer_id,
                RuntimeTransferChannel::Reply,
                payload,
                control,
            )
            .await
        }
        ConnectionFramingProfile::CompactTransfer => {
            send_compact_transfer(
                connections,
                connection_id,
                message_id,
                transfer_id,
                RuntimeTransferChannel::Reply,
                payload,
                control,
            )
            .await
        }
    }
}

/// 将一份已经 canonical encode 的 snapshot/backfill payload 分片并串行 flush。
///
/// 本函数直接调用 production `ConnectionRegistry::{reserve_paced, commit_paced}` 与
/// `FlushReceipt::wait`；不提供影子 pacer，也不在 Core/actor/SQLite 锁内等待 writer。
pub(crate) async fn send_json_transfer(
    connections: &ConnectionRegistry,
    connection_id: ConnectionId,
    message_id: MessageId,
    transfer_id: TransferId,
    channel: RuntimeTransferChannel,
    payload: &[u8],
    control: &TransferEgressControl,
) -> Result<TransferEgressReport, TransferEgressError> {
    if !message_id.is_valid_wire_value() || !transfer_id.is_valid_wire_value() {
        return Err(failed(TransferEgressErrorKind::InvalidIdentity, 0));
    }
    let part_count = json_transfer_part_count(payload.len()).map_err(|kind| failed(kind, 0))?;
    let total_bytes =
        u64::try_from(payload.len()).map_err(|_| failed(TransferEgressErrorKind::TooLarge, 0))?;
    let total_sha256: [u8; 32] = Sha256::digest(payload).into();
    let mut flushed_parts = 0_u32;

    for part_index in 0..part_count {
        ensure_active(control, flushed_parts)?;
        let start = part_index as usize * MAX_JSON_PART_BYTES;
        let end = start.saturating_add(MAX_JSON_PART_BYTES).min(payload.len());
        let part = if start < payload.len() {
            payload[start..end].to_vec()
        } else {
            Vec::new()
        };
        let transfer = TransferEnvelope::new_json(
            transfer_id.clone(),
            part_index,
            part_count,
            total_sha256,
            total_bytes,
            part,
        )
        .map_err(|error| failed(TransferEgressErrorKind::Transfer(error), flushed_parts))?;
        transfer
            .validate_json_part()
            .map_err(|error| failed(TransferEgressErrorKind::Transfer(error), flushed_parts))?;
        let body = match channel {
            RuntimeTransferChannel::Reply => {
                RuntimeMessage::Reply(RuntimeReply::TransferPart(transfer))
            }
            RuntimeTransferChannel::Stream => {
                RuntimeMessage::Stream(RuntimeStreamItem::TransferPart(transfer))
            }
        };
        let envelope = RuntimeEnvelope {
            version: RUNTIME_PROTOCOL_VERSION,
            message_id: message_id.clone(),
            body,
        };

        let frame = EncodedRuntimeFrame::from_envelope(&envelope)
            .map_err(|error| failed(TransferEgressErrorKind::Frame(error), flushed_parts))?;
        let reservation = controlled(control, connections.reserve_paced(connection_id, frame))
            .await
            .map_err(|kind| failed(kind, flushed_parts))?
            .map_err(|error| failed(TransferEgressErrorKind::Reserve(error), flushed_parts))?;
        ensure_active(control, flushed_parts)?;
        let receipt = connections
            .commit_paced(reservation)
            .map_err(|error| failed(TransferEgressErrorKind::Commit(error), flushed_parts))?;
        controlled(control, receipt.wait())
            .await
            .map_err(|kind| failed(kind, flushed_parts))?
            .map_err(|error| failed(TransferEgressErrorKind::Flush(error), flushed_parts))?;
        flushed_parts = flushed_parts
            .checked_add(1)
            .ok_or_else(|| failed(TransferEgressErrorKind::TooLarge, flushed_parts))?;
    }

    Ok(TransferEgressReport {
        part_count,
        total_bytes,
        total_sha256,
    })
}

async fn send_compact_transfer(
    connections: &ConnectionRegistry,
    connection_id: ConnectionId,
    message_id: MessageId,
    transfer_id: TransferId,
    channel: RuntimeTransferChannel,
    payload: &[u8],
    control: &TransferEgressControl,
) -> Result<TransferEgressReport, TransferEgressError> {
    if !message_id.is_valid_wire_value() || !transfer_id.is_valid_wire_value() {
        return Err(failed(TransferEgressErrorKind::InvalidIdentity, 0));
    }
    let part_count = compact_transfer_part_count(payload.len()).map_err(|kind| failed(kind, 0))?;
    let total_bytes =
        u64::try_from(payload.len()).map_err(|_| failed(TransferEgressErrorKind::TooLarge, 0))?;
    let total_sha256: [u8; 32] = Sha256::digest(payload).into();
    let mut flushed_parts = 0_u32;

    for part_index in 0..part_count {
        ensure_active(control, flushed_parts)?;
        let start = part_index as usize * MAX_PART_BYTES;
        let end = start.saturating_add(MAX_PART_BYTES).min(payload.len());
        let part = if start < payload.len() {
            payload[start..end].to_vec()
        } else {
            Vec::new()
        };
        let transfer = TransferEnvelope::new(
            transfer_id.clone(),
            part_index,
            part_count,
            total_sha256,
            total_bytes,
            part,
        )
        .map_err(|error| failed(TransferEgressErrorKind::Transfer(error), flushed_parts))?;
        let carrier = RuntimeTransferCarrierV1::new(message_id.clone(), channel, transfer);
        let frame = EncodedRuntimeFrame::from_transfer_carrier(&carrier)
            .map_err(|error| failed(TransferEgressErrorKind::Frame(error), flushed_parts))?;
        let reservation = controlled(control, connections.reserve_paced(connection_id, frame))
            .await
            .map_err(|kind| failed(kind, flushed_parts))?
            .map_err(|error| failed(TransferEgressErrorKind::Reserve(error), flushed_parts))?;
        ensure_active(control, flushed_parts)?;
        let receipt = connections
            .commit_paced(reservation)
            .map_err(|error| failed(TransferEgressErrorKind::Commit(error), flushed_parts))?;
        controlled(control, receipt.wait())
            .await
            .map_err(|kind| failed(kind, flushed_parts))?
            .map_err(|error| failed(TransferEgressErrorKind::Flush(error), flushed_parts))?;
        flushed_parts = flushed_parts
            .checked_add(1)
            .ok_or_else(|| failed(TransferEgressErrorKind::TooLarge, flushed_parts))?;
    }

    Ok(TransferEgressReport {
        part_count,
        total_bytes,
        total_sha256,
    })
}

fn ensure_active(
    control: &TransferEgressControl,
    flushed_parts: u32,
) -> Result<(), TransferEgressError> {
    if control.is_cancelled() {
        return Err(failed(TransferEgressErrorKind::Cancelled, flushed_parts));
    }
    if control
        .absolute_deadline
        .is_some_and(|deadline| Instant::now() >= deadline)
    {
        return Err(failed(TransferEgressErrorKind::Expired, flushed_parts));
    }
    Ok(())
}

async fn controlled<T>(
    control: &TransferEgressControl,
    operation: impl Future<Output = T>,
) -> Result<T, TransferEgressErrorKind> {
    if let Some(deadline) = control.absolute_deadline {
        tokio::select! {
            biased;
            _ = control.cancelled() => Err(TransferEgressErrorKind::Cancelled),
            _ = tokio::time::sleep_until(deadline) => Err(TransferEgressErrorKind::Expired),
            output = operation => Ok(output),
        }
    } else {
        tokio::select! {
            biased;
            _ = control.cancelled() => Err(TransferEgressErrorKind::Cancelled),
            output = operation => Ok(output),
        }
    }
}

fn failed(kind: TransferEgressErrorKind, flushed_parts: u32) -> TransferEgressError {
    TransferEgressError {
        kind,
        flushed_parts,
    }
}

#[cfg(test)]
#[path = "egress_tests.rs"]
mod tests;
