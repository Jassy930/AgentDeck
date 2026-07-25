//! 单 connection gate 内的 paced reply/stream 发送。

use std::future::Future;

use agentdeck_protocol::runtime::identity::MessageId;
use agentdeck_protocol::runtime::{
    RUNTIME_PROTOCOL_VERSION, RuntimeEnvelope, RuntimeMessage, RuntimeReply, RuntimeStreamItem,
};

use super::super::egress::{
    TransferEgressControl, TransferEgressError, send_reply_transfer, send_stream_transfer,
};
use crate::runtime::connection::{
    ConnectionError, ConnectionId, ConnectionRegistry, EncodedRuntimeFrame,
};
use crate::runtime::transfer_identity::{
    DurableReplyTransferIdentity, DurableStreamSource, DurableStreamTransferIdentity,
    DurableStreamTransferIdentityError,
};

#[derive(Debug, thiserror::Error)]
pub(in crate::runtime::subscription) enum PumpSendError {
    #[error(transparent)]
    Connection(#[from] ConnectionError),
    #[error(transparent)]
    Transfer(#[from] TransferEgressError),
    #[error("subscription egress was cancelled")]
    Cancelled,
    #[error("subscription egress reached its absolute deadline")]
    Expired,
    #[error("subscription egress identity entropy is unavailable")]
    Entropy,
    #[error("oversized runtime item has no transfer DTO payload")]
    MissingTransferPayload,
    #[error("stream-binding metadata cannot be represented by reply transfer framing")]
    StreamBindingTransferUnsupported,
    #[error(transparent)]
    DurableTransferIdentity(#[from] DurableStreamTransferIdentityError),
}

pub(super) async fn reply(
    connections: &ConnectionRegistry,
    connection_id: ConnectionId,
    message_id: MessageId,
    reply: RuntimeReply,
    transfer_payload: Option<&[u8]>,
    control: &TransferEgressControl,
) -> Result<(), PumpSendError> {
    reply_with_stream_binding(
        connections,
        connection_id,
        message_id,
        reply,
        transfer_payload,
        None,
        control,
    )
    .await
}

pub(super) async fn reply_with_stream_binding(
    connections: &ConnectionRegistry,
    connection_id: ConnectionId,
    message_id: MessageId,
    reply: RuntimeReply,
    transfer_payload: Option<&[u8]>,
    stream_binding: Option<crate::runtime::store::StreamBindingPermit>,
    control: &TransferEgressControl,
) -> Result<(), PumpSendError> {
    let carries_stream_binding = stream_binding.is_some();
    let transfer_identity = transfer_payload
        .map(|payload| DurableReplyTransferIdentity::for_reply(&message_id, &reply, payload))
        .transpose()?;
    let transfer_part_bytes = connections
        .framing_profile(connection_id)?
        .transfer_part_bytes();
    // 威胁场景：已 canonical encode 的 64 MiB snapshot 若先再尝试序列化成 1 MiB
    // envelope，raw payload、typed DTO 与注定失败的第二份大 buffer 会同时驻留。
    // 达到当前 transport 的单 part 大小时直接走对应 paced transfer。
    if let Some(payload) = transfer_payload
        && payload.len() >= transfer_part_bytes
    {
        if carries_stream_binding {
            return Err(PumpSendError::StreamBindingTransferUnsupported);
        }
        send_reply_transfer(
            connections,
            connection_id,
            message_id,
            transfer_identity
                .ok_or(PumpSendError::MissingTransferPayload)?
                .transfer_id(),
            payload,
            control,
        )
        .await?;
        return Ok(());
    }
    let envelope = RuntimeEnvelope {
        version: RUNTIME_PROTOCOL_VERSION,
        message_id: message_id.clone(),
        body: RuntimeMessage::Reply(reply),
    };
    match EncodedRuntimeFrame::from_envelope(&envelope).map(|frame| match stream_binding {
        Some(permit) => frame.with_stream_binding(permit),
        None => frame,
    }) {
        Ok(frame) => paced(connections, connection_id, frame, control).await,
        Err(ConnectionError::FrameTooLarge) => {
            if carries_stream_binding {
                return Err(PumpSendError::StreamBindingTransferUnsupported);
            }
            let payload = transfer_payload.ok_or(PumpSendError::MissingTransferPayload)?;
            let transfer_identity =
                transfer_identity.ok_or(PumpSendError::MissingTransferPayload)?;
            send_reply_transfer(
                connections,
                connection_id,
                message_id,
                transfer_identity.transfer_id(),
                payload,
                control,
            )
            .await?;
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}

pub(super) async fn stream(
    connections: &ConnectionRegistry,
    connection_id: ConnectionId,
    durable_source: DurableStreamSource,
    item: RuntimeStreamItem,
    transfer_payload: Option<&[u8]>,
    control: &TransferEgressControl,
) -> Result<(), PumpSendError> {
    let transfer_identity = transfer_payload
        .map(|payload| {
            DurableStreamTransferIdentity::for_stream_source(durable_source, &item, payload)
        })
        .transpose()?;
    let transfer_part_bytes = connections
        .framing_profile(connection_id)?
        .transfer_part_bytes();
    if let Some(payload) = transfer_payload
        && payload.len() >= transfer_part_bytes
    {
        send_stream_transfer(
            connections,
            connection_id,
            transfer_identity
                .ok_or(PumpSendError::MissingTransferPayload)?
                .message_id(),
            transfer_identity
                .ok_or(PumpSendError::MissingTransferPayload)?
                .transfer_id(),
            payload,
            control,
        )
        .await?;
        return Ok(());
    }
    let message_id = random_message_id()?;
    let envelope = RuntimeEnvelope {
        version: RUNTIME_PROTOCOL_VERSION,
        message_id: message_id.clone(),
        body: RuntimeMessage::Stream(item),
    };
    match EncodedRuntimeFrame::from_envelope(&envelope) {
        Ok(frame) => paced(connections, connection_id, frame, control).await,
        Err(ConnectionError::FrameTooLarge) => {
            let payload = transfer_payload.ok_or(PumpSendError::MissingTransferPayload)?;
            let transfer_identity =
                transfer_identity.ok_or(PumpSendError::MissingTransferPayload)?;
            send_stream_transfer(
                connections,
                connection_id,
                transfer_identity.message_id(),
                transfer_identity.transfer_id(),
                payload,
                control,
            )
            .await?;
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}

async fn paced(
    connections: &ConnectionRegistry,
    connection_id: ConnectionId,
    frame: EncodedRuntimeFrame,
    control: &TransferEgressControl,
) -> Result<(), PumpSendError> {
    let reservation =
        controlled(control, connections.reserve_paced(connection_id, frame)).await??;
    if control.is_cancelled() {
        return Err(PumpSendError::Cancelled);
    }
    let receipt = connections.commit_paced(reservation)?;
    controlled(control, receipt.wait()).await??;
    Ok(())
}

async fn controlled<T>(
    control: &TransferEgressControl,
    operation: impl Future<Output = T>,
) -> Result<T, PumpSendError> {
    if let Some(deadline) = control.absolute_deadline() {
        tokio::select! {
            biased;
            _ = control.cancelled() => Err(PumpSendError::Cancelled),
            _ = tokio::time::sleep_until(deadline) => Err(PumpSendError::Expired),
            result = operation => Ok(result),
        }
    } else {
        tokio::select! {
            biased;
            _ = control.cancelled() => Err(PumpSendError::Cancelled),
            result = operation => Ok(result),
        }
    }
}

fn random_message_id() -> Result<MessageId, PumpSendError> {
    Ok(MessageId::new(format!("stream-{}", random_uuid()?)))
}

fn random_uuid() -> Result<String, PumpSendError> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| PumpSendError::Entropy)?;
    if bytes == [0; 16] {
        return Err(PumpSendError::Entropy);
    }
    Ok(uuid::Uuid::from_bytes(bytes).hyphenated().to_string())
}
