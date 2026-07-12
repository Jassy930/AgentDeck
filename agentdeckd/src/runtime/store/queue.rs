//! Runtime prompt queue 的纯上界裁决。

use crate::runtime::model::{
    MAX_CONVERSATION_QUEUED_COMMANDS, MAX_GLOBAL_QUEUED_COMMANDS, MAX_GLOBAL_QUEUED_PAYLOAD_BYTES,
    QueueScope,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueueAdmission {
    pub queue_position: u32,
}

/// replay 必须由调用方先处理；本函数只裁决一条全新的 prompt。
pub fn evaluate_queue_admission(
    conversation_queued: u32,
    global_queued: u32,
    global_payload_bytes: u64,
    new_payload_bytes: u64,
) -> Result<QueueAdmission, QueueScope> {
    if conversation_queued >= MAX_CONVERSATION_QUEUED_COMMANDS {
        return Err(QueueScope::Conversation);
    }
    if global_queued >= MAX_GLOBAL_QUEUED_COMMANDS {
        return Err(QueueScope::GlobalCount);
    }
    if global_payload_bytes
        .checked_add(new_payload_bytes)
        .is_none_or(|projected| projected > MAX_GLOBAL_QUEUED_PAYLOAD_BYTES)
    {
        return Err(QueueScope::GlobalPayloadBytes);
    }
    Ok(QueueAdmission {
        queue_position: conversation_queued,
    })
}
