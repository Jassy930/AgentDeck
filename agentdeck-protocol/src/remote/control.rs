// agentdeck-protocol/src/remote/control.rs
use crate::remote::data::DataEnvelope;
use crate::remote::fleet::{DeviceDescriptor, MachineDescriptor, SessionDescriptor};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub enum SubTarget {
    Machines,
    Sessions {
        #[serde(rename = "machineId")]
        machine_id: String,
    },
    Events {
        #[serde(rename = "conversationId")]
        conversation_id: String,
        /// 重放起点（不含）：`Some(seq)` 表示只要 `seq > since_seq` 的事件；
        /// `None`（旧客户端不传该字段，或显式全量）走 R1a 原有全量回放行为。
        /// `#[serde(default)]` 保证旧 wire（无此字段）反序列化为 `None`；
        /// `skip_serializing_if` 保证 `None` 时不写字段，发出去的 wire 与旧
        /// 版本兼容。
        #[serde(rename = "sinceSeq", default, skip_serializing_if = "Option::is_none")]
        since_seq: Option<u64>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub enum CommandTarget {
    Conversation {
        #[serde(rename = "conversationId")]
        conversation_id: String,
    },
    Turn {
        #[serde(rename = "turnSessionId")]
        turn_session_id: String,
    },
    Machine {
        #[serde(rename = "machineId")]
        machine_id: String,
    },
}

/// 控制面消息：relay 完整可读；携带 agent 内容的变体用嵌套 DataEnvelope（opaque）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "msg", rename_all = "camelCase", deny_unknown_fields)]
pub enum RelayControlMsg {
    // machine → relay
    RegisterMachine {
        machine: MachineDescriptor,
    },
    Heartbeat {
        #[serde(rename = "machineId")]
        machine_id: String,
    },
    AnnounceSession {
        session: SessionDescriptor,
    },
    RetireSession {
        #[serde(rename = "conversationId")]
        conversation_id: String,
    },
    PublishEvent {
        #[serde(rename = "conversationId")]
        conversation_id: String,
        #[serde(rename = "turnSessionId")]
        turn_session_id: String,
        seq: u64,
        data: DataEnvelope,
    },
    AdminReply {
        #[serde(rename = "inReplyTo")]
        in_reply_to: String,
        data: DataEnvelope,
    },
    // device → relay
    ConnectDevice {
        device: DeviceDescriptor,
    },
    Subscribe {
        target: SubTarget,
    },
    Unsubscribe {
        target: SubTarget,
    },
    SendCommand {
        #[serde(rename = "requestId")]
        request_id: String,
        target: CommandTarget,
        data: DataEnvelope,
    },
    Ack {
        #[serde(rename = "upToSeq")]
        up_to_seq: u64,
        #[serde(rename = "conversationId")]
        conversation_id: Option<String>,
    },
    // relay → client
    MachineList {
        machines: Vec<MachineDescriptor>,
    },
    SessionList {
        #[serde(rename = "machineId")]
        machine_id: String,
        sessions: Vec<SessionDescriptor>,
    },
    Event {
        #[serde(rename = "conversationId")]
        conversation_id: String,
        #[serde(rename = "turnSessionId")]
        turn_session_id: String,
        seq: u64,
        data: DataEnvelope,
    },
    CommandDelivered {
        #[serde(rename = "requestId")]
        request_id: String,
    },
    Error {
        code: String,
        message: String,
        #[serde(rename = "inReplyTo")]
        in_reply_to: Option<String>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subtarget_events_since_seq_defaults_to_none_for_old_wire() {
        let v = serde_json::json!({"kind": "events", "conversationId": "C1"});
        let t: SubTarget = serde_json::from_value(v).unwrap();
        assert_eq!(t, SubTarget::Events { conversation_id: "C1".into(), since_seq: None });
    }
}
