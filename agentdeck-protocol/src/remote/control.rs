// agentdeck-protocol/src/remote/control.rs
use crate::remote::data::DataEnvelope;
use crate::remote::fleet::{DeviceDescriptor, MachineDescriptor, SessionDescriptor};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
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
