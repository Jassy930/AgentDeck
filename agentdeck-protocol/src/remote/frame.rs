// agentdeck-protocol/src/remote/frame.rs
use crate::remote::control::RelayControlMsg;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "role", rename_all = "camelCase", deny_unknown_fields)]
pub enum ClientRole {
    Relay,
    Machine {
        #[serde(rename = "machineId")]
        machine_id: String,
    },
    Device {
        #[serde(rename = "deviceId")]
        device_id: String,
    },
}

/// 控制面帧：relay 完整可读（路由元数据 + 控制消息）。仅控制消息内嵌的
/// DataEnvelope 对 relay 不可见。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RemoteFrame {
    pub relay_protocol_version: u16,
    pub trace_id: String,
    pub created_at_ms: i64,
    pub from: ClientRole,
    pub msg: RelayControlMsg,
}

impl RemoteFrame {
    pub fn control(from: ClientRole, trace_id: String, created_at_ms: i64, msg: RelayControlMsg) -> Self {
        RemoteFrame {
            relay_protocol_version: super::RELAY_PROTOCOL_VERSION,
            trace_id,
            created_at_ms,
            from,
            msg,
        }
    }
}
