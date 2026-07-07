// agentdeck-protocol/src/remote/fleet.rs
use crate::AgentKind;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MachineDescriptor {
    pub machine_id: String,
    pub name: String,
    pub agentdeck_protocol_version: u32,
    pub is_online: bool,
    pub last_heartbeat_ms: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum DeviceKind {
    Cli,
    Mobile,
    Desktop,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeviceDescriptor {
    pub device_id: String,
    pub kind: DeviceKind,
}

/// 稳定身份：conversation_id（= daemon thread_id 已知时）与 per-turn
/// current_turn_session_id 分离，填上 sendPrompt→SessionContinue 需要的
/// thread_id/agent_kind/cwd。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SessionDescriptor {
    pub conversation_id: String,
    pub machine_id: String,
    pub thread_id: Option<String>,
    pub current_turn_session_id: Option<String>,
    pub agent_kind: AgentKind,
    pub cwd: String,
    pub title: Option<String>,
}
