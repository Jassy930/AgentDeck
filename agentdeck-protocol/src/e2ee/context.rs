//! `OuterContextV1` —— AEAD AAD 的确定性编码（design §7.4）。
//!
//! 只编码在 **seal 前已经存在**的字段：frame kind、route、stream generation/cursor、
//! request ID、version 与 message key epoch。**明确排除** sealed ciphertext、signature、
//! hash 字段自身，避免循环 preimage。Relay 接收后才生成的 receivedAt/size 也不进 AAD。

use crate::e2ee::Enc;
use crate::relay_v2::cursor::StreamCursor;
use crate::relay_v2::id::{
    DeviceRouteId, MachineRouteId, RequestRouteId, StreamGenerationId, StreamRouteId,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// AAD 绑定的 outer frame 用途。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum OuterFrameKind {
    CatalogPublish,
    ConversationPublish,
    DirectedReply,
    UplinkSend,
    PairRequest,
    PairResponse,
    KeyUpdate,
}

impl OuterFrameKind {
    fn tag(self) -> u8 {
        match self {
            OuterFrameKind::CatalogPublish => 0,
            OuterFrameKind::ConversationPublish => 1,
            OuterFrameKind::DirectedReply => 2,
            OuterFrameKind::UplinkSend => 3,
            OuterFrameKind::PairRequest => 4,
            OuterFrameKind::PairResponse => 5,
            OuterFrameKind::KeyUpdate => 6,
        }
    }
}

/// AEAD AAD 的 canonical context（design §7.4）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OuterContextV1 {
    pub frame_kind: OuterFrameKind,
    pub relay_protocol_version: u16,
    pub e2ee_format_version: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub machine_route: Option<MachineRouteId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_route: Option<DeviceRouteId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_route: Option<StreamRouteId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_route: Option<RequestRouteId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_generation: Option<StreamGenerationId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_cursor: Option<StreamCursor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_seq: Option<u64>,
    pub message_key_epoch: u64,
}

impl OuterContextV1 {
    /// 确定性长度前缀编码（AEAD AAD bytes）。排除 ciphertext/signature/hash 自身。
    pub fn encode_aad(&self) -> Vec<u8> {
        let mut e = Enc::new();
        e.domain(b"AgentDeck/OuterContextV1\0");
        e.u8(self.frame_kind.tag());
        e.u16(self.relay_protocol_version);
        e.u16(self.e2ee_format_version);
        e.opt_id16(self.machine_route.as_ref().map(|x| x.as_bytes()));
        e.opt_id16(self.device_route.as_ref().map(|x| x.as_bytes()));
        e.opt_id16(self.stream_route.as_ref().map(|x| x.as_bytes()));
        e.opt_id16(self.request_route.as_ref().map(|x| x.as_bytes()));
        e.opt_id16(self.stream_generation.as_ref().map(|x| x.as_bytes()));
        e.opt_cursor(self.stream_cursor.as_ref());
        e.opt_u64(self.stream_seq);
        e.u64(self.message_key_epoch);
        e.finish()
    }
}
