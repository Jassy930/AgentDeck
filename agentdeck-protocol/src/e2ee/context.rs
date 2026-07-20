//! `OuterContextV1` —— AEAD AAD 的确定性编码（design §7.4）。
//!
//! 只编码在 **seal 前已经存在**的字段：frame kind、route、stream generation/cursor、
//! request ID、version 与 message key epoch。**明确排除** sealed ciphertext、signature、
//! hash 字段自身，避免循环 preimage。Relay 接收后才生成的 receivedAt/size 也不进 AAD。

use crate::e2ee::Enc;
use crate::relay_v2::cursor::StreamCursor;
use crate::relay_v2::id::{
    DeviceRouteId, MachineRouteId, PairRouteId, RequestRouteId, StreamGenerationId, StreamRouteId,
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
    PairPending,
    PairResponseReceived,
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
            OuterFrameKind::PairPending => 7,
            OuterFrameKind::PairResponseReceived => 8,
        }
    }
}

/// AEAD AAD 的 canonical context（design §7.4）。
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
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
    /// PairRequest/PairResponse 的唯一 outer route。作为尾部扩展进入 AAD，使既有非 pairing
    /// vector 在 `None` 时保持逐字节不变。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pair_route: Option<PairRouteId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_generation: Option<StreamGenerationId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_cursor: Option<StreamCursor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_seq: Option<u64>,
    pub message_key_epoch: u64,
}

impl std::fmt::Debug for OuterContextV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OuterContextV1")
            .field("frame_kind", &self.frame_kind)
            .field("relay_protocol_version", &self.relay_protocol_version)
            .field("e2ee_format_version", &self.e2ee_format_version)
            .field("routing_and_cursors", &"<redacted>")
            .finish()
    }
}

/// Outer context 的结构约束。Pairing 使用专用 pair route，不能伪装成业务 stream/request。
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum OuterContextError {
    #[error("pairing outer context must bind exactly one pair route and no business route/cursor")]
    InvalidPairingContext,
    #[error("non-pairing outer context must not carry a pair route")]
    PairRouteOnNonPairingFrame,
}

impl OuterContextV1 {
    pub fn validate(&self) -> Result<(), OuterContextError> {
        let pairing = matches!(
            self.frame_kind,
            OuterFrameKind::PairRequest
                | OuterFrameKind::PairResponse
                | OuterFrameKind::PairPending
                | OuterFrameKind::PairResponseReceived
        );
        if pairing {
            if self.pair_route.is_none()
                || self.machine_route.is_some()
                || self.device_route.is_some()
                || self.stream_route.is_some()
                || self.request_route.is_some()
                || self.stream_generation.is_some()
                || self.stream_cursor.is_some()
                || self.stream_seq.is_some()
                || self.message_key_epoch != 0
            {
                return Err(OuterContextError::InvalidPairingContext);
            }
        } else if self.pair_route.is_some() {
            return Err(OuterContextError::PairRouteOnNonPairingFrame);
        }
        Ok(())
    }

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
        // Pairing binding 是 v1 的 append-only 扩展。`None` 不写任何 bytes，避免改变既有
        // catalog/conversation/request/key-update vectors；pairing 调用方必须先 `validate()`。
        if let Some(pair_route) = self.pair_route.as_ref() {
            e.domain(b"AgentDeck/OuterContextPairRouteV1\0");
            e.bytes(pair_route.as_bytes());
        }
        e.finish()
    }
}
