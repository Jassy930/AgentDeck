//! `ToBeSignedV1` —— 确定性长度前缀签名 preimage（design §6.6）。
//!
//! 所有 root-signed cert/grant/revocation 与 endpoint-signed frame 都对该 canonical bytes
//! 签名，**不依赖 JSON canonicalization**。公共前缀固定包含域分隔符、对象类型、签名格式
//! 版本、Relay/Runtime/E2EE protocol version、relayServerId、machine route、可选
//! device/stream/request route 与 stream generation/cursor、role/scope、签名公钥
//! fingerprint、root key ID、machine trust epoch、grant serial 或 link/data generation、
//! 有效期，以及被签对象 canonical bytes 的 SHA-256。

use crate::e2ee::{Enc, b64_32};
use crate::relay_v2::cursor::StreamCursor;
use crate::relay_v2::id::{
    DeviceRouteId, MachineRouteId, RelayServerId, RequestRouteId, RootKeyId, StreamGenerationId,
    StreamRouteId, TrustEpoch,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// 被签对象类型（域分隔的一部分，避免跨对象重签）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum SignedObjectType {
    LinkCert,
    DataCert,
    RelayGrant,
    DeviceAuthorization,
    DeviceRevocation,
    RetireMachine,
    DownlinkData,
    UplinkRequest,
    PairingProof,
}

impl SignedObjectType {
    fn tag(self) -> u8 {
        match self {
            SignedObjectType::LinkCert => 0,
            SignedObjectType::DataCert => 1,
            SignedObjectType::RelayGrant => 2,
            SignedObjectType::DeviceAuthorization => 3,
            SignedObjectType::DeviceRevocation => 4,
            SignedObjectType::RetireMachine => 5,
            SignedObjectType::DownlinkData => 6,
            SignedObjectType::UplinkRequest => 7,
            SignedObjectType::PairingProof => 8,
        }
    }
}

/// 确定性签名 preimage（design §6.6 公共前缀）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ToBeSignedV1 {
    pub object_type: SignedObjectType,
    pub signature_format_version: u16,
    pub relay_protocol_version: u16,
    pub runtime_protocol_version: u16,
    pub e2ee_format_version: u16,
    pub relay_server_id: RelayServerId,
    pub machine_route: MachineRouteId,
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
    pub role_scope: String,
    #[serde(with = "b64_32")]
    #[schemars(with = "String")]
    pub signing_key_fingerprint: [u8; 32],
    pub root_key_id: RootKeyId,
    pub trust_epoch: TrustEpoch,
    /// grant serial 或 link/data generation（同一 authority 的单调值）。
    pub serial_or_generation: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_after_ms: Option<u64>,
    #[serde(with = "b64_32")]
    #[schemars(with = "String")]
    pub signed_object_sha256: [u8; 32],
}

impl ToBeSignedV1 {
    /// 确定性长度前缀编码（签名 preimage bytes）。
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Enc::new();
        e.domain(b"AgentDeck/ToBeSignedV1\0");
        e.u8(self.object_type.tag());
        e.u16(self.signature_format_version);
        e.u16(self.relay_protocol_version);
        e.u16(self.runtime_protocol_version);
        e.u16(self.e2ee_format_version);
        e.bytes(self.relay_server_id.as_bytes());
        e.bytes(self.machine_route.as_bytes());
        e.opt_id16(self.device_route.as_ref().map(|x| x.as_bytes()));
        e.opt_id16(self.stream_route.as_ref().map(|x| x.as_bytes()));
        e.opt_id16(self.request_route.as_ref().map(|x| x.as_bytes()));
        e.opt_id16(self.stream_generation.as_ref().map(|x| x.as_bytes()));
        e.opt_cursor(self.stream_cursor.as_ref());
        e.str(&self.role_scope);
        e.bytes(&self.signing_key_fingerprint);
        e.bytes(self.root_key_id.as_bytes());
        e.u64(self.trust_epoch.value());
        e.u64(self.serial_or_generation);
        e.opt_u64(self.not_after_ms);
        e.bytes(&self.signed_object_sha256);
        e.finish()
    }
}
