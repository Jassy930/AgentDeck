//! Relay v2 通用 frame families（design §10.1）。
//!
//! `RELAY_PROTOCOL_VERSION` 从 1 升到 2；v1 直接拒绝。v2 只保留**通用** frame——
//! 六组：Handshake / Pairing / Stream / Request / Auth control / Runtime。schema/wire
//! 中不存在机器名、session title、cwd、agent kind、conversation/thread/turn/approval/
//! vendor 真实业务字段（design §10.2 / RC-6，由 `relay_v2_neutrality` 守护）。
//!
//! 生产 WS outer frame 是固定长度前缀二进制 codec（`codec` 模块）；这里的 serde/JSON
//! 只用于 schema 生成与调试。`sealedBlob` 对 Relay 不可解析（见 `e2ee`）。

use crate::relay_v2::auth::{DeviceRevocation, Ed25519Signature, RelayGrant, SignedCertificate};
use crate::relay_v2::cursor::StreamCursor;
use crate::relay_v2::failure::RelayFailure;
use crate::relay_v2::id::{
    ConnectionInstanceId, DeviceRouteId, GrantSerial, MachineRouteId, PairRouteId, RelayServerId,
    RequestRouteId, StreamGenerationId, StreamRouteId, TrustEpoch, b64_32, b64_vec,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// 一段对 Relay 不可解析的 canonical sealed bytes（endpoint E2EE codec 才解析）。
/// wire/JSON 走 base64；二进制 codec 直接携带 bytes。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
pub struct SealedBlob(
    #[serde(with = "b64_vec")]
    #[schemars(with = "String")]
    pub Vec<u8>,
);

/// Relay 可见的外层 frame：只有 `version` + 通用 body（design §7.3）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpaqueRouteFrame {
    pub version: u16,
    pub body: RelayFrameBody,
}

// —— Handshake ——

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Hello {
    pub protocol_version: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Challenge {
    pub relay_server_id: RelayServerId,
    pub connection_instance: ConnectionInstanceId,
    #[serde(with = "b64_32")]
    #[schemars(with = "String")]
    pub challenge_nonce: [u8; 32],
}

/// 连接鉴权凭据（design §6.4）：MachineLink 用 link cert，DeviceLink 用 RelayGrant。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum AuthProof {
    MachineLink {
        machine_route: MachineRouteId,
        link_cert: SignedCertificate,
    },
    Device {
        relay_grant: RelayGrant,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Authenticate {
    pub proof: AuthProof,
    /// 对 challenge transcript 的签名（MachineLinkSign / DeviceSign）。
    pub signature: Ed25519Signature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Authenticated {
    pub heartbeat_interval_secs: u16,
}

// —— Pairing ——

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenPairRoute {
    pub machine_route: MachineRouteId,
    pub pair_route: PairRouteId,
    pub absolute_expiry_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PairRouteOpened {
    pub machine_route: MachineRouteId,
    pub pair_route: PairRouteId,
    pub absolute_expiry_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PairData {
    pub pair_route: PairRouteId,
    pub sealed_blob: SealedBlob,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClosePairRoute {
    pub machine_route: MachineRouteId,
    pub pair_route: PairRouteId,
}

/// close outcome 只允许 `Closed | AlreadyAbsent`（design §10.1）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum PairRouteCloseOutcome {
    Closed,
    AlreadyAbsent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PairRouteClosed {
    pub pair_route: PairRouteId,
    pub outcome: PairRouteCloseOutcome,
}

// —— Stream ——

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegisterStream {
    pub machine_route: MachineRouteId,
    pub stream_route: StreamRouteId,
    pub generation: StreamGenerationId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Publish {
    pub stream_route: StreamRouteId,
    pub generation: StreamGenerationId,
    /// 每个随机 stream generation 自己的传输序号（与 eventSeq 独立）。
    pub stream_seq: u64,
    pub sealed_blob: SealedBlob,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Subscribe {
    pub stream_route: StreamRouteId,
    pub generation: StreamGenerationId,
    pub cursor: StreamCursor,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Unsubscribe {
    pub stream_route: StreamRouteId,
    pub generation: StreamGenerationId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Ack {
    pub stream_route: StreamRouteId,
    pub generation: StreamGenerationId,
    pub up_to_seq: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Gap {
    pub stream_route: StreamRouteId,
    pub generation: StreamGenerationId,
    pub need_stream_seq: u64,
    pub oldest_stream_seq: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReplayComplete {
    pub stream_route: StreamRouteId,
    pub generation: StreamGenerationId,
    pub current_cursor: StreamCursor,
}

// —— Request（在线 Send/Reply，不进 Relay 离线队列，design §10.3）——

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Send {
    pub device_route: DeviceRouteId,
    pub request_route: RequestRouteId,
    pub sealed_blob: SealedBlob,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Reply {
    pub device_route: DeviceRouteId,
    pub request_route: RequestRouteId,
    pub sealed_blob: SealedBlob,
}

// —— Auth control ——

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InstallGrant {
    pub grant: RelayGrant,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GrantCommitted {
    pub device_route: DeviceRouteId,
    pub grant_serial: GrantSerial,
    #[serde(with = "b64_32")]
    #[schemars(with = "String")]
    pub grant_hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RevokeDevice {
    pub revocation: DeviceRevocation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RevocationCommitted {
    pub device_route: DeviceRouteId,
    pub grant_serial: GrantSerial,
    /// terminal frame 携带的 root-signed 撤销，Relay restart 后原样重放（design §10.3）。
    pub signed_revocation: DeviceRevocation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RetireMachine {
    pub machine_route: MachineRouteId,
    pub trust_epoch: TrustEpoch,
    pub signature: Ed25519Signature,
}

// —— Runtime ——

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Ping {
    pub nonce: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Pong {
    pub nonce: u64,
}

/// `RouteAccepted` 只表示已进入有界 writer，不代表 daemon 接受/执行（design RC-5）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum AcceptedRef {
    Request {
        request_route: RequestRouteId,
    },
    StreamFrame {
        stream_route: StreamRouteId,
        stream_seq: u64,
    },
    PairFrame {
        pair_route: PairRouteId,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RouteAccepted {
    pub accepted: AcceptedRef,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServerRestarting {
    pub drain_deadline_ms: u64,
}

/// 通用 frame body：六组共 28 个 variant（design core interface）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "frameKind", content = "frame", rename_all = "camelCase")]
pub enum RelayFrameBody {
    // Handshake
    Hello(Hello),
    Challenge(Challenge),
    Authenticate(Authenticate),
    Authenticated(Authenticated),
    // Pairing
    OpenPairRoute(OpenPairRoute),
    PairRouteOpened(PairRouteOpened),
    PairData(PairData),
    ClosePairRoute(ClosePairRoute),
    PairRouteClosed(PairRouteClosed),
    // Stream
    RegisterStream(RegisterStream),
    Publish(Publish),
    Subscribe(Subscribe),
    Unsubscribe(Unsubscribe),
    Ack(Ack),
    Gap(Gap),
    ReplayComplete(ReplayComplete),
    // Request
    Send(Send),
    Reply(Reply),
    // Auth control
    InstallGrant(InstallGrant),
    GrantCommitted(GrantCommitted),
    RevokeDevice(RevokeDevice),
    RevocationCommitted(RevocationCommitted),
    RetireMachine(RetireMachine),
    // Runtime
    Ping(Ping),
    Pong(Pong),
    RouteAccepted(RouteAccepted),
    Error(RelayFailure),
    ServerRestarting(ServerRestarting),
}

impl RelayFrameBody {
    /// 二进制 codec 的稳定 frame kind 判别码（`0..=27`，与 wire 契约绑定）。
    pub fn kind(&self) -> u16 {
        match self {
            RelayFrameBody::Hello(_) => 0,
            RelayFrameBody::Challenge(_) => 1,
            RelayFrameBody::Authenticate(_) => 2,
            RelayFrameBody::Authenticated(_) => 3,
            RelayFrameBody::OpenPairRoute(_) => 4,
            RelayFrameBody::PairRouteOpened(_) => 5,
            RelayFrameBody::PairData(_) => 6,
            RelayFrameBody::ClosePairRoute(_) => 7,
            RelayFrameBody::PairRouteClosed(_) => 8,
            RelayFrameBody::RegisterStream(_) => 9,
            RelayFrameBody::Publish(_) => 10,
            RelayFrameBody::Subscribe(_) => 11,
            RelayFrameBody::Unsubscribe(_) => 12,
            RelayFrameBody::Ack(_) => 13,
            RelayFrameBody::Gap(_) => 14,
            RelayFrameBody::ReplayComplete(_) => 15,
            RelayFrameBody::Send(_) => 16,
            RelayFrameBody::Reply(_) => 17,
            RelayFrameBody::InstallGrant(_) => 18,
            RelayFrameBody::GrantCommitted(_) => 19,
            RelayFrameBody::RevokeDevice(_) => 20,
            RelayFrameBody::RevocationCommitted(_) => 21,
            RelayFrameBody::RetireMachine(_) => 22,
            RelayFrameBody::Ping(_) => 23,
            RelayFrameBody::Pong(_) => 24,
            RelayFrameBody::RouteAccepted(_) => 25,
            RelayFrameBody::Error(_) => 26,
            RelayFrameBody::ServerRestarting(_) => 27,
        }
    }
}
