//! Relay v2 通用 frame families（design §10.1）。
//!
//! `RELAY_PROTOCOL_VERSION` 从 1 升到 2；v1 直接拒绝。v2 只保留**通用** frame——
//! 六组：Handshake / Pairing / Stream / Request / Auth control / Runtime。schema/wire
//! 中不存在机器名、session title、cwd、agent kind、conversation/thread/turn/approval/
//! vendor 真实业务字段（design §10.2 / RC-6，由 `relay_v2_neutrality` 守护）。
//!
//! 生产 WS outer frame 是固定长度前缀二进制 codec（`codec` 模块）；这里的 serde/JSON
//! 只用于 schema 生成与调试。`sealedBlob` 对 Relay 不可解析（见 `e2ee`）。

use crate::e2ee::tbs::{SignedObjectType, ToBeSignedV1};
use crate::e2ee::{E2EE_FORMAT_VERSION, Enc};
use crate::relay_v2::RELAY_PROTOCOL_VERSION;
use crate::relay_v2::auth::{
    AUTH_SIGNATURE_FORMAT_VERSION, DeviceRevocation, Ed25519Signature, RelayGrant,
    SignedCertificate,
};
use crate::relay_v2::cursor::StreamCursor;
use crate::relay_v2::failure::RelayFailure;
use crate::relay_v2::id::{
    ConnectionInstanceId, DeviceRouteId, GrantSerial, MachineRouteId, PairRouteId, RelayServerId,
    RequestRouteId, RootKeyId, StreamGenerationId, StreamRouteId, TrustEpoch, b64_32, b64_vec,
};
use crate::runtime::RUNTIME_PROTOCOL_VERSION;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const MACHINE_RETIREMENT_ROLE_SCOPE: &str = "relay-machine-retirement";

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

/// TLS 建立后，未配对 endpoint 选择唯一 PairRoute 的最小握手帧。
///
/// connection instance 与 protocol version 均由 server 已建立的连接上下文绑定，不能由
/// endpoint 重复声明；route 只在 binary body 中出现，禁止放入 URL/query/access log。
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PairingHello {
    pub relay_server_id: RelayServerId,
    pub pair_route: PairRouteId,
}

impl std::fmt::Debug for PairingHello {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PairingHello")
            .field("relay_server", &self.relay_server_id.redacted())
            .field("pair_route", &self.pair_route.redacted())
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Challenge {
    pub relay_server_id: RelayServerId,
    pub connection_instance: ConnectionInstanceId,
    #[serde(with = "b64_32")]
    #[schemars(with = "String")]
    pub challenge_nonce: [u8; 32],
}

impl std::fmt::Debug for Challenge {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Challenge")
            .field("relay_server", &"<redacted>")
            .field("connection", &"<redacted>")
            .field("nonce", &"<redacted>")
            .finish()
    }
}

/// 连接鉴权凭据（design §6.4）：MachineLink 用 link cert，DeviceLink 用 RelayGrant。
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
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

impl std::fmt::Debug for AuthProof {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MachineLink { machine_route, .. } => formatter
                .debug_struct("MachineLink")
                .field("machine", &machine_route.redacted())
                .field("credential", &"<redacted>")
                .finish(),
            Self::Device { .. } => formatter
                .debug_struct("Device")
                .field("credential", &"<redacted>")
                .finish(),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Authenticate {
    pub proof: AuthProof,
    /// 对 challenge transcript 的签名（MachineLinkSign / DeviceSign）。
    pub signature: Ed25519Signature,
}

impl std::fmt::Debug for Authenticate {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Authenticate")
            .field("proof", &self.proof)
            .field("signature", &"<redacted>")
            .finish()
    }
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
    pub root_key_id: RootKeyId,
    pub trust_epoch: TrustEpoch,
    pub signature: Ed25519Signature,
}

impl RetireMachine {
    /// 不含 MachineRoot signature 的退役请求 canonical bytes。
    pub fn unsigned_canonical_bytes(&self) -> Vec<u8> {
        let mut encoder = Enc::new();
        encoder.domain(b"AgentDeck/RetireMachineUnsignedV1\0");
        encoder.bytes(self.machine_route.as_bytes());
        encoder.bytes(self.root_key_id.as_bytes());
        encoder.u64(self.trust_epoch.value());
        encoder.finish()
    }

    /// 包含 MachineRoot signature 的完整退役请求 canonical bytes。
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let unsigned = self.unsigned_canonical_bytes();
        let mut encoder = Enc::new();
        encoder.domain(b"AgentDeck/RetireMachineV1\0");
        encoder.bytes(&unsigned);
        encoder.bytes(&self.signature.0);
        encoder.finish()
    }

    pub fn unsigned_canonical_sha256(&self) -> [u8; 32] {
        Sha256::digest(self.unsigned_canonical_bytes()).into()
    }

    pub fn canonical_sha256(&self) -> [u8; 32] {
        Sha256::digest(self.canonical_bytes()).into()
    }

    /// 构造 MachineRoot 对整机退役请求签名的 canonical [`ToBeSignedV1`]。
    pub fn to_be_signed_v1(
        &self,
        relay_server_id: RelayServerId,
        root_public_key_fingerprint: [u8; 32],
    ) -> ToBeSignedV1 {
        ToBeSignedV1 {
            object_type: SignedObjectType::RetireMachine,
            signature_format_version: AUTH_SIGNATURE_FORMAT_VERSION,
            relay_protocol_version: RELAY_PROTOCOL_VERSION,
            runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
            e2ee_format_version: E2EE_FORMAT_VERSION,
            relay_server_id,
            machine_route: self.machine_route,
            device_route: None,
            stream_route: None,
            request_route: None,
            stream_generation: None,
            stream_cursor: None,
            role_scope: MACHINE_RETIREMENT_ROLE_SCOPE.to_owned(),
            signing_key_fingerprint: root_public_key_fingerprint,
            root_key_id: self.root_key_id,
            trust_epoch: self.trust_epoch,
            serial_or_generation: self.trust_epoch.value(),
            not_after_ms: None,
            signed_object_sha256: self.unsigned_canonical_sha256(),
        }
    }
}

/// Relay 只在 machine purge COMMIT 且逐表 readback 通过后生成的终态 ACK。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RetirementCommitted {
    pub machine_route: MachineRouteId,
    pub trust_epoch: TrustEpoch,
    #[serde(with = "b64_32")]
    #[schemars(with = "String")]
    pub retire_hash: [u8; 32],
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

/// 通用 frame body：六组共 30 个 variant（P2.6 追加 binary PairingHello）。
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
    /// 追加到 kind 28，既有 0..=27 判别码保持冻结。
    RetirementCommitted(RetirementCommitted),
    /// 追加到 kind 29，既有 0..=28 判别码保持冻结。
    PairingHello(PairingHello),
}

impl RelayFrameBody {
    /// 二进制 codec 的稳定 frame kind 判别码（`0..=29`，与 wire 契约绑定）。
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
            RelayFrameBody::RetirementCommitted(_) => 28,
            RelayFrameBody::PairingHello(_) => 29,
        }
    }
}
