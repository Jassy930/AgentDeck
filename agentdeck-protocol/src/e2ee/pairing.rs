//! 版本化 pairing DTO 与两种 pairing HPKE info（design §6.2 / §6.3 / §7.4）。
//!
//! 这些是 endpoint 侧契约：完整 PairInvite 是带外邀请（含机器显示名，**不进 Relay
//! wire/schema**）；PairRequest/PairResponse/DeviceAuthorization 在 HPKE/AEAD 内流转，
//! Relay 只按 `pairRouteId` 转发密文。`PairResponseReceivedV1` 由 DeviceSign 签名并
//! 结构上绑定 request/grant/response hash（design §6.3 step 9）。

use crate::e2ee::keys::KeyDirectoryV1;
use crate::e2ee::{Enc, b64_32, b64_vec};
use crate::relay_v2::auth::{Ed25519Signature, PublicKeyBytes, RelayGrant, SignedCertificate};
use crate::relay_v2::id::{
    DeviceRouteId, GrantSerial, MachineRouteId, PairRouteId, RelayServerId, RootKeyId, TrustEpoch,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// 被控机器创建的配对邀请（design §6.2）。含 §6.2 列出的全部内容；`machine_display_name`
/// 仅存在于带外邀请，**不属于 Relay wire/schema**。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PairInviteV1 {
    pub format_version: u16,
    pub relay_protocol_version: u16,
    pub pair_route: PairRouteId,
    /// 256-bit invite bearer secret（带外传递，不进公开日志）。
    #[serde(with = "b64_32")]
    #[schemars(with = "String")]
    pub invite_secret: [u8; 32],
    /// 临时 HPKE receiver 公钥（设备封装 PairRequest 用）。
    pub invite_hpke_pubkey: PublicKeyBytes,
    pub wss_url: String,
    pub relay_server_id: RelayServerId,
    /// 当前/下一 SPKI pinset（`SHA-256(DER SPKI)`）。
    #[serde(with = "b64_32")]
    #[schemars(with = "String")]
    pub current_spki_pin: [u8; 32],
    #[serde(with = "b64_32")]
    #[schemars(with = "String")]
    pub next_spki_pin: [u8; 32],
    pub expires_at_ms: u64,
    /// MachineRoot 公钥与 fingerprint（设备在收到 PairResponse 前的机器真实性锚点）。
    pub machine_root_pubkey: PublicKeyBytes,
    #[serde(with = "b64_32")]
    #[schemars(with = "String")]
    pub machine_root_fingerprint: [u8; 32],
    pub data_sign_cert: SignedCertificate,
    /// 仅供人识别的机器显示名（带外邀请专用；绝不进 Relay wire/schema）。
    pub machine_display_name: String,
}

/// 设备封装在 HPKE 内的 PairRequest（design §6.3 step 2）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PairRequestV1 {
    pub format_version: u16,
    #[serde(with = "b64_32")]
    #[schemars(with = "String")]
    pub invite_secret: [u8; 32],
    pub device_sign_pubkey: PublicKeyBytes,
    pub device_hpke_pubkey: PublicKeyBytes,
    /// 加密的设备授权请求（对 daemon 之外 opaque）。
    #[serde(with = "b64_vec")]
    #[schemars(with = "String")]
    pub sealed_authorization_request: Vec<u8>,
    /// DeviceSign possession proof（对 invite transcript + HPKE enc + ciphertext hash）。
    pub proof_signature: Ed25519Signature,
}

/// 与 requestHash 绑定的待确认状态（design §6.3 step 4）；MachineDataSign 签名，无 grant。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PairPendingV1 {
    #[serde(with = "b64_32")]
    #[schemars(with = "String")]
    pub request_hash: [u8; 32],
    pub signature: Ed25519Signature,
}

/// 加密的设备授权（design §6.3）：绑定 grant serial、设备 HPKE 公钥、能力与业务权限，
/// MachineRoot 签名后加密（只供 endpoint）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeviceAuthorizationV1 {
    pub grant_serial: GrantSerial,
    pub device_hpke_pubkey: PublicKeyBytes,
    pub capabilities: Vec<String>,
    pub permissions: Vec<String>,
    pub root_key_id: RootKeyId,
    pub trust_epoch: TrustEpoch,
    pub signature: Ed25519Signature,
}

/// PairResponse（design §6.3 step 8）：DeviceHPKE 加密、MachineDataSign 签名的 DeviceGrant
/// 与 machine key directory。`relay_grant` 是公开部分（也在 Relay InstallGrant 注册）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PairResponseV1 {
    #[serde(with = "b64_32")]
    #[schemars(with = "String")]
    pub request_hash: [u8; 32],
    pub relay_grant: RelayGrant,
    #[serde(with = "b64_vec")]
    #[schemars(with = "String")]
    pub sealed_device_authorization: Vec<u8>,
    pub key_directory: KeyDirectoryV1,
    pub signature: Ed25519Signature,
}

/// PairResponseReceived（design §6.3 step 9）：DeviceSign 签名，结构上绑定
/// request/grant/response 三个 hash。daemon 验签匹配 frozen response 后才 delivered。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PairResponseReceivedV1 {
    #[serde(with = "b64_32")]
    #[schemars(with = "String")]
    pub request_hash: [u8; 32],
    #[serde(with = "b64_32")]
    #[schemars(with = "String")]
    pub grant_hash: [u8; 32],
    #[serde(with = "b64_32")]
    #[schemars(with = "String")]
    pub response_hash: [u8; 32],
    pub signature: Ed25519Signature,
}

/// `PairRequestInfoV1` —— PairRequest 的 HPKE `info`（design §7.4）。固定包含 domain、
/// E2EE/Runtime version、relayServerId、pairRoute、inviteHash、expiry；**此时不包含**尚未
/// 分配的 device route / grant serial。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PairRequestInfoV1 {
    pub e2ee_format_version: u16,
    pub runtime_protocol_version: u16,
    pub relay_server_id: RelayServerId,
    pub pair_route: PairRouteId,
    #[serde(with = "b64_32")]
    #[schemars(with = "String")]
    pub invite_hash: [u8; 32],
    pub expiry_ms: u64,
}

impl PairRequestInfoV1 {
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Enc::new();
        e.domain(b"AgentDeck/PairRequestInfoV1\0");
        e.u16(self.e2ee_format_version);
        e.u16(self.runtime_protocol_version);
        e.bytes(self.relay_server_id.as_bytes());
        e.bytes(self.pair_route.as_bytes());
        e.bytes(&self.invite_hash);
        e.u64(self.expiry_ms);
        e.finish()
    }
}

/// `PairResponseInfoV1` —— PairResponse 的 HPKE `info`（design §7.4）。固定包含 trust
/// domain、pairRoute、inviteHash、requestHash、已分配 machine/device route、grant serial
/// 与 root trust epoch。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PairResponseInfoV1 {
    pub e2ee_format_version: u16,
    pub runtime_protocol_version: u16,
    pub relay_server_id: RelayServerId,
    pub pair_route: PairRouteId,
    #[serde(with = "b64_32")]
    #[schemars(with = "String")]
    pub invite_hash: [u8; 32],
    #[serde(with = "b64_32")]
    #[schemars(with = "String")]
    pub request_hash: [u8; 32],
    pub machine_route: MachineRouteId,
    pub device_route: DeviceRouteId,
    pub grant_serial: GrantSerial,
    pub root_trust_epoch: TrustEpoch,
}

impl PairResponseInfoV1 {
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Enc::new();
        e.domain(b"AgentDeck/PairResponseInfoV1\0");
        e.u16(self.e2ee_format_version);
        e.u16(self.runtime_protocol_version);
        e.bytes(self.relay_server_id.as_bytes());
        e.bytes(self.pair_route.as_bytes());
        e.bytes(&self.invite_hash);
        e.bytes(&self.request_hash);
        e.bytes(self.machine_route.as_bytes());
        e.bytes(self.device_route.as_bytes());
        e.u64(self.grant_serial.value());
        e.u64(self.root_trust_epoch.value());
        e.finish()
    }
}
