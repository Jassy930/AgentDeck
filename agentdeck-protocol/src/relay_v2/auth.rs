//! Relay v2 公开授权对象（design §6.3 / §6.5 / §6.6）。
//!
//! 这些是 Relay **可见**的公开验签材料——只包含 Relay 鉴权/路由所需字段，不含任何
//! 业务权限或对称 key（那些在加密的 `DeviceAuthorization` / key directory 中，见
//! `e2ee` 模块）：
//!
//! - [`SignedCertificate`]：MachineRoot 签发的 MachineLink / MachineDataSign cert。
//! - [`RelayGrant`]：DeviceGrant 的 Relay 可见部分（随机 route、设备验签公钥、serial、
//!   root 签名）。
//! - [`DeviceRevocation`]：MachineRoot 签的撤销，绑定 `grantSerial`。
//!
//! 真实签名字节由 P1.4 crypto 产生；本 task 只固定公开对象形状。

use crate::relay_v2::id::{
    DeviceRouteId, GrantSerial, LinkGeneration, MachineRouteId, RootKeyId, TrustEpoch, b64_32,
    b64_64,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// 32-byte 公钥（Ed25519 验签公钥 / X25519 HPKE 公钥），base64 wire。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
pub struct PublicKeyBytes(
    #[serde(with = "b64_32")]
    #[schemars(with = "String")]
    pub [u8; 32],
);

/// 64-byte Ed25519 签名，base64 wire。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
pub struct Ed25519Signature(
    #[serde(with = "b64_64")]
    #[schemars(with = "String")]
    pub [u8; 64],
);

/// 证书角色：日常连接 auth（Link）或 daemon 下行数据来源签名（Data）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum CertRole {
    Link,
    Data,
}

/// MachineRoot 签发的 link / data 证书（design §6.6）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedCertificate {
    /// 被证明的日常签名公钥（MachineLinkSign / MachineDataSign）。
    pub subject_pubkey: PublicKeyBytes,
    pub cert_role: CertRole,
    /// 单调 cert generation；回退值一律拒绝。
    pub generation: LinkGeneration,
    /// machine trust anchor 的 root key ID。
    pub root_key_id: RootKeyId,
    pub trust_epoch: TrustEpoch,
    /// 可选有效期（grant 类默认无过期，cert 可带）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_after_ms: Option<u64>,
    /// MachineRoot 对 cert `ToBeSignedV1` 的签名。
    pub signature: Ed25519Signature,
}

/// DeviceGrant 的 Relay 可见部分（design §6.3）。只含 Relay 鉴权所需字段：随机
/// machine/device route、设备连接验签公钥、grant serial 与 MachineRoot 签名。加密的
/// `DeviceAuthorization`（业务权限）只供 endpoint，Relay 看不到。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RelayGrant {
    pub machine_route: MachineRouteId,
    pub device_route: DeviceRouteId,
    /// 设备连接验签公钥（DeviceSign）。
    pub device_sign_pubkey: PublicKeyBytes,
    pub grant_serial: GrantSerial,
    pub root_key_id: RootKeyId,
    pub trust_epoch: TrustEpoch,
    pub signature: Ed25519Signature,
}

/// MachineRoot 签的设备撤销，绑定 `grantSerial`（design §6.5）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeviceRevocation {
    pub machine_route: MachineRouteId,
    pub device_route: DeviceRouteId,
    pub grant_serial: GrantSerial,
    pub root_key_id: RootKeyId,
    pub trust_epoch: TrustEpoch,
    pub signature: Ed25519Signature,
}
