//! Relay v2 首次机器登记（design §6.1 / §10.1）。
//!
//! 机器登记**不属于**已鉴权 Relay frame family：Relay 额外提供一个只接收
//! [`MachineEnrollmentRequestV1`] 的专用 TLS endpoint，消费本机 admin 生成的 5 分钟
//! 单次 code，并在同一事务插入 machine route。它不提供 inventory / purge。
//!
//! daemon 必须在发送 code 与 root/link/data public material 前完成公开 CA 或 enrollment
//! bundle SPKI pin 验证（design §12.1）。

use crate::relay_v2::auth::{PublicKeyBytes, SignedCertificate};
use crate::relay_v2::id::{MachineRouteId, RelayServerId, b64_32};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// 256-bit 一次性登记 code（本机 admin 生成，Relay 只存 hash），base64 wire。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
pub struct EnrollmentCode(
    #[serde(with = "b64_32")]
    #[schemars(with = "String")]
    pub [u8; 32],
);

/// 专用 TLS endpoint 的机器登记请求（design core interface）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MachineEnrollmentRequestV1 {
    pub code: EnrollmentCode,
    pub machine_route: MachineRouteId,
    /// MachineRoot 验签公钥（machine trust anchor）。
    pub root_pubkey: PublicKeyBytes,
    pub link_cert: SignedCertificate,
    pub data_cert: SignedCertificate,
}

/// 机器登记响应（design core interface）。code 消费 + machine row insert 在同一事务；
/// TTL 内同 code + 同 request hash 幂等重放逐字节相同 response。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MachineEnrollmentResponseV1 {
    pub relay_server_id: RelayServerId,
    pub machine_route: MachineRouteId,
    pub trust_epoch: u64,
    #[serde(with = "b64_32")]
    #[schemars(with = "String")]
    pub receipt_hash: [u8; 32],
}
