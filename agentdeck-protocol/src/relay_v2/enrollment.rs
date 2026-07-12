//! Relay v2 首次机器登记（design §6.1 / §10.1）。
//!
//! 机器登记**不属于**已鉴权 Relay frame family：Relay 额外提供一个只接收
//! [`MachineEnrollmentRequestV1`] 的专用 TLS endpoint，消费本机 admin 生成的 5 分钟
//! 单次 code，并在同一事务插入 machine route。它不提供 inventory / purge。
//!
//! daemon 必须在发送 code 与 root/link/data public material 前完成公开 CA 或 enrollment
//! bundle SPKI pin 验证（design §12.1）。

use crate::e2ee::Enc;
use crate::relay_v2::auth::{PublicKeyBytes, SignedCertificate};
use crate::relay_v2::id::{MachineRouteId, RelayServerId, b64_32};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

/// enrollment code 是 secret，不能复用通用 base64 helper 的普通 String/Vec 临时分配。
mod secret_b64_32 {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use serde::{Deserialize, Deserializer, Serializer};
    use zeroize::Zeroizing;

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error> {
        let encoded = Zeroizing::new(STANDARD.encode(bytes));
        serializer.serialize_str(&encoded)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 32], D::Error> {
        let encoded = Zeroizing::new(String::deserialize(deserializer)?);
        let decoded = Zeroizing::new(
            STANDARD
                .decode(encoded.as_bytes())
                .map_err(serde::de::Error::custom)?,
        );
        decoded
            .as_slice()
            .try_into()
            .map_err(|_| serde::de::Error::custom("enrollment code must be exactly 32 bytes"))
    }
}

/// 256-bit 一次性登记 code（本机 admin 生成，Relay 只存 hash），base64 wire。
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
pub struct EnrollmentCode(
    #[serde(with = "secret_b64_32")]
    #[schemars(with = "String")]
    pub [u8; 32],
);

impl std::fmt::Debug for EnrollmentCode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("EnrollmentCode(<redacted>)")
    }
}

impl Drop for EnrollmentCode {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// 专用 TLS endpoint 的机器登记请求（design core interface）。
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MachineEnrollmentRequestV1 {
    pub code: EnrollmentCode,
    pub machine_route: MachineRouteId,
    /// MachineRoot 验签公钥（machine trust anchor）。
    pub root_pubkey: PublicKeyBytes,
    pub link_cert: SignedCertificate,
    pub data_cert: SignedCertificate,
}

impl std::fmt::Debug for MachineEnrollmentRequestV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MachineEnrollmentRequestV1")
            .field("enrollment_material", &"<redacted>")
            .finish()
    }
}

impl MachineEnrollmentRequestV1 {
    /// 与 HTTP JSON 表示独立的 deterministic enrollment request bytes。
    ///
    /// code、route、MachineRoot 与两张完整 root-signed certificate 均使用大端 u32
    /// 长度前缀绑定，避免依赖 JSON 字段顺序或 whitespace 做幂等 request hash。
    pub fn canonical_bytes(&self) -> Zeroizing<Vec<u8>> {
        let link = self.link_cert.canonical_bytes();
        let data = self.data_cert.canonical_bytes();
        let mut encoder = Enc::new();
        encoder.domain(b"AgentDeck/MachineEnrollmentRequestV1\0");
        encoder.bytes(&self.code.0);
        encoder.bytes(self.machine_route.as_bytes());
        encoder.bytes(&self.root_pubkey.0);
        encoder.bytes(&link);
        encoder.bytes(&data);
        Zeroizing::new(encoder.finish())
    }

    pub fn canonical_sha256(&self) -> [u8; 32] {
        let canonical = self.canonical_bytes();
        Sha256::digest(canonical.as_slice()).into()
    }
}

/// 机器登记响应（design core interface）。code 消费 + machine row insert 在同一事务；
/// TTL 内同 code + 同 request hash 幂等重放逐字节相同 response。
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MachineEnrollmentResponseV1 {
    pub relay_server_id: RelayServerId,
    pub machine_route: MachineRouteId,
    pub trust_epoch: u64,
    #[serde(with = "b64_32")]
    #[schemars(with = "String")]
    pub receipt_hash: [u8; 32],
}

impl std::fmt::Debug for MachineEnrollmentResponseV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MachineEnrollmentResponseV1")
            .field("enrollment_receipt", &"<redacted>")
            .finish()
    }
}

/// Relay 与 client 共用的 enrollment receipt hash。它绑定 Relay identity、machine
/// route、trust epoch 与完整 canonical request hash，避免 client 只信任 JSON 回显。
pub fn enrollment_receipt_hash(
    relay_server_id: RelayServerId,
    machine_route: MachineRouteId,
    trust_epoch: u64,
    request_hash: [u8; 32],
) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(108);
    bytes.extend_from_slice(b"AgentDeck/MachineEnrollmentReceiptV1\0");
    bytes.extend_from_slice(relay_server_id.as_bytes());
    bytes.extend_from_slice(machine_route.as_bytes());
    bytes.extend_from_slice(&trust_epoch.to_be_bytes());
    bytes.extend_from_slice(&request_hash);
    Sha256::digest(bytes).into()
}
