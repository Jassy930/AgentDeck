//! Relay v2 首次机器登记（design §6.1 / §10.1）。
//!
//! 机器登记**不属于**已鉴权 Relay frame family：Relay 额外提供一个只接收
//! [`MachineEnrollmentRequestV1`] 的专用 TLS endpoint，消费本机 admin 生成的 5 分钟
//! 单次 code，并在同一事务插入 machine route。它不提供 inventory / purge。
//!
//! daemon 必须在发送 code 与 root/link/data public material 前完成公开 CA 或 enrollment
//! bundle SPKI pin 验证（design §12.1）。

use crate::e2ee::Enc;
use crate::relay_v2::admin_receipt::RelayReceiptVerifyKeyV1;
use crate::relay_v2::auth::{PublicKeyBytes, SignedCertificate};
use crate::relay_v2::id::{MachineRouteId, RelayServerId, b64_32};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

/// Relay admin 与 daemon/CLI 共用的 enrollment bundle wire 版本。
pub const ENROLLMENT_BUNDLE_VERSION: u16 = 2;

fn deserialize_enrollment_bundle_version<'de, D>(deserializer: D) -> Result<u16, D::Error>
where
    D: Deserializer<'de>,
{
    let version = u16::deserialize(deserializer)?;
    if version == ENROLLMENT_BUNDLE_VERSION {
        Ok(version)
    } else {
        Err(serde::de::Error::custom(
            "unsupported enrollment bundle version",
        ))
    }
}

/// URL-safe、无 padding 的 32-byte digest wire DTO。
///
/// Enrollment bundle 用它携带 `SHA-256(DER SPKI)` pin；Relay admin 也复用同一
/// wire 表示承载本机确认 fingerprint/hash，避免复制可漂移的 JSON primitive。
#[derive(Clone, Copy, PartialEq, Eq, Hash, JsonSchema)]
#[serde(transparent)]
pub struct Digest32(#[schemars(with = "String")] pub [u8; 32]);

impl std::fmt::Debug for Digest32 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Digest32(<redacted>)")
    }
}

impl Serialize for Digest32 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&URL_SAFE_NO_PAD.encode(self.0))
    }
}

impl<'de> Deserialize<'de> for Digest32 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        let bytes = URL_SAFE_NO_PAD
            .decode(value.as_bytes())
            .map_err(serde::de::Error::custom)?;
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected a 32-byte digest"))?;
        Ok(Self(bytes))
    }
}

/// 本机 admin 创建、经用户控制的带外通道交给 daemon/CLI 的 enrollment bundle。
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EnrollmentBundleV2 {
    #[serde(deserialize_with = "deserialize_enrollment_bundle_version")]
    #[schemars(range(min = 2, max = 2))]
    pub version: u16,
    pub public_wss_url: String,
    pub relay_server_id: RelayServerId,
    pub receipt_verify_key: RelayReceiptVerifyKeyV1,
    pub code: EnrollmentCode,
    pub spki_pins: Vec<Digest32>,
    pub expires_at_ms: u64,
}

impl std::fmt::Debug for EnrollmentBundleV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EnrollmentBundleV2")
            .field("version", &self.version)
            .field("relay_server_id", &self.relay_server_id.redacted())
            .field("secret_material", &"<redacted>")
            .field("expires_at_ms", &self.expires_at_ms)
            .finish()
    }
}

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

/// Enrollment response 在持久化/比对 canonical terminal 前的绑定校验错误。
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MachineEnrollmentResponseError {
    #[error("machine enrollment response required field is all-zero: {0}")]
    ZeroBoundField(&'static str),
}

impl std::fmt::Debug for MachineEnrollmentResponseV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MachineEnrollmentResponseV1")
            .field("enrollment_receipt", &"<redacted>")
            .finish()
    }
}

impl MachineEnrollmentResponseV1 {
    /// 构造一个已验证的 response；保留公开字段以兼容既有 wire DTO 调用方。
    pub fn new(
        relay_server_id: RelayServerId,
        machine_route: MachineRouteId,
        trust_epoch: u64,
        receipt_hash: [u8; 32],
    ) -> Result<Self, MachineEnrollmentResponseError> {
        let response = Self {
            relay_server_id,
            machine_route,
            trust_epoch,
            receipt_hash,
        };
        response.validate()?;
        Ok(response)
    }

    pub fn validate(&self) -> Result<(), MachineEnrollmentResponseError> {
        if self.relay_server_id.as_bytes() == &[0; 16] {
            return Err(MachineEnrollmentResponseError::ZeroBoundField(
                "relayServerId",
            ));
        }
        if self.machine_route.as_bytes() == &[0; 16] {
            return Err(MachineEnrollmentResponseError::ZeroBoundField(
                "machineRoute",
            ));
        }
        if self.trust_epoch == 0 {
            return Err(MachineEnrollmentResponseError::ZeroBoundField("trustEpoch"));
        }
        if self.receipt_hash == [0; 32] {
            return Err(MachineEnrollmentResponseError::ZeroBoundField(
                "receiptHash",
            ));
        }
        Ok(())
    }

    /// 与 JSON 字段顺序无关的 deterministic response terminal bytes。
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, MachineEnrollmentResponseError> {
        self.validate()?;
        let mut encoder = Enc::new();
        encoder.domain(b"AgentDeck/MachineEnrollmentResponseV1\0");
        encoder.bytes(self.relay_server_id.as_bytes());
        encoder.bytes(self.machine_route.as_bytes());
        encoder.u64(self.trust_epoch);
        encoder.bytes(&self.receipt_hash);
        Ok(encoder.finish())
    }

    pub fn canonical_sha256(&self) -> Result<[u8; 32], MachineEnrollmentResponseError> {
        Ok(Sha256::digest(self.canonical_bytes()?).into())
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
