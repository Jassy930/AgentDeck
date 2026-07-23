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
//! 本模块同时拥有这些公开对象、challenge transcript 与 root-signed TBS 的 canonical
//! bytes/hash 合约；实际 Ed25519 签名与验签由 `agentdeck-crypto` 提供。

use crate::e2ee::tbs::{SignedObjectType, ToBeSignedV1};
use crate::e2ee::{E2EE_FORMAT_VERSION, Enc};
use crate::relay_v2::RELAY_PROTOCOL_VERSION;
use crate::relay_v2::id::{
    ConnectionInstanceId, DeviceRouteId, GrantSerial, LinkGeneration, MachineRouteId,
    RelayServerId, RootKeyId, TrustEpoch, b64_32, b64_64,
};
use crate::runtime::RUNTIME_PROTOCOL_VERSION;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Relay v2 root / endpoint 签名格式版本。该版本独立于 Relay、Runtime 与 E2EE 版本轴。
pub const AUTH_SIGNATURE_FORMAT_VERSION: u16 = 1;

/// 完整 MachineRoot-signed certificate canonical bytes 的解析硬上限。
///
/// 当前 v1 编码只有 222 bytes；保留 1 KiB 上限用于 fail-fast 拒绝不受信输入，且不把
/// canonical parser 变成通用无界 length-prefix reader。
pub const SIGNED_CERTIFICATE_MAX_CANONICAL_BYTES: usize = 1_024;

/// 完整 RelayGrant canonical bytes 的解析硬上限。
///
/// 当前 v1 编码固定为 238 bytes；2 KiB 与 PairResponse v1 已冻结的 nested bound 一致。
pub const RELAY_GRANT_MAX_CANONICAL_BYTES: usize = 2 * 1_024;

/// Relay 公开授权对象的严格 canonical decoder 错误。
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AuthCanonicalError {
    #[error("auth canonical value exceeds its bound: {0}")]
    SizeLimit(&'static str),
    #[error("invalid auth canonical encoding: {0}")]
    InvalidEncoding(&'static str),
}

const MACHINE_LINK_ROLE_SCOPE: &str = "machine-link";
const MACHINE_DATA_ROLE_SCOPE: &str = "machine-data";
const RELAY_GRANT_ROLE_SCOPE: &str = "relay-device-grant";
const DEVICE_REVOCATION_ROLE_SCOPE: &str = "relay-device-revocation";

/// challenge endpoint 身份域。枚举 tag 是 canonical transcript 的一部分，不得重排。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum AuthenticationRole {
    MachineLink,
    Device,
}

impl AuthenticationRole {
    const fn canonical_tag(self) -> u8 {
        match self {
            Self::MachineLink => 0,
            Self::Device => 1,
        }
    }
}

/// endpoint 对单次 Relay challenge 签名的完整 canonical transcript（design §6.4）。
///
/// `credential_sha256` 必须是 [`SignedCertificate::canonical_sha256`] 或
/// [`RelayGrant::canonical_sha256`] 的结果，即包含 root signature 的**完整**凭据 hash，
/// 不能用 unsigned object hash 代替。
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthenticationTranscriptV1 {
    pub role: AuthenticationRole,
    #[serde(with = "b64_32")]
    #[schemars(with = "String")]
    pub challenge_nonce: [u8; 32],
    pub connection_instance: ConnectionInstanceId,
    pub relay_server_id: RelayServerId,
    pub relay_protocol_version: u16,
    pub machine_route: MachineRouteId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_route: Option<DeviceRouteId>,
    /// MachineLink cert generation 或 RelayGrant serial。
    pub serial_or_generation: u64,
    #[serde(with = "b64_32")]
    #[schemars(with = "String")]
    pub credential_sha256: [u8; 32],
}

impl std::fmt::Debug for AuthenticationTranscriptV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthenticationTranscriptV1")
            .field("role", &self.role)
            .field("relay_protocol_version", &self.relay_protocol_version)
            .field("serial_or_generation", &self.serial_or_generation)
            .field("bound_material", &"<redacted>")
            .finish()
    }
}

impl AuthenticationTranscriptV1 {
    /// 与 outer frame codec 独立的确定性签名 preimage。
    pub fn encode(&self) -> Vec<u8> {
        let mut encoder = Enc::new();
        encoder.domain(b"AgentDeck/AuthenticationTranscriptV1\0");
        encoder.u8(self.role.canonical_tag());
        encoder.bytes(&self.challenge_nonce);
        encoder.bytes(self.connection_instance.as_bytes());
        encoder.bytes(self.relay_server_id.as_bytes());
        encoder.u16(self.relay_protocol_version);
        encoder.bytes(self.machine_route.as_bytes());
        encode_optional_device_route(&mut encoder, self.device_route.as_ref());
        encoder.u64(self.serial_or_generation);
        encoder.bytes(&self.credential_sha256);
        encoder.finish()
    }
}

/// 32-byte 公钥（Ed25519 验签公钥 / X25519 HPKE 公钥），base64 wire。
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
pub struct PublicKeyBytes(
    #[serde(with = "b64_32")]
    #[schemars(with = "String")]
    pub [u8; 32],
);

impl std::fmt::Debug for PublicKeyBytes {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PublicKeyBytes(<redacted>)")
    }
}

/// 64-byte Ed25519 签名，base64 wire。
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
pub struct Ed25519Signature(
    #[serde(with = "b64_64")]
    #[schemars(with = "String")]
    pub [u8; 64],
);

impl std::fmt::Debug for Ed25519Signature {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Ed25519Signature(<redacted>)")
    }
}

/// 证书角色：日常连接 auth（Link）或 daemon 下行数据来源签名（Data）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum CertRole {
    Link,
    Data,
}

/// MachineRoot 签发的 link / data 证书（design §6.6）。
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
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

impl std::fmt::Debug for SignedCertificate {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SignedCertificate")
            .field("cert_role", &self.cert_role)
            .field("generation", &self.generation.value())
            .field("trust_epoch", &self.trust_epoch.value())
            .field("not_after_ms", &self.not_after_ms)
            .field("key_and_signature", &"<redacted>")
            .finish()
    }
}

impl SignedCertificate {
    /// 不含 root signature 的 canonical object bytes；root 对其 SHA-256 构造 TBS。
    pub fn unsigned_canonical_bytes(&self) -> Vec<u8> {
        let mut encoder = Enc::new();
        encoder.domain(b"AgentDeck/SignedCertificateUnsignedV1\0");
        encoder.bytes(&self.subject_pubkey.0);
        encoder.u8(cert_role_tag(self.cert_role));
        encoder.u64(self.generation.value());
        encoder.bytes(self.root_key_id.as_bytes());
        encoder.u64(self.trust_epoch.value());
        encoder.opt_u64(self.not_after_ms);
        encoder.finish()
    }

    /// 包含 root signature 的完整 canonical credential bytes。
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let unsigned = self.unsigned_canonical_bytes();
        let mut encoder = Enc::new();
        encoder.domain(b"AgentDeck/SignedCertificateV1\0");
        encoder.bytes(&unsigned);
        encoder.bytes(&self.signature.0);
        encoder.finish()
    }

    /// 从唯一 canonical credential bytes 严格恢复证书。
    ///
    /// 解析在读取字段前执行总长上限，并拒绝未知 enum/optional tag、截断、内外层尾随
    /// bytes 以及不能逐字节重编码为原输入的非 canonical 表示。
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, AuthCanonicalError> {
        if bytes.len() > SIGNED_CERTIFICATE_MAX_CANONICAL_BYTES {
            return Err(AuthCanonicalError::SizeLimit("SignedCertificate"));
        }

        let mut outer = CanonicalDecoder::new(bytes);
        outer.domain(b"AgentDeck/SignedCertificateV1\0")?;
        let unsigned = outer.bytes(
            SIGNED_CERTIFICATE_MAX_CANONICAL_BYTES,
            "certificate unsigned",
        )?;
        let signature = Ed25519Signature(outer.fixed()?);
        outer.finish()?;

        let mut decoder = CanonicalDecoder::new(unsigned);
        decoder.domain(b"AgentDeck/SignedCertificateUnsignedV1\0")?;
        let subject_pubkey = PublicKeyBytes(decoder.fixed()?);
        let cert_role = match decoder.u8()? {
            0 => CertRole::Link,
            1 => CertRole::Data,
            _ => {
                return Err(AuthCanonicalError::InvalidEncoding("certificate role"));
            }
        };
        let value = Self {
            subject_pubkey,
            cert_role,
            generation: LinkGeneration::new(decoder.u64()?),
            root_key_id: RootKeyId::from_bytes(decoder.fixed()?),
            trust_epoch: TrustEpoch::new(decoder.u64()?),
            not_after_ms: decoder.optional_u64()?,
            signature,
        };
        decoder.finish()?;
        ensure_auth_canonical(bytes, &value.canonical_bytes())?;
        Ok(value)
    }

    pub fn unsigned_canonical_sha256(&self) -> [u8; 32] {
        sha256(&self.unsigned_canonical_bytes())
    }

    pub fn canonical_sha256(&self) -> [u8; 32] {
        sha256(&self.canonical_bytes())
    }

    /// 构造 MachineRoot 对证书签名的 canonical [`ToBeSignedV1`]。
    ///
    /// `root_public_key_fingerprint` 是 MachineRoot 公钥 canonical raw 32 bytes 的 SHA-256，
    /// 不是 subject（日常 link/data key）的 fingerprint。
    pub fn to_be_signed_v1(
        &self,
        relay_server_id: RelayServerId,
        machine_route: MachineRouteId,
        root_public_key_fingerprint: [u8; 32],
    ) -> ToBeSignedV1 {
        let (object_type, role_scope) = match self.cert_role {
            CertRole::Link => (SignedObjectType::LinkCert, MACHINE_LINK_ROLE_SCOPE),
            CertRole::Data => (SignedObjectType::DataCert, MACHINE_DATA_ROLE_SCOPE),
        };
        ToBeSignedV1 {
            object_type,
            signature_format_version: AUTH_SIGNATURE_FORMAT_VERSION,
            relay_protocol_version: RELAY_PROTOCOL_VERSION,
            runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
            e2ee_format_version: E2EE_FORMAT_VERSION,
            relay_server_id,
            machine_route,
            device_route: None,
            stream_route: None,
            request_route: None,
            stream_generation: None,
            stream_cursor: None,
            role_scope: role_scope.to_owned(),
            signing_key_fingerprint: root_public_key_fingerprint,
            root_key_id: self.root_key_id,
            trust_epoch: self.trust_epoch,
            serial_or_generation: self.generation.value(),
            not_after_ms: self.not_after_ms,
            signed_object_sha256: self.unsigned_canonical_sha256(),
        }
    }
}

/// DeviceGrant 的 Relay 可见部分（design §6.3）。只含 Relay 鉴权所需字段：随机
/// machine/device route、设备连接验签公钥、grant serial 与 MachineRoot 签名。加密的
/// `DeviceAuthorization`（业务权限）只供 endpoint，Relay 看不到。
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
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

impl std::fmt::Debug for RelayGrant {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RelayGrant")
            .field("machine", &self.machine_route.redacted())
            .field("device", &self.device_route.redacted())
            .field("grant_serial", &self.grant_serial.value())
            .field("trust_epoch", &self.trust_epoch.value())
            .field("key_and_signature", &"<redacted>")
            .finish()
    }
}

impl RelayGrant {
    /// 不含 MachineRoot signature 的 RelayGrant canonical bytes。
    pub fn unsigned_canonical_bytes(&self) -> Vec<u8> {
        let mut encoder = Enc::new();
        encoder.domain(b"AgentDeck/RelayGrantUnsignedV1\0");
        encoder.bytes(self.machine_route.as_bytes());
        encoder.bytes(self.device_route.as_bytes());
        encoder.bytes(&self.device_sign_pubkey.0);
        encoder.u64(self.grant_serial.value());
        encoder.bytes(self.root_key_id.as_bytes());
        encoder.u64(self.trust_epoch.value());
        encoder.finish()
    }

    /// 包含 MachineRoot signature 的完整 RelayGrant credential bytes。
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let unsigned = self.unsigned_canonical_bytes();
        let mut encoder = Enc::new();
        encoder.domain(b"AgentDeck/RelayGrantV1\0");
        encoder.bytes(&unsigned);
        encoder.bytes(&self.signature.0);
        encoder.finish()
    }

    /// 从唯一 canonical credential bytes 严格恢复 RelayGrant。
    ///
    /// 解析有总长与 nested length 双重上限，并拒绝截断、内外层尾随 bytes 以及不能
    /// 逐字节重编码为原输入的非 canonical 表示。
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, AuthCanonicalError> {
        if bytes.len() > RELAY_GRANT_MAX_CANONICAL_BYTES {
            return Err(AuthCanonicalError::SizeLimit("RelayGrant"));
        }

        let mut outer = CanonicalDecoder::new(bytes);
        outer.domain(b"AgentDeck/RelayGrantV1\0")?;
        let unsigned = outer.bytes(RELAY_GRANT_MAX_CANONICAL_BYTES, "RelayGrant unsigned")?;
        let signature = Ed25519Signature(outer.fixed()?);
        outer.finish()?;

        let mut decoder = CanonicalDecoder::new(unsigned);
        decoder.domain(b"AgentDeck/RelayGrantUnsignedV1\0")?;
        let value = Self {
            machine_route: MachineRouteId::from_bytes(decoder.fixed()?),
            device_route: DeviceRouteId::from_bytes(decoder.fixed()?),
            device_sign_pubkey: PublicKeyBytes(decoder.fixed()?),
            grant_serial: GrantSerial::new(decoder.u64()?),
            root_key_id: RootKeyId::from_bytes(decoder.fixed()?),
            trust_epoch: TrustEpoch::new(decoder.u64()?),
            signature,
        };
        decoder.finish()?;
        ensure_auth_canonical(bytes, &value.canonical_bytes())?;
        Ok(value)
    }

    pub fn unsigned_canonical_sha256(&self) -> [u8; 32] {
        sha256(&self.unsigned_canonical_bytes())
    }

    pub fn canonical_sha256(&self) -> [u8; 32] {
        sha256(&self.canonical_bytes())
    }

    /// 构造 MachineRoot 对 RelayGrant 签名的 canonical [`ToBeSignedV1`]。
    pub fn to_be_signed_v1(
        &self,
        relay_server_id: RelayServerId,
        root_public_key_fingerprint: [u8; 32],
    ) -> ToBeSignedV1 {
        ToBeSignedV1 {
            object_type: SignedObjectType::RelayGrant,
            signature_format_version: AUTH_SIGNATURE_FORMAT_VERSION,
            relay_protocol_version: RELAY_PROTOCOL_VERSION,
            runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
            e2ee_format_version: E2EE_FORMAT_VERSION,
            relay_server_id,
            machine_route: self.machine_route,
            device_route: Some(self.device_route),
            stream_route: None,
            request_route: None,
            stream_generation: None,
            stream_cursor: None,
            role_scope: RELAY_GRANT_ROLE_SCOPE.to_owned(),
            signing_key_fingerprint: root_public_key_fingerprint,
            root_key_id: self.root_key_id,
            trust_epoch: self.trust_epoch,
            serial_or_generation: self.grant_serial.value(),
            not_after_ms: None,
            signed_object_sha256: self.unsigned_canonical_sha256(),
        }
    }
}

/// MachineRoot 签的设备撤销，绑定 `grantSerial`（design §6.5）。
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeviceRevocation {
    pub machine_route: MachineRouteId,
    pub device_route: DeviceRouteId,
    pub grant_serial: GrantSerial,
    pub root_key_id: RootKeyId,
    pub trust_epoch: TrustEpoch,
    pub signature: Ed25519Signature,
}

impl std::fmt::Debug for DeviceRevocation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DeviceRevocation")
            .field("machine", &self.machine_route.redacted())
            .field("device", &self.device_route.redacted())
            .field("grant_serial", &self.grant_serial.value())
            .field("trust_epoch", &self.trust_epoch.value())
            .field("signature", &"<redacted>")
            .finish()
    }
}

impl DeviceRevocation {
    /// 不含 MachineRoot signature 的撤销 canonical bytes。
    pub fn unsigned_canonical_bytes(&self) -> Vec<u8> {
        let mut encoder = Enc::new();
        encoder.domain(b"AgentDeck/DeviceRevocationUnsignedV1\0");
        encoder.bytes(self.machine_route.as_bytes());
        encoder.bytes(self.device_route.as_bytes());
        encoder.u64(self.grant_serial.value());
        encoder.bytes(self.root_key_id.as_bytes());
        encoder.u64(self.trust_epoch.value());
        encoder.finish()
    }

    /// 包含 MachineRoot signature 的完整撤销 credential bytes。
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let unsigned = self.unsigned_canonical_bytes();
        let mut encoder = Enc::new();
        encoder.domain(b"AgentDeck/DeviceRevocationV1\0");
        encoder.bytes(&unsigned);
        encoder.bytes(&self.signature.0);
        encoder.finish()
    }

    pub fn unsigned_canonical_sha256(&self) -> [u8; 32] {
        sha256(&self.unsigned_canonical_bytes())
    }

    pub fn canonical_sha256(&self) -> [u8; 32] {
        sha256(&self.canonical_bytes())
    }

    /// 构造 MachineRoot 对设备撤销签名的 canonical [`ToBeSignedV1`]。
    pub fn to_be_signed_v1(
        &self,
        relay_server_id: RelayServerId,
        root_public_key_fingerprint: [u8; 32],
    ) -> ToBeSignedV1 {
        ToBeSignedV1 {
            object_type: SignedObjectType::DeviceRevocation,
            signature_format_version: AUTH_SIGNATURE_FORMAT_VERSION,
            relay_protocol_version: RELAY_PROTOCOL_VERSION,
            runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
            e2ee_format_version: E2EE_FORMAT_VERSION,
            relay_server_id,
            machine_route: self.machine_route,
            device_route: Some(self.device_route),
            stream_route: None,
            request_route: None,
            stream_generation: None,
            stream_cursor: None,
            role_scope: DEVICE_REVOCATION_ROLE_SCOPE.to_owned(),
            signing_key_fingerprint: root_public_key_fingerprint,
            root_key_id: self.root_key_id,
            trust_epoch: self.trust_epoch,
            serial_or_generation: self.grant_serial.value(),
            not_after_ms: None,
            signed_object_sha256: self.unsigned_canonical_sha256(),
        }
    }
}

fn cert_role_tag(role: CertRole) -> u8 {
    match role {
        CertRole::Link => 0,
        CertRole::Data => 1,
    }
}

fn encode_optional_device_route(encoder: &mut Enc, route: Option<&DeviceRouteId>) {
    match route {
        Some(route) => {
            encoder.u8(1);
            encoder.bytes(route.as_bytes());
        }
        None => encoder.u8(0),
    }
}

fn ensure_auth_canonical(input: &[u8], reencoded: &[u8]) -> Result<(), AuthCanonicalError> {
    if input != reencoded {
        return Err(AuthCanonicalError::InvalidEncoding("non-canonical bytes"));
    }
    Ok(())
}

/// 只服务本模块固定授权对象的 borrowed decoder。
struct CanonicalDecoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> CanonicalDecoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], AuthCanonicalError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(AuthCanonicalError::InvalidEncoding("length overflow"))?;
        if end > self.bytes.len() {
            return Err(AuthCanonicalError::InvalidEncoding("truncated bytes"));
        }
        let value = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(value)
    }

    fn domain(&mut self, expected: &[u8]) -> Result<(), AuthCanonicalError> {
        if self.take(expected.len())? != expected {
            return Err(AuthCanonicalError::InvalidEncoding("domain separator"));
        }
        Ok(())
    }

    fn u8(&mut self) -> Result<u8, AuthCanonicalError> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, AuthCanonicalError> {
        Ok(u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .expect("take returned exactly four bytes"),
        ))
    }

    fn u64(&mut self) -> Result<u64, AuthCanonicalError> {
        Ok(u64::from_be_bytes(
            self.take(8)?
                .try_into()
                .expect("take returned exactly eight bytes"),
        ))
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], AuthCanonicalError> {
        self.bytes(N, "fixed-width field")?
            .try_into()
            .map_err(|_| AuthCanonicalError::InvalidEncoding("fixed-width field"))
    }

    fn bytes(&mut self, max: usize, field: &'static str) -> Result<&'a [u8], AuthCanonicalError> {
        let length =
            usize::try_from(self.u32()?).map_err(|_| AuthCanonicalError::SizeLimit(field))?;
        if length > max {
            return Err(AuthCanonicalError::SizeLimit(field));
        }
        self.take(length)
    }

    fn optional_u64(&mut self) -> Result<Option<u64>, AuthCanonicalError> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.u64()?)),
            _ => Err(AuthCanonicalError::InvalidEncoding("optional u64 tag")),
        }
    }

    fn finish(self) -> Result<(), AuthCanonicalError> {
        if self.offset != self.bytes.len() {
            return Err(AuthCanonicalError::InvalidEncoding("trailing bytes"));
        }
        Ok(())
    }
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn certificate() -> SignedCertificate {
        SignedCertificate {
            subject_pubkey: PublicKeyBytes([0x11; 32]),
            cert_role: CertRole::Link,
            generation: LinkGeneration::new(7),
            root_key_id: RootKeyId::from_bytes([0x22; 16]),
            trust_epoch: TrustEpoch::new(3),
            not_after_ms: Some(9),
            signature: Ed25519Signature([0x33; 64]),
        }
    }

    fn grant() -> RelayGrant {
        RelayGrant {
            machine_route: MachineRouteId::from_bytes([0x44; 16]),
            device_route: DeviceRouteId::from_bytes([0x55; 16]),
            device_sign_pubkey: PublicKeyBytes([0x66; 32]),
            grant_serial: GrantSerial::new(8),
            root_key_id: RootKeyId::from_bytes([0x77; 16]),
            trust_epoch: TrustEpoch::new(4),
            signature: Ed25519Signature([0x88; 64]),
        }
    }

    #[test]
    fn certificate_unsigned_and_full_canonical_golden_are_fixed() {
        let certificate = certificate();
        assert_eq!(
            hex(&certificate.unsigned_canonical_bytes()),
            "4167656e744465636b2f5369676e65644365727469666963617465556e7369676e656456310000000020111111111111111111111111111111111111111111111111111111111111111100000000000000000700000010222222222222222222222222222222220000000000000003010000000000000009"
        );
        assert_eq!(certificate.canonical_bytes().len(), 222);
        assert_eq!(
            hex(&certificate.canonical_sha256()),
            "b0b95841d7484b28fc133bfcdb16677878023e361b3e8784079b5ff0fce3e204"
        );
    }

    #[test]
    fn relay_grant_unsigned_and_full_canonical_golden_are_fixed() {
        let grant = grant();
        assert_eq!(
            hex(&grant.unsigned_canonical_bytes()),
            "4167656e744465636b2f52656c61794772616e74556e7369676e656456310000000010444444444444444444444444444444440000001055555555555555555555555555555555000000206666666666666666666666666666666666666666666666666666666666666666000000000000000800000010777777777777777777777777777777770000000000000004"
        );
        assert_eq!(grant.canonical_bytes().len(), 238);
        assert_eq!(
            hex(&grant.canonical_sha256()),
            "4d7f552fa647dbe4611943756f4481ee99580d712445f70b5c1d0fe5bbb877dd"
        );
    }

    #[test]
    fn certificate_canonical_decoder_is_strict_and_bounded() {
        let certificate = certificate();
        let canonical = certificate.canonical_bytes();
        assert_eq!(
            SignedCertificate::from_canonical_bytes(&canonical).unwrap(),
            certificate
        );

        let mut trailing = canonical.clone();
        trailing.push(0);
        assert!(SignedCertificate::from_canonical_bytes(&trailing).is_err());

        let mut invalid_optional_tag = canonical;
        let unsigned_domain_len = b"AgentDeck/SignedCertificateUnsignedV1\0".len();
        let optional_tag_offset = b"AgentDeck/SignedCertificateV1\0".len()
            + 4
            + unsigned_domain_len
            + 4
            + 32
            + 1
            + 8
            + 4
            + 16
            + 8;
        invalid_optional_tag[optional_tag_offset] = 2;
        assert!(SignedCertificate::from_canonical_bytes(&invalid_optional_tag).is_err());

        assert!(
            SignedCertificate::from_canonical_bytes(&vec![
                0;
                SIGNED_CERTIFICATE_MAX_CANONICAL_BYTES
                    + 1
            ])
            .is_err()
        );
    }

    #[test]
    fn relay_grant_canonical_decoder_is_strict_and_bounded() {
        let grant = grant();
        let canonical = grant.canonical_bytes();
        assert_eq!(RelayGrant::from_canonical_bytes(&canonical).unwrap(), grant);

        let mut trailing = canonical;
        trailing.push(0);
        assert!(RelayGrant::from_canonical_bytes(&trailing).is_err());

        assert!(
            RelayGrant::from_canonical_bytes(&vec![0; RELAY_GRANT_MAX_CANONICAL_BYTES + 1])
                .is_err()
        );
    }

    #[test]
    fn authentication_transcript_golden_binds_complete_credential_hash() {
        let grant = grant();
        let transcript = AuthenticationTranscriptV1 {
            role: AuthenticationRole::Device,
            challenge_nonce: [0x99; 32],
            connection_instance: ConnectionInstanceId::from_bytes([0xaa; 16]),
            relay_server_id: RelayServerId::from_bytes([0xbb; 16]),
            relay_protocol_version: RELAY_PROTOCOL_VERSION,
            machine_route: grant.machine_route,
            device_route: Some(grant.device_route),
            serial_or_generation: grant.grant_serial.value(),
            credential_sha256: grant.canonical_sha256(),
        };
        assert_eq!(
            hex(&transcript.encode()),
            "4167656e744465636b2f41757468656e7469636174696f6e5472616e7363726970745631000100000020999999999999999999999999999999999999999999999999999999999999999900000010aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00000010bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb000200000010444444444444444444444444444444440100000010555555555555555555555555555555550000000000000008000000204d7f552fa647dbe4611943756f4481ee99580d712445f70b5c1d0fe5bbb877dd"
        );
    }

    #[test]
    fn root_signed_tbs_builders_fix_versions_scope_fingerprint_and_unsigned_hash() {
        let root_fingerprint = [0xab; 32];
        let cert = certificate();
        let relay_server_id = RelayServerId::from_bytes([0xcd; 16]);
        let machine_route = MachineRouteId::from_bytes([0xef; 16]);
        let cert_tbs = cert.to_be_signed_v1(relay_server_id, machine_route, root_fingerprint);
        assert_eq!(cert_tbs.object_type, SignedObjectType::LinkCert);
        assert_eq!(
            cert_tbs.signature_format_version,
            AUTH_SIGNATURE_FORMAT_VERSION
        );
        assert_eq!(cert_tbs.relay_protocol_version, RELAY_PROTOCOL_VERSION);
        assert_eq!(cert_tbs.runtime_protocol_version, RUNTIME_PROTOCOL_VERSION);
        assert_eq!(cert_tbs.e2ee_format_version, E2EE_FORMAT_VERSION);
        assert_eq!(cert_tbs.role_scope, MACHINE_LINK_ROLE_SCOPE);
        assert_eq!(cert_tbs.signing_key_fingerprint, root_fingerprint);
        assert_eq!(
            cert_tbs.signed_object_sha256,
            cert.unsigned_canonical_sha256()
        );

        let grant = grant();
        let grant_tbs = grant.to_be_signed_v1(relay_server_id, root_fingerprint);
        assert_eq!(grant_tbs.object_type, SignedObjectType::RelayGrant);
        assert_eq!(grant_tbs.role_scope, RELAY_GRANT_ROLE_SCOPE);
        assert_eq!(grant_tbs.device_route, Some(grant.device_route));
        assert_eq!(grant_tbs.signing_key_fingerprint, root_fingerprint);
        assert_eq!(
            grant_tbs.signed_object_sha256,
            grant.unsigned_canonical_sha256()
        );
    }

    #[test]
    fn every_authentication_transcript_field_changes_canonical_bytes() {
        let base = AuthenticationTranscriptV1 {
            role: AuthenticationRole::MachineLink,
            challenge_nonce: [1; 32],
            connection_instance: ConnectionInstanceId::from_bytes([2; 16]),
            relay_server_id: RelayServerId::from_bytes([3; 16]),
            relay_protocol_version: 2,
            machine_route: MachineRouteId::from_bytes([4; 16]),
            device_route: None,
            serial_or_generation: 5,
            credential_sha256: [6; 32],
        };
        let encoded = base.encode();
        let mut changes = Vec::new();
        let mut value = base.clone();
        value.role = AuthenticationRole::Device;
        changes.push(value);
        let mut value = base.clone();
        value.challenge_nonce[0] ^= 1;
        changes.push(value);
        let mut value = base.clone();
        value.connection_instance = ConnectionInstanceId::from_bytes([7; 16]);
        changes.push(value);
        let mut value = base.clone();
        value.relay_server_id = RelayServerId::from_bytes([7; 16]);
        changes.push(value);
        let mut value = base.clone();
        value.relay_protocol_version = 3;
        changes.push(value);
        let mut value = base.clone();
        value.machine_route = MachineRouteId::from_bytes([7; 16]);
        changes.push(value);
        let mut value = base.clone();
        value.device_route = Some(DeviceRouteId::from_bytes([7; 16]));
        changes.push(value);
        let mut value = base.clone();
        value.serial_or_generation += 1;
        changes.push(value);
        let mut value = base;
        value.credential_sha256[0] ^= 1;
        changes.push(value);

        for changed in changes {
            assert_ne!(changed.encode(), encoded);
        }
    }

    #[test]
    fn authentication_transcript_debug_redacts_bound_material() {
        let transcript = AuthenticationTranscriptV1 {
            role: AuthenticationRole::MachineLink,
            challenge_nonce: [0xa1; 32],
            connection_instance: ConnectionInstanceId::from_bytes([0xa2; 16]),
            relay_server_id: RelayServerId::from_bytes([0xa3; 16]),
            relay_protocol_version: 2,
            machine_route: MachineRouteId::from_bytes([0xa4; 16]),
            device_route: None,
            serial_or_generation: 5,
            credential_sha256: [0xa5; 32],
        };
        let debug = format!("{transcript:?}");
        for secret in ["a1a1a1a1", "a2a2a2a2", "a3a3a3a3", "a4a4a4a4", "a5a5a5a5"] {
            assert!(!debug.contains(secret));
        }
        assert!(debug.contains("<redacted>"));
    }
}
