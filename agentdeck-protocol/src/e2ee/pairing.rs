//! 版本化 pairing DTO、专属 canonical transcript 与两种 pairing HPKE info。
//!
//! PairRequest/PairResponse 都分成“进入 HPKE 的 plaintext”和“Relay 转发的 envelope”。
//! Ed25519 proof/signature 是 envelope 的 detached 字段：签名 TBS 绑定 info、AAD、`enc`
//! 与 ciphertext hash，但不包含签名自身；requestHash/responseHash 则覆盖包含 detached
//! signature 的完整 canonical envelope，从结构上消除 ciphertext preimage 循环。

use std::collections::HashSet;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;

use crate::e2ee::context::{OuterContextV1, OuterFrameKind};
use crate::e2ee::keys::KeyDirectoryV1;
use crate::e2ee::tbs::{SignedObjectType, ToBeSignedV1};
use crate::e2ee::{E2EE_FORMAT_VERSION, Enc, b64_32, b64_vec};
use crate::relay_v2::RELAY_PROTOCOL_VERSION;
use crate::relay_v2::auth::{
    AUTH_SIGNATURE_FORMAT_VERSION, CertRole, Ed25519Signature, PublicKeyBytes, RelayGrant,
    SignedCertificate,
};
use crate::relay_v2::id::{
    DeviceRouteId, GrantSerial, LinkGeneration, MachineRouteId, PairRouteId, RelayServerId,
    RootKeyId, TrustEpoch,
};

pub const PAIR_INVITE_URI_PREFIX: &str = "agentdeck-pair:v1:";
pub const PAIR_INVITE_MAX_TTL_MS: u64 = 5 * 60 * 1_000;
pub const PAIR_INVITE_MAX_URI_BYTES: usize = 8 * 1_024;
pub const PAIRING_MAX_URL_BYTES: usize = 2 * 1_024;
pub const PAIRING_MAX_DISPLAY_NAME_BYTES: usize = 128;
pub const PAIRING_HPKE_ENC_BYTES: usize = 32;
pub const PAIRING_MAX_CIPHERTEXT_BYTES: usize = 256 * 1_024;

const AUTHORIZATION_CAPABILITY_COUNT: usize = 7;
const AUTHORIZATION_PERMISSION_COUNT: usize = 9;
const MAX_NESTED_CANONICAL_BYTES: usize = 512 * 1_024;
const MAX_PAIR_RESPONSE_INFO_CANONICAL_BYTES: usize = 4 * 1_024;
const DEVICE_AUTHORIZATION_ROLE_SCOPE: &str = "device-authorization";

#[path = "pairing_response.rs"]
mod response;
pub use response::{MachineDataSignerBindingV1, PairResponseInfoV1, PairResponseV1};

mod optional_b64_32 {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(
        value: &Option<[u8; 32]>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        value
            .as_ref()
            .map(|bytes| STANDARD.encode(bytes))
            .serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<[u8; 32]>, D::Error> {
        let value = Option::<String>::deserialize(deserializer)?;
        value
            .map(|encoded| {
                STANDARD
                    .decode(encoded.as_bytes())
                    .map_err(serde::de::Error::custom)?
                    .try_into()
                    .map_err(|_| serde::de::Error::custom("hash must decode to exactly 32 bytes"))
            })
            .transpose()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PairingError {
    #[error("pairing value has an unsupported version")]
    UnsupportedVersion,
    #[error("pairing invitation is expired")]
    Expired,
    #[error("pairing invitation expiry exceeds the five-minute bound")]
    ExpiryOutOfBounds,
    #[error("invalid pairing field: {0}")]
    InvalidField(&'static str),
    #[error("pairing field exceeds its bound: {0}")]
    SizeLimit(&'static str),
    #[error("invalid canonical pairing encoding: {0}")]
    InvalidEncoding(&'static str),
    #[error("authorization permission is not covered by its capability")]
    PermissionWithoutCapability,
    #[error("authorization set contains a duplicate value")]
    DuplicateAuthorization,
    #[error("device authorization does not match RelayGrant")]
    GrantBindingMismatch,
    #[error("pairing info/AAD does not match the envelope kind or pair route")]
    ContextBindingMismatch,
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

pub fn validate_pairing_display_name(value: &str) -> Result<(), PairingError> {
    if value.is_empty()
        || value.len() > PAIRING_MAX_DISPLAY_NAME_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(PairingError::InvalidField("display name"));
    }
    Ok(())
}

fn fingerprint_display(value: &[u8; 32]) -> String {
    let mut output = String::from("sha256:");
    for (index, byte) in value.iter().enumerate() {
        if index != 0 {
            output.push(':');
        }
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

fn encode_optional_hash(encoder: &mut Enc, value: Option<&[u8; 32]>) {
    match value {
        Some(hash) => {
            encoder.u8(1);
            encoder.bytes(hash);
        }
        None => encoder.u8(0),
    }
}

/// P4 MVP 能力 family。不存在 machine admin、pairing admin 或 trust-reset family。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum AuthorizationCapabilityV1 {
    Catalog,
    Conversation,
    Prompt,
    Command,
    Approval,
    Metadata,
    SelfRevocation,
}

impl AuthorizationCapabilityV1 {
    const fn tag(self) -> u8 {
        match self {
            Self::Catalog => 0,
            Self::Conversation => 1,
            Self::Prompt => 2,
            Self::Command => 3,
            Self::Approval => 4,
            Self::Metadata => 5,
            Self::SelfRevocation => 6,
        }
    }

    fn from_tag(tag: u8) -> Result<Self, PairingError> {
        match tag {
            0 => Ok(Self::Catalog),
            1 => Ok(Self::Conversation),
            2 => Ok(Self::Prompt),
            3 => Ok(Self::Command),
            4 => Ok(Self::Approval),
            5 => Ok(Self::Metadata),
            6 => Ok(Self::SelfRevocation),
            _ => Err(PairingError::InvalidEncoding("authorization capability")),
        }
    }
}

/// P4 MVP 可授予的精确远程操作。枚举本身就是 allowlist，unknown serde 值直接拒绝。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum AuthorizationPermissionV1 {
    CatalogRead,
    ConversationRead,
    ConversationStart,
    PromptSend,
    CommandCancel,
    ApprovalResolve,
    ApprovalRetry,
    MetadataWrite,
    RevokeSelf,
}

impl AuthorizationPermissionV1 {
    const fn tag(self) -> u8 {
        match self {
            Self::CatalogRead => 0,
            Self::ConversationRead => 1,
            Self::ConversationStart => 2,
            Self::PromptSend => 3,
            Self::CommandCancel => 4,
            Self::ApprovalResolve => 5,
            Self::ApprovalRetry => 6,
            Self::MetadataWrite => 7,
            Self::RevokeSelf => 8,
        }
    }

    const fn required_capability(self) -> AuthorizationCapabilityV1 {
        match self {
            Self::CatalogRead => AuthorizationCapabilityV1::Catalog,
            Self::ConversationRead | Self::ConversationStart => {
                AuthorizationCapabilityV1::Conversation
            }
            Self::PromptSend => AuthorizationCapabilityV1::Prompt,
            Self::CommandCancel => AuthorizationCapabilityV1::Command,
            Self::ApprovalResolve | Self::ApprovalRetry => AuthorizationCapabilityV1::Approval,
            Self::MetadataWrite => AuthorizationCapabilityV1::Metadata,
            Self::RevokeSelf => AuthorizationCapabilityV1::SelfRevocation,
        }
    }

    fn from_tag(tag: u8) -> Result<Self, PairingError> {
        match tag {
            0 => Ok(Self::CatalogRead),
            1 => Ok(Self::ConversationRead),
            2 => Ok(Self::ConversationStart),
            3 => Ok(Self::PromptSend),
            4 => Ok(Self::CommandCancel),
            5 => Ok(Self::ApprovalResolve),
            6 => Ok(Self::ApprovalRetry),
            7 => Ok(Self::MetadataWrite),
            8 => Ok(Self::RevokeSelf),
            _ => Err(PairingError::InvalidEncoding("authorization permission")),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorizationRequestV1 {
    pub format_version: u16,
    pub device_display_name: String,
    pub capabilities: Vec<AuthorizationCapabilityV1>,
    pub permissions: Vec<AuthorizationPermissionV1>,
}

impl std::fmt::Debug for AuthorizationRequestV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthorizationRequestV1")
            .field("format_version", &self.format_version)
            .field("requested_material", &"<redacted>")
            .finish()
    }
}

fn validate_authorization_sets(
    capabilities: &[AuthorizationCapabilityV1],
    permissions: &[AuthorizationPermissionV1],
) -> Result<(), PairingError> {
    if capabilities.is_empty() || capabilities.len() > AUTHORIZATION_CAPABILITY_COUNT {
        return Err(PairingError::SizeLimit("capabilities"));
    }
    if permissions.is_empty() || permissions.len() > AUTHORIZATION_PERMISSION_COUNT {
        return Err(PairingError::SizeLimit("permissions"));
    }
    if capabilities
        .windows(2)
        .any(|pair| pair[0].tag() >= pair[1].tag())
        || permissions
            .windows(2)
            .any(|pair| pair[0].tag() >= pair[1].tag())
    {
        return Err(PairingError::DuplicateAuthorization);
    }
    let capabilities_set: HashSet<_> = capabilities.iter().copied().collect();
    if permissions
        .iter()
        .any(|permission| !capabilities_set.contains(&permission.required_capability()))
    {
        return Err(PairingError::PermissionWithoutCapability);
    }
    Ok(())
}

impl AuthorizationRequestV1 {
    pub fn validate(&self) -> Result<(), PairingError> {
        if self.format_version != E2EE_FORMAT_VERSION {
            return Err(PairingError::UnsupportedVersion);
        }
        validate_pairing_display_name(&self.device_display_name)?;
        validate_authorization_sets(&self.capabilities, &self.permissions)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, PairingError> {
        self.validate()?;
        let mut encoder = Enc::new();
        encoder.domain(b"AgentDeck/AuthorizationRequestV1\0");
        encoder.u16(self.format_version);
        encoder.str(&self.device_display_name);
        encoder.u8(self.capabilities.len() as u8);
        for capability in &self.capabilities {
            encoder.u8(capability.tag());
        }
        encoder.u8(self.permissions.len() as u8);
        for permission in &self.permissions {
            encoder.u8(permission.tag());
        }
        Ok(encoder.finish())
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, PairingError> {
        let mut decoder = Decoder::new(bytes);
        decoder.domain(b"AgentDeck/AuthorizationRequestV1\0")?;
        let format_version = decoder.u16()?;
        let device_display_name = decoder.string(PAIRING_MAX_DISPLAY_NAME_BYTES)?;
        let capability_count = decoder.u8()? as usize;
        if capability_count > AUTHORIZATION_CAPABILITY_COUNT {
            return Err(PairingError::SizeLimit("capabilities"));
        }
        let mut capabilities = Vec::with_capacity(capability_count);
        for _ in 0..capability_count {
            capabilities.push(AuthorizationCapabilityV1::from_tag(decoder.u8()?)?);
        }
        let permission_count = decoder.u8()? as usize;
        if permission_count > AUTHORIZATION_PERMISSION_COUNT {
            return Err(PairingError::SizeLimit("permissions"));
        }
        let mut permissions = Vec::with_capacity(permission_count);
        for _ in 0..permission_count {
            permissions.push(AuthorizationPermissionV1::from_tag(decoder.u8()?)?);
        }
        decoder.finish()?;
        let value = Self {
            format_version,
            device_display_name,
            capabilities,
            permissions,
        };
        value.validate()?;
        ensure_canonical(bytes, &value.canonical_bytes()?)?;
        Ok(value)
    }
}

/// 被控机器创建的带外配对邀请。完整值是 bearer secret，Debug 一律全量脱敏。
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(
    rename_all = "camelCase",
    deny_unknown_fields,
    try_from = "PairInviteWireV1"
)]
pub struct PairInviteV1 {
    pub format_version: u16,
    pub relay_protocol_version: u16,
    pub pair_route: PairRouteId,
    #[serde(with = "b64_32")]
    #[schemars(with = "String")]
    pub invite_secret: [u8; 32],
    pub invite_hpke_pubkey: PublicKeyBytes,
    pub wss_url: String,
    pub relay_server_id: RelayServerId,
    #[serde(with = "b64_32")]
    #[schemars(with = "String")]
    pub current_spki_pin: [u8; 32],
    #[serde(with = "b64_32")]
    #[schemars(with = "String")]
    pub next_spki_pin: [u8; 32],
    pub expires_at_ms: u64,
    pub machine_root_pubkey: PublicKeyBytes,
    #[serde(with = "b64_32")]
    #[schemars(with = "String")]
    pub machine_root_fingerprint: [u8; 32],
    pub data_sign_cert: SignedCertificate,
    pub machine_display_name: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PairInviteWireV1 {
    format_version: u16,
    relay_protocol_version: u16,
    pair_route: PairRouteId,
    #[serde(with = "b64_32")]
    invite_secret: [u8; 32],
    invite_hpke_pubkey: PublicKeyBytes,
    wss_url: String,
    relay_server_id: RelayServerId,
    #[serde(with = "b64_32")]
    current_spki_pin: [u8; 32],
    #[serde(with = "b64_32")]
    next_spki_pin: [u8; 32],
    expires_at_ms: u64,
    machine_root_pubkey: PublicKeyBytes,
    #[serde(with = "b64_32")]
    machine_root_fingerprint: [u8; 32],
    data_sign_cert: SignedCertificate,
    machine_display_name: String,
}

impl TryFrom<PairInviteWireV1> for PairInviteV1 {
    type Error = PairingError;

    fn try_from(value: PairInviteWireV1) -> Result<Self, Self::Error> {
        let invite = Self {
            format_version: value.format_version,
            relay_protocol_version: value.relay_protocol_version,
            pair_route: value.pair_route,
            invite_secret: value.invite_secret,
            invite_hpke_pubkey: value.invite_hpke_pubkey,
            wss_url: value.wss_url,
            relay_server_id: value.relay_server_id,
            current_spki_pin: value.current_spki_pin,
            next_spki_pin: value.next_spki_pin,
            expires_at_ms: value.expires_at_ms,
            machine_root_pubkey: value.machine_root_pubkey,
            machine_root_fingerprint: value.machine_root_fingerprint,
            data_sign_cert: value.data_sign_cert,
            machine_display_name: value.machine_display_name,
        };
        invite.validate_static()?;
        Ok(invite)
    }
}

impl std::fmt::Debug for PairInviteV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PairInviteV1")
            .field("pairing_material", &"<redacted>")
            .finish()
    }
}

impl PairInviteV1 {
    pub fn validate_static(&self) -> Result<(), PairingError> {
        if self.format_version != E2EE_FORMAT_VERSION
            || self.relay_protocol_version != RELAY_PROTOCOL_VERSION
        {
            return Err(PairingError::UnsupportedVersion);
        }
        if self.wss_url.len() > PAIRING_MAX_URL_BYTES {
            return Err(PairingError::SizeLimit("wss URL"));
        }
        let url = Url::parse(&self.wss_url).map_err(|_| PairingError::InvalidField("wss URL"))?;
        if url.scheme() != "wss"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.path() != "/"
            || url.port() == Some(0)
            || url.query().is_some()
            || url.fragment().is_some()
            || url.as_str() != self.wss_url
        {
            return Err(PairingError::InvalidField("wss URL"));
        }
        validate_pairing_display_name(&self.machine_display_name)?;
        if is_zero(self.pair_route.as_bytes())
            || is_zero(self.relay_server_id.as_bytes())
            || is_zero(&self.invite_secret)
            || is_zero(&self.invite_hpke_pubkey.0)
            || is_zero(&self.current_spki_pin)
            || is_zero(&self.next_spki_pin)
            || is_zero(&self.machine_root_pubkey.0)
            || is_zero(&self.data_sign_cert.subject_pubkey.0)
            || is_zero(&self.data_sign_cert.signature.0)
            || self.expires_at_ms == 0
        {
            return Err(PairingError::InvalidField("zero identity/key material"));
        }
        if self.machine_root_fingerprint != sha256(&self.machine_root_pubkey.0) {
            return Err(PairingError::InvalidField("MachineRoot fingerprint"));
        }
        if self.data_sign_cert.cert_role != CertRole::Data
            || self.data_sign_cert.generation.value() == 0
            || self.data_sign_cert.trust_epoch.value() == 0
            || is_zero(self.data_sign_cert.root_key_id.as_bytes())
            || self.data_sign_cert.not_after_ms == Some(0)
        {
            return Err(PairingError::InvalidField("MachineDataSign certificate"));
        }
        Ok(())
    }

    pub fn validate(&self, now_ms: u64) -> Result<(), PairingError> {
        self.validate_static()?;
        let remaining = self
            .expires_at_ms
            .checked_sub(now_ms)
            .ok_or(PairingError::Expired)?;
        if remaining == 0 {
            return Err(PairingError::Expired);
        }
        if remaining > PAIR_INVITE_MAX_TTL_MS {
            return Err(PairingError::ExpiryOutOfBounds);
        }
        if self
            .data_sign_cert
            .not_after_ms
            .is_some_and(|expiry| now_ms >= expiry)
        {
            return Err(PairingError::InvalidField(
                "expired MachineDataSign certificate",
            ));
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, PairingError> {
        self.validate_static()?;
        let mut encoder = Enc::new();
        encoder.domain(b"AgentDeck/PairInviteV1\0");
        encoder.u16(self.format_version);
        encoder.u16(self.relay_protocol_version);
        encoder.bytes(self.pair_route.as_bytes());
        encoder.bytes(&self.invite_secret);
        encoder.bytes(&self.invite_hpke_pubkey.0);
        encoder.str(&self.wss_url);
        encoder.bytes(self.relay_server_id.as_bytes());
        encoder.bytes(&self.current_spki_pin);
        encoder.bytes(&self.next_spki_pin);
        encoder.u64(self.expires_at_ms);
        encoder.bytes(&self.machine_root_pubkey.0);
        encoder.bytes(&self.machine_root_fingerprint);
        encoder.bytes(&self.data_sign_cert.canonical_bytes());
        encoder.str(&self.machine_display_name);
        Ok(encoder.finish())
    }

    pub fn canonical_sha256(&self) -> Result<[u8; 32], PairingError> {
        Ok(sha256(&self.canonical_bytes()?))
    }

    pub fn encode_uri(&self, now_ms: u64) -> Result<String, PairingError> {
        self.validate(now_ms)?;
        let encoded = format!(
            "{PAIR_INVITE_URI_PREFIX}{}",
            URL_SAFE_NO_PAD.encode(self.canonical_bytes()?)
        );
        if encoded.len() > PAIR_INVITE_MAX_URI_BYTES {
            return Err(PairingError::SizeLimit("pair invite URI"));
        }
        Ok(encoded)
    }

    pub fn decode_uri(encoded: &str, now_ms: u64) -> Result<Self, PairingError> {
        if encoded.len() > PAIR_INVITE_MAX_URI_BYTES || encoded.contains('=') {
            return Err(PairingError::SizeLimit("pair invite URI"));
        }
        let payload = encoded
            .strip_prefix(PAIR_INVITE_URI_PREFIX)
            .ok_or(PairingError::InvalidEncoding("pair invite URI prefix"))?;
        let bytes = URL_SAFE_NO_PAD
            .decode(payload.as_bytes())
            .map_err(|_| PairingError::InvalidEncoding("pair invite base64url"))?;
        if URL_SAFE_NO_PAD.encode(&bytes) != payload {
            return Err(PairingError::InvalidEncoding("non-canonical base64url"));
        }
        let value = Self::from_canonical_bytes(&bytes)?;
        value.validate(now_ms)?;
        Ok(value)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, PairingError> {
        if bytes.len() > PAIR_INVITE_MAX_URI_BYTES {
            return Err(PairingError::SizeLimit("pair invite canonical bytes"));
        }
        let mut decoder = Decoder::new(bytes);
        decoder.domain(b"AgentDeck/PairInviteV1\0")?;
        let value = Self {
            format_version: decoder.u16()?,
            relay_protocol_version: decoder.u16()?,
            pair_route: PairRouteId::from_bytes(decoder.fixed()?),
            invite_secret: decoder.fixed()?,
            invite_hpke_pubkey: PublicKeyBytes(decoder.fixed()?),
            wss_url: decoder.string(PAIRING_MAX_URL_BYTES)?,
            relay_server_id: RelayServerId::from_bytes(decoder.fixed()?),
            current_spki_pin: decoder.fixed()?,
            next_spki_pin: decoder.fixed()?,
            expires_at_ms: decoder.u64()?,
            machine_root_pubkey: PublicKeyBytes(decoder.fixed()?),
            machine_root_fingerprint: decoder.fixed()?,
            data_sign_cert: decode_signed_certificate(decoder.bytes(1_024)?)?,
            machine_display_name: decoder.string(PAIRING_MAX_DISPLAY_NAME_BYTES)?,
        };
        decoder.finish()?;
        ensure_canonical(bytes, &value.canonical_bytes()?)?;
        Ok(value)
    }

    pub fn machine_root_fingerprint_display(&self) -> String {
        fingerprint_display(&self.machine_root_fingerprint)
    }
}

/// HPKE plaintext。proof 不在这里，避免 seal 时要求预知 ciphertext/signature。
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PairRequestPlaintextV1 {
    pub format_version: u16,
    #[serde(with = "b64_32")]
    #[schemars(with = "String")]
    pub invite_secret: [u8; 32],
    pub device_sign_pubkey: PublicKeyBytes,
    pub device_hpke_pubkey: PublicKeyBytes,
    pub authorization_request: AuthorizationRequestV1,
}

impl std::fmt::Debug for PairRequestPlaintextV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PairRequestPlaintextV1")
            .field("format_version", &self.format_version)
            .field("plaintext", &"<redacted>")
            .finish()
    }
}

impl PairRequestPlaintextV1 {
    pub fn validate(&self) -> Result<(), PairingError> {
        if self.format_version != E2EE_FORMAT_VERSION {
            return Err(PairingError::UnsupportedVersion);
        }
        if is_zero(&self.invite_secret)
            || is_zero(&self.device_sign_pubkey.0)
            || is_zero(&self.device_hpke_pubkey.0)
        {
            return Err(PairingError::InvalidField("pair request key material"));
        }
        self.authorization_request.validate()
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, PairingError> {
        self.validate()?;
        let mut encoder = Enc::new();
        encoder.domain(b"AgentDeck/PairRequestPlaintextV1\0");
        encoder.u16(self.format_version);
        encoder.bytes(&self.invite_secret);
        encoder.bytes(&self.device_sign_pubkey.0);
        encoder.bytes(&self.device_hpke_pubkey.0);
        encoder.bytes(&self.authorization_request.canonical_bytes()?);
        Ok(encoder.finish())
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, PairingError> {
        let mut decoder = Decoder::new(bytes);
        decoder.domain(b"AgentDeck/PairRequestPlaintextV1\0")?;
        let value = Self {
            format_version: decoder.u16()?,
            invite_secret: decoder.fixed()?,
            device_sign_pubkey: PublicKeyBytes(decoder.fixed()?),
            device_hpke_pubkey: PublicKeyBytes(decoder.fixed()?),
            authorization_request: AuthorizationRequestV1::from_canonical_bytes(
                decoder.bytes(4 * 1_024)?,
            )?,
        };
        decoder.finish()?;
        value.validate()?;
        ensure_canonical(bytes, &value.canonical_bytes()?)?;
        Ok(value)
    }

    pub fn device_sign_fingerprint(&self) -> [u8; 32] {
        sha256(&self.device_sign_pubkey.0)
    }

    pub fn device_sign_fingerprint_display(&self) -> String {
        fingerprint_display(&self.device_sign_fingerprint())
    }
}

/// Relay PairData 携带的完整 PairRequest envelope。requestHash 覆盖 `canonical_bytes()`。
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PairRequestV1 {
    pub format_version: u16,
    #[serde(with = "b64_vec")]
    #[schemars(with = "String")]
    pub enc: Vec<u8>,
    #[serde(with = "b64_vec")]
    #[schemars(with = "String")]
    pub ciphertext: Vec<u8>,
    pub device_proof_signature: Ed25519Signature,
}

impl std::fmt::Debug for PairRequestV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PairRequestV1")
            .field("envelope", &"<redacted>")
            .finish()
    }
}

impl PairRequestV1 {
    pub fn validate(&self) -> Result<(), PairingError> {
        validate_envelope(
            self.format_version,
            &self.enc,
            &self.ciphertext,
            &self.device_proof_signature,
        )
    }

    pub fn unsigned_canonical_bytes(&self) -> Result<Vec<u8>, PairingError> {
        self.validate()?;
        encode_unsigned_envelope(
            PairingEnvelopeKindV1::PairRequest,
            self.format_version,
            None,
            &self.enc,
            &self.ciphertext,
        )
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, PairingError> {
        let unsigned = self.unsigned_canonical_bytes()?;
        Ok(encode_signed_envelope(
            PairingEnvelopeKindV1::PairRequest,
            &unsigned,
            &self.device_proof_signature,
        ))
    }

    pub fn canonical_sha256(&self) -> Result<[u8; 32], PairingError> {
        Ok(sha256(&self.canonical_bytes()?))
    }

    pub fn proof_tbs(
        &self,
        info: &PairRequestInfoV1,
        context: &OuterContextV1,
        device_sign_fingerprint: [u8; 32],
    ) -> Result<PairingEnvelopeTbsV1, PairingError> {
        self.validate()?;
        validate_request_context(info, context)?;
        if is_zero(&device_sign_fingerprint) {
            return Err(PairingError::InvalidField("DeviceSign fingerprint"));
        }
        PairingEnvelopeTbsV1::for_request(self, info, context, device_sign_fingerprint)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, PairingError> {
        let decoded = decode_signed_envelope(bytes, PairingEnvelopeKindV1::PairRequest)?;
        if decoded.response_info.is_some() {
            return Err(PairingError::InvalidEncoding("PairRequest embedded info"));
        }
        let value = Self {
            format_version: decoded.format_version,
            enc: decoded.enc,
            ciphertext: decoded.ciphertext,
            device_proof_signature: decoded.signature,
        };
        value.validate()?;
        ensure_canonical(bytes, &value.canonical_bytes()?)?;
        Ok(value)
    }
}

/// 与 requestHash 绑定的待确认状态；MachineDataSign 签名，无 grant。
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(
    rename_all = "camelCase",
    deny_unknown_fields,
    try_from = "PairPendingWireV1"
)]
pub struct PairPendingV1 {
    #[serde(with = "b64_32")]
    #[schemars(with = "String")]
    pub request_hash: [u8; 32],
    pub signature: Ed25519Signature,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PairPendingWireV1 {
    #[serde(with = "b64_32")]
    request_hash: [u8; 32],
    signature: Ed25519Signature,
}

impl TryFrom<PairPendingWireV1> for PairPendingV1 {
    type Error = PairingError;

    fn try_from(value: PairPendingWireV1) -> Result<Self, Self::Error> {
        let pending = Self {
            request_hash: value.request_hash,
            signature: value.signature,
        };
        pending.validate()?;
        Ok(pending)
    }
}

impl std::fmt::Debug for PairPendingV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PairPendingV1")
            .field("pending_material", &"<redacted>")
            .finish()
    }
}

/// MachineRoot 签名、随 PairResponse HPKE plaintext 交付的业务授权。
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeviceAuthorizationV1 {
    pub format_version: u16,
    #[serde(with = "b64_32")]
    #[schemars(with = "String")]
    pub grant_hash: [u8; 32],
    pub machine_route: MachineRouteId,
    pub device_route: DeviceRouteId,
    #[serde(with = "b64_32")]
    #[schemars(with = "String")]
    pub device_sign_fingerprint: [u8; 32],
    pub grant_serial: GrantSerial,
    pub device_hpke_pubkey: PublicKeyBytes,
    pub capabilities: Vec<AuthorizationCapabilityV1>,
    pub permissions: Vec<AuthorizationPermissionV1>,
    pub root_key_id: RootKeyId,
    pub trust_epoch: TrustEpoch,
    pub signature: Ed25519Signature,
}

impl std::fmt::Debug for DeviceAuthorizationV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DeviceAuthorizationV1")
            .field("format_version", &self.format_version)
            .field("authorization_material", &"<redacted>")
            .finish()
    }
}

impl DeviceAuthorizationV1 {
    fn validate_unsigned(&self) -> Result<(), PairingError> {
        if self.format_version != E2EE_FORMAT_VERSION {
            return Err(PairingError::UnsupportedVersion);
        }
        if is_zero(&self.grant_hash)
            || is_zero(self.machine_route.as_bytes())
            || is_zero(self.device_route.as_bytes())
            || is_zero(&self.device_sign_fingerprint)
            || self.grant_serial.value() == 0
            || is_zero(&self.device_hpke_pubkey.0)
            || is_zero(self.root_key_id.as_bytes())
            || self.trust_epoch.value() == 0
        {
            return Err(PairingError::InvalidField("device authorization material"));
        }
        validate_authorization_sets(&self.capabilities, &self.permissions)
    }

    pub fn validate(&self) -> Result<(), PairingError> {
        self.validate_unsigned()?;
        if is_zero(&self.signature.0) {
            return Err(PairingError::InvalidField("device authorization signature"));
        }
        Ok(())
    }

    pub fn validate_unsigned_for_grant(&self, grant: &RelayGrant) -> Result<(), PairingError> {
        self.validate_unsigned()?;
        self.validate_grant_binding(grant)
    }

    pub fn validate_for_grant(&self, grant: &RelayGrant) -> Result<(), PairingError> {
        self.validate()?;
        self.validate_grant_binding(grant)
    }

    fn validate_grant_binding(&self, grant: &RelayGrant) -> Result<(), PairingError> {
        if self.grant_hash != grant.canonical_sha256()
            || self.machine_route != grant.machine_route
            || self.device_route != grant.device_route
            || self.device_sign_fingerprint != sha256(&grant.device_sign_pubkey.0)
            || self.grant_serial != grant.grant_serial
            || self.root_key_id != grant.root_key_id
            || self.trust_epoch != grant.trust_epoch
        {
            return Err(PairingError::GrantBindingMismatch);
        }
        Ok(())
    }

    pub fn unsigned_canonical_bytes(&self) -> Result<Vec<u8>, PairingError> {
        self.validate_unsigned()?;
        let mut encoder = Enc::new();
        encoder.domain(b"AgentDeck/DeviceAuthorizationUnsignedV1\0");
        encode_device_authorization_fields(&mut encoder, self);
        Ok(encoder.finish())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, PairingError> {
        let unsigned = self.unsigned_canonical_bytes()?;
        let mut encoder = Enc::new();
        encoder.domain(b"AgentDeck/DeviceAuthorizationV1\0");
        encoder.bytes(&unsigned);
        encoder.bytes(&self.signature.0);
        Ok(encoder.finish())
    }

    pub fn canonical_sha256(&self) -> Result<[u8; 32], PairingError> {
        Ok(sha256(&self.canonical_bytes()?))
    }

    pub fn to_be_signed_v1(
        &self,
        relay_server_id: RelayServerId,
        root_public_key_fingerprint: [u8; 32],
    ) -> Result<ToBeSignedV1, PairingError> {
        Ok(ToBeSignedV1 {
            object_type: SignedObjectType::DeviceAuthorization,
            signature_format_version: AUTH_SIGNATURE_FORMAT_VERSION,
            relay_protocol_version: RELAY_PROTOCOL_VERSION,
            runtime_protocol_version: crate::runtime::RUNTIME_PROTOCOL_VERSION,
            e2ee_format_version: E2EE_FORMAT_VERSION,
            relay_server_id,
            machine_route: self.machine_route,
            device_route: Some(self.device_route),
            stream_route: None,
            request_route: None,
            stream_generation: None,
            stream_cursor: None,
            role_scope: DEVICE_AUTHORIZATION_ROLE_SCOPE.to_owned(),
            signing_key_fingerprint: root_public_key_fingerprint,
            root_key_id: self.root_key_id,
            trust_epoch: self.trust_epoch,
            serial_or_generation: self.grant_serial.value(),
            not_after_ms: None,
            signed_object_sha256: sha256(&self.unsigned_canonical_bytes()?),
        })
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, PairingError> {
        let mut outer = Decoder::new(bytes);
        outer.domain(b"AgentDeck/DeviceAuthorizationV1\0")?;
        let unsigned = outer.bytes(MAX_NESTED_CANONICAL_BYTES)?;
        let signature = Ed25519Signature(outer.fixed()?);
        outer.finish()?;

        let mut decoder = Decoder::new(unsigned);
        decoder.domain(b"AgentDeck/DeviceAuthorizationUnsignedV1\0")?;
        let format_version = decoder.u16()?;
        let grant_hash = decoder.fixed()?;
        let machine_route = MachineRouteId::from_bytes(decoder.fixed()?);
        let device_route = DeviceRouteId::from_bytes(decoder.fixed()?);
        let device_sign_fingerprint = decoder.fixed()?;
        let grant_serial = GrantSerial::new(decoder.u64()?);
        let device_hpke_pubkey = PublicKeyBytes(decoder.fixed()?);
        let capability_count = decoder.u8()? as usize;
        if capability_count > AUTHORIZATION_CAPABILITY_COUNT {
            return Err(PairingError::SizeLimit("capabilities"));
        }
        let mut capabilities = Vec::with_capacity(capability_count);
        for _ in 0..capability_count {
            capabilities.push(AuthorizationCapabilityV1::from_tag(decoder.u8()?)?);
        }
        let permission_count = decoder.u8()? as usize;
        if permission_count > AUTHORIZATION_PERMISSION_COUNT {
            return Err(PairingError::SizeLimit("permissions"));
        }
        let mut permissions = Vec::with_capacity(permission_count);
        for _ in 0..permission_count {
            permissions.push(AuthorizationPermissionV1::from_tag(decoder.u8()?)?);
        }
        let root_key_id = RootKeyId::from_bytes(decoder.fixed()?);
        let trust_epoch = TrustEpoch::new(decoder.u64()?);
        decoder.finish()?;
        let value = Self {
            format_version,
            grant_hash,
            machine_route,
            device_route,
            device_sign_fingerprint,
            grant_serial,
            device_hpke_pubkey,
            capabilities,
            permissions,
            root_key_id,
            trust_epoch,
            signature,
        };
        value.validate()?;
        ensure_canonical(bytes, &value.canonical_bytes()?)?;
        Ok(value)
    }
}

/// 进入 DeviceHPKE 的 PairResponse plaintext；MachineDataSign 不在 plaintext 内。
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PairResponsePlaintextV1 {
    pub format_version: u16,
    #[serde(with = "b64_32")]
    #[schemars(with = "String")]
    pub request_hash: [u8; 32],
    pub relay_grant: RelayGrant,
    pub device_authorization: DeviceAuthorizationV1,
    pub key_directory: KeyDirectoryV1,
}

impl std::fmt::Debug for PairResponsePlaintextV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PairResponsePlaintextV1")
            .field("format_version", &self.format_version)
            .field("plaintext", &"<redacted>")
            .finish()
    }
}

impl PairResponsePlaintextV1 {
    pub fn validate(&self) -> Result<(), PairingError> {
        if self.format_version != E2EE_FORMAT_VERSION {
            return Err(PairingError::UnsupportedVersion);
        }
        if is_zero(&self.request_hash)
            || is_zero(self.relay_grant.machine_route.as_bytes())
            || is_zero(self.relay_grant.device_route.as_bytes())
            || is_zero(&self.relay_grant.device_sign_pubkey.0)
            || self.relay_grant.grant_serial.value() == 0
            || is_zero(self.relay_grant.root_key_id.as_bytes())
            || self.relay_grant.trust_epoch.value() == 0
            || is_zero(&self.relay_grant.signature.0)
        {
            return Err(PairingError::InvalidField("PairResponse grant"));
        }
        self.device_authorization
            .validate_for_grant(&self.relay_grant)?;
        // PairResponse wire 可携带首次 grant 的 authenticated conversation epoch-1
        // entries；exact route 集合必须由 daemon 用 Store mapping 调用
        // `validate_initial_directory_for_device` 复核。
        self.key_directory
            .validate_for_device(self.relay_grant.device_route)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, PairingError> {
        self.validate()?;
        let mut encoder = Enc::new();
        encoder.domain(b"AgentDeck/PairResponsePlaintextV1\0");
        encoder.u16(self.format_version);
        encoder.bytes(&self.request_hash);
        encoder.bytes(&self.relay_grant.canonical_bytes());
        encoder.bytes(&self.device_authorization.canonical_bytes()?);
        encoder.bytes(&self.key_directory.canonical_bytes()?);
        Ok(encoder.finish())
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, PairingError> {
        let mut decoder = Decoder::new(bytes);
        decoder.domain(b"AgentDeck/PairResponsePlaintextV1\0")?;
        let value = Self {
            format_version: decoder.u16()?,
            request_hash: decoder.fixed()?,
            relay_grant: decode_relay_grant(decoder.bytes(2 * 1_024)?)?,
            device_authorization: DeviceAuthorizationV1::from_canonical_bytes(
                decoder.bytes(16 * 1_024)?,
            )?,
            key_directory: KeyDirectoryV1::from_canonical_bytes(
                decoder.bytes(MAX_NESTED_CANONICAL_BYTES)?,
            )?,
        };
        decoder.finish()?;
        value.validate()?;
        ensure_canonical(bytes, &value.canonical_bytes()?)?;
        Ok(value)
    }
}

/// DeviceSign 回执；daemon 仅在三个 hash 都匹配 frozen artifacts 后推进 delivered。
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(
    rename_all = "camelCase",
    deny_unknown_fields,
    try_from = "PairResponseReceivedWireV1"
)]
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

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PairResponseReceivedWireV1 {
    #[serde(with = "b64_32")]
    request_hash: [u8; 32],
    #[serde(with = "b64_32")]
    grant_hash: [u8; 32],
    #[serde(with = "b64_32")]
    response_hash: [u8; 32],
    signature: Ed25519Signature,
}

impl TryFrom<PairResponseReceivedWireV1> for PairResponseReceivedV1 {
    type Error = PairingError;

    fn try_from(value: PairResponseReceivedWireV1) -> Result<Self, Self::Error> {
        let receipt = Self {
            request_hash: value.request_hash,
            grant_hash: value.grant_hash,
            response_hash: value.response_hash,
            signature: value.signature,
        };
        receipt.canonical_bytes()?;
        Ok(receipt)
    }
}

impl std::fmt::Debug for PairResponseReceivedV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PairResponseReceivedV1")
            .field("receipt_material", &"<redacted>")
            .finish()
    }
}

impl PairResponseReceivedV1 {
    pub fn unsigned_canonical_bytes(&self) -> Result<Vec<u8>, PairingError> {
        if is_zero(&self.request_hash) || is_zero(&self.grant_hash) || is_zero(&self.response_hash)
        {
            return Err(PairingError::InvalidField("pair response receipt hash"));
        }
        let mut encoder = Enc::new();
        encoder.domain(b"AgentDeck/PairResponseReceivedUnsignedV1\0");
        encoder.bytes(&self.request_hash);
        encoder.bytes(&self.grant_hash);
        encoder.bytes(&self.response_hash);
        Ok(encoder.finish())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, PairingError> {
        if is_zero(&self.signature.0) {
            return Err(PairingError::InvalidField(
                "pair response receipt signature",
            ));
        }
        let mut encoder = Enc::new();
        encoder.domain(b"AgentDeck/PairResponseReceivedV1\0");
        encoder.bytes(&self.unsigned_canonical_bytes()?);
        encoder.bytes(&self.signature.0);
        Ok(encoder.finish())
    }
}

/// Pairing envelope 专属签名域。pre-grant PairRequest 没有 machine route，故不能硬套
/// `ToBeSignedV1` 的非空 machine-route 公共前缀。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum PairingEnvelopeKindV1 {
    PairRequest,
    PairResponse,
}

impl PairingEnvelopeKindV1 {
    const fn tag(self) -> u8 {
        match self {
            Self::PairRequest => 0,
            Self::PairResponse => 1,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PairingEnvelopeTbsV1 {
    pub envelope_kind: PairingEnvelopeKindV1,
    pub e2ee_format_version: u16,
    pub runtime_protocol_version: u16,
    pub relay_protocol_version: u16,
    pub relay_server_id: RelayServerId,
    pub pair_route: PairRouteId,
    #[serde(with = "b64_32")]
    #[schemars(with = "String")]
    pub invite_hash: [u8; 32],
    pub expiry_ms: u64,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "optional_b64_32"
    )]
    #[schemars(with = "Option<String>")]
    pub request_hash: Option<[u8; 32]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub machine_route: Option<MachineRouteId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_route: Option<DeviceRouteId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_serial: Option<GrantSerial>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_trust_epoch: Option<TrustEpoch>,
    #[serde(with = "b64_32")]
    #[schemars(with = "String")]
    pub signing_key_fingerprint: [u8; 32],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_key_generation: Option<LinkGeneration>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "optional_b64_32"
    )]
    #[schemars(with = "Option<String>")]
    pub signing_credential_sha256: Option<[u8; 32]>,
    #[serde(with = "b64_32")]
    #[schemars(with = "String")]
    pub info_sha256: [u8; 32],
    #[serde(with = "b64_32")]
    #[schemars(with = "String")]
    pub aad_sha256: [u8; 32],
    #[serde(with = "b64_vec")]
    #[schemars(with = "String")]
    pub enc: Vec<u8>,
    #[serde(with = "b64_32")]
    #[schemars(with = "String")]
    pub ciphertext_sha256: [u8; 32],
}

impl std::fmt::Debug for PairingEnvelopeTbsV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PairingEnvelopeTbsV1")
            .field("envelope_kind", &self.envelope_kind)
            .field("e2ee_format_version", &self.e2ee_format_version)
            .field("bound_material", &"<redacted>")
            .finish()
    }
}

impl PairingEnvelopeTbsV1 {
    pub fn for_request_parts(
        format_version: u16,
        enc: Vec<u8>,
        ciphertext: &[u8],
        info: &PairRequestInfoV1,
        context: &OuterContextV1,
        signing_key_fingerprint: [u8; 32],
    ) -> Result<Self, PairingError> {
        validate_request_context(info, context)?;
        let value = Self {
            envelope_kind: PairingEnvelopeKindV1::PairRequest,
            e2ee_format_version: format_version,
            runtime_protocol_version: info.runtime_protocol_version,
            relay_protocol_version: context.relay_protocol_version,
            relay_server_id: info.relay_server_id,
            pair_route: info.pair_route,
            invite_hash: info.invite_hash,
            expiry_ms: info.expiry_ms,
            request_hash: None,
            machine_route: None,
            device_route: None,
            grant_serial: None,
            root_trust_epoch: None,
            signing_key_fingerprint,
            signing_key_generation: None,
            signing_credential_sha256: None,
            info_sha256: sha256(&info.encode()),
            aad_sha256: sha256(&context.encode_aad()),
            enc,
            ciphertext_sha256: sha256(ciphertext),
        };
        value.validate()?;
        Ok(value)
    }

    fn for_request(
        envelope: &PairRequestV1,
        info: &PairRequestInfoV1,
        context: &OuterContextV1,
        signing_key_fingerprint: [u8; 32],
    ) -> Result<Self, PairingError> {
        Self::for_request_parts(
            envelope.format_version,
            envelope.enc.clone(),
            &envelope.ciphertext,
            info,
            context,
            signing_key_fingerprint,
        )
    }

    pub fn for_response_parts(
        format_version: u16,
        enc: Vec<u8>,
        ciphertext: &[u8],
        info: &PairResponseInfoV1,
        context: &OuterContextV1,
        signer: &MachineDataSignerBindingV1,
    ) -> Result<Self, PairingError> {
        validate_response_context(info, context)?;
        signer.validate()?;
        let value = Self {
            envelope_kind: PairingEnvelopeKindV1::PairResponse,
            e2ee_format_version: format_version,
            runtime_protocol_version: info.runtime_protocol_version,
            relay_protocol_version: context.relay_protocol_version,
            relay_server_id: info.relay_server_id,
            pair_route: info.pair_route,
            invite_hash: info.invite_hash,
            expiry_ms: info.expiry_ms,
            request_hash: Some(info.request_hash),
            machine_route: Some(info.machine_route),
            device_route: Some(info.device_route),
            grant_serial: Some(info.grant_serial),
            root_trust_epoch: Some(info.root_trust_epoch),
            signing_key_fingerprint: signer.signing_key_fingerprint,
            signing_key_generation: Some(signer.generation),
            signing_credential_sha256: Some(signer.certificate_sha256),
            info_sha256: sha256(&info.encode()),
            aad_sha256: sha256(&context.encode_aad()),
            enc,
            ciphertext_sha256: sha256(ciphertext),
        };
        value.validate()?;
        Ok(value)
    }

    fn for_response(
        envelope: &PairResponseV1,
        info: &PairResponseInfoV1,
        context: &OuterContextV1,
        signer: &MachineDataSignerBindingV1,
    ) -> Result<Self, PairingError> {
        envelope.ensure_info_matches(info)?;
        Self::for_response_parts(
            envelope.format_version,
            envelope.enc.clone(),
            &envelope.ciphertext,
            info,
            context,
            signer,
        )
    }

    pub fn validate(&self) -> Result<(), PairingError> {
        if self.e2ee_format_version != E2EE_FORMAT_VERSION
            || self.runtime_protocol_version != crate::runtime::RUNTIME_PROTOCOL_VERSION
            || self.relay_protocol_version != RELAY_PROTOCOL_VERSION
            || is_zero(self.relay_server_id.as_bytes())
            || is_zero(self.pair_route.as_bytes())
            || is_zero(&self.invite_hash)
            || self.expiry_ms == 0
            || is_zero(&self.signing_key_fingerprint)
            || is_zero(&self.info_sha256)
            || is_zero(&self.aad_sha256)
            || self.enc.len() != PAIRING_HPKE_ENC_BYTES
            || is_zero(&self.enc)
            || is_zero(&self.ciphertext_sha256)
        {
            return Err(PairingError::InvalidField("pairing envelope TBS"));
        }
        match self.envelope_kind {
            PairingEnvelopeKindV1::PairRequest => {
                if self.request_hash.is_some()
                    || self.machine_route.is_some()
                    || self.device_route.is_some()
                    || self.grant_serial.is_some()
                    || self.root_trust_epoch.is_some()
                    || self.signing_key_generation.is_some()
                    || self.signing_credential_sha256.is_some()
                {
                    return Err(PairingError::InvalidField("PairRequest TBS shape"));
                }
            }
            PairingEnvelopeKindV1::PairResponse => {
                if self.request_hash.is_none_or(|value| is_zero(&value))
                    || self
                        .machine_route
                        .is_none_or(|value| is_zero(value.as_bytes()))
                    || self
                        .device_route
                        .is_none_or(|value| is_zero(value.as_bytes()))
                    || self.grant_serial.is_none_or(|value| value.value() == 0)
                    || self.root_trust_epoch.is_none_or(|value| value.value() == 0)
                    || self
                        .signing_key_generation
                        .is_none_or(|value| value.value() == 0)
                    || self
                        .signing_credential_sha256
                        .is_none_or(|value| is_zero(&value))
                {
                    return Err(PairingError::InvalidField("PairResponse TBS shape"));
                }
            }
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, PairingError> {
        self.validate()?;
        let mut encoder = Enc::new();
        encoder.domain(b"AgentDeck/PairingEnvelopeTbsV1\0");
        encoder.u8(self.envelope_kind.tag());
        encoder.u16(self.e2ee_format_version);
        encoder.u16(self.runtime_protocol_version);
        encoder.u16(self.relay_protocol_version);
        encoder.bytes(self.relay_server_id.as_bytes());
        encoder.bytes(self.pair_route.as_bytes());
        encoder.bytes(&self.invite_hash);
        encoder.u64(self.expiry_ms);
        encode_optional_hash(&mut encoder, self.request_hash.as_ref());
        encoder.opt_id16(self.machine_route.as_ref().map(|value| value.as_bytes()));
        encoder.opt_id16(self.device_route.as_ref().map(|value| value.as_bytes()));
        encoder.opt_u64(self.grant_serial.map(|value| value.value()));
        encoder.opt_u64(self.root_trust_epoch.map(|value| value.value()));
        encoder.bytes(&self.signing_key_fingerprint);
        encoder.opt_u64(self.signing_key_generation.map(|value| value.value()));
        encode_optional_hash(&mut encoder, self.signing_credential_sha256.as_ref());
        encoder.bytes(&self.info_sha256);
        encoder.bytes(&self.aad_sha256);
        encoder.bytes(&self.enc);
        encoder.bytes(&self.ciphertext_sha256);
        Ok(encoder.finish())
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
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

impl std::fmt::Debug for PairRequestInfoV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PairRequestInfoV1")
            .field("e2ee_format_version", &self.e2ee_format_version)
            .field("runtime_protocol_version", &self.runtime_protocol_version)
            .field("binding", &"<redacted>")
            .finish()
    }
}

impl PairRequestInfoV1 {
    pub fn encode(&self) -> Vec<u8> {
        let mut encoder = Enc::new();
        encoder.domain(b"AgentDeck/PairRequestInfoV1\0");
        encoder.u16(self.e2ee_format_version);
        encoder.u16(self.runtime_protocol_version);
        encoder.bytes(self.relay_server_id.as_bytes());
        encoder.bytes(self.pair_route.as_bytes());
        encoder.bytes(&self.invite_hash);
        encoder.u64(self.expiry_ms);
        encoder.finish()
    }
}

fn validate_request_context(
    info: &PairRequestInfoV1,
    context: &OuterContextV1,
) -> Result<(), PairingError> {
    context
        .validate()
        .map_err(|_| PairingError::ContextBindingMismatch)?;
    if context.frame_kind != OuterFrameKind::PairRequest
        || context.pair_route != Some(info.pair_route)
        || context.e2ee_format_version != info.e2ee_format_version
        || info.e2ee_format_version != E2EE_FORMAT_VERSION
        || context.relay_protocol_version != RELAY_PROTOCOL_VERSION
        || is_zero(&info.invite_hash)
        || info.expiry_ms == 0
    {
        return Err(PairingError::ContextBindingMismatch);
    }
    Ok(())
}

fn validate_response_context(
    info: &PairResponseInfoV1,
    context: &OuterContextV1,
) -> Result<(), PairingError> {
    info.validate()
        .map_err(|_| PairingError::ContextBindingMismatch)?;
    context
        .validate()
        .map_err(|_| PairingError::ContextBindingMismatch)?;
    if context.frame_kind != OuterFrameKind::PairResponse
        || context.pair_route != Some(info.pair_route)
        || context.e2ee_format_version != info.e2ee_format_version
        || info.e2ee_format_version != E2EE_FORMAT_VERSION
        || context.relay_protocol_version != RELAY_PROTOCOL_VERSION
        || is_zero(&info.invite_hash)
        || info.expiry_ms == 0
        || is_zero(&info.request_hash)
        || is_zero(info.machine_route.as_bytes())
        || is_zero(info.device_route.as_bytes())
        || info.grant_serial.value() == 0
        || info.root_trust_epoch.value() == 0
    {
        return Err(PairingError::ContextBindingMismatch);
    }
    Ok(())
}

fn validate_envelope(
    format_version: u16,
    enc: &[u8],
    ciphertext: &[u8],
    signature: &Ed25519Signature,
) -> Result<(), PairingError> {
    if format_version != E2EE_FORMAT_VERSION {
        return Err(PairingError::UnsupportedVersion);
    }
    if enc.len() != PAIRING_HPKE_ENC_BYTES || is_zero(enc) {
        return Err(PairingError::InvalidField("HPKE enc"));
    }
    if ciphertext.is_empty() || ciphertext.len() > PAIRING_MAX_CIPHERTEXT_BYTES {
        return Err(PairingError::SizeLimit("pairing ciphertext"));
    }
    if is_zero(&signature.0) {
        return Err(PairingError::InvalidField("detached signature"));
    }
    Ok(())
}

fn encode_unsigned_envelope(
    kind: PairingEnvelopeKindV1,
    format_version: u16,
    response_info: Option<&PairResponseInfoV1>,
    enc: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, PairingError> {
    let mut encoder = Enc::new();
    match kind {
        PairingEnvelopeKindV1::PairRequest => {
            if response_info.is_some() {
                return Err(PairingError::InvalidEncoding("PairRequest embedded info"));
            }
            encoder.domain(b"AgentDeck/PairRequestUnsignedV1\0");
        }
        PairingEnvelopeKindV1::PairResponse => {
            let info =
                response_info.ok_or(PairingError::InvalidEncoding("PairResponse embedded info"))?;
            info.validate()?;
            encoder.domain(b"AgentDeck/PairResponseUnsignedV1\0");
        }
    }
    encoder.u16(format_version);
    if let Some(info) = response_info {
        encoder.bytes(&info.encode());
    }
    encoder.bytes(enc);
    encoder.bytes(ciphertext);
    Ok(encoder.finish())
}

fn encode_signed_envelope(
    kind: PairingEnvelopeKindV1,
    unsigned: &[u8],
    signature: &Ed25519Signature,
) -> Vec<u8> {
    let mut encoder = Enc::new();
    match kind {
        PairingEnvelopeKindV1::PairRequest => encoder.domain(b"AgentDeck/PairRequestV1\0"),
        PairingEnvelopeKindV1::PairResponse => encoder.domain(b"AgentDeck/PairResponseV1\0"),
    }
    encoder.bytes(unsigned);
    encoder.bytes(&signature.0);
    encoder.finish()
}

struct DecodedSignedEnvelope {
    format_version: u16,
    response_info: Option<PairResponseInfoV1>,
    enc: Vec<u8>,
    ciphertext: Vec<u8>,
    signature: Ed25519Signature,
}

fn decode_signed_envelope(
    bytes: &[u8],
    kind: PairingEnvelopeKindV1,
) -> Result<DecodedSignedEnvelope, PairingError> {
    if bytes.len() > PAIRING_MAX_CIPHERTEXT_BYTES + 2 * MAX_PAIR_RESPONSE_INFO_CANONICAL_BYTES {
        return Err(PairingError::SizeLimit("pairing envelope"));
    }
    let mut outer = Decoder::new(bytes);
    match kind {
        PairingEnvelopeKindV1::PairRequest => outer.domain(b"AgentDeck/PairRequestV1\0")?,
        PairingEnvelopeKindV1::PairResponse => outer.domain(b"AgentDeck/PairResponseV1\0")?,
    }
    let unsigned =
        outer.bytes(PAIRING_MAX_CIPHERTEXT_BYTES + MAX_PAIR_RESPONSE_INFO_CANONICAL_BYTES + 128)?;
    let signature = Ed25519Signature(outer.fixed()?);
    outer.finish()?;
    let mut decoder = Decoder::new(unsigned);
    match kind {
        PairingEnvelopeKindV1::PairRequest => {
            decoder.domain(b"AgentDeck/PairRequestUnsignedV1\0")?;
        }
        PairingEnvelopeKindV1::PairResponse => {
            decoder.domain(b"AgentDeck/PairResponseUnsignedV1\0")?;
        }
    }
    let format_version = decoder.u16()?;
    let response_info = match kind {
        PairingEnvelopeKindV1::PairRequest => None,
        PairingEnvelopeKindV1::PairResponse => Some(PairResponseInfoV1::from_canonical_bytes(
            decoder.bytes(MAX_PAIR_RESPONSE_INFO_CANONICAL_BYTES)?,
        )?),
    };
    let enc = decoder.bytes(PAIRING_HPKE_ENC_BYTES)?.to_vec();
    let ciphertext = decoder.bytes(PAIRING_MAX_CIPHERTEXT_BYTES)?.to_vec();
    decoder.finish()?;
    Ok(DecodedSignedEnvelope {
        format_version,
        response_info,
        enc,
        ciphertext,
        signature,
    })
}

fn encode_device_authorization_fields(encoder: &mut Enc, value: &DeviceAuthorizationV1) {
    encoder.u16(value.format_version);
    encoder.bytes(&value.grant_hash);
    encoder.bytes(value.machine_route.as_bytes());
    encoder.bytes(value.device_route.as_bytes());
    encoder.bytes(&value.device_sign_fingerprint);
    encoder.u64(value.grant_serial.value());
    encoder.bytes(&value.device_hpke_pubkey.0);
    encoder.u8(value.capabilities.len() as u8);
    for capability in &value.capabilities {
        encoder.u8(capability.tag());
    }
    encoder.u8(value.permissions.len() as u8);
    for permission in &value.permissions {
        encoder.u8(permission.tag());
    }
    encoder.bytes(value.root_key_id.as_bytes());
    encoder.u64(value.trust_epoch.value());
}

fn decode_relay_grant(bytes: &[u8]) -> Result<RelayGrant, PairingError> {
    let mut outer = Decoder::new(bytes);
    outer.domain(b"AgentDeck/RelayGrantV1\0")?;
    let unsigned = outer.bytes(1_024)?;
    let signature = Ed25519Signature(outer.fixed()?);
    outer.finish()?;
    let mut decoder = Decoder::new(unsigned);
    decoder.domain(b"AgentDeck/RelayGrantUnsignedV1\0")?;
    let value = RelayGrant {
        machine_route: MachineRouteId::from_bytes(decoder.fixed()?),
        device_route: DeviceRouteId::from_bytes(decoder.fixed()?),
        device_sign_pubkey: PublicKeyBytes(decoder.fixed()?),
        grant_serial: GrantSerial::new(decoder.u64()?),
        root_key_id: RootKeyId::from_bytes(decoder.fixed()?),
        trust_epoch: TrustEpoch::new(decoder.u64()?),
        signature,
    };
    decoder.finish()?;
    ensure_canonical(bytes, &value.canonical_bytes())?;
    Ok(value)
}

fn decode_signed_certificate(bytes: &[u8]) -> Result<SignedCertificate, PairingError> {
    let mut outer = Decoder::new(bytes);
    outer.domain(b"AgentDeck/SignedCertificateV1\0")?;
    let unsigned = outer.bytes(1_024)?;
    let signature = Ed25519Signature(outer.fixed()?);
    outer.finish()?;
    let mut decoder = Decoder::new(unsigned);
    decoder.domain(b"AgentDeck/SignedCertificateUnsignedV1\0")?;
    let subject_pubkey = PublicKeyBytes(decoder.fixed()?);
    let cert_role = match decoder.u8()? {
        0 => CertRole::Link,
        1 => CertRole::Data,
        _ => return Err(PairingError::InvalidEncoding("certificate role")),
    };
    let generation = LinkGeneration::new(decoder.u64()?);
    let root_key_id = RootKeyId::from_bytes(decoder.fixed()?);
    let trust_epoch = TrustEpoch::new(decoder.u64()?);
    let not_after_ms = decoder.optional_u64()?;
    decoder.finish()?;
    let value = SignedCertificate {
        subject_pubkey,
        cert_role,
        generation,
        root_key_id,
        trust_epoch,
        not_after_ms,
        signature,
    };
    ensure_canonical(bytes, &value.canonical_bytes())?;
    Ok(value)
}

fn ensure_canonical(input: &[u8], reencoded: &[u8]) -> Result<(), PairingError> {
    if input != reencoded {
        return Err(PairingError::InvalidEncoding("non-canonical bytes"));
    }
    Ok(())
}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], PairingError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(PairingError::InvalidEncoding("offset overflow"))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(PairingError::InvalidEncoding("truncated bytes"))?;
        self.offset = end;
        Ok(value)
    }

    fn domain(&mut self, expected: &[u8]) -> Result<(), PairingError> {
        if self.take(expected.len())? != expected {
            return Err(PairingError::InvalidEncoding("domain separator"));
        }
        Ok(())
    }

    fn u8(&mut self) -> Result<u8, PairingError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, PairingError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().expect("fixed")))
    }

    fn u32(&mut self) -> Result<u32, PairingError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().expect("fixed")))
    }

    fn u64(&mut self) -> Result<u64, PairingError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().expect("fixed")))
    }

    fn bytes(&mut self, maximum: usize) -> Result<&'a [u8], PairingError> {
        let length = self.u32()? as usize;
        if length > maximum {
            return Err(PairingError::SizeLimit("canonical byte field"));
        }
        self.take(length)
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], PairingError> {
        self.bytes(N)?
            .try_into()
            .map_err(|_| PairingError::InvalidEncoding("fixed-size field"))
    }

    fn string(&mut self, maximum: usize) -> Result<String, PairingError> {
        let value = self.bytes(maximum)?;
        std::str::from_utf8(value)
            .map(str::to_owned)
            .map_err(|_| PairingError::InvalidEncoding("UTF-8 string"))
    }

    fn optional_u64(&mut self) -> Result<Option<u64>, PairingError> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.u64()?)),
            _ => Err(PairingError::InvalidEncoding("optional u64")),
        }
    }

    fn finish(self) -> Result<(), PairingError> {
        if self.offset != self.bytes.len() {
            return Err(PairingError::InvalidEncoding("trailing bytes"));
        }
        Ok(())
    }
}
