//! Relay admin portable receipt contract。
//!
//! MachineRoot 丢失时，daemon 不能签 `RetireMachine`，也不能把 Relay 主机上的
//! same-UID admin JSON 当作跨主机授权证据。本模块冻结一个由 Relay 专用 Ed25519
//! receipt key 签发的 portable purge proof。该 key 与 TLS identity、MachineRoot
//! `ToBeSignedV1` 完全分域；MVP 只接受 generation 1，同一 `RelayServerId` 不原地轮换。

use crate::e2ee::Enc;
use crate::relay_v2::RELAY_PROTOCOL_VERSION;
use crate::relay_v2::auth::{Ed25519Signature, PublicKeyBytes};
use crate::relay_v2::id::{MachineRouteId, RelayServerId, RootKeyId, TrustEpoch, b64_32};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Portable Relay receipt wire/canonical 格式版本。
pub const RELAY_RECEIPT_FORMAT_VERSION: u16 = 1;

/// MVP 唯一允许的 receipt signer generation。同一 RelayServerId 不允许原地轮换。
pub const RELAY_RECEIPT_KEY_GENERATION_MVP: u64 = 1;

/// Portable purge proof 形状或外部 verify-key binding 不合法。
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RelayAdminPurgeReceiptError {
    #[error("unsupported Relay receipt format version")]
    UnsupportedReceiptFormatVersion,
    #[error("unsupported Relay protocol version in purge receipt")]
    UnsupportedRelayProtocolVersion,
    #[error("unsupported Relay receipt key generation")]
    UnsupportedReceiptKeyGeneration,
    #[error("Relay receipt key ID does not match the dedicated public-key derivation")]
    ReceiptKeyIdMismatch,
    #[error("Relay admin purge receipt required field is all-zero: {0}")]
    ZeroBoundField(&'static str),
    #[error("root-lost admin purge readback is not exact 0/1/0 or carries retirement material")]
    InvalidRootLostPurgeReadback,
    #[error("purge receipt does not match the provisioned Relay receipt verify key")]
    ReceiptVerifyKeyBindingMismatch,
    #[error("purge receipt does not match the caller's typed expected locator binding")]
    ExpectedBindingMismatch,
    #[error("purge request hash does not match its canonical route/root-fingerprint input")]
    PurgeRequestHashMismatch,
    #[error("admin purge tombstone hash does not match its canonical typed input")]
    TombstoneHashMismatch,
}

/// Relay receipt key ID 是完整 32-byte digest，不是随机 route ID：
/// `SHA256("AgentDeck/RelayReceiptKeyIdV1\0" || publicKey)`。
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
pub struct RelayReceiptKeyId(
    #[serde(with = "b64_32")]
    #[schemars(with = "String")]
    pub [u8; 32],
);

impl RelayReceiptKeyId {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn from_public_key(public_key: &PublicKeyBytes) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"AgentDeck/RelayReceiptKeyIdV1\0");
        hasher.update(public_key.0);
        Self(hasher.finalize().into())
    }

    pub fn redacted(&self) -> String {
        self.0[..4]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }
}

impl std::fmt::Debug for RelayReceiptKeyId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RelayReceiptKeyId(<redacted>)")
    }
}

/// Enrollment 必须在 TLS CA/SPKI 校验完成后持久化的 Relay receipt trust anchor。
///
/// `key_id` 与 public key 一起 pin；后续 receipt 必须同时匹配 RelayServerId、generation
/// 和 key ID。MVP 固定 generation 1，若需要轮换必须更换 RelayServerId/重新 enrollment。
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RelayReceiptVerifyKeyV1 {
    pub receipt_format_version: u16,
    pub relay_server_id: RelayServerId,
    pub key_generation: u64,
    pub key_id: RelayReceiptKeyId,
    pub public_key: PublicKeyBytes,
}

impl std::fmt::Debug for RelayReceiptVerifyKeyV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RelayReceiptVerifyKeyV1")
            .field("receipt_format_version", &self.receipt_format_version)
            .field("relay_server_id", &self.relay_server_id.redacted())
            .field("key_generation", &self.key_generation)
            .field("key_id", &self.key_id.redacted())
            .field("public_key", &"<redacted>")
            .finish()
    }
}

impl RelayReceiptVerifyKeyV1 {
    pub fn validate(&self) -> Result<(), RelayAdminPurgeReceiptError> {
        if self.receipt_format_version != RELAY_RECEIPT_FORMAT_VERSION {
            return Err(RelayAdminPurgeReceiptError::UnsupportedReceiptFormatVersion);
        }
        if self.key_generation != RELAY_RECEIPT_KEY_GENERATION_MVP {
            return Err(RelayAdminPurgeReceiptError::UnsupportedReceiptKeyGeneration);
        }
        require_nonzero(self.relay_server_id.as_bytes(), "relayServerId")?;
        require_nonzero(&self.public_key.0, "receiptPublicKey")?;
        require_nonzero(self.key_id.as_bytes(), "receiptKeyId")?;
        if self.key_id != RelayReceiptKeyId::from_public_key(&self.public_key) {
            return Err(RelayAdminPurgeReceiptError::ReceiptKeyIdMismatch);
        }
        Ok(())
    }

    /// 与 enrollment JSON 独立的 trust-anchor canonical bytes。
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, RelayAdminPurgeReceiptError> {
        self.validate()?;
        let mut encoder = Enc::new();
        encoder.domain(b"AgentDeck/RelayReceiptVerifyKeyV1\0");
        encoder.u16(self.receipt_format_version);
        encoder.bytes(self.relay_server_id.as_bytes());
        encoder.u64(self.key_generation);
        encoder.bytes(self.key_id.as_bytes());
        encoder.bytes(&self.public_key.0);
        Ok(encoder.finish())
    }

    pub fn canonical_sha256(&self) -> Result<[u8; 32], RelayAdminPurgeReceiptError> {
        Ok(Sha256::digest(self.canonical_bytes()?).into())
    }
}

/// portable proof 中可签名的 tombstone 类型。MVP 只有 root-lost admin purge；
/// root-present retirement 继续使用 MachineRoot-signed `RetireMachine` terminal。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum RelayMachineTombstoneKindV1 {
    RootLostAdminPurge,
}

impl RelayMachineTombstoneKindV1 {
    const fn canonical_tag(self) -> u8 {
        match self {
            Self::RootLostAdminPurge => 0,
        }
    }
}

/// Relay purge transaction 后的精确 root-lost readback。
///
/// 唯一有效形状为 active machine routes 0、retired tombstones 1、其余 durable
/// route/data counts 0，且没有 MachineRoot retirement hash/terminal。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RelayAdminPurgeReadbackV1 {
    pub active_machine_routes: u64,
    pub retired_tombstones: u64,
    pub consumed_enrollment_records: u64,
    pub device_grants: u64,
    pub revocations: u64,
    pub streams: u64,
    pub frames: u64,
    pub subscriptions: u64,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "optional_b64_32"
    )]
    #[schemars(with = "Option<String>")]
    pub retirement_hash: Option<[u8; 32]>,
    pub retirement_terminal_present: bool,
}

impl RelayAdminPurgeReadbackV1 {
    pub fn validate_root_lost(&self) -> Result<(), RelayAdminPurgeReceiptError> {
        if self.active_machine_routes == 0
            && self.retired_tombstones == 1
            && self.consumed_enrollment_records == 0
            && self.device_grants == 0
            && self.revocations == 0
            && self.streams == 0
            && self.frames == 0
            && self.subscriptions == 0
            && self.retirement_hash.is_none()
            && !self.retirement_terminal_present
        {
            Ok(())
        } else {
            Err(RelayAdminPurgeReceiptError::InvalidRootLostPurgeReadback)
        }
    }

    fn encode_into(&self, encoder: &mut Enc) {
        encoder.u64(self.active_machine_routes);
        encoder.u64(self.retired_tombstones);
        encoder.u64(self.consumed_enrollment_records);
        encoder.u64(self.device_grants);
        encoder.u64(self.revocations);
        encoder.u64(self.streams);
        encoder.u64(self.frames);
        encoder.u64(self.subscriptions);
        match self.retirement_hash {
            Some(hash) => {
                encoder.u8(1);
                encoder.bytes(&hash);
            }
            None => encoder.u8(0),
        }
        encoder.u8(u8::from(self.retirement_terminal_present));
    }
}

/// machine admin purge request 的唯一 canonical hash。
///
/// 只接受 typed machine route 与 expected root fingerprint；两者都必须非零。
pub fn purge_request_hash(
    machine_route: MachineRouteId,
    expected_root_fingerprint: [u8; 32],
) -> Result<[u8; 32], RelayAdminPurgeReceiptError> {
    require_nonzero(machine_route.as_bytes(), "purgeRequest.machineRoute")?;
    require_nonzero(
        &expected_root_fingerprint,
        "purgeRequest.expectedRootFingerprint",
    )?;
    let mut encoder = Enc::new();
    encoder.domain(b"AgentDeck/RelayAdminPurgeRequestV1\0");
    encoder.bytes(machine_route.as_bytes());
    encoder.bytes(&expected_root_fingerprint);
    Ok(Sha256::digest(encoder.finish()).into())
}

/// Relay terminal transaction 留下的最小 admin-purge tombstone canonical 输入。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayAdminPurgeTombstoneV1 {
    pub relay_server_id: RelayServerId,
    pub machine_route: MachineRouteId,
    pub root_key_id: RootKeyId,
    pub root_fingerprint: [u8; 32],
    pub trust_epoch: TrustEpoch,
    pub enrollment_receipt_hash: [u8; 32],
    pub purge_request_hash: [u8; 32],
    pub tombstone_kind: RelayMachineTombstoneKindV1,
    pub readback: RelayAdminPurgeReadbackV1,
}

impl RelayAdminPurgeTombstoneV1 {
    pub fn validate(&self) -> Result<(), RelayAdminPurgeReceiptError> {
        require_nonzero(self.relay_server_id.as_bytes(), "tombstone.relayServerId")?;
        require_nonzero(self.machine_route.as_bytes(), "tombstone.machineRoute")?;
        require_nonzero(self.root_key_id.as_bytes(), "tombstone.rootKeyId")?;
        require_nonzero(&self.root_fingerprint, "tombstone.rootFingerprint")?;
        if self.trust_epoch.value() == 0 {
            return Err(RelayAdminPurgeReceiptError::ZeroBoundField(
                "tombstone.trustEpoch",
            ));
        }
        require_nonzero(
            &self.enrollment_receipt_hash,
            "tombstone.enrollmentReceiptHash",
        )?;
        require_nonzero(&self.purge_request_hash, "tombstone.purgeRequestHash")?;
        if self.purge_request_hash != purge_request_hash(self.machine_route, self.root_fingerprint)?
        {
            return Err(RelayAdminPurgeReceiptError::PurgeRequestHashMismatch);
        }
        self.readback.validate_root_lost()
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, RelayAdminPurgeReceiptError> {
        self.validate()?;
        let mut encoder = Enc::new();
        encoder.domain(b"AgentDeck/RelayAdminPurgeTombstoneV1\0");
        encoder.u16(RELAY_RECEIPT_FORMAT_VERSION);
        encoder.u16(RELAY_PROTOCOL_VERSION);
        encoder.bytes(self.relay_server_id.as_bytes());
        encoder.bytes(self.machine_route.as_bytes());
        encoder.bytes(self.root_key_id.as_bytes());
        encoder.bytes(&self.root_fingerprint);
        encoder.u64(self.trust_epoch.value());
        encoder.bytes(&self.enrollment_receipt_hash);
        encoder.bytes(&self.purge_request_hash);
        encoder.u8(self.tombstone_kind.canonical_tag());
        self.readback.encode_into(&mut encoder);
        Ok(encoder.finish())
    }
}

/// 计算 Relay admin-purge tombstone 的唯一 canonical SHA-256。
pub fn admin_purge_tombstone_hash(
    tombstone: &RelayAdminPurgeTombstoneV1,
) -> Result<[u8; 32], RelayAdminPurgeReceiptError> {
    Ok(Sha256::digest(tombstone.canonical_bytes()?).into())
}

/// Relay 专用 receipt signer 的 canonical purge proof preimage。
///
/// 该类型有独立 domain，故意不实现/复用 MachineRoot `ToBeSignedV1`。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RelayAdminPurgeReceiptTbsV1 {
    pub receipt_format_version: u16,
    pub relay_protocol_version: u16,
    pub relay_server_id: RelayServerId,
    pub receipt_key_generation: u64,
    pub receipt_key_id: RelayReceiptKeyId,
    pub machine_route: MachineRouteId,
    pub root_key_id: RootKeyId,
    #[serde(with = "b64_32")]
    #[schemars(with = "String")]
    pub root_fingerprint: [u8; 32],
    pub trust_epoch: TrustEpoch,
    #[serde(with = "b64_32")]
    #[schemars(with = "String")]
    pub enrollment_receipt_hash: [u8; 32],
    #[serde(with = "b64_32")]
    #[schemars(with = "String")]
    pub purge_request_hash: [u8; 32],
    pub tombstone_kind: RelayMachineTombstoneKindV1,
    pub readback: RelayAdminPurgeReadbackV1,
    #[serde(with = "b64_32")]
    #[schemars(with = "String")]
    pub tombstone_hash: [u8; 32],
}

impl RelayAdminPurgeReceiptTbsV1 {
    pub fn validate(&self) -> Result<(), RelayAdminPurgeReceiptError> {
        if self.receipt_format_version != RELAY_RECEIPT_FORMAT_VERSION {
            return Err(RelayAdminPurgeReceiptError::UnsupportedReceiptFormatVersion);
        }
        if self.relay_protocol_version != RELAY_PROTOCOL_VERSION {
            return Err(RelayAdminPurgeReceiptError::UnsupportedRelayProtocolVersion);
        }
        if self.receipt_key_generation != RELAY_RECEIPT_KEY_GENERATION_MVP {
            return Err(RelayAdminPurgeReceiptError::UnsupportedReceiptKeyGeneration);
        }
        require_nonzero(self.relay_server_id.as_bytes(), "relayServerId")?;
        require_nonzero(self.receipt_key_id.as_bytes(), "receiptKeyId")?;
        require_nonzero(self.machine_route.as_bytes(), "machineRoute")?;
        require_nonzero(self.root_key_id.as_bytes(), "rootKeyId")?;
        require_nonzero(&self.root_fingerprint, "rootFingerprint")?;
        if self.trust_epoch.value() == 0 {
            return Err(RelayAdminPurgeReceiptError::ZeroBoundField("trustEpoch"));
        }
        require_nonzero(&self.enrollment_receipt_hash, "enrollmentReceiptHash")?;
        require_nonzero(&self.purge_request_hash, "purgeRequestHash")?;
        require_nonzero(&self.tombstone_hash, "tombstoneHash")?;
        self.readback.validate_root_lost()?;
        if self.purge_request_hash != purge_request_hash(self.machine_route, self.root_fingerprint)?
        {
            return Err(RelayAdminPurgeReceiptError::PurgeRequestHashMismatch);
        }
        let tombstone = RelayAdminPurgeTombstoneV1 {
            relay_server_id: self.relay_server_id,
            machine_route: self.machine_route,
            root_key_id: self.root_key_id,
            root_fingerprint: self.root_fingerprint,
            trust_epoch: self.trust_epoch,
            enrollment_receipt_hash: self.enrollment_receipt_hash,
            purge_request_hash: self.purge_request_hash,
            tombstone_kind: self.tombstone_kind,
            readback: self.readback.clone(),
        };
        if self.tombstone_hash != admin_purge_tombstone_hash(&tombstone)? {
            return Err(RelayAdminPurgeReceiptError::TombstoneHashMismatch);
        }
        Ok(())
    }

    /// 确定性、长度前缀的 Ed25519 preimage。
    pub fn encode(&self) -> Result<Vec<u8>, RelayAdminPurgeReceiptError> {
        self.validate()?;
        Ok(self.encode_unchecked())
    }

    fn encode_unchecked(&self) -> Vec<u8> {
        let mut encoder = Enc::new();
        encoder.domain(b"AgentDeck/RelayAdminPurgeReceiptTbsV1\0");
        encoder.u16(self.receipt_format_version);
        encoder.u16(self.relay_protocol_version);
        encoder.bytes(self.relay_server_id.as_bytes());
        encoder.u64(self.receipt_key_generation);
        encoder.bytes(self.receipt_key_id.as_bytes());
        encoder.bytes(self.machine_route.as_bytes());
        encoder.bytes(self.root_key_id.as_bytes());
        encoder.bytes(&self.root_fingerprint);
        encoder.u64(self.trust_epoch.value());
        encoder.bytes(&self.enrollment_receipt_hash);
        encoder.bytes(&self.purge_request_hash);
        encoder.u8(self.tombstone_kind.canonical_tag());
        self.readback.encode_into(&mut encoder);
        encoder.bytes(&self.tombstone_hash);
        encoder.finish()
    }

    pub fn canonical_sha256(&self) -> Result<[u8; 32], RelayAdminPurgeReceiptError> {
        Ok(Sha256::digest(self.encode()?).into())
    }
}

/// daemon 验证 portable proof 时必须提供的本地 authenticated locator expectation。
///
/// API 强制在验签同一处比较这些字段，不能把 route/root/hash 检查散落给调用方。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayAdminPurgeReceiptExpectationV1 {
    pub relay_server_id: RelayServerId,
    pub machine_route: MachineRouteId,
    pub root_key_id: RootKeyId,
    pub root_fingerprint: [u8; 32],
    pub trust_epoch: TrustEpoch,
    pub enrollment_receipt_hash: [u8; 32],
    pub purge_request_hash: [u8; 32],
}

impl RelayAdminPurgeReceiptExpectationV1 {
    pub fn validate(&self) -> Result<(), RelayAdminPurgeReceiptError> {
        require_nonzero(self.relay_server_id.as_bytes(), "expected.relayServerId")?;
        require_nonzero(self.machine_route.as_bytes(), "expected.machineRoute")?;
        require_nonzero(self.root_key_id.as_bytes(), "expected.rootKeyId")?;
        require_nonzero(&self.root_fingerprint, "expected.rootFingerprint")?;
        if self.trust_epoch.value() == 0 {
            return Err(RelayAdminPurgeReceiptError::ZeroBoundField(
                "expected.trustEpoch",
            ));
        }
        require_nonzero(
            &self.enrollment_receipt_hash,
            "expected.enrollmentReceiptHash",
        )?;
        require_nonzero(&self.purge_request_hash, "expected.purgeRequestHash")?;
        if self.purge_request_hash != purge_request_hash(self.machine_route, self.root_fingerprint)?
        {
            return Err(RelayAdminPurgeReceiptError::PurgeRequestHashMismatch);
        }
        Ok(())
    }

    pub fn matches(&self, receipt: &RelayAdminPurgeReceiptV1) -> bool {
        self.relay_server_id == receipt.relay_server_id
            && self.machine_route == receipt.machine_route
            && self.root_key_id == receipt.root_key_id
            && self.root_fingerprint == receipt.root_fingerprint
            && self.trust_epoch == receipt.trust_epoch
            && self.enrollment_receipt_hash == receipt.enrollment_receipt_hash
            && self.purge_request_hash == receipt.purge_request_hash
    }
}

/// Relay receipt signer 输出的 portable root-lost purge proof。
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RelayAdminPurgeReceiptV1 {
    pub receipt_format_version: u16,
    pub relay_protocol_version: u16,
    pub relay_server_id: RelayServerId,
    pub receipt_key_generation: u64,
    pub receipt_key_id: RelayReceiptKeyId,
    pub machine_route: MachineRouteId,
    pub root_key_id: RootKeyId,
    #[serde(with = "b64_32")]
    #[schemars(with = "String")]
    pub root_fingerprint: [u8; 32],
    pub trust_epoch: TrustEpoch,
    #[serde(with = "b64_32")]
    #[schemars(with = "String")]
    pub enrollment_receipt_hash: [u8; 32],
    #[serde(with = "b64_32")]
    #[schemars(with = "String")]
    pub purge_request_hash: [u8; 32],
    pub tombstone_kind: RelayMachineTombstoneKindV1,
    pub readback: RelayAdminPurgeReadbackV1,
    #[serde(with = "b64_32")]
    #[schemars(with = "String")]
    pub tombstone_hash: [u8; 32],
    pub signature: Ed25519Signature,
}

impl std::fmt::Debug for RelayAdminPurgeReceiptV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RelayAdminPurgeReceiptV1")
            .field("relay_server_id", &self.relay_server_id.redacted())
            .field("receipt_key_generation", &self.receipt_key_generation)
            .field("receipt_key_id", &self.receipt_key_id.redacted())
            .field("machine_route", &self.machine_route.redacted())
            .field("trust_epoch", &self.trust_epoch.value())
            .field("proof_material", &"<redacted>")
            .finish()
    }
}

impl RelayAdminPurgeReceiptV1 {
    pub fn from_tbs(
        tbs: RelayAdminPurgeReceiptTbsV1,
        signature: Ed25519Signature,
    ) -> Result<Self, RelayAdminPurgeReceiptError> {
        tbs.validate()?;
        Ok(Self {
            receipt_format_version: tbs.receipt_format_version,
            relay_protocol_version: tbs.relay_protocol_version,
            relay_server_id: tbs.relay_server_id,
            receipt_key_generation: tbs.receipt_key_generation,
            receipt_key_id: tbs.receipt_key_id,
            machine_route: tbs.machine_route,
            root_key_id: tbs.root_key_id,
            root_fingerprint: tbs.root_fingerprint,
            trust_epoch: tbs.trust_epoch,
            enrollment_receipt_hash: tbs.enrollment_receipt_hash,
            purge_request_hash: tbs.purge_request_hash,
            tombstone_kind: tbs.tombstone_kind,
            readback: tbs.readback,
            tombstone_hash: tbs.tombstone_hash,
            signature,
        })
    }

    pub fn to_be_signed(&self) -> RelayAdminPurgeReceiptTbsV1 {
        RelayAdminPurgeReceiptTbsV1 {
            receipt_format_version: self.receipt_format_version,
            relay_protocol_version: self.relay_protocol_version,
            relay_server_id: self.relay_server_id,
            receipt_key_generation: self.receipt_key_generation,
            receipt_key_id: self.receipt_key_id,
            machine_route: self.machine_route,
            root_key_id: self.root_key_id,
            root_fingerprint: self.root_fingerprint,
            trust_epoch: self.trust_epoch,
            enrollment_receipt_hash: self.enrollment_receipt_hash,
            purge_request_hash: self.purge_request_hash,
            tombstone_kind: self.tombstone_kind,
            readback: self.readback.clone(),
            tombstone_hash: self.tombstone_hash,
        }
    }

    pub fn validate(&self) -> Result<(), RelayAdminPurgeReceiptError> {
        self.to_be_signed().validate()
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, RelayAdminPurgeReceiptError> {
        let tbs = self.to_be_signed().encode()?;
        let mut encoder = Enc::new();
        encoder.domain(b"AgentDeck/RelayAdminPurgeReceiptV1\0");
        encoder.bytes(&tbs);
        encoder.bytes(&self.signature.0);
        Ok(encoder.finish())
    }

    pub fn canonical_sha256(&self) -> Result<[u8; 32], RelayAdminPurgeReceiptError> {
        Ok(Sha256::digest(self.canonical_bytes()?).into())
    }
}

fn require_nonzero(bytes: &[u8], field: &'static str) -> Result<(), RelayAdminPurgeReceiptError> {
    if bytes.iter().all(|byte| *byte == 0) {
        Err(RelayAdminPurgeReceiptError::ZeroBoundField(field))
    } else {
        Ok(())
    }
}

mod optional_b64_32 {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(
        value: &Option<[u8; 32]>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            Some(bytes) => serializer.serialize_some(&STANDARD.encode(bytes)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<[u8; 32]>, D::Error> {
        let encoded = Option::<String>::deserialize(deserializer)?;
        encoded
            .map(|encoded| {
                let decoded = STANDARD
                    .decode(encoded.as_bytes())
                    .map_err(serde::de::Error::custom)?;
                decoded.try_into().map_err(|_| {
                    serde::de::Error::custom("optional digest must decode to exactly 32 bytes")
                })
            })
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_tbs() -> RelayAdminPurgeReceiptTbsV1 {
        let relay_server_id = RelayServerId::from_bytes([1; 16]);
        let machine_route = MachineRouteId::from_bytes([3; 16]);
        let root_key_id = RootKeyId::from_bytes([4; 16]);
        let root_fingerprint = [5; 32];
        let trust_epoch = TrustEpoch::new(6);
        let enrollment_receipt_hash = [7; 32];
        let purge_request_hash = purge_request_hash(machine_route, root_fingerprint).unwrap();
        let readback = RelayAdminPurgeReadbackV1 {
            active_machine_routes: 0,
            retired_tombstones: 1,
            consumed_enrollment_records: 0,
            device_grants: 0,
            revocations: 0,
            streams: 0,
            frames: 0,
            subscriptions: 0,
            retirement_hash: None,
            retirement_terminal_present: false,
        };
        let tombstone_kind = RelayMachineTombstoneKindV1::RootLostAdminPurge;
        let tombstone_hash = admin_purge_tombstone_hash(&RelayAdminPurgeTombstoneV1 {
            relay_server_id,
            machine_route,
            root_key_id,
            root_fingerprint,
            trust_epoch,
            enrollment_receipt_hash,
            purge_request_hash,
            tombstone_kind,
            readback: readback.clone(),
        })
        .unwrap();
        RelayAdminPurgeReceiptTbsV1 {
            receipt_format_version: RELAY_RECEIPT_FORMAT_VERSION,
            relay_protocol_version: RELAY_PROTOCOL_VERSION,
            relay_server_id,
            receipt_key_generation: RELAY_RECEIPT_KEY_GENERATION_MVP,
            receipt_key_id: RelayReceiptKeyId::from_bytes([2; 32]),
            machine_route,
            root_key_id,
            root_fingerprint,
            trust_epoch,
            enrollment_receipt_hash,
            purge_request_hash,
            tombstone_kind,
            readback,
            tombstone_hash,
        }
    }

    #[test]
    fn raw_canonical_encoding_binds_readback_even_when_shape_is_invalid() {
        let base = valid_tbs();
        let canonical = base.encode_unchecked();
        let mut changed = base;
        changed.readback.retired_tombstones = 2;
        assert_ne!(changed.encode_unchecked(), canonical);
    }
}
