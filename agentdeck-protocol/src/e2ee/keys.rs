//! E2EE 密钥层级、key directory / update 与 epoch barrier（design §7.2）。
//!
//! HPKE 只封装这些小型对称 key；事件/命令内容用对称 AEAD。每个对称 key 只有一个发送
//! 方向。所有 key directory/update 都带 MachineDataSign 签名和单调 `keyDirectoryRevision`。

use crate::e2ee::context::{OuterContextV1, OuterFrameKind};
use crate::e2ee::pairing::{MachineDataSignerBindingV1, PAIRING_HPKE_ENC_BYTES, PairingError};
use crate::e2ee::{E2EE_FORMAT_VERSION, Enc, b64_32};
use crate::relay_v2::RELAY_PROTOCOL_VERSION;
use crate::relay_v2::auth::Ed25519Signature;
use crate::relay_v2::cursor::StreamCursor;
use crate::relay_v2::id::{
    DeviceRouteId, GrantSerial, KeyDirectoryRevision, MachineRouteId, RelayServerId,
    StreamGenerationId, StreamRouteId, TrustEpoch, b64_vec,
};
use crate::runtime::RUNTIME_PROTOCOL_VERSION;
use crate::runtime::sync::RuntimeInnerCursor;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// Runtime 最多 1,024 个 active conversations；首次目录还必须包含 catalog、
// DeviceCommandTx 与 DeviceReplyTx 三个 device-scoped key。
pub const KEY_DIRECTORY_MAX_ENTRIES: usize = 1_024 + 3;
pub const KEY_DIRECTORY_WRAPPED_KEY_BYTES: usize = 48;
const KEY_UPDATE_MAX_CANONICAL_BYTES: usize = 1_024;

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

/// 对称 key 用途（design §7.2）。每个用途一个发送方向。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum KeyPurpose {
    /// 机器/session catalog 与状态快照。
    Catalog,
    /// 每 conversation 的 daemon→device canonical events。
    ConversationDek,
    /// 单设备、device→daemon 命令通道。
    DeviceCommandTx,
    /// 单设备、daemon→device reply 通道。
    DeviceReplyTx,
}

impl KeyPurpose {
    pub(crate) fn tag(self) -> u8 {
        match self {
            KeyPurpose::Catalog => 0,
            KeyPurpose::ConversationDek => 1,
            KeyPurpose::DeviceCommandTx => 2,
            KeyPurpose::DeviceReplyTx => 3,
        }
    }

    fn from_tag(tag: u8) -> Result<Self, PairingError> {
        match tag {
            0 => Ok(Self::Catalog),
            1 => Ok(Self::ConversationDek),
            2 => Ok(Self::DeviceCommandTx),
            3 => Ok(Self::DeviceReplyTx),
            _ => Err(PairingError::InvalidEncoding("key purpose")),
        }
    }
}

/// 对称 key 的身份：用途 + epoch。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KeyId {
    pub purpose: KeyPurpose,
    pub epoch: u64,
}

/// key directory 中给某设备的一个 HPKE-wrapped key（`enc` + `wrapped_key` 对 Relay opaque）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KeyDirectoryEntry {
    pub key_id: KeyId,
    pub device_route: DeviceRouteId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_route: Option<StreamRouteId>,
    #[serde(with = "b64_vec")]
    #[schemars(with = "String")]
    pub enc: Vec<u8>,
    #[serde(with = "b64_vec")]
    #[schemars(with = "String")]
    pub wrapped_key: Vec<u8>,
}

/// 完整 key directory（MachineDataSign 签名 + 单调 revision）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KeyDirectoryV1 {
    pub revision: KeyDirectoryRevision,
    #[schemars(length(min = 3, max = 1027))]
    pub entries: Vec<KeyDirectoryEntry>,
    pub signature: Ed25519Signature,
}

/// 独立于一次 pairing request 的 durable key-directory 签名上下文。
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KeyDirectorySignatureContextV1 {
    pub relay_server_id: RelayServerId,
    pub machine_route: MachineRouteId,
    pub device_route: DeviceRouteId,
    pub grant_serial: GrantSerial,
    pub root_trust_epoch: TrustEpoch,
}

impl std::fmt::Debug for KeyDirectorySignatureContextV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("KeyDirectorySignatureContextV1([REDACTED])")
    }
}

impl KeyDirectorySignatureContextV1 {
    pub fn validate(&self) -> Result<(), PairingError> {
        if is_zero(self.relay_server_id.as_bytes())
            || is_zero(self.machine_route.as_bytes())
            || is_zero(self.device_route.as_bytes())
            || self.grant_serial.value() == 0
            || self.root_trust_epoch.value() == 0
        {
            return Err(PairingError::InvalidField(
                "key directory signature context",
            ));
        }
        Ok(())
    }
}

/// MachineDataSign 对完整、严格排序的 unsigned key directory 签名的确定性 preimage。
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KeyDirectoryTbsV1 {
    pub e2ee_format_version: u16,
    pub runtime_protocol_version: u16,
    pub relay_protocol_version: u16,
    pub relay_server_id: RelayServerId,
    pub machine_route: MachineRouteId,
    pub device_route: DeviceRouteId,
    pub grant_serial: GrantSerial,
    pub root_trust_epoch: TrustEpoch,
    pub key_directory_revision: KeyDirectoryRevision,
    #[serde(with = "b64_32")]
    #[schemars(with = "String")]
    pub signing_key_fingerprint: [u8; 32],
    pub signing_key_generation: crate::relay_v2::LinkGeneration,
    #[serde(with = "b64_32")]
    #[schemars(with = "String")]
    pub signing_credential_sha256: [u8; 32],
    #[serde(with = "b64_32")]
    #[schemars(with = "String")]
    pub unsigned_directory_sha256: [u8; 32],
}

impl std::fmt::Debug for KeyDirectoryTbsV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("KeyDirectoryTbsV1([REDACTED])")
    }
}

impl KeyDirectoryTbsV1 {
    pub fn validate(&self) -> Result<(), PairingError> {
        if self.e2ee_format_version != E2EE_FORMAT_VERSION
            || self.runtime_protocol_version != RUNTIME_PROTOCOL_VERSION
            || self.relay_protocol_version != RELAY_PROTOCOL_VERSION
            || is_zero(self.relay_server_id.as_bytes())
            || is_zero(self.machine_route.as_bytes())
            || is_zero(self.device_route.as_bytes())
            || self.grant_serial.value() == 0
            || self.root_trust_epoch.value() == 0
            || self.key_directory_revision.value() == 0
            || is_zero(&self.signing_key_fingerprint)
            || self.signing_key_generation.value() == 0
            || is_zero(&self.signing_credential_sha256)
            || is_zero(&self.unsigned_directory_sha256)
        {
            return Err(PairingError::InvalidField("key directory TBS"));
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, PairingError> {
        self.validate()?;
        let mut encoder = Enc::new();
        encoder.domain(b"AgentDeck/KeyDirectoryTbsV1\0");
        encoder.u16(self.e2ee_format_version);
        encoder.u16(self.runtime_protocol_version);
        encoder.u16(self.relay_protocol_version);
        encoder.bytes(self.relay_server_id.as_bytes());
        encoder.bytes(self.machine_route.as_bytes());
        encoder.bytes(self.device_route.as_bytes());
        encoder.u64(self.grant_serial.value());
        encoder.u64(self.root_trust_epoch.value());
        encoder.u64(self.key_directory_revision.value());
        encoder.bytes(&self.signing_key_fingerprint);
        encoder.u64(self.signing_key_generation.value());
        encoder.bytes(&self.signing_credential_sha256);
        encoder.bytes(&self.unsigned_directory_sha256);
        Ok(encoder.finish())
    }
}

impl KeyDirectoryV1 {
    fn entry_identity(entry: &KeyDirectoryEntry) -> (u8, [u8; 16], u64) {
        (
            entry.key_id.purpose.tag(),
            entry
                .stream_route
                .map_or([0; 16], |route| *route.as_bytes()),
            entry.key_id.epoch,
        )
    }

    fn validate_shape_for_device(
        &self,
        expected_device: DeviceRouteId,
    ) -> Result<usize, PairingError> {
        if self.revision.value() == 0
            || self.entries.is_empty()
            || self.entries.len() > KEY_DIRECTORY_MAX_ENTRIES
            || is_zero(expected_device.as_bytes())
        {
            return Err(PairingError::InvalidField("key directory"));
        }
        let mut previous = None;
        let mut catalog = 0_usize;
        let mut conversations = 0_usize;
        let mut command = 0_usize;
        let mut reply = 0_usize;
        for entry in &self.entries {
            let stream_shape_valid = match entry.key_id.purpose {
                KeyPurpose::ConversationDek => entry
                    .stream_route
                    .is_some_and(|route| !is_zero(route.as_bytes())),
                _ => entry.stream_route.is_none(),
            };
            let identity = Self::entry_identity(entry);
            if entry.device_route != expected_device
                || entry.key_id.epoch == 0
                || !stream_shape_valid
                || entry.enc.len() != PAIRING_HPKE_ENC_BYTES
                || is_zero(&entry.enc)
                || entry.wrapped_key.len() != KEY_DIRECTORY_WRAPPED_KEY_BYTES
                || is_zero(&entry.wrapped_key)
                || previous.is_some_and(|value| value >= identity)
            {
                return Err(PairingError::InvalidField("key directory entry"));
            }
            previous = Some(identity);
            match entry.key_id.purpose {
                KeyPurpose::Catalog => catalog += 1,
                KeyPurpose::ConversationDek => conversations += 1,
                KeyPurpose::DeviceCommandTx => command += 1,
                KeyPurpose::DeviceReplyTx => reply += 1,
            }
        }
        if catalog != 1 || command != 1 || reply != 1 {
            return Err(PairingError::InvalidField("required key directory entries"));
        }
        Ok(conversations)
    }

    pub fn validate_for_device(&self, expected_device: DeviceRouteId) -> Result<(), PairingError> {
        self.validate_shape_for_device(expected_device)?;
        if is_zero(&self.signature.0) {
            return Err(PairingError::InvalidField("key directory signature"));
        }
        Ok(())
    }

    pub fn validate_bootstrap_for_device(
        &self,
        expected_device: DeviceRouteId,
    ) -> Result<(), PairingError> {
        let conversations = self.validate_shape_for_device(expected_device)?;
        if conversations != 0 || is_zero(&self.signature.0) {
            return Err(PairingError::InvalidField("bootstrap key directory"));
        }
        Ok(())
    }

    /// 首个 grant 的完整 install directory：保留 strict bootstrap 的三项 device
    /// contract，同时要求 authenticated conversation route 集合逐项、唯一、无增删地
    /// 出现在 epoch 1。调用方必须传入 Store 已认证的 mapping，不能使用设备自报 routes。
    pub fn validate_initial_directory_for_device(
        &self,
        expected_device: DeviceRouteId,
        expected_conversation_routes: &[StreamRouteId],
    ) -> Result<(), PairingError> {
        let conversations = self.validate_shape_for_device(expected_device)?;
        if is_zero(&self.signature.0)
            || conversations != expected_conversation_routes.len()
            || self.entries.iter().any(|entry| entry.key_id.epoch != 1)
        {
            return Err(PairingError::InvalidField("initial key directory"));
        }
        let mut previous = None;
        for route in expected_conversation_routes {
            if is_zero(route.as_bytes()) || previous.is_some_and(|value| value >= *route.as_bytes())
            {
                return Err(PairingError::InvalidField(
                    "initial conversation key routes",
                ));
            }
            previous = Some(*route.as_bytes());
        }
        let observed = self
            .entries
            .iter()
            .filter_map(|entry| {
                (entry.key_id.purpose == KeyPurpose::ConversationDek)
                    .then_some(entry.stream_route)
                    .flatten()
            })
            .collect::<Vec<_>>();
        if observed != expected_conversation_routes {
            return Err(PairingError::InvalidField(
                "initial conversation key routes",
            ));
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), PairingError> {
        let device = self
            .entries
            .first()
            .ok_or(PairingError::InvalidField("key directory"))?
            .device_route;
        self.validate_for_device(device)
    }

    pub fn unsigned_canonical_bytes(&self) -> Result<Vec<u8>, PairingError> {
        let device = self
            .entries
            .first()
            .ok_or(PairingError::InvalidField("key directory"))?
            .device_route;
        self.validate_shape_for_device(device)?;
        let mut encoder = Enc::new();
        encoder.domain(b"AgentDeck/KeyDirectoryUnsignedV1\0");
        encoder.u64(self.revision.value());
        encoder.u16(self.entries.len() as u16);
        for entry in &self.entries {
            encoder.u8(entry.key_id.purpose.tag());
            encoder.u64(entry.key_id.epoch);
            encoder.bytes(entry.device_route.as_bytes());
            encoder.opt_id16(entry.stream_route.as_ref().map(|route| route.as_bytes()));
            encoder.bytes(&entry.enc);
            encoder.bytes(&entry.wrapped_key);
        }
        Ok(encoder.finish())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, PairingError> {
        self.validate()?;
        let unsigned = self.unsigned_canonical_bytes()?;
        let mut encoder = Enc::new();
        encoder.domain(b"AgentDeck/KeyDirectoryV1\0");
        encoder.bytes(&unsigned);
        encoder.bytes(&self.signature.0);
        Ok(encoder.finish())
    }

    pub fn unsigned_canonical_sha256(&self) -> Result<[u8; 32], PairingError> {
        Ok(sha256(&self.unsigned_canonical_bytes()?))
    }

    pub fn canonical_sha256(&self) -> Result<[u8; 32], PairingError> {
        Ok(sha256(&self.canonical_bytes()?))
    }

    pub fn signature_tbs(
        &self,
        context: &KeyDirectorySignatureContextV1,
        signer: &MachineDataSignerBindingV1,
    ) -> Result<KeyDirectoryTbsV1, PairingError> {
        context.validate()?;
        signer.validate()?;
        self.validate_shape_for_device(context.device_route)?;
        let tbs = KeyDirectoryTbsV1 {
            e2ee_format_version: E2EE_FORMAT_VERSION,
            runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
            relay_protocol_version: RELAY_PROTOCOL_VERSION,
            relay_server_id: context.relay_server_id,
            machine_route: context.machine_route,
            device_route: context.device_route,
            grant_serial: context.grant_serial,
            root_trust_epoch: context.root_trust_epoch,
            key_directory_revision: self.revision,
            signing_key_fingerprint: signer.signing_key_fingerprint,
            signing_key_generation: signer.generation,
            signing_credential_sha256: signer.certificate_sha256,
            unsigned_directory_sha256: self.unsigned_canonical_sha256()?,
        };
        tbs.validate()?;
        Ok(tbs)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, PairingError> {
        let mut outer = KeyDecoder::new(bytes);
        outer.domain(b"AgentDeck/KeyDirectoryV1\0")?;
        let unsigned = outer.bytes(512 * 1_024)?;
        let signature = Ed25519Signature(
            outer
                .bytes(64)?
                .try_into()
                .map_err(|_| PairingError::InvalidEncoding("key directory signature"))?,
        );
        outer.finish()?;

        let mut decoder = KeyDecoder::new(unsigned);
        decoder.domain(b"AgentDeck/KeyDirectoryUnsignedV1\0")?;
        let revision = KeyDirectoryRevision::new(decoder.u64()?);
        let count = decoder.u16()? as usize;
        if count > KEY_DIRECTORY_MAX_ENTRIES {
            return Err(PairingError::SizeLimit("key directory entries"));
        }
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            entries.push(KeyDirectoryEntry {
                key_id: KeyId {
                    purpose: KeyPurpose::from_tag(decoder.u8()?)?,
                    epoch: decoder.u64()?,
                },
                device_route: DeviceRouteId::from_bytes(
                    decoder
                        .bytes(16)?
                        .try_into()
                        .map_err(|_| PairingError::InvalidEncoding("key directory device route"))?,
                ),
                stream_route: decoder.optional_stream_route()?,
                enc: decoder.bytes(PAIRING_HPKE_ENC_BYTES)?.to_vec(),
                wrapped_key: decoder.bytes(KEY_DIRECTORY_WRAPPED_KEY_BYTES)?.to_vec(),
            });
        }
        decoder.finish()?;
        let value = Self {
            revision,
            entries,
            signature,
        };
        value.validate()?;
        if value.canonical_bytes()?.as_slice() != bytes {
            return Err(PairingError::InvalidEncoding("non-canonical key directory"));
        }
        Ok(value)
    }
}

/// 单个 key 更新（HPKE 封装给某设备；MachineDataSign/Root 签名）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KeyUpdateV1 {
    pub key_directory_revision: KeyDirectoryRevision,
    pub key_id: KeyId,
    pub device_route: DeviceRouteId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_route: Option<StreamRouteId>,
    #[serde(with = "b64_vec")]
    #[schemars(with = "String")]
    pub enc: Vec<u8>,
    #[serde(with = "b64_vec")]
    #[schemars(with = "String")]
    pub wrapped_key: Vec<u8>,
    pub signature: Ed25519Signature,
}

/// MachineDataSign 对单个 HPKE-wrapped key update 签名的确定性 preimage。
///
/// TBS 同时绑定三个版本轴、完整 machine/device trust domain、key identity、HPKE
/// `info`/AAD、`enc`、wrapped-key digest 与 root-certified MachineData credential；调用方
/// 不能只对 wrapped key 或一份脱离上下文的 JSON 签名。
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KeyUpdateTbsV1 {
    pub e2ee_format_version: u16,
    pub runtime_protocol_version: u16,
    pub relay_protocol_version: u16,
    pub relay_server_id: RelayServerId,
    pub machine_route: MachineRouteId,
    pub device_route: DeviceRouteId,
    pub grant_serial: GrantSerial,
    pub root_trust_epoch: TrustEpoch,
    pub key_directory_revision: KeyDirectoryRevision,
    pub key_purpose: KeyPurpose,
    pub key_epoch: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_route: Option<StreamRouteId>,
    #[serde(with = "b64_32")]
    #[schemars(with = "String")]
    pub signing_key_fingerprint: [u8; 32],
    pub signing_key_generation: crate::relay_v2::LinkGeneration,
    #[serde(with = "b64_32")]
    #[schemars(with = "String")]
    pub signing_credential_sha256: [u8; 32],
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
    pub wrapped_key_sha256: [u8; 32],
}

impl std::fmt::Debug for KeyUpdateTbsV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("KeyUpdateTbsV1")
            .field("versions", &"<redacted>")
            .field("bound_material", &"<redacted>")
            .finish()
    }
}

impl KeyUpdateTbsV1 {
    pub fn validate(&self) -> Result<(), PairingError> {
        let stream_shape_valid = match self.key_purpose {
            KeyPurpose::ConversationDek => self
                .stream_route
                .is_some_and(|route| !is_zero(route.as_bytes())),
            _ => self.stream_route.is_none(),
        };
        if self.e2ee_format_version != E2EE_FORMAT_VERSION
            || self.runtime_protocol_version != RUNTIME_PROTOCOL_VERSION
            || self.relay_protocol_version != RELAY_PROTOCOL_VERSION
            || is_zero(self.relay_server_id.as_bytes())
            || is_zero(self.machine_route.as_bytes())
            || is_zero(self.device_route.as_bytes())
            || self.grant_serial.value() == 0
            || self.root_trust_epoch.value() == 0
            || self.key_directory_revision.value() == 0
            || self.key_epoch == 0
            || !stream_shape_valid
            || is_zero(&self.signing_key_fingerprint)
            || self.signing_key_generation.value() == 0
            || is_zero(&self.signing_credential_sha256)
            || is_zero(&self.info_sha256)
            || is_zero(&self.aad_sha256)
            || self.enc.len() != PAIRING_HPKE_ENC_BYTES
            || is_zero(&self.enc)
            || is_zero(&self.wrapped_key_sha256)
        {
            return Err(PairingError::InvalidField("key update TBS"));
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, PairingError> {
        self.validate()?;
        let mut encoder = Enc::new();
        encoder.domain(b"AgentDeck/KeyUpdateTbsV1\0");
        encoder.u16(self.e2ee_format_version);
        encoder.u16(self.runtime_protocol_version);
        encoder.u16(self.relay_protocol_version);
        encoder.bytes(self.relay_server_id.as_bytes());
        encoder.bytes(self.machine_route.as_bytes());
        encoder.bytes(self.device_route.as_bytes());
        encoder.u64(self.grant_serial.value());
        encoder.u64(self.root_trust_epoch.value());
        encoder.u64(self.key_directory_revision.value());
        encoder.u8(self.key_purpose.tag());
        encoder.u64(self.key_epoch);
        encoder.opt_id16(self.stream_route.as_ref().map(|route| route.as_bytes()));
        encoder.bytes(&self.signing_key_fingerprint);
        encoder.u64(self.signing_key_generation.value());
        encoder.bytes(&self.signing_credential_sha256);
        encoder.bytes(&self.info_sha256);
        encoder.bytes(&self.aad_sha256);
        encoder.bytes(&self.enc);
        encoder.bytes(&self.wrapped_key_sha256);
        Ok(encoder.finish())
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, PairingError> {
        if bytes.len() > KEY_UPDATE_MAX_CANONICAL_BYTES {
            return Err(PairingError::SizeLimit("key update TBS"));
        }
        let mut decoder = KeyDecoder::new(bytes);
        decoder.domain(b"AgentDeck/KeyUpdateTbsV1\0")?;
        let value = Self {
            e2ee_format_version: decoder.u16()?,
            runtime_protocol_version: decoder.u16()?,
            relay_protocol_version: decoder.u16()?,
            relay_server_id: RelayServerId::from_bytes(decoder.fixed_bytes()?),
            machine_route: MachineRouteId::from_bytes(decoder.fixed_bytes()?),
            device_route: DeviceRouteId::from_bytes(decoder.fixed_bytes()?),
            grant_serial: GrantSerial::new(decoder.u64()?),
            root_trust_epoch: TrustEpoch::new(decoder.u64()?),
            key_directory_revision: KeyDirectoryRevision::new(decoder.u64()?),
            key_purpose: KeyPurpose::from_tag(decoder.u8()?)?,
            key_epoch: decoder.u64()?,
            stream_route: decoder.optional_stream_route()?,
            signing_key_fingerprint: decoder.fixed_bytes()?,
            signing_key_generation: crate::relay_v2::LinkGeneration::new(decoder.u64()?),
            signing_credential_sha256: decoder.fixed_bytes()?,
            info_sha256: decoder.fixed_bytes()?,
            aad_sha256: decoder.fixed_bytes()?,
            enc: decoder.bytes(PAIRING_HPKE_ENC_BYTES)?.to_vec(),
            wrapped_key_sha256: decoder.fixed_bytes()?,
        };
        decoder.finish()?;
        value.validate()?;
        if value.encode()?.as_slice() != bytes {
            return Err(PairingError::InvalidEncoding(
                "non-canonical key update TBS",
            ));
        }
        Ok(value)
    }
}

/// 只能由 protocol 在完整 authority/context 校验和 canonical 编码后构造的
/// KeyUpdate TBS capability。外部 signer/verifier 只能消费该 token，不能把任意字节
/// 喂给 protocol-owned hook。
///
/// 外部 crate 无法构造 token：
/// ```compile_fail
/// use agentdeck_protocol::e2ee::CanonicalKeyUpdateTbs;
/// let bytes = b"not protocol validated";
/// let _ = CanonicalKeyUpdateTbs { bytes };
/// ```
#[derive(Clone, Copy)]
pub struct CanonicalKeyUpdateTbs<'a> {
    bytes: &'a [u8],
}

impl<'a> CanonicalKeyUpdateTbs<'a> {
    #[must_use]
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }
}

impl std::fmt::Debug for CanonicalKeyUpdateTbs<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("CanonicalKeyUpdateTbs([REDACTED])")
    }
}

/// Protocol-owned signer hook：实现只能接收已经过完整 authority/context 校验的 canonical
/// TBS capability，并暴露实际 signing-key fingerprint 供 credential binding 复核。
pub trait KeyUpdateSignatureSigner {
    fn signing_key_fingerprint(&self) -> [u8; 32];

    fn sign_key_update_tbs(
        &self,
        canonical_tbs: CanonicalKeyUpdateTbs<'_>,
    ) -> Result<Ed25519Signature, PairingError>;
}

/// Protocol-owned verifier hook；与 signer hook 一样不能选择被验字节。
pub trait KeyUpdateSignatureVerifier {
    fn verifying_key_fingerprint(&self) -> [u8; 32];

    fn verify_key_update_tbs(
        &self,
        canonical_tbs: CanonicalKeyUpdateTbs<'_>,
        signature: &Ed25519Signature,
    ) -> Result<(), PairingError>;
}

impl KeyUpdateV1 {
    fn validate_shape(&self, require_signature: bool) -> Result<(), PairingError> {
        let stream_shape_valid = match self.key_id.purpose {
            KeyPurpose::ConversationDek => self
                .stream_route
                .is_some_and(|route| !is_zero(route.as_bytes())),
            _ => self.stream_route.is_none(),
        };
        if self.key_directory_revision.value() == 0
            || self.key_id.epoch == 0
            || is_zero(self.device_route.as_bytes())
            || !stream_shape_valid
            || self.enc.len() != PAIRING_HPKE_ENC_BYTES
            || is_zero(&self.enc)
            || self.wrapped_key.len() != KEY_DIRECTORY_WRAPPED_KEY_BYTES
            || is_zero(&self.wrapped_key)
            || (require_signature && is_zero(&self.signature.0))
            || (!require_signature && !is_zero(&self.signature.0))
        {
            return Err(PairingError::InvalidField("key update"));
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), PairingError> {
        self.validate_shape(true)
    }

    pub fn unsigned_canonical_bytes(&self) -> Result<Vec<u8>, PairingError> {
        let signed = !is_zero(&self.signature.0);
        self.validate_shape(signed)?;
        let mut encoder = Enc::new();
        encoder.domain(b"AgentDeck/KeyUpdateUnsignedV1\0");
        encoder.u64(self.key_directory_revision.value());
        encoder.u8(self.key_id.purpose.tag());
        encoder.u64(self.key_id.epoch);
        encoder.bytes(self.device_route.as_bytes());
        encoder.opt_id16(self.stream_route.as_ref().map(|route| route.as_bytes()));
        encoder.bytes(&self.enc);
        encoder.bytes(&self.wrapped_key);
        Ok(encoder.finish())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, PairingError> {
        self.validate()?;
        let mut encoder = Enc::new();
        encoder.domain(b"AgentDeck/KeyUpdateV1\0");
        encoder.bytes(&self.unsigned_canonical_bytes()?);
        encoder.bytes(&self.signature.0);
        Ok(encoder.finish())
    }

    pub fn canonical_sha256(&self) -> Result<[u8; 32], PairingError> {
        Ok(sha256(&self.canonical_bytes()?))
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, PairingError> {
        if bytes.len() > KEY_UPDATE_MAX_CANONICAL_BYTES {
            return Err(PairingError::SizeLimit("key update"));
        }
        let mut outer = KeyDecoder::new(bytes);
        outer.domain(b"AgentDeck/KeyUpdateV1\0")?;
        let unsigned = outer.bytes(KEY_UPDATE_MAX_CANONICAL_BYTES)?;
        let signature = Ed25519Signature(outer.fixed_bytes()?);
        outer.finish()?;

        let mut decoder = KeyDecoder::new(unsigned);
        decoder.domain(b"AgentDeck/KeyUpdateUnsignedV1\0")?;
        let value = Self {
            key_directory_revision: KeyDirectoryRevision::new(decoder.u64()?),
            key_id: KeyId {
                purpose: KeyPurpose::from_tag(decoder.u8()?)?,
                epoch: decoder.u64()?,
            },
            device_route: DeviceRouteId::from_bytes(decoder.fixed_bytes()?),
            stream_route: decoder.optional_stream_route()?,
            enc: decoder.bytes(PAIRING_HPKE_ENC_BYTES)?.to_vec(),
            wrapped_key: decoder.bytes(KEY_DIRECTORY_WRAPPED_KEY_BYTES)?.to_vec(),
            signature,
        };
        decoder.finish()?;
        value.validate()?;
        if value.canonical_bytes()?.as_slice() != bytes {
            return Err(PairingError::InvalidEncoding("non-canonical key update"));
        }
        Ok(value)
    }

    pub fn signature_tbs(
        &self,
        info: &KeyUpdateInfoV1,
        context: &OuterContextV1,
        signer: &MachineDataSignerBindingV1,
    ) -> Result<KeyUpdateTbsV1, PairingError> {
        let signed = !is_zero(&self.signature.0);
        self.validate_shape(signed)?;
        info.validate_context(context)?;
        signer.validate()?;
        if self.key_directory_revision != info.key_directory_revision
            || self.key_id.purpose != info.key_purpose
            || self.key_id.epoch != info.key_epoch
            || self.device_route != info.device_route
            || self.stream_route != info.stream_route
        {
            return Err(PairingError::ContextBindingMismatch);
        }
        let tbs = KeyUpdateTbsV1 {
            e2ee_format_version: info.e2ee_format_version,
            runtime_protocol_version: info.runtime_protocol_version,
            relay_protocol_version: context.relay_protocol_version,
            relay_server_id: info.relay_server_id,
            machine_route: info.machine_route,
            device_route: info.device_route,
            grant_serial: info.grant_serial,
            root_trust_epoch: info.root_trust_epoch,
            key_directory_revision: info.key_directory_revision,
            key_purpose: info.key_purpose,
            key_epoch: info.key_epoch,
            stream_route: info.stream_route,
            signing_key_fingerprint: signer.signing_key_fingerprint,
            signing_key_generation: signer.generation,
            signing_credential_sha256: signer.certificate_sha256,
            info_sha256: sha256(&info.encode()),
            aad_sha256: sha256(&context.encode_aad()),
            enc: self.enc.clone(),
            wrapped_key_sha256: sha256(&self.wrapped_key),
        };
        tbs.validate()?;
        Ok(tbs)
    }

    pub fn sign_with<S: KeyUpdateSignatureSigner>(
        mut self,
        signer_hook: &S,
        info: &KeyUpdateInfoV1,
        context: &OuterContextV1,
        signer: &MachineDataSignerBindingV1,
    ) -> Result<Self, PairingError> {
        self.validate_shape(false)?;
        signer.validate()?;
        if signer_hook.signing_key_fingerprint() != signer.signing_key_fingerprint {
            return Err(PairingError::InvalidField(
                "key update signer credential binding",
            ));
        }
        let tbs = self.signature_tbs(info, context, signer)?.encode()?;
        let signature = signer_hook.sign_key_update_tbs(CanonicalKeyUpdateTbs { bytes: &tbs })?;
        if is_zero(&signature.0) {
            return Err(PairingError::InvalidField("key update signature"));
        }
        self.signature = signature;
        self.validate()?;
        Ok(self)
    }

    pub fn verify_with<V: KeyUpdateSignatureVerifier>(
        &self,
        verifier_hook: &V,
        info: &KeyUpdateInfoV1,
        context: &OuterContextV1,
        signer: &MachineDataSignerBindingV1,
    ) -> Result<(), PairingError> {
        self.validate()?;
        signer.validate()?;
        if verifier_hook.verifying_key_fingerprint() != signer.signing_key_fingerprint {
            return Err(PairingError::InvalidField(
                "key update verifier credential binding",
            ));
        }
        let tbs = self.signature_tbs(info, context, signer)?.encode()?;
        verifier_hook.verify_key_update_tbs(CanonicalKeyUpdateTbs { bytes: &tbs }, &self.signature)
    }
}

/// 成员/epoch 变化时在每个 active stream 记录的 epoch barrier（design §7.2 / §9.2）。
/// 同时含外层 generation/cursor 与 tagged inner cursor；剩余设备从 `next(C)` 使用新 key。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EpochBarrierV1 {
    pub stream_generation: StreamGenerationId,
    pub stream_cursor: StreamCursor,
    pub inner_cursor: RuntimeInnerCursor,
    pub old_epoch: u64,
    pub new_epoch: u64,
    pub key_directory_revision: KeyDirectoryRevision,
}

/// `KeyUpdateInfoV1` —— HPKE `info`（design §7.4）。固定包含 trust domain、machine/device
/// route、grant serial、root trust epoch、key-directory revision、key purpose 与 key epoch。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KeyUpdateInfoV1 {
    pub e2ee_format_version: u16,
    pub runtime_protocol_version: u16,
    pub relay_server_id: RelayServerId,
    pub machine_route: MachineRouteId,
    pub device_route: DeviceRouteId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_route: Option<StreamRouteId>,
    pub grant_serial: GrantSerial,
    pub root_trust_epoch: TrustEpoch,
    pub key_directory_revision: KeyDirectoryRevision,
    pub key_purpose: KeyPurpose,
    pub key_epoch: u64,
}

impl KeyUpdateInfoV1 {
    pub fn validate(&self) -> Result<(), PairingError> {
        let stream_shape_valid = match self.key_purpose {
            KeyPurpose::ConversationDek => self
                .stream_route
                .is_some_and(|route| !is_zero(route.as_bytes())),
            _ => self.stream_route.is_none(),
        };
        if self.e2ee_format_version != E2EE_FORMAT_VERSION
            || self.runtime_protocol_version != RUNTIME_PROTOCOL_VERSION
            || is_zero(self.relay_server_id.as_bytes())
            || is_zero(self.machine_route.as_bytes())
            || is_zero(self.device_route.as_bytes())
            || !stream_shape_valid
            || self.grant_serial.value() == 0
            || self.root_trust_epoch.value() == 0
            || self.key_directory_revision.value() == 0
            || self.key_epoch == 0
        {
            return Err(PairingError::InvalidField("key update info"));
        }
        Ok(())
    }

    pub fn validate_context(&self, context: &OuterContextV1) -> Result<(), PairingError> {
        self.validate()?;
        context
            .validate()
            .map_err(|_| PairingError::ContextBindingMismatch)?;
        if context.frame_kind != OuterFrameKind::KeyUpdate
            || context.relay_protocol_version != RELAY_PROTOCOL_VERSION
            || context.e2ee_format_version != E2EE_FORMAT_VERSION
            || context.machine_route != Some(self.machine_route)
            || context.device_route != Some(self.device_route)
            || context.stream_route != self.stream_route
            || context.request_route.is_some()
            || context.pair_route.is_some()
            || context.stream_generation.is_some()
            || context.stream_cursor.is_some()
            || context.stream_seq.is_some()
            || context.message_key_epoch != self.key_epoch
        {
            return Err(PairingError::ContextBindingMismatch);
        }
        Ok(())
    }

    /// 确定性长度前缀编码（HPKE `info` bytes）。
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Enc::new();
        e.domain(b"AgentDeck/KeyUpdateInfoV1\0");
        e.u16(self.e2ee_format_version);
        e.u16(self.runtime_protocol_version);
        e.bytes(self.relay_server_id.as_bytes());
        e.bytes(self.machine_route.as_bytes());
        e.bytes(self.device_route.as_bytes());
        e.opt_id16(self.stream_route.as_ref().map(|route| route.as_bytes()));
        e.u64(self.grant_serial.value());
        e.u64(self.root_trust_epoch.value());
        e.u64(self.key_directory_revision.value());
        e.u8(self.key_purpose.tag());
        e.u64(self.key_epoch);
        e.finish()
    }
}

impl KeyDirectoryEntry {
    pub fn validate_for_info(&self, info: &KeyUpdateInfoV1) -> Result<(), PairingError> {
        info.validate()?;
        if self.key_id.purpose != info.key_purpose
            || self.key_id.epoch != info.key_epoch
            || self.device_route != info.device_route
            || self.stream_route != info.stream_route
            || self.enc.len() != PAIRING_HPKE_ENC_BYTES
            || is_zero(&self.enc)
            || self.wrapped_key.len() != KEY_DIRECTORY_WRAPPED_KEY_BYTES
            || is_zero(&self.wrapped_key)
        {
            return Err(PairingError::InvalidField("wrapped key directory entry"));
        }
        Ok(())
    }
}

struct KeyDecoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> KeyDecoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], PairingError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(PairingError::InvalidEncoding(
                "key directory offset overflow",
            ))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(PairingError::InvalidEncoding("truncated key directory"))?;
        self.offset = end;
        Ok(value)
    }

    fn domain(&mut self, expected: &[u8]) -> Result<(), PairingError> {
        if self.take(expected.len())? != expected {
            return Err(PairingError::InvalidEncoding(
                "key directory domain separator",
            ));
        }
        Ok(())
    }

    fn u8(&mut self) -> Result<u8, PairingError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, PairingError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().map_err(
            |_| PairingError::InvalidEncoding("key directory u16"),
        )?))
    }

    fn u64(&mut self) -> Result<u64, PairingError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().map_err(
            |_| PairingError::InvalidEncoding("key directory u64"),
        )?))
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], PairingError> {
        self.take(N)?
            .try_into()
            .map_err(|_| PairingError::InvalidEncoding("key directory fixed bytes"))
    }

    fn fixed_bytes<const N: usize>(&mut self) -> Result<[u8; N], PairingError> {
        self.bytes(N)?
            .try_into()
            .map_err(|_| PairingError::InvalidEncoding("key directory fixed field"))
    }

    fn bytes(&mut self, maximum: usize) -> Result<&'a [u8], PairingError> {
        let length = u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| PairingError::InvalidEncoding("key directory length"))?,
        ) as usize;
        if length > maximum {
            return Err(PairingError::SizeLimit("key directory field"));
        }
        self.take(length)
    }

    fn optional_stream_route(&mut self) -> Result<Option<StreamRouteId>, PairingError> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(StreamRouteId::from_bytes(self.fixed()?))),
            _ => Err(PairingError::InvalidEncoding("key directory stream route")),
        }
    }

    fn finish(self) -> Result<(), PairingError> {
        if self.offset != self.bytes.len() {
            return Err(PairingError::InvalidEncoding(
                "trailing key directory bytes",
            ));
        }
        Ok(())
    }
}
