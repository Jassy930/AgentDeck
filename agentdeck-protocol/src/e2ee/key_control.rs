//! P4.5 key update、epoch barrier、KeySync 与 authenticated device ACK 的 endpoint wire。
//!
//! 这些 DTO 只存在于 E2EE plaintext；Relay outer 继续只路由 opaque Publish/Send/Reply，
//! 不新增可观察 key-control family。

use schemars::{
    JsonSchema,
    r#gen::SchemaGenerator,
    schema::{InstanceType, Schema, SchemaObject, StringValidation},
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

use crate::e2ee::keys::{EpochBarrierV1, KeyId, KeyPurpose, KeyUpdateV1};
use crate::e2ee::pairing::PairingError;
use crate::e2ee::payload::SealedPayloadKind;
use crate::e2ee::{E2EE_FORMAT_VERSION, Enc};
use crate::relay_v2::RELAY_PROTOCOL_VERSION;
use crate::relay_v2::cursor::StreamCursor;
use crate::relay_v2::id::{
    DeviceRouteId, GrantSerial, KeyDirectoryRevision, MachineRouteId, StreamGenerationId,
    StreamRouteId, TrustEpoch,
};
use crate::runtime::RUNTIME_PROTOCOL_VERSION;
use crate::runtime::identity::ConversationId;
use crate::runtime::sync::RuntimeInnerCursor;

/// Runtime 最大 1,024 active conversations；一次更新还要能同时携带 catalog、command、reply
/// 三把设备相关 key，不能复用旧 directory 的 256-entry 上限。
pub const KEY_UPDATE_SET_MAX_KEYS: usize = 1_024 + 3;
/// 1,027 个固定形态 v1 update 的 canonical 上界。当前最大合法集合小于 278 KiB；
/// 保留有界编码余量，并作为 daemon Store admission 的唯一事实源。
pub const KEY_UPDATE_SET_MAX_CANONICAL_BYTES: usize = 384 * 1_024;
/// key-control 中 string-backed canonical identity 的 UTF-8 byte cap。
pub const KEY_CONTROL_MAX_ID_BYTES: usize = 1_024;
/// 单条 remote publication binding 的 canonical 上界。
pub const STREAM_BINDING_MAX_CANONICAL_BYTES: usize = 8 * 1_024;

const KEY_UPDATE_MAX_CANONICAL_BYTES: usize = 1_024;
const KEY_CONTROL_MAX_CANONICAL_BYTES: usize = 2 * 1_024 * 1_024;
const KEY_CONTROL_SMALL_CANONICAL_BYTES: usize = STREAM_BINDING_MAX_CANONICAL_BYTES;

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

fn key_identity(update: &KeyUpdateV1) -> (u8, [u8; 16]) {
    (
        update.key_id.purpose.tag(),
        update
            .stream_route
            .map_or([0; 16], |route| *route.as_bytes()),
    )
}

fn validate_stream_shape(
    purpose: KeyPurpose,
    stream_route: Option<StreamRouteId>,
) -> Result<(), PairingError> {
    let valid = match purpose {
        KeyPurpose::ConversationDek => stream_route.is_some_and(|route| !is_zero(route.as_bytes())),
        _ => stream_route.is_none(),
    };
    if !valid {
        return Err(PairingError::InvalidField("key-control stream shape"));
    }
    Ok(())
}

fn validate_authority(
    format_version: u16,
    runtime_protocol_version: u16,
    relay_protocol_version: u16,
    machine_route: MachineRouteId,
    device_route: DeviceRouteId,
    grant_serial: GrantSerial,
    root_trust_epoch: TrustEpoch,
) -> Result<(), PairingError> {
    if format_version != E2EE_FORMAT_VERSION
        || runtime_protocol_version != RUNTIME_PROTOCOL_VERSION
        || relay_protocol_version != RELAY_PROTOCOL_VERSION
        || is_zero(machine_route.as_bytes())
        || is_zero(device_route.as_bytes())
        || grant_serial.value() == 0
        || root_trust_epoch.value() == 0
    {
        return Err(PairingError::InvalidField("key-control authority"));
    }
    Ok(())
}

fn encode_authority(encoder: &mut Enc, authority: AuthorityFields) {
    encoder.u16(authority.format_version);
    encoder.u16(authority.runtime_protocol_version);
    encoder.u16(authority.relay_protocol_version);
    encoder.bytes(authority.machine_route.as_bytes());
    encoder.bytes(authority.device_route.as_bytes());
    encoder.u64(authority.grant_serial.value());
    encoder.u64(authority.root_trust_epoch.value());
}

/// 同一 revision、同一 device 的 bounded wrapped-key update set。
///
/// `updates` 以 `(purpose tag, stream route bytes)` 严格排序且不得重复；MVP 最大集合为
/// catalog + 1,024 conversation + command + reply，共 1,027 项，仍小于 Relay 4 MiB frame cap。
/// 本 protocol 类型只证明 carrier 的同质性、顺序与容量，不知道 Store 的 active stream roster，
/// 因而**不宣称 set 自身完整**；membership transition 冻结前必须由 Store 对 roster 做 exact 对账。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KeyUpdateSetV1 {
    pub key_directory_revision: KeyDirectoryRevision,
    pub device_route: DeviceRouteId,
    #[schemars(length(min = 1, max = 1027))]
    pub updates: Vec<KeyUpdateV1>,
}

impl KeyUpdateSetV1 {
    pub fn validate(&self) -> Result<(), PairingError> {
        if self.key_directory_revision.value() == 0
            || is_zero(self.device_route.as_bytes())
            || self.updates.is_empty()
            || self.updates.len() > KEY_UPDATE_SET_MAX_KEYS
        {
            return Err(PairingError::InvalidField("key update set"));
        }
        let mut previous = None;
        for update in &self.updates {
            update.validate()?;
            let identity = key_identity(update);
            if update.key_directory_revision != self.key_directory_revision
                || update.device_route != self.device_route
                || previous.is_some_and(|value| value >= identity)
            {
                return Err(PairingError::InvalidField("key update set entry"));
            }
            previous = Some(identity);
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, PairingError> {
        self.validate()?;
        let mut encoder = Enc::new();
        encoder.domain(b"AgentDeck/KeyUpdateSetV1\0");
        encoder.u64(self.key_directory_revision.value());
        encoder.bytes(self.device_route.as_bytes());
        encoder.u16(self.updates.len() as u16);
        for update in &self.updates {
            encoder.bytes(&update.canonical_bytes()?);
        }
        let bytes = encoder.finish();
        if bytes.len() > KEY_UPDATE_SET_MAX_CANONICAL_BYTES {
            return Err(PairingError::SizeLimit("key update set"));
        }
        Ok(bytes)
    }

    pub fn canonical_sha256(&self) -> Result<[u8; 32], PairingError> {
        Ok(sha256(&self.canonical_bytes()?))
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, PairingError> {
        if bytes.len() > KEY_UPDATE_SET_MAX_CANONICAL_BYTES {
            return Err(PairingError::SizeLimit("key update set"));
        }
        let mut decoder = ControlDecoder::new(bytes);
        decoder.domain(b"AgentDeck/KeyUpdateSetV1\0")?;
        let key_directory_revision = KeyDirectoryRevision::new(decoder.u64()?);
        let device_route = DeviceRouteId::from_bytes(decoder.fixed_bytes()?);
        let count = decoder.u16()? as usize;
        if count == 0 || count > KEY_UPDATE_SET_MAX_KEYS {
            return Err(PairingError::SizeLimit("key update set entries"));
        }
        let mut updates = Vec::with_capacity(count);
        for _ in 0..count {
            updates.push(KeyUpdateV1::from_canonical_bytes(
                decoder.bytes(KEY_UPDATE_MAX_CANONICAL_BYTES)?,
            )?);
        }
        decoder.finish()?;
        let value = Self {
            key_directory_revision,
            device_route,
            updates,
        };
        value.validate()?;
        if value.canonical_bytes()?.as_slice() != bytes {
            return Err(PairingError::InvalidEncoding(
                "non-canonical key update set",
            ));
        }
        Ok(value)
    }
}

/// daemon 尚未推进到 probe 所请求 revision 时返回的 authenticated 状态。
///
/// 该值只允许表达 `current=r, requested=r+1`。它在当前 `DeviceReplyTx` key 下
/// 定向返回，outer AAD/MachineDataSign 继续绑定 exact request route；设备收到后保持
/// 当前目录并在 bounded reconnect probe 的后续时机重试，不能把它当作 key update ACK。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectoryCurrentV1 {
    pub format_version: u16,
    pub runtime_protocol_version: u16,
    pub relay_protocol_version: u16,
    pub machine_route: MachineRouteId,
    pub device_route: DeviceRouteId,
    pub grant_serial: GrantSerial,
    pub root_trust_epoch: TrustEpoch,
    pub current_key_directory_revision: KeyDirectoryRevision,
    pub requested_key_directory_revision: KeyDirectoryRevision,
}

impl DirectoryCurrentV1 {
    pub fn validate(&self) -> Result<(), PairingError> {
        validate_authority(
            self.format_version,
            self.runtime_protocol_version,
            self.relay_protocol_version,
            self.machine_route,
            self.device_route,
            self.grant_serial,
            self.root_trust_epoch,
        )?;
        let expected = self
            .current_key_directory_revision
            .next()
            .map_err(|_| PairingError::InvalidField("directory current revision exhausted"))?;
        if self.current_key_directory_revision.value() == 0
            || self.requested_key_directory_revision != expected
        {
            return Err(PairingError::InvalidField("directory current status"));
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, PairingError> {
        self.validate()?;
        let mut encoder = Enc::new();
        encoder.domain(b"AgentDeck/DirectoryCurrentV1\0");
        encode_authority(
            &mut encoder,
            AuthorityFields {
                format_version: self.format_version,
                runtime_protocol_version: self.runtime_protocol_version,
                relay_protocol_version: self.relay_protocol_version,
                machine_route: self.machine_route,
                device_route: self.device_route,
                grant_serial: self.grant_serial,
                root_trust_epoch: self.root_trust_epoch,
            },
        );
        encoder.u64(self.current_key_directory_revision.value());
        encoder.u64(self.requested_key_directory_revision.value());
        Ok(encoder.finish())
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, PairingError> {
        let mut decoder = bounded_small_decoder(bytes, "directory current status")?;
        decoder.domain(b"AgentDeck/DirectoryCurrentV1\0")?;
        let authority = decoder.authority()?;
        let value = Self {
            format_version: authority.format_version,
            runtime_protocol_version: authority.runtime_protocol_version,
            relay_protocol_version: authority.relay_protocol_version,
            machine_route: authority.machine_route,
            device_route: authority.device_route,
            grant_serial: authority.grant_serial,
            root_trust_epoch: authority.root_trust_epoch,
            current_key_directory_revision: KeyDirectoryRevision::new(decoder.u64()?),
            requested_key_directory_revision: KeyDirectoryRevision::new(decoder.u64()?),
        };
        finish_small(value, decoder, bytes, Self::canonical_bytes)
    }
}

/// Remote endpoint 构造 Relay `Subscribe` 所需的 authenticated publication binding。
///
/// 该 carrier 只出现在 MachineDataSign + DeviceReplyTx 保护的定向 E2EE reply 内；
/// `stream_generation` 是 Relay publication generation，绝不是 Runtime 本地 subscription
/// generation。Catalog route 由 daemon 在此显式提供，不能从 Catalog key 的 `None` 猜测。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamBindingV1 {
    pub format_version: u16,
    pub runtime_protocol_version: u16,
    pub relay_protocol_version: u16,
    pub machine_route: MachineRouteId,
    pub device_route: DeviceRouteId,
    pub grant_serial: GrantSerial,
    pub root_trust_epoch: TrustEpoch,
    pub stream_route: StreamRouteId,
    pub stream_generation: StreamGenerationId,
    /// Relay outer committed/resume cursor。
    pub stream_cursor: StreamCursor,
    /// Runtime target 与该 target 的 inner canonical cursor。
    pub inner_cursor: RuntimeInnerCursor,
    pub key_directory_revision: KeyDirectoryRevision,
    pub key_id: KeyId,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StreamBindingWire {
    format_version: u16,
    runtime_protocol_version: u16,
    relay_protocol_version: u16,
    machine_route: MachineRouteId,
    device_route: DeviceRouteId,
    grant_serial: GrantSerial,
    root_trust_epoch: TrustEpoch,
    stream_route: StreamRouteId,
    stream_generation: StreamGenerationId,
    stream_cursor: StreamCursor,
    inner_cursor: RuntimeInnerCursor,
    key_directory_revision: KeyDirectoryRevision,
    key_id: KeyId,
}

impl From<&StreamBindingV1> for StreamBindingWire {
    fn from(value: &StreamBindingV1) -> Self {
        Self {
            format_version: value.format_version,
            runtime_protocol_version: value.runtime_protocol_version,
            relay_protocol_version: value.relay_protocol_version,
            machine_route: value.machine_route,
            device_route: value.device_route,
            grant_serial: value.grant_serial,
            root_trust_epoch: value.root_trust_epoch,
            stream_route: value.stream_route,
            stream_generation: value.stream_generation,
            stream_cursor: value.stream_cursor,
            inner_cursor: value.inner_cursor.clone(),
            key_directory_revision: value.key_directory_revision,
            key_id: value.key_id,
        }
    }
}

impl From<StreamBindingWire> for StreamBindingV1 {
    fn from(value: StreamBindingWire) -> Self {
        Self {
            format_version: value.format_version,
            runtime_protocol_version: value.runtime_protocol_version,
            relay_protocol_version: value.relay_protocol_version,
            machine_route: value.machine_route,
            device_route: value.device_route,
            grant_serial: value.grant_serial,
            root_trust_epoch: value.root_trust_epoch,
            stream_route: value.stream_route,
            stream_generation: value.stream_generation,
            stream_cursor: value.stream_cursor,
            inner_cursor: value.inner_cursor,
            key_directory_revision: value.key_directory_revision,
            key_id: value.key_id,
        }
    }
}

impl Serialize for StreamBindingV1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.validate().map_err(serde::ser::Error::custom)?;
        StreamBindingWire::from(self).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for StreamBindingV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Self::from(StreamBindingWire::deserialize(deserializer)?);
        value.validate().map_err(serde::de::Error::custom)?;
        Ok(value)
    }
}

#[derive(JsonSchema)]
#[schemars(rename_all = "camelCase", deny_unknown_fields)]
#[allow(dead_code)]
struct StreamBindingSchema {
    #[schemars(range(min = 1))]
    format_version: u16,
    #[schemars(range(min = 1))]
    runtime_protocol_version: u16,
    #[schemars(range(min = 1))]
    relay_protocol_version: u16,
    machine_route: MachineRouteId,
    device_route: DeviceRouteId,
    #[schemars(range(min = 1))]
    grant_serial: u64,
    #[schemars(range(min = 1))]
    root_trust_epoch: u64,
    stream_route: StreamRouteId,
    stream_generation: StreamGenerationId,
    stream_cursor: StreamCursor,
    inner_cursor: StreamBindingInnerCursorSchema,
    #[schemars(range(min = 1))]
    key_directory_revision: u64,
    key_id: StreamBindingKeyIdSchema,
}

#[derive(JsonSchema)]
#[schemars(tag = "scope", rename_all = "camelCase", deny_unknown_fields)]
#[allow(dead_code)]
enum StreamBindingInnerCursorSchema {
    Catalog {
        cursor: StreamCursor,
    },
    Conversation {
        #[schemars(rename = "conversationId")]
        conversation_id: StreamBindingConversationIdSchema,
        cursor: StreamCursor,
    },
}

#[derive(JsonSchema)]
#[schemars(rename_all = "camelCase", deny_unknown_fields)]
#[allow(dead_code)]
struct StreamBindingKeyIdSchema {
    purpose: KeyPurpose,
    #[schemars(range(min = 1))]
    epoch: u64,
}

#[allow(dead_code)]
struct StreamBindingConversationIdSchema;

impl JsonSchema for StreamBindingConversationIdSchema {
    fn is_referenceable() -> bool {
        false
    }

    fn schema_name() -> String {
        "StreamBindingConversationId".to_owned()
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        SchemaObject {
            instance_type: Some(InstanceType::String.into()),
            string: Some(Box::new(StringValidation {
                min_length: Some(1),
                max_length: Some(KEY_CONTROL_MAX_ID_BYTES as u32),
                ..Default::default()
            })),
            extensions: std::iter::once((
                "x-maxUtf8Bytes".to_owned(),
                serde_json::json!(KEY_CONTROL_MAX_ID_BYTES),
            ))
            .collect(),
            ..Default::default()
        }
        .into()
    }
}

impl JsonSchema for StreamBindingV1 {
    fn schema_name() -> String {
        "StreamBindingV1".to_owned()
    }

    fn json_schema(generator: &mut SchemaGenerator) -> Schema {
        StreamBindingSchema::json_schema(generator)
    }
}

impl StreamBindingV1 {
    pub fn validate(&self) -> Result<(), PairingError> {
        validate_authority(
            self.format_version,
            self.runtime_protocol_version,
            self.relay_protocol_version,
            self.machine_route,
            self.device_route,
            self.grant_serial,
            self.root_trust_epoch,
        )?;
        if is_zero(self.stream_route.as_bytes())
            || is_zero(self.stream_generation.as_bytes())
            || self.key_directory_revision.value() == 0
            || self.key_id.epoch == 0
            || self.stream_cursor.checked_next().is_err()
        {
            return Err(PairingError::InvalidField("stream binding"));
        }

        validate_inner_cursor(&self.inner_cursor)?;
        let inner_stream_cursor = match (&self.inner_cursor, self.key_id.purpose) {
            (RuntimeInnerCursor::Catalog { cursor }, KeyPurpose::Catalog) => cursor,
            (RuntimeInnerCursor::Conversation { cursor, .. }, KeyPurpose::ConversationDek) => {
                cursor
            }
            _ => {
                return Err(PairingError::InvalidField(
                    "stream binding target/key shape",
                ));
            }
        };
        if inner_stream_cursor.checked_next().is_err() {
            return Err(PairingError::InvalidField(
                "exhausted stream binding inner cursor",
            ));
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, PairingError> {
        self.validate()?;
        let mut encoder = Enc::new();
        encoder.domain(b"AgentDeck/StreamBindingV1\0");
        encode_authority(
            &mut encoder,
            AuthorityFields {
                format_version: self.format_version,
                runtime_protocol_version: self.runtime_protocol_version,
                relay_protocol_version: self.relay_protocol_version,
                machine_route: self.machine_route,
                device_route: self.device_route,
                grant_serial: self.grant_serial,
                root_trust_epoch: self.root_trust_epoch,
            },
        );
        encoder.bytes(self.stream_route.as_bytes());
        encoder.bytes(self.stream_generation.as_bytes());
        encoder.cursor(&self.stream_cursor);
        encode_inner_cursor(&mut encoder, &self.inner_cursor);
        encoder.u64(self.key_directory_revision.value());
        encoder.u8(self.key_id.purpose.tag());
        encoder.u64(self.key_id.epoch);
        let bytes = encoder.finish();
        if bytes.len() > STREAM_BINDING_MAX_CANONICAL_BYTES {
            return Err(PairingError::SizeLimit("stream binding"));
        }
        Ok(bytes)
    }

    pub fn canonical_sha256(&self) -> Result<[u8; 32], PairingError> {
        Ok(sha256(&self.canonical_bytes()?))
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, PairingError> {
        if bytes.len() > STREAM_BINDING_MAX_CANONICAL_BYTES {
            return Err(PairingError::SizeLimit("stream binding"));
        }
        let mut decoder = ControlDecoder::new(bytes);
        decoder.domain(b"AgentDeck/StreamBindingV1\0")?;
        let authority = decoder.authority()?;
        let value = Self {
            format_version: authority.format_version,
            runtime_protocol_version: authority.runtime_protocol_version,
            relay_protocol_version: authority.relay_protocol_version,
            machine_route: authority.machine_route,
            device_route: authority.device_route,
            grant_serial: authority.grant_serial,
            root_trust_epoch: authority.root_trust_epoch,
            stream_route: StreamRouteId::from_bytes(decoder.fixed_bytes()?),
            stream_generation: StreamGenerationId::from_bytes(decoder.fixed_bytes()?),
            stream_cursor: decoder.cursor()?,
            inner_cursor: decoder.inner_cursor()?,
            key_directory_revision: KeyDirectoryRevision::new(decoder.u64()?),
            key_id: KeyId {
                purpose: decode_key_purpose(decoder.u8()?)?,
                epoch: decoder.u64()?,
            },
        };
        finish_small(value, decoder, bytes, Self::canonical_bytes)
    }
}

/// 密文内 key-control carrier。Relay outer 继续使用既有 opaque Reply/Publish family。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyControlV1 {
    UpdateSet {
        format_version: u16,
        update_set: KeyUpdateSetV1,
    },
    EpochBarrier {
        format_version: u16,
        stream_route: StreamRouteId,
        barrier: EpochBarrierV1,
    },
    DirectoryCurrent {
        format_version: u16,
        status: DirectoryCurrentV1,
    },
    StreamBinding {
        format_version: u16,
        binding: StreamBindingV1,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
enum KeyControlWire {
    UpdateSet {
        format_version: u16,
        update_set: KeyUpdateSetV1,
    },
    EpochBarrier {
        format_version: u16,
        stream_route: StreamRouteId,
        barrier: EpochBarrierV1,
    },
    DirectoryCurrent {
        format_version: u16,
        status: DirectoryCurrentV1,
    },
    StreamBinding {
        format_version: u16,
        binding: StreamBindingV1,
    },
}

impl From<&KeyControlV1> for KeyControlWire {
    fn from(value: &KeyControlV1) -> Self {
        match value {
            KeyControlV1::UpdateSet {
                format_version,
                update_set,
            } => Self::UpdateSet {
                format_version: *format_version,
                update_set: update_set.clone(),
            },
            KeyControlV1::EpochBarrier {
                format_version,
                stream_route,
                barrier,
            } => Self::EpochBarrier {
                format_version: *format_version,
                stream_route: *stream_route,
                barrier: barrier.clone(),
            },
            KeyControlV1::DirectoryCurrent {
                format_version,
                status,
            } => Self::DirectoryCurrent {
                format_version: *format_version,
                status: status.clone(),
            },
            KeyControlV1::StreamBinding {
                format_version,
                binding,
            } => Self::StreamBinding {
                format_version: *format_version,
                binding: binding.clone(),
            },
        }
    }
}

impl From<KeyControlWire> for KeyControlV1 {
    fn from(value: KeyControlWire) -> Self {
        match value {
            KeyControlWire::UpdateSet {
                format_version,
                update_set,
            } => Self::UpdateSet {
                format_version,
                update_set,
            },
            KeyControlWire::EpochBarrier {
                format_version,
                stream_route,
                barrier,
            } => Self::EpochBarrier {
                format_version,
                stream_route,
                barrier,
            },
            KeyControlWire::DirectoryCurrent {
                format_version,
                status,
            } => Self::DirectoryCurrent {
                format_version,
                status,
            },
            KeyControlWire::StreamBinding {
                format_version,
                binding,
            } => Self::StreamBinding {
                format_version,
                binding,
            },
        }
    }
}

impl Serialize for KeyControlV1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.validate().map_err(serde::ser::Error::custom)?;
        KeyControlWire::from(self).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for KeyControlV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Self::from(KeyControlWire::deserialize(deserializer)?);
        value.validate().map_err(serde::de::Error::custom)?;
        Ok(value)
    }
}

#[derive(JsonSchema)]
#[schemars(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
#[allow(dead_code)]
enum KeyControlSchema {
    UpdateSet {
        #[schemars(rename = "formatVersion", range(min = 1))]
        format_version: u16,
        #[schemars(rename = "updateSet")]
        update_set: KeyUpdateSetV1,
    },
    EpochBarrier {
        #[schemars(rename = "formatVersion", range(min = 1))]
        format_version: u16,
        #[schemars(rename = "streamRoute")]
        stream_route: StreamRouteId,
        barrier: EpochBarrierV1,
    },
    DirectoryCurrent {
        #[schemars(rename = "formatVersion", range(min = 1))]
        format_version: u16,
        status: DirectoryCurrentV1,
    },
    StreamBinding {
        #[schemars(rename = "formatVersion", range(min = 1))]
        format_version: u16,
        binding: StreamBindingV1,
    },
}

impl JsonSchema for KeyControlV1 {
    fn schema_name() -> String {
        "KeyControlV1".to_owned()
    }

    fn json_schema(generator: &mut SchemaGenerator) -> Schema {
        KeyControlSchema::json_schema(generator)
    }
}

impl KeyControlV1 {
    /// Key-control 始终使用密文内 `KeyUpdate` kind；Relay outer 仍只看到
    /// opaque Publish/Reply，不新增 family。
    #[must_use]
    pub const fn sealed_payload_kind(&self) -> SealedPayloadKind {
        SealedPayloadKind::KeyUpdate
    }

    pub fn update_set(update_set: KeyUpdateSetV1) -> Self {
        Self::UpdateSet {
            format_version: E2EE_FORMAT_VERSION,
            update_set,
        }
    }

    pub fn epoch_barrier(stream_route: StreamRouteId, barrier: EpochBarrierV1) -> Self {
        Self::EpochBarrier {
            format_version: E2EE_FORMAT_VERSION,
            stream_route,
            barrier,
        }
    }

    pub fn directory_current(status: DirectoryCurrentV1) -> Self {
        Self::DirectoryCurrent {
            format_version: E2EE_FORMAT_VERSION,
            status,
        }
    }

    pub fn stream_binding(binding: StreamBindingV1) -> Self {
        Self::StreamBinding {
            format_version: E2EE_FORMAT_VERSION,
            binding,
        }
    }

    pub fn validate(&self) -> Result<(), PairingError> {
        match self {
            Self::UpdateSet {
                format_version,
                update_set,
            } => {
                if *format_version != E2EE_FORMAT_VERSION {
                    return Err(PairingError::UnsupportedVersion);
                }
                update_set.validate()
            }
            Self::EpochBarrier {
                format_version,
                stream_route,
                barrier,
            } => {
                if *format_version != E2EE_FORMAT_VERSION {
                    return Err(PairingError::UnsupportedVersion);
                }
                if is_zero(stream_route.as_bytes()) {
                    return Err(PairingError::InvalidField("epoch barrier stream route"));
                }
                barrier.validate()
            }
            Self::DirectoryCurrent {
                format_version,
                status,
            } => {
                if *format_version != E2EE_FORMAT_VERSION
                    || *format_version != status.format_version
                {
                    return Err(PairingError::UnsupportedVersion);
                }
                status.validate()
            }
            Self::StreamBinding {
                format_version,
                binding,
            } => {
                if *format_version != E2EE_FORMAT_VERSION
                    || *format_version != binding.format_version
                {
                    return Err(PairingError::UnsupportedVersion);
                }
                binding.validate()
            }
        }
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, PairingError> {
        self.validate()?;
        let mut encoder = Enc::new();
        encoder.domain(b"AgentDeck/KeyControlV1\0");
        match self {
            Self::UpdateSet {
                format_version,
                update_set,
            } => {
                encoder.u8(0);
                encoder.u16(*format_version);
                encoder.bytes(&update_set.canonical_bytes()?);
            }
            Self::EpochBarrier {
                format_version,
                stream_route,
                barrier,
            } => {
                encoder.u8(1);
                encoder.u16(*format_version);
                encoder.bytes(stream_route.as_bytes());
                encoder.bytes(&barrier.canonical_bytes()?);
            }
            Self::DirectoryCurrent {
                format_version,
                status,
            } => {
                encoder.u8(2);
                encoder.u16(*format_version);
                encoder.bytes(&status.canonical_bytes()?);
            }
            Self::StreamBinding {
                format_version,
                binding,
            } => {
                encoder.u8(3);
                encoder.u16(*format_version);
                encoder.bytes(&binding.canonical_bytes()?);
            }
        }
        let bytes = encoder.finish();
        if bytes.len() > KEY_CONTROL_MAX_CANONICAL_BYTES {
            return Err(PairingError::SizeLimit("key control"));
        }
        Ok(bytes)
    }

    pub fn canonical_sha256(&self) -> Result<[u8; 32], PairingError> {
        Ok(sha256(&self.canonical_bytes()?))
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, PairingError> {
        if bytes.len() > KEY_CONTROL_MAX_CANONICAL_BYTES {
            return Err(PairingError::SizeLimit("key control"));
        }
        let mut decoder = ControlDecoder::new(bytes);
        decoder.domain(b"AgentDeck/KeyControlV1\0")?;
        let kind = decoder.u8()?;
        let format_version = decoder.u16()?;
        let value = match kind {
            0 => Self::UpdateSet {
                format_version,
                update_set: KeyUpdateSetV1::from_canonical_bytes(
                    decoder.bytes(KEY_UPDATE_SET_MAX_CANONICAL_BYTES)?,
                )?,
            },
            1 => Self::EpochBarrier {
                format_version,
                stream_route: StreamRouteId::from_bytes(decoder.fixed_bytes()?),
                barrier: EpochBarrierV1::from_canonical_bytes(
                    decoder.bytes(KEY_CONTROL_SMALL_CANONICAL_BYTES)?,
                )?,
            },
            2 => Self::DirectoryCurrent {
                format_version,
                status: DirectoryCurrentV1::from_canonical_bytes(
                    decoder.bytes(KEY_CONTROL_SMALL_CANONICAL_BYTES)?,
                )?,
            },
            3 => Self::StreamBinding {
                format_version,
                binding: StreamBindingV1::from_canonical_bytes(
                    decoder.bytes(STREAM_BINDING_MAX_CANONICAL_BYTES)?,
                )?,
            },
            _ => return Err(PairingError::InvalidEncoding("key control kind")),
        };
        decoder.finish()?;
        value.validate()?;
        if value.canonical_bytes()?.as_slice() != bytes {
            return Err(PairingError::InvalidEncoding("non-canonical key control"));
        }
        Ok(value)
    }
}

impl EpochBarrierV1 {
    pub fn validate(&self) -> Result<(), PairingError> {
        let next_stream_seq = self
            .stream_cursor
            .checked_next()
            .map_err(|_| PairingError::InvalidField("exhausted epoch barrier cursor"))?;
        let next_epoch = self
            .old_epoch
            .checked_add(1)
            .ok_or(PairingError::InvalidField("exhausted epoch barrier epoch"))?;
        // `old=0,new=1` 是首个 remote member 加入已有本机 stream 时的显式
        // pre-shared-key sentinel；后续 rotation 仍严格要求相邻正 epoch。
        if is_zero(self.stream_generation.as_bytes())
            || self.new_epoch != next_epoch
            || self.new_epoch == 0
            || self.key_directory_revision.value() == 0
            || next_stream_seq == u64::MAX
        {
            return Err(PairingError::InvalidField("epoch barrier"));
        }
        validate_inner_cursor(&self.inner_cursor)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, PairingError> {
        self.validate()?;
        let mut encoder = Enc::new();
        encoder.domain(b"AgentDeck/EpochBarrierV1\0");
        encoder.bytes(self.stream_generation.as_bytes());
        encoder.cursor(&self.stream_cursor);
        encode_inner_cursor(&mut encoder, &self.inner_cursor);
        encoder.u64(self.old_epoch);
        encoder.u64(self.new_epoch);
        encoder.u64(self.key_directory_revision.value());
        Ok(encoder.finish())
    }

    pub fn canonical_sha256(&self) -> Result<[u8; 32], PairingError> {
        Ok(sha256(&self.canonical_bytes()?))
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, PairingError> {
        if bytes.len() > KEY_CONTROL_SMALL_CANONICAL_BYTES {
            return Err(PairingError::SizeLimit("epoch barrier"));
        }
        let mut decoder = ControlDecoder::new(bytes);
        decoder.domain(b"AgentDeck/EpochBarrierV1\0")?;
        let value = Self {
            stream_generation: StreamGenerationId::from_bytes(decoder.fixed_bytes()?),
            stream_cursor: decoder.cursor()?,
            inner_cursor: decoder.inner_cursor()?,
            old_epoch: decoder.u64()?,
            new_epoch: decoder.u64()?,
            key_directory_revision: KeyDirectoryRevision::new(decoder.u64()?),
        };
        decoder.finish()?;
        value.validate()?;
        if value.canonical_bytes()?.as_slice() != bytes {
            return Err(PairingError::InvalidEncoding("non-canonical epoch barrier"));
        }
        Ok(value)
    }
}

/// 设备看到已签名的未知更高 revision/epoch 后发出的有界 KeySync 请求。该 DTO 在进入
/// RuntimeCore 前由 RemoteLink 消费；daemon 只验证并冻结 `attempt` 为 1..=3。
/// 30 秒绝对 deadline 由 P4.6 CLI / P5 Swift endpoint 状态机持有。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KeySyncRequestV1 {
    pub format_version: u16,
    pub runtime_protocol_version: u16,
    pub relay_protocol_version: u16,
    pub machine_route: MachineRouteId,
    pub device_route: DeviceRouteId,
    pub grant_serial: GrantSerial,
    pub root_trust_epoch: TrustEpoch,
    pub known_key_directory_revision: KeyDirectoryRevision,
    pub requested_key_directory_revision: KeyDirectoryRevision,
    pub key_id: KeyId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_route: Option<StreamRouteId>,
    pub attempt: u8,
}

impl KeySyncRequestV1 {
    pub fn validate(&self) -> Result<(), PairingError> {
        validate_authority(
            self.format_version,
            self.runtime_protocol_version,
            self.relay_protocol_version,
            self.machine_route,
            self.device_route,
            self.grant_serial,
            self.root_trust_epoch,
        )?;
        validate_stream_shape(self.key_id.purpose, self.stream_route)?;
        if self.requested_key_directory_revision.value()
            <= self.known_key_directory_revision.value()
            || self.key_id.epoch == 0
            || !(1..=3).contains(&self.attempt)
        {
            return Err(PairingError::InvalidField("key sync request"));
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, PairingError> {
        self.validate()?;
        let mut encoder = Enc::new();
        encoder.domain(b"AgentDeck/KeySyncRequestV1\0");
        encode_authority(
            &mut encoder,
            AuthorityFields {
                format_version: self.format_version,
                runtime_protocol_version: self.runtime_protocol_version,
                relay_protocol_version: self.relay_protocol_version,
                machine_route: self.machine_route,
                device_route: self.device_route,
                grant_serial: self.grant_serial,
                root_trust_epoch: self.root_trust_epoch,
            },
        );
        encoder.u64(self.known_key_directory_revision.value());
        encoder.u64(self.requested_key_directory_revision.value());
        encoder.u8(self.key_id.purpose.tag());
        encoder.u64(self.key_id.epoch);
        encoder.opt_id16(self.stream_route.as_ref().map(|route| route.as_bytes()));
        encoder.u8(self.attempt);
        Ok(encoder.finish())
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, PairingError> {
        let mut decoder = bounded_small_decoder(bytes, "key sync request")?;
        decoder.domain(b"AgentDeck/KeySyncRequestV1\0")?;
        let authority = decoder.authority()?;
        let value = Self {
            format_version: authority.format_version,
            runtime_protocol_version: authority.runtime_protocol_version,
            relay_protocol_version: authority.relay_protocol_version,
            machine_route: authority.machine_route,
            device_route: authority.device_route,
            grant_serial: authority.grant_serial,
            root_trust_epoch: authority.root_trust_epoch,
            known_key_directory_revision: KeyDirectoryRevision::new(decoder.u64()?),
            requested_key_directory_revision: KeyDirectoryRevision::new(decoder.u64()?),
            key_id: KeyId {
                purpose: decode_key_purpose(decoder.u8()?)?,
                epoch: decoder.u64()?,
            },
            stream_route: decoder.optional_stream_route()?,
            attempt: decoder.u8()?,
        };
        finish_small(value, decoder, bytes, Self::canonical_bytes)
    }
}

/// 设备已安装 exact update set 的 authenticated ACK。DeviceSign sealed-blob signature 提供
/// 真实性；DTO 继续绑定完整 authority 与 set canonical hash，Relay RouteAccepted 不可替代它。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KeyUpdateAckV1 {
    pub format_version: u16,
    pub runtime_protocol_version: u16,
    pub relay_protocol_version: u16,
    pub machine_route: MachineRouteId,
    pub device_route: DeviceRouteId,
    pub grant_serial: GrantSerial,
    pub root_trust_epoch: TrustEpoch,
    pub key_directory_revision: KeyDirectoryRevision,
    #[serde(with = "crate::e2ee::b64_32")]
    #[schemars(with = "String")]
    pub update_set_sha256: [u8; 32],
}

impl KeyUpdateAckV1 {
    pub fn validate(&self) -> Result<(), PairingError> {
        validate_authority(
            self.format_version,
            self.runtime_protocol_version,
            self.relay_protocol_version,
            self.machine_route,
            self.device_route,
            self.grant_serial,
            self.root_trust_epoch,
        )?;
        if self.key_directory_revision.value() == 0 || is_zero(&self.update_set_sha256) {
            return Err(PairingError::InvalidField("key update ACK"));
        }
        Ok(())
    }

    pub fn validate_for_update_set(&self, set: &KeyUpdateSetV1) -> Result<(), PairingError> {
        self.validate()?;
        set.validate()?;
        if self.device_route != set.device_route
            || self.key_directory_revision != set.key_directory_revision
            || self.update_set_sha256 != set.canonical_sha256()?
        {
            return Err(PairingError::ContextBindingMismatch);
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, PairingError> {
        self.validate()?;
        let mut encoder = Enc::new();
        encoder.domain(b"AgentDeck/KeyUpdateAckV1\0");
        encode_authority(
            &mut encoder,
            AuthorityFields {
                format_version: self.format_version,
                runtime_protocol_version: self.runtime_protocol_version,
                relay_protocol_version: self.relay_protocol_version,
                machine_route: self.machine_route,
                device_route: self.device_route,
                grant_serial: self.grant_serial,
                root_trust_epoch: self.root_trust_epoch,
            },
        );
        encoder.u64(self.key_directory_revision.value());
        encoder.bytes(&self.update_set_sha256);
        Ok(encoder.finish())
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, PairingError> {
        let mut decoder = bounded_small_decoder(bytes, "key update ACK")?;
        decoder.domain(b"AgentDeck/KeyUpdateAckV1\0")?;
        let authority = decoder.authority()?;
        let value = Self {
            format_version: authority.format_version,
            runtime_protocol_version: authority.runtime_protocol_version,
            relay_protocol_version: authority.relay_protocol_version,
            machine_route: authority.machine_route,
            device_route: authority.device_route,
            grant_serial: authority.grant_serial,
            root_trust_epoch: authority.root_trust_epoch,
            key_directory_revision: KeyDirectoryRevision::new(decoder.u64()?),
            update_set_sha256: decoder.fixed_bytes()?,
        };
        finish_small(value, decoder, bytes, Self::canonical_bytes)
    }
}

/// 设备已应用 exact epoch barrier 的 authenticated ACK；只有该 ACK 才能证明 device delivery，
/// Relay 的 Publish COMMIT/RouteAccepted 仅证明 Relay 接收。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StreamAppliedAckV1 {
    pub format_version: u16,
    pub runtime_protocol_version: u16,
    pub relay_protocol_version: u16,
    pub machine_route: MachineRouteId,
    pub device_route: DeviceRouteId,
    pub grant_serial: GrantSerial,
    pub root_trust_epoch: TrustEpoch,
    pub stream_route: StreamRouteId,
    pub stream_generation: StreamGenerationId,
    /// 承载 barrier control payload 的 first-new-key outer streamSeq `D=next(C)`；barrier
    /// 自身的 `streamCursor` 仍引用 old committed cut `C`。
    pub applied_stream_seq: u64,
    pub inner_cursor: RuntimeInnerCursor,
    pub key_directory_revision: KeyDirectoryRevision,
    pub key_epoch: u64,
    #[serde(with = "crate::e2ee::b64_32")]
    #[schemars(with = "String")]
    pub epoch_barrier_sha256: [u8; 32],
}

impl StreamAppliedAckV1 {
    pub fn validate(&self) -> Result<(), PairingError> {
        validate_authority(
            self.format_version,
            self.runtime_protocol_version,
            self.relay_protocol_version,
            self.machine_route,
            self.device_route,
            self.grant_serial,
            self.root_trust_epoch,
        )?;
        if is_zero(self.stream_route.as_bytes())
            || is_zero(self.stream_generation.as_bytes())
            || self.key_directory_revision.value() == 0
            || self.key_epoch == 0
            || self.applied_stream_seq == u64::MAX
            || is_zero(&self.epoch_barrier_sha256)
        {
            return Err(PairingError::InvalidField("stream applied ACK"));
        }
        validate_inner_cursor(&self.inner_cursor)
    }

    pub fn validate_for_barrier(
        &self,
        stream_route: StreamRouteId,
        barrier: &EpochBarrierV1,
    ) -> Result<(), PairingError> {
        self.validate()?;
        barrier.validate()?;
        let expected_stream_seq = barrier
            .stream_cursor
            .checked_next()
            .map_err(|_| PairingError::ContextBindingMismatch)?;
        if self.stream_route != stream_route
            || self.stream_generation != barrier.stream_generation
            || self.applied_stream_seq != expected_stream_seq
            || self.inner_cursor != barrier.inner_cursor
            || self.key_directory_revision != barrier.key_directory_revision
            || self.key_epoch != barrier.new_epoch
            || self.epoch_barrier_sha256 != barrier.canonical_sha256()?
        {
            return Err(PairingError::ContextBindingMismatch);
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, PairingError> {
        self.validate()?;
        let mut encoder = Enc::new();
        encoder.domain(b"AgentDeck/StreamAppliedAckV1\0");
        encode_authority(
            &mut encoder,
            AuthorityFields {
                format_version: self.format_version,
                runtime_protocol_version: self.runtime_protocol_version,
                relay_protocol_version: self.relay_protocol_version,
                machine_route: self.machine_route,
                device_route: self.device_route,
                grant_serial: self.grant_serial,
                root_trust_epoch: self.root_trust_epoch,
            },
        );
        encoder.bytes(self.stream_route.as_bytes());
        encoder.bytes(self.stream_generation.as_bytes());
        encoder.u64(self.applied_stream_seq);
        encode_inner_cursor(&mut encoder, &self.inner_cursor);
        encoder.u64(self.key_directory_revision.value());
        encoder.u64(self.key_epoch);
        encoder.bytes(&self.epoch_barrier_sha256);
        Ok(encoder.finish())
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, PairingError> {
        let mut decoder = bounded_small_decoder(bytes, "stream applied ACK")?;
        decoder.domain(b"AgentDeck/StreamAppliedAckV1\0")?;
        let authority = decoder.authority()?;
        let value = Self {
            format_version: authority.format_version,
            runtime_protocol_version: authority.runtime_protocol_version,
            relay_protocol_version: authority.relay_protocol_version,
            machine_route: authority.machine_route,
            device_route: authority.device_route,
            grant_serial: authority.grant_serial,
            root_trust_epoch: authority.root_trust_epoch,
            stream_route: StreamRouteId::from_bytes(decoder.fixed_bytes()?),
            stream_generation: StreamGenerationId::from_bytes(decoder.fixed_bytes()?),
            applied_stream_seq: decoder.u64()?,
            inner_cursor: decoder.inner_cursor()?,
            key_directory_revision: KeyDirectoryRevision::new(decoder.u64()?),
            key_epoch: decoder.u64()?,
            epoch_barrier_sha256: decoder.fixed_bytes()?,
        };
        finish_small(value, decoder, bytes, Self::canonical_bytes)
    }
}

/// Device→daemon 的中立 key-control carrier。它在 DeviceCommandTxKey 保护的
/// `SealedPayloadKind::KeyUpdate` 明文内出现，RemoteLink 在 RuntimeCore 前消费；
/// Relay outer 仍只路由 opaque `Send`。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum KeyControlRequestV1 {
    KeySync { request: KeySyncRequestV1 },
    KeyUpdateAck { ack: KeyUpdateAckV1 },
    StreamAppliedAck { ack: StreamAppliedAckV1 },
}

impl KeyControlRequestV1 {
    #[must_use]
    pub fn key_sync(request: KeySyncRequestV1) -> Self {
        Self::KeySync { request }
    }

    #[must_use]
    pub fn key_update_ack(ack: KeyUpdateAckV1) -> Self {
        Self::KeyUpdateAck { ack }
    }

    #[must_use]
    pub fn stream_applied_ack(ack: StreamAppliedAckV1) -> Self {
        Self::StreamAppliedAck { ack }
    }

    #[must_use]
    pub const fn sealed_payload_kind(&self) -> SealedPayloadKind {
        SealedPayloadKind::KeyUpdate
    }

    pub fn validate(&self) -> Result<(), PairingError> {
        match self {
            Self::KeySync { request } => request.validate(),
            Self::KeyUpdateAck { ack } => ack.validate(),
            Self::StreamAppliedAck { ack } => ack.validate(),
        }
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, PairingError> {
        self.validate()?;
        let mut encoder = Enc::new();
        encoder.domain(b"AgentDeck/KeyControlRequestV1\0");
        match self {
            Self::KeySync { request } => {
                encoder.u8(0);
                encoder.bytes(&request.canonical_bytes()?);
            }
            Self::KeyUpdateAck { ack } => {
                encoder.u8(1);
                encoder.bytes(&ack.canonical_bytes()?);
            }
            Self::StreamAppliedAck { ack } => {
                encoder.u8(2);
                encoder.bytes(&ack.canonical_bytes()?);
            }
        }
        let bytes = encoder.finish();
        if bytes.len() > KEY_CONTROL_SMALL_CANONICAL_BYTES {
            return Err(PairingError::SizeLimit("key-control request"));
        }
        Ok(bytes)
    }

    pub fn canonical_sha256(&self) -> Result<[u8; 32], PairingError> {
        Ok(sha256(&self.canonical_bytes()?))
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, PairingError> {
        let mut decoder = bounded_small_decoder(bytes, "key-control request")?;
        decoder.domain(b"AgentDeck/KeyControlRequestV1\0")?;
        let value = match decoder.u8()? {
            0 => Self::key_sync(KeySyncRequestV1::from_canonical_bytes(
                decoder.bytes(KEY_CONTROL_SMALL_CANONICAL_BYTES)?,
            )?),
            1 => Self::key_update_ack(KeyUpdateAckV1::from_canonical_bytes(
                decoder.bytes(KEY_CONTROL_SMALL_CANONICAL_BYTES)?,
            )?),
            2 => Self::stream_applied_ack(StreamAppliedAckV1::from_canonical_bytes(
                decoder.bytes(KEY_CONTROL_SMALL_CANONICAL_BYTES)?,
            )?),
            _ => {
                return Err(PairingError::InvalidEncoding("key-control request kind"));
            }
        };
        decoder.finish()?;
        value.validate()?;
        if value.canonical_bytes()?.as_slice() != bytes {
            return Err(PairingError::InvalidEncoding(
                "non-canonical key-control request",
            ));
        }
        Ok(value)
    }
}

fn validate_inner_cursor(cursor: &RuntimeInnerCursor) -> Result<(), PairingError> {
    match cursor {
        RuntimeInnerCursor::Catalog { .. } => Ok(()),
        RuntimeInnerCursor::Conversation {
            conversation_id, ..
        } => {
            let length = conversation_id.as_str().len();
            if length == 0 || length > KEY_CONTROL_MAX_ID_BYTES {
                return Err(PairingError::SizeLimit("key-control conversation identity"));
            }
            Ok(())
        }
    }
}

fn encode_inner_cursor(encoder: &mut Enc, cursor: &RuntimeInnerCursor) {
    match cursor {
        RuntimeInnerCursor::Catalog { cursor } => {
            encoder.u8(0);
            encoder.cursor(cursor);
        }
        RuntimeInnerCursor::Conversation {
            conversation_id,
            cursor,
        } => {
            encoder.u8(1);
            encoder.str(conversation_id.as_str());
            encoder.cursor(cursor);
        }
    }
}

fn decode_key_purpose(tag: u8) -> Result<KeyPurpose, PairingError> {
    match tag {
        0 => Ok(KeyPurpose::Catalog),
        1 => Ok(KeyPurpose::ConversationDek),
        2 => Ok(KeyPurpose::DeviceCommandTx),
        3 => Ok(KeyPurpose::DeviceReplyTx),
        _ => Err(PairingError::InvalidEncoding("key-control key purpose")),
    }
}

fn bounded_small_decoder<'a>(
    bytes: &'a [u8],
    field: &'static str,
) -> Result<ControlDecoder<'a>, PairingError> {
    if bytes.len() > KEY_CONTROL_SMALL_CANONICAL_BYTES {
        return Err(PairingError::SizeLimit(field));
    }
    Ok(ControlDecoder::new(bytes))
}

fn finish_small<T>(
    value: T,
    decoder: ControlDecoder<'_>,
    input: &[u8],
    encode: impl Fn(&T) -> Result<Vec<u8>, PairingError>,
) -> Result<T, PairingError>
where
    T: ValidateControl,
{
    decoder.finish()?;
    value.validate_control()?;
    if encode(&value)?.as_slice() != input {
        return Err(PairingError::InvalidEncoding(
            "non-canonical key-control value",
        ));
    }
    Ok(value)
}

trait ValidateControl {
    fn validate_control(&self) -> Result<(), PairingError>;
}

impl ValidateControl for KeySyncRequestV1 {
    fn validate_control(&self) -> Result<(), PairingError> {
        self.validate()
    }
}

impl ValidateControl for KeyUpdateAckV1 {
    fn validate_control(&self) -> Result<(), PairingError> {
        self.validate()
    }
}

impl ValidateControl for StreamAppliedAckV1 {
    fn validate_control(&self) -> Result<(), PairingError> {
        self.validate()
    }
}

impl ValidateControl for DirectoryCurrentV1 {
    fn validate_control(&self) -> Result<(), PairingError> {
        self.validate()
    }
}

impl ValidateControl for StreamBindingV1 {
    fn validate_control(&self) -> Result<(), PairingError> {
        self.validate()
    }
}

struct AuthorityFields {
    format_version: u16,
    runtime_protocol_version: u16,
    relay_protocol_version: u16,
    machine_route: MachineRouteId,
    device_route: DeviceRouteId,
    grant_serial: GrantSerial,
    root_trust_epoch: TrustEpoch,
}

struct ControlDecoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> ControlDecoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], PairingError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(PairingError::InvalidEncoding("key-control offset overflow"))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(PairingError::InvalidEncoding("truncated key-control bytes"))?;
        self.offset = end;
        Ok(value)
    }

    fn domain(&mut self, expected: &[u8]) -> Result<(), PairingError> {
        if self.take(expected.len())? != expected {
            return Err(PairingError::InvalidEncoding(
                "key-control domain separator",
            ));
        }
        Ok(())
    }

    fn u8(&mut self) -> Result<u8, PairingError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, PairingError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().map_err(
            |_| PairingError::InvalidEncoding("key-control u16"),
        )?))
    }

    fn u32(&mut self) -> Result<u32, PairingError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().map_err(
            |_| PairingError::InvalidEncoding("key-control u32"),
        )?))
    }

    fn u64(&mut self) -> Result<u64, PairingError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().map_err(
            |_| PairingError::InvalidEncoding("key-control u64"),
        )?))
    }

    fn bytes(&mut self, maximum: usize) -> Result<&'a [u8], PairingError> {
        let length = self.u32()? as usize;
        if length > maximum {
            return Err(PairingError::SizeLimit("key-control field"));
        }
        self.take(length)
    }

    fn fixed_bytes<const N: usize>(&mut self) -> Result<[u8; N], PairingError> {
        self.bytes(N)?
            .try_into()
            .map_err(|_| PairingError::InvalidEncoding("key-control fixed field"))
    }

    fn optional_stream_route(&mut self) -> Result<Option<StreamRouteId>, PairingError> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(StreamRouteId::from_bytes(
                self.take(16)?
                    .try_into()
                    .map_err(|_| PairingError::InvalidEncoding("key-control stream route"))?,
            ))),
            _ => Err(PairingError::InvalidEncoding(
                "key-control optional stream route",
            )),
        }
    }

    fn cursor(&mut self) -> Result<StreamCursor, PairingError> {
        match self.u8()? {
            0 => Ok(StreamCursor::BeforeFirst),
            1 => Ok(StreamCursor::At(self.u64()?)),
            _ => Err(PairingError::InvalidEncoding("key-control cursor")),
        }
    }

    fn inner_cursor(&mut self) -> Result<RuntimeInnerCursor, PairingError> {
        match self.u8()? {
            0 => Ok(RuntimeInnerCursor::Catalog {
                cursor: self.cursor()?,
            }),
            1 => {
                let id = self.bytes(KEY_CONTROL_MAX_ID_BYTES)?;
                let id = std::str::from_utf8(id)
                    .map_err(|_| PairingError::InvalidEncoding("key-control conversation id"))?;
                Ok(RuntimeInnerCursor::Conversation {
                    conversation_id: ConversationId::new(id),
                    cursor: self.cursor()?,
                })
            }
            _ => Err(PairingError::InvalidEncoding("key-control inner cursor")),
        }
    }

    fn authority(&mut self) -> Result<AuthorityFields, PairingError> {
        Ok(AuthorityFields {
            format_version: self.u16()?,
            runtime_protocol_version: self.u16()?,
            relay_protocol_version: self.u16()?,
            machine_route: MachineRouteId::from_bytes(self.fixed_bytes()?),
            device_route: DeviceRouteId::from_bytes(self.fixed_bytes()?),
            grant_serial: GrantSerial::new(self.u64()?),
            root_trust_epoch: TrustEpoch::new(self.u64()?),
        })
    }

    fn finish(self) -> Result<(), PairingError> {
        if self.offset != self.bytes.len() {
            return Err(PairingError::InvalidEncoding("trailing key-control bytes"));
        }
        Ok(())
    }
}
