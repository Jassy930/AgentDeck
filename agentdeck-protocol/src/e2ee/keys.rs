//! E2EE 密钥层级、key directory / update 与 epoch barrier（design §7.2）。
//!
//! HPKE 只封装这些小型对称 key；事件/命令内容用对称 AEAD。每个对称 key 只有一个发送
//! 方向。所有 key directory/update 都带 MachineDataSign 签名和单调 `keyDirectoryRevision`。

use crate::e2ee::Enc;
use crate::relay_v2::auth::Ed25519Signature;
use crate::relay_v2::cursor::StreamCursor;
use crate::relay_v2::id::{
    DeviceRouteId, GrantSerial, KeyDirectoryRevision, MachineRouteId, StreamGenerationId,
    TrustEpoch, b64_vec,
};
use crate::runtime::sync::RuntimeInnerCursor;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

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
    pub entries: Vec<KeyDirectoryEntry>,
    pub signature: Ed25519Signature,
}

/// 单个 key 更新（HPKE 封装给某设备；MachineDataSign/Root 签名）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KeyUpdateV1 {
    pub key_directory_revision: KeyDirectoryRevision,
    pub key_id: KeyId,
    pub device_route: DeviceRouteId,
    #[serde(with = "b64_vec")]
    #[schemars(with = "String")]
    pub enc: Vec<u8>,
    #[serde(with = "b64_vec")]
    #[schemars(with = "String")]
    pub wrapped_key: Vec<u8>,
    pub signature: Ed25519Signature,
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
    pub machine_route: MachineRouteId,
    pub device_route: DeviceRouteId,
    pub grant_serial: GrantSerial,
    pub root_trust_epoch: TrustEpoch,
    pub key_directory_revision: KeyDirectoryRevision,
    pub key_purpose: KeyPurpose,
    pub key_epoch: u64,
}

impl KeyUpdateInfoV1 {
    /// 确定性长度前缀编码（HPKE `info` bytes）。
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Enc::new();
        e.domain(b"AgentDeck/KeyUpdateInfoV1\0");
        e.u16(self.e2ee_format_version);
        e.u16(self.runtime_protocol_version);
        e.bytes(self.machine_route.as_bytes());
        e.bytes(self.device_route.as_bytes());
        e.u64(self.grant_serial.value());
        e.u64(self.root_trust_epoch.value());
        e.u64(self.key_directory_revision.value());
        e.u8(self.key_purpose.tag());
        e.u64(self.key_epoch);
        e.finish()
    }
}
