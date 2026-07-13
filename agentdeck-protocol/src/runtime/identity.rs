//! Runtime v1 稳定中立身份 newtypes（design §8.1 / RC-9）。
//!
//! 所有业务身份都用中立、不含 vendor 字样的 newtype 表达：
//! - `ConversationId`：daemon 在 adapter 启动前生成，跨 turn/设备稳定。
//! - `TurnId`：每次实际执行新生成；approval/cancel 匹配 conversation + turn。
//! - `EventId`：每条 canonical event 的唯一去重 ID。
//! - `ItemId`/`EntityId`：多条 delta 更新同一 UI item/entity 时的稳定聚合 ID。
//! - `CommandId`：关联 prompt row / receipt / canonical UserMessage。
//! - `AdapterStateKey`：随机中立 handle；vendor resume reference **永不进入 wire**。
//!
//! 真实 vendor thread/session/turn 身份禁止出现在此层（由 neutrality 测试守护）。

use schemars::schema::{InstanceType, Schema, SchemaObject, StringValidation};
use schemars::{JsonSchema, r#gen::SchemaGenerator};
use serde::{Deserialize, Serialize};

/// RuntimeEnvelope messageId 的最大 UTF-8 字节数。与 JSON/UDS worst-case framing
/// 证明及 compact `ADRT1` carrier 共同冻结。
pub const MAX_MESSAGE_ID_BYTES: usize = 1024;
/// TransferEnvelope transferId 的最大 UTF-8 字节数。
pub const MAX_TRANSFER_ID_BYTES: usize = 1024;

/// 定义一个 `#[serde(transparent)]` 的 String-backed 中立 ID newtype。
macro_rules! string_id {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(
            Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
        )]
        #[serde(transparent)]
        pub struct $name(pub String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Self {
                Self(value.into())
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl From<&str> for $name {
            fn from(value: &str) -> Self {
                Self(value.to_owned())
            }
        }

        impl From<String> for $name {
            fn from(value: String) -> Self {
                Self(value)
            }
        }
    };
}

/// 定义一个 wire 上有明确 UTF-8 byte cap 的 String-backed ID。
///
/// `new` 保持现有调用点的轻量构造语义；所有 serde ingress/egress 与使用该 ID 的
/// binary carrier 都 fail-close。上层需要提前判断时可调用 `is_valid_wire_value`。
macro_rules! bounded_string_id {
    ($(#[$meta:meta])* $name:ident, $max:expr) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(pub String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Self {
                Self(value.into())
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn is_valid_wire_value(&self) -> bool {
                let len = self.0.len();
                len > 0 && len <= $max
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                if !self.is_valid_wire_value() {
                    return Err(serde::ser::Error::custom(concat!(
                        stringify!($name),
                        " exceeds its UTF-8 wire bound"
                    )));
                }
                serializer.serialize_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let value = Self(String::deserialize(deserializer)?);
                if !value.is_valid_wire_value() {
                    return Err(serde::de::Error::custom(concat!(
                        stringify!($name),
                        " exceeds its UTF-8 wire bound"
                    )));
                }
                Ok(value)
            }
        }

        impl JsonSchema for $name {
            fn is_referenceable() -> bool {
                false
            }

            fn schema_name() -> String {
                stringify!($name).to_owned()
            }

            fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
                SchemaObject {
                    instance_type: Some(InstanceType::String.into()),
                    string: Some(Box::new(StringValidation {
                        min_length: Some(1),
                        max_length: Some($max as u32),
                        ..Default::default()
                    })),
                    // JSON Schema maxLength 统计 Unicode code points；这个扩展记录真正由
                    // Rust/Swift codec 强制的 UTF-8 byte cap。
                    extensions: std::iter::once((
                        "x-maxUtf8Bytes".to_owned(),
                        serde_json::json!($max),
                    ))
                    .collect(),
                    ..Default::default()
                }
                .into()
            }
        }

        impl From<&str> for $name {
            fn from(value: &str) -> Self {
                Self(value.to_owned())
            }
        }

        impl From<String> for $name {
            fn from(value: String) -> Self {
                Self(value)
            }
        }
    };
}

bounded_string_id!(
    /// 一条 RuntimeEnvelope 的唯一消息 ID（请求/回复关联用）。
    MessageId,
    MAX_MESSAGE_ID_BYTES
);
string_id!(
    /// 稳定 conversation 身份；daemon 在 adapter 启动前生成。
    ConversationId
);
string_id!(
    /// 单次执行的 turn 身份；approval/cancel 必须匹配 conversation + turn。
    TurnId
);
string_id!(
    /// canonical event 的唯一去重 ID。
    EventId
);
string_id!(
    /// 稳定 UI item 聚合 ID；多条 delta 更新同一 item 时复用。
    ItemId
);
string_id!(
    /// 稳定实体聚合 ID；跨事件更新同一 entity 时复用。
    EntityId
);
string_id!(
    /// 命令身份；关联临时 prompt row、receipt 与 canonical UserMessage。
    CommandId
);
string_id!(
    /// approval 请求身份；first-wins 裁决基于它做 compare-and-swap。
    ApprovalId
);
string_id!(
    /// daemon 生成的随机中立 adapter state handle；vendor resume ref 永不进入 wire。
    AdapterStateKey
);
string_id!(
    /// 命令 idempotency key（客户端提供的去重键）。
    IdempotencyKey
);
bounded_string_id!(
    /// 分片传输 ID（TransferEnvelope）。
    TransferId,
    MAX_TRANSFER_ID_BYTES
);
string_id!(
    /// daemon 签发的 opaque catalog 冻结分页 cursor；客户端只能原样回传。
    CatalogPageCursor
);
string_id!(
    /// pending pairing 记录 ID（local-only administration 引用）。
    PairingId
);
string_id!(
    /// 随机 device handle（撤销/授权引用；中立，不含 vendor 身份）。
    DeviceHandle
);
string_id!(
    /// 随机 stream generation ID（128-bit 随机、永不复用，不做大小比较）。
    StreamGeneration
);

/// grant serial —— 单调 64-bit 无符号；由 MachineRoot authority 分配。
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(transparent)]
pub struct GrantSerial(pub u64);

impl GrantSerial {
    pub fn new(value: u64) -> Self {
        Self(value)
    }
}
