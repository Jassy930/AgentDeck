//! Relay v2 identity newtypes（design §6.6 / §7.3）。
//!
//! 两类身份，语义严格不同：
//!
//! - **128-bit 随机 route / generation / server / key ID**：newtype 包 `[u8; 16]`，
//!   **故意不实现 `Ord`/`PartialOrd`**——随机 ID 不可比较大小、不可复用，只做相等/
//!   哈希去重。提供 `random()` 随机构造与 base64 wire 表示。
//! - **单调 u64（trust epoch / link generation / grant serial / key-directory revision）**：
//!   各自 authority 分配的无符号整数；`next()` 达到 `u64::MAX` 返回 typed
//!   [`MonotonicError`]，**禁止 wrap**，要求 trust reset / rekey。
//!
//! 随机 ID 不可比较（编译期证明）：
//! ```compile_fail
//! use agentdeck_protocol::relay_v2::id::StreamRouteId;
//! let a = StreamRouteId::from_bytes([0u8; 16]);
//! let b = StreamRouteId::from_bytes([1u8; 16]);
//! let _ = a < b; // 随机 route id 不实现 PartialOrd，此处必须编译失败
//! ```

use rand::RngCore;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// 16-byte 数组的 base64 wire 编解码（与既有 `b64_hash` 风格一致）。
pub(crate) mod b64_16 {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 16], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 16], D::Error> {
        let s = String::deserialize(d)?;
        let raw = STANDARD
            .decode(s.as_bytes())
            .map_err(serde::de::Error::custom)?;
        raw.try_into()
            .map_err(|_| serde::de::Error::custom("128-bit id must decode to exactly 16 bytes"))
    }
}

/// 32-byte 数组的 base64 wire 编解码。
pub(crate) mod b64_32 {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        let raw = STANDARD
            .decode(s.as_bytes())
            .map_err(serde::de::Error::custom)?;
        raw.try_into()
            .map_err(|_| serde::de::Error::custom("32-byte value must decode to exactly 32 bytes"))
    }
}

/// 64-byte 数组（Ed25519 签名）的 base64 wire 编解码。
pub(crate) mod b64_64 {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        let s = String::deserialize(d)?;
        let raw = STANDARD
            .decode(s.as_bytes())
            .map_err(serde::de::Error::custom)?;
        raw.try_into()
            .map_err(|_| serde::de::Error::custom("signature must decode to exactly 64 bytes"))
    }
}

/// 可变长 bytes 的 base64 wire 编解码（sealed blob / wrapped key 等）。
pub(crate) mod b64_vec {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        STANDARD
            .decode(s.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}

/// 定义一个 128-bit 随机 ID newtype：`[u8; 16]`，base64 wire，**不实现 Ord/PartialOrd**。
macro_rules! random_id_128 {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
        #[serde(transparent)]
        pub struct $name(
            #[serde(with = "b64_16")]
            #[schemars(with = "String")]
            pub [u8; 16],
        );

        impl $name {
            /// 从固定 16 bytes 构造（fixture / 反序列化后）。
            pub const fn from_bytes(bytes: [u8; 16]) -> Self {
                Self(bytes)
            }

            /// 原始 16 bytes。
            pub fn as_bytes(&self) -> &[u8; 16] {
                &self.0
            }

            /// 加密随机生成一个新的 128-bit ID（`OsRng`）。
            pub fn random() -> Self {
                let mut b = [0u8; 16];
                rand::rngs::OsRng.fill_bytes(&mut b);
                Self(b)
            }

            /// 带类型域的 SHA-256 脱敏短 hash（前 4 digest bytes 的 hex）——供日志关联，
            /// 绝不直接暴露 route 原始前缀或完整 ID（design §12.3）。
            pub fn redacted(&self) -> String {
                let mut hasher = Sha256::new();
                hasher.update(b"agentdeck-relay-log-route-v1\0");
                hasher.update(stringify!($name).as_bytes());
                hasher.update(self.0);
                hasher.finalize()[..4]
                    .iter()
                    .map(|x| format!("{x:02x}"))
                    .collect()
            }
        }
    };
}

random_id_128!(
    /// 随机 machine route ID（一台被控机器一个 route，永不复用）。
    MachineRouteId
);
random_id_128!(
    /// 随机 device route ID（一台设备一个 route，永不复用）。
    DeviceRouteId
);
random_id_128!(
    /// 随机 stream route ID。
    StreamRouteId
);
random_id_128!(
    /// 随机 request route ID（在线 Send/Reply 关联）。
    RequestRouteId
);
random_id_128!(
    /// 随机 pair route ID（配对通道）。
    PairRouteId
);
random_id_128!(
    /// 随机 stream generation ID（每次 RegisterStream 新建，不做大小比较）。
    StreamGenerationId
);
random_id_128!(
    /// 随机 root key ID（machine trust anchor 的一部分；换 root 走 trust reset）。
    RootKeyId
);
random_id_128!(
    /// 随机 Relay server ID（绑定签名 transcript，防跨 Relay 重放）。
    RelayServerId
);
random_id_128!(
    /// 随机 connection instance ID（绑定单次连接的 challenge transcript）。
    ConnectionInstanceId
);

/// 单调 u64 到达上界：必须 trust reset / rekey，禁止 wrap。
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MonotonicError {
    #[error("monotonic counter reached u64::MAX; requires reset/rekey and must not wrap")]
    Exhausted,
}

/// 定义一个单调 u64 newtype：可比较（这正是它与随机 ID 的区别），`next()` 拒绝 wrap。
macro_rules! monotonic_u64 {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(
            Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
            JsonSchema,
        )]
        #[serde(transparent)]
        pub struct $name(pub u64);

        impl $name {
            pub const ZERO: Self = Self(0);

            pub const fn new(value: u64) -> Self {
                Self(value)
            }

            pub const fn value(&self) -> u64 {
                self.0
            }

            /// 下一单调值；到 `u64::MAX` 返回 typed error（禁止 wrap，要求 reset/rekey）。
            pub fn next(&self) -> Result<Self, MonotonicError> {
                self.0
                    .checked_add(1)
                    .map(Self)
                    .ok_or(MonotonicError::Exhausted)
            }

            /// authority/verifier 只接受严格更高值：candidate 是否高于 self。
            pub fn accepts_higher(&self, candidate: &Self) -> bool {
                candidate.0 > self.0
            }
        }
    };
}

monotonic_u64!(
    /// machine trust epoch（trust reset 时递增；换 root 才变更）。
    TrustEpoch
);
monotonic_u64!(
    /// MachineLink / MachineDataSign 的 cert generation。
    LinkGeneration
);
monotonic_u64!(
    /// DeviceGrant serial（renewal 递增，旧 serial tombstone）。
    GrantSerial
);
monotonic_u64!(
    /// key directory revision（成员/epoch 变化时递增）。
    KeyDirectoryRevision
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacted_route_is_domain_separated_hash_not_raw_prefix() {
        let machine = MachineRouteId::from_bytes([0xaa; 16]);
        let device = DeviceRouteId::from_bytes([0xaa; 16]);
        assert_eq!(machine.redacted().len(), 8);
        assert_ne!(machine.redacted(), "aaaaaaaa");
        assert_ne!(machine.redacted(), device.redacted());
        assert_eq!(machine.redacted(), machine.redacted());
    }
}
