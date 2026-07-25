//! E2EE canonical context 契约（design §6.6 / §7）。
//!
//! 本模块与 Relay v2 outer wire（`crate::relay_v2`）并列：Relay 只看到 opaque sealed
//! blob，业务内容与授权在这里的 endpoint 侧契约中。固定 `E2EE_FORMAT_VERSION = 1`，
//! 版本轴独立（与 Relay `RELAY_PROTOCOL_VERSION = 2` 不联动）。
//!
//! 本 task（P1.2）只定义**类型、确定性编码与 type-state 转换签名**；真实密码学
//! （HPKE / AEAD / Ed25519 sign/verify）留到 P1.4。所有确定性编码（TBS / AAD /
//! HPKE info）使用本模块的 [`Enc`] 长度前缀编码，与 Relay 二进制 codec **相互独立**。

pub mod context;
pub mod key_control;
pub mod key_recovery;
pub mod keys;
pub mod pairing;
pub mod pairing_control;
pub mod payload;
pub mod schema;
pub mod tbs;

use crate::relay_v2::cursor::StreamCursor;

/// E2EE 密文/签名 wire 格式版本；独立于 Relay `RELAY_PROTOCOL_VERSION`。
pub const E2EE_FORMAT_VERSION: u16 = 1;

// —— remote.crypto.* failure codes（design §14；解密/验签失败在 endpoint 侧产生）——
pub const REMOTE_CRYPTO_BAD_CIPHERTEXT: &str = "remote.crypto.bad_ciphertext";
pub const REMOTE_CRYPTO_KEY_EPOCH_MISSING: &str = "remote.crypto.key_epoch_missing";
pub const REMOTE_CRYPTO_KEY_REVISION_ROLLBACK: &str = "remote.crypto.key_revision_rollback";
pub const REMOTE_CRYPTO_COUNTER_REPLAY: &str = "remote.crypto.counter_replay";
pub const REMOTE_CRYPTO_NONCE_REUSE: &str = "remote.crypto.nonce_reuse";
pub const REMOTE_CRYPTO_BAD_SENDER_SIGNATURE: &str = "remote.crypto.bad_sender_signature";

/// E2EE 契约层错误（P1 只承载类型/边界；真实 crypto 判定在 P1.4）。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum E2eeError {
    /// P1 边界：真实 sign/verify/AEAD 尚未接入，绝不静默返回明文。
    #[error("real cryptography (sign/verify/AEAD) lands in P1.4; unavailable in the P1 contract")]
    CryptoNotAvailable,
    #[error("bad ciphertext / AEAD tag ({})", REMOTE_CRYPTO_BAD_CIPHERTEXT)]
    BadCiphertext,
    #[error("missing key epoch ({})", REMOTE_CRYPTO_KEY_EPOCH_MISSING)]
    KeyEpochMissing,
    #[error("key revision rollback ({})", REMOTE_CRYPTO_KEY_REVISION_ROLLBACK)]
    KeyRevisionRollback,
    #[error("counter replay ({})", REMOTE_CRYPTO_COUNTER_REPLAY)]
    CounterReplay,
    #[error("nonce reuse ({})", REMOTE_CRYPTO_NONCE_REUSE)]
    NonceReuse,
    #[error("bad sender signature ({})", REMOTE_CRYPTO_BAD_SENDER_SIGNATURE)]
    BadSenderSignature,
}

// —— 确定性长度前缀编码器（TBS / AAD / HPKE info 共用；不参与 Relay 二进制 wire）——

/// 确定性、长度前缀的二进制编码器（design §6.6 / §7.4）。所有 canonical 签名/AAD/info
/// preimage 都用它，**不依赖 JSON canonicalization**。
pub(crate) struct Enc(Vec<u8>);

impl Enc {
    pub(crate) fn new() -> Self {
        Enc(Vec::new())
    }
    /// 固定域分隔前缀（raw，不加长度）。
    pub(crate) fn domain(&mut self, d: &[u8]) {
        self.0.extend_from_slice(d);
    }
    pub(crate) fn u8(&mut self, v: u8) {
        self.0.push(v);
    }
    pub(crate) fn u16(&mut self, v: u16) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }
    pub(crate) fn u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }
    /// 长度前缀 bytes（u32 big-endian 长度 + bytes）。
    pub(crate) fn bytes(&mut self, b: &[u8]) {
        self.0.extend_from_slice(&(b.len() as u32).to_be_bytes());
        self.0.extend_from_slice(b);
    }
    pub(crate) fn str(&mut self, s: &str) {
        self.bytes(s.as_bytes());
    }
    /// Option<128-bit id>：presence byte + 可选 16 raw bytes。
    pub(crate) fn opt_id16(&mut self, id: Option<&[u8; 16]>) {
        match id {
            Some(x) => {
                self.u8(1);
                self.0.extend_from_slice(x);
            }
            None => self.u8(0),
        }
    }
    pub(crate) fn opt_u64(&mut self, v: Option<u64>) {
        match v {
            Some(x) => {
                self.u8(1);
                self.u64(x);
            }
            None => self.u8(0),
        }
    }
    pub(crate) fn cursor(&mut self, c: &StreamCursor) {
        match c {
            StreamCursor::BeforeFirst => self.u8(0),
            StreamCursor::At(n) => {
                self.u8(1);
                self.u64(*n);
            }
        }
    }
    pub(crate) fn opt_cursor(&mut self, c: Option<&StreamCursor>) {
        match c {
            Some(x) => {
                self.u8(1);
                self.cursor(x);
            }
            None => self.u8(0),
        }
    }
    pub(crate) fn finish(self) -> Vec<u8> {
        self.0
    }
}

// —— base64 wire 编解码（e2ee 自有 byte 字段）——

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
            .map_err(|_| serde::de::Error::custom("value must decode to exactly 32 bytes"))
    }
}

pub(crate) mod b64_12 {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 12], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(bytes))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 12], D::Error> {
        let s = String::deserialize(d)?;
        let raw = STANDARD
            .decode(s.as_bytes())
            .map_err(serde::de::Error::custom)?;
        raw.try_into()
            .map_err(|_| serde::de::Error::custom("nonce must decode to exactly 12 bytes"))
    }
}

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

pub use context::{OuterContextError, OuterContextV1, OuterFrameKind};
pub use key_control::{
    DirectoryCurrentV1, DirectoryRevisionAdvanceV1, KEY_CONTROL_MAX_ID_BYTES,
    KEY_UPDATE_SET_MAX_CANONICAL_BYTES, KEY_UPDATE_SET_MAX_KEYS, KeyControlRequestV1, KeyControlV1,
    KeySyncRequestV1, KeyUpdateAckV1, KeyUpdateSetV1, STREAM_BINDING_MAX_CANONICAL_BYTES,
    StreamAppliedAckV1, StreamBindingV1,
};
pub use key_recovery::{
    DEVICE_KEY_RECOVERY_HPKE_ENC_BYTES, DEVICE_KEY_RECOVERY_MAX_CIPHERTEXT_BYTES,
    DeviceKeyRecoveryInfoV1, DeviceKeyRecoveryReplyV1, DeviceKeyRecoveryTbsV1,
};
pub use keys::{
    CanonicalKeyUpdateTbs, EpochBarrierV1, KeyDirectoryEntry, KeyDirectorySignatureContextV1,
    KeyDirectoryTbsV1, KeyDirectoryV1, KeyId, KeyPurpose, KeyUpdateInfoV1,
    KeyUpdateSignatureSigner, KeyUpdateSignatureVerifier, KeyUpdateTbsV1, KeyUpdateV1,
};
pub use pairing::{
    AuthorizationCapabilityV1, AuthorizationPermissionV1, AuthorizationRequestV1,
    DeviceAuthorizationV1, MachineDataSignerBindingV1, PairInviteV1, PairPendingV1,
    PairRequestInfoV1, PairRequestPlaintextV1, PairRequestV1, PairResponseInfoV1,
    PairResponsePlaintextV1, PairResponseReceivedV1, PairResponseV1, PairingEnvelopeKindV1,
    PairingEnvelopeTbsV1, PairingError,
};
pub use pairing_control::{PairPendingTbsV1, PairResponseReceivedTbsV1, PairingControlEnvelopeV1};
pub use payload::{
    SealedBlobSignatureVerifier, SealedPayloadKind, SealedPayloadV1, SignedSealedBlobV1,
    UnsignedSealedBlobV1, VerifiedSealedBlobV1,
};
pub use schema::e2ee_schema;
pub use tbs::{SignedObjectType, ToBeSignedV1};
