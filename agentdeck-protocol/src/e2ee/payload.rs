//! E2EE sealed payload 与 type-state sealed blob（design §7.3）。
//!
//! [`SealedPayloadV1`] 是**密文内**的 endpoint 契约，允许引用业务 payload 类型
//! （catalog/event/command/approval…）——它只出现在 ciphertext 内，不进 Relay outer。
//!
//! type-state 强制三个不同类型的单向转换：
//!
//! `UnsignedSealedBlobV1` → `SignedSealedBlobV1` → `VerifiedSealedBlobV1`
//!
//! - Publish/outbound 只接收 [`SignedSealedBlobV1`]（`to_wire_bytes` 只在 Signed 上）。
//! - AEAD open 只接收 [`VerifiedSealedBlobV1`]（`open_plaintext` 只在 Verified 上）。
//! - 本 task 只定义类型与转换签名；真实 sign/verify/AEAD 在 P1.4。**P1 fail-closed**：
//!   `verify` 桩直接返回 `CryptoNotAvailable`，且 `VerifiedSealedBlobV1` 字段私有、
//!   不派生 `Deserialize`——P1 无法经任何公共 API 构造 Verified 实例；P4 必须显式实现
//!   真实 Ed25519 验签，链路才能跑通（RC-15）。
//!
//! type-state 编译期约束（Unsigned 不能发布、Signed 不能直接 open）：
//! ```compile_fail
//! use agentdeck_protocol::e2ee::payload::UnsignedSealedBlobV1;
//! fn f(u: UnsignedSealedBlobV1) { let _ = u.to_wire_bytes(); } // Unsigned 无 to_wire_bytes
//! ```
//! ```compile_fail
//! use agentdeck_protocol::e2ee::payload::SignedSealedBlobV1;
//! fn f(s: SignedSealedBlobV1) { let _ = s.open_plaintext(); } // 只有 Verified 能 open
//! ```

use crate::e2ee::context::OuterContextV1;
use crate::e2ee::keys::KeyId;
use crate::e2ee::{E2eeError, Enc};
use crate::relay_v2::auth::{Ed25519Signature, PublicKeyBytes};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// 业务 payload 类型引用（endpoint 契约，只在密文内）。这些词允许出现在 e2ee schema，
/// **禁止**出现在 Relay outer schema（两份 schema 独立，见 `relay_v2_neutrality`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum SealedPayloadKind {
    CatalogSnapshot,
    CatalogDelta,
    ConversationSnapshot,
    ConversationEvent,
    CommandRequest,
    CommandReceipt,
    ApprovalDecision,
    ApprovalReceipt,
    BackfillChunk,
    KeyUpdate,
    PairingMessage,
}

impl SealedPayloadKind {
    fn tag(self) -> u8 {
        match self {
            SealedPayloadKind::CatalogSnapshot => 0,
            SealedPayloadKind::CatalogDelta => 1,
            SealedPayloadKind::ConversationSnapshot => 2,
            SealedPayloadKind::ConversationEvent => 3,
            SealedPayloadKind::CommandRequest => 4,
            SealedPayloadKind::CommandReceipt => 5,
            SealedPayloadKind::ApprovalDecision => 6,
            SealedPayloadKind::ApprovalReceipt => 7,
            SealedPayloadKind::BackfillChunk => 8,
            SealedPayloadKind::KeyUpdate => 9,
            SealedPayloadKind::PairingMessage => 10,
        }
    }
}

/// 密文内 payload 头（引用业务类型，AEAD 保护）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SealedPayloadV1 {
    pub format_version: u16,
    pub payload_kind: SealedPayloadKind,
}

/// 未签名 sealed blob（outer 结构：format / keyId / epoch / revision / nonce / ciphertext）。
/// 无法发布（无 `to_wire_bytes`）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UnsignedSealedBlobV1 {
    pub format_version: u16,
    pub payload_kind: SealedPayloadKind,
    pub key_id: KeyId,
    pub key_epoch: u64,
    pub key_directory_revision: u64,
    #[serde(with = "crate::e2ee::b64_12")]
    #[schemars(with = "String")]
    pub nonce: [u8; 12],
    #[serde(with = "crate::e2ee::b64_vec")]
    #[schemars(with = "String")]
    pub ciphertext: Vec<u8>,
}

impl UnsignedSealedBlobV1 {
    pub fn new(
        payload_kind: SealedPayloadKind,
        key_id: KeyId,
        key_epoch: u64,
        key_directory_revision: u64,
        nonce: [u8; 12],
        ciphertext: Vec<u8>,
    ) -> Self {
        Self {
            format_version: super::E2EE_FORMAT_VERSION,
            payload_kind,
            key_id,
            key_epoch,
            key_directory_revision,
            nonce,
            ciphertext,
        }
    }

    /// 确定性 canonical 编码（进入签名 preimage / wire）。
    fn canonical(&self) -> Vec<u8> {
        let mut e = Enc::new();
        e.domain(b"AgentDeck/SealedBlobV1\0");
        e.u16(self.format_version);
        e.u8(self.payload_kind.tag());
        e.u8(self.key_id.purpose.tag());
        e.u64(self.key_id.epoch);
        e.u64(self.key_epoch);
        e.u64(self.key_directory_revision);
        e.bytes(&self.nonce);
        e.bytes(&self.ciphertext);
        e.finish()
    }

    /// 发送方签名 TBS preimage（design §7.3）——确定性长度前缀编码，供 crypto 侧
    /// （MachineDataSign / DeviceSign）签名与验签。
    ///
    /// 绑定：outer machine/device/stream/request route、outer stream generation +
    /// streamSeq/cursor、key epoch、inner format version + payload kind + key id +
    /// key-directory revision、nonce（含 sender counter，design §7.4）与 encrypted-section
    /// （ciphertext）的 SHA-256。**排除**签名本身，避免循环 preimage。
    ///
    /// TBS bytes 由 protocol 侧从 `context` + blob 计算，[`SignedSealedBlobV1::verify_with`]
    /// 只对这份 bytes 验签——调用方无法对任意错误字节验签并构造 [`VerifiedSealedBlobV1`]。
    pub fn sealed_blob_tbs(&self, context: &OuterContextV1) -> Vec<u8> {
        let mut e = Enc::new();
        e.domain(b"AgentDeck/SealedBlobTbsV1\0");
        // outer context（route / generation / cursor / seq / version / message key epoch）。
        e.bytes(&context.encode_aad());
        // inner 头部字段。
        e.u16(self.format_version);
        e.u8(self.payload_kind.tag());
        e.u8(self.key_id.purpose.tag());
        e.u64(self.key_id.epoch);
        e.u64(self.key_epoch);
        e.u64(self.key_directory_revision);
        e.bytes(&self.nonce);
        // encrypted-section SHA-256（design §7.3）。
        let hash: [u8; 32] = Sha256::digest(&self.ciphertext).into();
        e.bytes(&hash);
        e.finish()
    }

    /// 附加发送方签名（MachineDataSign / DeviceSign），进入 [`SignedSealedBlobV1`]。
    /// 真实签名由 P1.4 crypto 产生；此处只接受已产生的签名并推进 type-state。
    pub fn attach_signature(self, signature: Ed25519Signature) -> SignedSealedBlobV1 {
        SignedSealedBlobV1 {
            inner: self,
            signature,
        }
    }
}

/// 已签名 sealed blob。Publish/outbound 只接收本类型。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedSealedBlobV1 {
    pub inner: UnsignedSealedBlobV1,
    pub signature: Ed25519Signature,
}

impl SignedSealedBlobV1 {
    /// canonical sealed blob bytes，直接填入 Relay `SealedBlob`（design §7.3）。
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        let mut out = self.inner.canonical();
        out.extend_from_slice(&self.signature.0);
        out
    }

    /// 无 crypto verifier 的验证入口——**恒 fail-closed**。
    ///
    /// 真实 Ed25519 验签经 [`SignedSealedBlobV1::verify_with`] 由 `agentdeck-crypto`
    /// （P1.4）注入的 [`SealedBlobSignatureVerifier`] 完成；本方法不持有 verifier，故永远
    /// 返回 `Err(CryptoNotAvailable)`，保证 `VerifiedSealedBlobV1` 不会经无验签路径构造
    /// （design RC-15：共享对称 key 不能替代发送方签名）。
    pub fn verify(
        self,
        _verifying_key: &PublicKeyBytes,
    ) -> Result<VerifiedSealedBlobV1, E2eeError> {
        Err(E2eeError::CryptoNotAvailable)
    }

    /// 用注入的 [`SealedBlobSignatureVerifier`] 验证发送方签名并进入 [`VerifiedSealedBlobV1`]。
    ///
    /// TBS bytes 由 protocol 侧从 `context` + blob 计算（见
    /// [`UnsignedSealedBlobV1::sealed_blob_tbs`]），verifier 只能对这份 bytes 验签；调用方
    /// 无法对任意错误字节验签并构造 Verified。verifier 返回 `Ok` 才构造 Verified，否则透传
    /// 其 typed error（`agentdeck-crypto` 用 ed25519-dalek 实现该 trait）。
    pub fn verify_with<V: SealedBlobSignatureVerifier>(
        self,
        verifier: &V,
        context: &OuterContextV1,
    ) -> Result<VerifiedSealedBlobV1, E2eeError> {
        let tbs = self.inner.sealed_blob_tbs(context);
        verifier.verify_sealed_tbs(&tbs, &self.signature)?;
        Ok(VerifiedSealedBlobV1 { inner: self })
    }
}

/// P1.4 verifier-hook（design RC-15）：由 `agentdeck-crypto` 用 ed25519-dalek 实现真实的
/// sealed-blob 发送方验签。protocol 侧负责计算 canonical TBS bytes，本 trait 只对给定
/// bytes + 签名验签——它无法自行选择被验字节，因此不能绕过 [`SignedSealedBlobV1::verify_with`]
/// 的 type-state 约束去构造 [`VerifiedSealedBlobV1`]。
pub trait SealedBlobSignatureVerifier {
    /// 对 protocol 计算好的 sealed-blob TBS bytes 验签；`Ok(())` 表示签名有效。
    /// 失败必须返回 typed error（约定 [`E2eeError::BadSenderSignature`]）。
    fn verify_sealed_tbs(&self, tbs: &[u8], signature: &Ed25519Signature) -> Result<(), E2eeError>;
}

/// 已验证 sealed blob。AEAD open 只接收本类型。
///
/// 字段私有且**不派生 `Deserialize`**：唯一构造入口是
/// [`SignedSealedBlobV1::verify`]（P1 fail-closed，P1.4 接真实验签）。"已验证"是
/// 本地密码学判定的结果，不能从 wire 反序列化得到。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerifiedSealedBlobV1 {
    inner: SignedSealedBlobV1,
}

impl VerifiedSealedBlobV1 {
    /// AEAD 解密取明文。**P1 边界**：真实 AEAD open 在 P1.4；此处返回
    /// `CryptoNotAvailable`，确保 P1 契约永不吐出未解密内容。
    pub fn open_plaintext(&self) -> Result<Vec<u8>, E2eeError> {
        Err(E2eeError::CryptoNotAvailable)
    }

    /// 访问底层已签名 blob（例如取回签名/元数据）。
    pub fn sealed(&self) -> &SignedSealedBlobV1 {
        &self.inner
    }
}
