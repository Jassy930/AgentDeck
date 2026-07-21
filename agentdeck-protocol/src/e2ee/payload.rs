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
use crate::e2ee::keys::{KeyId, KeyPurpose};
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
    TransferPart,
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
            SealedPayloadKind::TransferPart => 11,
        }
    }

    fn from_tag(tag: u8) -> Option<Self> {
        Some(match tag {
            0 => Self::CatalogSnapshot,
            1 => Self::CatalogDelta,
            2 => Self::ConversationSnapshot,
            3 => Self::ConversationEvent,
            4 => Self::CommandRequest,
            5 => Self::CommandReceipt,
            6 => Self::ApprovalDecision,
            7 => Self::ApprovalReceipt,
            8 => Self::BackfillChunk,
            9 => Self::KeyUpdate,
            10 => Self::PairingMessage,
            11 => Self::TransferPart,
            _ => return None,
        })
    }
}

const SEALED_PAYLOAD_MAGIC: &[u8; 5] = b"ADSP1";
const SEALED_BLOB_DOMAIN: &[u8] = b"AgentDeck/SealedBlobV1\0";
const SEALED_BLOB_NONCE_BYTES: usize = 12;
const SEALED_BLOB_TAG_BYTES: usize = 16;
const SEALED_BLOB_SIGNATURE_BYTES: usize = 64;

/// 密文内 payload（业务类型 + 原始业务 bytes，整体由 AEAD 保护）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SealedPayloadV1 {
    pub format_version: u16,
    pub payload_kind: SealedPayloadKind,
    #[serde(with = "crate::e2ee::b64_vec")]
    #[schemars(with = "String")]
    pub payload: Vec<u8>,
}

impl SealedPayloadV1 {
    pub fn new(payload_kind: SealedPayloadKind, payload: Vec<u8>) -> Self {
        Self {
            format_version: super::E2EE_FORMAT_VERSION,
            payload_kind,
            payload,
        }
    }

    /// AEAD plaintext 的 compact canonical bytes：`ADSP1 | version | kind | len | payload`。
    pub fn to_plaintext_bytes(&self) -> Result<Vec<u8>, E2eeError> {
        if self.format_version != super::E2EE_FORMAT_VERSION {
            return Err(E2eeError::BadCiphertext);
        }
        let payload_len =
            u32::try_from(self.payload.len()).map_err(|_| E2eeError::BadCiphertext)?;
        let mut out = Vec::with_capacity(12 + self.payload.len());
        out.extend_from_slice(SEALED_PAYLOAD_MAGIC);
        out.extend_from_slice(&self.format_version.to_be_bytes());
        out.push(self.payload_kind.tag());
        out.extend_from_slice(&payload_len.to_be_bytes());
        out.extend_from_slice(&self.payload);
        Ok(out)
    }

    /// 只在 AEAD open 成功后调用；wrong magic/version/kind/length/trailing 都 fail-close。
    pub fn from_plaintext_bytes(bytes: &[u8]) -> Result<Self, E2eeError> {
        if bytes.len() < 12 || &bytes[..5] != SEALED_PAYLOAD_MAGIC {
            return Err(E2eeError::BadCiphertext);
        }
        let format_version = u16::from_be_bytes([bytes[5], bytes[6]]);
        if format_version != super::E2EE_FORMAT_VERSION {
            return Err(E2eeError::BadCiphertext);
        }
        let payload_kind = SealedPayloadKind::from_tag(bytes[7]).ok_or(E2eeError::BadCiphertext)?;
        let payload_len = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]) as usize;
        if payload_len != bytes.len() - 12 {
            return Err(E2eeError::BadCiphertext);
        }
        Ok(Self {
            format_version,
            payload_kind,
            payload: bytes[12..].to_vec(),
        })
    }
}

/// 未签名 sealed blob（outer 结构：format / keyId / epoch / revision / nonce / ciphertext）。
/// 无法发布（无 `to_wire_bytes`）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UnsignedSealedBlobV1 {
    pub format_version: u16,
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
        key_id: KeyId,
        key_epoch: u64,
        key_directory_revision: u64,
        nonce: [u8; 12],
        ciphertext: Vec<u8>,
    ) -> Self {
        Self {
            format_version: super::E2EE_FORMAT_VERSION,
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
        e.domain(SEALED_BLOB_DOMAIN);
        e.u16(self.format_version);
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
    /// streamSeq/cursor、key epoch、inner format version + key id +
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

    /// Relay `SealedBlob` 的严格 canonical 逆解码入口。
    ///
    /// 在复制 ciphertext 前先完成总长、固定字段、所有长度前缀与 trailing 检查；成功
    /// materialize 后再逐字节重编码核对，避免接受同一对象的第二种 wire 表示。
    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, E2eeError> {
        let minimum_bytes = SEALED_BLOB_DOMAIN.len()
            + 2
            + 1
            + 8
            + 8
            + 8
            + 4
            + SEALED_BLOB_NONCE_BYTES
            + 4
            + SEALED_BLOB_TAG_BYTES
            + SEALED_BLOB_SIGNATURE_BYTES;
        if bytes.len() < minimum_bytes || bytes.len() >= crate::relay_v2::MAX_FRAME_BYTES {
            return Err(E2eeError::BadCiphertext);
        }

        let mut cursor = 0;
        if take_wire(bytes, &mut cursor, SEALED_BLOB_DOMAIN.len())? != SEALED_BLOB_DOMAIN {
            return Err(E2eeError::BadCiphertext);
        }
        let format_version = take_wire_u16(bytes, &mut cursor)?;
        if format_version != super::E2EE_FORMAT_VERSION {
            return Err(E2eeError::BadCiphertext);
        }
        let purpose = match take_wire_u8(bytes, &mut cursor)? {
            0 => KeyPurpose::Catalog,
            1 => KeyPurpose::ConversationDek,
            2 => KeyPurpose::DeviceCommandTx,
            3 => KeyPurpose::DeviceReplyTx,
            _ => return Err(E2eeError::BadCiphertext),
        };
        let key_id_epoch = take_wire_u64(bytes, &mut cursor)?;
        let key_epoch = take_wire_u64(bytes, &mut cursor)?;
        let key_directory_revision = take_wire_u64(bytes, &mut cursor)?;
        if key_id_epoch == 0
            || key_epoch == 0
            || key_id_epoch != key_epoch
            || key_directory_revision == 0
        {
            return Err(E2eeError::BadCiphertext);
        }

        let nonce_len = usize::try_from(take_wire_u32(bytes, &mut cursor)?)
            .map_err(|_| E2eeError::BadCiphertext)?;
        if nonce_len != SEALED_BLOB_NONCE_BYTES {
            return Err(E2eeError::BadCiphertext);
        }
        let nonce: [u8; SEALED_BLOB_NONCE_BYTES] = take_wire(bytes, &mut cursor, nonce_len)?
            .try_into()
            .map_err(|_| E2eeError::BadCiphertext)?;

        let ciphertext_len = usize::try_from(take_wire_u32(bytes, &mut cursor)?)
            .map_err(|_| E2eeError::BadCiphertext)?;
        if ciphertext_len < SEALED_BLOB_TAG_BYTES {
            return Err(E2eeError::BadCiphertext);
        }
        let remaining = bytes
            .len()
            .checked_sub(cursor)
            .ok_or(E2eeError::BadCiphertext)?;
        if ciphertext_len
            .checked_add(SEALED_BLOB_SIGNATURE_BYTES)
            .ok_or(E2eeError::BadCiphertext)?
            != remaining
        {
            return Err(E2eeError::BadCiphertext);
        }
        let ciphertext = take_wire(bytes, &mut cursor, ciphertext_len)?;
        let signature: [u8; SEALED_BLOB_SIGNATURE_BYTES] =
            take_wire(bytes, &mut cursor, SEALED_BLOB_SIGNATURE_BYTES)?
                .try_into()
                .map_err(|_| E2eeError::BadCiphertext)?;
        if cursor != bytes.len() || signature.iter().all(|byte| *byte == 0) {
            return Err(E2eeError::BadCiphertext);
        }

        let decoded = Self {
            inner: UnsignedSealedBlobV1 {
                format_version,
                key_id: KeyId {
                    purpose,
                    epoch: key_id_epoch,
                },
                key_epoch,
                key_directory_revision,
                nonce,
                ciphertext: ciphertext.to_vec(),
            },
            signature: Ed25519Signature(signature),
        };
        if decoded.to_wire_bytes() != bytes {
            return Err(E2eeError::BadCiphertext);
        }
        Ok(decoded)
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

fn take_wire<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    length: usize,
) -> Result<&'a [u8], E2eeError> {
    let end = cursor
        .checked_add(length)
        .filter(|end| *end <= bytes.len())
        .ok_or(E2eeError::BadCiphertext)?;
    let value = &bytes[*cursor..end];
    *cursor = end;
    Ok(value)
}

fn take_wire_u8(bytes: &[u8], cursor: &mut usize) -> Result<u8, E2eeError> {
    Ok(take_wire(bytes, cursor, 1)?[0])
}

fn take_wire_u16(bytes: &[u8], cursor: &mut usize) -> Result<u16, E2eeError> {
    let value: [u8; 2] = take_wire(bytes, cursor, 2)?
        .try_into()
        .map_err(|_| E2eeError::BadCiphertext)?;
    Ok(u16::from_be_bytes(value))
}

fn take_wire_u32(bytes: &[u8], cursor: &mut usize) -> Result<u32, E2eeError> {
    let value: [u8; 4] = take_wire(bytes, cursor, 4)?
        .try_into()
        .map_err(|_| E2eeError::BadCiphertext)?;
    Ok(u32::from_be_bytes(value))
}

fn take_wire_u64(bytes: &[u8], cursor: &mut usize) -> Result<u64, E2eeError> {
    let value: [u8; 8] = take_wire(bytes, cursor, 8)?
        .try_into()
        .map_err(|_| E2eeError::BadCiphertext)?;
    Ok(u64::from_be_bytes(value))
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
