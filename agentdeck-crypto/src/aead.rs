//! 高频对称内容加密（design §7.1 / §7.4）——RFC 8439 ChaCha20-Poly1305。
//!
//! 每个对称发送 key 只有一个发送方向；nonce = `32-bit 随机 key prefix || 64-bit big-endian
//! sender counter`（design §7.4）。AAD 用 P1.2 的 [`OuterContextV1::encode_aad`] 确定性编码。
//!
//! 对称 key wrapper zeroize-on-drop，`Debug` 不输出材料。

use agentdeck_protocol::e2ee::context::OuterContextV1;
use agentdeck_protocol::e2ee::keys::KeyId;
use agentdeck_protocol::e2ee::payload::{
    SealedPayloadKind, UnsignedSealedBlobV1, VerifiedSealedBlobV1,
};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::CryptoError;

/// 32-byte 对称 AEAD key。zeroize-on-drop；`Debug` 脱敏。
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretAeadKey([u8; 32]);

impl std::fmt::Debug for SecretAeadKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("SecretAeadKey").field(&"<redacted>").finish()
    }
}

impl SecretAeadKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        SecretAeadKey(bytes)
    }

    fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// 64-bit sender counter（design §7.4）；填入 nonce 后 8 字节（big-endian）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SenderCounter(pub u64);

/// 单方向发送 key：key 身份 + epoch + key-directory revision + nonce prefix + 秘密 key。
///
/// # 安全（nonce 唯一性）
///
/// nonce = `nonce_prefix || counter`（design §7.4），因此**同一 key 下 counter 复用等价于
/// nonce 复用**——对 ChaCha20-Poly1305 是灾难性的（泄漏 keystream 与认证密钥）。counter 的
/// 唯一性由上层 CounterGuard / counter block reservation（P1.5，design §7.4）负责：预留先
/// 提升 Keychain high-water，崩溃恢复允许跳号但绝不复用；本类型与 [`seal_symmetric`]
/// **不做任何复用防护**。
#[derive(Debug)]
pub struct AeadSendingKey {
    pub key_id: KeyId,
    pub epoch: u64,
    pub key_directory_revision: u64,
    pub nonce_prefix: [u8; 4],
    key: SecretAeadKey,
}

impl AeadSendingKey {
    pub fn new(
        key_id: KeyId,
        epoch: u64,
        key_directory_revision: u64,
        nonce_prefix: [u8; 4],
        key: SecretAeadKey,
    ) -> Self {
        Self {
            key_id,
            epoch,
            key_directory_revision,
            nonce_prefix,
            key,
        }
    }
}

/// 单方向接收 key（open 使用 blob 内 nonce，故不需 nonce prefix）。
#[derive(Debug)]
pub struct AeadReceivingKey {
    pub key_id: KeyId,
    pub epoch: u64,
    key: SecretAeadKey,
}

impl AeadReceivingKey {
    pub fn new(key_id: KeyId, epoch: u64, key: SecretAeadKey) -> Self {
        Self { key_id, epoch, key }
    }
}

/// 组装 nonce = `nonce_prefix(4) || counter.to_be_bytes()(8)`（design §7.4）。
fn assemble_nonce(prefix: &[u8; 4], counter: SenderCounter) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..4].copy_from_slice(prefix);
    nonce[4..].copy_from_slice(&counter.0.to_be_bytes());
    nonce
}

fn seal(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher =
        ChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::InvalidKey("aead key"))?;
    let nonce = Nonce::from(*nonce);
    cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::BadCiphertext)
}

fn open(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher =
        ChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::InvalidKey("aead key"))?;
    let nonce = Nonce::from(*nonce);
    cipher
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoError::BadCiphertext)
}

/// 对称封装明文，产出未签名 sealed blob（design §7.3/§7.4）。AAD 绑定 `context`，nonce 由
/// key prefix + counter 组装。`payload_kind` 是每条消息的业务类型引用（只在密文外壳头，供
/// endpoint 解析），`key_directory_revision` 来自发送 key 的目录状态。
///
/// # 安全（调用方契约）
///
/// 调用方**必须保证同一 `key` 下 `counter` 永不复用**：(key, counter) 复用即 nonce 复用，
/// 对 ChaCha20-Poly1305 是灾难性的。本函数**不校验**复用——唯一性由上层 CounterGuard /
/// counter block reservation（P1.5，design §7.4）负责；counter 接近上界时上层必须强制新
/// epoch，不允许 wrap。
pub fn seal_symmetric(
    key: &AeadSendingKey,
    context: &OuterContextV1,
    payload_kind: SealedPayloadKind,
    plaintext: &[u8],
    counter: SenderCounter,
) -> Result<UnsignedSealedBlobV1, CryptoError> {
    let nonce = assemble_nonce(&key.nonce_prefix, counter);
    let aad = context.encode_aad();
    let ciphertext = seal(key.key.as_bytes(), &nonce, &aad, plaintext)?;
    Ok(UnsignedSealedBlobV1::new(
        payload_kind,
        key.key_id,
        key.epoch,
        key.key_directory_revision,
        nonce,
        ciphertext,
    ))
}

/// 对已验证 sealed blob 做 AEAD 解密取明文（type-state 保证已验签发送方）。AAD 必须与
/// 发送方 `context` 逐字节一致，否则 tag 校验失败返回 [`CryptoError::BadCiphertext`]。
///
/// # key 选择（上层职责）
///
/// 本函数**不交叉校验** [`AeadReceivingKey`] 的 `key_id`/`epoch` 与 blob 头
/// （`key_id`/`key_epoch`/`key_directory_revision`）的一致性——按 blob 头选取正确接收 key
/// 属上层（key directory / replay state，design §7.2/§7.5）职责；传错 key 由 AEAD tag
/// 校验失败兜底（[`CryptoError::BadCiphertext`]），不会静默解出错误明文。
pub fn open_symmetric(
    key: &AeadReceivingKey,
    context: &OuterContextV1,
    blob: VerifiedSealedBlobV1,
) -> Result<Vec<u8>, CryptoError> {
    let inner = &blob.sealed().inner;
    let aad = context.encode_aad();
    open(key.key.as_bytes(), &inner.nonce, &aad, &inner.ciphertext)
}
