//! `CryptoError` —— agentdeck-crypto 的 typed 错误（design §7.5：解密/验签失败必须是
//! 可观察 typed error，绝不静默）。

use agentdeck_protocol::e2ee::E2eeError;
use agentdeck_protocol::relay_v2::RelayAdminPurgeReceiptError;

/// Relay E2EE 密码学操作的 typed 错误。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CryptoError {
    /// Ed25519 验签失败（TBS / sealed-blob 发送方签名）。
    #[error("ed25519 signature verification failed")]
    BadSignature,
    /// AEAD tag 校验失败或密文损坏（ChaCha20-Poly1305 / HPKE open）。
    #[error("bad ciphertext / AEAD tag")]
    BadCiphertext,
    /// 密钥材料非法（长度错误或不可用点）。
    #[error("invalid key material: {0}")]
    InvalidKey(&'static str),
    /// Portable Relay admin receipt 的 shape / trust-anchor binding 非法。
    #[error("invalid Relay admin purge receipt: {0}")]
    InvalidRelayAdminPurgeReceipt(#[from] RelayAdminPurgeReceiptError),
    /// HPKE seal/open 失败（封装/解封装错误）。
    #[error("HPKE operation failed: {0}")]
    Hpke(&'static str),
    /// 发送 counter 触及上界，必须新 epoch/rekey（design §7.4，禁止 wrap）。
    #[error("sender counter exhausted; requires new key epoch (must not wrap)")]
    CounterExhausted,
    /// protocol 契约层 typed error（透传非签名类 E2eeError）。
    #[error("e2ee contract error: {0}")]
    E2ee(E2eeError),
}

impl From<E2eeError> for CryptoError {
    fn from(e: E2eeError) -> Self {
        match e {
            E2eeError::BadSenderSignature => CryptoError::BadSignature,
            E2eeError::BadCiphertext => CryptoError::BadCiphertext,
            other => CryptoError::E2ee(other),
        }
    }
}
