//! Ed25519 身份签名（design §7.1）——canonical `ToBeSignedV1` 的 sign/verify。
//!
//! 私钥 wrapper zeroize-on-drop（ed25519-dalek `zeroize` feature）且 `Debug` 不输出材料。

use agentdeck_protocol::e2ee::tbs::ToBeSignedV1;
use agentdeck_protocol::relay_v2::auth::Ed25519Signature;
use ed25519_dalek::{Signature, Signer};

use crate::error::CryptoError;

/// 64-byte Ed25519 签名。与 protocol 的 [`Ed25519Signature`] 双向可转换。
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SignatureBytes(pub [u8; 64]);

impl std::fmt::Debug for SignatureBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("SignatureBytes").field(&"..").finish()
    }
}

impl From<SignatureBytes> for Ed25519Signature {
    fn from(s: SignatureBytes) -> Self {
        Ed25519Signature(s.0)
    }
}

impl From<Ed25519Signature> for SignatureBytes {
    fn from(s: Ed25519Signature) -> Self {
        SignatureBytes(s.0)
    }
}

/// Ed25519 私钥 wrapper。zeroize-on-drop（内层 dalek `SigningKey` 启用 zeroize feature）；
/// `Debug` 脱敏。
pub struct SigningKey(ed25519_dalek::SigningKey);

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("SigningKey").field(&"<redacted>").finish()
    }
}

impl SigningKey {
    /// 从固定 32-byte seed 构造（Ed25519 RFC 8032 secret key）。
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        SigningKey(ed25519_dalek::SigningKey::from_bytes(seed))
    }

    /// 对应验签公钥。
    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey(self.0.verifying_key())
    }
}

/// Ed25519 验签公钥 wrapper。
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct VerifyingKey(ed25519_dalek::VerifyingKey);

impl std::fmt::Debug for VerifyingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("VerifyingKey")
            .field(&self.0.to_bytes())
            .finish()
    }
}

impl VerifyingKey {
    /// 原始 32-byte 公钥。
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// 从 32-byte 公钥构造；非法点返回 [`CryptoError::InvalidKey`]。
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, CryptoError> {
        ed25519_dalek::VerifyingKey::from_bytes(bytes)
            .map(VerifyingKey)
            .map_err(|_| CryptoError::InvalidKey("ed25519 verifying key"))
    }
}

/// 对 canonical `ToBeSignedV1` 确定性签名（Ed25519 RFC 8032）。
pub fn sign_tbs(key: &SigningKey, tbs: &ToBeSignedV1) -> SignatureBytes {
    let message = tbs.encode();
    SignatureBytes(key.0.sign(&message).to_bytes())
}

/// 验证 canonical `ToBeSignedV1` 签名。失败返回 [`CryptoError::BadSignature`]。
pub fn verify_tbs(
    key: &VerifyingKey,
    tbs: &ToBeSignedV1,
    signature: &SignatureBytes,
) -> Result<(), CryptoError> {
    let message = tbs.encode();
    let sig = Signature::from_bytes(&signature.0);
    key.0
        .verify_strict(&message, &sig)
        .map_err(|_| CryptoError::BadSignature)
}

/// 对任意 canonical bytes 验签（供 sealed-blob verifier-hook 复用）。
pub(crate) fn verify_raw(
    key: &VerifyingKey,
    message: &[u8],
    signature: &Ed25519Signature,
) -> Result<(), CryptoError> {
    let sig = Signature::from_bytes(&signature.0);
    key.0
        .verify_strict(message, &sig)
        .map_err(|_| CryptoError::BadSignature)
}

/// 对任意 canonical bytes 签名（供 sealed-blob 签名复用）。
pub(crate) fn sign_raw(key: &SigningKey, message: &[u8]) -> Ed25519Signature {
    Ed25519Signature(key.0.sign(message).to_bytes())
}
