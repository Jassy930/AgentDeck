//! sealed blob 发送方签名/验签（design §7.3 / RC-15）。
//!
//! sign_sealed 用 protocol 的 [`UnsignedSealedBlobV1::sealed_blob_tbs`] 计算 canonical TBS
//! 并以 Ed25519 签名，推进 type-state 到 `Signed`。verify_sealed 通过 protocol 的
//! verifier-hook（[`SealedBlobSignatureVerifier`]）注入真实 Ed25519 验签，验签通过才推进到
//! `Verified`——protocol 侧计算 TBS bytes，crypto 侧不能对任意字节验签并构造 Verified。

use agentdeck_protocol::e2ee::SealedBlobSignatureVerifier;
use agentdeck_protocol::e2ee::context::OuterContextV1;
use agentdeck_protocol::e2ee::payload::{
    SignedSealedBlobV1, UnsignedSealedBlobV1, VerifiedSealedBlobV1,
};
use agentdeck_protocol::relay_v2::auth::Ed25519Signature;

use crate::error::CryptoError;
use crate::signature::{SigningKey, VerifyingKey, sign_raw, verify_raw};

/// 对 sealed blob 计算 canonical TBS（context + blob）并用 MachineDataSign/DeviceSign 签名，
/// 推进到 [`SignedSealedBlobV1`]。
pub fn sign_sealed(
    blob: UnsignedSealedBlobV1,
    key: &SigningKey,
    context: &OuterContextV1,
) -> SignedSealedBlobV1 {
    let tbs = blob.sealed_blob_tbs(context);
    let signature = sign_raw(key, &tbs);
    blob.attach_signature(signature)
}

/// 用注入的 Ed25519 verifier 验证 sealed blob 发送方签名，推进到 [`VerifiedSealedBlobV1`]。
/// 签名无效返回 [`CryptoError::BadSignature`]。
pub fn verify_sealed(
    blob: SignedSealedBlobV1,
    key: &VerifyingKey,
    context: &OuterContextV1,
) -> Result<VerifiedSealedBlobV1, CryptoError> {
    let verifier = Ed25519SealedVerifier { key };
    blob.verify_with(&verifier, context)
        .map_err(CryptoError::from)
}

/// protocol verifier-hook 的 ed25519-dalek 实现（design RC-15）。持有验签公钥；只对 protocol
/// 计算好的 TBS bytes 验签。
struct Ed25519SealedVerifier<'a> {
    key: &'a VerifyingKey,
}

impl SealedBlobSignatureVerifier for Ed25519SealedVerifier<'_> {
    fn verify_sealed_tbs(
        &self,
        tbs: &[u8],
        signature: &Ed25519Signature,
    ) -> Result<(), agentdeck_protocol::e2ee::E2eeError> {
        verify_raw(self.key, tbs, signature)
            .map_err(|_| agentdeck_protocol::e2ee::E2eeError::BadSenderSignature)
    }
}
