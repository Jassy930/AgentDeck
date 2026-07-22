//! KeyUpdate canonical TBS 的真实 Ed25519 signer/verifier 适配层。
//!
//! protocol 拥有全部 authority/context 校验与 canonical 编码；本模块只把固定的
//! MachineDataSign key 绑定到 protocol hook，并提供保留 [`CryptoError`] 语义的便捷入口。

use agentdeck_protocol::e2ee::{
    CanonicalKeyUpdateTbs, KeyUpdateInfoV1, KeyUpdateSignatureSigner, KeyUpdateSignatureVerifier,
    KeyUpdateV1, MachineDataSignerBindingV1, OuterContextV1, PairingError,
};
use agentdeck_protocol::relay_v2::auth::Ed25519Signature;

use crate::canonical::sha256;
use crate::error::CryptoError;
use crate::signature::{SigningKey, VerifyingKey, sign_raw, verify_raw};

fn require_signer(
    key: &VerifyingKey,
    signer: &MachineDataSignerBindingV1,
) -> Result<(), CryptoError> {
    signer.validate()?;
    if sha256(&key.to_bytes()) != signer.signing_key_fingerprint {
        return Err(CryptoError::InvalidKey(
            "key-update signer fingerprint mismatch",
        ));
    }
    Ok(())
}

/// 把固定 MachineDataSign 私钥接到 protocol-owned KeyUpdate signer hook。
#[derive(Debug)]
pub struct Ed25519KeyUpdateSigner<'a> {
    key: &'a SigningKey,
}

impl<'a> Ed25519KeyUpdateSigner<'a> {
    pub const fn new(key: &'a SigningKey) -> Self {
        Self { key }
    }
}

impl KeyUpdateSignatureSigner for Ed25519KeyUpdateSigner<'_> {
    fn signing_key_fingerprint(&self) -> [u8; 32] {
        sha256(&self.key.verifying_key().to_bytes())
    }

    fn sign_key_update_tbs(
        &self,
        canonical_tbs: CanonicalKeyUpdateTbs<'_>,
    ) -> Result<Ed25519Signature, PairingError> {
        Ok(sign_raw(self.key, canonical_tbs.as_bytes()))
    }
}

/// 把固定 MachineDataSign 公钥接到 protocol-owned KeyUpdate verifier hook。
#[derive(Debug)]
pub struct Ed25519KeyUpdateVerifier<'a> {
    key: &'a VerifyingKey,
}

impl<'a> Ed25519KeyUpdateVerifier<'a> {
    pub const fn new(key: &'a VerifyingKey) -> Self {
        Self { key }
    }
}

impl KeyUpdateSignatureVerifier for Ed25519KeyUpdateVerifier<'_> {
    fn verifying_key_fingerprint(&self) -> [u8; 32] {
        sha256(&self.key.to_bytes())
    }

    fn verify_key_update_tbs(
        &self,
        canonical_tbs: CanonicalKeyUpdateTbs<'_>,
        signature: &Ed25519Signature,
    ) -> Result<(), PairingError> {
        verify_raw(self.key, canonical_tbs.as_bytes(), signature)
            .map_err(|_| PairingError::InvalidField("key update signature"))
    }
}

/// 对 unsigned KeyUpdate 的完整 protocol-owned TBS 做 MachineDataSign 签名。
///
/// 已签对象不可重签，避免调用方把同一 wrapped key 静默投影到另一个 authority/context。
pub fn sign_key_update(
    signing_key: &SigningKey,
    signer: &MachineDataSignerBindingV1,
    info: &KeyUpdateInfoV1,
    context: &OuterContextV1,
    mut update: KeyUpdateV1,
) -> Result<KeyUpdateV1, CryptoError> {
    if update.signature.0 != [0; 64] {
        return Err(CryptoError::InvalidKey(
            "key update must be unsigned before signing",
        ));
    }
    let verifying_key = signing_key.verifying_key();
    require_signer(&verifying_key, signer)?;
    let tbs = update.signature_tbs(info, context, signer)?.encode()?;
    update.signature = sign_raw(signing_key, &tbs);
    update.validate()?;
    verify_key_update(&verifying_key, signer, info, context, &update)?;
    Ok(update)
}

/// 验证 KeyUpdate 的完整 shape、authority/context、credential fingerprint 与 Ed25519 签名。
pub fn verify_key_update(
    verifying_key: &VerifyingKey,
    signer: &MachineDataSignerBindingV1,
    info: &KeyUpdateInfoV1,
    context: &OuterContextV1,
    update: &KeyUpdateV1,
) -> Result<(), CryptoError> {
    require_signer(verifying_key, signer)?;
    update.validate()?;
    let tbs = update.signature_tbs(info, context, signer)?.encode()?;
    verify_raw(verifying_key, &tbs, &update.signature)
}
