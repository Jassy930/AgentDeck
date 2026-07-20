//! Key directory 的 typed MachineDataSign 与 HPKE key-wrap。
//!
//! 本模块只接受 protocol-owned directory/TBS/info/context 与固定 32-byte secret key，
//! 不暴露可把任意 plaintext/info/AAD 组合成 production key entry 的入口。

use crate::aead::SecretAeadKey;
use crate::canonical::sha256;
use crate::error::CryptoError;
use crate::hpke::{HpkeEnvelopeV1, HpkePrivateKey, HpkePublicKey, hpke_open_base, hpke_seal_base};
use crate::signature::{SigningKey, VerifyingKey, sign_raw, verify_raw};
use agentdeck_protocol::e2ee::{
    KeyDirectoryEntry, KeyDirectorySignatureContextV1, KeyDirectoryV1, KeyUpdateInfoV1,
    MachineDataSignerBindingV1, OuterContextV1,
};
use zeroize::Zeroizing;

fn require_signer(
    key: &VerifyingKey,
    signer: &MachineDataSignerBindingV1,
) -> Result<(), CryptoError> {
    signer.validate()?;
    if sha256(&key.to_bytes()) != signer.signing_key_fingerprint {
        return Err(CryptoError::InvalidKey(
            "key-directory signer fingerprint mismatch",
        ));
    }
    Ok(())
}

/// 对 unsigned directory 附加当前 MachineDataSign 签名；已签对象不可重签。
pub fn sign_key_directory(
    signing_key: &SigningKey,
    signer: &MachineDataSignerBindingV1,
    context: &KeyDirectorySignatureContextV1,
    mut directory: KeyDirectoryV1,
) -> Result<KeyDirectoryV1, CryptoError> {
    if directory.signature.0 != [0; 64] {
        return Err(CryptoError::InvalidKey(
            "key directory must be unsigned before signing",
        ));
    }
    let verifying_key = signing_key.verifying_key();
    require_signer(&verifying_key, signer)?;
    let tbs = directory.signature_tbs(context, signer)?;
    directory.signature = sign_raw(signing_key, &tbs.encode()?);
    directory.validate_for_device(context.device_route)?;
    verify_key_directory(&verifying_key, signer, context, &directory)?;
    Ok(directory)
}

/// 验证 directory 的完整 shape、签名上下文与 MachineDataSign provenance。
pub fn verify_key_directory(
    verifying_key: &VerifyingKey,
    signer: &MachineDataSignerBindingV1,
    context: &KeyDirectorySignatureContextV1,
    directory: &KeyDirectoryV1,
) -> Result<(), CryptoError> {
    require_signer(verifying_key, signer)?;
    directory.validate_for_device(context.device_route)?;
    let tbs = directory.signature_tbs(context, signer)?;
    verify_raw(verifying_key, &tbs.encode()?, &directory.signature)
}

/// 使用 KeyUpdateInfo + exact KeyUpdate outer context 封装一个固定 32-byte 对称 key。
pub fn seal_key_directory_entry<R: ::hpke::rand_core::CryptoRng>(
    recipient: &HpkePublicKey,
    info: &KeyUpdateInfoV1,
    context: &OuterContextV1,
    key: &SecretAeadKey,
    rng: &mut R,
) -> Result<KeyDirectoryEntry, CryptoError> {
    info.validate_context(context)?;
    let sealed = hpke_seal_base(
        recipient,
        &info.encode(),
        &context.encode_aad(),
        key.as_bytes(),
        rng,
    )?;
    let entry = KeyDirectoryEntry {
        key_id: agentdeck_protocol::e2ee::KeyId {
            purpose: info.key_purpose,
            epoch: info.key_epoch,
        },
        device_route: info.device_route,
        stream_route: info.stream_route,
        enc: sealed.enc,
        wrapped_key: sealed.ciphertext,
    };
    entry.validate_for_info(info)?;
    Ok(entry)
}

/// 只从 exact-bound entry 解封固定 32-byte key；任意轴或长度不匹配均 fail-close。
pub fn open_key_directory_entry(
    recipient: &HpkePrivateKey,
    info: &KeyUpdateInfoV1,
    context: &OuterContextV1,
    entry: &KeyDirectoryEntry,
) -> Result<SecretAeadKey, CryptoError> {
    info.validate_context(context)?;
    entry.validate_for_info(info)?;
    let plaintext = Zeroizing::new(hpke_open_base(
        recipient,
        &info.encode(),
        &context.encode_aad(),
        &HpkeEnvelopeV1 {
            enc: entry.enc.clone(),
            ciphertext: entry.wrapped_key.clone(),
        },
    )?);
    let bytes: [u8; 32] = plaintext
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::InvalidKey("wrapped symmetric key length"))?;
    Ok(SecretAeadKey::from_bytes(bytes))
}
