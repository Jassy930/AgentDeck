//! DeviceReplyTx counter recovery 的一次性 DeviceHPKE reply。
//!
//! public API 只接受 typed HPKE/Ed25519 wrapper、protocol authority 与 RNG；没有
//! DeviceReplyTx key、sender counter 或 arbitrary raw-signing 入口。

use agentdeck_protocol::e2ee::{
    DeviceKeyRecoveryInfoV1, DeviceKeyRecoveryReplyV1, KeyUpdateSetV1, MachineDataSignerBindingV1,
    OuterContextV1, PairingError,
};
use agentdeck_protocol::relay_v2::auth::Ed25519Signature;
use zeroize::Zeroizing;

use crate::canonical::sha256;
use crate::error::CryptoError;
use crate::hpke::{HpkeEnvelopeV1, HpkePrivateKey, HpkePublicKey, hpke_open_base, hpke_seal_base};
use crate::signature::{SigningKey, VerifyingKey, sign_raw, verify_raw};

/// daemon 侧 recovery seal 的三项 typed authority。
pub struct DeviceKeyRecoverySealAuthority<'a> {
    pub device_hpke_public_key: &'a HpkePublicKey,
    pub machine_data_signing_key: &'a SigningKey,
    pub signer: &'a MachineDataSignerBindingV1,
}

impl std::fmt::Debug for DeviceKeyRecoverySealAuthority<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("DeviceKeyRecoverySealAuthority([REDACTED])")
    }
}

/// device 侧 recovery open 的三项 typed authority。
pub struct DeviceKeyRecoveryOpenAuthority<'a> {
    pub device_hpke_private_key: &'a HpkePrivateKey,
    pub machine_data_verifying_key: &'a VerifyingKey,
    pub signer: &'a MachineDataSignerBindingV1,
}

impl std::fmt::Debug for DeviceKeyRecoveryOpenAuthority<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("DeviceKeyRecoveryOpenAuthority([REDACTED])")
    }
}

fn require_signer(
    key: &VerifyingKey,
    expected: &DeviceKeyRecoveryInfoV1,
    signer: &MachineDataSignerBindingV1,
) -> Result<(), CryptoError> {
    expected.validate()?;
    signer.validate()?;
    if signer != &expected.machine_data_signer {
        return Err(PairingError::ContextBindingMismatch.into());
    }
    if sha256(&key.to_bytes()) != signer.signing_key_fingerprint {
        return Err(CryptoError::InvalidKey(
            "device key recovery MachineDataSign fingerprint mismatch",
        ));
    }
    Ok(())
}

/// 把完整 frozen `KeyUpdateSetV1` 一次 HPKE Base seal 给授权 DeviceHPKE，再对 envelope
/// 的 typed TBS 做 MachineDataSign。该签名 API 不接受任意 bytes。
pub fn seal_device_key_recovery_reply<R: ::hpke::rand_core::CryptoRng>(
    authority: DeviceKeyRecoverySealAuthority<'_>,
    info: &DeviceKeyRecoveryInfoV1,
    context: &OuterContextV1,
    update_set: &KeyUpdateSetV1,
    rng: &mut R,
) -> Result<DeviceKeyRecoveryReplyV1, CryptoError> {
    info.validate_for_update_set(update_set)?;
    info.validate_context(context)?;
    require_signer(
        &authority.machine_data_signing_key.verifying_key(),
        info,
        authority.signer,
    )?;

    let plaintext = Zeroizing::new(update_set.canonical_bytes()?);
    let info_bytes = info.canonical_bytes()?;
    let aad = context.encode_aad();
    let sealed = hpke_seal_base(
        authority.device_hpke_public_key,
        &info_bytes,
        &aad,
        plaintext.as_slice(),
        rng,
    )?;
    let mut reply = DeviceKeyRecoveryReplyV1 {
        format_version: info.e2ee_format_version,
        info: info.clone(),
        enc: sealed.enc,
        ciphertext: sealed.ciphertext,
        machine_data_signature: Ed25519Signature([0; 64]),
    };
    let tbs = reply
        .signature_tbs(context, authority.signer)?
        .canonical_bytes()?;
    reply.machine_data_signature = sign_raw(authority.machine_data_signing_key, &tbs);
    reply.validate()?;
    verify_device_key_recovery_reply(
        authority.machine_data_signing_key.verifying_key(),
        authority.signer,
        info,
        context,
        &reply,
    )?;
    Ok(reply)
}

/// 只验 clear authority、exact expected info/context 与 MachineDataSign；不执行 HPKE open。
pub fn verify_device_key_recovery_reply(
    machine_data_verifying_key: VerifyingKey,
    signer: &MachineDataSignerBindingV1,
    expected_info: &DeviceKeyRecoveryInfoV1,
    context: &OuterContextV1,
    reply: &DeviceKeyRecoveryReplyV1,
) -> Result<(), CryptoError> {
    reply.validate()?;
    expected_info.validate_context(context)?;
    reply.ensure_info_matches(expected_info)?;
    require_signer(&machine_data_verifying_key, expected_info, signer)?;
    let tbs = reply.signature_tbs(context, signer)?.canonical_bytes()?;
    verify_raw(
        &machine_data_verifying_key,
        &tbs,
        &reply.machine_data_signature,
    )
}

/// 严格顺序：先验外层 shape/expected axes/MachineDataSign，再 HPKE open，最后 canonical
/// parse 并复核 exact device/revision/frozen-set hash。
pub fn open_device_key_recovery_reply(
    authority: DeviceKeyRecoveryOpenAuthority<'_>,
    expected_info: &DeviceKeyRecoveryInfoV1,
    context: &OuterContextV1,
    reply: &DeviceKeyRecoveryReplyV1,
) -> Result<KeyUpdateSetV1, CryptoError> {
    verify_device_key_recovery_reply(
        *authority.machine_data_verifying_key,
        authority.signer,
        expected_info,
        context,
        reply,
    )?;

    let plaintext = Zeroizing::new(hpke_open_base(
        authority.device_hpke_private_key,
        &expected_info.canonical_bytes()?,
        &context.encode_aad(),
        &HpkeEnvelopeV1 {
            enc: reply.enc.clone(),
            ciphertext: reply.ciphertext.clone(),
        },
    )?);
    let update_set = KeyUpdateSetV1::from_canonical_bytes(plaintext.as_slice())
        .map_err(|_| CryptoError::BadCiphertext)?;
    expected_info
        .validate_for_update_set(&update_set)
        .map_err(|_| CryptoError::BadCiphertext)?;
    Ok(update_set)
}
