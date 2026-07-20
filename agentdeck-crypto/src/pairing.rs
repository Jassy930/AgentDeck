//! P4.3 pairing 的 typed Ed25519 + HPKE wrappers。
//!
//! 调用方不能把任意 raw bytes 交给这些签名入口；所有签名都先通过 protocol-owned typed
//! TBS validation。HPKE plaintext/ciphertext 只使用 frozen canonical bytes。

use agentdeck_protocol::e2ee::{
    DeviceAuthorizationV1, E2EE_FORMAT_VERSION, KeyDirectorySignatureContextV1,
    MachineDataSignerBindingV1, OuterContextV1, PairPendingV1, PairRequestInfoV1,
    PairRequestPlaintextV1, PairRequestV1, PairResponseInfoV1, PairResponsePlaintextV1,
    PairResponseReceivedV1, PairResponseV1, PairingControlEnvelopeV1, PairingEnvelopeTbsV1,
};
use agentdeck_protocol::relay_v2::auth::{Ed25519Signature, RelayGrant};
use agentdeck_protocol::relay_v2::id::RelayServerId;
use zeroize::Zeroizing;

use crate::canonical::sha256;
use crate::error::CryptoError;
use crate::hpke::{HpkeEnvelopeV1, HpkePrivateKey, HpkePublicKey, hpke_open_base, hpke_seal_base};
use crate::key_directory::verify_key_directory;
use crate::signature::{
    SignatureBytes, SigningKey, VerifyingKey, sign_raw, sign_tbs, verify_raw, verify_tbs,
};

fn signer_fingerprint(key: &VerifyingKey) -> [u8; 32] {
    sha256(&key.to_bytes())
}

fn require_signer(key: &VerifyingKey, expected_fingerprint: [u8; 32]) -> Result<(), CryptoError> {
    if signer_fingerprint(key) != expected_fingerprint {
        return Err(CryptoError::InvalidKey(
            "pairing signer fingerprint mismatch",
        ));
    }
    Ok(())
}

fn hpke_envelope(enc: &[u8], ciphertext: &[u8]) -> HpkeEnvelopeV1 {
    HpkeEnvelopeV1 {
        enc: enc.to_vec(),
        ciphertext: ciphertext.to_vec(),
    }
}

/// 已完成 HPKE open、invite-secret 与 DeviceSign possession proof 验证的 PairRequest。
/// 字段私有且类型不实现 Clone/Serialize，调用方只能经 [`open_pair_request_verified`] 构造。
pub struct VerifiedPairRequestV1 {
    canonical_request: Vec<u8>,
    request_hash: [u8; 32],
    canonical_plaintext: Zeroizing<Vec<u8>>,
    info: PairRequestInfoV1,
    context: OuterContextV1,
}

impl std::fmt::Debug for VerifiedPairRequestV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("VerifiedPairRequestV1([REDACTED])")
    }
}

impl VerifiedPairRequestV1 {
    #[must_use]
    pub fn canonical_request(&self) -> &[u8] {
        &self.canonical_request
    }

    #[must_use]
    pub const fn request_hash(&self) -> [u8; 32] {
        self.request_hash
    }

    #[must_use]
    pub fn canonical_plaintext(&self) -> &[u8] {
        self.canonical_plaintext.as_slice()
    }

    #[must_use]
    pub const fn info(&self) -> &PairRequestInfoV1 {
        &self.info
    }

    #[must_use]
    pub const fn context(&self) -> &OuterContextV1 {
        &self.context
    }

    #[must_use]
    pub fn retained_bytes(&self) -> usize {
        self.canonical_request.capacity() + self.canonical_plaintext.capacity()
    }
}

/// PairResponse sender 的三项已绑定 authority，作为一个 typed 参数避免 call-site 错位。
pub struct PairResponseSealAuthority<'a> {
    pub machine_data_signing_key: &'a SigningKey,
    pub signer: &'a MachineDataSignerBindingV1,
    pub machine_root_verifying_key: &'a VerifyingKey,
}

impl std::fmt::Debug for PairResponseSealAuthority<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PairResponseSealAuthority")
            .field("authority", &"<redacted>")
            .finish()
    }
}

pub fn seal_pair_request<R: ::hpke::rand_core::CryptoRng>(
    recipient: &HpkePublicKey,
    info: &PairRequestInfoV1,
    context: &OuterContextV1,
    plaintext: &PairRequestPlaintextV1,
    device_signing_key: &SigningKey,
    rng: &mut R,
) -> Result<PairRequestV1, CryptoError> {
    plaintext.validate()?;
    let verifying_key = device_signing_key.verifying_key();
    if verifying_key.to_bytes() != plaintext.device_sign_pubkey.0 {
        return Err(CryptoError::InvalidKey(
            "DeviceSign key does not match PairRequest plaintext",
        ));
    }
    let info_bytes = info.encode();
    let aad = context.encode_aad();
    let sealed = hpke_seal_base(
        recipient,
        &info_bytes,
        &aad,
        &plaintext.canonical_bytes()?,
        rng,
    )?;
    let fingerprint = signer_fingerprint(&verifying_key);
    let tbs = PairingEnvelopeTbsV1::for_request_parts(
        E2EE_FORMAT_VERSION,
        sealed.enc.clone(),
        &sealed.ciphertext,
        info,
        context,
        fingerprint,
    )?;
    let signature = sign_validated_pairing_tbs(device_signing_key, &tbs)?;
    let envelope = PairRequestV1 {
        format_version: E2EE_FORMAT_VERSION,
        enc: sealed.enc,
        ciphertext: sealed.ciphertext,
        device_proof_signature: signature,
    };
    envelope.validate()?;
    Ok(envelope)
}

pub fn open_pair_request(
    recipient: &HpkePrivateKey,
    info: &PairRequestInfoV1,
    context: &OuterContextV1,
    expected_invite_secret: &[u8; 32],
    envelope: &PairRequestV1,
) -> Result<PairRequestPlaintextV1, CryptoError> {
    envelope.validate()?;
    let opened = hpke_open_base(
        recipient,
        &info.encode(),
        &context.encode_aad(),
        &hpke_envelope(&envelope.enc, &envelope.ciphertext),
    )?;
    let plaintext = PairRequestPlaintextV1::from_canonical_bytes(&opened)
        .map_err(|_| CryptoError::BadCiphertext)?;
    if &plaintext.invite_secret != expected_invite_secret {
        return Err(CryptoError::BadCiphertext);
    }
    let verifying_key = VerifyingKey::from_bytes(&plaintext.device_sign_pubkey.0)?;
    let fingerprint = plaintext.device_sign_fingerprint();
    require_signer(&verifying_key, fingerprint)?;
    let tbs = envelope.proof_tbs(info, context, fingerprint)?;
    verify_validated_pairing_tbs(&verifying_key, &tbs, &envelope.device_proof_signature)?;
    Ok(plaintext)
}

/// 验证并冻结 Store 可接受的 PairRequest type-state。
pub fn open_pair_request_verified(
    recipient: &HpkePrivateKey,
    info: &PairRequestInfoV1,
    context: &OuterContextV1,
    expected_invite_secret: &[u8; 32],
    envelope: &PairRequestV1,
) -> Result<VerifiedPairRequestV1, CryptoError> {
    let plaintext = open_pair_request(recipient, info, context, expected_invite_secret, envelope)?;
    let canonical_request = envelope.canonical_bytes()?;
    let request_hash = sha256(&canonical_request);
    let canonical_plaintext = Zeroizing::new(plaintext.canonical_bytes()?);
    Ok(VerifiedPairRequestV1 {
        canonical_request,
        request_hash,
        canonical_plaintext,
        info: info.clone(),
        context: context.clone(),
    })
}

pub fn seal_pair_response<R: ::hpke::rand_core::CryptoRng>(
    recipient: &HpkePublicKey,
    info: &PairResponseInfoV1,
    context: &OuterContextV1,
    plaintext: &PairResponsePlaintextV1,
    authority: PairResponseSealAuthority<'_>,
    rng: &mut R,
) -> Result<PairResponseV1, CryptoError> {
    info.validate()?;
    validate_pair_response_plaintext(info, plaintext)?;
    require_signer(
        &authority.machine_data_signing_key.verifying_key(),
        authority.signer.signing_key_fingerprint,
    )?;
    if recipient.to_bytes() != plaintext.device_authorization.device_hpke_pubkey.0 {
        return Err(CryptoError::InvalidKey(
            "DeviceHPKE recipient does not match DeviceAuthorization",
        ));
    }
    verify_grant_and_authorization(
        authority.machine_root_verifying_key,
        info.relay_server_id,
        &plaintext.relay_grant,
        &plaintext.device_authorization,
    )?;
    verify_key_directory(
        &authority.machine_data_signing_key.verifying_key(),
        authority.signer,
        &key_directory_context(info),
        &plaintext.key_directory,
    )?;
    let sealed = hpke_seal_base(
        recipient,
        &info.encode(),
        &context.encode_aad(),
        &plaintext.canonical_bytes()?,
        rng,
    )?;
    let tbs = PairingEnvelopeTbsV1::for_response_parts(
        E2EE_FORMAT_VERSION,
        sealed.enc.clone(),
        &sealed.ciphertext,
        info,
        context,
        authority.signer,
    )?;
    let signature = sign_validated_pairing_tbs(authority.machine_data_signing_key, &tbs)?;
    let envelope = PairResponseV1 {
        format_version: E2EE_FORMAT_VERSION,
        info: info.clone(),
        enc: sealed.enc,
        ciphertext: sealed.ciphertext,
        machine_data_signature: signature,
    };
    envelope.validate()?;
    Ok(envelope)
}

pub fn open_pair_response(
    recipient: &HpkePrivateKey,
    info: &PairResponseInfoV1,
    context: &OuterContextV1,
    envelope: &PairResponseV1,
    machine_data_verifying_key: &VerifyingKey,
    signer: &MachineDataSignerBindingV1,
    machine_root_verifying_key: &VerifyingKey,
) -> Result<PairResponsePlaintextV1, CryptoError> {
    verify_pair_response_envelope(machine_data_verifying_key, info, context, envelope, signer)?;
    let opened = hpke_open_base(
        recipient,
        &info.encode(),
        &context.encode_aad(),
        &hpke_envelope(&envelope.enc, &envelope.ciphertext),
    )?;
    let plaintext = PairResponsePlaintextV1::from_canonical_bytes(&opened)
        .map_err(|_| CryptoError::BadCiphertext)?;
    validate_pair_response_plaintext(info, &plaintext)?;
    verify_grant_and_authorization(
        machine_root_verifying_key,
        info.relay_server_id,
        &plaintext.relay_grant,
        &plaintext.device_authorization,
    )?;
    verify_key_directory(
        machine_data_verifying_key,
        signer,
        &key_directory_context(info),
        &plaintext.key_directory,
    )?;
    Ok(plaintext)
}

/// 只验证 PairResponse 外层 shape、MachineDataSign provenance 与 typed TBS 签名。
/// 本入口不解密 ciphertext，也不验证密文内 grant / authorization / key directory。
pub fn verify_pair_response_envelope(
    machine_data_verifying_key: &VerifyingKey,
    info: &PairResponseInfoV1,
    context: &OuterContextV1,
    envelope: &PairResponseV1,
    signer: &MachineDataSignerBindingV1,
) -> Result<(), CryptoError> {
    envelope.validate()?;
    require_signer(machine_data_verifying_key, signer.signing_key_fingerprint)?;
    let tbs = envelope.signature_tbs(info, context, signer)?;
    verify_validated_pairing_tbs(
        machine_data_verifying_key,
        &tbs,
        &envelope.machine_data_signature,
    )
}

fn key_directory_context(info: &PairResponseInfoV1) -> KeyDirectorySignatureContextV1 {
    KeyDirectorySignatureContextV1 {
        relay_server_id: info.relay_server_id,
        machine_route: info.machine_route,
        device_route: info.device_route,
        grant_serial: info.grant_serial,
        root_trust_epoch: info.root_trust_epoch,
    }
}

pub fn seal_pair_pending<R: ::hpke::rand_core::CryptoRng>(
    recipient: &HpkePublicKey,
    info: &PairRequestInfoV1,
    context: &OuterContextV1,
    request_hash: [u8; 32],
    machine_data_signing_key: &SigningKey,
    signer: &MachineDataSignerBindingV1,
    rng: &mut R,
) -> Result<PairingControlEnvelopeV1, CryptoError> {
    require_signer(
        &machine_data_signing_key.verifying_key(),
        signer.signing_key_fingerprint,
    )?;
    let mut pending = PairPendingV1 {
        request_hash,
        signature: Ed25519Signature([0; 64]),
    };
    let tbs = pending.signature_tbs(info, context, signer)?;
    pending.signature = sign_validated_pending_tbs(machine_data_signing_key, &tbs)?;
    pending.validate()?;
    let sealed = hpke_seal_base(
        recipient,
        &info.encode(),
        &context.encode_aad(),
        &pending.canonical_bytes()?,
        rng,
    )?;
    let envelope = PairingControlEnvelopeV1 {
        format_version: E2EE_FORMAT_VERSION,
        enc: sealed.enc,
        ciphertext: sealed.ciphertext,
    };
    envelope.validate()?;
    Ok(envelope)
}

pub fn open_pair_pending(
    recipient: &HpkePrivateKey,
    info: &PairRequestInfoV1,
    context: &OuterContextV1,
    envelope: &PairingControlEnvelopeV1,
    machine_data_verifying_key: &VerifyingKey,
    signer: &MachineDataSignerBindingV1,
) -> Result<PairPendingV1, CryptoError> {
    envelope.validate()?;
    require_signer(machine_data_verifying_key, signer.signing_key_fingerprint)?;
    let opened = hpke_open_base(
        recipient,
        &info.encode(),
        &context.encode_aad(),
        &hpke_envelope(&envelope.enc, &envelope.ciphertext),
    )?;
    let pending =
        PairPendingV1::from_canonical_bytes(&opened).map_err(|_| CryptoError::BadCiphertext)?;
    let tbs = pending.signature_tbs(info, context, signer)?;
    verify_validated_pending_tbs(machine_data_verifying_key, &tbs, &pending.signature)?;
    Ok(pending)
}

pub fn sign_device_authorization(
    root_signing_key: &SigningKey,
    relay_server_id: RelayServerId,
    grant: &RelayGrant,
    mut authorization: DeviceAuthorizationV1,
) -> Result<DeviceAuthorizationV1, CryptoError> {
    authorization.validate_unsigned_for_grant(grant)?;
    let root_fingerprint = signer_fingerprint(&root_signing_key.verifying_key());
    let tbs = authorization.to_be_signed_v1(relay_server_id, root_fingerprint)?;
    authorization.signature = sign_tbs(root_signing_key, &tbs).into();
    authorization.validate_for_grant(grant)?;
    Ok(authorization)
}

pub fn verify_device_authorization(
    root_verifying_key: &VerifyingKey,
    relay_server_id: RelayServerId,
    grant: &RelayGrant,
    authorization: &DeviceAuthorizationV1,
) -> Result<(), CryptoError> {
    authorization.validate_for_grant(grant)?;
    let root_fingerprint = signer_fingerprint(root_verifying_key);
    let tbs = authorization.to_be_signed_v1(relay_server_id, root_fingerprint)?;
    verify_tbs(
        root_verifying_key,
        &tbs,
        &SignatureBytes::from(authorization.signature),
    )
}

pub fn sign_pair_response_received(
    device_signing_key: &SigningKey,
    info: &PairResponseInfoV1,
    context: &OuterContextV1,
    mut receipt: PairResponseReceivedV1,
) -> Result<PairResponseReceivedV1, CryptoError> {
    let fingerprint = signer_fingerprint(&device_signing_key.verifying_key());
    let tbs = receipt.receipt_tbs(info, context, fingerprint)?;
    tbs.validate()?;
    receipt.signature = sign_raw(device_signing_key, &tbs.encode()?);
    receipt.canonical_bytes()?;
    Ok(receipt)
}

pub fn verify_pair_response_received(
    device_verifying_key: &VerifyingKey,
    info: &PairResponseInfoV1,
    context: &OuterContextV1,
    receipt: &PairResponseReceivedV1,
) -> Result<(), CryptoError> {
    let fingerprint = signer_fingerprint(device_verifying_key);
    let tbs = receipt.receipt_tbs(info, context, fingerprint)?;
    tbs.validate()?;
    verify_raw(device_verifying_key, &tbs.encode()?, &receipt.signature)
}

pub fn seal_pair_response_received<R: ::hpke::rand_core::CryptoRng>(
    recipient: &HpkePublicKey,
    info: &PairResponseInfoV1,
    context: &OuterContextV1,
    receipt: PairResponseReceivedV1,
    device_signing_key: &SigningKey,
    rng: &mut R,
) -> Result<PairingControlEnvelopeV1, CryptoError> {
    let receipt = sign_pair_response_received(device_signing_key, info, context, receipt)?;
    let sealed = hpke_seal_base(
        recipient,
        &info.encode(),
        &context.encode_aad(),
        &receipt.canonical_bytes()?,
        rng,
    )?;
    let envelope = PairingControlEnvelopeV1 {
        format_version: E2EE_FORMAT_VERSION,
        enc: sealed.enc,
        ciphertext: sealed.ciphertext,
    };
    envelope.validate()?;
    Ok(envelope)
}

pub fn open_pair_response_received(
    recipient: &HpkePrivateKey,
    info: &PairResponseInfoV1,
    context: &OuterContextV1,
    envelope: &PairingControlEnvelopeV1,
    device_verifying_key: &VerifyingKey,
) -> Result<PairResponseReceivedV1, CryptoError> {
    envelope.validate()?;
    let opened = hpke_open_base(
        recipient,
        &info.encode(),
        &context.encode_aad(),
        &hpke_envelope(&envelope.enc, &envelope.ciphertext),
    )?;
    let receipt = PairResponseReceivedV1::from_canonical_bytes(&opened)
        .map_err(|_| CryptoError::BadCiphertext)?;
    verify_pair_response_received(device_verifying_key, info, context, &receipt)?;
    Ok(receipt)
}

fn sign_validated_pairing_tbs(
    key: &SigningKey,
    tbs: &PairingEnvelopeTbsV1,
) -> Result<Ed25519Signature, CryptoError> {
    tbs.validate()?;
    Ok(sign_raw(key, &tbs.encode()?))
}

fn verify_validated_pairing_tbs(
    key: &VerifyingKey,
    tbs: &PairingEnvelopeTbsV1,
    signature: &Ed25519Signature,
) -> Result<(), CryptoError> {
    tbs.validate()?;
    verify_raw(key, &tbs.encode()?, signature)
}

fn sign_validated_pending_tbs(
    key: &SigningKey,
    tbs: &agentdeck_protocol::e2ee::PairPendingTbsV1,
) -> Result<Ed25519Signature, CryptoError> {
    tbs.validate()?;
    Ok(sign_raw(key, &tbs.encode()?))
}

fn verify_validated_pending_tbs(
    key: &VerifyingKey,
    tbs: &agentdeck_protocol::e2ee::PairPendingTbsV1,
    signature: &Ed25519Signature,
) -> Result<(), CryptoError> {
    tbs.validate()?;
    verify_raw(key, &tbs.encode()?, signature)
}

fn validate_pair_response_plaintext(
    info: &PairResponseInfoV1,
    plaintext: &PairResponsePlaintextV1,
) -> Result<(), CryptoError> {
    plaintext.validate()?;
    let grant = &plaintext.relay_grant;
    if plaintext.request_hash != info.request_hash
        || grant.machine_route != info.machine_route
        || grant.device_route != info.device_route
        || grant.grant_serial != info.grant_serial
        || grant.trust_epoch != info.root_trust_epoch
    {
        return Err(CryptoError::InvalidPairing(
            agentdeck_protocol::e2ee::PairingError::GrantBindingMismatch,
        ));
    }
    Ok(())
}

fn verify_grant_and_authorization(
    root_verifying_key: &VerifyingKey,
    relay_server_id: RelayServerId,
    grant: &RelayGrant,
    authorization: &DeviceAuthorizationV1,
) -> Result<(), CryptoError> {
    let root_fingerprint = signer_fingerprint(root_verifying_key);
    verify_tbs(
        root_verifying_key,
        &grant.to_be_signed_v1(relay_server_id, root_fingerprint),
        &SignatureBytes::from(grant.signature),
    )?;
    verify_device_authorization(root_verifying_key, relay_server_id, grant, authorization)
}
