//! P4.3 pairing 的 typed Ed25519 + HPKE wrappers。
//!
//! 调用方不能把任意 raw bytes 交给这些签名入口；所有签名都先通过 protocol-owned typed
//! TBS validation。HPKE plaintext/ciphertext 只使用 frozen canonical bytes。

use std::collections::HashSet;

use agentdeck_protocol::e2ee::{
    AuthorizationRequestV1, DeviceAuthorizationV1, E2EE_FORMAT_VERSION,
    KeyDirectorySignatureContextV1, KeyDirectoryV1, KeyId, KeyUpdateInfoV1,
    MachineDataSignerBindingV1, OuterContextV1, OuterFrameKind, PairInviteV1, PairPendingV1,
    PairRequestInfoV1, PairRequestPlaintextV1, PairRequestV1, PairResponseInfoV1,
    PairResponsePlaintextV1, PairResponseReceivedV1, PairResponseV1, PairingControlEnvelopeV1,
    PairingEnvelopeTbsV1, PairingError,
};
use agentdeck_protocol::relay_v2::RELAY_PROTOCOL_VERSION;
use agentdeck_protocol::relay_v2::auth::{
    CertRole, Ed25519Signature, PublicKeyBytes, RelayGrant, SignedCertificate,
};
use agentdeck_protocol::relay_v2::id::{RelayServerId, StreamRouteId};
use agentdeck_protocol::runtime::RUNTIME_PROTOCOL_VERSION;
use zeroize::{Zeroize, Zeroizing};

use crate::aead::{SecretAeadKey, derive_nonce_prefix};
use crate::canonical::sha256;
use crate::error::CryptoError;
use crate::hpke::{HpkeEnvelopeV1, HpkePrivateKey, HpkePublicKey, hpke_open_base, hpke_seal_base};
use crate::key_directory::{open_key_directory_entry, verify_key_directory};
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

struct SensitivePairRequestPlaintext(Option<PairRequestPlaintextV1>);

impl SensitivePairRequestPlaintext {
    fn new(value: PairRequestPlaintextV1) -> Self {
        Self(Some(value))
    }

    fn as_ref(&self) -> &PairRequestPlaintextV1 {
        self.0.as_ref().expect("sensitive plaintext is present")
    }

    fn into_inner(mut self) -> PairRequestPlaintextV1 {
        self.0.take().expect("sensitive plaintext is present")
    }
}

impl Drop for SensitivePairRequestPlaintext {
    fn drop(&mut self) {
        if let Some(value) = &mut self.0 {
            value.invite_secret.zeroize();
        }
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

/// PairResponse 验证必须匹配的本地 pending 事实。
///
/// 这个值本身不是 verified marker；它只把所有 caller expectations 收拢成一个参数，避免
/// 调用点漏传轴。Persistent client 必须从已提交的 pending record 构造它，而不是从 response
/// 自报字段反向填充。
pub struct PairResponseExpectedV1<'a> {
    invite: &'a PairInviteV1,
    request_hash: [u8; 32],
    device_sign_pubkey: [u8; 32],
    device_hpke_pubkey: [u8; 32],
    authorization: &'a AuthorizationRequestV1,
    now_ms: u64,
}

impl std::fmt::Debug for PairResponseExpectedV1<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PairResponseExpectedV1([REDACTED])")
    }
}

impl<'a> PairResponseExpectedV1<'a> {
    #[must_use]
    pub const fn new(
        invite: &'a PairInviteV1,
        request_hash: [u8; 32],
        device_sign_pubkey: [u8; 32],
        device_hpke_pubkey: [u8; 32],
        authorization: &'a AuthorizationRequestV1,
        now_ms: u64,
    ) -> Self {
        Self {
            invite,
            request_hash,
            device_sign_pubkey,
            device_hpke_pubkey,
            authorization,
            now_ms,
        }
    }
}

/// 已用 pending DeviceHPKE 解封并绑定到 exact key identity 的 directory entry。
/// 字段私有、不实现 Clone/Serde，raw key 只能通过消费本值取得。
pub struct OpenedDirectoryKeyV1 {
    key_id: KeyId,
    stream_route: Option<StreamRouteId>,
    key: SecretAeadKey,
}

impl std::fmt::Debug for OpenedDirectoryKeyV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OpenedDirectoryKeyV1")
            .field("key_id", &self.key_id)
            .field("stream_route", &self.stream_route.map(|_| "[REDACTED]"))
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl OpenedDirectoryKeyV1 {
    #[must_use]
    pub const fn key_id(&self) -> KeyId {
        self.key_id
    }

    #[must_use]
    pub const fn stream_route(&self) -> Option<StreamRouteId> {
        self.stream_route
    }

    /// 不暴露 raw key 的稳定 nonce-prefix 投影，供调用方建立 counter domain。
    #[must_use]
    pub fn derived_nonce_prefix(&self) -> [u8; 4] {
        derive_nonce_prefix(&self.key)
    }

    #[must_use]
    pub fn into_key(self) -> SecretAeadKey {
        self.key
    }
}

/// 完整通过 Root→Data cert、MachineDataSign、DeviceHPKE、grant/authorization、
/// KeyDirectory 签名与每项 HPKE 解封的 PairResponse。
///
/// 字段私有且不实现 Clone/Serialize；后续 paired promotion 必须接受本能力类型，而不能接受
/// 裸 `PairResponsePlaintextV1`。
///
/// ```compile_fail
/// use agentdeck_crypto::VerifiedPairResponseV1;
/// fn require_clone<T: Clone>() {}
/// require_clone::<VerifiedPairResponseV1>();
/// ```
pub struct VerifiedPairResponseV1 {
    canonical_response: Vec<u8>,
    response_hash: [u8; 32],
    info: PairResponseInfoV1,
    machine_root_pubkey: PublicKeyBytes,
    machine_root_fingerprint: [u8; 32],
    data_sign_certificate: SignedCertificate,
    signer: MachineDataSignerBindingV1,
    relay_grant: RelayGrant,
    device_authorization: DeviceAuthorizationV1,
    key_directory: KeyDirectoryV1,
    opened_keys: Vec<OpenedDirectoryKeyV1>,
}

impl std::fmt::Debug for VerifiedPairResponseV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("VerifiedPairResponseV1([REDACTED])")
    }
}

impl VerifiedPairResponseV1 {
    #[must_use]
    pub fn canonical_response(&self) -> &[u8] {
        &self.canonical_response
    }

    #[must_use]
    pub const fn response_hash(&self) -> [u8; 32] {
        self.response_hash
    }

    #[must_use]
    pub const fn info(&self) -> &PairResponseInfoV1 {
        &self.info
    }

    #[must_use]
    pub const fn machine_root_pubkey(&self) -> PublicKeyBytes {
        self.machine_root_pubkey
    }

    #[must_use]
    pub const fn machine_root_fingerprint(&self) -> [u8; 32] {
        self.machine_root_fingerprint
    }

    #[must_use]
    pub const fn data_sign_certificate(&self) -> &SignedCertificate {
        &self.data_sign_certificate
    }

    #[must_use]
    pub const fn signer(&self) -> &MachineDataSignerBindingV1 {
        &self.signer
    }

    #[must_use]
    pub const fn relay_grant(&self) -> &RelayGrant {
        &self.relay_grant
    }

    #[must_use]
    pub const fn device_authorization(&self) -> &DeviceAuthorizationV1 {
        &self.device_authorization
    }

    #[must_use]
    pub const fn key_directory(&self) -> &KeyDirectoryV1 {
        &self.key_directory
    }

    #[must_use]
    pub fn opened_keys(&self) -> &[OpenedDirectoryKeyV1] {
        &self.opened_keys
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
    let canonical_plaintext = Zeroizing::new(plaintext.canonical_bytes()?);
    let sealed = hpke_seal_base(
        recipient,
        &info_bytes,
        &aad,
        canonical_plaintext.as_slice(),
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
    let opened = Zeroizing::new(hpke_open_base(
        recipient,
        &info.encode(),
        &context.encode_aad(),
        &hpke_envelope(&envelope.enc, &envelope.ciphertext),
    )?);
    let plaintext = SensitivePairRequestPlaintext::new(
        PairRequestPlaintextV1::from_canonical_bytes(&opened)
            .map_err(|_| CryptoError::BadCiphertext)?,
    );
    if &plaintext.as_ref().invite_secret != expected_invite_secret {
        return Err(CryptoError::BadCiphertext);
    }
    let verifying_key = VerifyingKey::from_bytes(&plaintext.as_ref().device_sign_pubkey.0)?;
    let fingerprint = plaintext.as_ref().device_sign_fingerprint();
    require_signer(&verifying_key, fingerprint)?;
    let tbs = envelope.proof_tbs(info, context, fingerprint)?;
    verify_validated_pairing_tbs(&verifying_key, &tbs, &envelope.device_proof_signature)?;
    Ok(plaintext.into_inner())
}

/// 验证并冻结 Store 可接受的 PairRequest type-state。
pub fn open_pair_request_verified(
    recipient: &HpkePrivateKey,
    info: &PairRequestInfoV1,
    context: &OuterContextV1,
    expected_invite_secret: &[u8; 32],
    envelope: &PairRequestV1,
) -> Result<VerifiedPairRequestV1, CryptoError> {
    let plaintext = SensitivePairRequestPlaintext::new(open_pair_request(
        recipient,
        info,
        context,
        expected_invite_secret,
        envelope,
    )?);
    let canonical_request = envelope.canonical_bytes()?;
    let request_hash = sha256(&canonical_request);
    let canonical_plaintext = Zeroizing::new(plaintext.as_ref().canonical_bytes()?);
    Ok(VerifiedPairRequestV1 {
        canonical_request,
        request_hash,
        canonical_plaintext,
        info: info.clone(),
        context: context.clone(),
    })
}

/// 只验证 PairRequest 的形状、完整 canonical carrier 上的 DeviceSign possession proof
/// 及其 info/AAD 绑定；不持有 invite private key，因此不解密 ciphertext。
pub fn verify_pair_request_envelope(
    device_verifying_key: &VerifyingKey,
    info: &PairRequestInfoV1,
    context: &OuterContextV1,
    envelope: &PairRequestV1,
) -> Result<(), CryptoError> {
    envelope.validate()?;
    let fingerprint = signer_fingerprint(device_verifying_key);
    let tbs = envelope.proof_tbs(info, context, fingerprint)?;
    verify_validated_pairing_tbs(device_verifying_key, &tbs, &envelope.device_proof_signature)
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

/// 从 canonical PairResponse 构造不可伪造的完整 verified capability。
///
/// 本入口自行解析 embedded info、派生 PairResponse/KeyUpdate context 与 verifier；调用方不能
/// 通过传入自选 info/context 绕开 pending、证书或 wrapped-key 绑定。
pub fn open_pair_response_verified(
    recipient: &HpkePrivateKey,
    expected: PairResponseExpectedV1<'_>,
    canonical_response: &[u8],
) -> Result<VerifiedPairResponseV1, CryptoError> {
    let response = PairResponseV1::from_canonical_bytes(canonical_response)?;
    expected.invite.validate(expected.now_ms)?;
    expected.authorization.validate()?;
    let invite_hash = expected.invite.canonical_sha256()?;
    let info = &response.info;
    if info.relay_server_id != expected.invite.relay_server_id
        || info.pair_route != expected.invite.pair_route
        || info.invite_hash != invite_hash
        || info.expiry_ms != expected.invite.expires_at_ms
        || info.request_hash != expected.request_hash
    {
        return Err(invalid_verified_response(
            "pending PairResponse info binding",
        ));
    }

    if recipient.public_key().to_bytes() != expected.device_hpke_pubkey {
        return Err(CryptoError::InvalidKey(
            "pending DeviceHPKE private/public key mismatch",
        ));
    }
    VerifyingKey::from_bytes(&expected.device_sign_pubkey)
        .map_err(|_| CryptoError::InvalidKey("pending DeviceSign public key"))?;
    HpkePublicKey::from_bytes(&expected.device_hpke_pubkey)
        .map_err(|_| CryptoError::InvalidKey("pending DeviceHPKE public key"))?;

    let root_verifying_key = VerifyingKey::from_bytes(&expected.invite.machine_root_pubkey.0)
        .map_err(|_| CryptoError::InvalidKey("MachineRoot public key"))?;
    if signer_fingerprint(&root_verifying_key) != expected.invite.machine_root_fingerprint {
        return Err(CryptoError::InvalidKey("MachineRoot fingerprint mismatch"));
    }
    let certificate = &expected.invite.data_sign_cert;
    if certificate.cert_role != CertRole::Data
        || certificate.generation.value() == 0
        || certificate.trust_epoch != info.root_trust_epoch
        || certificate
            .not_after_ms
            .is_some_and(|not_after_ms| expected.now_ms >= not_after_ms)
    {
        return Err(invalid_verified_response(
            "MachineDataSign certificate binding",
        ));
    }
    verify_tbs(
        &root_verifying_key,
        &certificate.to_be_signed_v1(
            info.relay_server_id,
            info.machine_route,
            expected.invite.machine_root_fingerprint,
        ),
        &SignatureBytes::from(certificate.signature),
    )?;

    let machine_data_verifying_key = VerifyingKey::from_bytes(&certificate.subject_pubkey.0)
        .map_err(|_| CryptoError::InvalidKey("MachineDataSign public key"))?;
    let signer = MachineDataSignerBindingV1::from_certificate(certificate)?;
    let response_context = pair_response_context(info.pair_route);
    let plaintext = open_pair_response(
        recipient,
        info,
        &response_context,
        &response,
        &machine_data_verifying_key,
        &signer,
        &root_verifying_key,
    )?;

    let grant = &plaintext.relay_grant;
    let authorization = &plaintext.device_authorization;
    if plaintext.request_hash != expected.request_hash
        || grant.machine_route != info.machine_route
        || grant.device_route != info.device_route
        || grant.grant_serial != info.grant_serial
        || grant.device_sign_pubkey.0 != expected.device_sign_pubkey
        || grant.root_key_id != certificate.root_key_id
        || grant.trust_epoch != certificate.trust_epoch
        || authorization.device_hpke_pubkey.0 != expected.device_hpke_pubkey
        || authorization.capabilities != expected.authorization.capabilities
        || authorization.permissions != expected.authorization.permissions
    {
        return Err(invalid_verified_response(
            "pending grant or authorization binding",
        ));
    }

    let mut semantic_slots = HashSet::with_capacity(plaintext.key_directory.entries.len());
    let mut opened_keys = Vec::with_capacity(plaintext.key_directory.entries.len());
    for entry in &plaintext.key_directory.entries {
        if !semantic_slots.insert((entry.key_id.purpose, entry.stream_route)) {
            return Err(invalid_verified_response(
                "ambiguous key directory current slot",
            ));
        }
        let entry_info = KeyUpdateInfoV1 {
            e2ee_format_version: E2EE_FORMAT_VERSION,
            runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
            relay_server_id: info.relay_server_id,
            machine_route: info.machine_route,
            device_route: info.device_route,
            stream_route: entry.stream_route,
            grant_serial: info.grant_serial,
            root_trust_epoch: info.root_trust_epoch,
            key_directory_revision: plaintext.key_directory.revision,
            key_purpose: entry.key_id.purpose,
            key_epoch: entry.key_id.epoch,
        };
        let entry_context = key_update_context(&entry_info);
        let key = open_key_directory_entry(recipient, &entry_info, &entry_context, entry)?;
        opened_keys.push(OpenedDirectoryKeyV1 {
            key_id: entry.key_id,
            stream_route: entry.stream_route,
            key,
        });
    }

    let PairResponsePlaintextV1 {
        relay_grant,
        device_authorization,
        key_directory,
        ..
    } = plaintext;
    Ok(VerifiedPairResponseV1 {
        canonical_response: canonical_response.to_vec(),
        response_hash: sha256(canonical_response),
        info: response.info,
        machine_root_pubkey: expected.invite.machine_root_pubkey,
        machine_root_fingerprint: expected.invite.machine_root_fingerprint,
        data_sign_certificate: certificate.clone(),
        signer,
        relay_grant,
        device_authorization,
        key_directory,
        opened_keys,
    })
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

fn pair_response_context(pair_route: agentdeck_protocol::relay_v2::PairRouteId) -> OuterContextV1 {
    OuterContextV1 {
        frame_kind: OuterFrameKind::PairResponse,
        relay_protocol_version: RELAY_PROTOCOL_VERSION,
        e2ee_format_version: E2EE_FORMAT_VERSION,
        machine_route: None,
        device_route: None,
        stream_route: None,
        request_route: None,
        pair_route: Some(pair_route),
        stream_generation: None,
        stream_cursor: None,
        stream_seq: None,
        message_key_epoch: 0,
    }
}

fn key_update_context(info: &KeyUpdateInfoV1) -> OuterContextV1 {
    OuterContextV1 {
        frame_kind: OuterFrameKind::KeyUpdate,
        relay_protocol_version: RELAY_PROTOCOL_VERSION,
        e2ee_format_version: E2EE_FORMAT_VERSION,
        machine_route: Some(info.machine_route),
        device_route: Some(info.device_route),
        stream_route: info.stream_route,
        request_route: None,
        pair_route: None,
        stream_generation: None,
        stream_cursor: None,
        stream_seq: None,
        message_key_epoch: info.key_epoch,
    }
}

fn invalid_verified_response(field: &'static str) -> CryptoError {
    CryptoError::InvalidPairing(PairingError::InvalidField(field))
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
