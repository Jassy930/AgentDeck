//! PairResponse delivery receipt 与 DeviceRevocation 的纯密码学边界。
//!
//! 本模块不读写 Store、不发送网络 frame，也不接收 raw MachineRoot/MachineHPKE 私钥。
//! receipt verifier 只从 durable frozen invite/grant/response 重建完整 info/AAD；revocation
//! freezer 只委托 [`PairingMachineAuthority`] 的 typed MachineRoot 签名入口，并在返回前自验。

use std::fmt;

use agentdeck_crypto::{
    CryptoError, HpkePrivateKey, SignatureBytes, VerifyingKey, open_pair_response_received, sha256,
    verify_pair_response_envelope, verify_pair_response_received, verify_tbs,
};
use agentdeck_protocol::e2ee::{
    E2EE_FORMAT_VERSION, MachineDataSignerBindingV1, OuterContextV1, OuterFrameKind, PairInviteV1,
    PairResponseInfoV1, PairResponseReceivedV1, PairResponseV1, PairingControlEnvelopeV1,
};
use agentdeck_protocol::relay_v2::{
    DeviceRevocation, DeviceRouteId, Ed25519Signature, GrantSerial, MachineRouteId, PairRouteId,
    PublicKeyBytes, RELAY_PROTOCOL_VERSION, RelayGrant, RelayServerId, RootKeyId, TrustEpoch,
};
use agentdeck_protocol::runtime::RUNTIME_PROTOCOL_VERSION;
use thiserror::Error;

use super::bootstrap::validate_pairing_device_sign_key;
use super::transport::{PairingMachineAuthority, RemoteTransportError};

/// Pairing access authority 的稳定、无敏感材料 failure taxonomy。
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub(crate) enum PairingAccessError {
    #[error("durable frozen PairResponse artifacts are invalid")]
    InvalidFrozenResponse,
    #[error("PairResponseReceived canonical encoding is invalid")]
    InvalidReceiptEncoding,
    #[error("PairResponseReceived does not match the frozen response")]
    ReceiptBindingMismatch,
    #[error("PairResponseReceived DeviceSign signature is invalid")]
    InvalidReceiptSignature,
    #[error("pairing MachineRoot authority is unavailable")]
    AuthorityUnavailable,
    #[error("pairing MachineRoot authority does not match the revocation target")]
    AuthorityMismatch,
    #[error("the durable grant cannot authorize a revocation")]
    InvalidRevocationGrant,
    #[error("MachineRoot could not sign DeviceRevocation")]
    RevocationSigningFailed,
    #[error("signed DeviceRevocation failed exact self-verification")]
    RevocationSelfVerificationFailed,
}

impl PairingAccessError {
    #[must_use]
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::InvalidFrozenResponse => "daemon.pairing.frozen_response_invalid",
            Self::InvalidReceiptEncoding => "daemon.pairing.receipt_encoding_invalid",
            Self::ReceiptBindingMismatch => "daemon.pairing.receipt_binding_mismatch",
            Self::InvalidReceiptSignature => "daemon.pairing.receipt_signature_invalid",
            Self::AuthorityUnavailable => "daemon.pairing.revocation_authority_unavailable",
            Self::AuthorityMismatch => "daemon.pairing.revocation_authority_mismatch",
            Self::InvalidRevocationGrant => "daemon.pairing.revocation_grant_invalid",
            Self::RevocationSigningFailed => "daemon.pairing.revocation_signing_failed",
            Self::RevocationSelfVerificationFailed => {
                "daemon.pairing.revocation_self_verification_failed"
            }
        }
    }
}

/// 从 durable frozen artifacts 重建的只读 receipt 验证能力。
///
/// 邀请 secret、响应密文和签名对象本身不会被保留；该类型故意不实现 `Clone`。
pub(crate) struct PairResponseAccessBinding {
    info: PairResponseInfoV1,
    receipt_context: OuterContextV1,
    device_verifying_key: VerifyingKey,
    device_sign_fingerprint: [u8; 32],
    grant_hash: [u8; 32],
    response_hash: [u8; 32],
}

impl fmt::Debug for PairResponseAccessBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PairResponseAccessBinding([REDACTED])")
    }
}

impl PairResponseAccessBinding {
    /// 从 Store 已认证并冻结的 exact invite/grant/response 重新计算全部 receipt 轴。
    /// 这里不读取当前时间；expiry 的 first-valid CAS 仍由 durable lifecycle 负责。
    pub(crate) fn from_frozen(
        invite: &PairInviteV1,
        request_hash: [u8; 32],
        grant: &RelayGrant,
        response: &PairResponseV1,
    ) -> Result<Self, PairingAccessError> {
        invite
            .validate_static()
            .map_err(|_| PairingAccessError::InvalidFrozenResponse)?;
        if request_hash == [0; 32]
            || grant.machine_route.as_bytes() == &[0; 16]
            || grant.device_route.as_bytes() == &[0; 16]
            || grant.grant_serial.value() == 0
            || grant.signature.0 == [0; 64]
            || grant.root_key_id != invite.data_sign_cert.root_key_id
            || grant.trust_epoch != invite.data_sign_cert.trust_epoch
        {
            return Err(PairingAccessError::InvalidFrozenResponse);
        }
        validate_pairing_device_sign_key(invite.relay_server_id, grant.device_sign_pubkey)
            .map_err(|_| PairingAccessError::InvalidFrozenResponse)?;

        let root_verifier = VerifyingKey::from_bytes(&invite.machine_root_pubkey.0)
            .map_err(|_| PairingAccessError::InvalidFrozenResponse)?;
        if sha256(&invite.machine_root_pubkey.0) != invite.machine_root_fingerprint {
            return Err(PairingAccessError::InvalidFrozenResponse);
        }
        verify_tbs(
            &root_verifier,
            &invite.data_sign_cert.to_be_signed_v1(
                invite.relay_server_id,
                grant.machine_route,
                invite.machine_root_fingerprint,
            ),
            &SignatureBytes::from(invite.data_sign_cert.signature),
        )
        .map_err(|_| PairingAccessError::InvalidFrozenResponse)?;
        verify_tbs(
            &root_verifier,
            &grant.to_be_signed_v1(invite.relay_server_id, invite.machine_root_fingerprint),
            &SignatureBytes::from(grant.signature),
        )
        .map_err(|_| PairingAccessError::InvalidFrozenResponse)?;

        let invite_hash = invite
            .canonical_sha256()
            .map_err(|_| PairingAccessError::InvalidFrozenResponse)?;
        let grant_hash = grant.canonical_sha256();
        let response_hash = response
            .canonical_sha256()
            .map_err(|_| PairingAccessError::InvalidFrozenResponse)?;
        if invite_hash == [0; 32] || grant_hash == [0; 32] || response_hash == [0; 32] {
            return Err(PairingAccessError::InvalidFrozenResponse);
        }
        let info = PairResponseInfoV1 {
            e2ee_format_version: E2EE_FORMAT_VERSION,
            runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
            relay_server_id: invite.relay_server_id,
            pair_route: invite.pair_route,
            invite_hash,
            expiry_ms: invite.expires_at_ms,
            request_hash,
            machine_route: grant.machine_route,
            device_route: grant.device_route,
            grant_serial: grant.grant_serial,
            root_trust_epoch: grant.trust_epoch,
        };
        let response_context = pairing_context(invite.pair_route, OuterFrameKind::PairResponse);
        let signer = MachineDataSignerBindingV1::from_certificate(&invite.data_sign_cert)
            .map_err(|_| PairingAccessError::InvalidFrozenResponse)?;
        let data_verifier = VerifyingKey::from_bytes(&invite.data_sign_cert.subject_pubkey.0)
            .map_err(|_| PairingAccessError::InvalidFrozenResponse)?;
        verify_pair_response_envelope(&data_verifier, &info, &response_context, response, &signer)
            .map_err(|_| PairingAccessError::InvalidFrozenResponse)?;

        let receipt_context =
            pairing_context(invite.pair_route, OuterFrameKind::PairResponseReceived);
        let device_verifying_key = VerifyingKey::from_bytes(&grant.device_sign_pubkey.0)
            .map_err(|_| PairingAccessError::InvalidFrozenResponse)?;
        let device_sign_fingerprint = sha256(&grant.device_sign_pubkey.0);
        Ok(Self {
            info,
            receipt_context,
            device_verifying_key,
            device_sign_fingerprint,
            grant_hash,
            response_hash,
        })
    }

    /// Canonical parse、完整 TBS 验签、三个 frozen hash exact-match；任一步失败都不产出 proof。
    pub(crate) fn verify_signed_receipt(
        &self,
        canonical_receipt: &[u8],
    ) -> Result<VerifiedPairResponseReceipt, PairingAccessError> {
        let receipt = PairResponseReceivedV1::from_canonical_bytes(canonical_receipt)
            .map_err(|_| PairingAccessError::InvalidReceiptEncoding)?;
        if receipt
            .canonical_bytes()
            .map_err(|_| PairingAccessError::InvalidReceiptEncoding)?
            != canonical_receipt
        {
            return Err(PairingAccessError::InvalidReceiptEncoding);
        }
        self.verify_parsed_receipt(receipt, canonical_receipt.to_vec())
    }

    /// 打开实际 PairData carrier 并验证 receipt。这里的 key **只能**是该 PairInvite 的
    /// ephemeral HPKE private key；禁止传入长期 MachineHPKE。临时 key 由 authenticated Store
    /// projection 提供，并一直保留到 terminal Close ACK 后再 scrub。
    pub(crate) fn open_and_verify_receipt(
        &self,
        invite_ephemeral_private_key: &HpkePrivateKey,
        canonical_envelope: &[u8],
    ) -> Result<VerifiedPairResponseReceipt, PairingAccessError> {
        let envelope = PairingControlEnvelopeV1::from_canonical_bytes(canonical_envelope)
            .map_err(|_| PairingAccessError::InvalidReceiptEncoding)?;
        if envelope
            .canonical_bytes()
            .map_err(|_| PairingAccessError::InvalidReceiptEncoding)?
            != canonical_envelope
        {
            return Err(PairingAccessError::InvalidReceiptEncoding);
        }
        let receipt = open_pair_response_received(
            invite_ephemeral_private_key,
            &self.info,
            &self.receipt_context,
            &envelope,
            &self.device_verifying_key,
        )
        .map_err(map_receipt_crypto_error)?;
        let canonical_receipt = receipt
            .canonical_bytes()
            .map_err(|_| PairingAccessError::InvalidReceiptEncoding)?;
        self.verify_parsed_receipt(receipt, canonical_receipt)
    }

    fn verify_parsed_receipt(
        &self,
        receipt: PairResponseReceivedV1,
        canonical_receipt: Vec<u8>,
    ) -> Result<VerifiedPairResponseReceipt, PairingAccessError> {
        if sha256(&self.device_verifying_key.to_bytes()) != self.device_sign_fingerprint {
            return Err(PairingAccessError::ReceiptBindingMismatch);
        }
        let tbs = receipt
            .receipt_tbs(
                &self.info,
                &self.receipt_context,
                self.device_sign_fingerprint,
            )
            .map_err(|_| PairingAccessError::ReceiptBindingMismatch)?;
        verify_pair_response_received(
            &self.device_verifying_key,
            &self.info,
            &self.receipt_context,
            &receipt,
        )
        .map_err(map_receipt_crypto_error)?;
        if receipt.request_hash != self.info.request_hash
            || receipt.grant_hash != self.grant_hash
            || receipt.response_hash != self.response_hash
        {
            return Err(PairingAccessError::ReceiptBindingMismatch);
        }
        let tbs_bytes = tbs
            .encode()
            .map_err(|_| PairingAccessError::ReceiptBindingMismatch)?;
        Ok(VerifiedPairResponseReceipt {
            canonical_receipt,
            receipt,
            relay_server_id: self.info.relay_server_id,
            pair_route: self.info.pair_route,
            invite_hash: self.info.invite_hash,
            expiry_ms: self.info.expiry_ms,
            machine_route: self.info.machine_route,
            device_route: self.info.device_route,
            grant_serial: self.info.grant_serial,
            root_trust_epoch: self.info.root_trust_epoch,
            device_sign_fingerprint: self.device_sign_fingerprint,
            info_sha256: sha256(&self.info.encode()),
            aad_sha256: sha256(&self.receipt_context.encode_aad()),
            tbs_sha256: sha256(&tbs_bytes),
        })
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) const fn info(&self) -> &PairResponseInfoV1 {
        &self.info
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) const fn receipt_context(&self) -> &OuterContextV1 {
        &self.receipt_context
    }
}

/// 只有完成 canonical parse、DeviceSign 验签和 frozen 三 hash 匹配后才能构造的 proof。
pub(crate) struct VerifiedPairResponseReceipt {
    canonical_receipt: Vec<u8>,
    receipt: PairResponseReceivedV1,
    relay_server_id: RelayServerId,
    pair_route: PairRouteId,
    invite_hash: [u8; 32],
    expiry_ms: u64,
    machine_route: MachineRouteId,
    device_route: DeviceRouteId,
    grant_serial: GrantSerial,
    root_trust_epoch: TrustEpoch,
    device_sign_fingerprint: [u8; 32],
    info_sha256: [u8; 32],
    aad_sha256: [u8; 32],
    tbs_sha256: [u8; 32],
}

impl fmt::Debug for VerifiedPairResponseReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VerifiedPairResponseReceipt([REDACTED])")
    }
}

impl VerifiedPairResponseReceipt {
    #[must_use]
    pub(crate) fn canonical_receipt(&self) -> &[u8] {
        &self.canonical_receipt
    }

    #[must_use]
    pub(crate) const fn request_hash(&self) -> [u8; 32] {
        self.receipt.request_hash
    }

    #[must_use]
    pub(crate) const fn grant_hash(&self) -> [u8; 32] {
        self.receipt.grant_hash
    }

    #[must_use]
    pub(crate) const fn response_hash(&self) -> [u8; 32] {
        self.receipt.response_hash
    }

    #[must_use]
    pub(crate) const fn relay_server_id(&self) -> RelayServerId {
        self.relay_server_id
    }

    #[must_use]
    pub(crate) const fn pair_route(&self) -> PairRouteId {
        self.pair_route
    }

    #[must_use]
    pub(crate) const fn invite_hash(&self) -> [u8; 32] {
        self.invite_hash
    }

    #[must_use]
    pub(crate) const fn expiry_ms(&self) -> u64 {
        self.expiry_ms
    }

    #[must_use]
    pub(crate) const fn machine_route(&self) -> MachineRouteId {
        self.machine_route
    }

    #[must_use]
    pub(crate) const fn device_route(&self) -> DeviceRouteId {
        self.device_route
    }

    #[must_use]
    pub(crate) const fn grant_serial(&self) -> GrantSerial {
        self.grant_serial
    }

    #[must_use]
    pub(crate) const fn root_trust_epoch(&self) -> TrustEpoch {
        self.root_trust_epoch
    }

    #[must_use]
    pub(crate) const fn device_sign_fingerprint(&self) -> [u8; 32] {
        self.device_sign_fingerprint
    }

    #[must_use]
    pub(crate) const fn info_sha256(&self) -> [u8; 32] {
        self.info_sha256
    }

    #[must_use]
    pub(crate) const fn aad_sha256(&self) -> [u8; 32] {
        self.aad_sha256
    }

    #[must_use]
    pub(crate) const fn tbs_sha256(&self) -> [u8; 32] {
        self.tbs_sha256
    }
}

/// 以 durable signed grant 为唯一目标，冻结 MachineRoot-signed revocation。
/// 该 builder 借用 typed authority，故意不实现 `Clone`。
pub(crate) struct DeviceRevocationFreezer<'a> {
    authority: &'a PairingMachineAuthority,
    relay_server_id: RelayServerId,
    grant: &'a RelayGrant,
}

impl fmt::Debug for DeviceRevocationFreezer<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DeviceRevocationFreezer([REDACTED])")
    }
}

impl<'a> DeviceRevocationFreezer<'a> {
    #[must_use]
    pub(crate) const fn new(
        authority: &'a PairingMachineAuthority,
        relay_server_id: RelayServerId,
        grant: &'a RelayGrant,
    ) -> Self {
        Self {
            authority,
            relay_server_id,
            grant,
        }
    }

    pub(crate) fn freeze(self) -> Result<FrozenDeviceRevocation, PairingAccessError> {
        freeze_device_revocation_with(
            self.relay_server_id,
            self.grant,
            &ProductionRevocationAuthority(self.authority),
        )
    }
}

/// 已签名、自验且在构造阶段通过 canonical bytes/hash 一致性检查的撤销对象。
pub(crate) struct FrozenDeviceRevocation {
    revocation: DeviceRevocation,
    #[cfg(test)]
    canonical_revocation: Vec<u8>,
    #[cfg(test)]
    revocation_hash: [u8; 32],
}

impl fmt::Debug for FrozenDeviceRevocation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FrozenDeviceRevocation([REDACTED])")
    }
}

impl FrozenDeviceRevocation {
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn revocation(&self) -> &DeviceRevocation {
        &self.revocation
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn canonical_revocation(&self) -> &[u8] {
        &self.canonical_revocation
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) const fn revocation_hash(&self) -> [u8; 32] {
        self.revocation_hash
    }

    #[must_use]
    pub(crate) fn into_revocation(self) -> DeviceRevocation {
        self.revocation
    }
}

struct MachineAuthorityBinding {
    relay_server_id: RelayServerId,
    machine_route: MachineRouteId,
    root_public_key: PublicKeyBytes,
    root_fingerprint: [u8; 32],
    root_key_id: RootKeyId,
    trust_epoch: TrustEpoch,
}

impl fmt::Debug for MachineAuthorityBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MachineAuthorityBinding([REDACTED])")
    }
}

trait RevocationCryptographicAuthority {
    fn active_binding(&self) -> Result<MachineAuthorityBinding, PairingAccessError>;

    fn sign_device_revocation(
        &self,
        revocation: DeviceRevocation,
    ) -> Result<DeviceRevocation, PairingAccessError>;
}

struct ProductionRevocationAuthority<'a>(&'a PairingMachineAuthority);

impl RevocationCryptographicAuthority for ProductionRevocationAuthority<'_> {
    fn active_binding(&self) -> Result<MachineAuthorityBinding, PairingAccessError> {
        let anchor = self.0.invite_anchor().map_err(map_active_authority_error)?;
        Ok(MachineAuthorityBinding {
            relay_server_id: anchor.relay_server_id(),
            machine_route: anchor.machine_route(),
            root_public_key: anchor.root_public_key(),
            root_fingerprint: anchor.root_fingerprint(),
            root_key_id: anchor.root_key_id(),
            trust_epoch: anchor.trust_epoch(),
        })
    }

    fn sign_device_revocation(
        &self,
        revocation: DeviceRevocation,
    ) -> Result<DeviceRevocation, PairingAccessError> {
        self.0
            .sign_device_revocation(revocation)
            .map_err(map_signing_authority_error)
    }
}

fn freeze_device_revocation_with(
    relay_server_id: RelayServerId,
    grant: &RelayGrant,
    authority: &impl RevocationCryptographicAuthority,
) -> Result<FrozenDeviceRevocation, PairingAccessError> {
    let binding = authority.active_binding()?;
    validate_grant_for_revocation(relay_server_id, grant, &binding)?;
    let expected = DeviceRevocation {
        machine_route: grant.machine_route,
        device_route: grant.device_route,
        grant_serial: grant.grant_serial,
        root_key_id: grant.root_key_id,
        trust_epoch: grant.trust_epoch,
        signature: Ed25519Signature([0; 64]),
    };
    let signed = authority.sign_device_revocation(expected)?;
    if signed.machine_route != grant.machine_route
        || signed.device_route != grant.device_route
        || signed.grant_serial != grant.grant_serial
        || signed.root_key_id != grant.root_key_id
        || signed.trust_epoch != grant.trust_epoch
        || signed.signature.0 == [0; 64]
    {
        return Err(PairingAccessError::RevocationSelfVerificationFailed);
    }
    let root_verifier = binding_root_verifier(&binding)
        .map_err(|_| PairingAccessError::RevocationSelfVerificationFailed)?;
    verify_tbs(
        &root_verifier,
        &signed.to_be_signed_v1(relay_server_id, binding.root_fingerprint),
        &SignatureBytes::from(signed.signature),
    )
    .map_err(|_| PairingAccessError::RevocationSelfVerificationFailed)?;
    let canonical_revocation = signed.canonical_bytes();
    let revocation_hash = sha256(&canonical_revocation);
    if revocation_hash == [0; 32] || signed.canonical_sha256() != revocation_hash {
        return Err(PairingAccessError::RevocationSelfVerificationFailed);
    }
    Ok(FrozenDeviceRevocation {
        revocation: signed,
        #[cfg(test)]
        canonical_revocation,
        #[cfg(test)]
        revocation_hash,
    })
}

fn validate_grant_for_revocation(
    relay_server_id: RelayServerId,
    grant: &RelayGrant,
    binding: &MachineAuthorityBinding,
) -> Result<(), PairingAccessError> {
    if relay_server_id != binding.relay_server_id
        || grant.machine_route != binding.machine_route
        || grant.device_route.as_bytes() == &[0; 16]
        || grant.grant_serial.value() == 0
        || grant.root_key_id != binding.root_key_id
        || grant.trust_epoch != binding.trust_epoch
        || grant.signature.0 == [0; 64]
    {
        return Err(PairingAccessError::AuthorityMismatch);
    }
    validate_pairing_device_sign_key(relay_server_id, grant.device_sign_pubkey)
        .map_err(|_| PairingAccessError::InvalidRevocationGrant)?;
    let root_verifier =
        binding_root_verifier(binding).map_err(|_| PairingAccessError::AuthorityMismatch)?;
    verify_tbs(
        &root_verifier,
        &grant.to_be_signed_v1(relay_server_id, binding.root_fingerprint),
        &SignatureBytes::from(grant.signature),
    )
    .map_err(|_| PairingAccessError::InvalidRevocationGrant)
}

fn binding_root_verifier(
    binding: &MachineAuthorityBinding,
) -> Result<VerifyingKey, PairingAccessError> {
    if binding.relay_server_id.as_bytes() == &[0; 16]
        || binding.machine_route.as_bytes() == &[0; 16]
        || binding.root_key_id.as_bytes() == &[0; 16]
        || binding.trust_epoch.value() == 0
        || sha256(&binding.root_public_key.0) != binding.root_fingerprint
    {
        return Err(PairingAccessError::AuthorityMismatch);
    }
    VerifyingKey::from_bytes(&binding.root_public_key.0)
        .map_err(|_| PairingAccessError::AuthorityMismatch)
}

fn pairing_context(pair_route: PairRouteId, frame_kind: OuterFrameKind) -> OuterContextV1 {
    OuterContextV1 {
        frame_kind,
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

fn map_receipt_crypto_error(error: CryptoError) -> PairingAccessError {
    match error {
        CryptoError::BadSignature => PairingAccessError::InvalidReceiptSignature,
        _ => PairingAccessError::ReceiptBindingMismatch,
    }
}

fn map_active_authority_error(error: RemoteTransportError) -> PairingAccessError {
    if matches!(error, RemoteTransportError::Closed) {
        PairingAccessError::AuthorityUnavailable
    } else {
        PairingAccessError::AuthorityMismatch
    }
}

fn map_signing_authority_error(error: RemoteTransportError) -> PairingAccessError {
    if matches!(error, RemoteTransportError::Closed) {
        PairingAccessError::AuthorityUnavailable
    } else if error.code() == "remote.transport.pairing_authority_mismatch" {
        PairingAccessError::AuthorityMismatch
    } else {
        PairingAccessError::RevocationSigningFailed
    }
}

#[cfg(test)]
#[path = "access_tests.rs"]
mod tests;
