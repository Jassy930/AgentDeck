//! MachineRoot 签发的确定性 MachineLink / MachineData 证书。
//!
//! 本模块只接受已经通过 P4.1 reconciliation 的冻结 binding 与 key material，并且只
//! 能一次构造固定的 Link/Data 两张证书。它不暴露 MachineRoot secret，也不提供接受
//! 任意 bytes 或任意 [`ToBeSignedV1`] 的通用签名入口。

use agentdeck_crypto::{SignatureBytes, VerifyingKey, sha256, sign_tbs, verify_tbs};
use agentdeck_protocol::e2ee::E2EE_FORMAT_VERSION;
use agentdeck_protocol::e2ee::tbs::{SignedObjectType, ToBeSignedV1};
use agentdeck_protocol::relay_v2::{
    AUTH_SIGNATURE_FORMAT_VERSION, CertRole, Ed25519Signature, LinkGeneration, MachineRouteId,
    PublicKeyBytes, RELAY_PROTOCOL_VERSION, RelayServerId, RootKeyId, SignedCertificate,
    TrustEpoch,
};
use agentdeck_protocol::runtime::RUNTIME_PROTOCOL_VERSION;
use thiserror::Error;

use crate::runtime::store::MachineIdentityBinding;

use super::identity::MachineKeyMaterial;

const MACHINE_LINK_ROLE_SCOPE: &str = "machine-link";
const MACHINE_DATA_ROLE_SCOPE: &str = "machine-data";

/// Active identity 验证 API 使用的共享 protocol 证书类型别名；不是新 DTO。
pub type MachineCertificate = SignedCertificate;

/// 同一个冻结 machine binding、Relay identity 与 route 下的两张 root-signed 证书。
#[derive(Clone, PartialEq, Eq)]
pub struct MachineCertificates {
    link: SignedCertificate,
    data: SignedCertificate,
}

impl MachineCertificates {
    #[must_use]
    pub const fn link(&self) -> &SignedCertificate {
        &self.link
    }

    #[must_use]
    pub const fn data(&self) -> &SignedCertificate {
        &self.data
    }

    /// enrollment DTO 取得所有权时使用；不会复制或暴露任何私钥。
    #[must_use]
    pub fn into_parts(self) -> (SignedCertificate, SignedCertificate) {
        (self.link, self.data)
    }
}

impl std::fmt::Debug for MachineCertificates {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("MachineCertificates([REDACTED])")
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum MachineCertificateError {
    #[error("active machine binding does not match its key material")]
    BindingMismatch,
    #[error("active machine root public key is invalid")]
    InvalidRootPublicKey,
    #[error("machine certificate Relay server ID must be nonzero")]
    InvalidRelayServerId,
    #[error("machine certificate route ID must be nonzero")]
    InvalidMachineRouteId,
    #[error("machine certificate role does not match the expected role")]
    RoleMismatch,
    #[error("machine certificate subject public key does not match the active binding")]
    SubjectMismatch,
    #[error("machine certificate root key ID does not match the active binding")]
    RootKeyIdMismatch,
    #[error("machine certificate trust epoch does not match the active binding")]
    TrustEpochMismatch,
    #[error("machine certificate generation does not match the active binding")]
    GenerationMismatch,
    #[error("MVP machine certificate must not carry an expiry")]
    UnexpectedExpiry,
    #[error("machine certificate TBS domain or context does not match the active binding")]
    TbsContextMismatch,
    #[error("machine certificate root signature verification failed")]
    SignatureInvalid,
}

impl MachineCertificateError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::BindingMismatch => "daemon.remote.certificate.binding_mismatch",
            Self::InvalidRootPublicKey => "daemon.remote.certificate.root_key_invalid",
            Self::InvalidRelayServerId => "daemon.remote.certificate.relay_id_invalid",
            Self::InvalidMachineRouteId => "daemon.remote.certificate.route_id_invalid",
            Self::RoleMismatch => "daemon.remote.certificate.role_mismatch",
            Self::SubjectMismatch => "daemon.remote.certificate.subject_mismatch",
            Self::RootKeyIdMismatch => "daemon.remote.certificate.root_id_mismatch",
            Self::TrustEpochMismatch => "daemon.remote.certificate.epoch_mismatch",
            Self::GenerationMismatch => "daemon.remote.certificate.generation_mismatch",
            Self::UnexpectedExpiry => "daemon.remote.certificate.expiry_unexpected",
            Self::TbsContextMismatch => "daemon.remote.certificate.tbs_mismatch",
            Self::SignatureInvalid => "daemon.remote.certificate.signature_invalid",
        }
    }
}

pub(super) fn issue_machine_certificates(
    binding: &MachineIdentityBinding,
    material: &MachineKeyMaterial,
    relay_server_id: RelayServerId,
    machine_route: MachineRouteId,
) -> Result<MachineCertificates, MachineCertificateError> {
    validate_context(relay_server_id, machine_route)?;
    validate_binding_material(binding, material)?;
    let root_verifying_key = root_verifying_key(binding)?;
    let link = issue_certificate(
        binding,
        material,
        relay_server_id,
        machine_route,
        CertRole::Link,
    );
    let data = issue_certificate(
        binding,
        material,
        relay_server_id,
        machine_route,
        CertRole::Data,
    );

    verify_machine_certificate(
        binding,
        &root_verifying_key,
        relay_server_id,
        machine_route,
        CertRole::Link,
        &link,
    )?;
    verify_machine_certificate(
        binding,
        &root_verifying_key,
        relay_server_id,
        machine_route,
        CertRole::Data,
        &data,
    )?;
    Ok(MachineCertificates { link, data })
}

pub(super) fn verify_active_machine_certificate(
    binding: &MachineIdentityBinding,
    material: &MachineKeyMaterial,
    relay_server_id: RelayServerId,
    machine_route: MachineRouteId,
    expected_role: CertRole,
    certificate: &SignedCertificate,
) -> Result<(), MachineCertificateError> {
    validate_context(relay_server_id, machine_route)?;
    validate_binding_material(binding, material)?;
    let root_verifying_key = root_verifying_key(binding)?;
    verify_machine_certificate(
        binding,
        &root_verifying_key,
        relay_server_id,
        machine_route,
        expected_role,
        certificate,
    )
}

fn issue_certificate(
    binding: &MachineIdentityBinding,
    material: &MachineKeyMaterial,
    relay_server_id: RelayServerId,
    machine_route: MachineRouteId,
    role: CertRole,
) -> SignedCertificate {
    let (subject_public_key, generation) = expected_subject_and_generation(binding, role);
    let mut certificate = SignedCertificate {
        subject_pubkey: PublicKeyBytes(subject_public_key),
        cert_role: role,
        generation: LinkGeneration::new(generation),
        root_key_id: RootKeyId::from_bytes(binding.root_key_id),
        trust_epoch: TrustEpoch::new(binding.trust_epoch),
        not_after_ms: None,
        signature: Ed25519Signature([0; 64]),
    };
    let tbs = certificate.to_be_signed_v1(relay_server_id, machine_route, binding.root_fingerprint);
    certificate.signature = sign_tbs(material.root_signing_key(), &tbs).into();
    certificate
}

fn verify_machine_certificate(
    binding: &MachineIdentityBinding,
    root_verifying_key: &VerifyingKey,
    relay_server_id: RelayServerId,
    machine_route: MachineRouteId,
    expected_role: CertRole,
    certificate: &SignedCertificate,
) -> Result<(), MachineCertificateError> {
    if certificate.cert_role != expected_role {
        return Err(MachineCertificateError::RoleMismatch);
    }
    let (expected_subject, expected_generation) =
        expected_subject_and_generation(binding, expected_role);
    if certificate.subject_pubkey.0 != expected_subject {
        return Err(MachineCertificateError::SubjectMismatch);
    }
    if certificate.root_key_id != RootKeyId::from_bytes(binding.root_key_id) {
        return Err(MachineCertificateError::RootKeyIdMismatch);
    }
    if certificate.trust_epoch != TrustEpoch::new(binding.trust_epoch) {
        return Err(MachineCertificateError::TrustEpochMismatch);
    }
    if certificate.generation != LinkGeneration::new(expected_generation) {
        return Err(MachineCertificateError::GenerationMismatch);
    }
    if certificate.not_after_ms.is_some() {
        return Err(MachineCertificateError::UnexpectedExpiry);
    }

    let tbs = certificate.to_be_signed_v1(relay_server_id, machine_route, binding.root_fingerprint);
    verify_tbs_contract(
        &tbs,
        certificate,
        binding,
        relay_server_id,
        machine_route,
        expected_role,
        expected_generation,
    )?;
    let signature = SignatureBytes::from(certificate.signature);
    verify_tbs(root_verifying_key, &tbs, &signature)
        .map_err(|_| MachineCertificateError::SignatureInvalid)
}

#[allow(clippy::too_many_arguments)]
fn verify_tbs_contract(
    tbs: &ToBeSignedV1,
    certificate: &SignedCertificate,
    binding: &MachineIdentityBinding,
    relay_server_id: RelayServerId,
    machine_route: MachineRouteId,
    expected_role: CertRole,
    expected_generation: u64,
) -> Result<(), MachineCertificateError> {
    let (expected_object_type, expected_scope) = match expected_role {
        CertRole::Link => (SignedObjectType::LinkCert, MACHINE_LINK_ROLE_SCOPE),
        CertRole::Data => (SignedObjectType::DataCert, MACHINE_DATA_ROLE_SCOPE),
    };
    let exact_context = tbs.object_type == expected_object_type
        && tbs.signature_format_version == AUTH_SIGNATURE_FORMAT_VERSION
        && tbs.relay_protocol_version == RELAY_PROTOCOL_VERSION
        && tbs.runtime_protocol_version == RUNTIME_PROTOCOL_VERSION
        && tbs.e2ee_format_version == E2EE_FORMAT_VERSION
        && tbs.relay_server_id == relay_server_id
        && tbs.machine_route == machine_route
        && tbs.device_route.is_none()
        && tbs.stream_route.is_none()
        && tbs.request_route.is_none()
        && tbs.stream_generation.is_none()
        && tbs.stream_cursor.is_none()
        && tbs.role_scope == expected_scope
        && tbs.signing_key_fingerprint == binding.root_fingerprint
        && tbs.root_key_id == RootKeyId::from_bytes(binding.root_key_id)
        && tbs.trust_epoch == TrustEpoch::new(binding.trust_epoch)
        && tbs.serial_or_generation == expected_generation
        && tbs.not_after_ms.is_none()
        && tbs.signed_object_sha256 == certificate.unsigned_canonical_sha256();
    if exact_context {
        Ok(())
    } else {
        Err(MachineCertificateError::TbsContextMismatch)
    }
}

fn expected_subject_and_generation(
    binding: &MachineIdentityBinding,
    role: CertRole,
) -> ([u8; 32], u64) {
    match role {
        CertRole::Link => (binding.link_sign_public_key, binding.link_generation),
        CertRole::Data => (binding.data_sign_public_key, binding.data_generation),
    }
}

fn root_verifying_key(
    binding: &MachineIdentityBinding,
) -> Result<VerifyingKey, MachineCertificateError> {
    if sha256(&binding.root_public_key) != binding.root_fingerprint {
        return Err(MachineCertificateError::BindingMismatch);
    }
    VerifyingKey::from_bytes(&binding.root_public_key)
        .map_err(|_| MachineCertificateError::InvalidRootPublicKey)
}

fn validate_context(
    relay_server_id: RelayServerId,
    machine_route: MachineRouteId,
) -> Result<(), MachineCertificateError> {
    if relay_server_id.as_bytes() == &[0; 16] {
        return Err(MachineCertificateError::InvalidRelayServerId);
    }
    if machine_route.as_bytes() == &[0; 16] {
        return Err(MachineCertificateError::InvalidMachineRouteId);
    }
    Ok(())
}

fn validate_binding_material(
    binding: &MachineIdentityBinding,
    material: &MachineKeyMaterial,
) -> Result<(), MachineCertificateError> {
    let public = material.public_identity();
    let matches = binding.root_public_key == *public.root().public_key()
        && binding.root_fingerprint == public.root().fingerprint()
        && binding.machine_hpke_public_key == *public.hpke().public_key()
        && binding.machine_hpke_fingerprint == public.hpke().fingerprint()
        && binding.link_sign_public_key == *public.link().public_key()
        && binding.link_sign_fingerprint == public.link().fingerprint()
        && binding.data_sign_public_key == *public.data().public_key()
        && binding.data_sign_fingerprint == public.data().fingerprint()
        && sha256(&binding.link_sign_public_key) == binding.link_sign_fingerprint
        && sha256(&binding.data_sign_public_key) == binding.data_sign_fingerprint;
    if matches {
        Ok(())
    } else {
        Err(MachineCertificateError::BindingMismatch)
    }
}
