//! Enrollment 发起前的纯冻结 owner 与 response binding 验证。
//!
//! 本模块不拨号、不读写 Store，也不暴露 enrollment code 或签名 oracle。

use std::fmt;

use agentdeck_crypto::{ValidatedRelayReceiptVerifyKey, sha256};
use agentdeck_protocol::relay_v2::enrollment::MachineEnrollmentResponseError;
use agentdeck_protocol::relay_v2::{
    EnrollmentBundleV2, MachineEnrollmentRequestV1, MachineEnrollmentResponseV1, MachineRouteId,
    PublicKeyBytes, RelayServerId, SignedCertificate, enrollment_receipt_hash,
};
use agentdeck_relay_client::RelayClientConfig;
use thiserror::Error;

use crate::runtime::store::MachineIdentityBinding;

use super::bootstrap::{ActiveMachineIdentity, PendingReenrollmentIdentity};
use super::certificate::MachineCertificateError;
use super::config::ValidatedEnrollmentConfig;

const MACHINE_ROUTE_ATTEMPTS: usize = 8;
const REENROLL_ROUTE_DOMAIN: &[u8] = b"AgentDeck/ReenrollMachineRouteV1\0";

/// 一次 enrollment 所有输入的唯一 owner。类型故意不实现 `Clone`。
pub struct FrozenMachineEnrollment {
    bundle: EnrollmentBundleV2,
    machine_route: MachineRouteId,
    root_public_key: PublicKeyBytes,
    trust_epoch: u64,
    binding: MachineIdentityBinding,
    link_certificate: SignedCertificate,
    data_certificate: SignedCertificate,
    relay_client_config: RelayClientConfig,
    receipt_verify_key: ValidatedRelayReceiptVerifyKey,
    request_hash: [u8; 32],
}

impl FrozenMachineEnrollment {
    /// 从已验证 bundle 与 active machine identity 冻结唯一 route/request。
    pub fn new(
        config: ValidatedEnrollmentConfig,
        identity: &ActiveMachineIdentity,
    ) -> Result<Self, MachineEnrollmentError> {
        freeze_machine_enrollment_with_route_fill(config, identity, |bytes| {
            getrandom::fill(bytes).map_err(|_| ())
        })
    }

    /// `LocalDeleted` 显式 re-enroll 使用 deterministic route。相同 DB key material
    /// 与相同 bundle 在 Keychain/Store crash retry 后会冻结逐字节相同 request；
    /// identity 仍必须等 Store 原子替换读回后才能提升为 active。
    pub fn new_reenrollment(
        config: ValidatedEnrollmentConfig,
        identity: &PendingReenrollmentIdentity,
    ) -> Result<Self, MachineEnrollmentError> {
        let route = deterministic_reenrollment_route(&config, identity.binding());
        freeze_machine_enrollment_with_route_fill(config, identity, |bytes| {
            *bytes = *route.as_bytes();
            Ok(())
        })
    }

    #[must_use]
    pub const fn relay_server_id(&self) -> RelayServerId {
        self.bundle.relay_server_id
    }

    #[must_use]
    pub const fn machine_route(&self) -> MachineRouteId {
        self.machine_route
    }

    #[must_use]
    pub const fn root_public_key(&self) -> PublicKeyBytes {
        self.root_public_key
    }

    #[must_use]
    pub const fn trust_epoch(&self) -> u64 {
        self.trust_epoch
    }

    #[must_use]
    pub const fn link_certificate(&self) -> &SignedCertificate {
        &self.link_certificate
    }

    #[must_use]
    pub const fn data_certificate(&self) -> &SignedCertificate {
        &self.data_certificate
    }

    #[must_use]
    pub const fn relay_client_config(&self) -> &RelayClientConfig {
        &self.relay_client_config
    }

    #[must_use]
    pub const fn receipt_verify_key(&self) -> &ValidatedRelayReceiptVerifyKey {
        &self.receipt_verify_key
    }

    #[must_use]
    pub const fn request_hash(&self) -> [u8; 32] {
        self.request_hash
    }

    /// 仅在真正发起 enrollment 时复制 code；返回 DTO 离开作用域时
    /// [`agentdeck_protocol::relay_v2::EnrollmentCode`] 的 `Drop` 会 zeroize 该临时副本。
    #[must_use]
    pub fn transient_request(&self) -> MachineEnrollmentRequestV1 {
        MachineEnrollmentRequestV1 {
            code: self.bundle.code.clone(),
            machine_route: self.machine_route,
            root_pubkey: self.root_public_key,
            link_cert: self.link_certificate.clone(),
            data_cert: self.data_certificate.clone(),
        }
    }

    /// 先执行 response 自身 shape 校验，再绑定冻结的 Relay/route/epoch/request hash。
    pub fn validate_response(
        &self,
        response: &MachineEnrollmentResponseV1,
    ) -> Result<[u8; 32], MachineEnrollmentError> {
        response
            .validate()
            .map_err(MachineEnrollmentError::InvalidResponse)?;
        if response.relay_server_id != self.bundle.relay_server_id {
            return Err(MachineEnrollmentError::ResponseRelayMismatch);
        }
        if response.machine_route != self.machine_route {
            return Err(MachineEnrollmentError::ResponseRouteMismatch);
        }
        if response.trust_epoch != self.trust_epoch {
            return Err(MachineEnrollmentError::ResponseTrustEpochMismatch);
        }
        let expected_receipt_hash = enrollment_receipt_hash(
            self.bundle.relay_server_id,
            self.machine_route,
            self.trust_epoch,
            self.request_hash,
        );
        if response.receipt_hash != expected_receipt_hash {
            return Err(MachineEnrollmentError::ResponseReceiptHashMismatch);
        }
        response
            .canonical_sha256()
            .map_err(MachineEnrollmentError::InvalidResponse)
    }

    /// 显式消费 owner 才能取得含 code 的完整 bundle。
    #[must_use]
    pub fn into_parts(self) -> FrozenMachineEnrollmentParts {
        FrozenMachineEnrollmentParts {
            bundle: self.bundle,
            machine_route: self.machine_route,
            root_public_key: self.root_public_key,
            trust_epoch: self.trust_epoch,
            binding: self.binding,
            link_certificate: self.link_certificate,
            data_certificate: self.data_certificate,
            relay_client_config: self.relay_client_config,
            receipt_verify_key: self.receipt_verify_key,
            request_hash: self.request_hash,
        }
    }
}

impl fmt::Debug for FrozenMachineEnrollment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FrozenMachineEnrollment([REDACTED])")
    }
}

/// [`FrozenMachineEnrollment::into_parts`] 的显式消费结果。不实现 `Clone`
/// 或 `Debug`，因为 `bundle` 拥有 enrollment code。
pub struct FrozenMachineEnrollmentParts {
    pub bundle: EnrollmentBundleV2,
    pub machine_route: MachineRouteId,
    pub root_public_key: PublicKeyBytes,
    pub trust_epoch: u64,
    pub binding: MachineIdentityBinding,
    pub link_certificate: SignedCertificate,
    pub data_certificate: SignedCertificate,
    pub relay_client_config: RelayClientConfig,
    pub receipt_verify_key: ValidatedRelayReceiptVerifyKey,
    pub request_hash: [u8; 32],
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum MachineEnrollmentError {
    #[error("machine route entropy source is unavailable")]
    RouteEntropyUnavailable,
    #[error("machine route generation exhausted eight all-zero draws")]
    RouteZeroExhausted,
    #[error("machine certificate construction failed: {0}")]
    Certificate(#[from] MachineCertificateError),
    #[error("machine enrollment response is invalid: {0}")]
    InvalidResponse(MachineEnrollmentResponseError),
    #[error("machine enrollment response belongs to another Relay")]
    ResponseRelayMismatch,
    #[error("machine enrollment response belongs to another route")]
    ResponseRouteMismatch,
    #[error("machine enrollment response trust epoch does not match the frozen request")]
    ResponseTrustEpochMismatch,
    #[error("machine enrollment response receipt hash does not bind the frozen request")]
    ResponseReceiptHashMismatch,
}

trait EnrollmentCertificateSource {
    fn binding(&self) -> MachineIdentityBinding;
    fn certificates(
        &self,
        relay_server_id: RelayServerId,
        machine_route: MachineRouteId,
    ) -> Result<(SignedCertificate, SignedCertificate), MachineCertificateError>;
}

impl EnrollmentCertificateSource for ActiveMachineIdentity {
    fn binding(&self) -> MachineIdentityBinding {
        self.binding().clone()
    }

    fn certificates(
        &self,
        relay_server_id: RelayServerId,
        machine_route: MachineRouteId,
    ) -> Result<(SignedCertificate, SignedCertificate), MachineCertificateError> {
        Ok(ActiveMachineIdentity::certificates(self, relay_server_id, machine_route)?.into_parts())
    }
}

impl EnrollmentCertificateSource for PendingReenrollmentIdentity {
    fn binding(&self) -> MachineIdentityBinding {
        self.binding().clone()
    }

    fn certificates(
        &self,
        relay_server_id: RelayServerId,
        machine_route: MachineRouteId,
    ) -> Result<(SignedCertificate, SignedCertificate), MachineCertificateError> {
        Ok(
            PendingReenrollmentIdentity::certificates(self, relay_server_id, machine_route)?
                .into_parts(),
        )
    }
}

fn deterministic_reenrollment_route(
    config: &ValidatedEnrollmentConfig,
    binding: &MachineIdentityBinding,
) -> MachineRouteId {
    let mut input = Vec::with_capacity(REENROLL_ROUTE_DOMAIN.len() + 16 + 32 + 32 + 8 + 1);
    input.extend_from_slice(REENROLL_ROUTE_DOMAIN);
    input.extend_from_slice(config.relay_server_id().as_bytes());
    input.extend_from_slice(&binding.root_fingerprint);
    input.extend_from_slice(config.enrollment_code_bytes());
    input.extend_from_slice(&config.expires_at_ms().to_be_bytes());
    for counter in 0_u8..=u8::MAX {
        input.push(counter);
        let digest = sha256(&input);
        input.pop();
        let mut route = [0; 16];
        route.copy_from_slice(&digest[..16]);
        if route != [0; 16] {
            return MachineRouteId::from_bytes(route);
        }
    }
    unreachable!("a 256-way SHA-256 derivation cannot yield only zero routes")
}

fn freeze_machine_enrollment_with_route_fill(
    config: ValidatedEnrollmentConfig,
    identity: &impl EnrollmentCertificateSource,
    mut fill_route: impl FnMut(&mut [u8; 16]) -> Result<(), ()>,
) -> Result<FrozenMachineEnrollment, MachineEnrollmentError> {
    let machine_route = fresh_machine_route_with(&mut fill_route)?;
    let relay_server_id = config.relay_server_id();
    let binding = identity.binding();
    let root_public_key = PublicKeyBytes(binding.root_public_key);
    let trust_epoch = binding.trust_epoch;
    let (link_certificate, data_certificate) =
        identity.certificates(relay_server_id, machine_route)?;
    let (bundle, relay_client_config, receipt_verify_key) = config.into_parts();

    let request_hash = {
        let request = MachineEnrollmentRequestV1 {
            code: bundle.code.clone(),
            machine_route,
            root_pubkey: root_public_key,
            link_cert: link_certificate.clone(),
            data_cert: data_certificate.clone(),
        };
        let request_hash = request.canonical_sha256();
        drop(request);
        request_hash
    };

    Ok(FrozenMachineEnrollment {
        bundle,
        machine_route,
        root_public_key,
        trust_epoch,
        binding,
        link_certificate,
        data_certificate,
        relay_client_config,
        receipt_verify_key,
        request_hash,
    })
}

fn fresh_machine_route_with(
    fill_route: &mut impl FnMut(&mut [u8; 16]) -> Result<(), ()>,
) -> Result<MachineRouteId, MachineEnrollmentError> {
    for _ in 0..MACHINE_ROUTE_ATTEMPTS {
        let mut bytes = [0; 16];
        fill_route(&mut bytes).map_err(|()| MachineEnrollmentError::RouteEntropyUnavailable)?;
        if bytes != [0; 16] {
            return Ok(MachineRouteId::from_bytes(bytes));
        }
    }
    Err(MachineEnrollmentError::RouteZeroExhausted)
}

#[cfg(test)]
mod tests {
    use agentdeck_crypto::{SigningKey, ValidatedRelayReceiptSignerIdentityV1, sha256, sign_tbs};
    use agentdeck_protocol::relay_v2::enrollment::MachineEnrollmentResponseError;
    use agentdeck_protocol::relay_v2::{
        CertRole, Digest32, ENROLLMENT_BUNDLE_VERSION, Ed25519Signature, EnrollmentBundleV2,
        EnrollmentCode, LinkGeneration, MachineEnrollmentResponseV1, MachineRouteId,
        PublicKeyBytes, RelayServerId, RootKeyId, SignedCertificate, TrustEpoch,
        enrollment_receipt_hash,
    };

    use crate::remote::certificate::MachineCertificateError;
    use crate::remote::config::ValidatedEnrollmentConfig;
    use crate::runtime::store::MachineIdentityBinding;

    use super::{
        EnrollmentCertificateSource, FrozenMachineEnrollmentParts, MachineEnrollmentError,
        deterministic_reenrollment_route, freeze_machine_enrollment_with_route_fill,
    };

    const NOW_MS: u64 = 1_700_000_000_000;
    const RELAY: RelayServerId = RelayServerId::from_bytes([0x22; 16]);
    const ROUTE: MachineRouteId = MachineRouteId::from_bytes([0x66; 16]);
    const ROOT_SEED: [u8; 32] = [0x71; 32];
    const LINK_SEED: [u8; 32] = [0x72; 32];
    const DATA_SEED: [u8; 32] = [0x73; 32];

    struct TestIdentity {
        root: SigningKey,
        link: SigningKey,
        data: SigningKey,
    }

    impl TestIdentity {
        fn new() -> Self {
            Self {
                root: SigningKey::from_seed(&ROOT_SEED),
                link: SigningKey::from_seed(&LINK_SEED),
                data: SigningKey::from_seed(&DATA_SEED),
            }
        }

        fn certificate(
            &self,
            relay_server_id: RelayServerId,
            machine_route: MachineRouteId,
            role: CertRole,
        ) -> SignedCertificate {
            let (subject, generation) = match role {
                CertRole::Link => (&self.link, 5),
                CertRole::Data => (&self.data, 7),
            };
            let mut certificate = SignedCertificate {
                subject_pubkey: PublicKeyBytes(subject.verifying_key().to_bytes()),
                cert_role: role,
                generation: LinkGeneration::new(generation),
                root_key_id: RootKeyId::from_bytes([0x74; 16]),
                trust_epoch: TrustEpoch::new(3),
                not_after_ms: None,
                signature: Ed25519Signature([0; 64]),
            };
            certificate.signature = sign_tbs(
                &self.root,
                &certificate.to_be_signed_v1(
                    relay_server_id,
                    machine_route,
                    sha256(&self.root.verifying_key().to_bytes()),
                ),
            )
            .into();
            certificate
        }
    }

    impl EnrollmentCertificateSource for TestIdentity {
        fn binding(&self) -> MachineIdentityBinding {
            let root_public_key = self.root.verifying_key().to_bytes();
            let machine_hpke_public_key = [0x75; 32];
            let link_sign_public_key = self.link.verifying_key().to_bytes();
            let data_sign_public_key = self.data.verifying_key().to_bytes();
            MachineIdentityBinding {
                root_key_id: [0x74; 16],
                trust_epoch: 3,
                link_generation: 5,
                data_generation: 7,
                key_directory_revision: 0,
                root_public_key,
                root_fingerprint: sha256(&root_public_key),
                machine_hpke_public_key,
                machine_hpke_fingerprint: sha256(&machine_hpke_public_key),
                link_sign_public_key,
                link_sign_fingerprint: sha256(&link_sign_public_key),
                data_sign_public_key,
                data_sign_fingerprint: sha256(&data_sign_public_key),
            }
        }

        fn certificates(
            &self,
            relay_server_id: RelayServerId,
            machine_route: MachineRouteId,
        ) -> Result<(SignedCertificate, SignedCertificate), MachineCertificateError> {
            Ok((
                self.certificate(relay_server_id, machine_route, CertRole::Link),
                self.certificate(relay_server_id, machine_route, CertRole::Data),
            ))
        }
    }

    fn config() -> ValidatedEnrollmentConfig {
        config_with_code(0x44)
    }

    fn config_with_code(code: u8) -> ValidatedEnrollmentConfig {
        let receipt_signer = SigningKey::from_seed(&[0x33; 32]);
        let receipt_verify_key =
            ValidatedRelayReceiptSignerIdentityV1::from_signing_key(&receipt_signer)
                .expect("valid receipt signer identity")
                .bind_to_relay(RELAY)
                .expect("bind receipt signer to Relay")
                .wire_anchor()
                .clone();
        ValidatedEnrollmentConfig::new(
            EnrollmentBundleV2 {
                version: ENROLLMENT_BUNDLE_VERSION,
                public_wss_url: "wss://relay.example.test:8443/".to_owned(),
                relay_server_id: RELAY,
                receipt_verify_key,
                code: EnrollmentCode([code; 32]),
                spki_pins: vec![Digest32([0x55; 32]), Digest32([0x56; 32])],
                expires_at_ms: NOW_MS + 1,
            },
            NOW_MS,
        )
        .expect("validated enrollment config")
    }

    #[test]
    fn reenrollment_route_is_exact_for_same_bundle_and_changes_with_code() {
        let binding = TestIdentity::new().binding();
        let first = deterministic_reenrollment_route(&config_with_code(0x44), &binding);
        let replay = deterministic_reenrollment_route(&config_with_code(0x44), &binding);
        let replacement = deterministic_reenrollment_route(&config_with_code(0x45), &binding);
        assert_eq!(first, replay);
        assert_ne!(first.as_bytes(), &[0; 16]);
        assert_ne!(first, replacement);
        assert_ne!(first, ROUTE, "re-enroll must not reuse the retired route");
    }

    fn freeze(identity: &TestIdentity) -> super::FrozenMachineEnrollment {
        freeze_machine_enrollment_with_route_fill(config(), identity, |bytes| {
            *bytes = *ROUTE.as_bytes();
            Ok(())
        })
        .expect("freeze deterministic enrollment")
    }

    #[test]
    fn frozen_enrollment_is_deterministic_and_only_clones_a_transient_request() {
        let identity = TestIdentity::new();
        let mut route_calls = 0;
        let frozen = freeze_machine_enrollment_with_route_fill(config(), &identity, |bytes| {
            route_calls += 1;
            *bytes = *ROUTE.as_bytes();
            Ok(())
        })
        .expect("freeze deterministic enrollment");
        assert_eq!(route_calls, 1);
        assert_eq!(frozen.relay_server_id(), RELAY);
        assert_eq!(frozen.machine_route(), ROUTE);
        assert_eq!(frozen.trust_epoch(), 3);
        assert_eq!(
            frozen.root_public_key().0,
            identity.root.verifying_key().to_bytes()
        );
        assert_eq!(
            frozen.relay_client_config().origin(),
            "wss://relay.example.test:8443/"
        );
        assert_eq!(
            frozen.receipt_verify_key().wire_anchor().relay_server_id,
            RELAY
        );

        let request = frozen.transient_request();
        assert_eq!(request.code.0, [0x44; 32]);
        assert_eq!(request.machine_route, ROUTE);
        assert_eq!(request.root_pubkey, frozen.root_public_key());
        assert_eq!(&request.link_cert, frozen.link_certificate());
        assert_eq!(&request.data_cert, frozen.data_certificate());
        assert_eq!(request.canonical_sha256(), frozen.request_hash());
        let canonical = request.canonical_bytes().to_vec();
        drop(request);

        let repeated = freeze(&identity);
        let repeated_request = repeated.transient_request();
        assert_eq!(repeated_request.canonical_bytes().as_slice(), canonical);
        assert_eq!(repeated.request_hash(), frozen.request_hash());
        assert_eq!(repeated.link_certificate(), frozen.link_certificate());
        assert_eq!(repeated.data_certificate(), frozen.data_certificate());
        drop(repeated_request);

        let debug = format!("{frozen:?}");
        for secret in ["relay.example.test", "RERER", "4444", "5555", "5656"] {
            assert!(!debug.contains(secret), "Debug leaked {secret}");
        }

        let FrozenMachineEnrollmentParts {
            bundle,
            machine_route,
            root_public_key,
            trust_epoch,
            binding,
            link_certificate,
            data_certificate,
            relay_client_config,
            receipt_verify_key,
            request_hash,
        } = frozen.into_parts();
        assert_eq!(bundle.code.0, [0x44; 32]);
        assert_eq!(machine_route, ROUTE);
        assert_eq!(root_public_key.0, identity.root.verifying_key().to_bytes());
        assert_eq!(trust_epoch, 3);
        assert_eq!(binding, identity.binding());
        assert_eq!(link_certificate.cert_role, CertRole::Link);
        assert_eq!(data_certificate.cert_role, CertRole::Data);
        assert_eq!(
            relay_client_config.origin(),
            "wss://relay.example.test:8443/"
        );
        assert_eq!(receipt_verify_key.wire_anchor().relay_server_id, RELAY);
        assert_eq!(request_hash, repeated.request_hash());
    }

    #[test]
    fn route_generation_is_nonzero_bounded_and_typed() {
        let identity = TestIdentity::new();
        let mut calls = 0;
        let frozen = freeze_machine_enrollment_with_route_fill(config(), &identity, |bytes| {
            calls += 1;
            *bytes = if calls < 3 {
                [0; 16]
            } else {
                *ROUTE.as_bytes()
            };
            Ok(())
        })
        .expect("zero draws before a nonzero route must retry");
        assert_eq!(calls, 3);
        assert_eq!(frozen.machine_route(), ROUTE);

        let mut calls = 0;
        let error = freeze_machine_enrollment_with_route_fill(config(), &identity, |bytes| {
            calls += 1;
            *bytes = [0; 16];
            Ok(())
        })
        .expect_err("eight zero routes must exhaust");
        assert_eq!(calls, 8);
        assert_eq!(error, MachineEnrollmentError::RouteZeroExhausted);

        let mut calls = 0;
        let error = freeze_machine_enrollment_with_route_fill(config(), &identity, |_| {
            calls += 1;
            Err(())
        })
        .expect_err("entropy failure must stay typed");
        assert_eq!(calls, 1);
        assert_eq!(error, MachineEnrollmentError::RouteEntropyUnavailable);
    }

    #[test]
    fn validated_response_binds_every_frozen_request_axis() {
        let identity = TestIdentity::new();
        let frozen = freeze(&identity);
        let expected_receipt =
            enrollment_receipt_hash(RELAY, ROUTE, frozen.trust_epoch(), frozen.request_hash());
        let valid =
            MachineEnrollmentResponseV1::new(RELAY, ROUTE, frozen.trust_epoch(), expected_receipt)
                .expect("valid response");
        assert_eq!(
            frozen.validate_response(&valid).expect("validate response"),
            valid.canonical_sha256().unwrap()
        );

        let mut wrong = valid.clone();
        wrong.relay_server_id = RelayServerId::from_bytes([0x23; 16]);
        assert_eq!(
            frozen.validate_response(&wrong).unwrap_err(),
            MachineEnrollmentError::ResponseRelayMismatch
        );

        let mut wrong = valid.clone();
        wrong.machine_route = MachineRouteId::from_bytes([0x67; 16]);
        assert_eq!(
            frozen.validate_response(&wrong).unwrap_err(),
            MachineEnrollmentError::ResponseRouteMismatch
        );

        let mut wrong = valid.clone();
        wrong.trust_epoch += 1;
        assert_eq!(
            frozen.validate_response(&wrong).unwrap_err(),
            MachineEnrollmentError::ResponseTrustEpochMismatch
        );

        let mut wrong = valid.clone();
        wrong.receipt_hash =
            enrollment_receipt_hash(RELAY, ROUTE, frozen.trust_epoch(), [0x99; 32]);
        assert_eq!(
            frozen.validate_response(&wrong).unwrap_err(),
            MachineEnrollmentError::ResponseReceiptHashMismatch
        );

        let mut zero = valid;
        zero.relay_server_id = RelayServerId::from_bytes([0; 16]);
        assert_eq!(
            frozen.validate_response(&zero).unwrap_err(),
            MachineEnrollmentError::InvalidResponse(
                MachineEnrollmentResponseError::ZeroBoundField("relayServerId")
            )
        );
    }
}
