//! Enrollment bundle 的纯配置校验；不拨号、不访问持久化或 Keychain。

use std::fmt;

use agentdeck_crypto::ValidatedRelayReceiptVerifyKey;
use agentdeck_protocol::relay_v2::{
    Digest32, ENROLLMENT_BUNDLE_VERSION, EnrollmentBundleV2, RelayReceiptVerifyKeyV1, RelayServerId,
};
use agentdeck_relay_client::{RelayClientConfig, RelayTlsPolicy};
use thiserror::Error;

/// 已完成 bundle shape、TLS pin、origin 与 receipt anchor 校验的 enrollment owner。
///
/// 类型故意不实现 `Clone`。完整原始 bundle（包括唯一 enrollment code owner）只在
/// [`Self::into_parts`] 时转移，getter 不暴露或复制 code。
pub struct ValidatedEnrollmentConfig {
    bundle: EnrollmentBundleV2,
    relay_client_config: RelayClientConfig,
    receipt_verify_key: ValidatedRelayReceiptVerifyKey,
}

impl ValidatedEnrollmentConfig {
    pub fn new(bundle: EnrollmentBundleV2, now_ms: u64) -> Result<Self, EnrollmentConfigError> {
        if bundle.version != ENROLLMENT_BUNDLE_VERSION {
            return Err(EnrollmentConfigError::UnsupportedVersion);
        }
        if bundle.code.0 == [0; 32] {
            return Err(EnrollmentConfigError::InvalidCode);
        }
        let (relay_client_config, receipt_verify_key) = validate_relay_connection(
            &bundle.public_wss_url,
            bundle.relay_server_id,
            &bundle.receipt_verify_key,
            &bundle.spki_pins,
            bundle.expires_at_ms,
            now_ms,
        )?;

        Ok(Self {
            bundle,
            relay_client_config,
            receipt_verify_key,
        })
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
    pub const fn relay_server_id(&self) -> RelayServerId {
        self.bundle.relay_server_id
    }

    #[must_use]
    pub const fn bundle_version(&self) -> u16 {
        self.bundle.version
    }

    #[must_use]
    pub const fn expires_at_ms(&self) -> u64 {
        self.bundle.expires_at_ms
    }

    /// 只供同模块 deterministic re-enrollment route 派生；不进入 Debug/status。
    pub(super) const fn enrollment_code_bytes(&self) -> &[u8; 32] {
        &self.bundle.code.0
    }

    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        EnrollmentBundleV2,
        RelayClientConfig,
        ValidatedRelayReceiptVerifyKey,
    ) {
        (
            self.bundle,
            self.relay_client_config,
            self.receipt_verify_key,
        )
    }
}

pub(super) fn validate_relay_connection(
    public_wss_url: &str,
    relay_server_id: RelayServerId,
    receipt_verify_key: &RelayReceiptVerifyKeyV1,
    spki_pins: &[Digest32],
    expires_at_ms: u64,
    now_ms: u64,
) -> Result<(RelayClientConfig, ValidatedRelayReceiptVerifyKey), EnrollmentConfigError> {
    if expires_at_ms <= now_ms {
        return Err(EnrollmentConfigError::Expired);
    }
    validate_sealed_relay_connection(
        public_wss_url,
        relay_server_id,
        receipt_verify_key,
        spki_pins,
        expires_at_ms,
    )
}

/// 重启恢复只重建已经 durable prepare 的连接材料；此处故意不按当前时间拒绝过期，
/// 以便 Relay 已提交但响应丢失时仍能逐字节重放同一个 enrollment request。
pub(super) fn validate_sealed_relay_connection(
    public_wss_url: &str,
    relay_server_id: RelayServerId,
    receipt_verify_key: &RelayReceiptVerifyKeyV1,
    spki_pins: &[Digest32],
    expires_at_ms: u64,
) -> Result<(RelayClientConfig, ValidatedRelayReceiptVerifyKey), EnrollmentConfigError> {
    if expires_at_ms == 0 {
        return Err(EnrollmentConfigError::Expired);
    }
    if relay_server_id.as_bytes() == &[0; 16] {
        return Err(EnrollmentConfigError::InvalidRelayServerId);
    }
    if !(1..=2).contains(&spki_pins.len())
        || spki_pins.iter().any(|pin| pin.0 == [0; 32])
        || (spki_pins.len() == 2 && spki_pins[0] == spki_pins[1])
    {
        return Err(EnrollmentConfigError::InvalidPinset);
    }
    let receipt_verify_key = ValidatedRelayReceiptVerifyKey::new(receipt_verify_key.clone())
        .map_err(|_| EnrollmentConfigError::InvalidReceiptVerifyKey)?;
    if receipt_verify_key.wire_anchor().relay_server_id != relay_server_id {
        return Err(EnrollmentConfigError::ReceiptRelayMismatch);
    }
    let pins = spki_pins.iter().map(|pin| pin.0).collect();
    let tls =
        RelayTlsPolicy::pinned_spki(pins).map_err(|_| EnrollmentConfigError::InvalidPinset)?;
    let relay_client_config = RelayClientConfig::new(public_wss_url, relay_server_id, tls)
        .map_err(|_| EnrollmentConfigError::InvalidOrigin)?;
    if relay_client_config.origin() != public_wss_url {
        return Err(EnrollmentConfigError::InvalidOrigin);
    }
    Ok((relay_client_config, receipt_verify_key))
}

impl fmt::Debug for ValidatedEnrollmentConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ValidatedEnrollmentConfig")
            .field("version", &self.bundle.version)
            .field("expires_at_ms", &self.bundle.expires_at_ms)
            .field("relay_server", &self.bundle.relay_server_id.redacted())
            .finish()
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum EnrollmentConfigError {
    #[error("unsupported enrollment bundle version")]
    UnsupportedVersion,
    #[error("enrollment bundle has expired")]
    Expired,
    #[error("enrollment bundle Relay server ID is invalid")]
    InvalidRelayServerId,
    #[error("enrollment bundle code is invalid")]
    InvalidCode,
    #[error("enrollment bundle SPKI pinset is invalid")]
    InvalidPinset,
    #[error("enrollment bundle receipt verify key is invalid")]
    InvalidReceiptVerifyKey,
    #[error("enrollment bundle receipt verify key belongs to another Relay")]
    ReceiptRelayMismatch,
    #[error("enrollment bundle WSS origin is invalid")]
    InvalidOrigin,
}

impl EnrollmentConfigError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::UnsupportedVersion => "daemon.remote.enrollment.version_unsupported",
            Self::Expired => "daemon.remote.enrollment.expired",
            Self::InvalidRelayServerId => "daemon.remote.enrollment.relay_id_invalid",
            Self::InvalidCode => "daemon.remote.enrollment.code_invalid",
            Self::InvalidPinset => "daemon.remote.enrollment.pinset_invalid",
            Self::InvalidReceiptVerifyKey => "daemon.remote.enrollment.receipt_key_invalid",
            Self::ReceiptRelayMismatch => "daemon.remote.enrollment.receipt_relay_mismatch",
            Self::InvalidOrigin => "daemon.remote.enrollment.origin_invalid",
        }
    }
}

#[cfg(test)]
mod tests {
    use agentdeck_crypto::{SigningKey, ValidatedRelayReceiptSignerIdentityV1};
    use agentdeck_protocol::relay_v2::{
        Digest32, ENROLLMENT_BUNDLE_VERSION, EnrollmentBundleV2, EnrollmentCode, RelayServerId,
    };

    use super::{EnrollmentConfigError, ValidatedEnrollmentConfig};

    const NOW_MS: u64 = 1_700_000_000_000;

    fn relay_server(seed: u8) -> RelayServerId {
        RelayServerId::from_bytes([seed; 16])
    }

    fn valid_bundle() -> EnrollmentBundleV2 {
        let relay_server_id = relay_server(0x22);
        let signing_key = SigningKey::from_seed(&[0x33; 32]);
        let receipt_verify_key =
            ValidatedRelayReceiptSignerIdentityV1::from_signing_key(&signing_key)
                .expect("valid receipt signing identity")
                .bind_to_relay(relay_server_id)
                .expect("valid receipt anchor")
                .wire_anchor()
                .clone();
        EnrollmentBundleV2 {
            version: ENROLLMENT_BUNDLE_VERSION,
            public_wss_url: "wss://relay.example.test:8443/".to_owned(),
            relay_server_id,
            receipt_verify_key,
            code: EnrollmentCode([0x44; 32]),
            spki_pins: vec![Digest32([0x55; 32]), Digest32([0x66; 32])],
            expires_at_ms: NOW_MS + 1,
        }
    }

    fn assert_code(bundle: EnrollmentBundleV2, expected: EnrollmentConfigError) {
        let error = ValidatedEnrollmentConfig::new(bundle, NOW_MS)
            .expect_err("invalid enrollment bundle must fail");
        assert_eq!(error, expected);
        assert_eq!(error.code(), expected.code());
    }

    #[test]
    fn valid_bundle_builds_owned_pinned_config_and_redacts_debug() {
        let validated =
            ValidatedEnrollmentConfig::new(valid_bundle(), NOW_MS).expect("valid bundle");
        assert_eq!(
            validated.relay_client_config().origin(),
            "wss://relay.example.test:8443/"
        );
        assert_eq!(
            validated.receipt_verify_key().wire_anchor().relay_server_id,
            relay_server(0x22)
        );
        assert_eq!(validated.bundle_version(), ENROLLMENT_BUNDLE_VERSION);
        assert_eq!(validated.expires_at_ms(), NOW_MS + 1);

        let debug = format!("{validated:?}");
        for secret in ["relay.example.test", "RERER", "5555", "6666"] {
            assert!(!debug.contains(secret), "Debug leaked {secret}");
        }
        assert!(debug.contains(&relay_server(0x22).redacted()));
        assert!(debug.contains("version: 2"));
        assert!(debug.contains("expires_at_ms: 1700000000001"));

        let (bundle, relay, receipt) = validated.into_parts();
        assert_eq!(relay.origin(), "wss://relay.example.test:8443/");
        assert_eq!(bundle.code.0, [0x44; 32]);
        assert_eq!(bundle.spki_pins.len(), 2);
        assert_eq!(receipt.wire_anchor().relay_server_id, relay_server(0x22));
        assert_eq!(bundle.expires_at_ms, NOW_MS + 1);
    }

    #[test]
    fn version_and_expiry_are_strict() {
        let mut bundle = valid_bundle();
        bundle.version = 1;
        assert_code(bundle, EnrollmentConfigError::UnsupportedVersion);

        let mut bundle = valid_bundle();
        bundle.expires_at_ms = NOW_MS;
        assert_code(bundle, EnrollmentConfigError::Expired);

        let mut bundle = valid_bundle();
        bundle.expires_at_ms = NOW_MS - 1;
        assert_code(bundle, EnrollmentConfigError::Expired);
    }

    #[test]
    fn relay_id_and_code_must_be_nonzero() {
        let mut bundle = valid_bundle();
        bundle.relay_server_id = relay_server(0);
        assert_code(bundle, EnrollmentConfigError::InvalidRelayServerId);

        let mut bundle = valid_bundle();
        bundle.code = EnrollmentCode([0; 32]);
        assert_code(bundle, EnrollmentConfigError::InvalidCode);
    }

    #[test]
    fn pinset_requires_one_or_two_unique_nonzero_pins() {
        let mut invalid_pinsets = [
            Vec::new(),
            vec![Digest32([0; 32])],
            vec![Digest32([7; 32]), Digest32([7; 32])],
            vec![Digest32([1; 32]), Digest32([2; 32]), Digest32([3; 32])],
        ];
        for pins in &mut invalid_pinsets {
            let mut bundle = valid_bundle();
            bundle.spki_pins = std::mem::take(pins);
            assert_code(bundle, EnrollmentConfigError::InvalidPinset);
        }
    }

    #[test]
    fn receipt_anchor_must_be_valid_and_bound_to_bundle_relay() {
        let mut bundle = valid_bundle();
        bundle.receipt_verify_key.key_id.0[0] ^= 1;
        assert_code(bundle, EnrollmentConfigError::InvalidReceiptVerifyKey);

        let mut bundle = valid_bundle();
        let signing_key = SigningKey::from_seed(&[0x33; 32]);
        bundle.receipt_verify_key =
            ValidatedRelayReceiptSignerIdentityV1::from_signing_key(&signing_key)
                .expect("valid receipt signing identity")
                .bind_to_relay(relay_server(0x99))
                .expect("valid mismatched anchor")
                .wire_anchor()
                .clone();
        assert_code(bundle, EnrollmentConfigError::ReceiptRelayMismatch);
    }

    #[test]
    fn origin_must_be_canonical_absolute_wss_root() {
        for origin in [
            "relay.example.test",
            "ws://relay.example.test/",
            "https://relay.example.test/",
            "wss://@relay.example.test/",
            "wss://user@relay.example.test/",
            "wss://user:password@relay.example.test/",
            "wss://relay.example.test:0/",
            "wss://relay.example.test/v2",
            "wss://relay.example.test/?query=1",
            "wss://relay.example.test/#fragment",
            "wss://RELAY.example.test/",
            "wss://relay.example.test",
            "wss://relay.example.test:443/",
            "wss://relay.example.test/a/..",
        ] {
            let mut bundle = valid_bundle();
            bundle.public_wss_url = origin.to_owned();
            assert_code(bundle, EnrollmentConfigError::InvalidOrigin);
        }
    }

    #[test]
    fn error_codes_are_stable_and_secret_free() {
        for (error, code) in [
            (
                EnrollmentConfigError::UnsupportedVersion,
                "daemon.remote.enrollment.version_unsupported",
            ),
            (
                EnrollmentConfigError::Expired,
                "daemon.remote.enrollment.expired",
            ),
            (
                EnrollmentConfigError::InvalidRelayServerId,
                "daemon.remote.enrollment.relay_id_invalid",
            ),
            (
                EnrollmentConfigError::InvalidCode,
                "daemon.remote.enrollment.code_invalid",
            ),
            (
                EnrollmentConfigError::InvalidPinset,
                "daemon.remote.enrollment.pinset_invalid",
            ),
            (
                EnrollmentConfigError::InvalidReceiptVerifyKey,
                "daemon.remote.enrollment.receipt_key_invalid",
            ),
            (
                EnrollmentConfigError::ReceiptRelayMismatch,
                "daemon.remote.enrollment.receipt_relay_mismatch",
            ),
            (
                EnrollmentConfigError::InvalidOrigin,
                "daemon.remote.enrollment.origin_invalid",
            ),
        ] {
            assert_eq!(error.code(), code);
            let debug = format!("{error:?}");
            assert!(!debug.contains("relay.example.test"));
            assert!(!debug.contains("RERER"));
        }
    }
}
