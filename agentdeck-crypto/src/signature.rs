//! Ed25519 身份签名（design §7.1）——canonical `ToBeSignedV1` 的 sign/verify。
//!
//! 私钥 wrapper zeroize-on-drop（ed25519-dalek `zeroize` feature）且 `Debug` 不输出材料。

use agentdeck_protocol::e2ee::tbs::ToBeSignedV1;
use agentdeck_protocol::relay_v2::auth::{AuthenticationTranscriptV1, Ed25519Signature};
use agentdeck_protocol::relay_v2::{
    RelayAdminPurgeReceiptError, RelayAdminPurgeReceiptExpectationV1, RelayAdminPurgeReceiptTbsV1,
    RelayAdminPurgeReceiptV1, RelayReceiptVerifyKeyV1,
};
use ed25519_dalek::{Signature, Signer};

use crate::error::CryptoError;

/// 64-byte Ed25519 签名。与 protocol 的 [`Ed25519Signature`] 双向可转换。
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SignatureBytes(pub [u8; 64]);

impl std::fmt::Debug for SignatureBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("SignatureBytes").field(&"..").finish()
    }
}

impl From<SignatureBytes> for Ed25519Signature {
    fn from(s: SignatureBytes) -> Self {
        Ed25519Signature(s.0)
    }
}

impl From<Ed25519Signature> for SignatureBytes {
    fn from(s: Ed25519Signature) -> Self {
        SignatureBytes(s.0)
    }
}

/// Ed25519 私钥 wrapper。zeroize-on-drop（内层 dalek `SigningKey` 启用 zeroize feature）；
/// `Debug` 脱敏。
pub struct SigningKey(ed25519_dalek::SigningKey);

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("SigningKey").field(&"<redacted>").finish()
    }
}

impl SigningKey {
    /// 从固定 32-byte seed 构造（Ed25519 RFC 8032 secret key）。
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        SigningKey(ed25519_dalek::SigningKey::from_bytes(seed))
    }

    /// 对应验签公钥。
    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey(self.0.verifying_key())
    }
}

/// Ed25519 验签公钥 wrapper。
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct VerifyingKey(ed25519_dalek::VerifyingKey);

impl std::fmt::Debug for VerifyingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("VerifyingKey").field(&"<redacted>").finish()
    }
}

impl VerifyingKey {
    /// 原始 32-byte 公钥。
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// 从 32-byte 公钥构造；非法点返回 [`CryptoError::InvalidKey`]。
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, CryptoError> {
        ed25519_dalek::VerifyingKey::from_bytes(bytes)
            .map(VerifyingKey)
            .map_err(|_| CryptoError::InvalidKey("ed25519 verifying key"))
    }
}

/// 已完成 protocol shape/key-id 与 Ed25519 compressed-point preflight 的 Relay receipt key。
///
/// Store 只能在成功构造该 wrapper 后持久化 [`Self::wire_anchor`]；sign/verify API 不再
/// 接受未经 crypto 校验的 wire DTO。
pub struct ValidatedRelayReceiptVerifyKey {
    wire_anchor: RelayReceiptVerifyKeyV1,
    verifying_key: VerifyingKey,
}

impl std::fmt::Debug for ValidatedRelayReceiptVerifyKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ValidatedRelayReceiptVerifyKey")
            .field("wire_anchor", &self.wire_anchor)
            .finish_non_exhaustive()
    }
}

impl ValidatedRelayReceiptVerifyKey {
    pub fn new(wire_anchor: RelayReceiptVerifyKeyV1) -> Result<Self, CryptoError> {
        wire_anchor.validate()?;
        let verifying_key = VerifyingKey::from_bytes(&wire_anchor.public_key.0)?;
        if verifying_key.0.is_weak() {
            return Err(CryptoError::InvalidKey("weak ed25519 verifying key"));
        }
        Ok(Self {
            wire_anchor,
            verifying_key,
        })
    }

    /// 可持久化的只读 wire trust anchor；调用方不能经该引用改写已验证字段。
    pub const fn wire_anchor(&self) -> &RelayReceiptVerifyKeyV1 {
        &self.wire_anchor
    }
}

/// 对 canonical `ToBeSignedV1` 确定性签名（Ed25519 RFC 8032）。
pub fn sign_tbs(key: &SigningKey, tbs: &ToBeSignedV1) -> SignatureBytes {
    let message = tbs.encode();
    SignatureBytes(key.0.sign(&message).to_bytes())
}

/// 验证 canonical `ToBeSignedV1` 签名。失败返回 [`CryptoError::BadSignature`]。
pub fn verify_tbs(
    key: &VerifyingKey,
    tbs: &ToBeSignedV1,
    signature: &SignatureBytes,
) -> Result<(), CryptoError> {
    let message = tbs.encode();
    let sig = Signature::from_bytes(&signature.0);
    key.0
        .verify_strict(&message, &sig)
        .map_err(|_| CryptoError::BadSignature)
}

/// 对 Relay v2 单次 challenge 的 typed canonical transcript 签名。
///
/// 本接口故意只接受 [`AuthenticationTranscriptV1`]，避免把 auth call site 退化成可对任意
/// raw bytes 签名的通用 oracle。
pub fn sign_authentication_transcript(
    key: &SigningKey,
    transcript: &AuthenticationTranscriptV1,
) -> SignatureBytes {
    SignatureBytes(key.0.sign(&transcript.encode()).to_bytes())
}

/// 验证 Relay v2 单次 challenge 的 typed canonical transcript 签名。
pub fn verify_authentication_transcript(
    key: &VerifyingKey,
    transcript: &AuthenticationTranscriptV1,
    signature: &SignatureBytes,
) -> Result<(), CryptoError> {
    let signature = Signature::from_bytes(&signature.0);
    key.0
        .verify_strict(&transcript.encode(), &signature)
        .map_err(|_| CryptoError::BadSignature)
}

/// 使用 Relay 专用 Ed25519 receipt key 签发 portable root-lost admin purge proof。
///
/// 本接口只接受 typed purge TBS，并要求 signing key 与 enrollment pin 的 verify key
/// 逐字节相同；它不复用 TLS key，也不是任意 raw bytes signing oracle。
pub fn sign_relay_admin_purge_receipt(
    key: &SigningKey,
    verify_key: &ValidatedRelayReceiptVerifyKey,
    tbs: RelayAdminPurgeReceiptTbsV1,
) -> Result<RelayAdminPurgeReceiptV1, CryptoError> {
    let wire_anchor = verify_key.wire_anchor();
    tbs.validate()?;
    validate_relay_receipt_key_binding(wire_anchor, &tbs)?;
    if key.verifying_key().to_bytes() != wire_anchor.public_key.0 {
        return Err(CryptoError::InvalidKey(
            "Relay receipt signing key does not match provisioned verify key",
        ));
    }
    let signature = Ed25519Signature(key.0.sign(&tbs.encode()?).to_bytes());
    RelayAdminPurgeReceiptV1::from_tbs(tbs, signature).map_err(Into::into)
}

/// 以 enrollment 持久化的专用 Relay receipt verify key 验证 portable purge proof。
pub fn verify_relay_admin_purge_receipt(
    verify_key: &ValidatedRelayReceiptVerifyKey,
    expectation: &RelayAdminPurgeReceiptExpectationV1,
    receipt: &RelayAdminPurgeReceiptV1,
) -> Result<(), CryptoError> {
    expectation.validate()?;
    receipt.validate()?;
    let tbs = receipt.to_be_signed();
    let signature = Signature::from_bytes(&receipt.signature.0);
    verify_key
        .verifying_key
        .0
        .verify_strict(&tbs.encode()?, &signature)
        .map_err(|_| CryptoError::BadSignature)?;
    validate_relay_receipt_key_binding(verify_key.wire_anchor(), &tbs)?;
    if !expectation.matches(receipt) {
        return Err(RelayAdminPurgeReceiptError::ExpectedBindingMismatch.into());
    }
    Ok(())
}

fn validate_relay_receipt_key_binding(
    verify_key: &RelayReceiptVerifyKeyV1,
    tbs: &RelayAdminPurgeReceiptTbsV1,
) -> Result<(), CryptoError> {
    if verify_key.relay_server_id != tbs.relay_server_id
        || verify_key.key_generation != tbs.receipt_key_generation
        || verify_key.key_id != tbs.receipt_key_id
    {
        return Err(RelayAdminPurgeReceiptError::ReceiptVerifyKeyBindingMismatch.into());
    }
    Ok(())
}

/// 对任意 canonical bytes 验签（供 sealed-blob verifier-hook 复用）。
pub(crate) fn verify_raw(
    key: &VerifyingKey,
    message: &[u8],
    signature: &Ed25519Signature,
) -> Result<(), CryptoError> {
    let sig = Signature::from_bytes(&signature.0);
    key.0
        .verify_strict(message, &sig)
        .map_err(|_| CryptoError::BadSignature)
}

/// 对任意 canonical bytes 签名（供 sealed-blob 签名复用）。
pub(crate) fn sign_raw(key: &SigningKey, message: &[u8]) -> Ed25519Signature {
    Ed25519Signature(key.0.sign(message).to_bytes())
}

#[cfg(test)]
mod tests {
    use agentdeck_protocol::relay_v2::auth::{AuthenticationRole, AuthenticationTranscriptV1};
    use agentdeck_protocol::relay_v2::{
        ConnectionInstanceId, DeviceRouteId, MachineRouteId, RelayServerId,
    };

    use super::*;

    fn transcript() -> AuthenticationTranscriptV1 {
        AuthenticationTranscriptV1 {
            role: AuthenticationRole::MachineLink,
            challenge_nonce: [1; 32],
            connection_instance: ConnectionInstanceId::from_bytes([2; 16]),
            relay_server_id: RelayServerId::from_bytes([3; 16]),
            relay_protocol_version: 2,
            machine_route: MachineRouteId::from_bytes([4; 16]),
            device_route: None,
            serial_or_generation: 5,
            credential_sha256: [6; 32],
        }
    }

    #[test]
    fn typed_authentication_signature_golden_is_stable() {
        let signing = SigningKey::from_seed(&[0x42; 32]);
        let signature = sign_authentication_transcript(&signing, &transcript());
        assert_eq!(
            signature.0,
            [
                0xd3, 0xb5, 0x86, 0xf2, 0x35, 0x8a, 0xed, 0x77, 0x5b, 0x3b, 0x83, 0x21, 0xc1, 0x34,
                0x52, 0x33, 0x93, 0xd4, 0xd6, 0x04, 0x81, 0x1b, 0x3a, 0x68, 0x32, 0x7a, 0x5a, 0xfe,
                0xec, 0x28, 0x7d, 0x1a, 0x9b, 0xbf, 0x9c, 0x82, 0x79, 0xda, 0xd3, 0x3a, 0x12, 0xcf,
                0x03, 0x9e, 0xd8, 0x33, 0x0d, 0xb9, 0x2d, 0x1a, 0x97, 0xe7, 0x21, 0xcc, 0x85, 0x5c,
                0x99, 0x33, 0x04, 0x6a, 0x31, 0x70, 0x11, 0x04,
            ]
        );
        verify_authentication_transcript(&signing.verifying_key(), &transcript(), &signature)
            .expect("golden signature verifies");
    }

    #[test]
    fn typed_authentication_signature_rejects_every_bound_field_tamper() {
        let signing = SigningKey::from_seed(&[0x42; 32]);
        let base = transcript();
        let signature = sign_authentication_transcript(&signing, &base);
        let mut tampered = Vec::new();

        let mut value = base.clone();
        value.role = AuthenticationRole::Device;
        tampered.push(value);
        let mut value = base.clone();
        value.challenge_nonce[0] ^= 1;
        tampered.push(value);
        let mut value = base.clone();
        value.connection_instance = ConnectionInstanceId::from_bytes([7; 16]);
        tampered.push(value);
        let mut value = base.clone();
        value.relay_server_id = RelayServerId::from_bytes([7; 16]);
        tampered.push(value);
        let mut value = base.clone();
        value.relay_protocol_version = 3;
        tampered.push(value);
        let mut value = base.clone();
        value.machine_route = MachineRouteId::from_bytes([7; 16]);
        tampered.push(value);
        let mut value = base.clone();
        value.device_route = Some(DeviceRouteId::from_bytes([7; 16]));
        tampered.push(value);
        let mut value = base.clone();
        value.serial_or_generation += 1;
        tampered.push(value);
        let mut value = base;
        value.credential_sha256[0] ^= 1;
        tampered.push(value);

        for changed in tampered {
            assert_eq!(
                verify_authentication_transcript(&signing.verifying_key(), &changed, &signature),
                Err(CryptoError::BadSignature)
            );
        }
    }

    #[test]
    fn typed_authentication_signature_rejects_wrong_key_and_signature() {
        let signing = SigningKey::from_seed(&[0x42; 32]);
        let wrong = SigningKey::from_seed(&[0x43; 32]);
        let transcript = transcript();
        let signature = sign_authentication_transcript(&signing, &transcript);
        assert_eq!(
            verify_authentication_transcript(&wrong.verifying_key(), &transcript, &signature),
            Err(CryptoError::BadSignature)
        );

        let mut changed = signature;
        changed.0[0] ^= 1;
        assert_eq!(
            verify_authentication_transcript(&signing.verifying_key(), &transcript, &changed),
            Err(CryptoError::BadSignature)
        );
    }
}
