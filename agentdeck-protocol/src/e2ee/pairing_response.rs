//! PairResponse 的 clear info、MachineDataSign identity 与 signed HPKE envelope。

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::e2ee::context::OuterContextV1;
use crate::e2ee::{E2EE_FORMAT_VERSION, Enc, b64_32, b64_vec};
use crate::relay_v2::auth::{CertRole, Ed25519Signature, SignedCertificate};
use crate::relay_v2::id::{
    DeviceRouteId, GrantSerial, LinkGeneration, MachineRouteId, PairRouteId, RelayServerId,
    TrustEpoch,
};

use super::{
    Decoder, MAX_PAIR_RESPONSE_INFO_CANONICAL_BYTES, PairingEnvelopeKindV1, PairingEnvelopeTbsV1,
    PairingError, decode_signed_envelope, encode_signed_envelope, encode_unsigned_envelope,
    ensure_canonical, is_zero, sha256, validate_envelope, validate_response_context,
};

/// Relay PairData 携带的完整 PairResponse envelope。responseHash 覆盖 `canonical_bytes()`。
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PairResponseV1 {
    pub format_version: u16,
    /// Relay 可见、且同时进入 HPKE info、MachineDataSign TBS 与 responseHash 的完整绑定。
    pub info: PairResponseInfoV1,
    #[serde(with = "b64_vec")]
    #[schemars(with = "String")]
    pub enc: Vec<u8>,
    #[serde(with = "b64_vec")]
    #[schemars(with = "String")]
    pub ciphertext: Vec<u8>,
    pub machine_data_signature: Ed25519Signature,
}

impl std::fmt::Debug for PairResponseV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PairResponseV1")
            .field("envelope", &"<redacted>")
            .finish()
    }
}

impl PairResponseV1 {
    pub(super) fn ensure_info_matches(
        &self,
        caller: &PairResponseInfoV1,
    ) -> Result<(), PairingError> {
        if caller != &self.info {
            return Err(PairingError::ContextBindingMismatch);
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), PairingError> {
        self.info.validate()?;
        validate_envelope(
            self.format_version,
            &self.enc,
            &self.ciphertext,
            &self.machine_data_signature,
        )
    }

    pub fn unsigned_canonical_bytes(&self) -> Result<Vec<u8>, PairingError> {
        self.validate()?;
        encode_unsigned_envelope(
            PairingEnvelopeKindV1::PairResponse,
            self.format_version,
            Some(&self.info),
            &self.enc,
            &self.ciphertext,
        )
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, PairingError> {
        let unsigned = self.unsigned_canonical_bytes()?;
        Ok(encode_signed_envelope(
            PairingEnvelopeKindV1::PairResponse,
            &unsigned,
            &self.machine_data_signature,
        ))
    }

    pub fn canonical_sha256(&self) -> Result<[u8; 32], PairingError> {
        Ok(sha256(&self.canonical_bytes()?))
    }

    pub fn signature_tbs(
        &self,
        info: &PairResponseInfoV1,
        context: &OuterContextV1,
        signer: &MachineDataSignerBindingV1,
    ) -> Result<PairingEnvelopeTbsV1, PairingError> {
        self.validate()?;
        self.ensure_info_matches(info)?;
        validate_response_context(info, context)?;
        signer.validate()?;
        PairingEnvelopeTbsV1::for_response(self, info, context, signer)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, PairingError> {
        let decoded = decode_signed_envelope(bytes, PairingEnvelopeKindV1::PairResponse)?;
        let value = Self {
            format_version: decoded.format_version,
            info: decoded
                .response_info
                .ok_or(PairingError::InvalidEncoding("PairResponse embedded info"))?,
            enc: decoded.enc,
            ciphertext: decoded.ciphertext,
            machine_data_signature: decoded.signature,
        };
        value.validate()?;
        ensure_canonical(bytes, &value.canonical_bytes()?)?;
        Ok(value)
    }
}

/// PairResponse 的当前 MachineDataSign 身份。绑定公钥 fingerprint、单调 generation 与
/// 包含 MachineRoot signature 的完整 data cert hash，避免只靠 verifier key 隐含身份。
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MachineDataSignerBindingV1 {
    #[serde(with = "b64_32")]
    #[schemars(with = "String")]
    pub signing_key_fingerprint: [u8; 32],
    pub generation: LinkGeneration,
    #[serde(with = "b64_32")]
    #[schemars(with = "String")]
    pub certificate_sha256: [u8; 32],
}

impl std::fmt::Debug for MachineDataSignerBindingV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MachineDataSignerBindingV1")
            .field("generation", &self.generation.value())
            .field("signer_material", &"<redacted>")
            .finish()
    }
}

impl MachineDataSignerBindingV1 {
    pub fn from_certificate(certificate: &SignedCertificate) -> Result<Self, PairingError> {
        if certificate.cert_role != CertRole::Data {
            return Err(PairingError::InvalidField(
                "MachineDataSign certificate role",
            ));
        }
        let value = Self {
            signing_key_fingerprint: sha256(&certificate.subject_pubkey.0),
            generation: certificate.generation,
            certificate_sha256: certificate.canonical_sha256(),
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), PairingError> {
        if is_zero(&self.signing_key_fingerprint)
            || self.generation.value() == 0
            || is_zero(&self.certificate_sha256)
        {
            return Err(PairingError::InvalidField("MachineDataSign binding"));
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PairResponseInfoV1 {
    pub e2ee_format_version: u16,
    pub runtime_protocol_version: u16,
    pub relay_server_id: RelayServerId,
    pub pair_route: PairRouteId,
    #[serde(with = "b64_32")]
    #[schemars(with = "String")]
    pub invite_hash: [u8; 32],
    pub expiry_ms: u64,
    #[serde(with = "b64_32")]
    #[schemars(with = "String")]
    pub request_hash: [u8; 32],
    pub machine_route: MachineRouteId,
    pub device_route: DeviceRouteId,
    pub grant_serial: GrantSerial,
    pub root_trust_epoch: TrustEpoch,
}

impl std::fmt::Debug for PairResponseInfoV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PairResponseInfoV1")
            .field("e2ee_format_version", &self.e2ee_format_version)
            .field("runtime_protocol_version", &self.runtime_protocol_version)
            .field("binding", &"<redacted>")
            .finish()
    }
}

impl PairResponseInfoV1 {
    pub fn validate(&self) -> Result<(), PairingError> {
        if self.e2ee_format_version != E2EE_FORMAT_VERSION
            || self.runtime_protocol_version != crate::runtime::RUNTIME_PROTOCOL_VERSION
            || is_zero(self.relay_server_id.as_bytes())
            || is_zero(self.pair_route.as_bytes())
            || is_zero(&self.invite_hash)
            || self.expiry_ms == 0
            || is_zero(&self.request_hash)
            || is_zero(self.machine_route.as_bytes())
            || is_zero(self.device_route.as_bytes())
            || self.grant_serial.value() == 0
            || self.root_trust_epoch.value() == 0
        {
            return Err(PairingError::InvalidField("PairResponse info"));
        }
        Ok(())
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut encoder = Enc::new();
        encoder.domain(b"AgentDeck/PairResponseInfoV1\0");
        encoder.u16(self.e2ee_format_version);
        encoder.u16(self.runtime_protocol_version);
        encoder.bytes(self.relay_server_id.as_bytes());
        encoder.bytes(self.pair_route.as_bytes());
        encoder.bytes(&self.invite_hash);
        encoder.u64(self.expiry_ms);
        encoder.bytes(&self.request_hash);
        encoder.bytes(self.machine_route.as_bytes());
        encoder.bytes(self.device_route.as_bytes());
        encoder.u64(self.grant_serial.value());
        encoder.u64(self.root_trust_epoch.value());
        encoder.finish()
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, PairingError> {
        if bytes.len() > MAX_PAIR_RESPONSE_INFO_CANONICAL_BYTES {
            return Err(PairingError::SizeLimit("PairResponse info"));
        }
        let mut decoder = Decoder::new(bytes);
        decoder.domain(b"AgentDeck/PairResponseInfoV1\0")?;
        let value = Self {
            e2ee_format_version: decoder.u16()?,
            runtime_protocol_version: decoder.u16()?,
            relay_server_id: RelayServerId::from_bytes(decoder.fixed()?),
            pair_route: PairRouteId::from_bytes(decoder.fixed()?),
            invite_hash: decoder.fixed()?,
            expiry_ms: decoder.u64()?,
            request_hash: decoder.fixed()?,
            machine_route: MachineRouteId::from_bytes(decoder.fixed()?),
            device_route: DeviceRouteId::from_bytes(decoder.fixed()?),
            grant_serial: GrantSerial::new(decoder.u64()?),
            root_trust_epoch: TrustEpoch::new(decoder.u64()?),
        };
        decoder.finish()?;
        value.validate()?;
        ensure_canonical(bytes, &value.encode())?;
        Ok(value)
    }
}
