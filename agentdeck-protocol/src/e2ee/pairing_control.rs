//! Pairing control receipts 的专属 deterministic TBS。
//!
//! PairPending/PairTerminal 由 MachineDataSign 签名；PairResponseReceived 由 DeviceSign
//! 签名。三者都绑定完整 pair trust domain，且不复用要求非空 pre-grant machine route 的
//! 通用 TBS。

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::e2ee::context::{OuterContextV1, OuterFrameKind};
use crate::e2ee::pairing::{
    MachineDataSignerBindingV1, PAIRING_HPKE_ENC_BYTES, PAIRING_MAX_CIPHERTEXT_BYTES,
    PairPendingV1, PairRequestInfoV1, PairResponseInfoV1, PairResponseReceivedV1,
    PairTerminalOutcomeV1, PairTerminalV1, PairingError,
};
use crate::e2ee::{E2EE_FORMAT_VERSION, Enc, b64_32, b64_vec};
use crate::relay_v2::RELAY_PROTOCOL_VERSION;
use crate::relay_v2::auth::Ed25519Signature;
use crate::relay_v2::id::{
    DeviceRouteId, GrantSerial, LinkGeneration, MachineRouteId, PairRouteId, RelayServerId,
    TrustEpoch,
};

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

const PAIR_TERMINAL_MAX_UNSIGNED_CANONICAL_BYTES: usize = 256;
const PAIR_TERMINAL_MAX_CANONICAL_BYTES: usize = 512;

/// PairPending/PairTerminal 等已签名 pairing control plaintext 的 HPKE carrier。Relay
/// 只能看到 `enc+ciphertext`，看不到 requestHash 或 control subtype。
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PairingControlEnvelopeV1 {
    pub format_version: u16,
    #[serde(with = "b64_vec")]
    #[schemars(with = "String")]
    pub enc: Vec<u8>,
    #[serde(with = "b64_vec")]
    #[schemars(with = "String")]
    pub ciphertext: Vec<u8>,
}

impl std::fmt::Debug for PairingControlEnvelopeV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PairingControlEnvelopeV1")
            .field("encrypted_material", &"<redacted>")
            .finish()
    }
}

impl PairingControlEnvelopeV1 {
    pub fn validate(&self) -> Result<(), PairingError> {
        if self.format_version != E2EE_FORMAT_VERSION {
            return Err(PairingError::UnsupportedVersion);
        }
        if self.enc.len() != PAIRING_HPKE_ENC_BYTES || is_zero(&self.enc) {
            return Err(PairingError::InvalidField("pairing control HPKE enc"));
        }
        if self.ciphertext.is_empty() || self.ciphertext.len() > PAIRING_MAX_CIPHERTEXT_BYTES {
            return Err(PairingError::SizeLimit("pairing control ciphertext"));
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, PairingError> {
        self.validate()?;
        let mut encoder = Enc::new();
        encoder.domain(b"AgentDeck/PairingControlEnvelopeV1\0");
        encoder.u16(self.format_version);
        encoder.bytes(&self.enc);
        encoder.bytes(&self.ciphertext);
        Ok(encoder.finish())
    }

    pub fn canonical_sha256(&self) -> Result<[u8; 32], PairingError> {
        Ok(sha256(&self.canonical_bytes()?))
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, PairingError> {
        let mut decoder = ControlDecoder::new(bytes);
        decoder.domain(b"AgentDeck/PairingControlEnvelopeV1\0")?;
        let value = Self {
            format_version: decoder.u16()?,
            enc: decoder.bytes(PAIRING_HPKE_ENC_BYTES)?.to_vec(),
            ciphertext: decoder.bytes(PAIRING_MAX_CIPHERTEXT_BYTES)?.to_vec(),
        };
        decoder.finish()?;
        value.validate()?;
        if value.canonical_bytes()?.as_slice() != bytes {
            return Err(PairingError::InvalidEncoding(
                "non-canonical pairing control",
            ));
        }
        Ok(value)
    }
}

impl PairPendingV1 {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, PairingError> {
        self.validate()?;
        let mut encoder = Enc::new();
        encoder.domain(b"AgentDeck/PairPendingV1\0");
        encoder.bytes(&self.request_hash);
        encoder.bytes(&self.signature.0);
        Ok(encoder.finish())
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, PairingError> {
        let mut decoder = ControlDecoder::new(bytes);
        decoder.domain(b"AgentDeck/PairPendingV1\0")?;
        let value = Self {
            request_hash: decoder.fixed()?,
            signature: Ed25519Signature(decoder.fixed()?),
        };
        decoder.finish()?;
        value.validate()?;
        if value.canonical_bytes()?.as_slice() != bytes {
            return Err(PairingError::InvalidEncoding("non-canonical PairPending"));
        }
        Ok(value)
    }
}

impl PairTerminalV1 {
    fn validate_unsigned(&self) -> Result<(), PairingError> {
        if is_zero(self.machine_route.as_bytes()) || is_zero(&self.request_hash) {
            return Err(PairingError::InvalidField("PairTerminal"));
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), PairingError> {
        self.validate_unsigned()?;
        if is_zero(&self.signature.0) {
            return Err(PairingError::InvalidField("PairTerminal signature"));
        }
        Ok(())
    }

    pub fn unsigned_canonical_bytes(&self) -> Result<Vec<u8>, PairingError> {
        self.validate_unsigned()?;
        let mut encoder = Enc::new();
        encoder.domain(b"AgentDeck/PairTerminalUnsignedV1\0");
        encoder.bytes(self.machine_route.as_bytes());
        encoder.bytes(&self.request_hash);
        encoder.u8(self.outcome.canonical_tag());
        let bytes = encoder.finish();
        if bytes.len() > PAIR_TERMINAL_MAX_UNSIGNED_CANONICAL_BYTES {
            return Err(PairingError::SizeLimit("PairTerminal unsigned canonical"));
        }
        Ok(bytes)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, PairingError> {
        self.validate()?;
        let unsigned = self.unsigned_canonical_bytes()?;
        let mut encoder = Enc::new();
        encoder.domain(b"AgentDeck/PairTerminalV1\0");
        encoder.bytes(&unsigned);
        encoder.bytes(&self.signature.0);
        let bytes = encoder.finish();
        if bytes.len() > PAIR_TERMINAL_MAX_CANONICAL_BYTES {
            return Err(PairingError::SizeLimit("PairTerminal canonical"));
        }
        Ok(bytes)
    }

    pub fn canonical_sha256(&self) -> Result<[u8; 32], PairingError> {
        Ok(sha256(&self.canonical_bytes()?))
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, PairingError> {
        if bytes.len() > PAIR_TERMINAL_MAX_CANONICAL_BYTES {
            return Err(PairingError::SizeLimit("PairTerminal canonical"));
        }
        let mut outer = ControlDecoder::new(bytes);
        outer.domain(b"AgentDeck/PairTerminalV1\0")?;
        let unsigned = outer.bytes(PAIR_TERMINAL_MAX_UNSIGNED_CANONICAL_BYTES)?;
        let signature = Ed25519Signature(outer.fixed()?);
        outer.finish()?;

        let mut decoder = ControlDecoder::new(unsigned);
        decoder.domain(b"AgentDeck/PairTerminalUnsignedV1\0")?;
        let value = Self {
            machine_route: MachineRouteId::from_bytes(decoder.fixed()?),
            request_hash: decoder.fixed()?,
            outcome: PairTerminalOutcomeV1::from_tag(decoder.u8()?)?,
            signature,
        };
        decoder.finish()?;
        value.validate()?;
        if value.canonical_bytes()?.as_slice() != bytes {
            return Err(PairingError::InvalidEncoding("non-canonical PairTerminal"));
        }
        Ok(value)
    }
}

/// PairTerminal 的 MachineDataSign TBS。绑定完整 invite trust domain、exact request 和
/// MachineDataSign certificate identity，不复用 PairPending 或通用 sealed-blob TBS。
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PairTerminalTbsV1 {
    pub e2ee_format_version: u16,
    pub runtime_protocol_version: u16,
    pub relay_protocol_version: u16,
    pub relay_server_id: RelayServerId,
    pub pair_route: PairRouteId,
    #[serde(with = "b64_32")]
    #[schemars(with = "String")]
    pub invite_hash: [u8; 32],
    pub expiry_ms: u64,
    pub machine_route: MachineRouteId,
    #[serde(with = "b64_32")]
    #[schemars(with = "String")]
    pub request_hash: [u8; 32],
    pub outcome: PairTerminalOutcomeV1,
    #[serde(with = "b64_32")]
    #[schemars(with = "String")]
    pub signing_key_fingerprint: [u8; 32],
    pub signing_key_generation: LinkGeneration,
    #[serde(with = "b64_32")]
    #[schemars(with = "String")]
    pub signing_credential_sha256: [u8; 32],
    #[serde(with = "b64_32")]
    #[schemars(with = "String")]
    pub info_sha256: [u8; 32],
    #[serde(with = "b64_32")]
    #[schemars(with = "String")]
    pub aad_sha256: [u8; 32],
}

impl std::fmt::Debug for PairTerminalTbsV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PairTerminalTbsV1")
            .field("outcome", &self.outcome)
            .field("versions", &"<redacted>")
            .field("bound_material", &"<redacted>")
            .finish()
    }
}

impl PairTerminalTbsV1 {
    pub fn validate(&self) -> Result<(), PairingError> {
        if self.e2ee_format_version != E2EE_FORMAT_VERSION
            || self.runtime_protocol_version != crate::runtime::RUNTIME_PROTOCOL_VERSION
            || self.relay_protocol_version != RELAY_PROTOCOL_VERSION
            || is_zero(self.relay_server_id.as_bytes())
            || is_zero(self.pair_route.as_bytes())
            || is_zero(&self.invite_hash)
            || self.expiry_ms == 0
            || is_zero(self.machine_route.as_bytes())
            || is_zero(&self.request_hash)
            || is_zero(&self.signing_key_fingerprint)
            || self.signing_key_generation.value() == 0
            || is_zero(&self.signing_credential_sha256)
            || is_zero(&self.info_sha256)
            || is_zero(&self.aad_sha256)
        {
            return Err(PairingError::InvalidField("PairTerminal TBS"));
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, PairingError> {
        self.validate()?;
        let mut encoder = Enc::new();
        encoder.domain(b"AgentDeck/PairTerminalTbsV1\0");
        encoder.u16(self.e2ee_format_version);
        encoder.u16(self.runtime_protocol_version);
        encoder.u16(self.relay_protocol_version);
        encoder.bytes(self.relay_server_id.as_bytes());
        encoder.bytes(self.pair_route.as_bytes());
        encoder.bytes(&self.invite_hash);
        encoder.u64(self.expiry_ms);
        encoder.bytes(self.machine_route.as_bytes());
        encoder.bytes(&self.request_hash);
        encoder.u8(self.outcome.canonical_tag());
        encoder.bytes(&self.signing_key_fingerprint);
        encoder.u64(self.signing_key_generation.value());
        encoder.bytes(&self.signing_credential_sha256);
        encoder.bytes(&self.info_sha256);
        encoder.bytes(&self.aad_sha256);
        Ok(encoder.finish())
    }
}

impl PairTerminalV1 {
    pub fn signature_tbs(
        &self,
        info: &PairRequestInfoV1,
        context: &OuterContextV1,
        signer: &MachineDataSignerBindingV1,
    ) -> Result<PairTerminalTbsV1, PairingError> {
        self.validate_unsigned()?;
        signer.validate()?;
        context
            .validate()
            .map_err(|_| PairingError::ContextBindingMismatch)?;
        if context.frame_kind != OuterFrameKind::PairTerminal
            || context.pair_route != Some(info.pair_route)
            || context.e2ee_format_version != info.e2ee_format_version
            || info.e2ee_format_version != E2EE_FORMAT_VERSION
            || info.runtime_protocol_version != crate::runtime::RUNTIME_PROTOCOL_VERSION
            || context.relay_protocol_version != RELAY_PROTOCOL_VERSION
            || is_zero(info.relay_server_id.as_bytes())
            || is_zero(info.pair_route.as_bytes())
            || is_zero(&info.invite_hash)
            || info.expiry_ms == 0
        {
            return Err(PairingError::ContextBindingMismatch);
        }
        let tbs = PairTerminalTbsV1 {
            e2ee_format_version: info.e2ee_format_version,
            runtime_protocol_version: info.runtime_protocol_version,
            relay_protocol_version: context.relay_protocol_version,
            relay_server_id: info.relay_server_id,
            pair_route: info.pair_route,
            invite_hash: info.invite_hash,
            expiry_ms: info.expiry_ms,
            machine_route: self.machine_route,
            request_hash: self.request_hash,
            outcome: self.outcome,
            signing_key_fingerprint: signer.signing_key_fingerprint,
            signing_key_generation: signer.generation,
            signing_credential_sha256: signer.certificate_sha256,
            info_sha256: sha256(&info.encode()),
            aad_sha256: sha256(&context.encode_aad()),
        };
        tbs.validate()?;
        Ok(tbs)
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PairPendingTbsV1 {
    pub e2ee_format_version: u16,
    pub runtime_protocol_version: u16,
    pub relay_protocol_version: u16,
    pub relay_server_id: RelayServerId,
    pub pair_route: PairRouteId,
    #[serde(with = "b64_32")]
    #[schemars(with = "String")]
    pub invite_hash: [u8; 32],
    pub expiry_ms: u64,
    #[serde(with = "b64_32")]
    #[schemars(with = "String")]
    pub request_hash: [u8; 32],
    #[serde(with = "b64_32")]
    #[schemars(with = "String")]
    pub signing_key_fingerprint: [u8; 32],
    pub signing_key_generation: LinkGeneration,
    #[serde(with = "b64_32")]
    #[schemars(with = "String")]
    pub signing_credential_sha256: [u8; 32],
    #[serde(with = "b64_32")]
    #[schemars(with = "String")]
    pub info_sha256: [u8; 32],
    #[serde(with = "b64_32")]
    #[schemars(with = "String")]
    pub aad_sha256: [u8; 32],
}

impl std::fmt::Debug for PairPendingTbsV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PairPendingTbsV1")
            .field("versions", &"<redacted>")
            .field("bound_material", &"<redacted>")
            .finish()
    }
}

impl PairPendingTbsV1 {
    pub fn validate(&self) -> Result<(), PairingError> {
        if self.e2ee_format_version != E2EE_FORMAT_VERSION
            || self.runtime_protocol_version != crate::runtime::RUNTIME_PROTOCOL_VERSION
            || self.relay_protocol_version != RELAY_PROTOCOL_VERSION
            || is_zero(self.relay_server_id.as_bytes())
            || is_zero(self.pair_route.as_bytes())
            || is_zero(&self.invite_hash)
            || self.expiry_ms == 0
            || is_zero(&self.request_hash)
            || is_zero(&self.signing_key_fingerprint)
            || self.signing_key_generation.value() == 0
            || is_zero(&self.signing_credential_sha256)
            || is_zero(&self.info_sha256)
            || is_zero(&self.aad_sha256)
        {
            return Err(PairingError::InvalidField("PairPending TBS"));
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, PairingError> {
        self.validate()?;
        let mut encoder = Enc::new();
        encoder.domain(b"AgentDeck/PairPendingTbsV1\0");
        encoder.u16(self.e2ee_format_version);
        encoder.u16(self.runtime_protocol_version);
        encoder.u16(self.relay_protocol_version);
        encoder.bytes(self.relay_server_id.as_bytes());
        encoder.bytes(self.pair_route.as_bytes());
        encoder.bytes(&self.invite_hash);
        encoder.u64(self.expiry_ms);
        encoder.bytes(&self.request_hash);
        encoder.bytes(&self.signing_key_fingerprint);
        encoder.u64(self.signing_key_generation.value());
        encoder.bytes(&self.signing_credential_sha256);
        encoder.bytes(&self.info_sha256);
        encoder.bytes(&self.aad_sha256);
        Ok(encoder.finish())
    }
}

impl PairPendingV1 {
    pub fn validate(&self) -> Result<(), PairingError> {
        if is_zero(&self.request_hash) || is_zero(&self.signature.0) {
            return Err(PairingError::InvalidField("PairPending"));
        }
        Ok(())
    }

    pub fn signature_tbs(
        &self,
        info: &PairRequestInfoV1,
        context: &OuterContextV1,
        signer: &MachineDataSignerBindingV1,
    ) -> Result<PairPendingTbsV1, PairingError> {
        signer.validate()?;
        context
            .validate()
            .map_err(|_| PairingError::ContextBindingMismatch)?;
        if context.frame_kind != OuterFrameKind::PairPending
            || context.pair_route != Some(info.pair_route)
            || context.e2ee_format_version != info.e2ee_format_version
            || info.e2ee_format_version != E2EE_FORMAT_VERSION
            || context.relay_protocol_version != RELAY_PROTOCOL_VERSION
            || is_zero(&self.request_hash)
            || is_zero(&info.invite_hash)
            || info.expiry_ms == 0
        {
            return Err(PairingError::ContextBindingMismatch);
        }
        let tbs = PairPendingTbsV1 {
            e2ee_format_version: info.e2ee_format_version,
            runtime_protocol_version: info.runtime_protocol_version,
            relay_protocol_version: context.relay_protocol_version,
            relay_server_id: info.relay_server_id,
            pair_route: info.pair_route,
            invite_hash: info.invite_hash,
            expiry_ms: info.expiry_ms,
            request_hash: self.request_hash,
            signing_key_fingerprint: signer.signing_key_fingerprint,
            signing_key_generation: signer.generation,
            signing_credential_sha256: signer.certificate_sha256,
            info_sha256: sha256(&info.encode()),
            aad_sha256: sha256(&context.encode_aad()),
        };
        tbs.validate()?;
        Ok(tbs)
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PairResponseReceivedTbsV1 {
    pub e2ee_format_version: u16,
    pub runtime_protocol_version: u16,
    pub relay_protocol_version: u16,
    pub relay_server_id: RelayServerId,
    pub pair_route: PairRouteId,
    #[serde(with = "b64_32")]
    #[schemars(with = "String")]
    pub invite_hash: [u8; 32],
    pub expiry_ms: u64,
    #[serde(with = "b64_32")]
    #[schemars(with = "String")]
    pub request_hash: [u8; 32],
    #[serde(with = "b64_32")]
    #[schemars(with = "String")]
    pub grant_hash: [u8; 32],
    #[serde(with = "b64_32")]
    #[schemars(with = "String")]
    pub response_hash: [u8; 32],
    pub machine_route: MachineRouteId,
    pub device_route: DeviceRouteId,
    pub grant_serial: GrantSerial,
    pub root_trust_epoch: TrustEpoch,
    #[serde(with = "b64_32")]
    #[schemars(with = "String")]
    pub device_sign_fingerprint: [u8; 32],
    #[serde(with = "b64_32")]
    #[schemars(with = "String")]
    pub info_sha256: [u8; 32],
    #[serde(with = "b64_32")]
    #[schemars(with = "String")]
    pub aad_sha256: [u8; 32],
}

impl std::fmt::Debug for PairResponseReceivedTbsV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PairResponseReceivedTbsV1")
            .field("versions", &"<redacted>")
            .field("bound_material", &"<redacted>")
            .finish()
    }
}

impl PairResponseReceivedTbsV1 {
    pub fn validate(&self) -> Result<(), PairingError> {
        if self.e2ee_format_version != E2EE_FORMAT_VERSION
            || self.runtime_protocol_version != crate::runtime::RUNTIME_PROTOCOL_VERSION
            || self.relay_protocol_version != RELAY_PROTOCOL_VERSION
            || is_zero(self.relay_server_id.as_bytes())
            || is_zero(self.pair_route.as_bytes())
            || is_zero(&self.invite_hash)
            || self.expiry_ms == 0
            || is_zero(&self.request_hash)
            || is_zero(&self.grant_hash)
            || is_zero(&self.response_hash)
            || is_zero(self.machine_route.as_bytes())
            || is_zero(self.device_route.as_bytes())
            || self.grant_serial.value() == 0
            || self.root_trust_epoch.value() == 0
            || is_zero(&self.device_sign_fingerprint)
            || is_zero(&self.info_sha256)
            || is_zero(&self.aad_sha256)
        {
            return Err(PairingError::InvalidField("PairResponseReceived TBS"));
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, PairingError> {
        self.validate()?;
        let mut encoder = Enc::new();
        encoder.domain(b"AgentDeck/PairResponseReceivedTbsV1\0");
        encoder.u16(self.e2ee_format_version);
        encoder.u16(self.runtime_protocol_version);
        encoder.u16(self.relay_protocol_version);
        encoder.bytes(self.relay_server_id.as_bytes());
        encoder.bytes(self.pair_route.as_bytes());
        encoder.bytes(&self.invite_hash);
        encoder.u64(self.expiry_ms);
        encoder.bytes(&self.request_hash);
        encoder.bytes(&self.grant_hash);
        encoder.bytes(&self.response_hash);
        encoder.bytes(self.machine_route.as_bytes());
        encoder.bytes(self.device_route.as_bytes());
        encoder.u64(self.grant_serial.value());
        encoder.u64(self.root_trust_epoch.value());
        encoder.bytes(&self.device_sign_fingerprint);
        encoder.bytes(&self.info_sha256);
        encoder.bytes(&self.aad_sha256);
        Ok(encoder.finish())
    }
}

impl PairResponseReceivedV1 {
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, PairingError> {
        let mut outer = ControlDecoder::new(bytes);
        outer.domain(b"AgentDeck/PairResponseReceivedV1\0")?;
        let unsigned = outer.bytes(1_024)?;
        let signature = Ed25519Signature(outer.fixed()?);
        outer.finish()?;

        let mut decoder = ControlDecoder::new(unsigned);
        decoder.domain(b"AgentDeck/PairResponseReceivedUnsignedV1\0")?;
        let value = Self {
            request_hash: decoder.fixed()?,
            grant_hash: decoder.fixed()?,
            response_hash: decoder.fixed()?,
            signature,
        };
        decoder.finish()?;
        if value.canonical_bytes()?.as_slice() != bytes {
            return Err(PairingError::InvalidEncoding(
                "non-canonical PairResponseReceived",
            ));
        }
        Ok(value)
    }

    pub fn receipt_tbs(
        &self,
        info: &PairResponseInfoV1,
        context: &OuterContextV1,
        device_sign_fingerprint: [u8; 32],
    ) -> Result<PairResponseReceivedTbsV1, PairingError> {
        context
            .validate()
            .map_err(|_| PairingError::ContextBindingMismatch)?;
        if context.frame_kind != OuterFrameKind::PairResponseReceived
            || context.pair_route != Some(info.pair_route)
            || context.e2ee_format_version != info.e2ee_format_version
            || info.e2ee_format_version != E2EE_FORMAT_VERSION
            || context.relay_protocol_version != RELAY_PROTOCOL_VERSION
            || self.request_hash != info.request_hash
            || is_zero(&self.grant_hash)
            || is_zero(&self.response_hash)
            || is_zero(&device_sign_fingerprint)
            || is_zero(&info.invite_hash)
            || info.expiry_ms == 0
            || is_zero(info.machine_route.as_bytes())
            || is_zero(info.device_route.as_bytes())
            || info.grant_serial.value() == 0
            || info.root_trust_epoch.value() == 0
        {
            return Err(PairingError::ContextBindingMismatch);
        }
        let tbs = PairResponseReceivedTbsV1 {
            e2ee_format_version: info.e2ee_format_version,
            runtime_protocol_version: info.runtime_protocol_version,
            relay_protocol_version: context.relay_protocol_version,
            relay_server_id: info.relay_server_id,
            pair_route: info.pair_route,
            invite_hash: info.invite_hash,
            expiry_ms: info.expiry_ms,
            request_hash: self.request_hash,
            grant_hash: self.grant_hash,
            response_hash: self.response_hash,
            machine_route: info.machine_route,
            device_route: info.device_route,
            grant_serial: info.grant_serial,
            root_trust_epoch: info.root_trust_epoch,
            device_sign_fingerprint,
            info_sha256: sha256(&info.encode()),
            aad_sha256: sha256(&context.encode_aad()),
        };
        tbs.validate()?;
        Ok(tbs)
    }
}

struct ControlDecoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> ControlDecoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], PairingError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(PairingError::InvalidEncoding("offset overflow"))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(PairingError::InvalidEncoding("truncated control bytes"))?;
        self.offset = end;
        Ok(value)
    }

    fn domain(&mut self, expected: &[u8]) -> Result<(), PairingError> {
        if self.take(expected.len())? != expected {
            return Err(PairingError::InvalidEncoding("control domain"));
        }
        Ok(())
    }

    fn u16(&mut self) -> Result<u16, PairingError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().expect("fixed")))
    }

    fn u8(&mut self) -> Result<u8, PairingError> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, PairingError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().expect("fixed")))
    }

    fn bytes(&mut self, maximum: usize) -> Result<&'a [u8], PairingError> {
        let length = self.u32()? as usize;
        if length > maximum {
            return Err(PairingError::SizeLimit("control byte field"));
        }
        self.take(length)
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], PairingError> {
        self.bytes(N)?
            .try_into()
            .map_err(|_| PairingError::InvalidEncoding("control fixed-size field"))
    }

    fn finish(self) -> Result<(), PairingError> {
        if self.offset != self.bytes.len() {
            return Err(PairingError::InvalidEncoding("control trailing bytes"));
        }
        Ok(())
    }
}
