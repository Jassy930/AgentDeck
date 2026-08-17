//! Relay Web Test Companion 的 transport-neutral Rust/WASM contract core。
//!
//! W0 只验证同一 Rust protocol/crypto 实现可以在 native 与 browser WASM 中产生
//! byte-identical Relay/crypto 结果，并严格读写 current Runtime v5 envelope；WebSocket、
//! IndexedDB 与 UI 仍由薄 host adapter 提供。

#![forbid(unsafe_code)]

use std::convert::Infallible;

use agentdeck_crypto::rand_core::{TryCryptoRng, TryRng};
use agentdeck_crypto::{
    AeadSendingKey, HpkeEnvelopeV1, HpkePrivateKey, SecretAeadKey, SenderCounter, SigningKey,
    hpke_open_base, hpke_seal_base, seal_symmetric, sha256, sign_tbs, verify_tbs,
};
use agentdeck_protocol::e2ee::context::{OuterContextV1, OuterFrameKind};
use agentdeck_protocol::e2ee::keys::{KeyId, KeyPurpose};
use agentdeck_protocol::e2ee::payload::SealedPayloadKind;
use agentdeck_protocol::e2ee::tbs::{SignedObjectType, ToBeSignedV1};
use agentdeck_protocol::relay_v2::frame::Hello;
use agentdeck_protocol::relay_v2::{
    DeviceRouteId, MachineRouteId, OpaqueRouteFrame, RELAY_PROTOCOL_VERSION, RelayFrameBody,
    RelayServerId, RootKeyId, StreamCursor, StreamGenerationId, StreamRouteId, TrustEpoch, decode,
    encode,
};
use agentdeck_protocol::runtime::{RUNTIME_PROTOCOL_VERSION, RuntimeEnvelope};
use serde::{Deserialize, Serialize};

#[cfg(feature = "w1-test-fixture")]
mod w1;
#[cfg(feature = "w1-test-fixture")]
pub use w1::{
    W1_SENTINEL, W1TestIdentity, W1TransportCore, W1TransportError, W1TransportFault,
    w1_test_identity,
};

#[cfg(feature = "w2-test-fixture")]
mod w2;
#[cfg(feature = "w2-test-fixture")]
mod w2_business;
#[cfg(feature = "w2-test-fixture")]
pub use w2::{W2PairingCore, W2PairingError, W2PairingEvidence, W2PairingPreview};
#[cfg(feature = "w2-test-fixture")]
pub use w2_business::{
    W2BusinessEvidence, W2ConversationView, W2NegativeSnapshot, w2_negative_snapshot,
};

const ED_SEED: [u8; 32] = [0x01; 32];
const AEAD_KEY: [u8; 32] = [0x11; 32];
const NONCE_PREFIX: [u8; 4] = [0xaa, 0xbb, 0xcc, 0xdd];
const SENDER_COUNTER: u64 = 0x0102_0304_0506_0708;
const HPKE_IKM: [u8; 32] = [0x42; 32];
const HPKE_RNG_SEED: [u8; 32] = [0x24; 32];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct W0ContractSnapshot {
    pub relay_hello_hex: String,
    pub sha256_hex: String,
    pub tbs_hex: String,
    pub ed25519_public_key_hex: String,
    pub ed25519_signature_hex: String,
    pub aead_nonce_hex: String,
    pub aead_ciphertext_hex: String,
    pub hpke_info_hex: String,
    pub hpke_recipient_public_hex: String,
    pub hpke_enc_hex: String,
    pub hpke_ciphertext_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct W0NegativeSnapshot {
    pub ed25519_signature_tamper_rejected: bool,
    pub hpke_ciphertext_tamper_rejected: bool,
    pub hpke_info_tamper_rejected: bool,
    pub hpke_aad_tamper_rejected: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum WebCoreError {
    #[error("Relay frame is invalid")]
    RelayFrameInvalid,
    #[error("Runtime v5 request is invalid")]
    RuntimeRequestInvalid,
    #[error("W0 cryptographic contract failed")]
    CryptoContractFailed,
    #[error("W0 contract serialization failed")]
    SerializationFailed,
}

pub(crate) struct DeterministicRng {
    seed: [u8; 32],
    counter: u64,
    buffer: [u8; 32],
    position: usize,
}

impl DeterministicRng {
    pub(crate) fn new(seed: [u8; 32]) -> Self {
        Self {
            seed,
            counter: 0,
            buffer: [0; 32],
            position: 32,
        }
    }

    fn refill(&mut self) {
        let mut input = Vec::with_capacity(9 + 32 + 8);
        input.extend_from_slice(b"AD/DetRng");
        input.extend_from_slice(&self.seed);
        input.extend_from_slice(&self.counter.to_be_bytes());
        self.buffer = sha256(&input);
        self.counter = self.counter.checked_add(1).expect("W0 KAT counter bound");
        self.position = 0;
    }

    fn fill(&mut self, destination: &mut [u8]) {
        for byte in destination {
            if self.position == self.buffer.len() {
                self.refill();
            }
            *byte = self.buffer[self.position];
            self.position += 1;
        }
    }
}

impl TryRng for DeterministicRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0; 4];
        self.fill(&mut bytes);
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0; 8];
        self.fill(&mut bytes);
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Self::Error> {
        self.fill(destination);
        Ok(())
    }
}

impl TryCryptoRng for DeterministicRng {}

impl Drop for DeterministicRng {
    fn drop(&mut self) {
        self.seed.fill(0);
        self.buffer.fill(0);
        self.counter = 0;
        self.position = self.buffer.len();
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

fn machine_route() -> MachineRouteId {
    MachineRouteId::from_bytes([0x11; 16])
}

fn device_route() -> DeviceRouteId {
    DeviceRouteId::from_bytes([0x22; 16])
}

fn relay_server_id() -> RelayServerId {
    RelayServerId::from_bytes([0x88; 16])
}

fn tbs_sample() -> ToBeSignedV1 {
    ToBeSignedV1 {
        object_type: SignedObjectType::RelayGrant,
        signature_format_version: 1,
        relay_protocol_version: RELAY_PROTOCOL_VERSION,
        runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
        e2ee_format_version: 1,
        relay_server_id: relay_server_id(),
        machine_route: machine_route(),
        device_route: Some(device_route()),
        stream_route: None,
        request_route: None,
        stream_generation: None,
        stream_cursor: None,
        role_scope: "device".into(),
        signing_key_fingerprint: [0x0f; 32],
        root_key_id: RootKeyId::from_bytes([0x77; 16]),
        trust_epoch: TrustEpoch::new(3),
        serial_or_generation: 9,
        not_after_ms: None,
        signed_object_sha256: [0x0e; 32],
    }
}

fn outer_sample() -> OuterContextV1 {
    OuterContextV1 {
        frame_kind: OuterFrameKind::ConversationPublish,
        relay_protocol_version: RELAY_PROTOCOL_VERSION,
        e2ee_format_version: 1,
        machine_route: Some(machine_route()),
        device_route: None,
        stream_route: Some(StreamRouteId::from_bytes([0x33; 16])),
        request_route: None,
        pair_route: None,
        stream_generation: Some(StreamGenerationId::from_bytes([0x66; 16])),
        stream_cursor: Some(StreamCursor::At(7)),
        stream_seq: Some(7),
        message_key_epoch: 4,
    }
}

fn outer_key_update_sample() -> OuterContextV1 {
    OuterContextV1 {
        frame_kind: OuterFrameKind::KeyUpdate,
        relay_protocol_version: RELAY_PROTOCOL_VERSION,
        e2ee_format_version: 1,
        machine_route: Some(machine_route()),
        device_route: Some(device_route()),
        stream_route: Some(StreamRouteId::from_bytes([0x33; 16])),
        request_route: None,
        pair_route: None,
        stream_generation: None,
        stream_cursor: None,
        stream_seq: None,
        message_key_epoch: 4,
    }
}

fn key_update_info() -> agentdeck_protocol::e2ee::keys::KeyUpdateInfoV1 {
    agentdeck_protocol::e2ee::keys::KeyUpdateInfoV1 {
        e2ee_format_version: 1,
        runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
        relay_server_id: relay_server_id(),
        machine_route: machine_route(),
        device_route: device_route(),
        stream_route: Some(StreamRouteId::from_bytes([0x33; 16])),
        grant_serial: agentdeck_protocol::relay_v2::GrantSerial::new(9),
        root_trust_epoch: TrustEpoch::new(3),
        key_directory_revision: agentdeck_protocol::relay_v2::KeyDirectoryRevision::new(2),
        key_purpose: KeyPurpose::ConversationDek,
        key_epoch: 4,
    }
}

fn hpke_sample() -> Result<(HpkePrivateKey, Vec<u8>, HpkeEnvelopeV1), WebCoreError> {
    let (private_key, public_key) = HpkePrivateKey::derive_keypair(&HPKE_IKM);
    let mut rng = DeterministicRng::new(HPKE_RNG_SEED);
    let envelope = hpke_seal_base(
        &public_key,
        &key_update_info().encode(),
        &outer_key_update_sample().encode_aad(),
        &[0x33; 32],
        &mut rng,
    )
    .map_err(|_| WebCoreError::CryptoContractFailed)?;
    Ok((private_key, public_key.to_bytes(), envelope))
}

pub fn relay_hello_bytes() -> Vec<u8> {
    encode(&OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::Hello(Hello {
            protocol_version: RELAY_PROTOCOL_VERSION,
        }),
    })
}

pub fn validate_relay_frame(bytes: &[u8]) -> Result<(), WebCoreError> {
    decode(bytes)
        .map(|_| ())
        .map_err(|_| WebCoreError::RelayFrameInvalid)
}

pub fn runtime_request_roundtrip(bytes: &[u8]) -> Result<Vec<u8>, WebCoreError> {
    let envelope = RuntimeEnvelope::from_json_bytes_checked(bytes)
        .map_err(|_| WebCoreError::RuntimeRequestInvalid)?;
    envelope
        .to_json_bytes_checked()
        .map_err(|_| WebCoreError::RuntimeRequestInvalid)
}

pub fn w0_contract_snapshot() -> Result<W0ContractSnapshot, WebCoreError> {
    let tbs = tbs_sample();
    let signing_key = SigningKey::from_seed(&ED_SEED);
    let sealed = seal_symmetric(
        &AeadSendingKey::new(
            KeyId {
                purpose: KeyPurpose::ConversationDek,
                epoch: 4,
            },
            4,
            2,
            NONCE_PREFIX,
            SecretAeadKey::from_bytes(AEAD_KEY),
        ),
        &outer_sample(),
        SealedPayloadKind::ConversationEvent,
        b"agentdeck-relay-e2ee",
        SenderCounter(SENDER_COUNTER),
    )
    .map_err(|_| WebCoreError::CryptoContractFailed)?;
    let (_, hpke_public, hpke_envelope) = hpke_sample()?;

    Ok(W0ContractSnapshot {
        relay_hello_hex: hex(&relay_hello_bytes()),
        sha256_hex: hex(&sha256(b"agentdeck/crypto-vectors-v1")),
        tbs_hex: hex(&tbs.encode()),
        ed25519_public_key_hex: hex(&signing_key.verifying_key().to_bytes()),
        ed25519_signature_hex: hex(&sign_tbs(&signing_key, &tbs).0),
        aead_nonce_hex: hex(&sealed.nonce),
        aead_ciphertext_hex: hex(&sealed.ciphertext),
        hpke_info_hex: hex(&key_update_info().encode()),
        hpke_recipient_public_hex: hex(&hpke_public),
        hpke_enc_hex: hex(&hpke_envelope.enc),
        hpke_ciphertext_hex: hex(&hpke_envelope.ciphertext),
    })
}

pub fn crypto_tamper_is_rejected() -> Result<bool, WebCoreError> {
    Ok(w0_negative_snapshot()?.hpke_ciphertext_tamper_rejected)
}

pub fn w0_negative_snapshot() -> Result<W0NegativeSnapshot, WebCoreError> {
    let signing_key = SigningKey::from_seed(&ED_SEED);
    let mut signature = sign_tbs(&signing_key, &tbs_sample());
    signature.0[0] ^= 0x01;

    let (private_key, _, mut envelope) = hpke_sample()?;
    let last = envelope
        .ciphertext
        .last_mut()
        .ok_or(WebCoreError::CryptoContractFailed)?;
    *last ^= 0x01;
    let info = key_update_info().encode();
    let aad = outer_key_update_sample().encode_aad();
    let hpke_ciphertext_tamper_rejected =
        hpke_open_base(&private_key, &info, &aad, &envelope).is_err();

    let (_, _, valid_envelope) = hpke_sample()?;
    let mut bad_info = info.clone();
    bad_info[0] ^= 0x01;
    let hpke_info_tamper_rejected =
        hpke_open_base(&private_key, &bad_info, &aad, &valid_envelope).is_err();
    let mut bad_aad = aad.clone();
    bad_aad[0] ^= 0x01;
    let hpke_aad_tamper_rejected =
        hpke_open_base(&private_key, &info, &bad_aad, &valid_envelope).is_err();

    Ok(W0NegativeSnapshot {
        ed25519_signature_tamper_rejected: verify_tbs(
            &signing_key.verifying_key(),
            &tbs_sample(),
            &signature,
        )
        .is_err(),
        hpke_ciphertext_tamper_rejected,
        hpke_info_tamper_rejected,
        hpke_aad_tamper_rejected,
    })
}

#[cfg(target_arch = "wasm32")]
mod wasm {
    use wasm_bindgen::prelude::*;

    fn js_error(error: super::WebCoreError) -> JsValue {
        JsValue::from_str(&error.to_string())
    }

    #[wasm_bindgen(js_name = w0RelayHello)]
    pub fn relay_hello() -> Vec<u8> {
        super::relay_hello_bytes()
    }

    #[wasm_bindgen(js_name = w0ValidateRelayFrame)]
    pub fn validate_relay_frame(bytes: &[u8]) -> Result<(), JsValue> {
        super::validate_relay_frame(bytes).map_err(js_error)
    }

    #[wasm_bindgen(js_name = w0RuntimeRequestRoundtrip)]
    pub fn runtime_request_roundtrip(bytes: &[u8]) -> Result<Vec<u8>, JsValue> {
        super::runtime_request_roundtrip(bytes).map_err(js_error)
    }

    #[wasm_bindgen(js_name = w0ContractSnapshot)]
    pub fn contract_snapshot() -> Result<String, JsValue> {
        let snapshot = super::w0_contract_snapshot().map_err(js_error)?;
        serde_json::to_string(&snapshot)
            .map_err(|_| js_error(super::WebCoreError::SerializationFailed))
    }

    #[wasm_bindgen(js_name = w0CryptoTamperIsRejected)]
    pub fn crypto_tamper_is_rejected() -> Result<bool, JsValue> {
        super::crypto_tamper_is_rejected().map_err(js_error)
    }

    #[wasm_bindgen(js_name = w0NegativeSnapshot)]
    pub fn negative_snapshot() -> Result<String, JsValue> {
        let snapshot = super::w0_negative_snapshot().map_err(js_error)?;
        serde_json::to_string(&snapshot)
            .map_err(|_| js_error(super::WebCoreError::SerializationFailed))
    }
}

#[cfg(all(target_arch = "wasm32", feature = "w2-test-fixture"))]
mod w2_negative_wasm {
    use wasm_bindgen::prelude::*;

    #[wasm_bindgen(js_name = w2NegativeSnapshot)]
    pub fn negative_snapshot() -> Result<String, JsValue> {
        serde_json::to_string(&super::w2_negative_snapshot())
            .map_err(|_| JsValue::from_str("web.remote.pairing.serialization_failed"))
    }
}

#[cfg(all(target_arch = "wasm32", feature = "w1-test-fixture"))]
mod w1_wasm {
    use wasm_bindgen::prelude::*;

    use super::{W1TransportCore, W1TransportFault};
    use agentdeck_protocol::relay_v2::RelayServerId;

    fn js_error(error: super::W1TransportError) -> JsValue {
        JsValue::from_str(error.code())
    }

    fn relay_server_id(bytes: &[u8]) -> Result<RelayServerId, JsValue> {
        let bytes: [u8; 16] = bytes
            .try_into()
            .map_err(|_| JsValue::from_str("web.remote.server_identity_invalid"))?;
        Ok(RelayServerId::from_bytes(bytes))
    }

    fn fault(value: &str) -> Result<W1TransportFault, JsValue> {
        match value {
            "none" => Ok(W1TransportFault::None),
            "tamperChallenge" => Ok(W1TransportFault::TamperChallenge),
            "tamperSignature" => Ok(W1TransportFault::TamperSignature),
            _ => Err(JsValue::from_str("web.remote.fault_invalid")),
        }
    }

    #[wasm_bindgen(js_name = W1Session)]
    pub struct W1Session {
        core: W1TransportCore,
    }

    #[wasm_bindgen(js_class = W1Session)]
    impl W1Session {
        #[wasm_bindgen(constructor)]
        pub fn new(origin: &str, expected_relay_server_id: &[u8]) -> Result<W1Session, JsValue> {
            let expected = relay_server_id(expected_relay_server_id)?;
            let core = W1TransportCore::new(origin, expected).map_err(js_error)?;
            Ok(Self { core })
        }

        #[wasm_bindgen(js_name = connectUrl)]
        pub fn connect_url(&self) -> String {
            self.core.connect_url().to_owned()
        }

        #[wasm_bindgen(js_name = start)]
        pub fn start(&mut self) -> Result<Vec<u8>, JsValue> {
            self.core.start().map_err(js_error)
        }

        #[wasm_bindgen(js_name = acceptChallenge)]
        pub fn accept_challenge(
            &mut self,
            bytes: &[u8],
            fault_name: &str,
        ) -> Result<Vec<u8>, JsValue> {
            self.core
                .accept_challenge(bytes, fault(fault_name)?)
                .map_err(js_error)
        }

        #[wasm_bindgen(js_name = acceptAuthenticated)]
        pub fn accept_authenticated(&mut self, bytes: &[u8]) -> Result<(), JsValue> {
            self.core.accept_authenticated(bytes).map_err(js_error)
        }

        #[wasm_bindgen(js_name = registerStream)]
        pub fn register_stream(&mut self) -> Result<Vec<u8>, JsValue> {
            self.core.register_stream().map_err(js_error)
        }

        #[wasm_bindgen(js_name = publishSentinel)]
        pub fn publish_sentinel(&mut self) -> Result<Vec<u8>, JsValue> {
            self.core.publish_sentinel().map_err(js_error)
        }

        #[wasm_bindgen(js_name = acceptActiveFrame)]
        pub fn accept_active_frame(&mut self, bytes: &[u8]) -> Result<Vec<u8>, JsValue> {
            self.core.accept_active_frame(bytes).map_err(js_error)
        }

        #[wasm_bindgen(js_name = sentinelAccepted)]
        pub fn sentinel_accepted(&self) -> bool {
            self.core.sentinel_accepted()
        }

        #[wasm_bindgen(js_name = oversizeFaultFrame)]
        pub fn oversize_fault_frame(&self) -> Vec<u8> {
            self.core.oversize_fault_frame()
        }
    }
}
