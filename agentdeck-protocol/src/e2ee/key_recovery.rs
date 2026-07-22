//! DeviceReplyTx counter rollback 的独立 DeviceHPKE recovery reply 契约。
//!
//! 该 envelope 不经过 `DeviceReplyTx` AEAD，因此 replacement reply key 可以安全地放在
//! 完整 [`KeyUpdateSetV1`] plaintext 中。clear info、HPKE info、AAD 与外层
//! MachineDataSign TBS 共同绑定 request route、授权/信任轴和 exact next revision。

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::e2ee::context::{OuterContextV1, OuterFrameKind};
use crate::e2ee::key_control::KeyUpdateSetV1;
use crate::e2ee::pairing::{MachineDataSignerBindingV1, PairingError};
use crate::e2ee::{E2EE_FORMAT_VERSION, Enc, b64_32, b64_vec};
use crate::relay_v2::RELAY_PROTOCOL_VERSION;
use crate::relay_v2::auth::Ed25519Signature;
use crate::relay_v2::id::{
    DeviceRouteId, GrantSerial, KeyDirectoryRevision, LinkGeneration, MachineRouteId,
    RelayServerId, RequestRouteId, TrustEpoch,
};
use crate::runtime::RUNTIME_PROTOCOL_VERSION;

/// X25519 encapsulated public key 的固定长度。
pub const DEVICE_KEY_RECOVERY_HPKE_ENC_BYTES: usize = 32;
/// `KeyUpdateSetV1` canonical 上限 1 MiB，加 HPKE ChaCha20-Poly1305 16-byte tag。
pub const DEVICE_KEY_RECOVERY_MAX_CIPHERTEXT_BYTES: usize = 1_024 * 1_024 + 16;

const DEVICE_KEY_RECOVERY_INFO_MAX_CANONICAL_BYTES: usize = 1_024;
const DEVICE_KEY_RECOVERY_TBS_MAX_CANONICAL_BYTES: usize = 2 * 1_024;
const DEVICE_KEY_RECOVERY_REPLY_MAX_CANONICAL_BYTES: usize = 2 * 1_024 * 1_024;

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

/// HPKE clear `info` 与 recovery authority。完整结构也进入外层签名 TBS。
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeviceKeyRecoveryInfoV1 {
    pub e2ee_format_version: u16,
    pub runtime_protocol_version: u16,
    pub relay_protocol_version: u16,
    pub relay_server_id: RelayServerId,
    pub machine_route: MachineRouteId,
    pub device_route: DeviceRouteId,
    pub request_route: RequestRouteId,
    pub grant_serial: GrantSerial,
    pub root_trust_epoch: TrustEpoch,
    pub known_key_directory_revision: KeyDirectoryRevision,
    pub target_key_directory_revision: KeyDirectoryRevision,
    #[serde(with = "b64_32")]
    #[schemars(with = "String")]
    pub update_set_sha256: [u8; 32],
    /// 已由 MachineRoot certificate 固定的当前 MachineDataSign 身份。
    pub machine_data_signer: MachineDataSignerBindingV1,
}

impl std::fmt::Debug for DeviceKeyRecoveryInfoV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DeviceKeyRecoveryInfoV1")
            .field("versions", &"<redacted>")
            .field("authority_and_hash", &"<redacted>")
            .finish()
    }
}

impl DeviceKeyRecoveryInfoV1 {
    pub fn validate(&self) -> Result<(), PairingError> {
        let expected_target = self
            .known_key_directory_revision
            .next()
            .map_err(|_| PairingError::InvalidField("key recovery revision exhausted"))?;
        if self.e2ee_format_version != E2EE_FORMAT_VERSION
            || self.runtime_protocol_version != RUNTIME_PROTOCOL_VERSION
            || self.relay_protocol_version != RELAY_PROTOCOL_VERSION
            || is_zero(self.relay_server_id.as_bytes())
            || is_zero(self.machine_route.as_bytes())
            || is_zero(self.device_route.as_bytes())
            || is_zero(self.request_route.as_bytes())
            || self.grant_serial.value() == 0
            || self.root_trust_epoch.value() == 0
            || self.target_key_directory_revision.value() == 0
            || self.target_key_directory_revision != expected_target
            || is_zero(&self.update_set_sha256)
        {
            return Err(PairingError::InvalidField("device key recovery info"));
        }
        self.machine_data_signer.validate()
    }

    /// 校验密文 plaintext 是 exact target revision、device 与 frozen set hash。
    pub fn validate_for_update_set(&self, set: &KeyUpdateSetV1) -> Result<(), PairingError> {
        self.validate()?;
        set.validate()?;
        if set.device_route != self.device_route
            || set.key_directory_revision != self.target_key_directory_revision
            || set.canonical_sha256()? != self.update_set_sha256
        {
            return Err(PairingError::ContextBindingMismatch);
        }
        Ok(())
    }

    /// Recovery AAD 必须是唯一 request-bound carrier，且不携带任何对称 key epoch/counter 轴。
    pub fn validate_context(&self, context: &OuterContextV1) -> Result<(), PairingError> {
        self.validate()?;
        context
            .validate()
            .map_err(|_| PairingError::ContextBindingMismatch)?;
        if context.frame_kind != OuterFrameKind::DeviceKeyRecovery
            || context.relay_protocol_version != self.relay_protocol_version
            || context.e2ee_format_version != self.e2ee_format_version
            || context.machine_route != Some(self.machine_route)
            || context.device_route != Some(self.device_route)
            || context.request_route != Some(self.request_route)
            || context.stream_route.is_some()
            || context.pair_route.is_some()
            || context.stream_generation.is_some()
            || context.stream_cursor.is_some()
            || context.stream_seq.is_some()
            || context.message_key_epoch != 0
        {
            return Err(PairingError::ContextBindingMismatch);
        }
        Ok(())
    }

    /// HPKE `info` 的 canonical bytes。
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, PairingError> {
        self.validate()?;
        let mut encoder = Enc::new();
        encoder.domain(b"AgentDeck/DeviceKeyRecoveryInfoV1\0");
        encode_info_fields(&mut encoder, self);
        Ok(encoder.finish())
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, PairingError> {
        if bytes.len() > DEVICE_KEY_RECOVERY_INFO_MAX_CANONICAL_BYTES {
            return Err(PairingError::SizeLimit("device key recovery info"));
        }
        let mut decoder = RecoveryDecoder::new(bytes);
        decoder.domain(b"AgentDeck/DeviceKeyRecoveryInfoV1\0")?;
        let value = decoder.info_fields()?;
        decoder.finish()?;
        value.validate()?;
        if value.canonical_bytes()?.as_slice() != bytes {
            return Err(PairingError::InvalidEncoding(
                "non-canonical device key recovery info",
            ));
        }
        Ok(value)
    }
}

/// MachineDataSign 的 canonical TBS；显式重复 clear info 的全部安全轴，并加入 HPKE/AAD digest。
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeviceKeyRecoveryTbsV1 {
    pub e2ee_format_version: u16,
    pub runtime_protocol_version: u16,
    pub relay_protocol_version: u16,
    pub relay_server_id: RelayServerId,
    pub machine_route: MachineRouteId,
    pub device_route: DeviceRouteId,
    pub request_route: RequestRouteId,
    pub grant_serial: GrantSerial,
    pub root_trust_epoch: TrustEpoch,
    pub known_key_directory_revision: KeyDirectoryRevision,
    pub target_key_directory_revision: KeyDirectoryRevision,
    #[serde(with = "b64_32")]
    #[schemars(with = "String")]
    pub update_set_sha256: [u8; 32],
    pub machine_data_signer: MachineDataSignerBindingV1,
    #[serde(with = "b64_32")]
    #[schemars(with = "String")]
    pub info_sha256: [u8; 32],
    #[serde(with = "b64_vec")]
    #[schemars(with = "String")]
    pub enc: Vec<u8>,
    #[serde(with = "b64_32")]
    #[schemars(with = "String")]
    pub ciphertext_sha256: [u8; 32],
    #[serde(with = "b64_32")]
    #[schemars(with = "String")]
    pub outer_context_aad_sha256: [u8; 32],
}

impl std::fmt::Debug for DeviceKeyRecoveryTbsV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("DeviceKeyRecoveryTbsV1([REDACTED])")
    }
}

impl DeviceKeyRecoveryTbsV1 {
    fn info(&self) -> DeviceKeyRecoveryInfoV1 {
        DeviceKeyRecoveryInfoV1 {
            e2ee_format_version: self.e2ee_format_version,
            runtime_protocol_version: self.runtime_protocol_version,
            relay_protocol_version: self.relay_protocol_version,
            relay_server_id: self.relay_server_id,
            machine_route: self.machine_route,
            device_route: self.device_route,
            request_route: self.request_route,
            grant_serial: self.grant_serial,
            root_trust_epoch: self.root_trust_epoch,
            known_key_directory_revision: self.known_key_directory_revision,
            target_key_directory_revision: self.target_key_directory_revision,
            update_set_sha256: self.update_set_sha256,
            machine_data_signer: self.machine_data_signer.clone(),
        }
    }

    pub fn validate(&self) -> Result<(), PairingError> {
        let info = self.info();
        info.validate()?;
        if self.info_sha256 != sha256(&info.canonical_bytes()?)
            || self.enc.len() != DEVICE_KEY_RECOVERY_HPKE_ENC_BYTES
            || is_zero(&self.enc)
            || is_zero(&self.ciphertext_sha256)
            || is_zero(&self.outer_context_aad_sha256)
        {
            return Err(PairingError::InvalidField("device key recovery TBS"));
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, PairingError> {
        self.validate()?;
        let mut encoder = Enc::new();
        encoder.domain(b"AgentDeck/DeviceKeyRecoveryTbsV1\0");
        encode_info_fields(&mut encoder, &self.info());
        encoder.bytes(&self.info_sha256);
        encoder.bytes(&self.enc);
        encoder.bytes(&self.ciphertext_sha256);
        encoder.bytes(&self.outer_context_aad_sha256);
        Ok(encoder.finish())
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, PairingError> {
        if bytes.len() > DEVICE_KEY_RECOVERY_TBS_MAX_CANONICAL_BYTES {
            return Err(PairingError::SizeLimit("device key recovery TBS"));
        }
        let mut decoder = RecoveryDecoder::new(bytes);
        decoder.domain(b"AgentDeck/DeviceKeyRecoveryTbsV1\0")?;
        let info = decoder.info_fields()?;
        let value = Self {
            e2ee_format_version: info.e2ee_format_version,
            runtime_protocol_version: info.runtime_protocol_version,
            relay_protocol_version: info.relay_protocol_version,
            relay_server_id: info.relay_server_id,
            machine_route: info.machine_route,
            device_route: info.device_route,
            request_route: info.request_route,
            grant_serial: info.grant_serial,
            root_trust_epoch: info.root_trust_epoch,
            known_key_directory_revision: info.known_key_directory_revision,
            target_key_directory_revision: info.target_key_directory_revision,
            update_set_sha256: info.update_set_sha256,
            machine_data_signer: info.machine_data_signer,
            info_sha256: decoder.fixed_bytes()?,
            enc: decoder.bytes(DEVICE_KEY_RECOVERY_HPKE_ENC_BYTES)?.to_vec(),
            ciphertext_sha256: decoder.fixed_bytes()?,
            outer_context_aad_sha256: decoder.fixed_bytes()?,
        };
        decoder.finish()?;
        value.validate()?;
        if value.canonical_bytes()?.as_slice() != bytes {
            return Err(PairingError::InvalidEncoding(
                "non-canonical device key recovery TBS",
            ));
        }
        Ok(value)
    }
}

/// Relay opaque Reply 中的独立 recovery envelope；外层必须由当前 MachineDataSign 签名。
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeviceKeyRecoveryReplyV1 {
    pub format_version: u16,
    pub info: DeviceKeyRecoveryInfoV1,
    #[serde(with = "b64_vec")]
    #[schemars(with = "String")]
    pub enc: Vec<u8>,
    #[serde(with = "b64_vec")]
    #[schemars(with = "String")]
    pub ciphertext: Vec<u8>,
    pub machine_data_signature: Ed25519Signature,
}

impl std::fmt::Debug for DeviceKeyRecoveryReplyV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("DeviceKeyRecoveryReplyV1([REDACTED])")
    }
}

impl DeviceKeyRecoveryReplyV1 {
    fn validate_shape(&self, require_signature: bool) -> Result<(), PairingError> {
        self.info.validate()?;
        if self.format_version != E2EE_FORMAT_VERSION
            || self.format_version != self.info.e2ee_format_version
            || self.enc.len() != DEVICE_KEY_RECOVERY_HPKE_ENC_BYTES
            || is_zero(&self.enc)
            || self.ciphertext.len() < 16
            || self.ciphertext.len() > DEVICE_KEY_RECOVERY_MAX_CIPHERTEXT_BYTES
            || is_zero(&self.ciphertext)
            || (require_signature && is_zero(&self.machine_data_signature.0))
            || (!require_signature && !is_zero(&self.machine_data_signature.0))
        {
            return Err(PairingError::InvalidField("device key recovery reply"));
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), PairingError> {
        self.validate_shape(true)
    }

    pub fn ensure_info_matches(
        &self,
        expected: &DeviceKeyRecoveryInfoV1,
    ) -> Result<(), PairingError> {
        expected.validate()?;
        if &self.info != expected {
            return Err(PairingError::ContextBindingMismatch);
        }
        Ok(())
    }

    pub fn signature_tbs(
        &self,
        context: &OuterContextV1,
        signer: &MachineDataSignerBindingV1,
    ) -> Result<DeviceKeyRecoveryTbsV1, PairingError> {
        let signed = !is_zero(&self.machine_data_signature.0);
        self.validate_shape(signed)?;
        self.info.validate_context(context)?;
        signer.validate()?;
        if signer != &self.info.machine_data_signer {
            return Err(PairingError::ContextBindingMismatch);
        }
        let info_bytes = self.info.canonical_bytes()?;
        let tbs = DeviceKeyRecoveryTbsV1 {
            e2ee_format_version: self.info.e2ee_format_version,
            runtime_protocol_version: self.info.runtime_protocol_version,
            relay_protocol_version: self.info.relay_protocol_version,
            relay_server_id: self.info.relay_server_id,
            machine_route: self.info.machine_route,
            device_route: self.info.device_route,
            request_route: self.info.request_route,
            grant_serial: self.info.grant_serial,
            root_trust_epoch: self.info.root_trust_epoch,
            known_key_directory_revision: self.info.known_key_directory_revision,
            target_key_directory_revision: self.info.target_key_directory_revision,
            update_set_sha256: self.info.update_set_sha256,
            machine_data_signer: signer.clone(),
            info_sha256: sha256(&info_bytes),
            enc: self.enc.clone(),
            ciphertext_sha256: sha256(&self.ciphertext),
            outer_context_aad_sha256: sha256(&context.encode_aad()),
        };
        tbs.validate()?;
        Ok(tbs)
    }

    pub fn unsigned_canonical_bytes(&self) -> Result<Vec<u8>, PairingError> {
        let signed = !is_zero(&self.machine_data_signature.0);
        self.validate_shape(signed)?;
        let mut encoder = Enc::new();
        encoder.domain(b"AgentDeck/DeviceKeyRecoveryReplyUnsignedV1\0");
        encoder.u16(self.format_version);
        encoder.bytes(&self.info.canonical_bytes()?);
        encoder.bytes(&self.enc);
        encoder.bytes(&self.ciphertext);
        Ok(encoder.finish())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, PairingError> {
        self.validate()?;
        let mut encoder = Enc::new();
        encoder.domain(b"AgentDeck/DeviceKeyRecoveryReplyV1\0");
        encoder.bytes(&self.unsigned_canonical_bytes()?);
        encoder.bytes(&self.machine_data_signature.0);
        let bytes = encoder.finish();
        if bytes.len() > DEVICE_KEY_RECOVERY_REPLY_MAX_CANONICAL_BYTES {
            return Err(PairingError::SizeLimit("device key recovery reply"));
        }
        Ok(bytes)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, PairingError> {
        if bytes.len() > DEVICE_KEY_RECOVERY_REPLY_MAX_CANONICAL_BYTES {
            return Err(PairingError::SizeLimit("device key recovery reply"));
        }
        let mut outer = RecoveryDecoder::new(bytes);
        outer.domain(b"AgentDeck/DeviceKeyRecoveryReplyV1\0")?;
        let unsigned = outer.bytes(DEVICE_KEY_RECOVERY_REPLY_MAX_CANONICAL_BYTES)?;
        let signature = Ed25519Signature(outer.fixed_bytes()?);
        outer.finish()?;

        let mut decoder = RecoveryDecoder::new(unsigned);
        decoder.domain(b"AgentDeck/DeviceKeyRecoveryReplyUnsignedV1\0")?;
        let value = Self {
            format_version: decoder.u16()?,
            info: DeviceKeyRecoveryInfoV1::from_canonical_bytes(
                decoder.bytes(DEVICE_KEY_RECOVERY_INFO_MAX_CANONICAL_BYTES)?,
            )?,
            enc: decoder.bytes(DEVICE_KEY_RECOVERY_HPKE_ENC_BYTES)?.to_vec(),
            ciphertext: decoder
                .bytes(DEVICE_KEY_RECOVERY_MAX_CIPHERTEXT_BYTES)?
                .to_vec(),
            machine_data_signature: signature,
        };
        decoder.finish()?;
        value.validate()?;
        if value.canonical_bytes()?.as_slice() != bytes {
            return Err(PairingError::InvalidEncoding(
                "non-canonical device key recovery reply",
            ));
        }
        Ok(value)
    }
}

fn encode_info_fields(encoder: &mut Enc, info: &DeviceKeyRecoveryInfoV1) {
    encoder.u16(info.e2ee_format_version);
    encoder.u16(info.runtime_protocol_version);
    encoder.u16(info.relay_protocol_version);
    encoder.bytes(info.relay_server_id.as_bytes());
    encoder.bytes(info.machine_route.as_bytes());
    encoder.bytes(info.device_route.as_bytes());
    encoder.bytes(info.request_route.as_bytes());
    encoder.u64(info.grant_serial.value());
    encoder.u64(info.root_trust_epoch.value());
    encoder.u64(info.known_key_directory_revision.value());
    encoder.u64(info.target_key_directory_revision.value());
    encoder.bytes(&info.update_set_sha256);
    encoder.bytes(&info.machine_data_signer.signing_key_fingerprint);
    encoder.u64(info.machine_data_signer.generation.value());
    encoder.bytes(&info.machine_data_signer.certificate_sha256);
}

struct RecoveryDecoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> RecoveryDecoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], PairingError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(PairingError::InvalidEncoding(
                "device key recovery offset overflow",
            ))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(PairingError::InvalidEncoding(
                "truncated device key recovery value",
            ))?;
        self.offset = end;
        Ok(value)
    }

    fn domain(&mut self, expected: &[u8]) -> Result<(), PairingError> {
        if self.take(expected.len())? != expected {
            return Err(PairingError::InvalidEncoding(
                "device key recovery domain separator",
            ));
        }
        Ok(())
    }

    fn u16(&mut self) -> Result<u16, PairingError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().map_err(
            |_| PairingError::InvalidEncoding("device key recovery u16"),
        )?))
    }

    fn u64(&mut self) -> Result<u64, PairingError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().map_err(
            |_| PairingError::InvalidEncoding("device key recovery u64"),
        )?))
    }

    fn bytes(&mut self, maximum: usize) -> Result<&'a [u8], PairingError> {
        let length = u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| PairingError::InvalidEncoding("device key recovery length prefix"))?,
        ) as usize;
        if length > maximum {
            return Err(PairingError::SizeLimit("device key recovery field"));
        }
        self.take(length)
    }

    fn fixed_bytes<const N: usize>(&mut self) -> Result<[u8; N], PairingError> {
        self.bytes(N)?
            .try_into()
            .map_err(|_| PairingError::InvalidEncoding("device key recovery fixed field"))
    }

    fn info_fields(&mut self) -> Result<DeviceKeyRecoveryInfoV1, PairingError> {
        Ok(DeviceKeyRecoveryInfoV1 {
            e2ee_format_version: self.u16()?,
            runtime_protocol_version: self.u16()?,
            relay_protocol_version: self.u16()?,
            relay_server_id: RelayServerId::from_bytes(self.fixed_bytes()?),
            machine_route: MachineRouteId::from_bytes(self.fixed_bytes()?),
            device_route: DeviceRouteId::from_bytes(self.fixed_bytes()?),
            request_route: RequestRouteId::from_bytes(self.fixed_bytes()?),
            grant_serial: GrantSerial::new(self.u64()?),
            root_trust_epoch: TrustEpoch::new(self.u64()?),
            known_key_directory_revision: KeyDirectoryRevision::new(self.u64()?),
            target_key_directory_revision: KeyDirectoryRevision::new(self.u64()?),
            update_set_sha256: self.fixed_bytes()?,
            machine_data_signer: MachineDataSignerBindingV1 {
                signing_key_fingerprint: self.fixed_bytes()?,
                generation: LinkGeneration::new(self.u64()?),
                certificate_sha256: self.fixed_bytes()?,
            },
        })
    }

    fn finish(&self) -> Result<(), PairingError> {
        if self.offset != self.bytes.len() {
            return Err(PairingError::InvalidEncoding(
                "trailing device key recovery bytes",
            ));
        }
        Ok(())
    }
}
