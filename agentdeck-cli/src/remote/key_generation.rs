//! Paired machine 的 durable key-generation 投影与 canonical codec。
//!
//! 本模块只持久化已经过 wire canonical decode 的 signed [`KeyUpdateV1`]，不验签、
//! 不解封，也不推进 barrier。`bootstrap_directory_revision` 是 immutable pairing anchor；
//! `effective_directory_revision` 是当前已接受的 control revision，两者不能混用。

use std::fmt;

use agentdeck_protocol::e2ee::{KeyId, KeyPurpose, KeyUpdateV1};
use agentdeck_protocol::relay_v2::{DeviceRouteId, KeyDirectoryRevision, StreamRouteId};
use thiserror::Error;

macro_rules! redacted_debug {
    ($type:ty, $label:literal) => {
        impl fmt::Debug for $type {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!($label, "([REDACTED])"))
            }
        }
    };
}

const KEY_GENERATION_STATE_MAGIC: &[u8; 4] = b"ADKG";
const KEY_GENERATION_STATE_VERSION: u16 = 1;
const KEY_GENERATION_STATE_HEADER_LEN: usize = 12;
const MAX_CANONICAL_KEY_UPDATE_BYTES: usize = 1_024;

/// 与 protocol key-directory 的 1,024 conversations + 三个 device-scoped slots 对齐。
pub const MAX_KEY_GENERATION_SLOTS: usize = 1_024 + 3;
/// 单 slot 的旧 epoch retention 仍受整个 8 MiB 状态上限二次约束。
pub const MAX_RETIRED_KEY_GENERATIONS_PER_SLOT: usize = 64;
/// V5 作为 ADPS 的单一 length-prefixed field，必须留在 paired state 的 8 MiB field cap 内。
pub const MAX_DURABLE_KEY_GENERATION_STATE_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Error, Clone, Copy, Eq, PartialEq)]
pub enum KeyGenerationStateError {
    #[error("durable key-generation state has an invalid canonical encoding")]
    InvalidCanonical,
    #[error("durable key-generation state exceeds its hard bound")]
    TooLarge,
    #[error("durable key-generation revision moved backwards")]
    RevisionRollback,
    #[error("durable key-generation epoch moved backwards")]
    EpochRollback,
    #[error("normal UpdateSet attempted to rotate a directed device key")]
    DirectedKeyRotation,
}

/// 一个 durable slot 的稳定身份；epoch/revision 属于 generation record，不属于 slot。
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct KeySlotIdentityV1 {
    purpose: KeyPurpose,
    stream_route: Option<StreamRouteId>,
}

redacted_debug!(KeySlotIdentityV1, "KeySlotIdentityV1");

impl KeySlotIdentityV1 {
    pub fn new(
        purpose: KeyPurpose,
        stream_route: Option<StreamRouteId>,
    ) -> Result<Self, KeyGenerationStateError> {
        let value = Self {
            purpose,
            stream_route,
        };
        value.validate()?;
        Ok(value)
    }

    #[must_use]
    pub const fn purpose(self) -> KeyPurpose {
        self.purpose
    }

    #[must_use]
    pub const fn stream_route(self) -> Option<StreamRouteId> {
        self.stream_route
    }

    fn validate(self) -> Result<(), KeyGenerationStateError> {
        let valid = match self.purpose {
            KeyPurpose::ConversationDek => self
                .stream_route
                .is_some_and(|route| !is_zero(route.as_bytes())),
            KeyPurpose::Catalog | KeyPurpose::DeviceCommandTx | KeyPurpose::DeviceReplyTx => {
                self.stream_route.is_none()
            }
        };
        if valid {
            Ok(())
        } else {
            Err(KeyGenerationStateError::InvalidCanonical)
        }
    }

    fn sort_key(self) -> (u8, [u8; 16]) {
        (
            key_purpose_tag(self.purpose),
            self.stream_route.map_or([0; 16], |route| *route.as_bytes()),
        )
    }
}

/// Generation 的来源。BootstrapEntry 由 paired audit 回查 immutable KeyDirectoryEntry；
/// Update 则保留可验签、可解封的 typed carrier。
#[derive(Clone, Eq, PartialEq)]
pub enum DurableKeyCarrierV1 {
    BootstrapEntry,
    Update(KeyUpdateV1),
}

redacted_debug!(DurableKeyCarrierV1, "DurableKeyCarrierV1");

/// 一代 key 的 durable metadata 与 exact carrier。
#[derive(Clone, Eq, PartialEq)]
pub struct DurableKeyGenerationV1 {
    key_directory_revision: KeyDirectoryRevision,
    key_id: KeyId,
    stream_route: Option<StreamRouteId>,
    device_route: DeviceRouteId,
    carrier: DurableKeyCarrierV1,
    canonical_key_update_bytes: Option<Vec<u8>>,
}

redacted_debug!(DurableKeyGenerationV1, "DurableKeyGenerationV1");

impl DurableKeyGenerationV1 {
    pub fn from_bootstrap_entry(
        key_directory_revision: KeyDirectoryRevision,
        key_id: KeyId,
        stream_route: Option<StreamRouteId>,
        device_route: DeviceRouteId,
    ) -> Result<Self, KeyGenerationStateError> {
        let value = Self {
            key_directory_revision,
            key_id,
            stream_route,
            device_route,
            carrier: DurableKeyCarrierV1::BootstrapEntry,
            canonical_key_update_bytes: None,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn from_update(update: KeyUpdateV1) -> Result<Self, KeyGenerationStateError> {
        let canonical = update
            .canonical_bytes()
            .map_err(|_| KeyGenerationStateError::InvalidCanonical)?;
        Self::from_canonical_key_update(
            update.key_directory_revision,
            update.key_id,
            update.stream_route,
            &canonical,
        )
    }

    pub fn from_canonical_key_update(
        key_directory_revision: KeyDirectoryRevision,
        key_id: KeyId,
        stream_route: Option<StreamRouteId>,
        canonical_key_update_bytes: &[u8],
    ) -> Result<Self, KeyGenerationStateError> {
        if canonical_key_update_bytes.len() > MAX_CANONICAL_KEY_UPDATE_BYTES {
            return Err(KeyGenerationStateError::TooLarge);
        }
        if canonical_key_update_bytes.is_empty() {
            return Err(KeyGenerationStateError::InvalidCanonical);
        }
        let key_update = KeyUpdateV1::from_canonical_bytes(canonical_key_update_bytes)
            .map_err(|_| KeyGenerationStateError::InvalidCanonical)?;
        let value = Self {
            key_directory_revision,
            key_id,
            stream_route,
            device_route: key_update.device_route,
            carrier: DurableKeyCarrierV1::Update(key_update),
            canonical_key_update_bytes: Some(canonical_key_update_bytes.to_vec()),
        };
        value.validate()?;
        Ok(value)
    }

    #[must_use]
    pub const fn key_directory_revision(&self) -> KeyDirectoryRevision {
        self.key_directory_revision
    }

    #[must_use]
    pub const fn key_id(&self) -> KeyId {
        self.key_id
    }

    #[must_use]
    pub const fn stream_route(&self) -> Option<StreamRouteId> {
        self.stream_route
    }

    #[must_use]
    pub const fn device_route(&self) -> DeviceRouteId {
        self.device_route
    }

    #[must_use]
    pub const fn carrier(&self) -> &DurableKeyCarrierV1 {
        &self.carrier
    }

    #[must_use]
    pub const fn is_bootstrap_entry(&self) -> bool {
        matches!(&self.carrier, DurableKeyCarrierV1::BootstrapEntry)
    }

    #[must_use]
    pub const fn canonical_key_update(&self) -> Option<&KeyUpdateV1> {
        match &self.carrier {
            DurableKeyCarrierV1::BootstrapEntry => None,
            DurableKeyCarrierV1::Update(update) => Some(update),
        }
    }

    #[must_use]
    pub fn canonical_key_update_bytes(&self) -> Option<&[u8]> {
        self.canonical_key_update_bytes.as_deref()
    }

    fn identity(&self) -> KeySlotIdentityV1 {
        KeySlotIdentityV1 {
            purpose: self.key_id.purpose,
            stream_route: self.stream_route,
        }
    }

    fn validate(&self) -> Result<(), KeyGenerationStateError> {
        self.identity().validate()?;
        if self.key_directory_revision.value() == 0
            || self.key_id.epoch == 0
            || is_zero(self.device_route.as_bytes())
        {
            return Err(KeyGenerationStateError::InvalidCanonical);
        }
        match (&self.carrier, &self.canonical_key_update_bytes) {
            (DurableKeyCarrierV1::BootstrapEntry, None) => Ok(()),
            (DurableKeyCarrierV1::Update(update), Some(canonical)) => {
                update
                    .validate()
                    .map_err(|_| KeyGenerationStateError::InvalidCanonical)?;
                if update.key_directory_revision != self.key_directory_revision
                    || update.key_id != self.key_id
                    || update.stream_route != self.stream_route
                    || update.device_route != self.device_route
                    || canonical.is_empty()
                    || canonical.len() > MAX_CANONICAL_KEY_UPDATE_BYTES
                    || update
                        .canonical_bytes()
                        .map_err(|_| KeyGenerationStateError::InvalidCanonical)?
                        != *canonical
                {
                    return Err(KeyGenerationStateError::InvalidCanonical);
                }
                Ok(())
            }
            _ => Err(KeyGenerationStateError::InvalidCanonical),
        }
    }
}

/// 一个 slot 的 active、可选 staged 与有界 retired generation 链。
#[derive(Clone, Eq, PartialEq)]
pub struct DurableKeySlotV1 {
    identity: KeySlotIdentityV1,
    current: DurableKeyGenerationV1,
    staged: Option<DurableKeyGenerationV1>,
    retired: Vec<DurableKeyGenerationV1>,
}

redacted_debug!(DurableKeySlotV1, "DurableKeySlotV1");

impl DurableKeySlotV1 {
    pub fn new(
        identity: KeySlotIdentityV1,
        current: DurableKeyGenerationV1,
        staged: Option<DurableKeyGenerationV1>,
        retired: Vec<DurableKeyGenerationV1>,
    ) -> Result<Self, KeyGenerationStateError> {
        let value = Self {
            identity,
            current,
            staged,
            retired,
        };
        value.validate()?;
        Ok(value)
    }

    #[must_use]
    pub const fn identity(&self) -> KeySlotIdentityV1 {
        self.identity
    }

    #[must_use]
    pub const fn current(&self) -> &DurableKeyGenerationV1 {
        &self.current
    }

    #[must_use]
    pub const fn staged(&self) -> Option<&DurableKeyGenerationV1> {
        self.staged.as_ref()
    }

    #[must_use]
    pub fn retired(&self) -> &[DurableKeyGenerationV1] {
        &self.retired
    }

    fn validate(&self) -> Result<(), KeyGenerationStateError> {
        self.identity.validate()?;
        self.current.validate()?;
        if self.retired.len() > MAX_RETIRED_KEY_GENERATIONS_PER_SLOT {
            return Err(KeyGenerationStateError::TooLarge);
        }
        if self.current.identity() != self.identity {
            return Err(KeyGenerationStateError::InvalidCanonical);
        }
        let mut previous: Option<&DurableKeyGenerationV1> = None;
        let mut bootstrap_count = usize::from(self.current.is_bootstrap_entry());
        for (index, generation) in self.retired.iter().enumerate() {
            generation.validate()?;
            if generation.identity() != self.identity {
                return Err(KeyGenerationStateError::InvalidCanonical);
            }
            if generation.is_bootstrap_entry() {
                bootstrap_count += 1;
                if index != 0 {
                    return Err(KeyGenerationStateError::InvalidCanonical);
                }
            }
            if let Some(previous) = previous {
                validate_generation_advance(previous, generation)?;
            }
            previous = Some(generation);
        }
        if let Some(previous) = previous {
            validate_generation_advance(previous, &self.current)?;
        }
        if let Some(staged) = &self.staged {
            staged.validate()?;
            if staged.identity() != self.identity || staged.is_bootstrap_entry() {
                return Err(KeyGenerationStateError::InvalidCanonical);
            }
            validate_generation_advance(&self.current, staged)?;
        }
        if bootstrap_count > 1 {
            return Err(KeyGenerationStateError::InvalidCanonical);
        }
        Ok(())
    }
}

/// V5 durable key-generation state。bootstrap revision 永不随 UpdateSet 推进。
#[derive(Clone, Eq, PartialEq)]
pub struct DurableKeyGenerationStateV1 {
    bootstrap_directory_revision: KeyDirectoryRevision,
    effective_directory_revision: KeyDirectoryRevision,
    slots: Vec<DurableKeySlotV1>,
}

redacted_debug!(DurableKeyGenerationStateV1, "DurableKeyGenerationStateV1");

impl DurableKeyGenerationStateV1 {
    pub fn new(
        bootstrap_directory_revision: KeyDirectoryRevision,
        effective_directory_revision: KeyDirectoryRevision,
        slots: Vec<DurableKeySlotV1>,
    ) -> Result<Self, KeyGenerationStateError> {
        let value = Self {
            bootstrap_directory_revision,
            effective_directory_revision,
            slots,
        };
        value.validate()?;
        Ok(value)
    }

    #[must_use]
    pub const fn bootstrap_directory_revision(&self) -> KeyDirectoryRevision {
        self.bootstrap_directory_revision
    }

    #[must_use]
    pub const fn effective_directory_revision(&self) -> KeyDirectoryRevision {
        self.effective_directory_revision
    }

    #[must_use]
    pub fn slots(&self) -> &[DurableKeySlotV1] {
        &self.slots
    }

    #[must_use]
    pub fn device_route(&self) -> DeviceRouteId {
        self.slots[0].current.device_route()
    }

    #[must_use]
    pub fn find_slot(
        &self,
        purpose: KeyPurpose,
        stream_route: Option<StreamRouteId>,
    ) -> Option<&DurableKeySlotV1> {
        let identity = KeySlotIdentityV1 {
            purpose,
            stream_route,
        };
        self.slots
            .binary_search_by(|slot| slot.identity.sort_key().cmp(&identity.sort_key()))
            .ok()
            .map(|index| &self.slots[index])
    }

    #[must_use]
    pub fn directed_current(&self, purpose: KeyPurpose) -> Option<&DurableKeyGenerationV1> {
        matches!(
            purpose,
            KeyPurpose::DeviceCommandTx | KeyPurpose::DeviceReplyTx
        )
        .then(|| self.find_slot(purpose, None))
        .flatten()
        .map(DurableKeySlotV1::current)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, KeyGenerationStateError> {
        self.validate()?;
        let mut body = Vec::new();
        body.extend_from_slice(&self.bootstrap_directory_revision.value().to_be_bytes());
        body.extend_from_slice(&self.effective_directory_revision.value().to_be_bytes());
        body.extend_from_slice(
            &u16::try_from(self.slots.len())
                .map_err(|_| KeyGenerationStateError::TooLarge)?
                .to_be_bytes(),
        );
        for slot in &self.slots {
            encode_identity(&mut body, slot.identity);
            encode_generation(&mut body, &slot.current)?;
            match &slot.staged {
                None => body.push(0),
                Some(staged) => {
                    body.push(1);
                    encode_generation(&mut body, staged)?;
                }
            }
            body.extend_from_slice(
                &u16::try_from(slot.retired.len())
                    .map_err(|_| KeyGenerationStateError::TooLarge)?
                    .to_be_bytes(),
            );
            for retired in &slot.retired {
                encode_generation(&mut body, retired)?;
            }
        }
        if body.len() > MAX_DURABLE_KEY_GENERATION_STATE_BYTES - KEY_GENERATION_STATE_HEADER_LEN {
            return Err(KeyGenerationStateError::TooLarge);
        }
        let mut encoded = Vec::with_capacity(KEY_GENERATION_STATE_HEADER_LEN + body.len());
        encoded.extend_from_slice(KEY_GENERATION_STATE_MAGIC);
        encoded.extend_from_slice(&KEY_GENERATION_STATE_VERSION.to_be_bytes());
        encoded.extend_from_slice(&[0, 0]);
        encoded.extend_from_slice(
            &u32::try_from(body.len())
                .map_err(|_| KeyGenerationStateError::TooLarge)?
                .to_be_bytes(),
        );
        encoded.extend_from_slice(&body);
        Ok(encoded)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, KeyGenerationStateError> {
        if bytes.len() > MAX_DURABLE_KEY_GENERATION_STATE_BYTES {
            return Err(KeyGenerationStateError::TooLarge);
        }
        if bytes.len() < KEY_GENERATION_STATE_HEADER_LEN
            || &bytes[..4] != KEY_GENERATION_STATE_MAGIC
            || u16::from_be_bytes([bytes[4], bytes[5]]) != KEY_GENERATION_STATE_VERSION
            || bytes[6..8] != [0, 0]
        {
            return Err(KeyGenerationStateError::InvalidCanonical);
        }
        let declared = u32::from_be_bytes(
            bytes[8..12]
                .try_into()
                .map_err(|_| KeyGenerationStateError::InvalidCanonical)?,
        ) as usize;
        if declared != bytes.len() - KEY_GENERATION_STATE_HEADER_LEN {
            return Err(KeyGenerationStateError::InvalidCanonical);
        }
        let mut decoder = Decoder::new(&bytes[KEY_GENERATION_STATE_HEADER_LEN..]);
        let bootstrap_directory_revision = KeyDirectoryRevision::new(decoder.u64()?);
        let effective_directory_revision = KeyDirectoryRevision::new(decoder.u64()?);
        let slot_count = usize::from(decoder.u16()?);
        if slot_count > MAX_KEY_GENERATION_SLOTS {
            return Err(KeyGenerationStateError::TooLarge);
        }
        if slot_count == 0 {
            return Err(KeyGenerationStateError::InvalidCanonical);
        }
        let mut slots = Vec::with_capacity(slot_count);
        for _ in 0..slot_count {
            let identity = decode_identity(&mut decoder)?;
            let current = decode_generation(&mut decoder)?;
            let staged = match decoder.u8()? {
                0 => None,
                1 => Some(decode_generation(&mut decoder)?),
                _ => return Err(KeyGenerationStateError::InvalidCanonical),
            };
            let retired_count = usize::from(decoder.u16()?);
            if retired_count > MAX_RETIRED_KEY_GENERATIONS_PER_SLOT {
                return Err(KeyGenerationStateError::TooLarge);
            }
            let mut retired = Vec::with_capacity(retired_count);
            for _ in 0..retired_count {
                retired.push(decode_generation(&mut decoder)?);
            }
            slots.push(DurableKeySlotV1::new(identity, current, staged, retired)?);
        }
        decoder.finish()?;
        let value = Self::new(
            bootstrap_directory_revision,
            effective_directory_revision,
            slots,
        )?;
        if value.canonical_bytes()? != bytes {
            return Err(KeyGenerationStateError::InvalidCanonical);
        }
        Ok(value)
    }

    fn validate(&self) -> Result<(), KeyGenerationStateError> {
        if self.slots.len() > MAX_KEY_GENERATION_SLOTS {
            return Err(KeyGenerationStateError::TooLarge);
        }
        if self.bootstrap_directory_revision.value() == 0
            || self.effective_directory_revision.value() == 0
            || self.slots.is_empty()
        {
            return Err(KeyGenerationStateError::InvalidCanonical);
        }
        if self.effective_directory_revision < self.bootstrap_directory_revision {
            return Err(KeyGenerationStateError::RevisionRollback);
        }
        let mut previous_identity = None;
        let mut expected_device = None;
        let mut catalog = 0_usize;
        let mut command = 0_usize;
        let mut reply = 0_usize;
        let mut highest_revision = KeyDirectoryRevision::ZERO;
        for slot in &self.slots {
            slot.validate()?;
            let identity = slot.identity.sort_key();
            if previous_identity.is_some_and(|previous| previous >= identity) {
                return Err(KeyGenerationStateError::InvalidCanonical);
            }
            previous_identity = Some(identity);
            match slot.identity.purpose {
                KeyPurpose::Catalog => catalog += 1,
                KeyPurpose::ConversationDek => {}
                KeyPurpose::DeviceCommandTx => command += 1,
                KeyPurpose::DeviceReplyTx => reply += 1,
            }
            if slot.staged.as_ref().is_some_and(|staged| {
                staged.key_directory_revision != self.effective_directory_revision
            }) {
                return Err(KeyGenerationStateError::InvalidCanonical);
            }
            for generation in slot
                .retired
                .iter()
                .chain(std::iter::once(&slot.current))
                .chain(slot.staged.iter())
            {
                let revision_valid = match &generation.carrier {
                    DurableKeyCarrierV1::BootstrapEntry => {
                        generation.key_directory_revision == self.bootstrap_directory_revision
                    }
                    DurableKeyCarrierV1::Update(_) => {
                        generation.key_directory_revision >= self.bootstrap_directory_revision
                            && generation.key_directory_revision
                                <= self.effective_directory_revision
                    }
                };
                if !revision_valid
                    || generation.key_directory_revision > self.effective_directory_revision
                {
                    return Err(KeyGenerationStateError::RevisionRollback);
                }
                highest_revision = highest_revision.max(generation.key_directory_revision);
                match expected_device {
                    None => expected_device = Some(generation.device_route()),
                    Some(device) if device != generation.device_route() => {
                        return Err(KeyGenerationStateError::InvalidCanonical);
                    }
                    Some(_) => {}
                }
            }
        }
        if catalog != 1
            || command != 1
            || reply != 1
            || highest_revision != self.effective_directory_revision
        {
            return Err(KeyGenerationStateError::InvalidCanonical);
        }
        Ok(())
    }
}

/// directed rewrap metadata 通过后的 `(previous, candidate)`；固定为 command、reply。
/// V5-B 必须另建 exact-roster/shared validator，不能把本 alias 当完整 UpdateSet。
pub type ValidatedDirectedRewrapMetadataV1<'a> =
    [(&'a DurableKeyGenerationV1, &'a DurableKeyGenerationV1); 2];

/// V5-A 只校验 normal UpdateSet 的 directed-key 不变量；shared roster exact 对账与
/// activation/recovery 留给 V5-B production installer。返回值迫使上层解封比较 raw key。
pub fn validate_directed_rewrap_metadata<'a>(
    previous: &'a DurableKeyGenerationStateV1,
    candidate: &'a DurableKeyGenerationStateV1,
) -> Result<ValidatedDirectedRewrapMetadataV1<'a>, KeyGenerationStateError> {
    previous.validate()?;
    candidate.validate()?;
    if previous == candidate {
        let unchanged = |purpose| {
            previous
                .find_slot(purpose, None)
                .map(|slot| (&slot.current, &slot.current))
                .ok_or(KeyGenerationStateError::InvalidCanonical)
        };
        return Ok([
            unchanged(KeyPurpose::DeviceCommandTx)?,
            unchanged(KeyPurpose::DeviceReplyTx)?,
        ]);
    }
    if previous.bootstrap_directory_revision != candidate.bootstrap_directory_revision
        || previous.device_route() != candidate.device_route()
        || candidate.effective_directory_revision <= previous.effective_directory_revision
    {
        return Err(KeyGenerationStateError::RevisionRollback);
    }
    let compare = |purpose| -> Result<_, KeyGenerationStateError> {
        let previous_slot = previous
            .find_slot(purpose, None)
            .ok_or(KeyGenerationStateError::InvalidCanonical)?;
        let candidate_slot = candidate
            .find_slot(purpose, None)
            .ok_or(KeyGenerationStateError::InvalidCanonical)?;
        if previous_slot.staged.is_some()
            || candidate_slot.staged.is_some()
            || previous_slot.current.key_id.epoch != candidate_slot.current.key_id.epoch
            || candidate_slot.current.key_directory_revision
                <= previous_slot.current.key_directory_revision
            || candidate_slot.current.key_directory_revision
                != candidate.effective_directory_revision
            || previous_slot.retired != candidate_slot.retired
        {
            return Err(KeyGenerationStateError::DirectedKeyRotation);
        }
        Ok((&previous_slot.current, &candidate_slot.current))
    };
    Ok([
        compare(KeyPurpose::DeviceCommandTx)?,
        compare(KeyPurpose::DeviceReplyTx)?,
    ])
}

fn validate_generation_advance(
    previous: &DurableKeyGenerationV1,
    candidate: &DurableKeyGenerationV1,
) -> Result<(), KeyGenerationStateError> {
    if candidate.key_directory_revision <= previous.key_directory_revision {
        return Err(KeyGenerationStateError::RevisionRollback);
    }
    if candidate.key_id.epoch <= previous.key_id.epoch {
        return Err(KeyGenerationStateError::EpochRollback);
    }
    Ok(())
}

fn encode_identity(output: &mut Vec<u8>, identity: KeySlotIdentityV1) {
    output.push(key_purpose_tag(identity.purpose));
    match identity.stream_route {
        None => output.push(0),
        Some(route) => {
            output.push(1);
            output.extend_from_slice(route.as_bytes());
        }
    }
}

fn decode_identity(
    decoder: &mut Decoder<'_>,
) -> Result<KeySlotIdentityV1, KeyGenerationStateError> {
    let purpose = decode_key_purpose(decoder.u8()?)?;
    let stream_route = match decoder.u8()? {
        0 => None,
        1 => Some(StreamRouteId::from_bytes(decoder.fixed()?)),
        _ => return Err(KeyGenerationStateError::InvalidCanonical),
    };
    KeySlotIdentityV1::new(purpose, stream_route)
}

fn encode_generation(
    output: &mut Vec<u8>,
    generation: &DurableKeyGenerationV1,
) -> Result<(), KeyGenerationStateError> {
    output.extend_from_slice(&generation.key_directory_revision.value().to_be_bytes());
    output.push(key_purpose_tag(generation.key_id.purpose));
    output.extend_from_slice(&generation.key_id.epoch.to_be_bytes());
    encode_optional_route(output, generation.stream_route);
    output.extend_from_slice(generation.device_route.as_bytes());
    match (&generation.carrier, &generation.canonical_key_update_bytes) {
        (DurableKeyCarrierV1::BootstrapEntry, None) => {
            output.push(0);
            Ok(())
        }
        (DurableKeyCarrierV1::Update(_), Some(canonical)) => {
            output.push(1);
            put_bytes(output, canonical)
        }
        _ => Err(KeyGenerationStateError::InvalidCanonical),
    }
}

fn decode_generation(
    decoder: &mut Decoder<'_>,
) -> Result<DurableKeyGenerationV1, KeyGenerationStateError> {
    let revision = KeyDirectoryRevision::new(decoder.u64()?);
    let key_id = KeyId {
        purpose: decode_key_purpose(decoder.u8()?)?,
        epoch: decoder.u64()?,
    };
    let stream_route = decode_optional_route(decoder)?;
    let device_route = DeviceRouteId::from_bytes(decoder.fixed()?);
    let value = match decoder.u8()? {
        0 => DurableKeyGenerationV1::from_bootstrap_entry(
            revision,
            key_id,
            stream_route,
            device_route,
        )?,
        1 => DurableKeyGenerationV1::from_canonical_key_update(
            revision,
            key_id,
            stream_route,
            decoder.bytes(MAX_CANONICAL_KEY_UPDATE_BYTES)?,
        )?,
        _ => return Err(KeyGenerationStateError::InvalidCanonical),
    };
    if value.device_route != device_route {
        return Err(KeyGenerationStateError::InvalidCanonical);
    }
    Ok(value)
}

fn encode_optional_route(output: &mut Vec<u8>, route: Option<StreamRouteId>) {
    match route {
        None => output.push(0),
        Some(route) => {
            output.push(1);
            output.extend_from_slice(route.as_bytes());
        }
    }
}

fn decode_optional_route(
    decoder: &mut Decoder<'_>,
) -> Result<Option<StreamRouteId>, KeyGenerationStateError> {
    match decoder.u8()? {
        0 => Ok(None),
        1 => Ok(Some(StreamRouteId::from_bytes(decoder.fixed()?))),
        _ => Err(KeyGenerationStateError::InvalidCanonical),
    }
}

fn key_purpose_tag(purpose: KeyPurpose) -> u8 {
    match purpose {
        KeyPurpose::Catalog => 0,
        KeyPurpose::ConversationDek => 1,
        KeyPurpose::DeviceCommandTx => 2,
        KeyPurpose::DeviceReplyTx => 3,
    }
}

fn decode_key_purpose(tag: u8) -> Result<KeyPurpose, KeyGenerationStateError> {
    match tag {
        0 => Ok(KeyPurpose::Catalog),
        1 => Ok(KeyPurpose::ConversationDek),
        2 => Ok(KeyPurpose::DeviceCommandTx),
        3 => Ok(KeyPurpose::DeviceReplyTx),
        _ => Err(KeyGenerationStateError::InvalidCanonical),
    }
}

fn put_bytes(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), KeyGenerationStateError> {
    if bytes.len() > MAX_CANONICAL_KEY_UPDATE_BYTES {
        return Err(KeyGenerationStateError::TooLarge);
    }
    if bytes.is_empty() {
        return Err(KeyGenerationStateError::InvalidCanonical);
    }
    output.extend_from_slice(
        &u32::try_from(bytes.len())
            .map_err(|_| KeyGenerationStateError::TooLarge)?
            .to_be_bytes(),
    );
    output.extend_from_slice(bytes);
    Ok(())
}

fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

struct Decoder<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> Decoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], KeyGenerationStateError> {
        let end = self
            .cursor
            .checked_add(length)
            .ok_or(KeyGenerationStateError::InvalidCanonical)?;
        let value = self
            .bytes
            .get(self.cursor..end)
            .ok_or(KeyGenerationStateError::InvalidCanonical)?;
        self.cursor = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, KeyGenerationStateError> {
        self.take(1)?
            .first()
            .copied()
            .ok_or(KeyGenerationStateError::InvalidCanonical)
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], KeyGenerationStateError> {
        self.take(N)?
            .try_into()
            .map_err(|_| KeyGenerationStateError::InvalidCanonical)
    }

    fn u16(&mut self) -> Result<u16, KeyGenerationStateError> {
        Ok(u16::from_be_bytes(self.fixed()?))
    }

    fn u32(&mut self) -> Result<u32, KeyGenerationStateError> {
        Ok(u32::from_be_bytes(self.fixed()?))
    }

    fn u64(&mut self) -> Result<u64, KeyGenerationStateError> {
        Ok(u64::from_be_bytes(self.fixed()?))
    }

    fn bytes(&mut self, maximum: usize) -> Result<&'a [u8], KeyGenerationStateError> {
        let length =
            usize::try_from(self.u32()?).map_err(|_| KeyGenerationStateError::InvalidCanonical)?;
        if length == 0 {
            return Err(KeyGenerationStateError::InvalidCanonical);
        }
        if length > maximum {
            return Err(KeyGenerationStateError::TooLarge);
        }
        self.take(length)
    }

    fn finish(self) -> Result<(), KeyGenerationStateError> {
        if self.cursor == self.bytes.len() {
            Ok(())
        } else {
            Err(KeyGenerationStateError::InvalidCanonical)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentdeck_protocol::relay_v2::auth::Ed25519Signature;

    fn update(
        purpose: KeyPurpose,
        stream_route: Option<StreamRouteId>,
        revision: u64,
        epoch: u64,
        seed: u8,
    ) -> KeyUpdateV1 {
        KeyUpdateV1 {
            key_directory_revision: KeyDirectoryRevision::new(revision),
            key_id: KeyId { purpose, epoch },
            device_route: DeviceRouteId::from_bytes([9; 16]),
            stream_route,
            enc: vec![seed; 32],
            wrapped_key: vec![seed.wrapping_add(1); 48],
            signature: Ed25519Signature([seed.wrapping_add(2); 64]),
        }
    }

    fn generation(
        purpose: KeyPurpose,
        stream_route: Option<StreamRouteId>,
        revision: u64,
        epoch: u64,
        seed: u8,
    ) -> DurableKeyGenerationV1 {
        DurableKeyGenerationV1::from_update(update(purpose, stream_route, revision, epoch, seed))
            .expect("valid generation")
    }

    fn slot(purpose: KeyPurpose, revision: u64, epoch: u64, seed: u8) -> DurableKeySlotV1 {
        DurableKeySlotV1::new(
            KeySlotIdentityV1::new(purpose, None).expect("valid identity"),
            generation(purpose, None, revision, epoch, seed),
            None,
            Vec::new(),
        )
        .expect("valid slot")
    }

    fn bootstrap_slot(purpose: KeyPurpose, revision: u64, epoch: u64) -> DurableKeySlotV1 {
        DurableKeySlotV1::new(
            KeySlotIdentityV1::new(purpose, None).expect("valid identity"),
            DurableKeyGenerationV1::from_bootstrap_entry(
                KeyDirectoryRevision::new(revision),
                KeyId { purpose, epoch },
                None,
                DeviceRouteId::from_bytes([9; 16]),
            )
            .expect("bootstrap generation"),
            None,
            Vec::new(),
        )
        .expect("bootstrap slot")
    }

    fn state(revision: u64, command_epoch: u64) -> DurableKeyGenerationStateV1 {
        DurableKeyGenerationStateV1::new(
            KeyDirectoryRevision::new(1),
            KeyDirectoryRevision::new(revision),
            vec![
                slot(KeyPurpose::Catalog, revision, revision, 11),
                slot(KeyPurpose::DeviceCommandTx, revision, command_epoch, 21),
                slot(KeyPurpose::DeviceReplyTx, revision, 1, 31),
            ],
        )
        .expect("valid state")
    }

    #[test]
    fn canonical_roundtrip_preserves_typed_updates_and_redacts_debug() {
        let route = StreamRouteId::from_bytes([7; 16]);
        let conversation = DurableKeySlotV1::new(
            KeySlotIdentityV1::new(KeyPurpose::ConversationDek, Some(route))
                .expect("conversation identity"),
            generation(KeyPurpose::ConversationDek, Some(route), 2, 2, 41),
            Some(generation(
                KeyPurpose::ConversationDek,
                Some(route),
                3,
                3,
                42,
            )),
            vec![generation(
                KeyPurpose::ConversationDek,
                Some(route),
                1,
                1,
                40,
            )],
        )
        .expect("generation chain");
        let value = DurableKeyGenerationStateV1::new(
            KeyDirectoryRevision::new(1),
            KeyDirectoryRevision::new(3),
            vec![
                slot(KeyPurpose::Catalog, 3, 3, 11),
                conversation,
                slot(KeyPurpose::DeviceCommandTx, 3, 1, 21),
                slot(KeyPurpose::DeviceReplyTx, 3, 1, 31),
            ],
        )
        .expect("valid state");

        let canonical = value.canonical_bytes().expect("canonical bytes");
        let decoded = DurableKeyGenerationStateV1::from_canonical_bytes(&canonical)
            .expect("strict roundtrip");
        assert_eq!(decoded, value);
        assert_eq!(decoded.bootstrap_directory_revision().value(), 1);
        assert_eq!(decoded.effective_directory_revision().value(), 3);
        let staged = decoded
            .find_slot(KeyPurpose::ConversationDek, Some(route))
            .and_then(DurableKeySlotV1::staged)
            .expect("staged generation");
        let typed = staged
            .canonical_key_update()
            .expect("staged carrier is an update");
        assert_eq!(typed.key_id.epoch, 3);
        assert_eq!(
            staged
                .canonical_key_update_bytes()
                .expect("exact update bytes"),
            typed.canonical_bytes().expect("canonical update")
        );
        let debug = format!("{decoded:?} {staged:?}");
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("wrapped_key"));
        assert!(!debug.contains("41, 41"));
    }

    #[test]
    fn rejects_unsorted_duplicate_and_record_metadata_mismatch() {
        let mut slots = state(1, 1).slots().to_vec();
        slots.swap(0, 1);
        assert_eq!(
            DurableKeyGenerationStateV1::new(
                KeyDirectoryRevision::new(1),
                KeyDirectoryRevision::new(1),
                slots,
            )
            .unwrap_err(),
            KeyGenerationStateError::InvalidCanonical
        );

        let duplicate = vec![
            slot(KeyPurpose::Catalog, 1, 1, 11),
            slot(KeyPurpose::Catalog, 1, 1, 12),
            slot(KeyPurpose::DeviceCommandTx, 1, 1, 21),
            slot(KeyPurpose::DeviceReplyTx, 1, 1, 31),
        ];
        assert_eq!(
            DurableKeyGenerationStateV1::new(
                KeyDirectoryRevision::new(1),
                KeyDirectoryRevision::new(1),
                duplicate,
            )
            .unwrap_err(),
            KeyGenerationStateError::InvalidCanonical
        );

        let canonical = update(KeyPurpose::Catalog, None, 1, 1, 51)
            .canonical_bytes()
            .expect("canonical update");
        assert_eq!(
            DurableKeyGenerationV1::from_canonical_key_update(
                KeyDirectoryRevision::new(2),
                KeyId {
                    purpose: KeyPurpose::Catalog,
                    epoch: 1,
                },
                None,
                &canonical,
            )
            .unwrap_err(),
            KeyGenerationStateError::InvalidCanonical
        );
    }

    #[test]
    fn rejects_revision_and_epoch_rollback_in_generation_chain() {
        let identity = KeySlotIdentityV1::new(KeyPurpose::Catalog, None).expect("identity");
        assert_eq!(
            DurableKeySlotV1::new(
                identity,
                generation(KeyPurpose::Catalog, None, 2, 2, 12),
                None,
                vec![generation(KeyPurpose::Catalog, None, 3, 1, 11)],
            )
            .unwrap_err(),
            KeyGenerationStateError::RevisionRollback
        );
        assert_eq!(
            DurableKeySlotV1::new(
                identity,
                generation(KeyPurpose::Catalog, None, 2, 1, 12),
                None,
                vec![generation(KeyPurpose::Catalog, None, 1, 2, 11)],
            )
            .unwrap_err(),
            KeyGenerationStateError::EpochRollback
        );
        assert_eq!(
            DurableKeyGenerationStateV1::new(
                KeyDirectoryRevision::new(2),
                KeyDirectoryRevision::new(1),
                state(1, 1).slots().to_vec(),
            )
            .unwrap_err(),
            KeyGenerationStateError::RevisionRollback
        );
    }

    #[test]
    fn directed_rewrap_metadata_returns_raw_comparison_without_roster_claim() {
        let previous = state(1, 1);
        let candidate = state(2, 1);
        let checked = validate_directed_rewrap_metadata(&previous, &candidate)
            .expect("same directed epochs are metadata-valid");
        assert_eq!(checked.len(), 2);
        assert_eq!(checked[0].0.key_id().purpose, KeyPurpose::DeviceCommandTx);
        assert_ne!(
            checked[0].0.canonical_key_update_bytes(),
            checked[0].1.canonical_key_update_bytes(),
            "metadata validation deliberately leaves opened raw-key equality to the caller"
        );

        assert_eq!(
            validate_directed_rewrap_metadata(&previous, &state(2, 2)).unwrap_err(),
            KeyGenerationStateError::DirectedKeyRotation
        );

        let mut slots = state(2, 1).slots().to_vec();
        let command = slots.remove(1);
        slots.insert(
            1,
            DurableKeySlotV1::new(
                command.identity(),
                command.current().clone(),
                Some(generation(KeyPurpose::DeviceCommandTx, None, 3, 2, 22)),
                Vec::new(),
            )
            .expect("structurally valid recovery-shaped directed staging"),
        );
        let staged = DurableKeyGenerationStateV1::new(
            KeyDirectoryRevision::new(1),
            KeyDirectoryRevision::new(3),
            slots,
        )
        .expect("codec reserves recovery shape");
        assert_eq!(
            validate_directed_rewrap_metadata(&previous, &staged).unwrap_err(),
            KeyGenerationStateError::DirectedKeyRotation
        );
    }

    #[test]
    fn strict_decoder_rejects_trailing_and_oversize_bytes() {
        let canonical = state(1, 1).canonical_bytes().expect("canonical state");
        let mut trailing = canonical.clone();
        trailing.push(0);
        assert_eq!(
            DurableKeyGenerationStateV1::from_canonical_bytes(&trailing).unwrap_err(),
            KeyGenerationStateError::InvalidCanonical
        );
        assert_eq!(
            DurableKeyGenerationStateV1::from_canonical_bytes(&vec![
                0;
                MAX_DURABLE_KEY_GENERATION_STATE_BYTES
                    + 1
            ])
            .unwrap_err(),
            KeyGenerationStateError::TooLarge
        );
    }

    #[test]
    fn bootstrap_current_can_stage_first_v5_update_and_roundtrip() {
        let catalog = DurableKeySlotV1::new(
            KeySlotIdentityV1::new(KeyPurpose::Catalog, None).expect("catalog identity"),
            bootstrap_slot(KeyPurpose::Catalog, 4, 1).current().clone(),
            Some(generation(KeyPurpose::Catalog, None, 5, 2, 61)),
            Vec::new(),
        )
        .expect("bootstrap current with staged update");
        let value = DurableKeyGenerationStateV1::new(
            KeyDirectoryRevision::new(4),
            KeyDirectoryRevision::new(5),
            vec![
                catalog,
                bootstrap_slot(KeyPurpose::DeviceCommandTx, 4, 1),
                bootstrap_slot(KeyPurpose::DeviceReplyTx, 4, 1),
            ],
        )
        .expect("first V5 state");

        let decoded = DurableKeyGenerationStateV1::from_canonical_bytes(
            &value.canonical_bytes().expect("canonical first V5 state"),
        )
        .expect("bootstrap carrier roundtrip");
        let catalog = decoded
            .find_slot(KeyPurpose::Catalog, None)
            .expect("catalog slot");
        assert!(matches!(
            catalog.current().carrier(),
            DurableKeyCarrierV1::BootstrapEntry
        ));
        assert!(matches!(
            catalog.staged().expect("staged update").carrier(),
            DurableKeyCarrierV1::Update(_)
        ));
    }

    #[test]
    fn directed_rewrap_allows_exact_preserve_and_same_epoch_rewrap() {
        let previous = DurableKeyGenerationStateV1::new(
            KeyDirectoryRevision::new(4),
            KeyDirectoryRevision::new(4),
            vec![
                bootstrap_slot(KeyPurpose::Catalog, 4, 1),
                bootstrap_slot(KeyPurpose::DeviceCommandTx, 4, 1),
                bootstrap_slot(KeyPurpose::DeviceReplyTx, 4, 1),
            ],
        )
        .expect("bootstrap state");
        assert!(validate_directed_rewrap_metadata(&previous, &previous).is_ok());

        let rewrapped_slot = |purpose, seed| {
            DurableKeySlotV1::new(
                KeySlotIdentityV1::new(purpose, None).expect("directed identity"),
                generation(purpose, None, 5, 1, seed),
                None,
                Vec::new(),
            )
            .expect("same-epoch directed current rewrap")
        };
        let candidate = DurableKeyGenerationStateV1::new(
            KeyDirectoryRevision::new(4),
            KeyDirectoryRevision::new(5),
            vec![
                DurableKeySlotV1::new(
                    KeySlotIdentityV1::new(KeyPurpose::Catalog, None).expect("catalog identity"),
                    bootstrap_slot(KeyPurpose::Catalog, 4, 1).current().clone(),
                    Some(generation(KeyPurpose::Catalog, None, 5, 2, 71)),
                    Vec::new(),
                )
                .expect("catalog stage"),
                rewrapped_slot(KeyPurpose::DeviceCommandTx, 72),
                rewrapped_slot(KeyPurpose::DeviceReplyTx, 73),
            ],
        )
        .expect("normal staged candidate");
        let comparisons = validate_directed_rewrap_metadata(&previous, &candidate)
            .expect("metadata admits upper-layer raw-key equality audit");
        assert!(matches!(
            comparisons[0].1.carrier(),
            DurableKeyCarrierV1::Update(_)
        ));
        assert_eq!(comparisons[0].1.key_id().epoch, 1);
    }

    #[test]
    fn bootstrap_entry_may_be_only_the_first_retired_generation() {
        let bootstrap = bootstrap_slot(KeyPurpose::Catalog, 4, 1).current().clone();
        let catalog = DurableKeySlotV1::new(
            KeySlotIdentityV1::new(KeyPurpose::Catalog, None).expect("catalog identity"),
            generation(KeyPurpose::Catalog, None, 5, 2, 81),
            None,
            vec![bootstrap],
        )
        .expect("bootstrap retained at chain head");
        let value = DurableKeyGenerationStateV1::new(
            KeyDirectoryRevision::new(4),
            KeyDirectoryRevision::new(5),
            vec![
                catalog,
                bootstrap_slot(KeyPurpose::DeviceCommandTx, 4, 1),
                bootstrap_slot(KeyPurpose::DeviceReplyTx, 4, 1),
            ],
        )
        .expect("post-barrier state");
        let decoded = DurableKeyGenerationStateV1::from_canonical_bytes(
            &value.canonical_bytes().expect("canonical state"),
        )
        .expect("retired bootstrap roundtrip");
        assert!(matches!(
            decoded
                .find_slot(KeyPurpose::Catalog, None)
                .expect("catalog slot")
                .retired()[0]
                .carrier(),
            DurableKeyCarrierV1::BootstrapEntry
        ));

        let staged_bootstrap = DurableKeyGenerationV1::from_bootstrap_entry(
            KeyDirectoryRevision::new(6),
            KeyId {
                purpose: KeyPurpose::Catalog,
                epoch: 3,
            },
            None,
            DeviceRouteId::from_bytes([9; 16]),
        )
        .expect("shape-valid bootstrap carrier");
        assert_eq!(
            DurableKeySlotV1::new(
                KeySlotIdentityV1::new(KeyPurpose::Catalog, None).expect("identity"),
                generation(KeyPurpose::Catalog, None, 5, 2, 82),
                Some(staged_bootstrap),
                Vec::new(),
            )
            .unwrap_err(),
            KeyGenerationStateError::InvalidCanonical
        );

        let misplaced_bootstrap = bootstrap_slot(KeyPurpose::Catalog, 4, 2).current().clone();
        assert_eq!(
            DurableKeySlotV1::new(
                KeySlotIdentityV1::new(KeyPurpose::Catalog, None).expect("identity"),
                generation(KeyPurpose::Catalog, None, 5, 3, 84),
                None,
                vec![
                    generation(KeyPurpose::Catalog, None, 3, 1, 83),
                    misplaced_bootstrap,
                ],
            )
            .unwrap_err(),
            KeyGenerationStateError::InvalidCanonical
        );
    }
}
