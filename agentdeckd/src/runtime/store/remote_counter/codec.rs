//! Counter state 的 canonical codec、anchor 与 row-AEAD 辅助实现。

use agentdeck_protocol::e2ee::{KeyId, KeyPurpose};
use zeroize::Zeroizing;

use crate::runtime::model::RuntimeStoreError;
use crate::security::SecretBytes;

use super::super::cipher::{CipherError, RowAad, RuntimeKeyBundle};
use super::super::schema::{RUNTIME_CRYPTO_CONTEXT_VERSION, RUNTIME_SCHEMA_FAMILY};
use super::{
    ActiveSenderCounterBinding, CounterRecoveryDisposition, CounterRecoveryStageOutcome,
    CounterRecoveryStageRequest, CounterRecoveryStageTarget, CounterState, RemoteCounterRecord,
    RemoteCounterRecordKind, RemoteCounterRecoveryBinding,
};

const COUNTER_TABLE: &[u8] = b"remote_counter_states";
const COUNTER_COLUMN: &[u8] = b"sealed_state";
const COUNTER_ANCHOR_DOMAIN: &[u8] = b"runtime.remote.counter.db-anchor.v1";
const COUNTER_GENESIS_DOMAIN: &[u8] = b"runtime.remote.counter.genesis.v1";
const COUNTER_MAGIC: &[u8; 4] = b"ADCG";
const COUNTER_VERSION: u8 = 1;
const GAP_TAG: u8 = 1;
const FROZEN_TAG: u8 = 2;
const RETIRED_TAG: u8 = 3;
const RECOVERY_STAGED_TAG: u8 = 4;
const RECOVERED_TAG: u8 = 5;
const COUNTER_RECOVERY_ENTROPY_ATTEMPTS: usize = 16;
const MAX_COUNTER_PLAINTEXT_BYTES: usize = 512;

impl CounterState {
    pub(super) fn encode(&self) -> Result<Zeroizing<Vec<u8>>, RuntimeStoreError> {
        self.validate()?;
        let mut encoded = Zeroizing::new(Vec::with_capacity(MAX_COUNTER_PLAINTEXT_BYTES));
        encoded.extend_from_slice(COUNTER_MAGIC);
        encoded.push(COUNTER_VERSION);
        encoded.push(match self.record.kind {
            RemoteCounterRecordKind::Gap => GAP_TAG,
            RemoteCounterRecordKind::Frozen => FROZEN_TAG,
            RemoteCounterRecordKind::Retired => RETIRED_TAG,
            RemoteCounterRecordKind::RecoveryStaged => RECOVERY_STAGED_TAG,
            RemoteCounterRecordKind::Recovered => RECOVERED_TAG,
            RemoteCounterRecordKind::Genesis => {
                return Err(RuntimeStoreError::InvalidStateTransition);
            }
        });
        encoded.extend_from_slice(&self.record.scope_token);
        encoded.push(purpose_tag(self.record.key_id.purpose));
        encoded.extend_from_slice(&self.record.key_id.epoch.to_be_bytes());
        encoded.extend_from_slice(&self.record.reserved_end.to_be_bytes());
        encoded.extend_from_slice(&self.record.reservation_id.unwrap_or([0; 16]));
        encoded.extend_from_slice(&self.record.publication_id.unwrap_or([0; 16]));
        encoded.extend_from_slice(&self.previous_db_anchor);
        encoded.extend_from_slice(&self.record.db_anchor);
        match self.record.kind {
            RemoteCounterRecordKind::Frozen => {
                encoded.extend_from_slice(
                    &self
                        .publication_stream_id
                        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?,
                );
                encoded.extend_from_slice(
                    &self
                        .generation
                        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?,
                );
                encoded.extend_from_slice(
                    &self
                        .stream_seq
                        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?
                        .to_be_bytes(),
                );
                encoded.extend_from_slice(
                    &self
                        .sender_counter
                        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?
                        .to_be_bytes(),
                );
                encoded.extend_from_slice(
                    &self
                        .blob_sha256
                        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?,
                );
            }
            RemoteCounterRecordKind::RecoveryStaged | RemoteCounterRecordKind::Recovered => {
                let recovery = self
                    .recovery
                    .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
                encoded.extend_from_slice(&recovery.operation_id);
                encoded.extend_from_slice(&recovery.replacement_scope_token);
                encoded.push(purpose_tag(recovery.replacement_key_id.purpose));
                encoded.extend_from_slice(&recovery.replacement_key_id.epoch.to_be_bytes());
                encoded.extend_from_slice(&recovery.from_revision.to_be_bytes());
                encoded.extend_from_slice(&recovery.to_revision.to_be_bytes());
            }
            RemoteCounterRecordKind::Gap | RemoteCounterRecordKind::Retired => {}
            RemoteCounterRecordKind::Genesis => unreachable!(),
        }
        if encoded.len() > MAX_COUNTER_PLAINTEXT_BYTES {
            return Err(RuntimeStoreError::PayloadTooLarge);
        }
        Ok(encoded)
    }

    pub(super) fn decode(bytes: &[u8]) -> Result<Self, RuntimeStoreError> {
        let mut decoder = Decoder::new(bytes);
        if decoder.take(4)? != COUNTER_MAGIC || decoder.u8()? != COUNTER_VERSION {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        let kind = match decoder.u8()? {
            GAP_TAG => RemoteCounterRecordKind::Gap,
            FROZEN_TAG => RemoteCounterRecordKind::Frozen,
            RETIRED_TAG => RemoteCounterRecordKind::Retired,
            RECOVERY_STAGED_TAG => RemoteCounterRecordKind::RecoveryStaged,
            RECOVERED_TAG => RemoteCounterRecordKind::Recovered,
            _ => return Err(RuntimeStoreError::UnknownOrCorruptSchema),
        };
        let scope_token = decoder.fixed()?;
        let purpose = purpose_from_tag(decoder.u8()?)?;
        let key_epoch = decoder.u64()?;
        let reserved_end = decoder.u64()?;
        let encoded_reservation_id: [u8; 16] = decoder.fixed()?;
        let encoded_publication_id: [u8; 16] = decoder.fixed()?;
        let previous_db_anchor = decoder.fixed()?;
        let db_anchor = decoder.fixed()?;
        let (publication_stream_id, generation, stream_seq, sender_counter, blob_sha256) =
            if kind == RemoteCounterRecordKind::Frozen {
                (
                    Some(decoder.fixed()?),
                    Some(decoder.fixed()?),
                    Some(decoder.u64()?),
                    Some(decoder.u64()?),
                    Some(decoder.fixed()?),
                )
            } else {
                (None, None, None, None, None)
            };
        let recovery = if matches!(
            kind,
            RemoteCounterRecordKind::RecoveryStaged | RemoteCounterRecordKind::Recovered
        ) {
            Some((
                decoder.fixed()?,
                decoder.fixed()?,
                purpose_from_tag(decoder.u8()?)?,
                decoder.u64()?,
                decoder.u64()?,
                decoder.u64()?,
            ))
        } else {
            None
        };
        if !decoder.finished() {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        let state = Self {
            record: RemoteCounterRecord {
                scope_token,
                key_id: KeyId {
                    purpose,
                    epoch: key_epoch,
                },
                reserved_end,
                reservation_id: (encoded_reservation_id != [0; 16])
                    .then_some(encoded_reservation_id),
                publication_id: (encoded_publication_id != [0; 16])
                    .then_some(encoded_publication_id),
                db_anchor,
                kind,
            },
            previous_db_anchor,
            publication_stream_id,
            generation,
            stream_seq,
            sender_counter,
            blob_sha256,
            recovery: recovery.map(
                |(
                    operation_id,
                    replacement_scope_token,
                    replacement_purpose,
                    replacement_epoch,
                    from_revision,
                    to_revision,
                )| RemoteCounterRecoveryBinding {
                    operation_id,
                    retired_scope_token: scope_token,
                    retired_key_id: KeyId {
                        purpose,
                        epoch: key_epoch,
                    },
                    replacement_scope_token,
                    replacement_key_id: KeyId {
                        purpose: replacement_purpose,
                        epoch: replacement_epoch,
                    },
                    from_revision,
                    to_revision,
                },
            ),
        };
        state.validate()?;
        if state.encode()?.as_slice() != bytes {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        Ok(state)
    }

    fn validate(&self) -> Result<(), RuntimeStoreError> {
        validate_identity(self.record.scope_token, self.record.key_id)?;
        validate_nonzero(self.previous_db_anchor)?;
        validate_nonzero(self.record.db_anchor)?;
        match self.record.kind {
            RemoteCounterRecordKind::Frozen => {
                validate_counter_operation_ids(&self.record)?;
                if self.record.reserved_end == 0 {
                    return Err(RuntimeStoreError::UnknownOrCorruptSchema);
                }
                validate_nonzero(
                    self.publication_stream_id
                        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?,
                )?;
                validate_nonzero(
                    self.generation
                        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?,
                )?;
                validate_nonzero(
                    self.blob_sha256
                        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?,
                )?;
                let counter = self
                    .sender_counter
                    .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
                if counter >= self.record.reserved_end || self.stream_seq.is_none() {
                    return Err(RuntimeStoreError::UnknownOrCorruptSchema);
                }
                if self.recovery.is_some() {
                    return Err(RuntimeStoreError::UnknownOrCorruptSchema);
                }
            }
            RemoteCounterRecordKind::Gap => {
                validate_counter_operation_ids(&self.record)?;
                if self.record.reserved_end == 0
                    || self.publication_stream_id.is_some()
                    || self.generation.is_some()
                    || self.stream_seq.is_some()
                    || self.sender_counter.is_some()
                    || self.blob_sha256.is_some()
                    || self.recovery.is_some()
                {
                    return Err(RuntimeStoreError::UnknownOrCorruptSchema);
                }
            }
            RemoteCounterRecordKind::Retired => {
                if self.record.reservation_id.is_some() != self.record.publication_id.is_some() {
                    return Err(RuntimeStoreError::UnknownOrCorruptSchema);
                }
                if let Some(reservation_id) = self.record.reservation_id {
                    validate_nonzero(reservation_id)?;
                }
                if let Some(publication_id) = self.record.publication_id {
                    validate_nonzero(publication_id)?;
                }
                if self.publication_stream_id.is_some()
                    || self.generation.is_some()
                    || self.stream_seq.is_some()
                    || self.sender_counter.is_some()
                    || self.blob_sha256.is_some()
                    || self.recovery.is_some()
                {
                    return Err(RuntimeStoreError::UnknownOrCorruptSchema);
                }
            }
            RemoteCounterRecordKind::RecoveryStaged | RemoteCounterRecordKind::Recovered => {
                if self.record.reservation_id.is_some() != self.record.publication_id.is_some()
                    || self.publication_stream_id.is_some()
                    || self.generation.is_some()
                    || self.stream_seq.is_some()
                    || self.sender_counter.is_some()
                    || self.blob_sha256.is_some()
                {
                    return Err(RuntimeStoreError::UnknownOrCorruptSchema);
                }
                let recovery = self
                    .recovery
                    .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
                validate_nonzero(recovery.operation_id)?;
                validate_nonzero(recovery.replacement_scope_token)?;
                if recovery.retired_scope_token != self.record.scope_token
                    || recovery.retired_key_id != self.record.key_id
                    || recovery.replacement_scope_token == self.record.scope_token
                    || recovery.replacement_key_id.purpose != self.record.key_id.purpose
                    || recovery.replacement_key_id.epoch
                        != self
                            .record
                            .key_id
                            .epoch
                            .checked_add(1)
                            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?
                    || recovery.from_revision == 0
                    || recovery.to_revision != recovery.from_revision.checked_add(1).unwrap_or(0)
                {
                    return Err(RuntimeStoreError::UnknownOrCorruptSchema);
                }
            }
            RemoteCounterRecordKind::Genesis => {
                return Err(RuntimeStoreError::UnknownOrCorruptSchema);
            }
        }
        Ok(())
    }
}

fn validate_counter_operation_ids(record: &RemoteCounterRecord) -> Result<(), RuntimeStoreError> {
    validate_nonzero(
        record
            .reservation_id
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?,
    )?;
    validate_nonzero(
        record
            .publication_id
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?,
    )
}

pub(super) fn derive_anchor(
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    state: &CounterState,
) -> Result<[u8; 32], RuntimeStoreError> {
    let mut canonical = state.encode()?;
    // current anchor 自身不进入 preimage，避免循环；codec 中该字段位置固定。
    let anchor_offset = 4 + 1 + 1 + 32 + 1 + 8 + 8 + 16 + 16 + 32;
    canonical
        .get_mut(anchor_offset..anchor_offset + 32)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?
        .fill(0);
    let mut message = Vec::with_capacity(16 + canonical.len());
    message.extend_from_slice(&database_id);
    message.extend_from_slice(canonical.as_ref());
    Ok(*key_bundle
        .blind_index(COUNTER_ANCHOR_DOMAIN, &message)?
        .as_bytes())
}

pub(super) fn genesis_anchor(
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    scope_token: [u8; 32],
    key_id: KeyId,
) -> Result<[u8; 32], RuntimeStoreError> {
    let mut message = Vec::with_capacity(16 + 32 + 1 + 8);
    message.extend_from_slice(&database_id);
    message.extend_from_slice(&scope_token);
    message.push(purpose_tag(key_id.purpose));
    message.extend_from_slice(&key_id.epoch.to_be_bytes());
    Ok(*key_bundle
        .blind_index(COUNTER_GENESIS_DOMAIN, &message)?
        .as_bytes())
}

pub(super) fn seal_state(
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    scope_token: [u8; 32],
    plaintext: &[u8],
) -> Result<Vec<u8>, RuntimeStoreError> {
    Ok(key_bundle.row_cipher().seal_bounded(
        &RowAad {
            schema_family: RUNTIME_SCHEMA_FAMILY.as_bytes(),
            schema_version: RUNTIME_CRYPTO_CONTEXT_VERSION,
            database_id: &database_id,
            table: COUNTER_TABLE,
            primary_key: &scope_token,
            column: COUNTER_COLUMN,
        },
        plaintext,
        MAX_COUNTER_PLAINTEXT_BYTES,
    )?)
}

pub(super) fn open_state(
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    scope_token: [u8; 32],
    ciphertext: &[u8],
) -> Result<crate::security::SecretBytes, RuntimeStoreError> {
    Ok(key_bundle.row_cipher().open_bounded(
        &RowAad {
            schema_family: RUNTIME_SCHEMA_FAMILY.as_bytes(),
            schema_version: RUNTIME_CRYPTO_CONTEXT_VERSION,
            database_id: &database_id,
            table: COUNTER_TABLE,
            primary_key: &scope_token,
            column: COUNTER_COLUMN,
        },
        ciphertext,
        MAX_COUNTER_PLAINTEXT_BYTES,
    )?)
}

pub(super) fn validate_identity(
    scope_token: [u8; 32],
    key_id: KeyId,
) -> Result<(), RuntimeStoreError> {
    validate_nonzero(scope_token)?;
    if key_id.epoch == 0 {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    Ok(())
}

pub(super) fn validate_recovery_stage_request(
    request: &CounterRecoveryStageRequest,
) -> Result<(), RuntimeStoreError> {
    validate_nonzero(request.operation_id)?;
    validate_identity(request.retired_scope_token, request.retired_key_id)?;
    validate_nonzero(request.replacement_scope_token)?;
    if request.replacement_scope_token == request.retired_scope_token
        || request.retired_key_id.epoch == u64::MAX
        || matches!(request.retired_key_id.purpose, KeyPurpose::DeviceCommandTx)
    {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    match &request.target {
        CounterRecoveryStageTarget::SharedPublication {
            publication_stream_id,
        } => {
            validate_nonzero(*publication_stream_id)?;
            if !matches!(
                request.retired_key_id.purpose,
                KeyPurpose::Catalog | KeyPurpose::ConversationDek
            ) {
                return Err(RuntimeStoreError::PublicationMismatch);
            }
        }
        CounterRecoveryStageTarget::DirectedReply { authorization } => {
            if request.retired_key_id.purpose != KeyPurpose::DeviceReplyTx
                || authorization.reply_key_epoch() != request.retired_key_id.epoch
            {
                return Err(RuntimeStoreError::PublicationMismatch);
            }
        }
    }
    Ok(())
}

pub(super) fn request_uniquely_matches_active_binding(
    request: &CounterRecoveryStageRequest,
    active: &[ActiveSenderCounterBinding],
) -> bool {
    active
        .iter()
        .filter(|binding| match (binding, &request.target) {
            (
                ActiveSenderCounterBinding::SharedPublication {
                    publication_stream_id,
                    key_id,
                },
                CounterRecoveryStageTarget::SharedPublication {
                    publication_stream_id: expected_stream,
                },
            ) => *publication_stream_id == *expected_stream && *key_id == request.retired_key_id,
            (
                ActiveSenderCounterBinding::DirectedReply { authorization },
                CounterRecoveryStageTarget::DirectedReply {
                    authorization: expected,
                },
            ) => {
                authorization == expected
                    && request.retired_key_id
                        == (KeyId {
                            purpose: KeyPurpose::DeviceReplyTx,
                            epoch: authorization.reply_key_epoch(),
                        })
            }
            _ => false,
        })
        .take(2)
        .count()
        == 1
}

pub(super) fn recovery_request_matches_binding(
    request: &CounterRecoveryStageRequest,
    binding: RemoteCounterRecoveryBinding,
) -> bool {
    binding.operation_id == request.operation_id
        && binding.retired_scope_token == request.retired_scope_token
        && binding.retired_key_id == request.retired_key_id
        && binding.replacement_scope_token == request.replacement_scope_token
        && binding.replacement_key_id.purpose == request.retired_key_id.purpose
        && binding.replacement_key_id.epoch
            == request.retired_key_id.epoch.checked_add(1).unwrap_or(0)
}

pub(super) const fn trust_reset_required() -> CounterRecoveryStageOutcome {
    CounterRecoveryStageOutcome {
        disposition: CounterRecoveryDisposition::TrustResetRequired,
        binding: None,
    }
}

pub(super) fn fresh_counter_recovery_key() -> Result<SecretBytes, RuntimeStoreError> {
    for _ in 0..COUNTER_RECOVERY_ENTROPY_ATTEMPTS {
        let mut key = Zeroizing::new([0_u8; 32]);
        getrandom::fill(key.as_mut()).map_err(|_| CipherError::EntropyUnavailable)?;
        if key.iter().any(|byte| *byte != 0) {
            return Ok(SecretBytes::new(key.as_slice().to_vec()));
        }
    }
    Err(CipherError::EntropyUnavailable.into())
}

pub(super) fn validate_nonzero<const N: usize>(bytes: [u8; N]) -> Result<(), RuntimeStoreError> {
    if bytes == [0; N] {
        Err(RuntimeStoreError::PublicationMismatch)
    } else {
        Ok(())
    }
}

const fn purpose_tag(purpose: KeyPurpose) -> u8 {
    match purpose {
        KeyPurpose::Catalog => 1,
        KeyPurpose::ConversationDek => 2,
        KeyPurpose::DeviceCommandTx => 3,
        KeyPurpose::DeviceReplyTx => 4,
    }
}

fn purpose_from_tag(tag: u8) -> Result<KeyPurpose, RuntimeStoreError> {
    match tag {
        1 => Ok(KeyPurpose::Catalog),
        2 => Ok(KeyPurpose::ConversationDek),
        3 => Ok(KeyPurpose::DeviceCommandTx),
        4 => Ok(KeyPurpose::DeviceReplyTx),
        _ => Err(RuntimeStoreError::UnknownOrCorruptSchema),
    }
}

pub(super) const fn purpose_text(purpose: KeyPurpose) -> &'static str {
    match purpose {
        KeyPurpose::Catalog => "catalog",
        KeyPurpose::ConversationDek => "conversationDek",
        KeyPurpose::DeviceCommandTx => "deviceCommandTx",
        KeyPurpose::DeviceReplyTx => "deviceReplyTx",
    }
}

pub(super) fn parse_purpose(value: &str) -> Result<KeyPurpose, RuntimeStoreError> {
    match value {
        "catalog" => Ok(KeyPurpose::Catalog),
        "conversationDek" => Ok(KeyPurpose::ConversationDek),
        "deviceCommandTx" => Ok(KeyPurpose::DeviceCommandTx),
        "deviceReplyTx" => Ok(KeyPurpose::DeviceReplyTx),
        _ => Err(RuntimeStoreError::UnknownOrCorruptSchema),
    }
}

pub(super) const fn lifecycle_text(kind: RemoteCounterRecordKind) -> &'static str {
    match kind {
        RemoteCounterRecordKind::Gap | RemoteCounterRecordKind::Frozen => "active",
        RemoteCounterRecordKind::Retired
        | RemoteCounterRecordKind::RecoveryStaged
        | RemoteCounterRecordKind::Recovered => "retired",
        RemoteCounterRecordKind::Genesis => "active",
    }
}

pub(super) fn canonical_sequence(value: &str, allow_zero: bool) -> Result<u64, RuntimeStoreError> {
    if value.len() != super::super::sequence::SEQUENCE_TEXT_WIDTH
        || !value.as_bytes().iter().all(u8::is_ascii_digit)
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let decoded = value
        .parse::<u64>()
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    if (!allow_zero && decoded == 0) || super::super::sequence::encode_sequence(decoded) != value {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(decoded)
}

pub(super) fn fixed<const N: usize>(value: Vec<u8>) -> Result<[u8; N], RuntimeStoreError> {
    value
        .try_into()
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)
}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], RuntimeStoreError> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        self.offset = end;
        Ok(value)
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], RuntimeStoreError> {
        self.take(N)?
            .try_into()
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)
    }

    fn u8(&mut self) -> Result<u8, RuntimeStoreError> {
        Ok(self.take(1)?[0])
    }

    fn u64(&mut self) -> Result<u64, RuntimeStoreError> {
        Ok(u64::from_be_bytes(self.fixed()?))
    }

    fn finished(&self) -> bool {
        self.offset == self.bytes.len()
    }
}
