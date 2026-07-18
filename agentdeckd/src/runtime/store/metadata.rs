//! Runtime v5 conversation metadata mutation ledger。
//!
//! managed conversation 的 rename/archive 在单一 SQLite transaction 内直接写入
//! terminal `applied` 行，并同步推进 authenticated entry/catalog revision。native
//! mutation 的 durable state shape 与迁移矩阵也在这里统一认证；vendor 副作用接线
//! 属于后续 projector task。

use std::collections::BTreeMap;

use agentdeck_protocol::runtime::{
    CatalogChange, CatalogDelta, ConversationMetadataMutation, RuntimeFailure,
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::runtime::events::CommandStreamEffects;
use crate::runtime::model::{
    ConversationLifecycle, IdempotencyOwner, MAX_CONVERSATION_DESCRIPTOR_BYTES,
    MAX_IDEMPOTENCY_KEY_BYTES, MetadataMutationLimitScope, RuntimeCommitOperation,
    RuntimeStoreConfig, RuntimeStoreError, RuntimeStoreOperation,
};

use super::cipher::{ROW_BLOB_V1_OVERHEAD_LEN, RowAad, RuntimeKeyBundle};
use super::identity::{RuntimeId, RuntimeIdKind};
use super::schema::{
    MAX_ACTIVE_METADATA_MUTATIONS, MAX_METADATA_MUTATION_CHARGED_BYTES_GLOBAL,
    MAX_METADATA_MUTATION_OUTCOME_BYTES, MAX_METADATA_MUTATION_REQUEST_BYTES,
    MAX_METADATA_MUTATIONS_GLOBAL, MAX_METADATA_MUTATIONS_PER_CONVERSATION,
    RUNTIME_CRYPTO_CONTEXT_VERSION, RUNTIME_SCHEMA_FAMILY,
};
use super::sequence::{SequenceScope, decode_sequence, encode_sequence, next_sequence};
use super::sqlite::{RuntimeLedger, RuntimeSqlite, SafetyReserveProjection};

const METADATA_OWNER_DOMAIN: &[u8] = b"metadata.mutation.owner.v1";
const METADATA_IDEMPOTENCY_DOMAIN: &[u8] = b"metadata.mutation.idempotency.v1";
const METADATA_REQUEST_DOMAIN: &[u8] = b"metadata.mutation.request.v1";
const METADATA_ROW_DOMAIN: &[u8] = b"metadata.mutation.ledger.metadata.v1";
const METADATA_REQUEST_MAGIC: &[u8; 4] = b"ADM1";
const METADATA_OUTCOME_MAGIC: &[u8; 4] = b"ADM2";
const METADATA_PRIMARY_KEY_MAGIC: &[u8; 4] = b"ADK1";
const METADATA_TABLE: &[u8] = b"metadata_mutation_ledger";
const SEALED_REQUEST_COLUMN: &[u8] = b"sealed_request";
const SEALED_OUTCOME_COLUMN: &[u8] = b"sealed_outcome";
pub(super) const MAX_METADATA_MUTATION_TERMINAL_RESERVE_BYTES: u64 =
    (MAX_METADATA_MUTATION_OUTCOME_BYTES
        + ROW_BLOB_V1_OVERHEAD_LEN
        + 2 * (MAX_CONVERSATION_DESCRIPTOR_BYTES + ROW_BLOB_V1_OVERHEAD_LEN + 8 * 1024)) as u64;

#[derive(Clone)]
pub struct UpdateManagedConversationMetadata {
    pub conversation_id: RuntimeId,
    pub owner: IdempotencyOwner,
    pub idempotency_key: String,
    pub expected_entry_revision: u64,
    pub mutation: ConversationMetadataMutation,
}

impl std::fmt::Debug for UpdateManagedConversationMetadata {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("UpdateManagedConversationMetadata")
            .field("conversation_id", &self.conversation_id)
            .field("owner", &self.owner)
            .field("idempotency_key", &"[REDACTED]")
            .field("expected_entry_revision", &self.expected_entry_revision)
            .field("mutation", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetadataMutationRecord {
    pub conversation_id: RuntimeId,
    pub entry_revision: u64,
    pub catalog_revision: u64,
    pub state_changed_at_ms: u64,
}

#[derive(Clone, Debug, PartialEq)]
pub enum UpdateConversationMetadataOutcome {
    Applied { mutation: MetadataMutationRecord },
    Replayed { mutation: MetadataMutationRecord },
    Conflict { current_entry_revision: u64 },
    Failed { failure: RuntimeFailure },
}

pub(crate) struct PreparedMetadataMutationRequest {
    conversation_id: RuntimeId,
    expected_entry_revision: u64,
    request_plaintext: Zeroizing<Vec<u8>>,
}

impl PreparedMetadataMutationRequest {
    pub(crate) fn retained_capacity(&self) -> Result<usize, RuntimeStoreError> {
        Ok(self.request_plaintext.capacity())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MetadataMutationState {
    Claimed,
    Applying,
    Applied,
    OutcomeUnknown,
    Failed,
}

impl MetadataMutationState {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Claimed => "claimed",
            Self::Applying => "applying",
            Self::Applied => "applied",
            Self::OutcomeUnknown => "outcomeUnknown",
            Self::Failed => "failed",
        }
    }

    fn parse(value: &str) -> Result<Self, RuntimeStoreError> {
        match value {
            "claimed" => Ok(Self::Claimed),
            "applying" => Ok(Self::Applying),
            "applied" => Ok(Self::Applied),
            "outcomeUnknown" => Ok(Self::OutcomeUnknown),
            "failed" => Ok(Self::Failed),
            _ => Err(RuntimeStoreError::UnknownOrCorruptSchema),
        }
    }

    const fn is_active(self) -> bool {
        matches!(self, Self::Claimed | Self::Applying | Self::OutcomeUnknown)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "camelCase", deny_unknown_fields)]
enum MetadataMutationTerminalOutcome {
    Applied {
        conversation_id: String,
        entry_revision: u64,
        catalog_revision: u64,
    },
    Conflict {
        current_entry_revision: u64,
    },
    Failed {
        failure: RuntimeFailure,
    },
}

#[derive(Clone)]
struct DecodedMetadataRequest {
    conversation_id: RuntimeId,
    owner_bytes: Zeroizing<Vec<u8>>,
    idempotency_key: Zeroizing<Vec<u8>>,
    expected_entry_revision: u64,
    mutation: ConversationMetadataMutation,
}

struct RawMetadataMutationRow {
    conversation_id: Vec<u8>,
    owner_token: Vec<u8>,
    idempotency_token: Vec<u8>,
    request_token: Vec<u8>,
    expected_entry_revision: String,
    applied_entry_revision: Option<String>,
    applied_catalog_revision: Option<String>,
    state: String,
    logical_request_bytes: i64,
    logical_outcome_bytes: i64,
    charged_outcome_bytes: i64,
    created_at_ms: i64,
    state_changed_at_ms: i64,
    metadata_token: Vec<u8>,
    sealed_request: Vec<u8>,
    sealed_outcome: Option<Vec<u8>>,
}

struct AuthenticatedMetadataMutationRow {
    conversation_id: RuntimeId,
    request_token: [u8; 32],
    expected_entry_revision: u64,
    applied_entry_revision: Option<u64>,
    applied_catalog_revision: Option<u64>,
    state: MetadataMutationState,
    state_changed_at_ms: u64,
    charged_bytes: u64,
    request: DecodedMetadataRequest,
    outcome: Option<MetadataMutationTerminalOutcome>,
}

#[derive(Clone)]
struct ConversationAuditItem {
    expected_entry_revision: u64,
    applied_entry_revision: Option<u64>,
    applied_catalog_revision: Option<u64>,
    state: MetadataMutationState,
    state_changed_at_ms: u64,
    mutation: ConversationMetadataMutation,
    conflict_entry_revision: Option<u64>,
}

pub(crate) fn prepare_metadata_mutation_request(
    input: UpdateManagedConversationMetadata,
) -> Result<PreparedMetadataMutationRequest, RuntimeStoreError> {
    let UpdateManagedConversationMetadata {
        conversation_id,
        owner,
        idempotency_key,
        expected_entry_revision,
        mutation,
    } = input;
    if conversation_id.kind() != RuntimeIdKind::Conversation {
        return Err(RuntimeStoreError::IdKindMismatch {
            expected: RuntimeIdKind::Conversation,
            actual: conversation_id.kind(),
        });
    }
    if idempotency_key.is_empty() || idempotency_key.len() > MAX_IDEMPOTENCY_KEY_BYTES {
        return Err(RuntimeStoreError::InvalidConfig(
            "idempotency key must contain 1 to 1024 UTF-8 bytes",
        ));
    }
    let owner_bytes = Zeroizing::new(super::journal::canonical_owner_v1(&owner));
    let mutation_bytes = Zeroizing::new(serde_json::to_vec(&mutation).map_err(|_| {
        RuntimeStoreError::InvalidConfig("metadata mutation must serialize as canonical JSON")
    })?);
    let expected_revision = encode_sequence(expected_entry_revision);
    let request_plaintext = Zeroizing::new(encode_fields(
        METADATA_REQUEST_MAGIC,
        &[
            conversation_id.as_bytes(),
            owner_bytes.as_ref(),
            idempotency_key.as_bytes(),
            expected_revision.as_bytes(),
            mutation_bytes.as_ref(),
        ],
    )?);
    if request_plaintext.is_empty() || request_plaintext.len() > MAX_METADATA_MUTATION_REQUEST_BYTES
    {
        return Err(RuntimeStoreError::PayloadTooLarge);
    }
    Ok(PreparedMetadataMutationRequest {
        conversation_id,
        expected_entry_revision,
        request_plaintext,
    })
}

fn encode_fields(magic: &[u8; 4], fields: &[&[u8]]) -> Result<Vec<u8>, RuntimeStoreError> {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(magic);
    for field in fields {
        let length = u32::try_from(field.len()).map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
        encoded.extend_from_slice(&length.to_be_bytes());
        encoded.extend_from_slice(field);
    }
    Ok(encoded)
}

fn decode_fields<'a>(
    encoded: &'a [u8],
    magic: &[u8; 4],
    count: usize,
) -> Result<Vec<&'a [u8]>, RuntimeStoreError> {
    if encoded.get(..4) != Some(magic) {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let mut cursor = 4_usize;
    let mut fields = Vec::with_capacity(count);
    for _ in 0..count {
        let length_end = cursor
            .checked_add(4)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        let length = u32::from_be_bytes(
            encoded
                .get(cursor..length_end)
                .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?
                .try_into()
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
        );
        cursor = length_end;
        let end = cursor
            .checked_add(
                usize::try_from(length).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            )
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        fields.push(
            encoded
                .get(cursor..end)
                .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?,
        );
        cursor = end;
    }
    if cursor != encoded.len() {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(fields)
}

fn decode_metadata_request(plaintext: &[u8]) -> Result<DecodedMetadataRequest, RuntimeStoreError> {
    let fields = decode_fields(plaintext, METADATA_REQUEST_MAGIC, 5)?;
    let conversation_id = RuntimeId::from_bytes(
        RuntimeIdKind::Conversation,
        fields[0]
            .try_into()
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
    )?;
    super::journal::decode_canonical_owner(fields[1])?;
    if fields[2].is_empty()
        || fields[2].len() > MAX_IDEMPOTENCY_KEY_BYTES
        || std::str::from_utf8(fields[2]).is_err()
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let expected_revision =
        std::str::from_utf8(fields[3]).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let expected_entry_revision = decode_sequence(SequenceScope::EntryRevision, expected_revision)?;
    let mutation: ConversationMetadataMutation =
        serde_json::from_slice(fields[4]).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    if serde_json::to_vec(&mutation).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
        != fields[4]
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(DecodedMetadataRequest {
        conversation_id,
        owner_bytes: Zeroizing::new(fields[1].to_vec()),
        idempotency_key: Zeroizing::new(fields[2].to_vec()),
        expected_entry_revision,
        mutation,
    })
}

fn encode_terminal_outcome(
    outcome: &MetadataMutationTerminalOutcome,
) -> Result<Zeroizing<Vec<u8>>, RuntimeStoreError> {
    let mut encoded = Vec::from(METADATA_OUTCOME_MAGIC);
    encoded.extend_from_slice(
        &serde_json::to_vec(outcome).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
    );
    if encoded.is_empty() || encoded.len() > MAX_METADATA_MUTATION_OUTCOME_BYTES {
        return Err(RuntimeStoreError::PayloadTooLarge);
    }
    Ok(Zeroizing::new(encoded))
}

fn decode_terminal_outcome(
    plaintext: &[u8],
) -> Result<MetadataMutationTerminalOutcome, RuntimeStoreError> {
    let payload = plaintext
        .strip_prefix(METADATA_OUTCOME_MAGIC)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let outcome: MetadataMutationTerminalOutcome =
        serde_json::from_slice(payload).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    match &outcome {
        MetadataMutationTerminalOutcome::Applied {
            conversation_id,
            entry_revision,
            catalog_revision,
        } if *entry_revision == 0
            || *catalog_revision == 0
            || RuntimeId::parse_canonical(RuntimeIdKind::Conversation, conversation_id)
                .is_err() =>
        {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        MetadataMutationTerminalOutcome::Conflict {
            current_entry_revision: _,
        }
        | MetadataMutationTerminalOutcome::Failed { .. }
        | MetadataMutationTerminalOutcome::Applied { .. } => {}
    }
    if encode_terminal_outcome(&outcome)?.as_slice() != plaintext {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(outcome)
}

fn append_mac_field(message: &mut Vec<u8>, field: &[u8]) {
    message.extend_from_slice(&(field.len() as u64).to_be_bytes());
    message.extend_from_slice(field);
}

fn append_optional_mac_field(message: &mut Vec<u8>, field: Option<&[u8]>) {
    match field {
        None => message.push(0),
        Some(field) => {
            message.push(1);
            append_mac_field(message, field);
        }
    }
}

fn blind_token(
    key_bundle: &RuntimeKeyBundle,
    domain: &[u8],
    value: &[u8],
) -> Result<[u8; 32], RuntimeStoreError> {
    Ok(*key_bundle.blind_index(domain, value)?.as_bytes())
}

fn metadata_idempotency_token(
    key_bundle: &RuntimeKeyBundle,
    conversation_id: RuntimeId,
    owner_bytes: &[u8],
    idempotency_key: &[u8],
) -> Result<[u8; 32], RuntimeStoreError> {
    let message = Zeroizing::new(encode_fields(
        b"ADI1",
        &[conversation_id.as_bytes(), owner_bytes, idempotency_key],
    )?);
    Ok(*key_bundle
        .blind_index(METADATA_IDEMPOTENCY_DOMAIN, message.as_ref())?
        .as_bytes())
}

fn metadata_primary_key(conversation_id: RuntimeId, idempotency_token: &[u8; 32]) -> Vec<u8> {
    let mut primary_key = Vec::with_capacity(4 + 16 + 32);
    primary_key.extend_from_slice(METADATA_PRIMARY_KEY_MAGIC);
    primary_key.extend_from_slice(conversation_id.as_bytes());
    primary_key.extend_from_slice(idempotency_token);
    primary_key
}

#[allow(clippy::too_many_arguments)]
fn metadata_row_token(
    key_bundle: &RuntimeKeyBundle,
    conversation_id: RuntimeId,
    owner_token: &[u8; 32],
    idempotency_token: &[u8; 32],
    request_token: &[u8; 32],
    expected_entry_revision: &str,
    applied_entry_revision: Option<&str>,
    applied_catalog_revision: Option<&str>,
    state: MetadataMutationState,
    logical_request_bytes: u64,
    logical_outcome_bytes: u64,
    charged_outcome_bytes: u64,
    created_at_ms: u64,
    state_changed_at_ms: u64,
    sealed_request_bytes: u64,
    sealed_outcome_bytes: Option<u64>,
) -> Result<[u8; 32], RuntimeStoreError> {
    let mut message = Vec::with_capacity(512);
    append_mac_field(&mut message, conversation_id.as_bytes());
    append_mac_field(&mut message, owner_token);
    append_mac_field(&mut message, idempotency_token);
    append_mac_field(&mut message, request_token);
    append_mac_field(&mut message, expected_entry_revision.as_bytes());
    append_optional_mac_field(&mut message, applied_entry_revision.map(str::as_bytes));
    append_optional_mac_field(&mut message, applied_catalog_revision.map(str::as_bytes));
    append_mac_field(&mut message, state.as_str().as_bytes());
    for value in [
        logical_request_bytes,
        logical_outcome_bytes,
        charged_outcome_bytes,
        created_at_ms,
        state_changed_at_ms,
        sealed_request_bytes,
    ] {
        append_mac_field(&mut message, &value.to_be_bytes());
    }
    let sealed_outcome_bytes = sealed_outcome_bytes.map(u64::to_be_bytes);
    append_optional_mac_field(
        &mut message,
        sealed_outcome_bytes.as_ref().map(|value| &value[..]),
    );
    Ok(*key_bundle
        .blind_index(METADATA_ROW_DOMAIN, &message)?
        .as_bytes())
}

fn seal_metadata_value(
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    primary_key: &[u8],
    column: &[u8],
    plaintext: &[u8],
    maximum_plaintext_len: usize,
) -> Result<Vec<u8>, RuntimeStoreError> {
    Ok(key_bundle.row_cipher().seal_bounded(
        &RowAad {
            schema_family: RUNTIME_SCHEMA_FAMILY.as_bytes(),
            schema_version: RUNTIME_CRYPTO_CONTEXT_VERSION,
            database_id: &database_id,
            table: METADATA_TABLE,
            primary_key,
            column,
        },
        plaintext,
        maximum_plaintext_len,
    )?)
}

fn open_metadata_value(
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    primary_key: &[u8],
    column: &[u8],
    ciphertext: &[u8],
    maximum_plaintext_len: usize,
) -> Result<crate::security::SecretBytes, RuntimeStoreError> {
    Ok(key_bundle.row_cipher().open_bounded(
        &RowAad {
            schema_family: RUNTIME_SCHEMA_FAMILY.as_bytes(),
            schema_version: RUNTIME_CRYPTO_CONTEXT_VERSION,
            database_id: &database_id,
            table: METADATA_TABLE,
            primary_key,
            column,
        },
        ciphertext,
        maximum_plaintext_len,
    )?)
}

fn raw_metadata_mutation_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawMetadataMutationRow> {
    Ok(RawMetadataMutationRow {
        conversation_id: row.get(0)?,
        owner_token: row.get(1)?,
        idempotency_token: row.get(2)?,
        request_token: row.get(3)?,
        expected_entry_revision: row.get(4)?,
        applied_entry_revision: row.get(5)?,
        applied_catalog_revision: row.get(6)?,
        state: row.get(7)?,
        logical_request_bytes: row.get(8)?,
        logical_outcome_bytes: row.get(9)?,
        charged_outcome_bytes: row.get(10)?,
        created_at_ms: row.get(11)?,
        state_changed_at_ms: row.get(12)?,
        metadata_token: row.get(13)?,
        sealed_request: row.get(14)?,
        sealed_outcome: row.get(15)?,
    })
}

fn query_metadata_row_by_idempotency(
    connection: &Connection,
    idempotency_token: &[u8; 32],
) -> Result<Option<RawMetadataMutationRow>, RuntimeStoreError> {
    connection
        .query_row(
            "SELECT conversation_id, owner_token, idempotency_token, request_token,
                    expected_entry_revision, applied_entry_revision,
                    applied_catalog_revision, state, logical_request_bytes,
                    logical_outcome_bytes, charged_outcome_bytes, created_at_ms,
                    state_changed_at_ms, metadata_token, sealed_request, sealed_outcome
             FROM metadata_mutation_ledger WHERE idempotency_token = ?1",
            [&idempotency_token[..]],
            raw_metadata_mutation_row,
        )
        .optional()
        .map_err(RuntimeStoreError::from)
}

fn fixed_token(value: Vec<u8>) -> Result<[u8; 32], RuntimeStoreError> {
    value
        .try_into()
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)
}

fn nonnegative(value: i64) -> Result<u64, RuntimeStoreError> {
    u64::try_from(value).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)
}

fn validate_state_transition(
    from: MetadataMutationState,
    to: MetadataMutationState,
) -> Result<(), RuntimeStoreError> {
    if matches!(
        (from, to),
        (
            MetadataMutationState::Claimed,
            MetadataMutationState::Applying
        ) | (
            MetadataMutationState::Applying,
            MetadataMutationState::Applied
                | MetadataMutationState::Failed
                | MetadataMutationState::OutcomeUnknown
        ) | (
            MetadataMutationState::OutcomeUnknown,
            MetadataMutationState::Applied | MetadataMutationState::Failed
        )
    ) {
        Ok(())
    } else {
        Err(RuntimeStoreError::InvalidStateTransition)
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_persisted_state(
    state: MetadataMutationState,
    applied_entry_revision: Option<u64>,
    applied_catalog_revision: Option<u64>,
    logical_outcome_bytes: u64,
    charged_outcome_bytes: u64,
    sealed_outcome_bytes: Option<u64>,
) -> Result<(), RuntimeStoreError> {
    if applied_entry_revision.is_some() != applied_catalog_revision.is_some()
        || applied_entry_revision == Some(0)
        || applied_catalog_revision == Some(0)
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    if state.is_active() {
        if applied_entry_revision.is_some()
            || logical_outcome_bytes != 0
            || sealed_outcome_bytes.is_some()
            || charged_outcome_bytes
                != u64::try_from(MAX_METADATA_MUTATION_OUTCOME_BYTES + ROW_BLOB_V1_OVERHEAD_LEN)
                    .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
        {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        match state {
            MetadataMutationState::Claimed => {}
            MetadataMutationState::Applying => {
                validate_state_transition(MetadataMutationState::Claimed, state)
                    .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
            }
            MetadataMutationState::OutcomeUnknown => {
                validate_state_transition(MetadataMutationState::Applying, state)
                    .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
            }
            MetadataMutationState::Applied | MetadataMutationState::Failed => unreachable!(),
        }
        return Ok(());
    }
    let sealed_outcome_bytes =
        sealed_outcome_bytes.ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    if logical_outcome_bytes == 0
        || logical_outcome_bytes > MAX_METADATA_MUTATION_OUTCOME_BYTES as u64
        || sealed_outcome_bytes
            != logical_outcome_bytes
                .checked_add(ROW_BLOB_V1_OVERHEAD_LEN as u64)
                .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?
        || charged_outcome_bytes != sealed_outcome_bytes
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    match state {
        MetadataMutationState::Applied if applied_entry_revision.is_some() => Ok(()),
        MetadataMutationState::Failed if applied_entry_revision.is_none() => Ok(()),
        _ => Err(RuntimeStoreError::UnknownOrCorruptSchema),
    }
}

fn authenticate_metadata_row(
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    raw: RawMetadataMutationRow,
) -> Result<AuthenticatedMetadataMutationRow, RuntimeStoreError> {
    let conversation_id = RuntimeId::from_bytes(
        RuntimeIdKind::Conversation,
        raw.conversation_id
            .try_into()
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
    )?;
    let owner_token = fixed_token(raw.owner_token)?;
    let idempotency_token = fixed_token(raw.idempotency_token)?;
    let request_token = fixed_token(raw.request_token)?;
    let metadata_token = fixed_token(raw.metadata_token)?;
    let expected_entry_revision =
        decode_sequence(SequenceScope::EntryRevision, &raw.expected_entry_revision)?;
    let applied_entry_revision = raw
        .applied_entry_revision
        .as_deref()
        .map(|value| decode_sequence(SequenceScope::EntryRevision, value))
        .transpose()?;
    let applied_catalog_revision = raw
        .applied_catalog_revision
        .as_deref()
        .map(|value| decode_sequence(SequenceScope::CatalogRevision, value))
        .transpose()?;
    let state = MetadataMutationState::parse(&raw.state)?;
    let logical_request_bytes = nonnegative(raw.logical_request_bytes)?;
    let logical_outcome_bytes = nonnegative(raw.logical_outcome_bytes)?;
    let charged_outcome_bytes = nonnegative(raw.charged_outcome_bytes)?;
    let created_at_ms = nonnegative(raw.created_at_ms)?;
    let state_changed_at_ms = nonnegative(raw.state_changed_at_ms)?;
    if state_changed_at_ms < created_at_ms
        || logical_request_bytes == 0
        || logical_request_bytes > MAX_METADATA_MUTATION_REQUEST_BYTES as u64
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let sealed_request_bytes = u64::try_from(raw.sealed_request.len())
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let sealed_outcome_bytes = raw
        .sealed_outcome
        .as_ref()
        .map(Vec::len)
        .map(u64::try_from)
        .transpose()
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    if sealed_request_bytes
        != logical_request_bytes
            .checked_add(ROW_BLOB_V1_OVERHEAD_LEN as u64)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    validate_persisted_state(
        state,
        applied_entry_revision,
        applied_catalog_revision,
        logical_outcome_bytes,
        charged_outcome_bytes,
        sealed_outcome_bytes,
    )?;
    let expected_metadata_token = metadata_row_token(
        key_bundle,
        conversation_id,
        &owner_token,
        &idempotency_token,
        &request_token,
        &raw.expected_entry_revision,
        raw.applied_entry_revision.as_deref(),
        raw.applied_catalog_revision.as_deref(),
        state,
        logical_request_bytes,
        logical_outcome_bytes,
        charged_outcome_bytes,
        created_at_ms,
        state_changed_at_ms,
        sealed_request_bytes,
        sealed_outcome_bytes,
    )?;
    if metadata_token != expected_metadata_token {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let primary_key = metadata_primary_key(conversation_id, &idempotency_token);
    let request_plaintext = open_metadata_value(
        key_bundle,
        database_id,
        &primary_key,
        SEALED_REQUEST_COLUMN,
        &raw.sealed_request,
        MAX_METADATA_MUTATION_REQUEST_BYTES,
    )?;
    if request_plaintext.expose_secret().len()
        != usize::try_from(logical_request_bytes)
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let request = decode_metadata_request(request_plaintext.expose_secret())?;
    if request.conversation_id != conversation_id
        || request.expected_entry_revision != expected_entry_revision
        || owner_token
            != blind_token(
                key_bundle,
                METADATA_OWNER_DOMAIN,
                request.owner_bytes.as_ref(),
            )?
        || idempotency_token
            != metadata_idempotency_token(
                key_bundle,
                conversation_id,
                request.owner_bytes.as_ref(),
                request.idempotency_key.as_ref(),
            )?
        || request_token
            != blind_token(
                key_bundle,
                METADATA_REQUEST_DOMAIN,
                request_plaintext.expose_secret(),
            )?
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let outcome = match (raw.sealed_outcome.as_deref(), sealed_outcome_bytes) {
        (None, None) => None,
        (Some(sealed), Some(_)) => {
            let plaintext = open_metadata_value(
                key_bundle,
                database_id,
                &primary_key,
                SEALED_OUTCOME_COLUMN,
                sealed,
                MAX_METADATA_MUTATION_OUTCOME_BYTES,
            )?;
            if plaintext.expose_secret().len()
                != usize::try_from(logical_outcome_bytes)
                    .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
            {
                return Err(RuntimeStoreError::UnknownOrCorruptSchema);
            }
            Some(decode_terminal_outcome(plaintext.expose_secret())?)
        }
        _ => return Err(RuntimeStoreError::UnknownOrCorruptSchema),
    };
    match (&outcome, state) {
        (
            Some(MetadataMutationTerminalOutcome::Applied {
                conversation_id: outcome_conversation_id,
                entry_revision,
                catalog_revision,
            }),
            MetadataMutationState::Applied,
        ) if RuntimeId::parse_canonical(RuntimeIdKind::Conversation, outcome_conversation_id)
            .ok()
            == Some(conversation_id)
            && Some(*entry_revision) == applied_entry_revision
            && Some(*catalog_revision) == applied_catalog_revision => {}
        (Some(MetadataMutationTerminalOutcome::Conflict { .. }), MetadataMutationState::Failed) => {
        }
        (Some(MetadataMutationTerminalOutcome::Failed { .. }), MetadataMutationState::Failed) => {}
        (None, state) if state.is_active() => {}
        _ => return Err(RuntimeStoreError::UnknownOrCorruptSchema),
    }
    let charged_bytes = sealed_request_bytes
        .checked_add(charged_outcome_bytes)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    Ok(AuthenticatedMetadataMutationRow {
        conversation_id,
        request_token,
        expected_entry_revision,
        applied_entry_revision,
        applied_catalog_revision,
        state,
        state_changed_at_ms,
        charged_bytes,
        request,
        outcome,
    })
}

fn replay_outcome(
    row: AuthenticatedMetadataMutationRow,
) -> Result<UpdateConversationMetadataOutcome, RuntimeStoreError> {
    match (row.state, row.outcome) {
        (
            MetadataMutationState::Applied,
            Some(MetadataMutationTerminalOutcome::Applied {
                conversation_id,
                entry_revision,
                catalog_revision,
            }),
        ) => Ok(UpdateConversationMetadataOutcome::Replayed {
            mutation: MetadataMutationRecord {
                conversation_id: RuntimeId::parse_canonical(
                    RuntimeIdKind::Conversation,
                    &conversation_id,
                )?,
                entry_revision,
                catalog_revision,
                state_changed_at_ms: row.state_changed_at_ms,
            },
        }),
        (
            MetadataMutationState::Failed,
            Some(MetadataMutationTerminalOutcome::Failed { failure }),
        ) => Ok(UpdateConversationMetadataOutcome::Failed { failure }),
        (
            MetadataMutationState::Failed,
            Some(MetadataMutationTerminalOutcome::Conflict {
                current_entry_revision,
            }),
        ) => Ok(UpdateConversationMetadataOutcome::Conflict {
            current_entry_revision,
        }),
        (state, None) if state.is_active() => Err(RuntimeStoreError::MetadataMutationPending),
        _ => Err(RuntimeStoreError::UnknownOrCorruptSchema),
    }
}

fn try_replay_metadata_mutation(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    idempotency_token: &[u8; 32],
    request_token: &[u8; 32],
) -> Result<Option<UpdateConversationMetadataOutcome>, RuntimeStoreError> {
    let Some(raw) = query_metadata_row_by_idempotency(connection, idempotency_token)? else {
        return Ok(None);
    };
    let row = authenticate_metadata_row(key_bundle, database_id, raw)?;
    if row.request_token != *request_token {
        return Err(RuntimeStoreError::IdempotencyConflict);
    }
    replay_outcome(row).map(Some)
}

fn metadata_count_for_conversation(
    connection: &Connection,
    conversation_id: RuntimeId,
) -> Result<u64, RuntimeStoreError> {
    let count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM metadata_mutation_ledger WHERE conversation_id = ?1",
        [&conversation_id.as_bytes()[..]],
        |row| row.get(0),
    )?;
    nonnegative(count)
}

pub(super) fn ensure_metadata_mutation_capacity(
    ledger: &RuntimeLedger,
    conversation_count: u64,
    new_charged_bytes: u64,
    add_active: bool,
) -> Result<(), RuntimeStoreError> {
    if conversation_count >= MAX_METADATA_MUTATIONS_PER_CONVERSATION {
        return Err(RuntimeStoreError::MetadataMutationLimit {
            scope: MetadataMutationLimitScope::Conversation,
        });
    }
    if ledger.metadata_mutation_count >= MAX_METADATA_MUTATIONS_GLOBAL {
        return Err(RuntimeStoreError::MetadataMutationLimit {
            scope: MetadataMutationLimitScope::GlobalCount,
        });
    }
    if ledger
        .metadata_mutation_charged_bytes
        .checked_add(new_charged_bytes)
        .is_none_or(|value| value > MAX_METADATA_MUTATION_CHARGED_BYTES_GLOBAL)
    {
        return Err(RuntimeStoreError::MetadataMutationLimit {
            scope: MetadataMutationLimitScope::GlobalChargedBytes,
        });
    }
    if add_active && ledger.active_metadata_mutation_count >= MAX_ACTIVE_METADATA_MUTATIONS {
        return Err(RuntimeStoreError::MetadataMutationLimit {
            scope: MetadataMutationLimitScope::Active,
        });
    }
    Ok(())
}

fn apply_mutation(
    conversation: &crate::runtime::model::ConversationRecord,
    mutation: &ConversationMetadataMutation,
) -> Result<
    (
        crate::runtime::model::ConversationDescriptor,
        ConversationLifecycle,
    ),
    RuntimeStoreError,
> {
    let mut descriptor = conversation.descriptor.clone();
    let lifecycle = match mutation {
        ConversationMetadataMutation::Rename { title } => {
            descriptor.title.clone_from(title);
            conversation.lifecycle
        }
        ConversationMetadataMutation::SetArchived { archived } => {
            if conversation.lifecycle == ConversationLifecycle::RecoveryBlocked {
                return Err(RuntimeStoreError::InvalidStateTransition);
            }
            if *archived {
                ConversationLifecycle::Archived
            } else {
                ConversationLifecycle::Active
            }
        }
    };
    Ok((descriptor, lifecycle))
}

pub(crate) fn update_managed_conversation_metadata(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    prepared: PreparedMetadataMutationRequest,
    effects: &mut CommandStreamEffects,
) -> Result<UpdateConversationMetadataOutcome, RuntimeStoreError> {
    let request = decode_metadata_request(prepared.request_plaintext.as_ref())?;
    if request.conversation_id != prepared.conversation_id
        || request.expected_entry_revision != prepared.expected_entry_revision
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let owner_token = blind_token(
        &state.key_bundle,
        METADATA_OWNER_DOMAIN,
        request.owner_bytes.as_ref(),
    )?;
    let idempotency_token = metadata_idempotency_token(
        &state.key_bundle,
        request.conversation_id,
        request.owner_bytes.as_ref(),
        request.idempotency_key.as_ref(),
    )?;
    let request_token = blind_token(
        &state.key_bundle,
        METADATA_REQUEST_DOMAIN,
        prepared.request_plaintext.as_ref(),
    )?;
    if let Some(replayed) = try_replay_metadata_mutation(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        &idempotency_token,
        &request_token,
    )? {
        return Ok(replayed);
    }
    let preflight_conversation = super::journal::load_conversation(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        request.conversation_id,
    )?;
    let preflight_state = super::configuration::load_conversation_state(
        &state.connection,
        &state.key_bundle,
        request.conversation_id,
    )?;
    if !preflight_state.is_managed() {
        return Err(RuntimeStoreError::MetadataMutationUnsupported);
    }
    let current_entry_revision = preflight_state.entry_revision()?;
    let projected_request_bytes = prepared
        .request_plaintext
        .len()
        .checked_add(ROW_BLOB_V1_OVERHEAD_LEN)
        .ok_or(RuntimeStoreError::PayloadTooLarge)?;
    let observed_at_ms = config.clock.now_ms().map_err(RuntimeStoreError::from)?;
    let latest_mutation_at: Option<i64> = state.connection.query_row(
        "SELECT MAX(state_changed_at_ms) FROM metadata_mutation_ledger
         WHERE conversation_id = ?1",
        [&request.conversation_id.as_bytes()[..]],
        |row| row.get(0),
    )?;
    let persisted_at_ms = latest_mutation_at
        .map(nonnegative)
        .transpose()?
        .unwrap_or(preflight_conversation.updated_at_ms)
        .max(preflight_conversation.updated_at_ms);
    if observed_at_ms < persisted_at_ms {
        return Err(RuntimeStoreError::ClockRegressed {
            persisted_ms: persisted_at_ms,
            observed_ms: observed_at_ms,
        });
    }
    let projected_descriptor_bytes = if request.expected_entry_revision == current_entry_revision {
        let (descriptor, _) = apply_mutation(&preflight_conversation, &request.mutation)?;
        super::journal::canonical_conversation_descriptor(&descriptor)?.len()
    } else {
        0
    };
    let projected_write_bytes = super::journal::projected_write_bytes(&[
        projected_request_bytes,
        MAX_METADATA_MUTATION_OUTCOME_BYTES + ROW_BLOB_V1_OVERHEAD_LEN,
        projected_descriptor_bytes + ROW_BLOB_V1_OVERHEAD_LEN,
        projected_descriptor_bytes + ROW_BLOB_V1_OVERHEAD_LEN + 8 * 1024,
        8 * 1024,
    ])?;
    super::sqlite::admit_ordinary_write(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        &state.storage_path,
        &mut state.admission_state,
        config.capacity_probe.as_ref(),
        projected_write_bytes,
        SafetyReserveProjection::Current,
    )?;

    let transaction = state
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let ledger =
        super::sqlite::load_runtime_ledger(&transaction, &state.key_bundle, state.database_id)?;
    if let Some(replayed) = try_replay_metadata_mutation(
        &transaction,
        &state.key_bundle,
        state.database_id,
        &idempotency_token,
        &request_token,
    )? {
        return Ok(replayed);
    }
    let conversation = super::journal::load_conversation(
        &transaction,
        &state.key_bundle,
        state.database_id,
        request.conversation_id,
    )?;
    let conversation_state = super::configuration::load_conversation_state(
        &transaction,
        &state.key_bundle,
        request.conversation_id,
    )?;
    if !conversation_state.is_managed() {
        return Err(RuntimeStoreError::MetadataMutationUnsupported);
    }
    let current_entry_revision = conversation_state.entry_revision()?;
    let (
        terminal_outcome,
        row_state,
        applied_entry_revision,
        applied_catalog_revision,
        response,
        mut next_ledger,
    ) = if request.expected_entry_revision != current_entry_revision {
        (
            MetadataMutationTerminalOutcome::Conflict {
                current_entry_revision,
            },
            MetadataMutationState::Failed,
            None,
            None,
            UpdateConversationMetadataOutcome::Conflict {
                current_entry_revision,
            },
            ledger.clone(),
        )
    } else {
        let next_entry_revision = current_entry_revision.checked_add(1).ok_or(
            super::sequence::SequenceError::Exhausted {
                scope: SequenceScope::EntryRevision,
            },
        )?;
        let next_entry_revision_encoded = encode_sequence(next_entry_revision);
        let next_catalog_revision = next_sequence(
            SequenceScope::CatalogRevision,
            ledger.catalog_high_water.as_deref(),
        )?;
        let (next_descriptor, next_lifecycle) = apply_mutation(&conversation, &request.mutation)?;
        let updated = super::journal::update_conversation_metadata(
            &transaction,
            &state.key_bundle,
            state.database_id,
            &conversation,
            next_descriptor,
            next_lifecycle,
            next_catalog_revision.value,
        )?;
        super::configuration::advance_entry_revision(
            &transaction,
            &state.key_bundle,
            request.conversation_id,
            &conversation_state,
            &next_entry_revision_encoded,
        )?;
        if updated.conversation_id != request.conversation_id
            || updated.catalog_revision != next_catalog_revision.value
        {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        let mut next_ledger = ledger.clone();
        next_ledger.catalog_high_water = Some(next_catalog_revision.encoded.clone());
        (
            MetadataMutationTerminalOutcome::Applied {
                conversation_id: request.conversation_id.to_canonical_string(),
                entry_revision: next_entry_revision,
                catalog_revision: next_catalog_revision.value,
            },
            MetadataMutationState::Applied,
            Some(next_entry_revision_encoded),
            Some(next_catalog_revision.encoded),
            UpdateConversationMetadataOutcome::Applied {
                mutation: MetadataMutationRecord {
                    conversation_id: request.conversation_id,
                    entry_revision: next_entry_revision,
                    catalog_revision: next_catalog_revision.value,
                    state_changed_at_ms: observed_at_ms,
                },
            },
            next_ledger,
        )
    };
    let outcome_plaintext = encode_terminal_outcome(&terminal_outcome)?;
    let projected_outcome_bytes = outcome_plaintext
        .len()
        .checked_add(ROW_BLOB_V1_OVERHEAD_LEN)
        .ok_or(RuntimeStoreError::PayloadTooLarge)?;
    let projected_charged_bytes = u64::try_from(
        projected_request_bytes
            .checked_add(projected_outcome_bytes)
            .ok_or(RuntimeStoreError::PayloadTooLarge)?,
    )
    .map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
    let primary_key = metadata_primary_key(request.conversation_id, &idempotency_token);
    let sealed_request = seal_metadata_value(
        &state.key_bundle,
        state.database_id,
        &primary_key,
        SEALED_REQUEST_COLUMN,
        prepared.request_plaintext.as_ref(),
        MAX_METADATA_MUTATION_REQUEST_BYTES,
    )?;
    let sealed_outcome = seal_metadata_value(
        &state.key_bundle,
        state.database_id,
        &primary_key,
        SEALED_OUTCOME_COLUMN,
        outcome_plaintext.as_ref(),
        MAX_METADATA_MUTATION_OUTCOME_BYTES,
    )?;
    if sealed_request.len() != projected_request_bytes
        || sealed_outcome.len() != projected_outcome_bytes
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    ensure_metadata_mutation_capacity(
        &ledger,
        metadata_count_for_conversation(&transaction, request.conversation_id)?,
        projected_charged_bytes,
        false,
    )?;
    let latest_mutation_at: Option<i64> = transaction.query_row(
        "SELECT MAX(state_changed_at_ms) FROM metadata_mutation_ledger
         WHERE conversation_id = ?1",
        [&request.conversation_id.as_bytes()[..]],
        |row| row.get(0),
    )?;
    let persisted_at_ms = latest_mutation_at
        .map(nonnegative)
        .transpose()?
        .unwrap_or(conversation.updated_at_ms)
        .max(conversation.updated_at_ms);
    if observed_at_ms < persisted_at_ms {
        return Err(RuntimeStoreError::ClockRegressed {
            persisted_ms: persisted_at_ms,
            observed_ms: observed_at_ms,
        });
    }
    let expected_entry_revision_encoded = encode_sequence(request.expected_entry_revision);
    let logical_request_bytes = u64::try_from(prepared.request_plaintext.len())
        .map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
    let logical_outcome_bytes =
        u64::try_from(outcome_plaintext.len()).map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
    let charged_outcome_bytes =
        u64::try_from(sealed_outcome.len()).map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
    let row_token = metadata_row_token(
        &state.key_bundle,
        request.conversation_id,
        &owner_token,
        &idempotency_token,
        &request_token,
        &expected_entry_revision_encoded,
        applied_entry_revision.as_deref(),
        applied_catalog_revision.as_deref(),
        row_state,
        logical_request_bytes,
        logical_outcome_bytes,
        charged_outcome_bytes,
        observed_at_ms,
        observed_at_ms,
        u64::try_from(sealed_request.len()).map_err(|_| RuntimeStoreError::PayloadTooLarge)?,
        Some(charged_outcome_bytes),
    )?;
    transaction.execute(
        "INSERT INTO metadata_mutation_ledger (
             conversation_id, owner_token, idempotency_token, request_token,
             expected_entry_revision, applied_entry_revision, applied_catalog_revision,
             state, logical_request_bytes, logical_outcome_bytes, charged_outcome_bytes,
             created_at_ms, state_changed_at_ms, metadata_token, sealed_request, sealed_outcome
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?12,
                   ?13, ?14, ?15)",
        params![
            &request.conversation_id.as_bytes()[..],
            &owner_token[..],
            &idempotency_token[..],
            &request_token[..],
            &expected_entry_revision_encoded,
            applied_entry_revision.as_deref(),
            applied_catalog_revision.as_deref(),
            row_state.as_str(),
            i64::try_from(logical_request_bytes).map_err(|_| RuntimeStoreError::PayloadTooLarge)?,
            i64::try_from(logical_outcome_bytes).map_err(|_| RuntimeStoreError::PayloadTooLarge)?,
            i64::try_from(charged_outcome_bytes).map_err(|_| RuntimeStoreError::PayloadTooLarge)?,
            i64::try_from(observed_at_ms).map_err(|_| RuntimeStoreError::TimeOutOfRange)?,
            &row_token[..],
            sealed_request,
            sealed_outcome,
        ],
    )?;
    next_ledger.metadata_mutation_count = next_ledger
        .metadata_mutation_count
        .checked_add(1)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    next_ledger.metadata_mutation_charged_bytes = next_ledger
        .metadata_mutation_charged_bytes
        .checked_add(projected_charged_bytes)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let pending_targets = super::sqlite::update_runtime_ledger_with_trim_clock(
        &transaction,
        &state.key_bundle,
        state.database_id,
        &ledger,
        &next_ledger,
        observed_at_ms,
    )?;
    config
        .fault_injector
        .before_operation(RuntimeStoreOperation::UpdateConversationMetadataBeforeCommit)?;
    let commit_result = super::sqlite::commit_transaction(
        transaction,
        RuntimeCommitOperation::UpdateConversationMetadata,
    );
    effects.record_commit_result(pending_targets, &commit_result);
    commit_result?;
    super::sqlite::latch_post_commit_capacity(state, config);
    if config
        .fault_injector
        .before_operation(RuntimeStoreOperation::UpdateConversationMetadataAfterCommit)
        .is_err()
    {
        return Err(RuntimeStoreError::CommitOutcomeUnknown {
            operation: RuntimeCommitOperation::UpdateConversationMetadata,
        });
    }
    Ok(response)
}

fn validate_catalog_delta_for_mutation(
    delta: &CatalogDelta,
    conversation_id: RuntimeId,
    entry_revision: u64,
    catalog_revision: u64,
    mutation: &ConversationMetadataMutation,
    current: Option<&crate::runtime::model::ConversationRecord>,
) -> Result<(), RuntimeStoreError> {
    if delta.catalog_revision != catalog_revision || delta.changes.len() != 1 {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let CatalogChange::Upserted { entry } = &delta.changes[0] else {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    };
    if entry.conversation_id.as_str() != conversation_id.to_canonical_string()
        || entry.entry_revision != entry_revision
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let matches_mutation = match mutation {
        ConversationMetadataMutation::Rename { title } => &entry.title == title,
        ConversationMetadataMutation::SetArchived { archived } => entry.archived == *archived,
    };
    if !matches_mutation {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    if let Some(current) = current
        && (entry.agent_kind != current.descriptor.agent_kind
            || entry.title != current.descriptor.title
            || entry.cwd.as_ref() != Some(&current.descriptor.cwd)
            || (current.lifecycle != ConversationLifecycle::RecoveryBlocked
                && (entry.last_active_ms != current.updated_at_ms
                    || entry.archived != (current.lifecycle == ConversationLifecycle::Archived))))
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(())
}

fn validate_conversation_audit(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    ledger: &RuntimeLedger,
    conversation_id: RuntimeId,
    mut items: Vec<ConversationAuditItem>,
) -> Result<(), RuntimeStoreError> {
    if items.len()
        > usize::try_from(MAX_METADATA_MUTATIONS_PER_CONVERSATION)
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let conversation_state =
        super::configuration::load_conversation_state(connection, key_bundle, conversation_id)?;
    let current_entry_revision = conversation_state.entry_revision()?;
    if conversation_state.is_managed()
        && items.iter().any(|item| {
            item.state != MetadataMutationState::Applied
                && !(item.state == MetadataMutationState::Failed
                    && item.conflict_entry_revision.is_some())
        })
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let active = items.iter().filter(|item| item.state.is_active()).count();
    if active > 1
        || items
            .iter()
            .filter(|item| item.state.is_active())
            .any(|item| item.expected_entry_revision != current_entry_revision)
        || items
            .iter()
            .filter(|item| item.state == MetadataMutationState::Failed)
            .any(|item| {
                item.conflict_entry_revision.is_none()
                    && item.expected_entry_revision > current_entry_revision
            })
        || items.iter().any(|item| {
            item.conflict_entry_revision.is_some_and(|revision| {
                revision > current_entry_revision || revision == item.expected_entry_revision
            })
        })
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let mut applied = items
        .drain(..)
        .filter(|item| item.state == MetadataMutationState::Applied)
        .collect::<Vec<_>>();
    applied.sort_by_key(|item| item.applied_entry_revision);
    if u64::try_from(applied.len()).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
        != current_entry_revision
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let retention_floor = ledger
        .catalog_retention_floor
        .as_deref()
        .map(|value| decode_sequence(SequenceScope::CatalogRevision, value))
        .transpose()?;
    let read_crypto = key_bundle.read_only_capability();
    let conversation =
        super::journal::load_conversation(connection, key_bundle, database_id, conversation_id)?;
    let mut previous_catalog_revision = None;
    for (offset, item) in applied.iter().enumerate() {
        let expected_entry_revision = u64::try_from(offset)
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
            .checked_add(1)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        let entry_revision = item
            .applied_entry_revision
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        let catalog_revision = item
            .applied_catalog_revision
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        if entry_revision != expected_entry_revision
            || item.expected_entry_revision.checked_add(1) != Some(entry_revision)
            || previous_catalog_revision.is_some_and(|previous| catalog_revision <= previous)
        {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        previous_catalog_revision = Some(catalog_revision);
        if retention_floor.is_none_or(|floor| catalog_revision >= floor) {
            let revision = encode_sequence(catalog_revision);
            let (delta, created_at_ms) = super::catalog::load_delta_with_created_at(
                connection,
                &read_crypto,
                database_id,
                &revision,
            )?;
            if created_at_ms != item.state_changed_at_ms {
                return Err(RuntimeStoreError::UnknownOrCorruptSchema);
            }
            validate_catalog_delta_for_mutation(
                &delta,
                conversation_id,
                entry_revision,
                catalog_revision,
                &item.mutation,
                (offset + 1 == applied.len()).then_some(&conversation),
            )?;
        }
    }
    if let Some(last_catalog_revision) = previous_catalog_revision
        && conversation.catalog_revision != last_catalog_revision
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    if let Some(title) = applied.iter().rev().find_map(|item| match &item.mutation {
        ConversationMetadataMutation::Rename { title } => Some(title),
        ConversationMetadataMutation::SetArchived { .. } => None,
    }) && &conversation.descriptor.title != title
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    if conversation.lifecycle != ConversationLifecycle::RecoveryBlocked
        && let Some(archived) = applied.iter().rev().find_map(|item| match item.mutation {
            ConversationMetadataMutation::SetArchived { archived } => Some(archived),
            ConversationMetadataMutation::Rename { .. } => None,
        })
        && archived != (conversation.lifecycle == ConversationLifecycle::Archived)
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(())
}

pub(super) fn validate_v5_integrity(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    ledger: &RuntimeLedger,
) -> Result<(), RuntimeStoreError> {
    let version: u32 = connection
        .query_row(
            "SELECT schema_version FROM runtime_meta WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    if version < 5 {
        return if ledger.metadata_mutation_count == 0
            && ledger.active_metadata_mutation_count == 0
            && ledger.metadata_mutation_charged_bytes == 0
        {
            Ok(())
        } else {
            Err(RuntimeStoreError::UnknownOrCorruptSchema)
        };
    }
    if !matches!(version, 5 | 6) {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let mut statement = connection.prepare(
        "SELECT conversation_id, owner_token, idempotency_token, request_token,
                expected_entry_revision, applied_entry_revision,
                applied_catalog_revision, state, logical_request_bytes,
                logical_outcome_bytes, charged_outcome_bytes, created_at_ms,
                state_changed_at_ms, metadata_token, sealed_request, sealed_outcome
         FROM metadata_mutation_ledger
         ORDER BY conversation_id, created_at_ms, idempotency_token",
    )?;
    let rows = statement.query_map([], raw_metadata_mutation_row)?;
    let (mut count, mut active_count, mut charged_bytes) = (0_u64, 0_u64, 0_u64);
    let mut audits = BTreeMap::<RuntimeId, Vec<ConversationAuditItem>>::new();
    for raw in rows {
        let raw = raw?;
        let authenticated = authenticate_metadata_row(key_bundle, database_id, raw)?;
        count = count
            .checked_add(1)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        active_count = active_count
            .checked_add(u64::from(authenticated.state.is_active()))
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        charged_bytes = charged_bytes
            .checked_add(authenticated.charged_bytes)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        let item = ConversationAuditItem {
            expected_entry_revision: authenticated.expected_entry_revision,
            applied_entry_revision: authenticated.applied_entry_revision,
            applied_catalog_revision: authenticated.applied_catalog_revision,
            state: authenticated.state,
            state_changed_at_ms: authenticated.state_changed_at_ms,
            mutation: authenticated.request.mutation,
            conflict_entry_revision: match authenticated.outcome {
                Some(MetadataMutationTerminalOutcome::Conflict {
                    current_entry_revision,
                }) => Some(current_entry_revision),
                _ => None,
            },
        };
        let bucket = audits.entry(authenticated.conversation_id).or_default();
        bucket.push(item);
        if bucket.len()
            > usize::try_from(MAX_METADATA_MUTATIONS_PER_CONVERSATION)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
        {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
    }
    if count != ledger.metadata_mutation_count
        || active_count != ledger.active_metadata_mutation_count
        || charged_bytes != ledger.metadata_mutation_charged_bytes
        || count > MAX_METADATA_MUTATIONS_GLOBAL
        || active_count > MAX_ACTIVE_METADATA_MUTATIONS
        || charged_bytes > MAX_METADATA_MUTATION_CHARGED_BYTES_GLOBAL
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let mut conversation_statement = connection
        .prepare("SELECT conversation_id FROM conversation_state ORDER BY conversation_id")?;
    let conversation_rows = conversation_statement.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
    let mut state_conversation_count = 0_u64;
    for conversation_id in conversation_rows {
        let conversation_id = RuntimeId::from_bytes(
            RuntimeIdKind::Conversation,
            conversation_id?
                .try_into()
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
        )?;
        state_conversation_count = state_conversation_count
            .checked_add(1)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        validate_conversation_audit(
            connection,
            key_bundle,
            database_id,
            ledger,
            conversation_id,
            audits.remove(&conversation_id).unwrap_or_default(),
        )?;
    }
    if state_conversation_count != ledger.conversation_count || !audits.is_empty() {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(())
}

#[cfg(test)]
#[path = "metadata_tests.rs"]
mod tests;
