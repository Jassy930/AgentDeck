//! Runtime v5 configuration sidecar 的初始状态、CAS writer 与完整性门禁。
//!
//! B2a 只接入 append-only configuration writer；pin/metadata writer 仍由 B3/B4
//! 接入。在这些 writer 落地前，任一对应物理行都必须 fail-close，不能把未认证
//! 的手写 fixture 当作合法状态。

use agentdeck_protocol::runtime::identity::{ConversationId, EventId};
use agentdeck_protocol::runtime::{
    ConversationConfiguration, ConversationConfigurationState, RuntimeEvent, RuntimeEventBody,
};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use zeroize::Zeroizing;

use crate::runtime::events::CommandStreamEffects;
use crate::runtime::model::{
    ConfigurationLimitScope, ConversationRecord, IdempotencyOwner, MAX_IDEMPOTENCY_KEY_BYTES,
    MAX_RUNTIME_CONVERSATIONS, MAX_RUNTIME_EVENT_BYTES, RuntimeCommitOperation, RuntimeStoreConfig,
    RuntimeStoreError, RuntimeStoreOperation,
};

use super::cipher::{ROW_BLOB_V1_OVERHEAD_LEN, RowAad, RuntimeKeyBundle};
use super::identity::{RuntimeId, RuntimeIdKind};
use super::schema::{RUNTIME_CRYPTO_CONTEXT_VERSION, RUNTIME_SCHEMA_FAMILY};
use super::sequence::{SequenceScope, decode_sequence, encode_sequence, next_sequence};
use super::sqlite::{RuntimeLedger, RuntimeSqlite, SafetyReserveProjection};

const CONVERSATION_STATE_DOMAIN: &[u8] = b"conversation.state.metadata.v1";
const CONFIGURATION_OWNER_DOMAIN: &[u8] = b"configuration.owner.v1";
const CONFIGURATION_IDEMPOTENCY_DOMAIN: &[u8] = b"configuration.idempotency.v1";
const CONFIGURATION_REQUEST_DOMAIN: &[u8] = b"configuration.request.v1";
const CONFIGURATION_METADATA_DOMAIN: &[u8] = b"configuration.journal.metadata.v1";
const CONFIGURATION_REQUEST_MAGIC: &[u8; 4] = b"ADQ1";
const CONFIGURATION_PRIMARY_KEY_MAGIC: &[u8; 4] = b"ADP1";
const CONFIGURATION_TABLE: &[u8] = b"configuration_journal";
const CONFIGURATION_COLUMN: &[u8] = b"sealed_request";
pub const MAX_CONFIGURATION_CANONICAL_BYTES: usize = 16 * 1024;
pub const MAX_CONFIGURATION_REQUEST_BYTES: usize = 32 * 1024;
pub const MAX_CONFIGURATIONS_PER_CONVERSATION: u64 = 4_096;
pub const MAX_CONFIGURATIONS_GLOBAL: u64 = 65_536;
pub const MAX_CONFIGURATION_SEALED_BYTES_GLOBAL: u64 = 64 * 1024 * 1024;
const V5_SCHEMA_FIXED_PROJECTION_BYTES: u64 = 2 * 1024 * 1024;
const V5_STATE_ROW_PROJECTION_BYTES: u64 = 1024;

#[derive(Clone)]
pub struct ConfigureConversation {
    pub conversation_id: RuntimeId,
    pub owner: IdempotencyOwner,
    pub idempotency_key: String,
    pub expected_configuration_revision: u64,
    pub configuration: ConversationConfiguration,
}

impl std::fmt::Debug for ConfigureConversation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConfigureConversation")
            .field("conversation_id", &self.conversation_id)
            .field("owner", &self.owner)
            .field("idempotency_key", &"[REDACTED]")
            .field(
                "expected_configuration_revision",
                &self.expected_configuration_revision,
            )
            .field("configuration", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ConfigurationRecord {
    pub conversation_id: RuntimeId,
    pub configuration_revision: u64,
    pub base_configuration_revision: u64,
    pub event_id: RuntimeId,
    pub event_seq: u64,
    pub created_at_ms: u64,
    pub configuration: ConversationConfiguration,
}

impl std::fmt::Debug for ConfigurationRecord {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConfigurationRecord")
            .field("conversation_id", &self.conversation_id)
            .field("configuration_revision", &self.configuration_revision)
            .field(
                "base_configuration_revision",
                &self.base_configuration_revision,
            )
            .field("event_id", &self.event_id)
            .field("event_seq", &self.event_seq)
            .field("created_at_ms", &self.created_at_ms)
            .field("configuration", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConfigureConversationOutcome {
    Applied { configuration: ConfigurationRecord },
    Replayed { configuration: ConfigurationRecord },
    Conflict { current_configuration_revision: u64 },
}

pub(crate) struct PreparedConfigurationRequest {
    conversation_id: RuntimeId,
    expected_configuration_revision: u64,
    request_plaintext: Zeroizing<Vec<u8>>,
}

impl PreparedConfigurationRequest {
    pub(crate) fn retained_capacity(&self) -> Result<usize, RuntimeStoreError> {
        Ok(self.request_plaintext.capacity())
    }
}

fn append_field(message: &mut Vec<u8>, value: &[u8]) {
    message.extend_from_slice(&(value.len() as u64).to_be_bytes());
    message.extend_from_slice(value);
}

fn append_optional_field(message: &mut Vec<u8>, value: Option<&[u8]>) {
    match value {
        None => message.push(0),
        Some(value) => {
            message.push(1);
            append_field(message, value);
        }
    }
}

fn append_request_field(message: &mut Vec<u8>, value: &[u8]) -> Result<(), RuntimeStoreError> {
    let length = u32::try_from(value.len()).map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
    message.extend_from_slice(&length.to_be_bytes());
    message.extend_from_slice(value);
    Ok(())
}

pub(crate) fn prepare_configuration_request(
    input: ConfigureConversation,
) -> Result<PreparedConfigurationRequest, RuntimeStoreError> {
    let ConfigureConversation {
        conversation_id,
        owner,
        idempotency_key,
        expected_configuration_revision,
        configuration,
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
    let configuration_bytes = Zeroizing::new(serde_json::to_vec(&configuration).map_err(|_| {
        RuntimeStoreError::InvalidConfig(
            "conversation configuration must serialize as canonical JSON",
        )
    })?);
    if configuration_bytes.is_empty()
        || configuration_bytes.len() > MAX_CONFIGURATION_CANONICAL_BYTES
    {
        return Err(RuntimeStoreError::PayloadTooLarge);
    }
    let owner_bytes = Zeroizing::new(super::journal::canonical_owner_v1(&owner));
    let expected_revision = encode_sequence(expected_configuration_revision);
    let mut request_plaintext = Vec::with_capacity(
        4 + 5 * 4
            + conversation_id.as_bytes().len()
            + owner_bytes.len()
            + idempotency_key.len()
            + expected_revision.len()
            + configuration_bytes.len(),
    );
    request_plaintext.extend_from_slice(CONFIGURATION_REQUEST_MAGIC);
    append_request_field(&mut request_plaintext, conversation_id.as_bytes())?;
    append_request_field(&mut request_plaintext, owner_bytes.as_ref())?;
    append_request_field(&mut request_plaintext, idempotency_key.as_bytes())?;
    append_request_field(&mut request_plaintext, expected_revision.as_bytes())?;
    append_request_field(&mut request_plaintext, configuration_bytes.as_ref())?;
    if request_plaintext.len() > MAX_CONFIGURATION_REQUEST_BYTES {
        return Err(RuntimeStoreError::PayloadTooLarge);
    }
    Ok(PreparedConfigurationRequest {
        conversation_id,
        expected_configuration_revision,
        request_plaintext: Zeroizing::new(request_plaintext),
    })
}

fn decode_configuration_request(plaintext: &[u8]) -> Result<[&[u8]; 5], RuntimeStoreError> {
    if plaintext.get(..4) != Some(CONFIGURATION_REQUEST_MAGIC) {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let mut cursor = 4_usize;
    let mut fields = Vec::with_capacity(5);
    for _ in 0..5 {
        let length_end = cursor
            .checked_add(4)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        let length = u32::from_be_bytes(
            plaintext
                .get(cursor..length_end)
                .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?
                .try_into()
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
        );
        cursor = length_end;
        let length =
            usize::try_from(length).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
        let field_end = cursor
            .checked_add(length)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        fields.push(
            plaintext
                .get(cursor..field_end)
                .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?,
        );
        cursor = field_end;
    }
    if cursor != plaintext.len() {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    fields
        .try_into()
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)
}

fn configuration_idempotency_token(
    key_bundle: &RuntimeKeyBundle,
    conversation_id: RuntimeId,
    owner_bytes: &[u8],
    idempotency_key: &[u8],
) -> Result<[u8; 32], RuntimeStoreError> {
    let mut message =
        Vec::with_capacity(4 + 3 * 4 + 16 + owner_bytes.len() + idempotency_key.len());
    message.extend_from_slice(b"ADF1");
    append_request_field(&mut message, conversation_id.as_bytes())?;
    append_request_field(&mut message, owner_bytes)?;
    append_request_field(&mut message, idempotency_key)?;
    Ok(*key_bundle
        .blind_index(CONFIGURATION_IDEMPOTENCY_DOMAIN, &message)?
        .as_bytes())
}

fn configuration_primary_key(
    conversation_id: RuntimeId,
    revision: &str,
    idempotency_token: &[u8; 32],
) -> Vec<u8> {
    let mut primary_key = Vec::with_capacity(4 + 16 + revision.len() + 32);
    primary_key.extend_from_slice(CONFIGURATION_PRIMARY_KEY_MAGIC);
    primary_key.extend_from_slice(conversation_id.as_bytes());
    primary_key.extend_from_slice(revision.as_bytes());
    primary_key.extend_from_slice(idempotency_token);
    primary_key
}

#[allow(clippy::too_many_arguments)]
fn configuration_metadata_token(
    key_bundle: &RuntimeKeyBundle,
    conversation_id: RuntimeId,
    revision: &str,
    base_revision: &str,
    event_seq: &str,
    owner_token: &[u8; 32],
    idempotency_token: &[u8; 32],
    request_token: &[u8; 32],
    logical_configuration_bytes: u64,
    logical_request_bytes: u64,
    sealed_request_bytes: u64,
    created_at_ms: u64,
) -> Result<[u8; 32], RuntimeStoreError> {
    let configuration_bytes = logical_configuration_bytes.to_be_bytes();
    let request_bytes = logical_request_bytes.to_be_bytes();
    let sealed_bytes = sealed_request_bytes.to_be_bytes();
    let created_at = created_at_ms.to_be_bytes();
    let mut message = Vec::with_capacity(384);
    for field in [
        &conversation_id.as_bytes()[..],
        revision.as_bytes(),
        base_revision.as_bytes(),
        event_seq.as_bytes(),
        &owner_token[..],
        &idempotency_token[..],
        &request_token[..],
        &configuration_bytes[..],
        &request_bytes[..],
        &sealed_bytes[..],
        &created_at[..],
    ] {
        append_field(&mut message, field);
    }
    Ok(*key_bundle
        .blind_index(CONFIGURATION_METADATA_DOMAIN, &message)?
        .as_bytes())
}

fn seal_configuration_request(
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    primary_key: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, RuntimeStoreError> {
    Ok(key_bundle.row_cipher().seal_bounded(
        &RowAad {
            schema_family: RUNTIME_SCHEMA_FAMILY.as_bytes(),
            schema_version: RUNTIME_CRYPTO_CONTEXT_VERSION,
            database_id: &database_id,
            table: CONFIGURATION_TABLE,
            primary_key,
            column: CONFIGURATION_COLUMN,
        },
        plaintext,
        MAX_CONFIGURATION_REQUEST_BYTES,
    )?)
}

fn open_configuration_request(
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    primary_key: &[u8],
    ciphertext: &[u8],
) -> Result<crate::security::SecretBytes, RuntimeStoreError> {
    Ok(key_bundle.row_cipher().open_bounded(
        &RowAad {
            schema_family: RUNTIME_SCHEMA_FAMILY.as_bytes(),
            schema_version: RUNTIME_CRYPTO_CONTEXT_VERSION,
            database_id: &database_id,
            table: CONFIGURATION_TABLE,
            primary_key,
            column: CONFIGURATION_COLUMN,
        },
        ciphertext,
        MAX_CONFIGURATION_REQUEST_BYTES,
    )?)
}

pub(super) fn conversation_state_metadata_token(
    key_bundle: &RuntimeKeyBundle,
    conversation_id: &[u8; 16],
    current_configuration_revision: Option<&str>,
    entry_revision: &str,
    origin_kind: &str,
    origin_namespace: Option<&str>,
    legacy_command_high_water: Option<&str>,
) -> Result<[u8; 32], RuntimeStoreError> {
    let mut message = Vec::with_capacity(192);
    append_field(&mut message, conversation_id);
    append_optional_field(
        &mut message,
        current_configuration_revision.map(str::as_bytes),
    );
    append_field(&mut message, entry_revision.as_bytes());
    append_field(&mut message, origin_kind.as_bytes());
    append_optional_field(&mut message, origin_namespace.map(str::as_bytes));
    append_optional_field(&mut message, legacy_command_high_water.map(str::as_bytes));
    let token = key_bundle.blind_index(CONVERSATION_STATE_DOMAIN, &message)?;
    Ok(*token.as_bytes())
}

#[derive(Clone)]
pub(super) struct AuthenticatedConversationState {
    current_configuration_revision: Option<String>,
    entry_revision: String,
    origin_kind: String,
    origin_namespace: Option<String>,
    legacy_command_high_water: Option<String>,
    metadata_token: [u8; 32],
}

impl AuthenticatedConversationState {
    pub(super) fn current_revision(&self) -> Result<u64, RuntimeStoreError> {
        self.current_configuration_revision
            .as_deref()
            .map(|value| decode_sequence(SequenceScope::ConfigurationRevision, value))
            .transpose()
            .map(Option::unwrap_or_default)
            .map_err(RuntimeStoreError::from)
    }

    pub(super) fn legacy_command_high_water(&self) -> Result<Option<u64>, RuntimeStoreError> {
        self.legacy_command_high_water
            .as_deref()
            .map(|value| decode_sequence(SequenceScope::CommandSeq, value))
            .transpose()
            .map_err(RuntimeStoreError::from)
    }

    pub(super) fn entry_revision(&self) -> Result<u64, RuntimeStoreError> {
        decode_sequence(SequenceScope::EntryRevision, &self.entry_revision)
            .map_err(RuntimeStoreError::from)
    }

    pub(super) fn is_managed(&self) -> bool {
        self.origin_kind == "managed" && self.origin_namespace.is_none()
    }
}

fn fixed_token(value: Vec<u8>) -> Result<[u8; 32], RuntimeStoreError> {
    value
        .try_into()
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)
}

pub(super) fn load_conversation_state(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    conversation_id: RuntimeId,
) -> Result<AuthenticatedConversationState, RuntimeStoreError> {
    let raw = connection
        .query_row(
            "SELECT current_configuration_revision, entry_revision, origin_kind,
                    origin_namespace, legacy_command_high_water, metadata_token
             FROM conversation_state WHERE conversation_id = ?1",
            [&conversation_id.as_bytes()[..]],
            |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                ))
            },
        )
        .map_err(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => RuntimeStoreError::UnknownOrCorruptSchema,
            other => RuntimeStoreError::Sqlite(other),
        })?;
    if let Some(current) = raw.0.as_deref()
        && decode_sequence(SequenceScope::ConfigurationRevision, current)? == 0
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    decode_sequence(SequenceScope::EntryRevision, &raw.1)?;
    if let Some(cutoff) = raw.4.as_deref() {
        decode_sequence(SequenceScope::CommandSeq, cutoff)?;
    }
    if !matches!(
        (raw.2.as_str(), raw.3.as_deref()),
        ("managed", None) | ("nativeProjected", Some(_))
    ) {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let token = fixed_token(raw.5)?;
    let expected = conversation_state_metadata_token(
        key_bundle,
        conversation_id.as_bytes(),
        raw.0.as_deref(),
        &raw.1,
        &raw.2,
        raw.3.as_deref(),
        raw.4.as_deref(),
    )?;
    if token != expected {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(AuthenticatedConversationState {
        current_configuration_revision: raw.0,
        entry_revision: raw.1,
        origin_kind: raw.2,
        origin_namespace: raw.3,
        legacy_command_high_water: raw.4,
        metadata_token: token,
    })
}

#[derive(Clone)]
struct RawConfigurationRow {
    conversation_id: Vec<u8>,
    configuration_revision: String,
    base_configuration_revision: String,
    event_seq: String,
    owner_token: Vec<u8>,
    idempotency_token: Vec<u8>,
    request_token: Vec<u8>,
    logical_configuration_bytes: i64,
    logical_request_bytes: i64,
    created_at_ms: i64,
    metadata_token: Vec<u8>,
    sealed_request: Vec<u8>,
}

fn raw_configuration_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawConfigurationRow> {
    Ok(RawConfigurationRow {
        conversation_id: row.get(0)?,
        configuration_revision: row.get(1)?,
        base_configuration_revision: row.get(2)?,
        event_seq: row.get(3)?,
        owner_token: row.get(4)?,
        idempotency_token: row.get(5)?,
        request_token: row.get(6)?,
        logical_configuration_bytes: row.get(7)?,
        logical_request_bytes: row.get(8)?,
        created_at_ms: row.get(9)?,
        metadata_token: row.get(10)?,
        sealed_request: row.get(11)?,
    })
}

fn query_configuration_row(
    connection: &Connection,
    clause: &str,
    parameter: &[u8],
) -> Result<Option<RawConfigurationRow>, RuntimeStoreError> {
    let sql = format!(
        "SELECT conversation_id, configuration_revision, base_configuration_revision,
                event_seq, owner_token, idempotency_token, request_token,
                logical_configuration_bytes, logical_request_bytes, created_at_ms,
                metadata_token, sealed_request
         FROM configuration_journal WHERE {clause}"
    );
    connection
        .query_row(&sql, [parameter], raw_configuration_row)
        .optional()
        .map_err(RuntimeStoreError::from)
}

fn query_configuration_row_by_event(
    connection: &Connection,
    conversation_id: RuntimeId,
    event_seq: &str,
) -> Result<Option<RawConfigurationRow>, RuntimeStoreError> {
    connection
        .query_row(
            "SELECT conversation_id, configuration_revision, base_configuration_revision,
                    event_seq, owner_token, idempotency_token, request_token,
                    logical_configuration_bytes, logical_request_bytes, created_at_ms,
                    metadata_token, sealed_request
             FROM configuration_journal
             WHERE conversation_id = ?1 AND event_seq = ?2",
            params![&conversation_id.as_bytes()[..], event_seq],
            raw_configuration_row,
        )
        .optional()
        .map_err(RuntimeStoreError::from)
}

fn query_configuration_row_by_revision(
    connection: &Connection,
    conversation_id: RuntimeId,
    configuration_revision: &str,
) -> Result<Option<RawConfigurationRow>, RuntimeStoreError> {
    connection
        .query_row(
            "SELECT conversation_id, configuration_revision, base_configuration_revision,
                    event_seq, owner_token, idempotency_token, request_token,
                    logical_configuration_bytes, logical_request_bytes, created_at_ms,
                    metadata_token, sealed_request
             FROM configuration_journal
             WHERE conversation_id = ?1 AND configuration_revision = ?2",
            params![&conversation_id.as_bytes()[..], configuration_revision],
            raw_configuration_row,
        )
        .optional()
        .map_err(RuntimeStoreError::from)
}

pub(super) fn configuration_row_exists_for_event(
    connection: &Connection,
    conversation_id: RuntimeId,
    event_seq: &str,
) -> Result<bool, RuntimeStoreError> {
    Ok(query_configuration_row_by_event(connection, conversation_id, event_seq)?.is_some())
}

struct AuthenticatedConfigurationRow {
    record: ConfigurationRecord,
    request_token: [u8; 32],
    sealed_bytes: u64,
}

fn authenticate_configuration_row(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    conversation: &ConversationRecord,
    raw: RawConfigurationRow,
) -> Result<AuthenticatedConfigurationRow, RuntimeStoreError> {
    let conversation_id = RuntimeId::from_bytes(
        RuntimeIdKind::Conversation,
        raw.conversation_id
            .as_slice()
            .try_into()
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
    )?;
    let revision = decode_sequence(
        SequenceScope::ConfigurationRevision,
        &raw.configuration_revision,
    )?;
    let base_revision = decode_sequence(
        SequenceScope::ConfigurationRevision,
        &raw.base_configuration_revision,
    )?;
    let event_seq = decode_sequence(SequenceScope::EventSeq, &raw.event_seq)?;
    if revision == 0 || base_revision.checked_add(1) != Some(revision) {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let logical_configuration_bytes = u64::try_from(raw.logical_configuration_bytes)
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let logical_request_bytes = u64::try_from(raw.logical_request_bytes)
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let created_at_ms =
        u64::try_from(raw.created_at_ms).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let owner_token = fixed_token(raw.owner_token)?;
    let idempotency_token = fixed_token(raw.idempotency_token)?;
    let request_token = fixed_token(raw.request_token)?;
    let metadata_token = fixed_token(raw.metadata_token)?;
    let primary_key = configuration_primary_key(
        conversation_id,
        &raw.configuration_revision,
        &idempotency_token,
    );
    let plaintext =
        open_configuration_request(key_bundle, database_id, &primary_key, &raw.sealed_request)?;
    if u64::try_from(plaintext.expose_secret().len())
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
        != logical_request_bytes
        || raw.sealed_request.len()
            != plaintext
                .expose_secret()
                .len()
                .checked_add(ROW_BLOB_V1_OVERHEAD_LEN)
                .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let fields = decode_configuration_request(plaintext.expose_secret())?;
    if fields[0] != conversation_id.as_bytes()
        || fields[2].is_empty()
        || fields[2].len() > MAX_IDEMPOTENCY_KEY_BYTES
        || fields[3].len() != super::sequence::SEQUENCE_TEXT_WIDTH
        || fields[4].is_empty()
        || fields[4].len() > MAX_CONFIGURATION_CANONICAL_BYTES
        || u64::try_from(fields[4].len()).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
            != logical_configuration_bytes
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let expected_revision = decode_sequence(
        SequenceScope::ConfigurationRevision,
        std::str::from_utf8(fields[3]).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
    )?;
    if expected_revision != base_revision || std::str::from_utf8(fields[2]).is_err() {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let owner = super::journal::decode_canonical_owner(fields[1])?;
    let configuration: ConversationConfiguration =
        serde_json::from_slice(fields[4]).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let canonical = Zeroizing::new(
        serde_json::to_vec(&configuration)
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
    );
    if canonical.as_slice() != fields[4] {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    if conversation.conversation_id != conversation_id
        || conversation.descriptor.agent_kind != configuration.agent_kind()
        || created_at_ms < conversation.created_at_ms
        || created_at_ms > conversation.updated_at_ms
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let expected_owner_token = key_bundle.blind_index(CONFIGURATION_OWNER_DOMAIN, fields[1])?;
    let expected_idempotency_token =
        configuration_idempotency_token(key_bundle, conversation_id, fields[1], fields[2])?;
    let expected_request_token =
        key_bundle.blind_index(CONFIGURATION_REQUEST_DOMAIN, plaintext.expose_secret())?;
    let expected_metadata_token = configuration_metadata_token(
        key_bundle,
        conversation_id,
        &raw.configuration_revision,
        &raw.base_configuration_revision,
        &raw.event_seq,
        &owner_token,
        &idempotency_token,
        &request_token,
        logical_configuration_bytes,
        logical_request_bytes,
        u64::try_from(raw.sealed_request.len())
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
        created_at_ms,
    )?;
    if owner_token != *expected_owner_token.as_bytes()
        || idempotency_token != expected_idempotency_token
        || request_token != *expected_request_token.as_bytes()
        || metadata_token != expected_metadata_token
        || super::journal::canonical_owner_v1(&owner) != fields[1]
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let event_id = connection
        .query_row(
            "SELECT event_id FROM event_journal
             WHERE conversation_id = ?1 AND event_seq = ?2",
            params![&conversation_id.as_bytes()[..], &raw.event_seq],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .map_err(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => RuntimeStoreError::UnknownOrCorruptSchema,
            other => RuntimeStoreError::Sqlite(other),
        })?;
    let event_id = RuntimeId::from_bytes(
        RuntimeIdKind::Event,
        event_id
            .as_slice()
            .try_into()
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
    )?;
    let event = super::journal::load_event(connection, key_bundle, database_id, event_id)?;
    if event.command_id.is_some()
        || event.conversation_id != conversation_id
        || event.event_seq != event_seq
        || event.created_at_ms != created_at_ms
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let super::persisted_event::PersistedRuntimeEvent::Canonical(decoded) =
        super::persisted_event::decode_persisted_runtime_event(&event)?
    else {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    };
    let expected_state = ConversationConfigurationState::new(revision, Some(configuration.clone()))
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    match decoded.body {
        RuntimeEventBody::ConfigurationChanged { state } if state == expected_state => {}
        _ => return Err(RuntimeStoreError::UnknownOrCorruptSchema),
    }
    Ok(AuthenticatedConfigurationRow {
        record: ConfigurationRecord {
            conversation_id,
            configuration_revision: revision,
            base_configuration_revision: base_revision,
            event_id,
            event_seq,
            created_at_ms,
            configuration,
        },
        request_token,
        sealed_bytes: u64::try_from(raw.sealed_request.len())
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
    })
}

/// 对单 conversation 的完整 `1...head` configuration chain 做唯一实现的有界认证。
/// snapshot cursor 与 command exact-revision selector 必须共用本函数，避免其中一条
/// 路径漏验 tail/intermediate row、event 单调性或 parent event HWM anchor。
fn load_authenticated_configuration_chain<T>(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    conversation: &ConversationRecord,
    current_revision: u64,
    mut select: impl FnMut(&ConfigurationRecord) -> Option<T>,
) -> Result<Option<T>, RuntimeStoreError> {
    if current_revision > MAX_CONFIGURATIONS_PER_CONVERSATION {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let conversation_id = conversation.conversation_id;
    let mut statement = connection.prepare(
        "SELECT conversation_id, configuration_revision, base_configuration_revision,
                event_seq, owner_token, idempotency_token, request_token,
                logical_configuration_bytes, logical_request_bytes, created_at_ms,
                metadata_token, sealed_request
         FROM configuration_journal
         WHERE conversation_id = ?1
         ORDER BY configuration_revision",
    )?;
    let rows = statement.query_map([&conversation_id.as_bytes()[..]], raw_configuration_row)?;
    let mut next_revision = 1_u64;
    let mut last_event_seq = None;
    let mut selected = None;
    for row in rows {
        if next_revision > MAX_CONFIGURATIONS_PER_CONVERSATION {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        let authenticated = authenticate_configuration_row(
            connection,
            key_bundle,
            database_id,
            conversation,
            row?,
        )?;
        let record = authenticated.record;
        if record.conversation_id != conversation_id
            || record.configuration_revision != next_revision
            || record.base_configuration_revision.checked_add(1) != Some(next_revision)
            || last_event_seq.is_some_and(|previous| record.event_seq <= previous)
        {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        last_event_seq = Some(record.event_seq);
        if let Some(candidate) = select(&record) {
            selected = Some(candidate);
        }
        next_revision = next_revision
            .checked_add(1)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    }
    let authenticated_count = next_revision - 1;
    let chain_is_anchored_to_parent = match (
        current_revision,
        last_event_seq,
        conversation.event_high_water,
    ) {
        (0, None, _) => true,
        (0, Some(_), _) | (_, None, _) | (_, Some(_), None) => false,
        (_, Some(last_configuration_event), Some(parent_event_high_water)) => {
            last_configuration_event <= parent_event_high_water
        }
    };
    if authenticated_count != current_revision || !chain_is_anchored_to_parent {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(selected)
}

/// 在最多 4,096 行的固定上限内认证指定 conversation 的完整 `1...head`
/// append-only chain，并从认证结果中选择 exact historical revision。
///
/// selector 绝不能只验证目标行：head 推进后，旧 command pin 仍必须证明目标行位于
/// 一条连续、单调且锚定到 authenticated conversation event HWM 的完整链中。调用方
/// 必须在自己的 SQLite transaction 内调用，保证 command、pin 与配置来自同一快照。
pub(super) fn load_authenticated_configuration_at_revision(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    conversation_id: RuntimeId,
    configuration_revision: u64,
) -> Result<ConfigurationRecord, RuntimeStoreError> {
    if configuration_revision == 0 {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let conversation =
        super::journal::load_conversation(connection, key_bundle, database_id, conversation_id)?;
    let current_revision =
        load_conversation_state(connection, key_bundle, conversation_id)?.current_revision()?;
    if configuration_revision > current_revision {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    load_authenticated_configuration_chain(
        connection,
        key_bundle,
        database_id,
        &conversation,
        current_revision,
        |record| (record.configuration_revision == configuration_revision).then(|| record.clone()),
    )?
    .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)
}

/// 认证指定 conversation 的 exact current configuration revision，并确认物理
/// journal 行数与该 append-only revision 一致。调用方必须在自己的 SQLite
/// transaction 内调用，避免 admission 把“行存在”误当成 current head 已认证。
pub(super) fn load_authenticated_configuration_revision(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    conversation_id: RuntimeId,
    configuration_revision: u64,
) -> Result<ConfigurationRecord, RuntimeStoreError> {
    if configuration_revision == 0 {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let encoded_revision = encode_sequence(configuration_revision);
    let raw = query_configuration_row_by_revision(connection, conversation_id, &encoded_revision)?
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let conversation =
        super::journal::load_conversation(connection, key_bundle, database_id, conversation_id)?;
    let authenticated =
        authenticate_configuration_row(connection, key_bundle, database_id, &conversation, raw)?;
    let (physical_count, first_revision, last_revision) = connection.query_row(
        "SELECT COUNT(*), MIN(configuration_revision), MAX(configuration_revision)
         FROM configuration_journal WHERE conversation_id = ?1",
        [&conversation_id.as_bytes()[..]],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, Option<String>>(2)?,
            ))
        },
    )?;
    let physical_count =
        u64::try_from(physical_count).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let first_revision = first_revision
        .as_deref()
        .map(|value| decode_sequence(SequenceScope::ConfigurationRevision, value))
        .transpose()?
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let last_revision = last_revision
        .as_deref()
        .map(|value| decode_sequence(SequenceScope::ConfigurationRevision, value))
        .transpose()?
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    if authenticated.record.conversation_id != conversation_id
        || authenticated.record.configuration_revision != configuration_revision
        || physical_count != configuration_revision
        || first_revision != 1
        || last_revision != configuration_revision
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(authenticated.record)
}

fn try_replay_configuration(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    conversation_id: RuntimeId,
    idempotency_token: &[u8; 32],
    request_token: &[u8; 32],
) -> Result<Option<ConfigurationRecord>, RuntimeStoreError> {
    let Some(raw) =
        query_configuration_row(connection, "idempotency_token = ?1", idempotency_token)?
    else {
        return Ok(None);
    };
    let conversation =
        super::journal::load_conversation(connection, key_bundle, database_id, conversation_id)?;
    let authenticated =
        authenticate_configuration_row(connection, key_bundle, database_id, &conversation, raw)?;
    if authenticated.request_token != *request_token {
        return Err(RuntimeStoreError::IdempotencyConflict);
    }
    let current =
        load_conversation_state(connection, key_bundle, conversation_id)?.current_revision()?;
    if current < authenticated.record.configuration_revision
        || configuration_count_for_conversation(connection, conversation_id)? != current
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(Some(authenticated.record))
}

fn configuration_count_for_conversation(
    connection: &Connection,
    conversation_id: RuntimeId,
) -> Result<u64, RuntimeStoreError> {
    let count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM configuration_journal WHERE conversation_id = ?1",
        [&conversation_id.as_bytes()[..]],
        |row| row.get(0),
    )?;
    u64::try_from(count).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)
}

/// 读取 frozen event cursor 对应的最新 configuration。每次读取都对最多 4,096
/// 条 append-only journal 做完整有界认证；current head 只参与完整性判断，绝不能
/// 作为 selector 的返回值。
pub(super) fn load_configuration_state_at_event_cursor(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    conversation_id: RuntimeId,
    base_event_seq: Option<u64>,
) -> Result<ConversationConfigurationState, RuntimeStoreError> {
    let conversation =
        super::journal::load_conversation(connection, key_bundle, database_id, conversation_id)?;
    let current_revision =
        load_conversation_state(connection, key_bundle, conversation_id)?.current_revision()?;
    if base_event_seq.is_some_and(|base_event_seq| {
        conversation
            .event_high_water
            .is_none_or(|event_high_water| base_event_seq > event_high_water)
    }) {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }

    let selected = load_authenticated_configuration_chain(
        connection,
        key_bundle,
        database_id,
        &conversation,
        current_revision,
        |record| {
            base_event_seq
                .is_some_and(|base| record.event_seq <= base)
                .then(|| (record.configuration_revision, record.configuration.clone()))
        },
    )?;
    let (revision, configuration) = selected
        .map(|(revision, configuration)| (revision, Some(configuration)))
        .unwrap_or((0, None));
    ConversationConfigurationState::new(revision, configuration)
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)
}

fn ensure_configuration_capacity(
    ledger: &RuntimeLedger,
    conversation_count: u64,
    new_sealed_bytes: u64,
) -> Result<(), RuntimeStoreError> {
    if conversation_count >= MAX_CONFIGURATIONS_PER_CONVERSATION {
        return Err(RuntimeStoreError::ConfigurationLimit {
            scope: ConfigurationLimitScope::Conversation,
        });
    }
    if ledger.configuration_count >= MAX_CONFIGURATIONS_GLOBAL {
        return Err(RuntimeStoreError::ConfigurationLimit {
            scope: ConfigurationLimitScope::GlobalCount,
        });
    }
    if ledger
        .configuration_sealed_bytes
        .checked_add(new_sealed_bytes)
        .is_none_or(|value| value > MAX_CONFIGURATION_SEALED_BYTES_GLOBAL)
    {
        return Err(RuntimeStoreError::ConfigurationLimit {
            scope: ConfigurationLimitScope::GlobalSealedBytes,
        });
    }
    Ok(())
}

struct DecodedConfigurationInput {
    conversation_id: RuntimeId,
    expected_configuration_revision: u64,
    configuration: ConversationConfiguration,
}

fn validate_configuration_preflight(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    input: &DecodedConfigurationInput,
    ledger: &RuntimeLedger,
    new_sealed_bytes: u64,
) -> Result<Result<(ConversationRecord, AuthenticatedConversationState), u64>, RuntimeStoreError> {
    let conversation = super::journal::load_conversation(
        connection,
        key_bundle,
        database_id,
        input.conversation_id,
    )?;
    if conversation.descriptor.agent_kind != input.configuration.agent_kind() {
        return Err(RuntimeStoreError::ConfigurationAgentMismatch);
    }
    let state = load_conversation_state(connection, key_bundle, input.conversation_id)?;
    let current = state.current_revision()?;
    let conversation_count =
        configuration_count_for_conversation(connection, input.conversation_id)?;
    if conversation_count != current {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    if input.expected_configuration_revision != current {
        return Ok(Err(current));
    }
    ensure_configuration_capacity(ledger, conversation_count, new_sealed_bytes)?;
    if let Some(event_high_water) = conversation.event_high_water {
        let encoded = encode_sequence(event_high_water);
        let event_id = connection
            .query_row(
                "SELECT event_id FROM event_journal
                 WHERE conversation_id = ?1 AND event_seq = ?2",
                params![&input.conversation_id.as_bytes()[..], encoded],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .map_err(|error| match error {
                rusqlite::Error::QueryReturnedNoRows => RuntimeStoreError::UnknownOrCorruptSchema,
                other => RuntimeStoreError::Sqlite(other),
            })?;
        let event_id = RuntimeId::from_bytes(
            RuntimeIdKind::Event,
            event_id
                .as_slice()
                .try_into()
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
        )?;
        let event = super::journal::load_event(connection, key_bundle, database_id, event_id)?;
        if event.created_at_ms > conversation.updated_at_ms {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
    }
    Ok(Ok((conversation, state)))
}

fn update_configuration_head(
    transaction: &Transaction<'_>,
    key_bundle: &RuntimeKeyBundle,
    conversation_id: RuntimeId,
    state: &AuthenticatedConversationState,
    next_revision: &str,
) -> Result<(), RuntimeStoreError> {
    let next_token = conversation_state_metadata_token(
        key_bundle,
        conversation_id.as_bytes(),
        Some(next_revision),
        &state.entry_revision,
        &state.origin_kind,
        state.origin_namespace.as_deref(),
        state.legacy_command_high_water.as_deref(),
    )?;
    if transaction.execute(
        "UPDATE conversation_state
         SET current_configuration_revision = ?1, metadata_token = ?2
         WHERE conversation_id = ?3
           AND ((?4 IS NULL AND current_configuration_revision IS NULL)
                OR current_configuration_revision = ?4)
           AND metadata_token = ?5",
        params![
            next_revision,
            &next_token[..],
            &conversation_id.as_bytes()[..],
            state.current_configuration_revision.as_deref(),
            &state.metadata_token[..],
        ],
    )? != 1
    {
        return Err(RuntimeStoreError::SchemaInspectionRaced);
    }
    Ok(())
}

pub(super) fn advance_entry_revision(
    transaction: &Transaction<'_>,
    key_bundle: &RuntimeKeyBundle,
    conversation_id: RuntimeId,
    state: &AuthenticatedConversationState,
    next_revision: &str,
) -> Result<(), RuntimeStoreError> {
    let current_revision = state.entry_revision()?;
    let next_revision_value = decode_sequence(SequenceScope::EntryRevision, next_revision)?;
    if current_revision.checked_add(1) != Some(next_revision_value) {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }
    let next_token = conversation_state_metadata_token(
        key_bundle,
        conversation_id.as_bytes(),
        state.current_configuration_revision.as_deref(),
        next_revision,
        &state.origin_kind,
        state.origin_namespace.as_deref(),
        state.legacy_command_high_water.as_deref(),
    )?;
    if transaction.execute(
        "UPDATE conversation_state
         SET entry_revision = ?1, metadata_token = ?2
         WHERE conversation_id = ?3 AND entry_revision = ?4 AND metadata_token = ?5",
        params![
            next_revision,
            &next_token[..],
            &conversation_id.as_bytes()[..],
            &state.entry_revision,
            &state.metadata_token[..],
        ],
    )? != 1
    {
        return Err(RuntimeStoreError::SchemaInspectionRaced);
    }
    Ok(())
}

fn seal_configuration_event(
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    event_id: RuntimeId,
    payload: &[u8],
) -> Result<Vec<u8>, RuntimeStoreError> {
    Ok(key_bundle.row_cipher().seal_bounded(
        &RowAad {
            schema_family: RUNTIME_SCHEMA_FAMILY.as_bytes(),
            schema_version: RUNTIME_CRYPTO_CONTEXT_VERSION,
            database_id: &database_id,
            table: b"event_journal",
            primary_key: event_id.as_bytes(),
            column: b"sealed_event",
        },
        payload,
        MAX_RUNTIME_EVENT_BYTES,
    )?)
}

pub(crate) fn configure_conversation(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    prepared: PreparedConfigurationRequest,
    effects: &mut CommandStreamEffects,
) -> Result<ConfigureConversationOutcome, RuntimeStoreError> {
    let request_fields = decode_configuration_request(prepared.request_plaintext.as_ref())?;
    if request_fields[0] != prepared.conversation_id.as_bytes() {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let encoded_expected_revision = std::str::from_utf8(request_fields[3])
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    if decode_sequence(
        SequenceScope::ConfigurationRevision,
        encoded_expected_revision,
    )? != prepared.expected_configuration_revision
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let input = DecodedConfigurationInput {
        conversation_id: prepared.conversation_id,
        expected_configuration_revision: prepared.expected_configuration_revision,
        configuration: serde_json::from_slice(request_fields[4])
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
    };
    let owner_token = state
        .key_bundle
        .blind_index(CONFIGURATION_OWNER_DOMAIN, request_fields[1])?;
    let idempotency_token = configuration_idempotency_token(
        &state.key_bundle,
        input.conversation_id,
        request_fields[1],
        request_fields[2],
    )?;
    let request_token = state.key_bundle.blind_index(
        CONFIGURATION_REQUEST_DOMAIN,
        prepared.request_plaintext.as_ref(),
    )?;
    let projected_sealed_bytes = prepared
        .request_plaintext
        .len()
        .checked_add(ROW_BLOB_V1_OVERHEAD_LEN)
        .and_then(|value| u64::try_from(value).ok())
        .ok_or(RuntimeStoreError::CapacityArithmeticOverflow {
            field: "configuration sealed request bytes",
        })?;
    let preflight_ledger = super::sqlite::load_runtime_ledger(
        &state.connection,
        &state.key_bundle,
        state.database_id,
    )?;
    if let Some(configuration) = try_replay_configuration(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        input.conversation_id,
        &idempotency_token,
        request_token.as_bytes(),
    )? {
        return Ok(ConfigureConversationOutcome::Replayed { configuration });
    }
    if let Err(current_configuration_revision) = validate_configuration_preflight(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        &input,
        &preflight_ledger,
        projected_sealed_bytes,
    )? {
        return Ok(ConfigureConversationOutcome::Conflict {
            current_configuration_revision,
        });
    }
    let projected_write_bytes = super::journal::projected_write_bytes(&[
        usize::try_from(projected_sealed_bytes).map_err(|_| RuntimeStoreError::PayloadTooLarge)?,
        request_fields[4]
            .len()
            .checked_add(2 * 1024)
            .ok_or(RuntimeStoreError::PayloadTooLarge)?,
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
    let trim_now_ms = config.clock.now_ms().map_err(RuntimeStoreError::from)?;

    let transaction = state
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let ledger =
        super::sqlite::load_runtime_ledger(&transaction, &state.key_bundle, state.database_id)?;
    if let Some(configuration) = try_replay_configuration(
        &transaction,
        &state.key_bundle,
        state.database_id,
        input.conversation_id,
        &idempotency_token,
        request_token.as_bytes(),
    )? {
        return Ok(ConfigureConversationOutcome::Replayed { configuration });
    }
    let (conversation, conversation_state) = match validate_configuration_preflight(
        &transaction,
        &state.key_bundle,
        state.database_id,
        &input,
        &ledger,
        projected_sealed_bytes,
    )? {
        Ok(value) => value,
        Err(current_configuration_revision) => {
            return Ok(ConfigureConversationOutcome::Conflict {
                current_configuration_revision,
            });
        }
    };
    let base_revision = conversation_state.current_revision()?;
    let base_revision_encoded = encode_sequence(base_revision);
    let revision =
        base_revision
            .checked_add(1)
            .ok_or(super::sequence::SequenceError::Exhausted {
                scope: SequenceScope::ConfigurationRevision,
            })?;
    let revision_encoded = encode_sequence(revision);
    let previous_event = conversation.event_high_water.map(encode_sequence);
    let event_seq = next_sequence(SequenceScope::EventSeq, previous_event.as_deref())?;
    let event_id = super::journal::allocate_id(&transaction, config, RuntimeIdKind::Event)?;
    let configuration_state =
        ConversationConfigurationState::new(revision, Some(input.configuration.clone())).map_err(
            |_| RuntimeStoreError::InvalidConfig("invalid conversation configuration state"),
        )?;
    let event = RuntimeEvent::new(
        ConversationId::new(input.conversation_id.to_canonical_string()),
        EventId::new(event_id.to_canonical_string()),
        event_seq.value,
        None,
        None,
        None,
        RuntimeEventBody::ConfigurationChanged {
            state: configuration_state,
        },
    )
    .map_err(|_| RuntimeStoreError::InvalidConfig("invalid configuration event identity"))?;
    let event_payload =
        Zeroizing::new(serde_json::to_vec(&event).map_err(|_| {
            RuntimeStoreError::InvalidConfig("configuration event is not canonical")
        })?);
    if event_payload.len() > MAX_RUNTIME_EVENT_BYTES {
        return Err(RuntimeStoreError::PayloadTooLarge);
    }
    let sealed_event = seal_configuration_event(
        &state.key_bundle,
        state.database_id,
        event_id,
        event_payload.as_ref(),
    )?;
    let primary_key =
        configuration_primary_key(input.conversation_id, &revision_encoded, &idempotency_token);
    let sealed_request = seal_configuration_request(
        &state.key_bundle,
        state.database_id,
        &primary_key,
        prepared.request_plaintext.as_ref(),
    )?;
    if u64::try_from(sealed_request.len()).map_err(|_| RuntimeStoreError::PayloadTooLarge)?
        != projected_sealed_bytes
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let created_at_ms = conversation.updated_at_ms;
    let created_at = i64::try_from(created_at_ms).map_err(|_| RuntimeStoreError::TimeOutOfRange)?;
    let logical_event_bytes =
        u64::try_from(event_payload.len()).map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
    let logical_configuration_bytes =
        u64::try_from(request_fields[4].len()).map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
    let logical_request_bytes = u64::try_from(prepared.request_plaintext.len())
        .map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
    let event_metadata_token = super::journal::event_metadata_token(
        &state.key_bundle,
        input.conversation_id,
        event_id,
        event_seq.value,
        None,
        logical_event_bytes,
        created_at_ms,
    )?;
    let configuration_metadata_token = configuration_metadata_token(
        &state.key_bundle,
        input.conversation_id,
        &revision_encoded,
        &base_revision_encoded,
        &event_seq.encoded,
        owner_token.as_bytes(),
        &idempotency_token,
        request_token.as_bytes(),
        logical_configuration_bytes,
        logical_request_bytes,
        projected_sealed_bytes,
        created_at_ms,
    )?;
    transaction.execute(
        "INSERT INTO event_journal (
             conversation_id, event_seq, event_id, command_id,
             logical_event_bytes, created_at_ms, metadata_token, sealed_event
         ) VALUES (?1, ?2, ?3, NULL, ?4, ?5, ?6, ?7)",
        params![
            &input.conversation_id.as_bytes()[..],
            &event_seq.encoded,
            &event_id.as_bytes()[..],
            i64::try_from(logical_event_bytes).map_err(|_| RuntimeStoreError::PayloadTooLarge)?,
            created_at,
            &event_metadata_token[..],
            sealed_event,
        ],
    )?;
    transaction.execute(
        "INSERT INTO configuration_journal (
             conversation_id, configuration_revision, base_configuration_revision,
             event_seq, owner_token, idempotency_token, request_token,
             logical_configuration_bytes, logical_request_bytes, created_at_ms,
             metadata_token, sealed_request
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        params![
            &input.conversation_id.as_bytes()[..],
            &revision_encoded,
            &base_revision_encoded,
            &event_seq.encoded,
            &owner_token.as_bytes()[..],
            &idempotency_token[..],
            &request_token.as_bytes()[..],
            i64::try_from(logical_configuration_bytes)
                .map_err(|_| RuntimeStoreError::PayloadTooLarge)?,
            i64::try_from(logical_request_bytes).map_err(|_| RuntimeStoreError::PayloadTooLarge)?,
            created_at,
            &configuration_metadata_token[..],
            sealed_request,
        ],
    )?;
    super::journal::update_conversation_event_high_water_preserving_activity(
        &transaction,
        input.conversation_id,
        &event_seq.encoded,
        previous_event.as_deref(),
        &state.key_bundle,
        state.database_id,
    )?;
    update_configuration_head(
        &transaction,
        &state.key_bundle,
        input.conversation_id,
        &conversation_state,
        &revision_encoded,
    )?;
    let mut next_ledger = ledger.clone();
    next_ledger.event_count = next_ledger
        .event_count
        .checked_add(1)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    next_ledger.configuration_count = next_ledger
        .configuration_count
        .checked_add(1)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    next_ledger.configuration_sealed_bytes = next_ledger
        .configuration_sealed_bytes
        .checked_add(projected_sealed_bytes)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let pending_targets = super::sqlite::update_runtime_ledger_with_trim_clock(
        &transaction,
        &state.key_bundle,
        state.database_id,
        &ledger,
        &next_ledger,
        trim_now_ms,
    )?;
    config
        .fault_injector
        .before_operation(RuntimeStoreOperation::ConfigureConversationBeforeCommit)?;
    let commit_result = super::sqlite::commit_transaction(
        transaction,
        RuntimeCommitOperation::ConfigureConversation,
    );
    effects.record_commit_result(pending_targets, &commit_result);
    commit_result?;
    super::sqlite::latch_post_commit_capacity(state, config);
    if config
        .fault_injector
        .before_operation(RuntimeStoreOperation::ConfigureConversationAfterCommit)
        .is_err()
    {
        return Err(RuntimeStoreError::CommitOutcomeUnknown {
            operation: RuntimeCommitOperation::ConfigureConversation,
        });
    }
    Ok(ConfigureConversationOutcome::Applied {
        configuration: ConfigurationRecord {
            conversation_id: input.conversation_id,
            configuration_revision: revision,
            base_configuration_revision: base_revision,
            event_id,
            event_seq: event_seq.value,
            created_at_ms,
            configuration: input.configuration,
        },
    })
}

pub(super) fn migration_projection_bytes(
    conversation_count: u64,
) -> Result<u64, RuntimeStoreError> {
    if conversation_count > MAX_RUNTIME_CONVERSATIONS {
        return Err(RuntimeStoreError::ConversationLimit);
    }
    V5_SCHEMA_FIXED_PROJECTION_BYTES
        .checked_add(
            conversation_count
                .checked_mul(V5_STATE_ROW_PROJECTION_BYTES)
                .ok_or(RuntimeStoreError::CapacityArithmeticOverflow {
                    field: "v5 conversation state projection bytes",
                })?,
        )
        .ok_or(RuntimeStoreError::CapacityArithmeticOverflow {
            field: "v5 migration projection bytes",
        })
}

pub(super) fn insert_fresh_managed_state(
    transaction: &Transaction<'_>,
    key_bundle: &RuntimeKeyBundle,
    conversation_id: &[u8; 16],
) -> Result<(), RuntimeStoreError> {
    insert_managed_state(transaction, key_bundle, conversation_id, None)
}

fn insert_managed_state(
    transaction: &Transaction<'_>,
    key_bundle: &RuntimeKeyBundle,
    conversation_id: &[u8; 16],
    legacy_command_high_water: Option<&str>,
) -> Result<(), RuntimeStoreError> {
    if let Some(cutoff) = legacy_command_high_water {
        decode_sequence(SequenceScope::CommandSeq, cutoff)?;
    }
    let entry_revision = encode_sequence(0);
    let metadata_token = conversation_state_metadata_token(
        key_bundle,
        conversation_id,
        None,
        &entry_revision,
        "managed",
        None,
        legacy_command_high_water,
    )?;
    transaction.execute(
        "INSERT INTO conversation_state (
             conversation_id, current_configuration_revision, entry_revision,
             origin_kind, origin_namespace, legacy_command_high_water, metadata_token
         ) VALUES (?1, NULL, ?2, 'managed', NULL, ?3, ?4)",
        params![
            &conversation_id[..],
            entry_revision,
            legacy_command_high_water,
            &metadata_token[..],
        ],
    )?;
    Ok(())
}

pub(super) fn materialize_legacy_v4_states(
    transaction: &Transaction<'_>,
    key_bundle: &RuntimeKeyBundle,
    ledger: &RuntimeLedger,
) -> Result<(), RuntimeStoreError> {
    migration_projection_bytes(ledger.conversation_count)?;
    let rows = transaction
        .prepare(
            "SELECT conversation_id, command_high_water
             FROM conversations ORDER BY conversation_id",
        )?
        .query_map([], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Option<String>>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    if u64::try_from(rows.len()).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
        != ledger.conversation_count
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    for (conversation_id, legacy_command_high_water) in rows {
        let conversation_id: [u8; 16] = conversation_id
            .try_into()
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
        insert_managed_state(
            transaction,
            key_bundle,
            &conversation_id,
            legacy_command_high_water.as_deref(),
        )?;
    }
    Ok(())
}

fn all_v5_totals_are_zero(ledger: &RuntimeLedger) -> bool {
    ledger.configuration_count == 0
        && ledger.configuration_sealed_bytes == 0
        && ledger.command_configuration_pin_count == 0
        && ledger.metadata_mutation_count == 0
        && ledger.active_metadata_mutation_count == 0
        && ledger.metadata_mutation_charged_bytes == 0
}

pub(super) fn validate_v5_integrity(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    ledger: &RuntimeLedger,
) -> Result<u64, RuntimeStoreError> {
    let version: u32 = connection
        .query_row(
            "SELECT schema_version FROM runtime_meta WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    if version < 5 {
        return if all_v5_totals_are_zero(ledger) {
            Ok(0)
        } else {
            Err(RuntimeStoreError::UnknownOrCorruptSchema)
        };
    }
    if version != 5 {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }

    let mut statement = connection.prepare(
        "SELECT conversation_id, current_configuration_revision, entry_revision,
                origin_kind, origin_namespace, legacy_command_high_water, metadata_token
         FROM conversation_state ORDER BY conversation_id",
    )?;
    let mapped = statement.query_map([], |row| {
        Ok((
            row.get::<_, Vec<u8>>(0)?,
            row.get::<_, Option<String>>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, Option<String>>(4)?,
            row.get::<_, Option<String>>(5)?,
            row.get::<_, Vec<u8>>(6)?,
        ))
    })?;
    let state_limit = usize::try_from(MAX_RUNTIME_CONVERSATIONS)
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let mut rows = Vec::with_capacity(state_limit);
    for row in mapped {
        if rows.len() == state_limit {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        rows.push(row?);
    }
    if u64::try_from(rows.len()).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
        != ledger.conversation_count
        || ledger.conversation_count > MAX_RUNTIME_CONVERSATIONS
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let mut authenticated_configuration_count = 0_u64;
    let mut authenticated_sealed_bytes = 0_u64;
    for (conversation_id, current, entry, origin, namespace, cutoff, token) in rows {
        let conversation_id: [u8; 16] = conversation_id
            .try_into()
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
        let current_revision = current
            .as_deref()
            .map(|value| decode_sequence(SequenceScope::ConfigurationRevision, value))
            .transpose()?
            .unwrap_or_default();
        if current.is_some() && current_revision == 0 {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        decode_sequence(SequenceScope::EntryRevision, &entry)?;
        let cutoff_value = cutoff
            .as_deref()
            .map(|value| decode_sequence(SequenceScope::CommandSeq, value))
            .transpose()?;
        if !matches!(
            (origin.as_str(), namespace.as_deref()),
            ("managed", None) | ("nativeProjected", Some(_))
        ) || origin == "nativeProjected" && cutoff.is_some()
        {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        let expected = conversation_state_metadata_token(
            key_bundle,
            &conversation_id,
            current.as_deref(),
            &entry,
            &origin,
            namespace.as_deref(),
            cutoff.as_deref(),
        )?;
        if token.as_slice() != expected {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        let conversation_id = RuntimeId::from_bytes(RuntimeIdKind::Conversation, conversation_id)?;
        let conversation =
            super::journal::load_conversation(connection, key_bundle, database_id, conversation_id)
                .map_err(|error| match error {
                    RuntimeStoreError::ConversationNotFound => {
                        RuntimeStoreError::UnknownOrCorruptSchema
                    }
                    other => other,
                })?;
        if cutoff_value.is_some_and(|cutoff| {
            conversation
                .command_high_water
                .is_none_or(|high_water| high_water < cutoff)
        }) {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        let mut statement = connection.prepare(
            "SELECT conversation_id, configuration_revision, base_configuration_revision,
                    event_seq, owner_token, idempotency_token, request_token,
                    logical_configuration_bytes, logical_request_bytes, created_at_ms,
                    metadata_token, sealed_request
             FROM configuration_journal
             WHERE conversation_id = ?1
             ORDER BY configuration_revision",
        )?;
        let configuration_rows =
            statement.query_map([&conversation_id.as_bytes()[..]], raw_configuration_row)?;
        let mut next_revision = 1_u64;
        let mut last_event_seq = None;
        for row in configuration_rows {
            let authenticated = authenticate_configuration_row(
                connection,
                key_bundle,
                database_id,
                &conversation,
                row?,
            )?;
            if authenticated.record.conversation_id != conversation_id
                || authenticated.record.configuration_revision != next_revision
                || authenticated.record.base_configuration_revision + 1 != next_revision
                || last_event_seq.is_some_and(|previous| authenticated.record.event_seq <= previous)
            {
                return Err(RuntimeStoreError::UnknownOrCorruptSchema);
            }
            last_event_seq = Some(authenticated.record.event_seq);
            next_revision = next_revision
                .checked_add(1)
                .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
            authenticated_configuration_count = authenticated_configuration_count
                .checked_add(1)
                .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
            authenticated_sealed_bytes = authenticated_sealed_bytes
                .checked_add(authenticated.sealed_bytes)
                .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        }
        let conversation_configuration_count = next_revision - 1;
        if conversation_configuration_count != current_revision
            || conversation_configuration_count > MAX_CONFIGURATIONS_PER_CONVERSATION
        {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
    }
    let authenticated_pin_count =
        super::command_configuration::validate_v5_integrity(connection, key_bundle, ledger)?;
    super::metadata::validate_v5_integrity(connection, key_bundle, database_id, ledger)?;
    let missing_states: i64 = connection.query_row(
        "SELECT COUNT(*) FROM conversations AS c
         LEFT JOIN conversation_state AS s USING (conversation_id)
         WHERE s.conversation_id IS NULL",
        [],
        |row| row.get(0),
    )?;
    let physical: (i64, i64, i64) = connection.query_row(
        "SELECT
             (SELECT COUNT(*) FROM configuration_journal),
             (SELECT COALESCE(SUM(length(sealed_request)), 0) FROM configuration_journal),
             (SELECT COUNT(*) FROM command_configuration_pins)",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    let physical_configuration_count =
        u64::try_from(physical.0).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let physical_configuration_bytes =
        u64::try_from(physical.1).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let physical_pin_count =
        u64::try_from(physical.2).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    if missing_states != 0
        || physical_configuration_count != authenticated_configuration_count
        || physical_configuration_bytes != authenticated_sealed_bytes
        || physical_pin_count != authenticated_pin_count
        || ledger.configuration_count != authenticated_configuration_count
        || ledger.configuration_sealed_bytes != authenticated_sealed_bytes
        || authenticated_configuration_count > MAX_CONFIGURATIONS_GLOBAL
        || authenticated_sealed_bytes > MAX_CONFIGURATION_SEALED_BYTES_GLOBAL
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(authenticated_configuration_count)
}

#[cfg(test)]
mod tests {
    use agentdeck_protocol::ClaudeCodePermissionMode;
    use agentdeck_protocol::runtime::{
        ClaudeCodeConversationConfiguration, VendorConfigurationSnapshot,
    };

    use super::*;

    #[test]
    fn configuration_capacity_accepts_exact_limits_and_rejects_one_past_each_scope() {
        let exact_new_bytes = 123;
        let mut exact = RuntimeLedger {
            configuration_count: MAX_CONFIGURATIONS_GLOBAL - 1,
            configuration_sealed_bytes: MAX_CONFIGURATION_SEALED_BYTES_GLOBAL - exact_new_bytes,
            ..RuntimeLedger::default()
        };
        ensure_configuration_capacity(
            &exact,
            MAX_CONFIGURATIONS_PER_CONVERSATION - 1,
            exact_new_bytes,
        )
        .expect("last legal configuration must reach every exact cap");

        assert!(matches!(
            ensure_configuration_capacity(
                &RuntimeLedger::default(),
                MAX_CONFIGURATIONS_PER_CONVERSATION,
                0,
            ),
            Err(RuntimeStoreError::ConfigurationLimit {
                scope: ConfigurationLimitScope::Conversation,
            })
        ));
        exact.configuration_count = MAX_CONFIGURATIONS_GLOBAL;
        exact.configuration_sealed_bytes = 0;
        assert!(matches!(
            ensure_configuration_capacity(&exact, 0, 0),
            Err(RuntimeStoreError::ConfigurationLimit {
                scope: ConfigurationLimitScope::GlobalCount,
            })
        ));
        exact.configuration_count = 0;
        exact.configuration_sealed_bytes = MAX_CONFIGURATION_SEALED_BYTES_GLOBAL;
        assert!(matches!(
            ensure_configuration_capacity(&exact, 0, 1),
            Err(RuntimeStoreError::ConfigurationLimit {
                scope: ConfigurationLimitScope::GlobalSealedBytes,
            })
        ));
        exact.configuration_sealed_bytes = u64::MAX;
        assert!(matches!(
            ensure_configuration_capacity(&exact, 0, 1),
            Err(RuntimeStoreError::ConfigurationLimit {
                scope: ConfigurationLimitScope::GlobalSealedBytes,
            })
        ));
    }

    #[test]
    fn prepared_request_drops_large_caller_capacities_before_worker_admission() {
        fn short_value_with_large_capacity(value: &str) -> String {
            let mut retained = String::with_capacity(1024 * 1024);
            retained.push_str(value);
            retained
        }

        let configuration =
            ConversationConfiguration::new(VendorConfigurationSnapshot::ClaudeCode(
                ClaudeCodeConversationConfiguration::new(
                    ClaudeCodePermissionMode::Default,
                    Some(short_value_with_large_capacity("m")),
                    Some(short_value_with_large_capacity("e")),
                    Some(short_value_with_large_capacity("o")),
                )
                .expect("short Claude fields are valid"),
            ));
        let prepared = prepare_configuration_request(ConfigureConversation {
            conversation_id: RuntimeId::from_bytes(RuntimeIdKind::Conversation, [0x61; 16])
                .expect("conversation id"),
            owner: IdempotencyOwner::Local {
                machine_trust_domain: [0x62; 32],
                uid: 501,
                client_installation_id: [0x63; 16],
            },
            idempotency_key: short_value_with_large_capacity("k"),
            expected_configuration_revision: 0,
            configuration,
        })
        .expect("prepare canonical request");
        assert_eq!(
            prepared.retained_capacity().expect("retained capacity"),
            prepared.request_plaintext.capacity()
        );
        assert!(prepared.request_plaintext.capacity() < MAX_CONFIGURATION_REQUEST_BYTES);
    }
}
