//! Runtime v5 conversation metadata mutation ledger。
//!
//! managed conversation 的 rename/archive 在单一 SQLite transaction 内直接写入
//! terminal `applied` 行，并同步推进 authenticated entry/catalog revision。native
//! mutation 的 durable state shape 与迁移矩阵也在这里统一认证；vendor 副作用接线
//! 属于后续 projector task。

use std::collections::BTreeMap;

use agentdeck_protocol::AgentKind;
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
use crate::runtime::adapter_state::AdapterStateNamespace;

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
const MAX_NATIVE_METADATA_RECOVERY_PAGE_ITEMS: usize = 64;
pub(super) const MAX_METADATA_MUTATION_TERMINAL_RESERVE_BYTES: u64 =
    (MAX_METADATA_MUTATION_OUTCOME_BYTES
        + ROW_BLOB_V1_OVERHEAD_LEN
        + 2 * (MAX_CONVERSATION_DESCRIPTOR_BYTES + ROW_BLOB_V1_OVERHEAD_LEN + 8 * 1024)) as u64;
/// claimed native mutation 在 terminal write set 之前还必须安全写入 effect fence、
/// release evidence，并可能先落一笔 OutcomeUnknown。这里分别保守覆盖 sealed payload、
/// side columns、索引、runtime_meta 与 WAL/page closure；不能挪用 terminal reserve。
pub(super) const MAX_NATIVE_METADATA_EFFECT_PERSIST_RESERVE_BYTES: u64 = 128 * 1024;
pub(super) const MAX_NATIVE_METADATA_EFFECT_RELEASE_RESERVE_BYTES: u64 = 64 * 1024;
pub(super) const MAX_NATIVE_METADATA_OUTCOME_UNKNOWN_RESERVE_BYTES: u64 = 64 * 1024;
pub(super) const MAX_NATIVE_METADATA_PRE_TERMINAL_RESERVE_BYTES: u64 =
    MAX_NATIVE_METADATA_EFFECT_PERSIST_RESERVE_BYTES
        + MAX_NATIVE_METADATA_EFFECT_RELEASE_RESERVE_BYTES
        + MAX_NATIVE_METADATA_OUTCOME_UNKNOWN_RESERVE_BYTES;
pub(super) const MAX_NATIVE_METADATA_MUTATION_SAFETY_RESERVE_BYTES: u64 =
    MAX_METADATA_MUTATION_TERMINAL_RESERVE_BYTES + MAX_NATIVE_METADATA_PRE_TERMINAL_RESERVE_BYTES;

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

/// Native metadata mutation 的 active durable state。terminal state 只通过
/// `UpdateConversationMetadataOutcome` 暴露，避免 coordinator 再次执行 vendor。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NativeMetadataMutationStatus {
    Claimed,
    Applying,
    OutcomeUnknown,
}

/// Store 签发的 opaque native metadata mutation capability。
///
/// blind tokens 与请求正文均不进入 Debug/wire；C-e2 只能把 capability 原样交回
/// Store transaction helper，不能自行构造另一个 mutation parent。
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct NativeMetadataMutationClaim {
    database_id: [u8; 16],
    conversation_id: RuntimeId,
    idempotency_token: [u8; 32],
    request_token: [u8; 32],
    expected_entry_revision: u64,
    requested_title: Option<String>,
    created_at_ms: u64,
    state_changed_at_ms: u64,
    status: NativeMetadataMutationStatus,
}

impl std::fmt::Debug for NativeMetadataMutationClaim {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeMetadataMutationClaim")
            .field("database_id", &"[REDACTED]")
            .field("conversation_id", &self.conversation_id)
            .field("idempotency_token", &"[REDACTED]")
            .field("request_token", &"[REDACTED]")
            .field("expected_entry_revision", &self.expected_entry_revision)
            .field("requested_title", &"[REDACTED]")
            .field("created_at_ms", &self.created_at_ms)
            .field("state_changed_at_ms", &self.state_changed_at_ms)
            .field("status", &self.status)
            .finish()
    }
}

#[allow(dead_code)] // C-e4 coordinator 接线前由 focused Store tests 消费完整 capability。
impl NativeMetadataMutationClaim {
    pub(crate) const fn database_id(&self) -> &[u8; 16] {
        &self.database_id
    }

    pub(crate) const fn conversation_id(&self) -> RuntimeId {
        self.conversation_id
    }

    pub(crate) const fn idempotency_token(&self) -> &[u8; 32] {
        &self.idempotency_token
    }

    pub(crate) const fn request_token(&self) -> &[u8; 32] {
        &self.request_token
    }

    pub(crate) const fn expected_entry_revision(&self) -> u64 {
        self.expected_entry_revision
    }

    pub(crate) fn requested_title(&self) -> Option<&str> {
        self.requested_title.as_deref()
    }

    pub(crate) const fn created_at_ms(&self) -> u64 {
        self.created_at_ms
    }

    pub(crate) const fn state_changed_at_ms(&self) -> u64 {
        self.state_changed_at_ms
    }

    pub(crate) const fn status(&self) -> NativeMetadataMutationStatus {
        self.status
    }

    pub(crate) fn retained_capacity(&self) -> usize {
        self.requested_title.as_ref().map_or(0, String::capacity)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum ClaimNativeMetadataMutationOutcome {
    Claimed {
        mutation: NativeMetadataMutationClaim,
    },
    Replayed {
        outcome: UpdateConversationMetadataOutcome,
    },
}

#[allow(dead_code)] // C-e4 coordinator 接线前由 focused Store tests 构造 readback。
#[derive(Clone, PartialEq)]
pub(crate) enum NativeMetadataMutationReadback {
    Applied { observed_title: Option<String> },
    Failed { failure: RuntimeFailure },
    Inconclusive,
}

impl std::fmt::Debug for NativeMetadataMutationReadback {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Applied { .. } => formatter
                .debug_struct("Applied")
                .field("observed_title", &"[REDACTED]")
                .finish(),
            Self::Failed { failure } => formatter
                .debug_struct("Failed")
                .field("failure_code", &failure.code)
                .finish_non_exhaustive(),
            Self::Inconclusive => formatter.write_str("Inconclusive"),
        }
    }
}

/// 同一 Store 实例内的 opaque keyset cursor；不进入 wire，不跨 database 复用。
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct NativeMetadataMutationRecoveryCursor {
    database_id: [u8; 16],
    after_conversation_id: RuntimeId,
    after_idempotency_token: [u8; 32],
}

impl std::fmt::Debug for NativeMetadataMutationRecoveryCursor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeMetadataMutationRecoveryCursor")
            .field("database_id", &"[REDACTED]")
            .field("after_conversation_id", &self.after_conversation_id)
            .field("after_idempotency_token", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NativeMetadataMutationRecoveryPage {
    mutations: Vec<NativeMetadataMutationClaim>,
    next_cursor: Option<NativeMetadataMutationRecoveryCursor>,
}

#[allow(dead_code)] // C-e4 startup recovery 接线前由 focused Store tests 翻页。
impl NativeMetadataMutationRecoveryPage {
    pub(crate) fn mutations(&self) -> &[NativeMetadataMutationClaim] {
        &self.mutations
    }

    pub(crate) const fn next_cursor(&self) -> Option<NativeMetadataMutationRecoveryCursor> {
        self.next_cursor
    }
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
        #[serde(default, skip_serializing_if = "Option::is_none")]
        clean_reap_commitment: Option<[u8; 32]>,
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
    owner_token: [u8; 32],
    idempotency_token: [u8; 32],
    request_token: [u8; 32],
    expected_entry_revision: u64,
    applied_entry_revision: Option<u64>,
    applied_catalog_revision: Option<u64>,
    state: MetadataMutationState,
    created_at_ms: u64,
    state_changed_at_ms: u64,
    logical_request_bytes: u64,
    logical_outcome_bytes: u64,
    charged_outcome_bytes: u64,
    sealed_request_bytes: u64,
    sealed_outcome_bytes: Option<u64>,
    charged_bytes: u64,
    request: DecodedMetadataRequest,
    outcome: Option<MetadataMutationTerminalOutcome>,
}

pub(super) struct AuthenticatedMetadataMutationParent {
    conversation_id: RuntimeId,
    idempotency_token: [u8; 32],
    state: MetadataMutationState,
    created_at_ms: u64,
    state_changed_at_ms: u64,
    is_rename: bool,
}

impl AuthenticatedMetadataMutationParent {
    pub(super) const fn conversation_id(&self) -> RuntimeId {
        self.conversation_id
    }

    pub(super) const fn idempotency_token(&self) -> &[u8; 32] {
        &self.idempotency_token
    }

    pub(super) const fn created_at_ms(&self) -> u64 {
        self.created_at_ms
    }

    pub(super) const fn state_changed_at_ms(&self) -> u64 {
        self.state_changed_at_ms
    }

    pub(super) const fn is_rename(&self) -> bool {
        self.is_rename
    }

    pub(super) const fn is_claimed(&self) -> bool {
        matches!(self.state, MetadataMutationState::Claimed)
    }

    pub(super) const fn is_applying(&self) -> bool {
        matches!(self.state, MetadataMutationState::Applying)
    }

    pub(super) const fn is_applied(&self) -> bool {
        matches!(self.state, MetadataMutationState::Applied)
    }

    pub(super) const fn is_outcome_unknown(&self) -> bool {
        matches!(self.state, MetadataMutationState::OutcomeUnknown)
    }

    pub(super) const fn is_failed(&self) -> bool {
        matches!(self.state, MetadataMutationState::Failed)
    }
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
        MetadataMutationTerminalOutcome::Failed {
            clean_reap_commitment: Some(commitment),
            ..
        } if commitment == &[0; 32] => {
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
            MetadataMutationState::Applying | MetadataMutationState::Failed
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
        owner_token,
        idempotency_token,
        request_token,
        expected_entry_revision,
        applied_entry_revision,
        applied_catalog_revision,
        state,
        created_at_ms,
        state_changed_at_ms,
        logical_request_bytes,
        logical_outcome_bytes,
        charged_outcome_bytes,
        sealed_request_bytes,
        sealed_outcome_bytes,
        charged_bytes,
        request,
        outcome,
    })
}

pub(super) fn load_authenticated_metadata_mutation_parent(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    conversation_id: RuntimeId,
    idempotency_token: &[u8; 32],
) -> Result<Option<AuthenticatedMetadataMutationParent>, RuntimeStoreError> {
    let Some(raw) = query_metadata_row_by_idempotency(connection, idempotency_token)? else {
        return Ok(None);
    };
    let authenticated = authenticate_metadata_row(key_bundle, database_id, raw)?;
    if authenticated.conversation_id != conversation_id
        || authenticated.idempotency_token != *idempotency_token
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(Some(AuthenticatedMetadataMutationParent {
        conversation_id: authenticated.conversation_id,
        idempotency_token: authenticated.idempotency_token,
        state: authenticated.state,
        created_at_ms: authenticated.created_at_ms,
        state_changed_at_ms: authenticated.state_changed_at_ms,
        is_rename: matches!(
            authenticated.request.mutation,
            ConversationMetadataMutation::Rename { .. }
        ),
    }))
}

/// 完整认证指定 conversation 的 metadata mutation rows，并报告是否仍有 B4 active
/// parent（claimed/applying/outcomeUnknown）。native lifecycle 的 quiescence CAS 不能只
/// 依赖裸 state/COUNT 查询。
pub(super) fn conversation_has_active_authenticated_metadata_mutation(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    conversation_id: RuntimeId,
) -> Result<bool, RuntimeStoreError> {
    let mut statement = connection.prepare(
        "SELECT conversation_id, owner_token, idempotency_token, request_token,
                expected_entry_revision, applied_entry_revision,
                applied_catalog_revision, state, logical_request_bytes,
                logical_outcome_bytes, charged_outcome_bytes, created_at_ms,
                state_changed_at_ms, metadata_token, sealed_request, sealed_outcome
         FROM metadata_mutation_ledger
         WHERE conversation_id = ?1 ORDER BY idempotency_token",
    )?;
    let rows = statement.query_map([&conversation_id.as_bytes()[..]], raw_metadata_mutation_row)?;
    let mut count = 0_u64;
    let mut has_active = false;
    for row in rows {
        count = count
            .checked_add(1)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        if count > MAX_METADATA_MUTATIONS_PER_CONVERSATION {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        let authenticated = authenticate_metadata_row(key_bundle, database_id, row?)?;
        if authenticated.conversation_id != conversation_id {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        has_active |= authenticated.state.is_active();
    }
    Ok(has_active)
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
            Some(MetadataMutationTerminalOutcome::Failed { failure, .. }),
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

fn native_status(state: MetadataMutationState) -> Option<NativeMetadataMutationStatus> {
    match state {
        MetadataMutationState::Claimed => Some(NativeMetadataMutationStatus::Claimed),
        MetadataMutationState::Applying => Some(NativeMetadataMutationStatus::Applying),
        MetadataMutationState::OutcomeUnknown => Some(NativeMetadataMutationStatus::OutcomeUnknown),
        MetadataMutationState::Applied | MetadataMutationState::Failed => None,
    }
}

fn native_claim_from_row(
    database_id: [u8; 16],
    row: &AuthenticatedMetadataMutationRow,
) -> Result<NativeMetadataMutationClaim, RuntimeStoreError> {
    let ConversationMetadataMutation::Rename { title } = &row.request.mutation else {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    };
    Ok(NativeMetadataMutationClaim {
        database_id,
        conversation_id: row.conversation_id,
        idempotency_token: row.idempotency_token,
        request_token: row.request_token,
        expected_entry_revision: row.expected_entry_revision,
        requested_title: title.clone(),
        created_at_ms: row.created_at_ms,
        state_changed_at_ms: row.state_changed_at_ms,
        status: native_status(row.state).ok_or(RuntimeStoreError::InvalidStateTransition)?,
    })
}

fn load_row_for_native_claim(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    claim: &NativeMetadataMutationClaim,
) -> Result<AuthenticatedMetadataMutationRow, RuntimeStoreError> {
    if claim.database_id != database_id {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }
    let raw = query_metadata_row_by_idempotency(connection, &claim.idempotency_token)?
        .ok_or(RuntimeStoreError::InvalidStateTransition)?;
    let row = authenticate_metadata_row(key_bundle, database_id, raw)?;
    let ConversationMetadataMutation::Rename { title } = &row.request.mutation else {
        return Err(RuntimeStoreError::InvalidStateTransition);
    };
    if row.conversation_id != claim.conversation_id
        || row.idempotency_token != claim.idempotency_token
        || row.request_token != claim.request_token
        || row.expected_entry_revision != claim.expected_entry_revision
        || title != &claim.requested_title
        || row.created_at_ms != claim.created_at_ms
    {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }
    Ok(row)
}

pub(super) fn authenticate_native_metadata_claim(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    claim: &NativeMetadataMutationClaim,
) -> Result<NativeMetadataMutationClaim, RuntimeStoreError> {
    let row = load_row_for_native_claim(connection, key_bundle, database_id, claim)?;
    native_claim_from_row(database_id, &row)
}

fn validate_supported_native_rename(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    request: &DecodedMetadataRequest,
) -> Result<crate::runtime::model::ConversationRecord, RuntimeStoreError> {
    if !matches!(
        request.mutation,
        ConversationMetadataMutation::Rename { .. }
    ) {
        return Err(RuntimeStoreError::MetadataMutationUnsupported);
    }
    let conversation = super::journal::load_conversation(
        connection,
        key_bundle,
        database_id,
        request.conversation_id,
    )?;
    let conversation_state = super::configuration::load_conversation_state(
        connection,
        key_bundle,
        request.conversation_id,
    )?;
    if conversation.descriptor.agent_kind != AgentKind::ClaudeCode
        || !conversation_state.is_native_projected()
        || conversation_state.origin_namespace()
            != Some(AdapterStateNamespace::ClaudeCode.origin_namespace())
        || super::native_projection::authenticated_native_catalog_change(
            connection,
            key_bundle,
            database_id,
            &conversation,
        )? != Some(super::native_projection::NativeCatalogChange::Upsert)
    {
        return Err(RuntimeStoreError::MetadataMutationUnsupported);
    }
    Ok(conversation)
}

fn latest_metadata_mutation_at(
    connection: &Connection,
    conversation_id: RuntimeId,
    conversation_updated_at_ms: u64,
) -> Result<u64, RuntimeStoreError> {
    let latest: Option<i64> = connection.query_row(
        "SELECT MAX(state_changed_at_ms) FROM metadata_mutation_ledger
         WHERE conversation_id = ?1",
        [&conversation_id.as_bytes()[..]],
        |row| row.get(0),
    )?;
    Ok(latest
        .map(nonnegative)
        .transpose()?
        .unwrap_or(conversation_updated_at_ms)
        .max(conversation_updated_at_ms))
}

pub(crate) fn claim_native_conversation_metadata(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    prepared: PreparedMetadataMutationRequest,
    effects: &mut CommandStreamEffects,
) -> Result<ClaimNativeMetadataMutationOutcome, RuntimeStoreError> {
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
    if let Some(outcome) = try_replay_metadata_mutation(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        &idempotency_token,
        &request_token,
    )? {
        return Ok(ClaimNativeMetadataMutationOutcome::Replayed { outcome });
    }
    let conversation = validate_supported_native_rename(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        &request,
    )?;
    let conversation_state = super::configuration::load_conversation_state(
        &state.connection,
        &state.key_bundle,
        request.conversation_id,
    )?;
    let current_entry_revision = conversation_state.entry_revision()?;
    if request.expected_entry_revision != current_entry_revision {
        return Ok(ClaimNativeMetadataMutationOutcome::Replayed {
            outcome: UpdateConversationMetadataOutcome::Conflict {
                current_entry_revision,
            },
        });
    }
    if conversation_has_active_authenticated_metadata_mutation(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        request.conversation_id,
    )? {
        return Err(RuntimeStoreError::MetadataMutationPending);
    }
    let observed_at_ms = config.clock.now_ms().map_err(RuntimeStoreError::from)?;
    let persisted_at_ms = latest_metadata_mutation_at(
        &state.connection,
        request.conversation_id,
        conversation.updated_at_ms,
    )?;
    if observed_at_ms < persisted_at_ms {
        return Err(RuntimeStoreError::ClockRegressed {
            persisted_ms: persisted_at_ms,
            observed_ms: observed_at_ms,
        });
    }
    let sealed_request_bytes = prepared
        .request_plaintext
        .len()
        .checked_add(ROW_BLOB_V1_OVERHEAD_LEN)
        .ok_or(RuntimeStoreError::PayloadTooLarge)?;
    let reserved_outcome_bytes = MAX_METADATA_MUTATION_OUTCOME_BYTES
        .checked_add(ROW_BLOB_V1_OVERHEAD_LEN)
        .ok_or(RuntimeStoreError::PayloadTooLarge)?;
    let charged_bytes = u64::try_from(
        sealed_request_bytes
            .checked_add(reserved_outcome_bytes)
            .ok_or(RuntimeStoreError::PayloadTooLarge)?,
    )
    .map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
    let projected_write_bytes =
        super::journal::projected_write_bytes(&[sealed_request_bytes, 8 * 1024])?;
    super::sqlite::admit_ordinary_write(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        &state.storage_path,
        &mut state.admission_state,
        config.capacity_probe.as_ref(),
        projected_write_bytes,
        SafetyReserveProjection::ClaimMetadataMutation,
    )?;

    let transaction = state
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let ledger =
        super::sqlite::load_runtime_ledger(&transaction, &state.key_bundle, state.database_id)?;
    if let Some(outcome) = try_replay_metadata_mutation(
        &transaction,
        &state.key_bundle,
        state.database_id,
        &idempotency_token,
        &request_token,
    )? {
        return Ok(ClaimNativeMetadataMutationOutcome::Replayed { outcome });
    }
    let conversation = validate_supported_native_rename(
        &transaction,
        &state.key_bundle,
        state.database_id,
        &request,
    )?;
    let conversation_state = super::configuration::load_conversation_state(
        &transaction,
        &state.key_bundle,
        request.conversation_id,
    )?;
    let current_entry_revision = conversation_state.entry_revision()?;
    if request.expected_entry_revision != current_entry_revision {
        return Ok(ClaimNativeMetadataMutationOutcome::Replayed {
            outcome: UpdateConversationMetadataOutcome::Conflict {
                current_entry_revision,
            },
        });
    }
    if conversation_has_active_authenticated_metadata_mutation(
        &transaction,
        &state.key_bundle,
        state.database_id,
        request.conversation_id,
    )? {
        return Err(RuntimeStoreError::MetadataMutationPending);
    }
    let persisted_at_ms = latest_metadata_mutation_at(
        &transaction,
        request.conversation_id,
        conversation.updated_at_ms,
    )?;
    if observed_at_ms < persisted_at_ms {
        return Err(RuntimeStoreError::ClockRegressed {
            persisted_ms: persisted_at_ms,
            observed_ms: observed_at_ms,
        });
    }
    ensure_metadata_mutation_capacity(
        &ledger,
        metadata_count_for_conversation(&transaction, request.conversation_id)?,
        charged_bytes,
        true,
    )?;
    let primary_key = metadata_primary_key(request.conversation_id, &idempotency_token);
    let sealed_request = seal_metadata_value(
        &state.key_bundle,
        state.database_id,
        &primary_key,
        SEALED_REQUEST_COLUMN,
        prepared.request_plaintext.as_ref(),
        MAX_METADATA_MUTATION_REQUEST_BYTES,
    )?;
    if sealed_request.len() != sealed_request_bytes {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let expected_entry_revision = encode_sequence(request.expected_entry_revision);
    let logical_request_bytes = u64::try_from(prepared.request_plaintext.len())
        .map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
    let charged_outcome_bytes =
        u64::try_from(reserved_outcome_bytes).map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
    let row_token = metadata_row_token(
        &state.key_bundle,
        request.conversation_id,
        &owner_token,
        &idempotency_token,
        &request_token,
        &expected_entry_revision,
        None,
        None,
        MetadataMutationState::Claimed,
        logical_request_bytes,
        0,
        charged_outcome_bytes,
        observed_at_ms,
        observed_at_ms,
        u64::try_from(sealed_request.len()).map_err(|_| RuntimeStoreError::PayloadTooLarge)?,
        None,
    )?;
    transaction.execute(
        "INSERT INTO metadata_mutation_ledger (
             conversation_id, owner_token, idempotency_token, request_token,
             expected_entry_revision, applied_entry_revision, applied_catalog_revision,
             state, logical_request_bytes, logical_outcome_bytes, charged_outcome_bytes,
             created_at_ms, state_changed_at_ms, metadata_token, sealed_request, sealed_outcome
         ) VALUES (?1, ?2, ?3, ?4, ?5, NULL, NULL, 'claimed', ?6, 0, ?7,
                   ?8, ?8, ?9, ?10, NULL)",
        params![
            &request.conversation_id.as_bytes()[..],
            &owner_token[..],
            &idempotency_token[..],
            &request_token[..],
            &expected_entry_revision,
            i64::try_from(logical_request_bytes).map_err(|_| RuntimeStoreError::PayloadTooLarge)?,
            i64::try_from(charged_outcome_bytes).map_err(|_| RuntimeStoreError::PayloadTooLarge)?,
            i64::try_from(observed_at_ms).map_err(|_| RuntimeStoreError::TimeOutOfRange)?,
            &row_token[..],
            sealed_request,
        ],
    )?;
    let mut next_ledger = ledger.clone();
    next_ledger.metadata_mutation_count = next_ledger
        .metadata_mutation_count
        .checked_add(1)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    next_ledger.active_metadata_mutation_count = next_ledger
        .active_metadata_mutation_count
        .checked_add(1)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    next_ledger.metadata_mutation_charged_bytes = next_ledger
        .metadata_mutation_charged_bytes
        .checked_add(charged_bytes)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let pending_targets = super::sqlite::update_runtime_ledger(
        &transaction,
        &state.key_bundle,
        state.database_id,
        &ledger,
        &next_ledger,
    )?;
    config
        .fault_injector
        .before_operation(RuntimeStoreOperation::ClaimNativeMetadataMutationBeforeCommit)?;
    let commit_result = super::sqlite::commit_transaction(
        transaction,
        RuntimeCommitOperation::ClaimNativeMetadataMutation,
    );
    effects.record_commit_result(pending_targets, &commit_result);
    commit_result?;
    super::sqlite::latch_post_commit_capacity(state, config);
    if config
        .fault_injector
        .before_operation(RuntimeStoreOperation::ClaimNativeMetadataMutationAfterCommit)
        .is_err()
    {
        return Err(RuntimeStoreError::CommitOutcomeUnknown {
            operation: RuntimeCommitOperation::ClaimNativeMetadataMutation,
        });
    }
    Ok(ClaimNativeMetadataMutationOutcome::Claimed {
        mutation: NativeMetadataMutationClaim {
            database_id: state.database_id,
            conversation_id: request.conversation_id,
            idempotency_token,
            request_token,
            expected_entry_revision: request.expected_entry_revision,
            requested_title: match request.mutation {
                ConversationMetadataMutation::Rename { title } => title,
                ConversationMetadataMutation::SetArchived { .. } => {
                    return Err(RuntimeStoreError::UnknownOrCorruptSchema);
                }
            },
            created_at_ms: observed_at_ms,
            state_changed_at_ms: observed_at_ms,
            status: NativeMetadataMutationStatus::Claimed,
        },
    })
}

/// C-e2 fence writer 在自己的 `BEGIN IMMEDIATE` 内调用；只有 parent 与当前
/// present Claude Code projection、entry revision 都仍精确匹配时才推进 Applying。
/// 本 helper 不提交、不写 fence，也不改变 ledger totals。
pub(super) fn transition_native_metadata_claim_to_applying(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    claim: &NativeMetadataMutationClaim,
    observed_at_ms: u64,
) -> Result<NativeMetadataMutationClaim, RuntimeStoreError> {
    let row = load_row_for_native_claim(connection, key_bundle, database_id, claim)?;
    if row.state == MetadataMutationState::Applying {
        return native_claim_from_row(database_id, &row);
    }
    if row.state != MetadataMutationState::Claimed || observed_at_ms < row.state_changed_at_ms {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }
    validate_state_transition(row.state, MetadataMutationState::Applying)?;
    let conversation =
        validate_supported_native_rename(connection, key_bundle, database_id, &row.request)?;
    let conversation_state =
        super::configuration::load_conversation_state(connection, key_bundle, row.conversation_id)?;
    if conversation_state.entry_revision()? != row.expected_entry_revision
        || observed_at_ms < conversation.updated_at_ms
    {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }
    let expected_entry_revision = encode_sequence(row.expected_entry_revision);
    let old_token = metadata_row_token(
        key_bundle,
        row.conversation_id,
        &row.owner_token,
        &row.idempotency_token,
        &row.request_token,
        &expected_entry_revision,
        None,
        None,
        row.state,
        row.logical_request_bytes,
        row.logical_outcome_bytes,
        row.charged_outcome_bytes,
        row.created_at_ms,
        row.state_changed_at_ms,
        row.sealed_request_bytes,
        row.sealed_outcome_bytes,
    )?;
    let next_token = metadata_row_token(
        key_bundle,
        row.conversation_id,
        &row.owner_token,
        &row.idempotency_token,
        &row.request_token,
        &expected_entry_revision,
        None,
        None,
        MetadataMutationState::Applying,
        row.logical_request_bytes,
        0,
        row.charged_outcome_bytes,
        row.created_at_ms,
        observed_at_ms,
        row.sealed_request_bytes,
        None,
    )?;
    if connection.execute(
        "UPDATE metadata_mutation_ledger
         SET state = 'applying', state_changed_at_ms = ?1, metadata_token = ?2
         WHERE conversation_id = ?3 AND idempotency_token = ?4
           AND state = 'claimed' AND metadata_token = ?5",
        params![
            i64::try_from(observed_at_ms).map_err(|_| RuntimeStoreError::TimeOutOfRange)?,
            &next_token[..],
            &row.conversation_id.as_bytes()[..],
            &row.idempotency_token[..],
            &old_token[..],
        ],
    )? != 1
    {
        return Err(RuntimeStoreError::SchemaInspectionRaced);
    }
    let mut next = native_claim_from_row(database_id, &row)?;
    next.state_changed_at_ms = observed_at_ms;
    next.status = NativeMetadataMutationStatus::Applying;
    Ok(next)
}

fn authenticated_row_token(
    key_bundle: &RuntimeKeyBundle,
    row: &AuthenticatedMetadataMutationRow,
) -> Result<[u8; 32], RuntimeStoreError> {
    let expected_entry_revision = encode_sequence(row.expected_entry_revision);
    let applied_entry_revision = row.applied_entry_revision.map(encode_sequence);
    let applied_catalog_revision = row.applied_catalog_revision.map(encode_sequence);
    metadata_row_token(
        key_bundle,
        row.conversation_id,
        &row.owner_token,
        &row.idempotency_token,
        &row.request_token,
        &expected_entry_revision,
        applied_entry_revision.as_deref(),
        applied_catalog_revision.as_deref(),
        row.state,
        row.logical_request_bytes,
        row.logical_outcome_bytes,
        row.charged_outcome_bytes,
        row.created_at_ms,
        row.state_changed_at_ms,
        row.sealed_request_bytes,
        row.sealed_outcome_bytes,
    )
}

#[allow(clippy::too_many_arguments)]
fn write_native_metadata_terminal_row(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    row: &AuthenticatedMetadataMutationRow,
    state: MetadataMutationState,
    applied_entry_revision: Option<u64>,
    applied_catalog_revision: Option<u64>,
    outcome: &MetadataMutationTerminalOutcome,
    changed_at_ms: u64,
) -> Result<u64, RuntimeStoreError> {
    validate_state_transition(row.state, state)?;
    if changed_at_ms < row.state_changed_at_ms {
        return Err(RuntimeStoreError::ClockRegressed {
            persisted_ms: row.state_changed_at_ms,
            observed_ms: changed_at_ms,
        });
    }
    let outcome_plaintext = encode_terminal_outcome(outcome)?;
    let primary_key = metadata_primary_key(row.conversation_id, &row.idempotency_token);
    let sealed_outcome = seal_metadata_value(
        key_bundle,
        database_id,
        &primary_key,
        SEALED_OUTCOME_COLUMN,
        outcome_plaintext.as_ref(),
        MAX_METADATA_MUTATION_OUTCOME_BYTES,
    )?;
    let logical_outcome_bytes =
        u64::try_from(outcome_plaintext.len()).map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
    let charged_outcome_bytes =
        u64::try_from(sealed_outcome.len()).map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
    let expected_entry_revision = encode_sequence(row.expected_entry_revision);
    let applied_entry_revision = applied_entry_revision.map(encode_sequence);
    let applied_catalog_revision = applied_catalog_revision.map(encode_sequence);
    let next_token = metadata_row_token(
        key_bundle,
        row.conversation_id,
        &row.owner_token,
        &row.idempotency_token,
        &row.request_token,
        &expected_entry_revision,
        applied_entry_revision.as_deref(),
        applied_catalog_revision.as_deref(),
        state,
        row.logical_request_bytes,
        logical_outcome_bytes,
        charged_outcome_bytes,
        row.created_at_ms,
        changed_at_ms,
        row.sealed_request_bytes,
        Some(charged_outcome_bytes),
    )?;
    let old_token = authenticated_row_token(key_bundle, row)?;
    if connection.execute(
        "UPDATE metadata_mutation_ledger
         SET applied_entry_revision = ?1, applied_catalog_revision = ?2,
             state = ?3, logical_outcome_bytes = ?4, charged_outcome_bytes = ?5,
             state_changed_at_ms = ?6, metadata_token = ?7, sealed_outcome = ?8
         WHERE conversation_id = ?9 AND idempotency_token = ?10 AND metadata_token = ?11",
        params![
            applied_entry_revision.as_deref(),
            applied_catalog_revision.as_deref(),
            state.as_str(),
            i64::try_from(logical_outcome_bytes).map_err(|_| RuntimeStoreError::PayloadTooLarge)?,
            i64::try_from(charged_outcome_bytes).map_err(|_| RuntimeStoreError::PayloadTooLarge)?,
            i64::try_from(changed_at_ms).map_err(|_| RuntimeStoreError::TimeOutOfRange)?,
            &next_token[..],
            sealed_outcome,
            &row.conversation_id.as_bytes()[..],
            &row.idempotency_token[..],
            &old_token[..],
        ],
    )? != 1
    {
        return Err(RuntimeStoreError::SchemaInspectionRaced);
    }
    row.sealed_request_bytes
        .checked_add(charged_outcome_bytes)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)
}

fn terminalize_native_metadata_ledger(
    transaction: &Connection,
    ledger: &RuntimeLedger,
    row: &AuthenticatedMetadataMutationRow,
    terminal_charged_bytes: u64,
) -> Result<RuntimeLedger, RuntimeStoreError> {
    let mut next = ledger.clone();
    next.active_metadata_mutation_count = next
        .active_metadata_mutation_count
        .checked_sub(1)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    next.metadata_mutation_charged_bytes = next
        .metadata_mutation_charged_bytes
        .checked_sub(row.charged_bytes)
        .and_then(|value| value.checked_add(terminal_charged_bytes))
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    if next.active_metadata_mutation_count
        != nonnegative(transaction.query_row(
            "SELECT COUNT(*) FROM metadata_mutation_ledger
             WHERE state IN ('claimed', 'applying', 'outcomeUnknown')",
            [],
            |value| value.get(0),
        )?)?
    {
        return Err(RuntimeStoreError::SchemaInspectionRaced);
    }
    Ok(next)
}

fn constant_time_commitment_eq(left: &[u8; 32], right: &[u8; 32]) -> bool {
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

/// clean-reap 的只读前置认证。fresh 路径必须拿到 exact Applying claim；
/// terminal replay 则只接受同一 failure 与 sealed outcome 中持久化的 exact
/// capability commitment。调用方必须在 clock/capacity admission 前执行本函数。
pub(super) fn preflight_fail_unreleased_native_metadata_effect(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    claim: &NativeMetadataMutationClaim,
    failure: &RuntimeFailure,
    clean_reap_commitment: &[u8; 32],
) -> Result<Option<UpdateConversationMetadataOutcome>, RuntimeStoreError> {
    if clean_reap_commitment == &[0; 32] || claim.status() != NativeMetadataMutationStatus::Applying
    {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }
    let row = load_row_for_native_claim(connection, key_bundle, database_id, claim)?;
    if row.state == MetadataMutationState::Failed {
        return match row.outcome.as_ref() {
            Some(MetadataMutationTerminalOutcome::Failed {
                failure: stored_failure,
                clean_reap_commitment: Some(stored_commitment),
            }) if stored_failure == failure
                && constant_time_commitment_eq(stored_commitment, clean_reap_commitment) =>
            {
                Ok(Some(UpdateConversationMetadataOutcome::Failed {
                    failure: failure.clone(),
                }))
            }
            _ => Err(RuntimeStoreError::TerminalConflict),
        };
    }
    if row.state != MetadataMutationState::Applying
        || native_claim_from_row(database_id, &row)? != *claim
    {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }
    Ok(None)
}

/// `Applying + unreleased fence -> Failed` transaction 中只负责认证并 terminalize
/// metadata parent。effect fence 的 exact 认证、DELETE 与三项 fence totals 由同一
/// transaction 的 native projection helper 完成。
#[allow(
    clippy::too_many_arguments,
    reason = "transaction-local helper must authenticate every exact clean-reap binding"
)]
pub(super) fn fail_unreleased_native_metadata_effect_parent(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    ledger: &RuntimeLedger,
    claim: &NativeMetadataMutationClaim,
    failure: &RuntimeFailure,
    clean_reap_commitment: [u8; 32],
    changed_at_ms: u64,
) -> Result<RuntimeLedger, RuntimeStoreError> {
    if clean_reap_commitment == [0; 32] || claim.status() != NativeMetadataMutationStatus::Applying
    {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }
    let row = load_row_for_native_claim(connection, key_bundle, database_id, claim)?;
    if row.state != MetadataMutationState::Applying
        || native_claim_from_row(database_id, &row)? != *claim
    {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }
    let outcome = MetadataMutationTerminalOutcome::Failed {
        failure: failure.clone(),
        clean_reap_commitment: Some(clean_reap_commitment),
    };
    let terminal_charged_bytes = write_native_metadata_terminal_row(
        connection,
        key_bundle,
        database_id,
        &row,
        MetadataMutationState::Failed,
        None,
        None,
        &outcome,
        changed_at_ms,
    )?;
    terminalize_native_metadata_ledger(connection, ledger, &row, terminal_charged_bytes)
}

fn metadata_commit_unknown(
    config: &RuntimeStoreConfig,
    operation: RuntimeStoreOperation,
    commit_operation: RuntimeCommitOperation,
) -> Result<(), RuntimeStoreError> {
    if config.fault_injector.before_operation(operation).is_err() {
        Err(RuntimeStoreError::CommitOutcomeUnknown {
            operation: commit_operation,
        })
    } else {
        Ok(())
    }
}

pub(crate) fn fail_claimed_native_metadata_mutation(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    claim: NativeMetadataMutationClaim,
    failure: RuntimeFailure,
    effects: &mut CommandStreamEffects,
) -> Result<UpdateConversationMetadataOutcome, RuntimeStoreError> {
    let preflight = load_row_for_native_claim(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        &claim,
    )?;
    if preflight.state == MetadataMutationState::Failed {
        return match preflight.outcome.as_ref() {
            Some(MetadataMutationTerminalOutcome::Failed {
                failure: stored,
                clean_reap_commitment: None,
            }) if stored == &failure => Ok(UpdateConversationMetadataOutcome::Failed { failure }),
            _ => Err(RuntimeStoreError::TerminalConflict),
        };
    }
    if preflight.state != MetadataMutationState::Claimed {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }
    super::sqlite::admit_safety_write_with_credit(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        &state.storage_path,
        config.capacity_probe.as_ref(),
        MAX_NATIVE_METADATA_PRE_TERMINAL_RESERVE_BYTES,
    )?;
    let changed_at_ms = config.clock.now_ms().map_err(RuntimeStoreError::from)?;
    let transaction = state
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let ledger =
        super::sqlite::load_runtime_ledger(&transaction, &state.key_bundle, state.database_id)?;
    let row =
        load_row_for_native_claim(&transaction, &state.key_bundle, state.database_id, &claim)?;
    if row.state == MetadataMutationState::Failed {
        return match row.outcome.as_ref() {
            Some(MetadataMutationTerminalOutcome::Failed {
                failure: stored,
                clean_reap_commitment: None,
            }) if stored == &failure => Ok(UpdateConversationMetadataOutcome::Failed { failure }),
            _ => Err(RuntimeStoreError::TerminalConflict),
        };
    }
    if row.state != MetadataMutationState::Claimed {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }
    let fence_count: i64 = transaction.query_row(
        "SELECT COUNT(*) FROM native_metadata_effect_fences
         WHERE conversation_id = ?1 AND idempotency_token = ?2",
        params![
            &row.conversation_id.as_bytes()[..],
            &row.idempotency_token[..],
        ],
        |value| value.get(0),
    )?;
    if fence_count != 0 {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }
    let outcome = MetadataMutationTerminalOutcome::Failed {
        failure: failure.clone(),
        clean_reap_commitment: None,
    };
    let terminal_charged_bytes = write_native_metadata_terminal_row(
        &transaction,
        &state.key_bundle,
        state.database_id,
        &row,
        MetadataMutationState::Failed,
        None,
        None,
        &outcome,
        changed_at_ms,
    )?;
    let next_ledger =
        terminalize_native_metadata_ledger(&transaction, &ledger, &row, terminal_charged_bytes)?;
    let pending_targets = super::sqlite::update_runtime_ledger(
        &transaction,
        &state.key_bundle,
        state.database_id,
        &ledger,
        &next_ledger,
    )?;
    config
        .fault_injector
        .before_operation(RuntimeStoreOperation::FailClaimedNativeMetadataMutationBeforeCommit)?;
    let commit_result = super::sqlite::commit_transaction(
        transaction,
        RuntimeCommitOperation::FailClaimedNativeMetadataMutation,
    );
    effects.record_commit_result(pending_targets, &commit_result);
    commit_result?;
    super::sqlite::latch_post_commit_capacity(state, config);
    metadata_commit_unknown(
        config,
        RuntimeStoreOperation::FailClaimedNativeMetadataMutationAfterCommit,
        RuntimeCommitOperation::FailClaimedNativeMetadataMutation,
    )?;
    Ok(UpdateConversationMetadataOutcome::Failed { failure })
}

pub(crate) fn mark_native_metadata_mutation_outcome_unknown(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    claim: NativeMetadataMutationClaim,
) -> Result<NativeMetadataMutationClaim, RuntimeStoreError> {
    let current = authenticate_native_metadata_claim(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        &claim,
    )?;
    super::native_projection::ensure_released_native_metadata_effect_fence(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        &current,
    )?;
    if current.status == NativeMetadataMutationStatus::OutcomeUnknown {
        return Ok(current);
    }
    if current.status != NativeMetadataMutationStatus::Applying {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }
    super::sqlite::admit_safety_write_with_credit(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        &state.storage_path,
        config.capacity_probe.as_ref(),
        MAX_NATIVE_METADATA_EFFECT_PERSIST_RESERVE_BYTES
            + MAX_NATIVE_METADATA_EFFECT_RELEASE_RESERVE_BYTES,
    )?;
    let changed_at_ms = config.clock.now_ms().map_err(RuntimeStoreError::from)?;
    let transaction = state
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let row =
        load_row_for_native_claim(&transaction, &state.key_bundle, state.database_id, &claim)?;
    let authenticated = native_claim_from_row(state.database_id, &row)?;
    super::native_projection::ensure_released_native_metadata_effect_fence(
        &transaction,
        &state.key_bundle,
        state.database_id,
        &authenticated,
    )?;
    if row.state == MetadataMutationState::OutcomeUnknown {
        return Ok(authenticated);
    }
    if row.state != MetadataMutationState::Applying || changed_at_ms < row.state_changed_at_ms {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }
    validate_state_transition(row.state, MetadataMutationState::OutcomeUnknown)?;
    let expected_entry_revision = encode_sequence(row.expected_entry_revision);
    let old_token = authenticated_row_token(&state.key_bundle, &row)?;
    let next_token = metadata_row_token(
        &state.key_bundle,
        row.conversation_id,
        &row.owner_token,
        &row.idempotency_token,
        &row.request_token,
        &expected_entry_revision,
        None,
        None,
        MetadataMutationState::OutcomeUnknown,
        row.logical_request_bytes,
        0,
        row.charged_outcome_bytes,
        row.created_at_ms,
        changed_at_ms,
        row.sealed_request_bytes,
        None,
    )?;
    if transaction.execute(
        "UPDATE metadata_mutation_ledger
         SET state = 'outcomeUnknown', state_changed_at_ms = ?1, metadata_token = ?2
         WHERE conversation_id = ?3 AND idempotency_token = ?4
           AND state = 'applying' AND metadata_token = ?5",
        params![
            i64::try_from(changed_at_ms).map_err(|_| RuntimeStoreError::TimeOutOfRange)?,
            &next_token[..],
            &row.conversation_id.as_bytes()[..],
            &row.idempotency_token[..],
            &old_token[..],
        ],
    )? != 1
    {
        return Err(RuntimeStoreError::SchemaInspectionRaced);
    }
    config.fault_injector.before_operation(
        RuntimeStoreOperation::MarkNativeMetadataMutationOutcomeUnknownBeforeCommit,
    )?;
    super::sqlite::commit_transaction(
        transaction,
        RuntimeCommitOperation::MarkNativeMetadataMutationOutcomeUnknown,
    )?;
    super::sqlite::latch_post_commit_capacity(state, config);
    metadata_commit_unknown(
        config,
        RuntimeStoreOperation::MarkNativeMetadataMutationOutcomeUnknownAfterCommit,
        RuntimeCommitOperation::MarkNativeMetadataMutationOutcomeUnknown,
    )?;
    let mut next = authenticated;
    next.state_changed_at_ms = changed_at_ms;
    next.status = NativeMetadataMutationStatus::OutcomeUnknown;
    Ok(next)
}

pub(crate) fn finalize_native_metadata_mutation_readback(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    claim: NativeMetadataMutationClaim,
    readback: NativeMetadataMutationReadback,
    effects: &mut CommandStreamEffects,
) -> Result<UpdateConversationMetadataOutcome, RuntimeStoreError> {
    let preflight = load_row_for_native_claim(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        &claim,
    )?;
    if !preflight.state.is_active() {
        return replay_outcome(preflight);
    }
    if matches!(readback, NativeMetadataMutationReadback::Inconclusive) {
        return Err(RuntimeStoreError::MetadataMutationPending);
    }
    let current = native_claim_from_row(state.database_id, &preflight)?;
    super::native_projection::ensure_released_native_metadata_effect_fence(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        &current,
    )?;
    super::sqlite::admit_safety_write_with_credit(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        &state.storage_path,
        config.capacity_probe.as_ref(),
        MAX_NATIVE_METADATA_PRE_TERMINAL_RESERVE_BYTES,
    )?;
    let changed_at_ms = config.clock.now_ms().map_err(RuntimeStoreError::from)?;
    let transaction = state
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let ledger =
        super::sqlite::load_runtime_ledger(&transaction, &state.key_bundle, state.database_id)?;
    let row =
        load_row_for_native_claim(&transaction, &state.key_bundle, state.database_id, &claim)?;
    if !row.state.is_active() {
        return replay_outcome(row);
    }
    if matches!(readback, NativeMetadataMutationReadback::Inconclusive) {
        return Err(RuntimeStoreError::MetadataMutationPending);
    }
    let authenticated = native_claim_from_row(state.database_id, &row)?;
    super::native_projection::ensure_released_native_metadata_effect_fence(
        &transaction,
        &state.key_bundle,
        state.database_id,
        &authenticated,
    )?;
    if !matches!(
        row.state,
        MetadataMutationState::Applying | MetadataMutationState::OutcomeUnknown
    ) {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }

    let (
        terminal_state,
        terminal_outcome,
        applied_entry_revision,
        applied_catalog_revision,
        response,
        mut next_ledger,
    ) = match readback {
        NativeMetadataMutationReadback::Applied { observed_title } => {
            let ConversationMetadataMutation::Rename { title } = &row.request.mutation else {
                return Err(RuntimeStoreError::UnknownOrCorruptSchema);
            };
            if &observed_title != title {
                return Err(RuntimeStoreError::MetadataMutationPending);
            }
            let conversation = validate_supported_native_rename(
                &transaction,
                &state.key_bundle,
                state.database_id,
                &row.request,
            )?;
            let conversation_state = super::configuration::load_conversation_state(
                &transaction,
                &state.key_bundle,
                row.conversation_id,
            )?;
            let current_entry_revision = conversation_state.entry_revision()?;
            if current_entry_revision != row.expected_entry_revision {
                return Err(RuntimeStoreError::InvalidStateTransition);
            }
            let next_entry_revision = current_entry_revision.checked_add(1).ok_or(
                super::sequence::SequenceError::Exhausted {
                    scope: SequenceScope::EntryRevision,
                },
            )?;
            let next_catalog_revision = next_sequence(
                SequenceScope::CatalogRevision,
                ledger.catalog_high_water.as_deref(),
            )?;
            let (next_descriptor, next_lifecycle) =
                apply_mutation(&conversation, &row.request.mutation)?;
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
                row.conversation_id,
                &conversation_state,
                &encode_sequence(next_entry_revision),
            )?;
            if updated.conversation_id != row.conversation_id
                || updated.updated_at_ms != conversation.updated_at_ms
                || updated.event_high_water != conversation.event_high_water
            {
                return Err(RuntimeStoreError::UnknownOrCorruptSchema);
            }
            super::native_projection::advance_present_native_projection_catalog_revision(
                &transaction,
                &state.key_bundle,
                state.database_id,
                row.conversation_id,
                conversation.catalog_revision,
                next_catalog_revision.value,
            )?;
            let mut next_ledger = ledger.clone();
            next_ledger.catalog_high_water = Some(next_catalog_revision.encoded);
            let record = MetadataMutationRecord {
                conversation_id: row.conversation_id,
                entry_revision: next_entry_revision,
                catalog_revision: next_catalog_revision.value,
                state_changed_at_ms: changed_at_ms,
            };
            (
                MetadataMutationState::Applied,
                MetadataMutationTerminalOutcome::Applied {
                    conversation_id: row.conversation_id.to_canonical_string(),
                    entry_revision: next_entry_revision,
                    catalog_revision: next_catalog_revision.value,
                },
                Some(next_entry_revision),
                Some(next_catalog_revision.value),
                UpdateConversationMetadataOutcome::Applied { mutation: record },
                next_ledger,
            )
        }
        NativeMetadataMutationReadback::Failed { failure } => (
            MetadataMutationState::Failed,
            MetadataMutationTerminalOutcome::Failed {
                failure: failure.clone(),
                clean_reap_commitment: None,
            },
            None,
            None,
            UpdateConversationMetadataOutcome::Failed { failure },
            ledger.clone(),
        ),
        NativeMetadataMutationReadback::Inconclusive => unreachable!(),
    };
    let terminal_charged_bytes = write_native_metadata_terminal_row(
        &transaction,
        &state.key_bundle,
        state.database_id,
        &row,
        terminal_state,
        applied_entry_revision,
        applied_catalog_revision,
        &terminal_outcome,
        changed_at_ms,
    )?;
    let terminal_ledger =
        terminalize_native_metadata_ledger(&transaction, &ledger, &row, terminal_charged_bytes)?;
    next_ledger.active_metadata_mutation_count = terminal_ledger.active_metadata_mutation_count;
    next_ledger.metadata_mutation_charged_bytes = terminal_ledger.metadata_mutation_charged_bytes;
    let pending_targets = if terminal_state == MetadataMutationState::Applied {
        super::sqlite::update_runtime_ledger_with_trim_clock(
            &transaction,
            &state.key_bundle,
            state.database_id,
            &ledger,
            &next_ledger,
            changed_at_ms,
        )?
    } else {
        super::sqlite::update_runtime_ledger(
            &transaction,
            &state.key_bundle,
            state.database_id,
            &ledger,
            &next_ledger,
        )?
    };
    config.fault_injector.before_operation(
        RuntimeStoreOperation::FinalizeNativeMetadataMutationReadbackBeforeCommit,
    )?;
    let commit_result = super::sqlite::commit_transaction(
        transaction,
        RuntimeCommitOperation::FinalizeNativeMetadataMutationReadback,
    );
    effects.record_commit_result(pending_targets, &commit_result);
    commit_result?;
    super::sqlite::latch_post_commit_capacity(state, config);
    metadata_commit_unknown(
        config,
        RuntimeStoreOperation::FinalizeNativeMetadataMutationReadbackAfterCommit,
        RuntimeCommitOperation::FinalizeNativeMetadataMutationReadback,
    )?;
    Ok(response)
}

pub(crate) fn load_active_native_metadata_mutations(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    cursor: Option<NativeMetadataMutationRecoveryCursor>,
) -> Result<NativeMetadataMutationRecoveryPage, RuntimeStoreError> {
    if cursor.is_some_and(|value| value.database_id != database_id) {
        return Err(RuntimeStoreError::InvalidRecoveryCursor);
    }
    let limit = i64::try_from(MAX_NATIVE_METADATA_RECOVERY_PAGE_ITEMS + 1)
        .map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
    let mut statement = match cursor {
        None => connection.prepare(
            "SELECT conversation_id, owner_token, idempotency_token, request_token,
                    expected_entry_revision, applied_entry_revision,
                    applied_catalog_revision, state, logical_request_bytes,
                    logical_outcome_bytes, charged_outcome_bytes, created_at_ms,
                    state_changed_at_ms, metadata_token, sealed_request, sealed_outcome
             FROM metadata_mutation_ledger
             WHERE state IN ('claimed', 'applying', 'outcomeUnknown')
             ORDER BY conversation_id, idempotency_token LIMIT ?1",
        )?,
        Some(_) => connection.prepare(
            "SELECT conversation_id, owner_token, idempotency_token, request_token,
                    expected_entry_revision, applied_entry_revision,
                    applied_catalog_revision, state, logical_request_bytes,
                    logical_outcome_bytes, charged_outcome_bytes, created_at_ms,
                    state_changed_at_ms, metadata_token, sealed_request, sealed_outcome
             FROM metadata_mutation_ledger
             WHERE state IN ('claimed', 'applying', 'outcomeUnknown')
               AND (conversation_id > ?1
                    OR (conversation_id = ?1 AND idempotency_token > ?2))
             ORDER BY conversation_id, idempotency_token LIMIT ?3",
        )?,
    };
    let mut mutations = Vec::with_capacity(MAX_NATIVE_METADATA_RECOVERY_PAGE_ITEMS + 1);
    match cursor {
        None => {
            let rows = statement.query_map([limit], raw_metadata_mutation_row)?;
            for row in rows {
                let authenticated = authenticate_metadata_row(key_bundle, database_id, row?)?;
                validate_supported_native_rename(
                    connection,
                    key_bundle,
                    database_id,
                    &authenticated.request,
                )?;
                mutations.push(native_claim_from_row(database_id, &authenticated)?);
            }
        }
        Some(cursor) => {
            let rows = statement.query_map(
                params![
                    &cursor.after_conversation_id.as_bytes()[..],
                    &cursor.after_idempotency_token[..],
                    limit,
                ],
                raw_metadata_mutation_row,
            )?;
            for row in rows {
                let authenticated = authenticate_metadata_row(key_bundle, database_id, row?)?;
                validate_supported_native_rename(
                    connection,
                    key_bundle,
                    database_id,
                    &authenticated.request,
                )?;
                mutations.push(native_claim_from_row(database_id, &authenticated)?);
            }
        }
    }
    let has_next = mutations.len() > MAX_NATIVE_METADATA_RECOVERY_PAGE_ITEMS;
    if has_next {
        mutations.pop();
    }
    let next_cursor = if has_next {
        let last = mutations
            .last()
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        Some(NativeMetadataMutationRecoveryCursor {
            database_id,
            after_conversation_id: last.conversation_id,
            after_idempotency_token: last.idempotency_token,
        })
    } else {
        None
    };
    Ok(NativeMetadataMutationRecoveryPage {
        mutations,
        next_cursor,
    })
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
    native_projected: bool,
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
            || if native_projected {
                entry.cwd.is_some()
            } else {
                entry.cwd.as_ref() != Some(&current.descriptor.cwd)
            }
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
                conversation_state.is_native_projected(),
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
#[allow(
    clippy::too_many_arguments,
    reason = "authenticated native metadata parent fixtures need every persisted time/state input"
)]
pub(super) fn insert_native_metadata_parent_fixture(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    conversation_id: RuntimeId,
    idempotency_key: &str,
    state: &str,
    created_at_ms: u64,
    state_changed_at_ms: u64,
) -> Result<([u8; 32], u64), RuntimeStoreError> {
    let state = MetadataMutationState::parse(state)?;
    if !state.is_active() || state_changed_at_ms < created_at_ms {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }
    let prepared = prepare_metadata_mutation_request(UpdateManagedConversationMetadata {
        conversation_id,
        owner: IdempotencyOwner::Local {
            machine_trust_domain: [0xB1; 32],
            uid: 501,
            client_installation_id: [0xB2; 16],
        },
        idempotency_key: idempotency_key.to_owned(),
        expected_entry_revision: 0,
        mutation: ConversationMetadataMutation::rename(Some("native fixture".to_owned()))
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
    })?;
    let request = decode_metadata_request(prepared.request_plaintext.as_ref())?;
    let owner_token = blind_token(
        key_bundle,
        METADATA_OWNER_DOMAIN,
        request.owner_bytes.as_ref(),
    )?;
    let idempotency_token = metadata_idempotency_token(
        key_bundle,
        conversation_id,
        request.owner_bytes.as_ref(),
        request.idempotency_key.as_ref(),
    )?;
    let request_token = blind_token(
        key_bundle,
        METADATA_REQUEST_DOMAIN,
        prepared.request_plaintext.as_ref(),
    )?;
    let primary_key = metadata_primary_key(conversation_id, &idempotency_token);
    let sealed_request = seal_metadata_value(
        key_bundle,
        database_id,
        &primary_key,
        SEALED_REQUEST_COLUMN,
        prepared.request_plaintext.as_ref(),
        MAX_METADATA_MUTATION_REQUEST_BYTES,
    )?;
    let logical_request_bytes = u64::try_from(prepared.request_plaintext.len())
        .map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
    let sealed_request_bytes =
        u64::try_from(sealed_request.len()).map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
    let charged_outcome_bytes =
        u64::try_from(MAX_METADATA_MUTATION_OUTCOME_BYTES + ROW_BLOB_V1_OVERHEAD_LEN)
            .map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
    let expected_entry_revision = encode_sequence(0);
    let metadata_token = metadata_row_token(
        key_bundle,
        conversation_id,
        &owner_token,
        &idempotency_token,
        &request_token,
        &expected_entry_revision,
        None,
        None,
        state,
        logical_request_bytes,
        0,
        charged_outcome_bytes,
        created_at_ms,
        state_changed_at_ms,
        sealed_request_bytes,
        None,
    )?;
    connection.execute(
        "INSERT INTO metadata_mutation_ledger (
             conversation_id, owner_token, idempotency_token, request_token,
             expected_entry_revision, applied_entry_revision, applied_catalog_revision,
             state, logical_request_bytes, logical_outcome_bytes, charged_outcome_bytes,
             created_at_ms, state_changed_at_ms, metadata_token, sealed_request, sealed_outcome
         ) VALUES (?1, ?2, ?3, ?4, ?5, NULL, NULL, ?6, ?7, 0, ?8, ?9, ?10, ?11, ?12, NULL)",
        params![
            &conversation_id.as_bytes()[..],
            &owner_token[..],
            &idempotency_token[..],
            &request_token[..],
            expected_entry_revision,
            state.as_str(),
            i64::try_from(logical_request_bytes).map_err(|_| RuntimeStoreError::PayloadTooLarge)?,
            i64::try_from(charged_outcome_bytes).map_err(|_| RuntimeStoreError::PayloadTooLarge)?,
            i64::try_from(created_at_ms).map_err(|_| RuntimeStoreError::TimeOutOfRange)?,
            i64::try_from(state_changed_at_ms).map_err(|_| RuntimeStoreError::TimeOutOfRange)?,
            &metadata_token[..],
            sealed_request,
        ],
    )?;
    Ok((
        idempotency_token,
        sealed_request_bytes
            .checked_add(charged_outcome_bytes)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?,
    ))
}

#[cfg(test)]
pub(super) fn rewrite_native_metadata_parent_active_state_fixture(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    idempotency_token: &[u8; 32],
    state: &str,
    state_changed_at_ms: u64,
) -> Result<(), RuntimeStoreError> {
    let state = MetadataMutationState::parse(state)?;
    if !state.is_active() {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }
    let raw = query_metadata_row_by_idempotency(connection, idempotency_token)?
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let authenticated = authenticate_metadata_row(key_bundle, database_id, raw)?;
    if authenticated.idempotency_token != *idempotency_token
        || state_changed_at_ms < authenticated.created_at_ms
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let raw = query_metadata_row_by_idempotency(connection, idempotency_token)?
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let conversation_id = RuntimeId::from_bytes(
        RuntimeIdKind::Conversation,
        raw.conversation_id
            .as_slice()
            .try_into()
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
    )?;
    let owner_token = fixed_token(raw.owner_token)?;
    let persisted_idempotency_token = fixed_token(raw.idempotency_token)?;
    let request_token = fixed_token(raw.request_token)?;
    let logical_request_bytes = nonnegative(raw.logical_request_bytes)?;
    let charged_outcome_bytes = nonnegative(raw.charged_outcome_bytes)?;
    let created_at_ms = nonnegative(raw.created_at_ms)?;
    let sealed_request_bytes = u64::try_from(raw.sealed_request.len())
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let token = metadata_row_token(
        key_bundle,
        conversation_id,
        &owner_token,
        &persisted_idempotency_token,
        &request_token,
        &raw.expected_entry_revision,
        None,
        None,
        state,
        logical_request_bytes,
        0,
        charged_outcome_bytes,
        created_at_ms,
        state_changed_at_ms,
        sealed_request_bytes,
        None,
    )?;
    if connection.execute(
        "UPDATE metadata_mutation_ledger
         SET state = ?1, state_changed_at_ms = ?2, metadata_token = ?3
         WHERE idempotency_token = ?4",
        params![
            state.as_str(),
            i64::try_from(state_changed_at_ms).map_err(|_| RuntimeStoreError::TimeOutOfRange)?,
            &token[..],
            &idempotency_token[..],
        ],
    )? != 1
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn rewrite_native_metadata_parent_failed_fixture(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    idempotency_token: &[u8; 32],
    state_changed_at_ms: u64,
) -> Result<(u64, u64), RuntimeStoreError> {
    let raw = query_metadata_row_by_idempotency(connection, idempotency_token)?
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let authenticated = authenticate_metadata_row(key_bundle, database_id, raw)?;
    if authenticated.idempotency_token != *idempotency_token
        || state_changed_at_ms < authenticated.created_at_ms
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let raw = query_metadata_row_by_idempotency(connection, idempotency_token)?
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let conversation_id = RuntimeId::from_bytes(
        RuntimeIdKind::Conversation,
        raw.conversation_id
            .as_slice()
            .try_into()
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
    )?;
    let owner_token = fixed_token(raw.owner_token)?;
    let persisted_idempotency_token = fixed_token(raw.idempotency_token)?;
    let request_token = fixed_token(raw.request_token)?;
    let logical_request_bytes = nonnegative(raw.logical_request_bytes)?;
    let old_charged_outcome_bytes = nonnegative(raw.charged_outcome_bytes)?;
    let created_at_ms = nonnegative(raw.created_at_ms)?;
    let sealed_request_bytes = u64::try_from(raw.sealed_request.len())
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let outcome = MetadataMutationTerminalOutcome::Failed {
        failure: RuntimeFailure::new(
            agentdeck_protocol::runtime::failure::DAEMON_RUNTIME_EXECUTION_FAILED,
            "native metadata effect failed",
        ),
        clean_reap_commitment: None,
    };
    let outcome_plaintext = encode_terminal_outcome(&outcome)?;
    let primary_key = metadata_primary_key(conversation_id, idempotency_token);
    let sealed_outcome = seal_metadata_value(
        key_bundle,
        database_id,
        &primary_key,
        SEALED_OUTCOME_COLUMN,
        outcome_plaintext.as_ref(),
        MAX_METADATA_MUTATION_OUTCOME_BYTES,
    )?;
    let logical_outcome_bytes = u64::try_from(outcome_plaintext.len())
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let charged_outcome_bytes = u64::try_from(sealed_outcome.len())
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let token = metadata_row_token(
        key_bundle,
        conversation_id,
        &owner_token,
        &persisted_idempotency_token,
        &request_token,
        &raw.expected_entry_revision,
        None,
        None,
        MetadataMutationState::Failed,
        logical_request_bytes,
        logical_outcome_bytes,
        charged_outcome_bytes,
        created_at_ms,
        state_changed_at_ms,
        sealed_request_bytes,
        Some(charged_outcome_bytes),
    )?;
    if connection.execute(
        "UPDATE metadata_mutation_ledger
         SET state = 'failed', logical_outcome_bytes = ?1, charged_outcome_bytes = ?2,
             state_changed_at_ms = ?3, metadata_token = ?4, sealed_outcome = ?5
         WHERE idempotency_token = ?6",
        params![
            i64::try_from(logical_outcome_bytes).map_err(|_| RuntimeStoreError::PayloadTooLarge)?,
            i64::try_from(charged_outcome_bytes).map_err(|_| RuntimeStoreError::PayloadTooLarge)?,
            i64::try_from(state_changed_at_ms).map_err(|_| RuntimeStoreError::TimeOutOfRange)?,
            &token[..],
            sealed_outcome,
            &idempotency_token[..],
        ],
    )? != 1
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok((
        sealed_request_bytes
            .checked_add(old_charged_outcome_bytes)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?,
        sealed_request_bytes
            .checked_add(charged_outcome_bytes)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?,
    ))
}

#[cfg(test)]
#[path = "metadata_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "runtime_native_metadata_mutation.rs"]
mod runtime_native_metadata_mutation_tests;
