//! Runtime v7 machine-wide admin command ledger。

use agentdeck_protocol::runtime::{
    ArtifactSha256, IdempotencyKey, LocalOnlyAdministration, RuntimeFailure, StageUpgradeRequest,
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use zeroize::Zeroizing;

use crate::runtime::model::{
    AdminCommandLimitScope, MAX_IDEMPOTENCY_KEY_BYTES, MAX_RUNTIME_CONVERSATIONS,
    RuntimeCommitOperation, RuntimeStoreConfig, RuntimeStoreError, RuntimeStoreOperation,
};

use super::cipher::{ROW_BLOB_V1_OVERHEAD_LEN, RowAad, RuntimeKeyBundle};
use super::schema::{
    ADMIN_COMMAND_RETENTION_MS, MAX_ADMIN_COMMAND_CHARGED_BYTES, MAX_ADMIN_COMMAND_OUTCOME_BYTES,
    MAX_ADMIN_COMMAND_REQUEST_BYTES, MAX_ADMIN_COMMANDS, MAX_PENDING_ADMIN_COMMANDS,
    RUNTIME_CRYPTO_CONTEXT_VERSION, RUNTIME_SCHEMA_FAMILY,
};
use super::sqlite::{RuntimeLedger, RuntimeSqlite, SafetyReserveProjection};

const ADMIN_TABLE: &[u8] = b"admin_commands";
const REQUEST_COLUMN: &[u8] = b"sealed_request";
const OUTCOME_COLUMN: &[u8] = b"sealed_outcome";
const COMMAND_KIND: &str = "stageUpgrade";
const REQUEST_MAGIC: &[u8; 4] = b"ADA1";
const OUTCOME_MAGIC: &[u8; 4] = b"ADA2";
const IDEMPOTENCY_DOMAIN: &[u8] = b"admin.command.idempotency.v1";
const REQUEST_DOMAIN: &[u8] = b"admin.command.request.v1";
const OUTCOME_DOMAIN: &[u8] = b"admin.command.outcome.v1";
const METADATA_DOMAIN: &[u8] = b"admin.command.metadata.v1";
const MAX_RECOVERY_PAGE_ITEMS: usize = 64;
pub(super) const MAX_ADMIN_COMMAND_TERMINAL_RESERVE_BYTES: u64 = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdminUpgradeStatus {
    Pending,
    Completed,
    Failed,
}

impl AdminUpgradeStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Completed => "completed",
            Self::Failed => "failed",
        }
    }

    fn parse(value: &str) -> Result<Self, RuntimeStoreError> {
        match value {
            "pending" => Ok(Self::Pending),
            "completed" => Ok(Self::Completed),
            "failed" => Ok(Self::Failed),
            _ => Err(RuntimeStoreError::UnknownOrCorruptSchema),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdminUpgradeTerminalOutcome {
    Completed,
    Failed { failure: RuntimeFailure },
}

#[derive(Clone)]
pub struct AdminUpgradeCommand {
    database_id: [u8; 16],
    idempotency_token: [u8; 32],
    request_token: [u8; 32],
    request: StageUpgradeRequest,
    status: AdminUpgradeStatus,
    terminal_failure: Option<RuntimeFailure>,
    created_at_ms: u64,
    state_changed_at_ms: u64,
    retain_until_ms: u64,
}

impl std::fmt::Debug for AdminUpgradeCommand {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AdminUpgradeCommand")
            .field("database_id", &"[REDACTED]")
            .field("idempotency_token", &"[REDACTED]")
            .field("request_token", &"[REDACTED]")
            .field("target_version", &self.request.target_version())
            .field("candidate_sha256", &"[REDACTED]")
            .field("status", &self.status)
            .field(
                "terminal_failure",
                &self.terminal_failure.as_ref().map(|_| "[REDACTED]"),
            )
            .field("created_at_ms", &self.created_at_ms)
            .field("state_changed_at_ms", &self.state_changed_at_ms)
            .field("retain_until_ms", &self.retain_until_ms)
            .finish()
    }
}

impl AdminUpgradeCommand {
    #[must_use]
    pub const fn request(&self) -> &StageUpgradeRequest {
        &self.request
    }

    #[must_use]
    pub fn target_version(&self) -> &str {
        self.request.target_version()
    }

    #[must_use]
    pub const fn candidate_sha256(&self) -> &ArtifactSha256 {
        self.request.candidate_sha256()
    }

    #[must_use]
    pub const fn status(&self) -> AdminUpgradeStatus {
        self.status
    }

    #[must_use]
    pub const fn terminal_failure(&self) -> Option<&RuntimeFailure> {
        self.terminal_failure.as_ref()
    }
}

#[derive(Clone, Debug)]
pub enum AcceptAdminUpgradeOutcome {
    Accepted {
        command: AdminUpgradeCommand,
        active_started_commands: u32,
    },
    Replayed {
        command: AdminUpgradeCommand,
        active_started_commands: u32,
    },
}

#[derive(Clone, Debug)]
pub enum FinalizeAdminUpgradeOutcome {
    Finalized { command: AdminUpgradeCommand },
    Replayed { command: AdminUpgradeCommand },
}

#[derive(Clone, Eq, PartialEq)]
pub struct AdminUpgradeRecoveryCursor([u8; 32]);

impl std::fmt::Debug for AdminUpgradeRecoveryCursor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("AdminUpgradeRecoveryCursor([REDACTED])")
    }
}

#[derive(Clone, Debug)]
pub struct AdminUpgradeRecoveryPage {
    commands: Vec<AdminUpgradeCommand>,
    next_cursor: Option<AdminUpgradeRecoveryCursor>,
}

impl AdminUpgradeRecoveryPage {
    #[must_use]
    pub fn commands(&self) -> &[AdminUpgradeCommand] {
        &self.commands
    }

    #[must_use]
    pub const fn next_cursor(&self) -> Option<&AdminUpgradeRecoveryCursor> {
        self.next_cursor.as_ref()
    }
}

pub(crate) struct PreparedAdminUpgradeRequest {
    plaintext: Zeroizing<Vec<u8>>,
}

impl PreparedAdminUpgradeRequest {
    pub(crate) fn retained_capacity(&self) -> usize {
        self.plaintext.capacity()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum DecodedOutcome {
    Pending,
    Completed,
    Failed(RuntimeFailure),
}

impl DecodedOutcome {
    fn status(&self) -> AdminUpgradeStatus {
        match self {
            Self::Pending => AdminUpgradeStatus::Pending,
            Self::Completed => AdminUpgradeStatus::Completed,
            Self::Failed(_) => AdminUpgradeStatus::Failed,
        }
    }
}

struct RawAdminRow {
    idempotency_token: Vec<u8>,
    command_kind: String,
    request_token: Vec<u8>,
    state: String,
    sealed_request: Vec<u8>,
    sealed_outcome: Vec<u8>,
    created_at_ms: i64,
    state_changed_at_ms: i64,
    retain_until_ms: i64,
    charged_bytes: i64,
    metadata_token: Vec<u8>,
}

struct AuthenticatedAdminRow {
    command: AdminUpgradeCommand,
    charged_bytes: u64,
    sealed_outcome_bytes: u64,
    metadata_token: [u8; 32],
    outcome: DecodedOutcome,
}

pub(crate) fn prepare_admin_upgrade_request(
    request: StageUpgradeRequest,
) -> Result<PreparedAdminUpgradeRequest, RuntimeStoreError> {
    if !request.is_local_only() {
        return Err(RuntimeStoreError::InvalidConfig(
            "admin upgrade request must be local-only",
        ));
    }
    let key = request.idempotency_key().as_str();
    if key.is_empty() || key.len() > MAX_IDEMPOTENCY_KEY_BYTES {
        return Err(RuntimeStoreError::InvalidConfig(
            "idempotency key must contain 1 to 1024 UTF-8 bytes",
        ));
    }
    let plaintext = Zeroizing::new(encode_fields(
        REQUEST_MAGIC,
        &[
            key.as_bytes(),
            request.target_version().as_bytes(),
            request.candidate_sha256().as_str().as_bytes(),
        ],
    )?);
    if plaintext.len() > MAX_ADMIN_COMMAND_REQUEST_BYTES {
        return Err(RuntimeStoreError::PayloadTooLarge);
    }
    Ok(PreparedAdminUpgradeRequest { plaintext })
}

fn encode_fields(magic: &[u8; 4], fields: &[&[u8]]) -> Result<Vec<u8>, RuntimeStoreError> {
    let mut output = Vec::new();
    output.extend_from_slice(magic);
    for field in fields {
        let len = u32::try_from(field.len()).map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
        output.extend_from_slice(&len.to_be_bytes());
        output.extend_from_slice(field);
    }
    Ok(output)
}

fn decode_fields<'a>(
    input: &'a [u8],
    magic: &[u8; 4],
    count: usize,
) -> Result<Vec<&'a [u8]>, RuntimeStoreError> {
    if input.get(..4) != Some(magic) {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let mut cursor = 4_usize;
    let mut fields = Vec::with_capacity(count);
    for _ in 0..count {
        let length_end = cursor
            .checked_add(4)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        let length = u32::from_be_bytes(
            input
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
            input
                .get(cursor..end)
                .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?,
        );
        cursor = end;
    }
    if cursor != input.len() {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(fields)
}

fn decode_request(plaintext: &[u8]) -> Result<StageUpgradeRequest, RuntimeStoreError> {
    let fields = decode_fields(plaintext, REQUEST_MAGIC, 3)?;
    let key =
        std::str::from_utf8(fields[0]).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    if key.is_empty() || key.len() > MAX_IDEMPOTENCY_KEY_BYTES {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let target =
        std::str::from_utf8(fields[1]).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let hash =
        std::str::from_utf8(fields[2]).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    StageUpgradeRequest::new(
        target.to_owned(),
        ArtifactSha256::new(hash.to_owned())
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
        IdempotencyKey::new(key),
        LocalOnlyAdministration::LocalOnly,
    )
    .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)
}

fn encode_outcome(outcome: &DecodedOutcome) -> Result<Zeroizing<Vec<u8>>, RuntimeStoreError> {
    let (state, failure) = match outcome {
        DecodedOutcome::Pending => (b"pending".as_slice(), Vec::new()),
        DecodedOutcome::Completed => (b"completed".as_slice(), Vec::new()),
        DecodedOutcome::Failed(failure) => (
            b"failed".as_slice(),
            serde_json::to_vec(failure)
                .map_err(|_| RuntimeStoreError::InvalidConfig("admin failure serialization"))?,
        ),
    };
    let encoded = Zeroizing::new(encode_fields(OUTCOME_MAGIC, &[state, &failure])?);
    if encoded.len() > MAX_ADMIN_COMMAND_OUTCOME_BYTES {
        return Err(RuntimeStoreError::PayloadTooLarge);
    }
    Ok(encoded)
}

fn decode_outcome(plaintext: &[u8]) -> Result<DecodedOutcome, RuntimeStoreError> {
    let fields = decode_fields(plaintext, OUTCOME_MAGIC, 2)?;
    match fields[0] {
        b"pending" if fields[1].is_empty() => Ok(DecodedOutcome::Pending),
        b"completed" if fields[1].is_empty() => Ok(DecodedOutcome::Completed),
        b"failed" => {
            let failure: RuntimeFailure = serde_json::from_slice(fields[1])
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
            if serde_json::to_vec(&failure)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
                != fields[1]
            {
                return Err(RuntimeStoreError::UnknownOrCorruptSchema);
            }
            Ok(DecodedOutcome::Failed(failure))
        }
        _ => Err(RuntimeStoreError::UnknownOrCorruptSchema),
    }
}

fn blind_token(
    key_bundle: &RuntimeKeyBundle,
    domain: &[u8],
    value: &[u8],
) -> Result<[u8; 32], RuntimeStoreError> {
    Ok(*key_bundle.blind_index(domain, value)?.as_bytes())
}

#[allow(clippy::too_many_arguments)]
fn row_token(
    key_bundle: &RuntimeKeyBundle,
    idempotency_token: &[u8; 32],
    request_token: &[u8; 32],
    outcome_token: &[u8; 32],
    status: AdminUpgradeStatus,
    created_at_ms: u64,
    state_changed_at_ms: u64,
    retain_until_ms: u64,
    charged_bytes: u64,
    sealed_request_bytes: u64,
    sealed_outcome_bytes: u64,
) -> Result<[u8; 32], RuntimeStoreError> {
    super::stream::metadata_mac(
        key_bundle,
        METADATA_DOMAIN,
        &[
            idempotency_token,
            COMMAND_KIND.as_bytes(),
            request_token,
            outcome_token,
            status.as_str().as_bytes(),
            &created_at_ms.to_be_bytes(),
            &state_changed_at_ms.to_be_bytes(),
            &retain_until_ms.to_be_bytes(),
            &charged_bytes.to_be_bytes(),
            &sealed_request_bytes.to_be_bytes(),
            &sealed_outcome_bytes.to_be_bytes(),
        ],
    )
}

fn seal(
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    primary_key: &[u8; 32],
    column: &[u8],
    plaintext: &[u8],
    maximum: usize,
) -> Result<Vec<u8>, RuntimeStoreError> {
    Ok(key_bundle.row_cipher().seal_bounded(
        &RowAad {
            schema_family: RUNTIME_SCHEMA_FAMILY.as_bytes(),
            schema_version: RUNTIME_CRYPTO_CONTEXT_VERSION,
            database_id: &database_id,
            table: ADMIN_TABLE,
            primary_key,
            column,
        },
        plaintext,
        maximum,
    )?)
}

fn open(
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    primary_key: &[u8; 32],
    column: &[u8],
    ciphertext: &[u8],
    maximum: usize,
) -> Result<crate::security::SecretBytes, RuntimeStoreError> {
    Ok(key_bundle.row_cipher().open_bounded(
        &RowAad {
            schema_family: RUNTIME_SCHEMA_FAMILY.as_bytes(),
            schema_version: RUNTIME_CRYPTO_CONTEXT_VERSION,
            database_id: &database_id,
            table: ADMIN_TABLE,
            primary_key,
            column,
        },
        ciphertext,
        maximum,
    )?)
}

fn raw_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawAdminRow> {
    Ok(RawAdminRow {
        idempotency_token: row.get(0)?,
        command_kind: row.get(1)?,
        request_token: row.get(2)?,
        state: row.get(3)?,
        sealed_request: row.get(4)?,
        sealed_outcome: row.get(5)?,
        created_at_ms: row.get(6)?,
        state_changed_at_ms: row.get(7)?,
        retain_until_ms: row.get(8)?,
        charged_bytes: row.get(9)?,
        metadata_token: row.get(10)?,
    })
}

const ROW_SELECT: &str = "SELECT idempotency_token, command_kind, request_token, state,
                                sealed_request, sealed_outcome, created_at_ms,
                                state_changed_at_ms, retain_until_ms, charged_bytes,
                                metadata_token FROM admin_commands";

fn query_row(
    connection: &Connection,
    idempotency_token: &[u8; 32],
) -> Result<Option<RawAdminRow>, RuntimeStoreError> {
    connection
        .query_row(
            &format!("{ROW_SELECT} WHERE idempotency_token = ?1"),
            [&idempotency_token[..]],
            raw_row,
        )
        .optional()
        .map_err(RuntimeStoreError::from)
}

fn fixed<const N: usize>(value: Vec<u8>) -> Result<[u8; N], RuntimeStoreError> {
    value
        .try_into()
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)
}

fn nonnegative(value: i64) -> Result<u64, RuntimeStoreError> {
    u64::try_from(value).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)
}

fn authenticate_row(
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    raw: RawAdminRow,
) -> Result<AuthenticatedAdminRow, RuntimeStoreError> {
    let idempotency_token = fixed(raw.idempotency_token)?;
    let request_token = fixed(raw.request_token)?;
    let metadata_token = fixed(raw.metadata_token)?;
    if raw.command_kind != COMMAND_KIND {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let status = AdminUpgradeStatus::parse(&raw.state)?;
    let created_at_ms = nonnegative(raw.created_at_ms)?;
    let state_changed_at_ms = nonnegative(raw.state_changed_at_ms)?;
    let retain_until_ms = nonnegative(raw.retain_until_ms)?;
    let charged_bytes = nonnegative(raw.charged_bytes)?;
    let sealed_request_bytes = u64::try_from(raw.sealed_request.len())
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let sealed_outcome_bytes = u64::try_from(raw.sealed_outcome.len())
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    if state_changed_at_ms < created_at_ms
        || retain_until_ms
            < state_changed_at_ms
                .checked_add(ADMIN_COMMAND_RETENTION_MS)
                .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?
        || charged_bytes
            != sealed_request_bytes
                .checked_add(sealed_outcome_bytes)
                .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let request_plaintext = open(
        key_bundle,
        database_id,
        &idempotency_token,
        REQUEST_COLUMN,
        &raw.sealed_request,
        MAX_ADMIN_COMMAND_REQUEST_BYTES,
    )?;
    let request = decode_request(request_plaintext.expose_secret())?;
    if blind_token(
        key_bundle,
        IDEMPOTENCY_DOMAIN,
        request.idempotency_key().as_str().as_bytes(),
    )? != idempotency_token
        || blind_token(
            key_bundle,
            REQUEST_DOMAIN,
            request_plaintext.expose_secret(),
        )? != request_token
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let outcome_plaintext = open(
        key_bundle,
        database_id,
        &idempotency_token,
        OUTCOME_COLUMN,
        &raw.sealed_outcome,
        MAX_ADMIN_COMMAND_OUTCOME_BYTES,
    )?;
    let outcome = decode_outcome(outcome_plaintext.expose_secret())?;
    if outcome.status() != status {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let outcome_token = blind_token(
        key_bundle,
        OUTCOME_DOMAIN,
        outcome_plaintext.expose_secret(),
    )?;
    let expected_row_token = row_token(
        key_bundle,
        &idempotency_token,
        &request_token,
        &outcome_token,
        status,
        created_at_ms,
        state_changed_at_ms,
        retain_until_ms,
        charged_bytes,
        sealed_request_bytes,
        sealed_outcome_bytes,
    )?;
    if metadata_token != expected_row_token {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let terminal_failure = match &outcome {
        DecodedOutcome::Failed(failure) => Some(failure.clone()),
        DecodedOutcome::Pending | DecodedOutcome::Completed => None,
    };
    Ok(AuthenticatedAdminRow {
        command: AdminUpgradeCommand {
            database_id,
            idempotency_token,
            request_token,
            request,
            status,
            terminal_failure,
            created_at_ms,
            state_changed_at_ms,
            retain_until_ms,
        },
        charged_bytes,
        sealed_outcome_bytes,
        metadata_token,
        outcome,
    })
}

fn request_tokens(
    key_bundle: &RuntimeKeyBundle,
    plaintext: &[u8],
) -> Result<([u8; 32], [u8; 32]), RuntimeStoreError> {
    let request = decode_request(plaintext)?;
    Ok((
        blind_token(
            key_bundle,
            IDEMPOTENCY_DOMAIN,
            request.idempotency_key().as_str().as_bytes(),
        )?,
        blind_token(key_bundle, REQUEST_DOMAIN, plaintext)?,
    ))
}

fn replay(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    idempotency_token: &[u8; 32],
    request_token: &[u8; 32],
) -> Result<Option<AdminUpgradeCommand>, RuntimeStoreError> {
    let Some(raw) = query_row(connection, idempotency_token)? else {
        return Ok(None);
    };
    let row = authenticate_row(key_bundle, database_id, raw)?;
    if row.command.request_token != *request_token {
        return Err(RuntimeStoreError::IdempotencyConflict);
    }
    Ok(Some(row.command))
}

fn active_started_count(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
) -> Result<u32, RuntimeStoreError> {
    let ledger = super::sqlite::load_runtime_ledger(connection, key_bundle, database_id)?;
    let expected = ledger
        .started_without_fence_count
        .checked_add(ledger.started_without_release_count)
        .and_then(|value| value.checked_add(ledger.started_released_count))
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    if expected > MAX_RUNTIME_CONVERSATIONS {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    u32::try_from(expected).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)
}

pub(crate) fn active_started_command_count(
    state: &RuntimeSqlite,
) -> Result<u32, RuntimeStoreError> {
    active_started_count(&state.connection, &state.key_bundle, state.database_id)
}

fn latest_state_changed_at(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
) -> Result<Option<u64>, RuntimeStoreError> {
    let raw = connection
        .query_row(
            &format!(
                "{ROW_SELECT} ORDER BY state_changed_at_ms DESC, idempotency_token DESC LIMIT 1"
            ),
            [],
            raw_row,
        )
        .optional()?;
    raw.map(|row| {
        authenticate_row(key_bundle, database_id, row).map(|row| row.command.state_changed_at_ms)
    })
    .transpose()
}

fn ensure_capacity(ledger: &RuntimeLedger, charged_bytes: u64) -> Result<(), RuntimeStoreError> {
    if ledger.admin_command_count >= MAX_ADMIN_COMMANDS {
        return Err(RuntimeStoreError::AdminCommandLimit {
            scope: AdminCommandLimitScope::GlobalCount,
        });
    }
    if ledger.admin_command_pending_count >= MAX_PENDING_ADMIN_COMMANDS {
        return Err(RuntimeStoreError::AdminCommandLimit {
            scope: AdminCommandLimitScope::Pending,
        });
    }
    let terminal_growth = ledger
        .admin_command_pending_count
        .checked_add(1)
        .and_then(|count| count.checked_mul(MAX_ADMIN_COMMAND_OUTCOME_BYTES as u64))
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    if ledger
        .admin_command_charged_bytes
        .checked_add(charged_bytes)
        .and_then(|value| value.checked_add(terminal_growth))
        .is_none_or(|value| value > MAX_ADMIN_COMMAND_CHARGED_BYTES)
    {
        return Err(RuntimeStoreError::AdminCommandLimit {
            scope: AdminCommandLimitScope::ChargedBytes,
        });
    }
    Ok(())
}

pub(crate) fn accept_admin_upgrade(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    prepared: PreparedAdminUpgradeRequest,
) -> Result<AcceptAdminUpgradeOutcome, RuntimeStoreError> {
    let (idempotency_token, request_token) =
        request_tokens(&state.key_bundle, prepared.plaintext.as_ref())?;
    if replay(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        &idempotency_token,
        &request_token,
    )?
    .is_some()
    {
        let transaction = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let active_started_commands =
            active_started_count(&transaction, &state.key_bundle, state.database_id)?;
        let command = replay(
            &transaction,
            &state.key_bundle,
            state.database_id,
            &idempotency_token,
            &request_token,
        )?
        .ok_or(RuntimeStoreError::SchemaInspectionRaced)?;
        return Ok(AcceptAdminUpgradeOutcome::Replayed {
            command,
            active_started_commands,
        });
    }
    let pending_plaintext = encode_outcome(&DecodedOutcome::Pending)?;
    let sealed_request_bytes = prepared
        .plaintext
        .len()
        .checked_add(ROW_BLOB_V1_OVERHEAD_LEN)
        .ok_or(RuntimeStoreError::PayloadTooLarge)?;
    let sealed_outcome_bytes = pending_plaintext
        .len()
        .checked_add(ROW_BLOB_V1_OVERHEAD_LEN)
        .ok_or(RuntimeStoreError::PayloadTooLarge)?;
    let charged_bytes = u64::try_from(
        sealed_request_bytes
            .checked_add(sealed_outcome_bytes)
            .ok_or(RuntimeStoreError::PayloadTooLarge)?,
    )
    .map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
    let projected = super::journal::projected_write_bytes(&[
        sealed_request_bytes,
        sealed_outcome_bytes,
        8 * 1024,
    ])?;
    super::sqlite::admit_ordinary_write(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        &state.storage_path,
        &mut state.admission_state,
        config.capacity_probe.as_ref(),
        projected,
        SafetyReserveProjection::AcceptAdminUpgrade,
    )?;

    let transaction = state
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let active_started_commands =
        active_started_count(&transaction, &state.key_bundle, state.database_id)?;
    if let Some(command) = replay(
        &transaction,
        &state.key_bundle,
        state.database_id,
        &idempotency_token,
        &request_token,
    )? {
        return Ok(AcceptAdminUpgradeOutcome::Replayed {
            command,
            active_started_commands,
        });
    }
    let observed_at_ms = config.clock.now_ms().map_err(RuntimeStoreError::from)?;
    if let Some(persisted) =
        latest_state_changed_at(&transaction, &state.key_bundle, state.database_id)?
        && observed_at_ms < persisted
    {
        return Err(RuntimeStoreError::ClockRegressed {
            persisted_ms: persisted,
            observed_ms: observed_at_ms,
        });
    }
    let retain_until_ms = observed_at_ms
        .checked_add(ADMIN_COMMAND_RETENTION_MS)
        .ok_or(RuntimeStoreError::TimeOutOfRange)?;
    let ledger =
        super::sqlite::load_runtime_ledger(&transaction, &state.key_bundle, state.database_id)?;
    ensure_capacity(&ledger, charged_bytes)?;
    let sealed_request = seal(
        &state.key_bundle,
        state.database_id,
        &idempotency_token,
        REQUEST_COLUMN,
        prepared.plaintext.as_ref(),
        MAX_ADMIN_COMMAND_REQUEST_BYTES,
    )?;
    let sealed_outcome = seal(
        &state.key_bundle,
        state.database_id,
        &idempotency_token,
        OUTCOME_COLUMN,
        pending_plaintext.as_ref(),
        MAX_ADMIN_COMMAND_OUTCOME_BYTES,
    )?;
    let token = row_token(
        &state.key_bundle,
        &idempotency_token,
        &request_token,
        &blind_token(
            &state.key_bundle,
            OUTCOME_DOMAIN,
            pending_plaintext.as_ref(),
        )?,
        AdminUpgradeStatus::Pending,
        observed_at_ms,
        observed_at_ms,
        retain_until_ms,
        charged_bytes,
        u64::try_from(sealed_request.len()).map_err(|_| RuntimeStoreError::PayloadTooLarge)?,
        u64::try_from(sealed_outcome.len()).map_err(|_| RuntimeStoreError::PayloadTooLarge)?,
    )?;
    transaction.execute(
        "INSERT INTO admin_commands (
             idempotency_token, command_kind, request_token, state,
             sealed_request, sealed_outcome, created_at_ms, state_changed_at_ms,
             retain_until_ms, charged_bytes, metadata_token
         ) VALUES (?1, 'stageUpgrade', ?2, 'pending', ?3, ?4, ?5, ?5, ?6, ?7, ?8)",
        params![
            &idempotency_token[..],
            &request_token[..],
            sealed_request,
            sealed_outcome,
            i64::try_from(observed_at_ms).map_err(|_| RuntimeStoreError::TimeOutOfRange)?,
            i64::try_from(retain_until_ms).map_err(|_| RuntimeStoreError::TimeOutOfRange)?,
            i64::try_from(charged_bytes).map_err(|_| RuntimeStoreError::PayloadTooLarge)?,
            &token[..],
        ],
    )?;
    let mut next_ledger = ledger.clone();
    next_ledger.admin_command_count = next_ledger
        .admin_command_count
        .checked_add(1)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    next_ledger.admin_command_pending_count = next_ledger
        .admin_command_pending_count
        .checked_add(1)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    next_ledger.admin_command_charged_bytes = next_ledger
        .admin_command_charged_bytes
        .checked_add(charged_bytes)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let _ = super::sqlite::update_runtime_ledger(
        &transaction,
        &state.key_bundle,
        state.database_id,
        &ledger,
        &next_ledger,
    )?;
    config
        .fault_injector
        .before_operation(RuntimeStoreOperation::AcceptAdminUpgradeBeforeCommit)?;
    super::sqlite::commit_transaction(transaction, RuntimeCommitOperation::AcceptAdminUpgrade)?;
    super::sqlite::latch_post_commit_capacity(state, config);
    if config
        .fault_injector
        .before_operation(RuntimeStoreOperation::AcceptAdminUpgradeAfterCommit)
        .is_err()
    {
        return Err(RuntimeStoreError::CommitOutcomeUnknown {
            operation: RuntimeCommitOperation::AcceptAdminUpgrade,
        });
    }
    let command = replay(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        &idempotency_token,
        &request_token,
    )?
    .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    Ok(AcceptAdminUpgradeOutcome::Accepted {
        command,
        active_started_commands,
    })
}

pub(crate) fn query_admin_upgrade(
    state: &RuntimeSqlite,
    prepared: &PreparedAdminUpgradeRequest,
) -> Result<Option<AdminUpgradeCommand>, RuntimeStoreError> {
    let (idempotency_token, request_token) =
        request_tokens(&state.key_bundle, prepared.plaintext.as_ref())?;
    replay(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        &idempotency_token,
        &request_token,
    )
}

fn exact_finalize_replay(
    command: &AdminUpgradeCommand,
    current: &AuthenticatedAdminRow,
    terminal: &DecodedOutcome,
) -> Result<Option<FinalizeAdminUpgradeOutcome>, RuntimeStoreError> {
    if current.command.request_token != command.request_token
        || current.command.request != command.request
        || current.command.created_at_ms != command.created_at_ms
    {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }
    if current.command.status == AdminUpgradeStatus::Pending {
        return Ok(None);
    }
    if current.outcome == *terminal {
        Ok(Some(FinalizeAdminUpgradeOutcome::Replayed {
            command: current.command.clone(),
        }))
    } else {
        Err(RuntimeStoreError::TerminalConflict)
    }
}

pub(crate) fn finalize_admin_upgrade(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    command: AdminUpgradeCommand,
    terminal: AdminUpgradeTerminalOutcome,
) -> Result<FinalizeAdminUpgradeOutcome, RuntimeStoreError> {
    if command.database_id != state.database_id {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }
    let decoded_terminal = match terminal {
        AdminUpgradeTerminalOutcome::Completed => DecodedOutcome::Completed,
        AdminUpgradeTerminalOutcome::Failed { failure } => DecodedOutcome::Failed(failure),
    };
    // exact terminal replay/conflict 是 authenticated read-only readback。after-COMMIT unknown
    // 重试不得因新的容量低水位或 capacity probe 失败拿不到已经提交的 terminal。
    let raw = query_row(&state.connection, &command.idempotency_token)?
        .ok_or(RuntimeStoreError::InvalidStateTransition)?;
    let preflight = authenticate_row(&state.key_bundle, state.database_id, raw)?;
    if let Some(replayed) = exact_finalize_replay(&command, &preflight, &decoded_terminal)? {
        return Ok(replayed);
    }
    super::sqlite::admit_safety_write(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        &state.storage_path,
        config.capacity_probe.as_ref(),
    )?;
    let terminal_plaintext = encode_outcome(&decoded_terminal)?;
    let transaction = state
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let raw = query_row(&transaction, &command.idempotency_token)?
        .ok_or(RuntimeStoreError::InvalidStateTransition)?;
    let current = authenticate_row(&state.key_bundle, state.database_id, raw)?;
    if let Some(replayed) = exact_finalize_replay(&command, &current, &decoded_terminal)? {
        return Ok(replayed);
    }
    let observed_at_ms = config.clock.now_ms().map_err(RuntimeStoreError::from)?;
    if observed_at_ms < current.command.state_changed_at_ms {
        return Err(RuntimeStoreError::ClockRegressed {
            persisted_ms: current.command.state_changed_at_ms,
            observed_ms: observed_at_ms,
        });
    }
    let retain_until_ms = observed_at_ms
        .checked_add(ADMIN_COMMAND_RETENTION_MS)
        .ok_or(RuntimeStoreError::TimeOutOfRange)?;
    let sealed_outcome = seal(
        &state.key_bundle,
        state.database_id,
        &command.idempotency_token,
        OUTCOME_COLUMN,
        terminal_plaintext.as_ref(),
        MAX_ADMIN_COMMAND_OUTCOME_BYTES,
    )?;
    let sealed_request_bytes = current
        .charged_bytes
        .checked_sub(current.sealed_outcome_bytes)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let next_charged = sealed_request_bytes
        .checked_add(
            u64::try_from(sealed_outcome.len()).map_err(|_| RuntimeStoreError::PayloadTooLarge)?,
        )
        .ok_or(RuntimeStoreError::PayloadTooLarge)?;
    let token = row_token(
        &state.key_bundle,
        &command.idempotency_token,
        &command.request_token,
        &blind_token(
            &state.key_bundle,
            OUTCOME_DOMAIN,
            terminal_plaintext.as_ref(),
        )?,
        decoded_terminal.status(),
        command.created_at_ms,
        observed_at_ms,
        retain_until_ms,
        next_charged,
        sealed_request_bytes,
        u64::try_from(sealed_outcome.len()).map_err(|_| RuntimeStoreError::PayloadTooLarge)?,
    )?;
    if transaction.execute(
        "UPDATE admin_commands
         SET state = ?1, sealed_outcome = ?2, state_changed_at_ms = ?3,
             retain_until_ms = ?4, charged_bytes = ?5, metadata_token = ?6
         WHERE idempotency_token = ?7 AND state = 'pending' AND metadata_token = ?8",
        params![
            decoded_terminal.status().as_str(),
            sealed_outcome,
            i64::try_from(observed_at_ms).map_err(|_| RuntimeStoreError::TimeOutOfRange)?,
            i64::try_from(retain_until_ms).map_err(|_| RuntimeStoreError::TimeOutOfRange)?,
            i64::try_from(next_charged).map_err(|_| RuntimeStoreError::PayloadTooLarge)?,
            &token[..],
            &command.idempotency_token[..],
            &current.metadata_token[..],
        ],
    )? != 1
    {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }
    let ledger =
        super::sqlite::load_runtime_ledger(&transaction, &state.key_bundle, state.database_id)?;
    let mut next = ledger.clone();
    next.admin_command_pending_count = next
        .admin_command_pending_count
        .checked_sub(1)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    next.admin_command_charged_bytes = next
        .admin_command_charged_bytes
        .checked_sub(current.charged_bytes)
        .and_then(|value| value.checked_add(next_charged))
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    if next.admin_command_charged_bytes > MAX_ADMIN_COMMAND_CHARGED_BYTES {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let _ = super::sqlite::update_runtime_ledger(
        &transaction,
        &state.key_bundle,
        state.database_id,
        &ledger,
        &next,
    )?;
    config
        .fault_injector
        .before_operation(RuntimeStoreOperation::FinalizeAdminUpgradeBeforeCommit)?;
    super::sqlite::commit_transaction(transaction, RuntimeCommitOperation::FinalizeAdminUpgrade)?;
    super::sqlite::latch_post_commit_capacity(state, config);
    if config
        .fault_injector
        .before_operation(RuntimeStoreOperation::FinalizeAdminUpgradeAfterCommit)
        .is_err()
    {
        return Err(RuntimeStoreError::CommitOutcomeUnknown {
            operation: RuntimeCommitOperation::FinalizeAdminUpgrade,
        });
    }
    let raw = query_row(&state.connection, &command.idempotency_token)?
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    Ok(FinalizeAdminUpgradeOutcome::Finalized {
        command: authenticate_row(&state.key_bundle, state.database_id, raw)?.command,
    })
}

pub(crate) fn load_pending_admin_upgrades(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    cursor: Option<AdminUpgradeRecoveryCursor>,
) -> Result<AdminUpgradeRecoveryPage, RuntimeStoreError> {
    let mut statement = connection.prepare(&format!(
        "{ROW_SELECT} WHERE state = 'pending'
         AND (?1 IS NULL OR idempotency_token > ?1)
         ORDER BY idempotency_token LIMIT ?2"
    ))?;
    let after = cursor.as_ref().map(|cursor| &cursor.0[..]);
    let rows = statement
        .query_map(
            params![
                after,
                i64::try_from(MAX_RECOVERY_PAGE_ITEMS + 1).unwrap_or(i64::MAX)
            ],
            raw_row,
        )?
        .collect::<Result<Vec<_>, _>>()?;
    let has_more = rows.len() > MAX_RECOVERY_PAGE_ITEMS;
    let mut commands = Vec::with_capacity(rows.len().min(MAX_RECOVERY_PAGE_ITEMS));
    for raw in rows.into_iter().take(MAX_RECOVERY_PAGE_ITEMS) {
        let row = authenticate_row(key_bundle, database_id, raw)?;
        if row.command.status != AdminUpgradeStatus::Pending {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        commands.push(row.command);
    }
    let next_cursor = if has_more {
        commands
            .last()
            .map(|command| AdminUpgradeRecoveryCursor(command.idempotency_token))
    } else {
        None
    };
    Ok(AdminUpgradeRecoveryPage {
        commands,
        next_cursor,
    })
}

pub(super) fn validate_v7_integrity(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    ledger: &RuntimeLedger,
) -> Result<(), RuntimeStoreError> {
    let mut statement = connection.prepare(&format!("{ROW_SELECT} ORDER BY idempotency_token"))?;
    let rows = statement.query_map([], raw_row)?;
    let mut count = 0_u64;
    let mut pending = 0_u64;
    let mut charged = 0_u64;
    for raw in rows {
        let row = authenticate_row(key_bundle, database_id, raw?)?;
        count = count
            .checked_add(1)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        pending = pending
            .checked_add(u64::from(row.command.status == AdminUpgradeStatus::Pending))
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        charged = charged
            .checked_add(row.charged_bytes)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        if count > MAX_ADMIN_COMMANDS
            || pending > MAX_PENDING_ADMIN_COMMANDS
            || charged > MAX_ADMIN_COMMAND_CHARGED_BYTES
        {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
    }
    if count != ledger.admin_command_count
        || pending != ledger.admin_command_pending_count
        || charged != ledger.admin_command_charged_bytes
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ledger(count: u64, pending: u64, charged: u64) -> RuntimeLedger {
        RuntimeLedger {
            admin_command_count: count,
            admin_command_pending_count: pending,
            admin_command_charged_bytes: charged,
            ..RuntimeLedger::default()
        }
    }

    #[test]
    fn capacity_count_and_pending_limits_accept_the_boundary_and_reject_one_past() {
        ensure_capacity(&ledger(MAX_ADMIN_COMMANDS - 1, 0, 0), 1)
            .expect("65,536th admin command is accepted");
        assert!(matches!(
            ensure_capacity(&ledger(MAX_ADMIN_COMMANDS, 0, 0), 1),
            Err(RuntimeStoreError::AdminCommandLimit {
                scope: AdminCommandLimitScope::GlobalCount
            })
        ));

        ensure_capacity(&ledger(0, MAX_PENDING_ADMIN_COMMANDS - 1, 0), 1)
            .expect("1,024th pending admin command is accepted");
        assert!(matches!(
            ensure_capacity(&ledger(0, MAX_PENDING_ADMIN_COMMANDS, 0), 1),
            Err(RuntimeStoreError::AdminCommandLimit {
                scope: AdminCommandLimitScope::Pending
            })
        ));
    }

    #[test]
    fn charged_byte_limit_includes_every_pending_terminal_growth_reserve() {
        let new_charge = 1_024_u64;
        let pending_after_accept = 4_u64;
        let terminal_growth = pending_after_accept * MAX_ADMIN_COMMAND_OUTCOME_BYTES as u64;
        let exact_existing = MAX_ADMIN_COMMAND_CHARGED_BYTES - new_charge - terminal_growth;

        ensure_capacity(
            &ledger(3, pending_after_accept - 1, exact_existing),
            new_charge,
        )
        .expect("exact 64 MiB projected charge is accepted");
        assert!(matches!(
            ensure_capacity(
                &ledger(3, pending_after_accept - 1, exact_existing + 1),
                new_charge,
            ),
            Err(RuntimeStoreError::AdminCommandLimit {
                scope: AdminCommandLimitScope::ChargedBytes
            })
        ));
    }
}
