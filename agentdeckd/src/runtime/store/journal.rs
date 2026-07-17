//! Runtime durable journal 的事务实现。
//!
//! 所有 ID/high-water 分配、command 状态变化和 canonical event 都只在单一
//! `BEGIN IMMEDIATE` 中发生；公开 outcome 只在 COMMIT 成功后返回。

use std::collections::{HashMap, HashSet};
use std::mem::size_of;

use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use zeroize::Zeroizing;

use crate::runtime::adapter_state::AdapterStateNamespace;
use crate::runtime::events::{CommandStreamEffects, PendingStreamTargets};
use crate::runtime::model::{
    AcceptCommand, AcceptOutcome, AcceptedTerminationReason, AuthorizeExecutionRelease,
    COMMAND_LEDGER_RETENTION_MS, COMMAND_QUEUE_TTL_MS, CommandReceiptRecord,
    CommandReceiptSelector, CommandRecord, CommandState, CompleteCommand, CompleteOutcome,
    ConversationDescriptor, ConversationLifecycle, ConversationRecord, ConversationRecoveryRecord,
    CreateConversationOutcome, EventRecord, ExecutionFence, ExecutionFenceRecord,
    ExecutionIntentRecord, IdempotencyOwner, MAX_ADAPTER_STATE_REFERENCE_BYTES,
    MAX_COMMAND_PAYLOAD_BYTES, MAX_COMMAND_RESULT_BYTES, MAX_CONVERSATION_DESCRIPTOR_BYTES,
    MAX_EXECUTION_FENCE_BYTES, MAX_EXECUTION_INTENT_BYTES, MAX_EXECUTION_NONCE_BYTES,
    MAX_IDEMPOTENCY_KEY_BYTES, MAX_RECOVERY_PAGE_RETAINED_BYTES, MAX_RUNTIME_EVENT_BYTES,
    MarkConversationRecoveryBlocked, NewConversation, QueryCommandReceipt, RecoverStartedCommand,
    RecoveryBlockedCommandBinding, RecoveryCompletion, RecoveryCursor, RecoveryFenceBinding,
    RecoveryPage, RuntimeCommitOperation, RuntimeStoreConfig, RuntimeStoreError,
    RuntimeStoreOperation, SanitizedTerminalFailure, StartCommand, StartOutcome,
    StartedBeforeReleaseTermination, StartedRecoveryRecord, TerminalState,
    TerminateAcceptedCommand, TerminateAcceptedOutcome, TerminateStartedBeforeRelease,
    TerminateStartedBeforeReleaseOutcome,
};
use crate::security::SecretBytes;

use super::approval;
use super::cipher::RowAad;
use super::command_event::{self, CommandEventIdentity, StartEventSource};
use super::execution_event::{AppendExecutionEventOutcome, PreparedExecutionEvent};
use super::identity::{
    MAX_RUNTIME_ID_COLLISION_ATTEMPTS, RuntimeId, RuntimeIdError, RuntimeIdKind,
};
use super::persisted_event::{PersistedRuntimeEvent, decode_persisted_runtime_event};
use super::queue::{QueueAdmission, evaluate_queue_admission};
use super::schema::{RUNTIME_CRYPTO_CONTEXT_VERSION, RUNTIME_SCHEMA_FAMILY};
use super::sequence::{SequenceScope, decode_sequence, next_sequence};
use super::sqlite::{
    self, RecoveryScanCounts, RecoveryScanState, RuntimeSqlite, SafetyReserveProjection,
};

/// 每次普通事务除显式 payload 外预留的 row/index/sequence 固定开销。
const RUNTIME_WRITE_FIXED_OVERHEAD_BYTES: u64 = 64 * 1024;

const COMMAND_MAGIC: &[u8; 4] = b"ADC1";
const INTENT_MAGIC: &[u8; 4] = b"ADI1";
const FENCE_MAGIC: &[u8; 4] = b"ADF2";
const EXPIRY_EVENT_MAGIC: &[u8; 4] = b"ADX1";
const CANCELED_BEFORE_START_TOKEN_DOMAIN_V1: &[u8] = b"command.canceled-before-start.v1";
const REVOKED_BEFORE_START_TOKEN_DOMAIN_V1: &[u8] = b"command.revoked-before-start.v1";
const CANCELED_BEFORE_START_TOKEN_DOMAIN_V2: &[u8] = b"command.canceled-before-start.v2";
const REVOKED_BEFORE_START_TOKEN_DOMAIN_V2: &[u8] = b"command.revoked-before-start.v2";
const MAX_SEALED_INTENT_BYTES: usize = MAX_EXECUTION_INTENT_BYTES + MAX_EXECUTION_NONCE_BYTES + 128;
const MAX_SEALED_FENCE_BYTES: usize = MAX_EXECUTION_FENCE_BYTES + MAX_EXECUTION_NONCE_BYTES + 128;

struct CommandIndexTokens {
    owner_token: Vec<u8>,
    idempotency_token: Vec<u8>,
    payload_token: Vec<u8>,
    terminal_token: Option<Vec<u8>>,
    metadata_token: Vec<u8>,
}

struct RawAdapterStateBinding {
    state_key_token: Vec<u8>,
    conversation_id: Vec<u8>,
    state_reference_token: Vec<u8>,
    sealed_state_reference: Vec<u8>,
}

pub(super) fn bind_adapter_state(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    namespace: AdapterStateNamespace,
    adapter_state_key: RuntimeId,
    state_reference: SecretBytes,
) -> Result<(), RuntimeStoreError> {
    ensure_kind(adapter_state_key, RuntimeIdKind::AdapterState)?;
    if state_reference.expose_secret().is_empty()
        || state_reference.expose_secret().len() > MAX_ADAPTER_STATE_REFERENCE_BYTES
    {
        return Err(RuntimeStoreError::InvalidConfig(
            "adapter state reference must contain 1 to 4096 bytes",
        ));
    }

    let conversation = load_conversation_for_adapter_state(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        adapter_state_key,
    )?;
    ensure_adapter_state_namespace(&conversation, namespace)?;
    if let Some(existing) = load_adapter_state_binding_for_conversation(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        namespace,
        &conversation,
    )? {
        return if existing.expose_secret() == state_reference.expose_secret() {
            Ok(())
        } else {
            Err(RuntimeStoreError::AdapterStateConflict)
        };
    }
    if load_adapter_state_binding_for_conversation(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        namespace.other(),
        &conversation,
    )?
    .is_some()
    {
        return Err(RuntimeStoreError::AdapterStateNamespaceMismatch);
    }

    let projected = projected_write_bytes(&[
        state_reference.expose_secret().len(),
        state_reference.expose_secret().len(),
    ])?;
    sqlite::admit_ordinary_write(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        &state.storage_path,
        &mut state.admission_state,
        config.capacity_probe.as_ref(),
        projected,
        SafetyReserveProjection::Current,
    )?;

    let database_id = state.database_id;
    let key_bundle = &state.key_bundle;
    let transaction = state
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let conversation = load_conversation_for_adapter_state(
        &transaction,
        key_bundle,
        database_id,
        adapter_state_key,
    )?;
    ensure_adapter_state_namespace(&conversation, namespace)?;
    if let Some(existing) = load_adapter_state_binding_for_conversation(
        &transaction,
        key_bundle,
        database_id,
        namespace,
        &conversation,
    )? {
        return if existing.expose_secret() == state_reference.expose_secret() {
            Ok(())
        } else {
            Err(RuntimeStoreError::AdapterStateConflict)
        };
    }
    if load_adapter_state_binding_for_conversation(
        &transaction,
        key_bundle,
        database_id,
        namespace.other(),
        &conversation,
    )?
    .is_some()
    {
        return Err(RuntimeStoreError::AdapterStateNamespaceMismatch);
    }

    let state_key_token =
        key_bundle.blind_index(namespace.key_token_domain(), adapter_state_key.as_bytes())?;
    let state_reference_token = key_bundle.blind_index(
        namespace.reference_token_domain(),
        state_reference.expose_secret(),
    )?;
    if adapter_reference_token_exists(&transaction, namespace, state_reference_token.as_bytes())? {
        return Err(RuntimeStoreError::AdapterStateConflict);
    }
    let primary_key = adapter_state_primary_key(
        state_key_token.as_bytes(),
        conversation.conversation_id.as_bytes(),
        state_reference_token.as_bytes(),
    );
    let sealed_state_reference = seal(
        key_bundle,
        database_id,
        namespace.table_bytes(),
        &primary_key,
        b"sealed_state_reference",
        state_reference.expose_secret(),
        MAX_ADAPTER_STATE_REFERENCE_BYTES,
    )?;
    let sql = match namespace {
        AdapterStateNamespace::Codex => {
            "INSERT INTO codex_adapter_state (
                 state_key_token, conversation_id, state_reference_token, sealed_state_reference
             ) VALUES (?1, ?2, ?3, ?4)"
        }
        AdapterStateNamespace::ClaudeCode => {
            "INSERT INTO claude_code_adapter_state (
                 state_key_token, conversation_id, state_reference_token, sealed_state_reference
             ) VALUES (?1, ?2, ?3, ?4)"
        }
    };
    transaction.execute(
        sql,
        params![
            &state_key_token.as_bytes()[..],
            &conversation.conversation_id.as_bytes()[..],
            &state_reference_token.as_bytes()[..],
            sealed_state_reference,
        ],
    )?;
    let ledger = sqlite::load_runtime_ledger(&transaction, key_bundle, database_id)?;
    let mut next_ledger = ledger.clone();
    match namespace {
        AdapterStateNamespace::Codex => {
            next_ledger.codex_adapter_state_count = next_ledger
                .codex_adapter_state_count
                .checked_add(1)
                .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        }
        AdapterStateNamespace::ClaudeCode => {
            next_ledger.claude_code_adapter_state_count = next_ledger
                .claude_code_adapter_state_count
                .checked_add(1)
                .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        }
    }
    let _pending_targets = sqlite::update_runtime_ledger(
        &transaction,
        key_bundle,
        database_id,
        &ledger,
        &next_ledger,
    )?;
    config
        .fault_injector
        .before_operation(RuntimeStoreOperation::BindAdapterStateBeforeCommit)?;
    commit_transaction(transaction, RuntimeCommitOperation::BindAdapterState)?;
    sqlite::latch_post_commit_capacity(state, config);
    after_commit(
        config,
        RuntimeStoreOperation::BindAdapterStateAfterCommit,
        RuntimeCommitOperation::BindAdapterState,
    )?;
    Ok(())
}

pub(super) fn resolve_adapter_state(
    state: &RuntimeSqlite,
    namespace: AdapterStateNamespace,
    adapter_state_key: RuntimeId,
) -> Result<Option<SecretBytes>, RuntimeStoreError> {
    ensure_kind(adapter_state_key, RuntimeIdKind::AdapterState)?;
    let conversation = load_conversation_for_adapter_state(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        adapter_state_key,
    )?;
    ensure_adapter_state_namespace(&conversation, namespace)?;
    let requested = load_adapter_state_binding_for_conversation(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        namespace,
        &conversation,
    )?;
    let other = load_adapter_state_binding_for_conversation(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        namespace.other(),
        &conversation,
    )?;
    match (requested, other) {
        (Some(_), Some(_)) => Err(RuntimeStoreError::UnknownOrCorruptSchema),
        (Some(reference), None) => Ok(Some(reference)),
        (None, Some(_)) => Err(RuntimeStoreError::AdapterStateNamespaceMismatch),
        (None, None) => Ok(None),
    }
}

fn ensure_adapter_state_namespace(
    conversation: &ConversationRecord,
    namespace: AdapterStateNamespace,
) -> Result<(), RuntimeStoreError> {
    if conversation.descriptor.agent_kind != namespace.agent_kind() {
        return Err(RuntimeStoreError::AdapterStateNamespaceMismatch);
    }
    Ok(())
}

fn load_conversation_for_adapter_state(
    connection: &Connection,
    key_bundle: &super::cipher::RuntimeKeyBundle,
    database_id: [u8; 16],
    adapter_state_key: RuntimeId,
) -> Result<ConversationRecord, RuntimeStoreError> {
    let raw: Option<Vec<u8>> = connection
        .query_row(
            "SELECT conversation_id FROM conversations WHERE adapter_state_key = ?1",
            [&adapter_state_key.as_bytes()[..]],
            |row| row.get(0),
        )
        .optional()?;
    let conversation_id = raw
        .map(|value| runtime_id(RuntimeIdKind::Conversation, value))
        .transpose()?
        .ok_or(RuntimeStoreError::ConversationNotFound)?;
    let conversation = load_conversation(connection, key_bundle, database_id, conversation_id)?;
    if conversation.adapter_state_key != adapter_state_key {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(conversation)
}

fn load_adapter_state_binding_for_conversation(
    connection: &Connection,
    key_bundle: &super::cipher::RuntimeKeyBundle,
    database_id: [u8; 16],
    namespace: AdapterStateNamespace,
    conversation: &ConversationRecord,
) -> Result<Option<SecretBytes>, RuntimeStoreError> {
    let expected_key_token = key_bundle.blind_index(
        namespace.key_token_domain(),
        conversation.adapter_state_key.as_bytes(),
    )?;
    let sql = match namespace {
        AdapterStateNamespace::Codex => {
            "SELECT state_key_token, conversation_id, state_reference_token,
                    sealed_state_reference
             FROM codex_adapter_state
             WHERE state_key_token = ?1 OR conversation_id = ?2"
        }
        AdapterStateNamespace::ClaudeCode => {
            "SELECT state_key_token, conversation_id, state_reference_token,
                    sealed_state_reference
             FROM claude_code_adapter_state
             WHERE state_key_token = ?1 OR conversation_id = ?2"
        }
    };
    let raw: Option<RawAdapterStateBinding> = connection
        .query_row(
            sql,
            params![
                &expected_key_token.as_bytes()[..],
                &conversation.conversation_id.as_bytes()[..],
            ],
            |row| {
                Ok(RawAdapterStateBinding {
                    state_key_token: row.get(0)?,
                    conversation_id: row.get(1)?,
                    state_reference_token: row.get(2)?,
                    sealed_state_reference: row.get(3)?,
                })
            },
        )
        .optional()?;
    let Some(raw) = raw else {
        return Ok(None);
    };
    if raw.state_key_token.as_slice() != expected_key_token.as_bytes()
        || raw.conversation_id.as_slice() != conversation.conversation_id.as_bytes()
        || raw.state_reference_token.len() != 32
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let primary_key = adapter_state_primary_key(
        expected_key_token.as_bytes(),
        conversation.conversation_id.as_bytes(),
        &raw.state_reference_token,
    );
    let reference = open(
        key_bundle,
        database_id,
        namespace.table_bytes(),
        &primary_key,
        b"sealed_state_reference",
        &raw.sealed_state_reference,
        MAX_ADAPTER_STATE_REFERENCE_BYTES,
    )?;
    if reference.expose_secret().is_empty() {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let expected_reference_token = key_bundle.blind_index(
        namespace.reference_token_domain(),
        reference.expose_secret(),
    )?;
    if raw.state_reference_token.as_slice() != expected_reference_token.as_bytes() {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(Some(reference))
}

fn adapter_reference_token_exists(
    connection: &Connection,
    namespace: AdapterStateNamespace,
    token: &[u8; 32],
) -> Result<bool, RuntimeStoreError> {
    let sql = match namespace {
        AdapterStateNamespace::Codex => {
            "SELECT EXISTS(SELECT 1 FROM codex_adapter_state WHERE state_reference_token = ?1)"
        }
        AdapterStateNamespace::ClaudeCode => {
            "SELECT EXISTS(SELECT 1 FROM claude_code_adapter_state WHERE state_reference_token = ?1)"
        }
    };
    let exists: i64 = connection.query_row(sql, [&token[..]], |row| row.get(0))?;
    Ok(exists != 0)
}

fn adapter_state_primary_key(
    state_key_token: &[u8; 32],
    conversation_id: &[u8; 16],
    state_reference_token: &[u8],
) -> Vec<u8> {
    let mut primary_key = Vec::with_capacity(84);
    primary_key.extend_from_slice(b"ADS1");
    primary_key.extend_from_slice(state_key_token);
    primary_key.extend_from_slice(conversation_id);
    primary_key.extend_from_slice(state_reference_token);
    primary_key
}

struct RawCommandMetadata {
    conversation_id: Vec<u8>,
    command_seq: String,
    command_id: Vec<u8>,
    owner_token: Vec<u8>,
    idempotency_token: Vec<u8>,
    payload_token: Vec<u8>,
    terminal_token: Option<Vec<u8>>,
    turn_id: Option<Vec<u8>>,
    started_event_id: Option<Vec<u8>>,
    terminal_event_id: Option<Vec<u8>>,
    state: String,
    logical_payload_bytes: i64,
    accepted_at_ms: i64,
    expires_at_ms: i64,
    retain_until_ms: i64,
    started_at_ms: Option<i64>,
    terminal_at_ms: Option<i64>,
    metadata_token: Vec<u8>,
    sealed_result_present: bool,
}

#[derive(Default)]
struct ConversationCatalogSummary {
    latest_updated_at_ms: Option<u64>,
    adapter_owner: Option<RuntimeId>,
    max_catalog_revision: Option<u64>,
    conversation_count: u64,
    accepted_count: u64,
}

#[derive(Default)]
pub(crate) struct CommandLedgerSummary {
    total_count: u64,
    accepted_count: u64,
    accepted_payload_bytes: u64,
    started_count: u64,
}

pub(crate) fn create_conversation(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    input: NewConversation,
    descriptor_bytes: Zeroizing<Vec<u8>>,
    effects: &mut CommandStreamEffects,
) -> Result<CreateConversationOutcome, RuntimeStoreError> {
    ensure_kind(input.conversation_id, RuntimeIdKind::Conversation)?;
    ensure_kind(input.adapter_state_key, RuntimeIdKind::AdapterState)?;
    validate_payload_len(descriptor_bytes.len(), MAX_CONVERSATION_DESCRIPTOR_BYTES)?;
    if let Some(existing) = load_optional_conversation(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        input.conversation_id,
    )? {
        if existing.adapter_state_key == input.adapter_state_key
            && existing.descriptor == input.descriptor
        {
            return Ok(CreateConversationOutcome::Replayed {
                conversation: existing,
            });
        }
        return Err(RuntimeStoreError::ConversationConflict);
    }
    let preflight_catalog = validate_conversation_catalog(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        Some(input.adapter_state_key),
        false,
    )?;
    if preflight_catalog.adapter_owner.is_some() {
        return Err(RuntimeStoreError::ConversationConflict);
    }
    let preflight_ledger =
        sqlite::load_runtime_ledger(&state.connection, &state.key_bundle, state.database_id)?;
    if preflight_ledger.conversation_count >= config.conversation_capacity {
        return Err(RuntimeStoreError::ConversationLimit);
    }
    let created_at_ms = config.clock.now_ms()?;
    if preflight_catalog
        .latest_updated_at_ms
        .is_some_and(|latest| created_at_ms < latest)
    {
        return Err(RuntimeStoreError::ClockRegressed {
            persisted_ms: preflight_catalog.latest_updated_at_ms.unwrap_or_default(),
            observed_ms: created_at_ms,
        });
    }
    let created_at = sqlite_time(created_at_ms)?;
    let projected_write_bytes =
        projected_write_bytes(&[descriptor_bytes.len(), descriptor_bytes.len(), 4 * 1024])?;
    sqlite::admit_ordinary_write(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        &state.storage_path,
        &mut state.admission_state,
        config.capacity_probe.as_ref(),
        projected_write_bytes,
        SafetyReserveProjection::Current,
    )?;
    let database_id = state.database_id;
    let key_bundle = &state.key_bundle;
    let transaction = state
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let ledger = sqlite::load_runtime_ledger(&transaction, key_bundle, database_id)?;
    if ledger.conversation_count >= config.conversation_capacity {
        return Err(RuntimeStoreError::ConversationLimit);
    }
    if load_optional_conversation(&transaction, key_bundle, database_id, input.conversation_id)?
        .is_some()
    {
        return Err(RuntimeStoreError::ConversationConflict);
    }
    let catalog = validate_conversation_catalog(
        &transaction,
        key_bundle,
        database_id,
        Some(input.adapter_state_key),
        false,
    )?;
    if catalog.adapter_owner.is_some() {
        return Err(RuntimeStoreError::ConversationConflict);
    }
    if let Some(latest_updated_at) = catalog.latest_updated_at_ms
        && created_at_ms < latest_updated_at
    {
        return Err(RuntimeStoreError::ClockRegressed {
            persisted_ms: latest_updated_at,
            observed_ms: created_at_ms,
        });
    }
    let revision = next_sequence(
        SequenceScope::CatalogRevision,
        ledger.catalog_high_water.as_deref(),
    )?;
    let metadata_token = conversation_metadata_token(
        key_bundle,
        input.conversation_id,
        input.adapter_state_key,
        revision.value,
        None,
        None,
        0,
        ConversationLifecycle::Active,
        created_at_ms,
        created_at_ms,
    )?;
    let sealed_descriptor = seal(
        key_bundle,
        database_id,
        b"conversations",
        input.conversation_id.as_bytes(),
        b"sealed_descriptor",
        descriptor_bytes.as_ref(),
        MAX_CONVERSATION_DESCRIPTOR_BYTES,
    )?;
    transaction.execute(
        "INSERT INTO conversations (
             conversation_id, adapter_state_key, catalog_revision,
             command_high_water, event_high_water, lifecycle,
             created_at_ms, updated_at_ms, accepted_count, metadata_token,
             sealed_descriptor
         ) VALUES (?1, ?2, ?3, NULL, NULL, 'active', ?4, ?4, 0, ?5, ?6)",
        params![
            &input.conversation_id.as_bytes()[..],
            &input.adapter_state_key.as_bytes()[..],
            revision.encoded,
            created_at,
            &metadata_token[..],
            sealed_descriptor,
        ],
    )?;
    super::configuration::insert_fresh_managed_state(
        &transaction,
        key_bundle,
        input.conversation_id.as_bytes(),
    )?;
    let mut next_ledger = ledger.clone();
    next_ledger.catalog_high_water = Some(revision.encoded.clone());
    next_ledger.conversation_count = next_ledger
        .conversation_count
        .checked_add(1)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let pending_targets = sqlite::update_runtime_ledger(
        &transaction,
        key_bundle,
        database_id,
        &ledger,
        &next_ledger,
    )?;
    config
        .fault_injector
        .before_operation(RuntimeStoreOperation::CreateConversationBeforeCommit)?;
    commit_transaction_with_effects(
        transaction,
        RuntimeCommitOperation::CreateConversation,
        pending_targets,
        effects,
    )?;
    sqlite::latch_post_commit_capacity(state, config);
    after_commit(
        config,
        RuntimeStoreOperation::CreateConversationAfterCommit,
        RuntimeCommitOperation::CreateConversation,
    )?;
    Ok(CreateConversationOutcome::Created {
        conversation: ConversationRecord {
            conversation_id: input.conversation_id,
            adapter_state_key: input.adapter_state_key,
            catalog_revision: revision.value,
            command_high_water: None,
            event_high_water: None,
            accepted_command_count: 0,
            lifecycle: ConversationLifecycle::Active,
            created_at_ms,
            updated_at_ms: created_at_ms,
            descriptor: input.descriptor,
        },
    })
}

/// 威胁场景：daemon 已确认某个旧 execution 无法安全 fencing，却在仅内存阻断后再次
/// 崩溃；若该状态没有写入 authenticated conversation row，下次启动会把同一队列重新
/// 安装并与未知旧进程并发。该 safety transaction 先验证当前 metadata MAC 与可选的
/// command/turn 绑定，再用旧 token 做 CAS，把 lifecycle 原子推进为 RecoveryBlocked。
pub(crate) fn mark_conversation_recovery_blocked(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    input: MarkConversationRecoveryBlocked,
) -> Result<ConversationRecord, RuntimeStoreError> {
    ensure_kind(input.conversation_id, RuntimeIdKind::Conversation)?;

    let database_id = state.database_id;
    let key_bundle = &state.key_bundle;
    let transaction = state
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let conversation =
        load_conversation(&transaction, key_bundle, database_id, input.conversation_id)?;

    match &input.expected_command {
        None => {
            if authenticated_started_command(
                &transaction,
                key_bundle,
                database_id,
                input.conversation_id,
            )?
            .is_some()
            {
                return Err(RuntimeStoreError::StartConflict);
            }
        }
        Some(RecoveryBlockedCommandBinding::Accepted { command_id }) => {
            ensure_kind(*command_id, RuntimeIdKind::Command)?;
            let command = load_command(&transaction, key_bundle, database_id, *command_id)?;
            if command.conversation_id != input.conversation_id {
                return Err(RuntimeStoreError::CommandNotFound);
            }
            if command.state != CommandState::Accepted || command.turn_id.is_some() {
                return Err(RuntimeStoreError::StartConflict);
            }
            if authenticated_started_command(
                &transaction,
                key_bundle,
                database_id,
                input.conversation_id,
            )?
            .is_some()
            {
                return Err(RuntimeStoreError::StartConflict);
            }
        }
        Some(RecoveryBlockedCommandBinding::Started {
            command_id,
            turn_id,
            daemon_boot_id,
            execution_nonce,
            fence,
        }) => {
            ensure_kind(*command_id, RuntimeIdKind::Command)?;
            ensure_kind(*turn_id, RuntimeIdKind::Turn)?;
            ensure_kind(*daemon_boot_id, RuntimeIdKind::DaemonBoot)?;
            if execution_nonce.is_empty() || execution_nonce.len() > MAX_EXECUTION_NONCE_BYTES {
                return Err(RuntimeStoreError::InvalidConfig(
                    "recovery-blocked execution nonce must contain 1 to 1024 bytes",
                ));
            }
            let command = load_command(&transaction, key_bundle, database_id, *command_id)?;
            if command.conversation_id != input.conversation_id {
                return Err(RuntimeStoreError::CommandNotFound);
            }
            if command.state != CommandState::Started || command.turn_id != Some(*turn_id) {
                return Err(RuntimeStoreError::StartConflict);
            }
            let intent = load_intent(&transaction, key_bundle, database_id, *command_id)?;
            let started_event = load_event(
                &transaction,
                key_bundle,
                database_id,
                intent.started_event_id,
            )?;
            validate_started_linkage(&command, &intent, &started_event)?;
            if intent.turn_id != *turn_id
                || intent.daemon_boot_id != *daemon_boot_id
                || intent.execution_nonce != *execution_nonce
            {
                return Err(RuntimeStoreError::StartConflict);
            }
            let observed_fence =
                load_optional_fence(&transaction, key_bundle, database_id, *command_id)?;
            let observed_binding = observed_fence
                .as_ref()
                .map(RecoveryFenceBinding::from_record);
            if observed_binding.as_ref() != fence.as_deref() {
                return Err(RuntimeStoreError::FenceConflict);
            }
            if fence.as_ref().is_some_and(|fence| {
                fence.command_id != *command_id
                    || fence.daemon_boot_id != *daemon_boot_id
                    || fence.execution_nonce != *execution_nonce
            }) {
                return Err(RuntimeStoreError::FenceConflict);
            }
        }
    }

    if conversation.lifecycle == ConversationLifecycle::RecoveryBlocked {
        return Ok(conversation);
    }
    if conversation.lifecycle != ConversationLifecycle::Active {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }

    sqlite::admit_safety_write(
        &transaction,
        key_bundle,
        database_id,
        &state.storage_path,
        config.capacity_probe.as_ref(),
    )?;
    let updated_at_ms = config.clock.now_ms()?.max(conversation.updated_at_ms);
    let old_token = conversation_metadata_token(
        key_bundle,
        conversation.conversation_id,
        conversation.adapter_state_key,
        conversation.catalog_revision,
        conversation.command_high_water,
        conversation.event_high_water,
        conversation.accepted_command_count,
        conversation.lifecycle,
        conversation.created_at_ms,
        conversation.updated_at_ms,
    )?;
    let new_token = conversation_metadata_token(
        key_bundle,
        conversation.conversation_id,
        conversation.adapter_state_key,
        conversation.catalog_revision,
        conversation.command_high_water,
        conversation.event_high_water,
        conversation.accepted_command_count,
        ConversationLifecycle::RecoveryBlocked,
        conversation.created_at_ms,
        updated_at_ms,
    )?;
    if transaction.execute(
        "UPDATE conversations
         SET lifecycle = 'recoveryBlocked', updated_at_ms = ?1, metadata_token = ?2
         WHERE conversation_id = ?3 AND lifecycle = 'active' AND metadata_token = ?4",
        params![
            sqlite_time(updated_at_ms)?,
            &new_token[..],
            &input.conversation_id.as_bytes()[..],
            &old_token[..],
        ],
    )? != 1
    {
        return Err(RuntimeStoreError::SchemaInspectionRaced);
    }
    config
        .fault_injector
        .before_operation(RuntimeStoreOperation::MarkConversationRecoveryBlockedBeforeCommit)?;
    commit_transaction(
        transaction,
        RuntimeCommitOperation::MarkConversationRecoveryBlocked,
    )?;
    sqlite::latch_post_commit_capacity(state, config);
    after_commit(
        config,
        RuntimeStoreOperation::MarkConversationRecoveryBlockedAfterCommit,
        RuntimeCommitOperation::MarkConversationRecoveryBlocked,
    )?;
    Ok(ConversationRecord {
        lifecycle: ConversationLifecycle::RecoveryBlocked,
        updated_at_ms,
        ..conversation
    })
}

pub(crate) fn accept_command(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    input: AcceptCommand,
    effects: &mut CommandStreamEffects,
) -> Result<AcceptOutcome, RuntimeStoreError> {
    ensure_kind(input.conversation_id, RuntimeIdKind::Conversation)?;
    validate_payload_len(input.payload.len(), MAX_COMMAND_PAYLOAD_BYTES)?;
    if input.idempotency_key.is_empty() || input.idempotency_key.len() > MAX_IDEMPOTENCY_KEY_BYTES {
        return Err(RuntimeStoreError::InvalidConfig(
            "idempotency key must contain 1 to 1024 UTF-8 bytes",
        ));
    }
    let owner_bytes = Zeroizing::new(canonical_owner_v1(&input.owner));
    let owner_token = state
        .key_bundle
        .blind_index(b"command.owner.v1", owner_bytes.as_ref())?;
    let idempotency_bytes = Zeroizing::new(canonical_fields(&[
        input.conversation_id.as_bytes(),
        owner_bytes.as_ref(),
        input.idempotency_key.as_bytes(),
    ])?);
    let idempotency_token = state
        .key_bundle
        .blind_index(b"command.idempotency.v1", idempotency_bytes.as_ref())?;
    let payload_token = super::command_configuration::command_payload_token(
        &state.key_bundle,
        input.expected_configuration_revision,
        &input.payload,
    )?;

    let database_id = state.database_id;
    let preflight_ledger =
        sqlite::load_runtime_ledger(&state.connection, &state.key_bundle, database_id)?;
    if let Some((command_id, persisted_payload_token)) = state
        .connection
        .query_row(
            "SELECT command_id, payload_token FROM commands WHERE idempotency_token = ?1",
            [&idempotency_token.as_bytes()[..]],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )
        .optional()?
    {
        let command_id = runtime_id(RuntimeIdKind::Command, command_id)?;
        let command = load_command(
            &state.connection,
            &state.key_bundle,
            database_id,
            command_id,
        )?;
        if persisted_payload_token.as_slice() != payload_token {
            return Err(RuntimeStoreError::IdempotencyConflict);
        }
        return Ok(AcceptOutcome::Replayed { command });
    }
    super::command_configuration::validate_fresh_admission(
        &state.connection,
        &state.key_bundle,
        database_id,
        input.conversation_id,
        input.expected_configuration_revision,
    )?;
    super::command_configuration::ensure_pin_capacity(&preflight_ledger)?;
    let accepted_at_ms = config.clock.now_ms()?;
    expire_accepted_commands(state, config, accepted_at_ms, effects)?;
    let accepted_at = sqlite_time(accepted_at_ms)?;
    let expires_at_ms = accepted_at_ms
        .checked_add(COMMAND_QUEUE_TTL_MS)
        .ok_or(RuntimeStoreError::TimeOutOfRange)?;
    let retain_until_ms = expires_at_ms
        .checked_add(COMMAND_LEDGER_RETENTION_MS)
        .ok_or(RuntimeStoreError::TimeOutOfRange)?;
    let expires_at = sqlite_time(expires_at_ms)?;
    let retain_until = sqlite_time(retain_until_ms)?;
    let projected_write_bytes =
        projected_write_bytes(&[input.idempotency_key.len(), input.payload.len(), 1024])?;
    let (preflight_conversation, _, _) = load_new_command_queue_state(
        &state.connection,
        &state.key_bundle,
        database_id,
        input.conversation_id,
        input.payload.len(),
    )?;
    if accepted_at_ms < preflight_conversation.updated_at_ms {
        return Err(RuntimeStoreError::ClockRegressed {
            persisted_ms: preflight_conversation.updated_at_ms,
            observed_ms: accepted_at_ms,
        });
    }
    sqlite::admit_ordinary_write(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        &state.storage_path,
        &mut state.admission_state,
        config.capacity_probe.as_ref(),
        projected_write_bytes,
        SafetyReserveProjection::AcceptCommand,
    )?;
    let key_bundle = &state.key_bundle;
    let transaction = state
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    if let Some((command_id, persisted_payload_token)) = transaction
        .query_row(
            "SELECT command_id, payload_token FROM commands WHERE idempotency_token = ?1",
            [&idempotency_token.as_bytes()[..]],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )
        .optional()?
    {
        let command_id = runtime_id(RuntimeIdKind::Command, command_id)?;
        let command = load_command(&transaction, key_bundle, database_id, command_id)?;
        if persisted_payload_token.as_slice() != payload_token {
            return Err(RuntimeStoreError::IdempotencyConflict);
        }
        return Ok(AcceptOutcome::Replayed { command });
    }
    let configuration_revision = super::command_configuration::validate_fresh_admission(
        &transaction,
        key_bundle,
        database_id,
        input.conversation_id,
        input.expected_configuration_revision,
    )?;
    let (conversation, ledger, queue_admission) = load_new_command_queue_state(
        &transaction,
        key_bundle,
        database_id,
        input.conversation_id,
        input.payload.len(),
    )?;
    super::command_configuration::ensure_pin_capacity(&ledger)?;

    if accepted_at_ms < conversation.updated_at_ms {
        return Err(RuntimeStoreError::ClockRegressed {
            persisted_ms: conversation.updated_at_ms,
            observed_ms: accepted_at_ms,
        });
    }

    let previous = conversation
        .command_high_water
        .map(super::sequence::encode_sequence);
    let command_seq = next_sequence(SequenceScope::CommandSeq, previous.as_deref())?;
    let command_id = allocate_id(&transaction, config, RuntimeIdKind::Command)?;
    let command_plaintext = Zeroizing::new(encode_fields(
        COMMAND_MAGIC,
        &[
            owner_bytes.as_ref(),
            input.idempotency_key.as_bytes(),
            &input.payload,
        ],
    )?);
    let sealed_command = seal(
        key_bundle,
        database_id,
        b"commands",
        command_id.as_bytes(),
        b"sealed_command",
        command_plaintext.as_ref(),
        MAX_CONVERSATION_DESCRIPTOR_BYTES,
    )?;
    let logical_payload_bytes =
        u64::try_from(input.payload.len()).map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
    let metadata_token = command_metadata_token(
        key_bundle,
        input.conversation_id,
        command_id,
        command_seq.value,
        owner_token.as_bytes(),
        idempotency_token.as_bytes(),
        &payload_token,
        None,
        CommandState::Accepted,
        logical_payload_bytes,
        accepted_at_ms,
        expires_at_ms,
        retain_until_ms,
        None,
        None,
        None,
        None,
        None,
    )?;
    transaction.execute(
        "INSERT INTO commands (
             conversation_id, command_seq, command_id, owner_token,
             idempotency_token, payload_token, terminal_token,
             turn_id, started_event_id, terminal_event_id,
             state, logical_payload_bytes, accepted_at_ms, expires_at_ms,
             retain_until_ms, started_at_ms, terminal_at_ms,
             metadata_token, sealed_command, sealed_result
         ) VALUES (
             ?1, ?2, ?3, ?4, ?5, ?6, NULL, NULL, NULL, NULL,
             'accepted', ?7, ?8, ?9, ?10, NULL, NULL, ?11, ?12, NULL
         )",
        params![
            &input.conversation_id.as_bytes()[..],
            command_seq.encoded,
            &command_id.as_bytes()[..],
            &owner_token.as_bytes()[..],
            &idempotency_token.as_bytes()[..],
            &payload_token[..],
            i64::try_from(input.payload.len()).map_err(|_| RuntimeStoreError::PayloadTooLarge)?,
            accepted_at,
            expires_at,
            retain_until,
            &metadata_token[..],
            sealed_command,
        ],
    )?;
    super::command_configuration::insert_pin(
        &transaction,
        key_bundle,
        input.conversation_id,
        command_seq.value,
        configuration_revision,
    )?;
    update_conversation_high_water(
        &transaction,
        input.conversation_id,
        "command_high_water",
        &command_seq.encoded,
        previous.as_deref(),
        accepted_at,
        key_bundle,
        database_id,
        ConversationQueueDelta::Increment,
    )?;
    let mut next_ledger = ledger.clone();
    next_ledger.command_count = next_ledger
        .command_count
        .checked_add(1)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    next_ledger.command_configuration_pin_count = next_ledger
        .command_configuration_pin_count
        .checked_add(1)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    next_ledger.accepted_count = next_ledger
        .accepted_count
        .checked_add(1)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    next_ledger.accepted_payload_bytes = next_ledger
        .accepted_payload_bytes
        .checked_add(logical_payload_bytes)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let pending_targets = sqlite::update_runtime_ledger(
        &transaction,
        key_bundle,
        database_id,
        &ledger,
        &next_ledger,
    )?;
    config
        .fault_injector
        .before_operation(RuntimeStoreOperation::AcceptCommandBeforeCommit)?;
    commit_transaction_with_effects(
        transaction,
        RuntimeCommitOperation::AcceptCommand,
        pending_targets,
        effects,
    )?;
    sqlite::latch_post_commit_capacity(state, config);
    after_commit(
        config,
        RuntimeStoreOperation::AcceptCommandAfterCommit,
        RuntimeCommitOperation::AcceptCommand,
    )?;
    Ok(AcceptOutcome::Accepted {
        command: CommandRecord {
            conversation_id: input.conversation_id,
            command_id,
            command_seq: command_seq.value,
            configuration_revision,
            owner: input.owner,
            state: CommandState::Accepted,
            accepted_at_ms,
            expires_at_ms,
            retain_until_ms,
            started_at_ms: None,
            terminal_at_ms: None,
            turn_id: None,
            started_event_id: None,
            terminal_event_id: None,
            payload: input.payload,
            result: None,
        },
        queue_position: queue_admission.queue_position,
    })
}

pub(crate) fn mark_started_with_event(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    input: StartCommand,
    event_source: StartEventSource,
    effects: &mut CommandStreamEffects,
) -> Result<StartOutcome, RuntimeStoreError> {
    ensure_kind(input.conversation_id, RuntimeIdKind::Conversation)?;
    ensure_kind(input.command_id, RuntimeIdKind::Command)?;
    ensure_kind(input.daemon_boot_id, RuntimeIdKind::DaemonBoot)?;
    if input.execution_nonce.is_empty() || input.execution_nonce.len() > MAX_EXECUTION_NONCE_BYTES {
        return Err(RuntimeStoreError::InvalidConfig(
            "execution nonce must contain 1 to 1024 bytes",
        ));
    }
    let projected_write_bytes = projected_write_bytes(&[
        input.execution_nonce.len(),
        crate::runtime::model::MAX_CRITICAL_COMMAND_RECORD_BYTES,
        event_source.retained_capacity(),
    ])?;
    let started_at_ms = config.clock.now_ms()?;
    expire_accepted_commands(state, config, started_at_ms, effects)?;
    let started_at = sqlite_time(started_at_ms)?;
    let nonce_bytes = Zeroizing::new(canonical_fields(&[
        input.command_id.as_bytes(),
        input.daemon_boot_id.as_bytes(),
        &input.execution_nonce,
    ])?);
    let nonce_token = state
        .key_bundle
        .blind_index(b"execution.nonce.v1", nonce_bytes.as_ref())?;
    let database_id = state.database_id;
    let key_bundle = &state.key_bundle;
    sqlite::load_runtime_ledger(&state.connection, key_bundle, database_id)?;
    let preflight_command =
        load_command(&state.connection, key_bundle, database_id, input.command_id)?;
    if preflight_command.conversation_id != input.conversation_id {
        return Err(RuntimeStoreError::CommandNotFound);
    }
    if preflight_command.state == CommandState::Started {
        let intent = load_intent(&state.connection, key_bundle, database_id, input.command_id)?;
        let event = load_event(
            &state.connection,
            key_bundle,
            database_id,
            intent.started_event_id,
        )?;
        validate_started_linkage(&preflight_command, &intent, &event)?;
        let expected = command_event::start_records(
            &preflight_command,
            CommandEventIdentity {
                conversation_id: preflight_command.conversation_id,
                command_id: preflight_command.command_id,
                turn_id: intent.turn_id,
                event_id: event.event_id,
                event_seq: event.event_seq,
            },
            &event_source,
        )?;
        if intent.daemon_boot_id != input.daemon_boot_id
            || intent.execution_nonce != input.execution_nonce
            || intent.payload != expected.intent
            || event.payload != expected.event
        {
            return Err(RuntimeStoreError::StartConflict);
        }
        return Ok(StartOutcome::Replayed {
            command: preflight_command,
            intent,
            event,
        });
    }
    if preflight_command.state == CommandState::Expired {
        return Err(RuntimeStoreError::CommandExpired);
    }
    if preflight_command.state != CommandState::Accepted {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }
    if started_at_ms < preflight_command.accepted_at_ms {
        return Err(RuntimeStoreError::ClockRegressed {
            persisted_ms: preflight_command.accepted_at_ms,
            observed_ms: started_at_ms,
        });
    }
    if authenticated_queue_head(
        &state.connection,
        key_bundle,
        database_id,
        input.conversation_id,
    )? != input.command_id
    {
        return Err(RuntimeStoreError::NotQueueHead);
    }
    if authenticated_started_command(
        &state.connection,
        key_bundle,
        database_id,
        input.conversation_id,
    )?
    .is_some()
    {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }
    let preflight_conversation = load_conversation(
        &state.connection,
        key_bundle,
        database_id,
        input.conversation_id,
    )?;
    if started_at_ms < preflight_conversation.updated_at_ms {
        return Err(RuntimeStoreError::ClockRegressed {
            persisted_ms: preflight_conversation.updated_at_ms,
            observed_ms: started_at_ms,
        });
    }
    sqlite::admit_ordinary_write(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        &state.storage_path,
        &mut state.admission_state,
        config.capacity_probe.as_ref(),
        projected_write_bytes,
        SafetyReserveProjection::StartCommand,
    )?;
    let transaction = state
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let ledger = sqlite::load_runtime_ledger(&transaction, key_bundle, database_id)?;
    let command = load_command(&transaction, key_bundle, database_id, input.command_id)?;
    if command.conversation_id != input.conversation_id {
        return Err(RuntimeStoreError::CommandNotFound);
    }
    if command.state == CommandState::Started {
        let intent = load_intent(&transaction, key_bundle, database_id, input.command_id)?;
        let event = load_event(
            &transaction,
            key_bundle,
            database_id,
            intent.started_event_id,
        )?;
        validate_started_linkage(&command, &intent, &event)?;
        let expected = command_event::start_records(
            &command,
            CommandEventIdentity {
                conversation_id: command.conversation_id,
                command_id: command.command_id,
                turn_id: intent.turn_id,
                event_id: event.event_id,
                event_seq: event.event_seq,
            },
            &event_source,
        )?;
        if intent.daemon_boot_id != input.daemon_boot_id
            || intent.execution_nonce != input.execution_nonce
            || intent.payload != expected.intent
            || event.payload != expected.event
        {
            return Err(RuntimeStoreError::StartConflict);
        }
        return Ok(StartOutcome::Replayed {
            command,
            intent,
            event,
        });
    }
    if command.state == CommandState::Expired {
        return Err(RuntimeStoreError::CommandExpired);
    }
    if command.state != CommandState::Accepted {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }
    if started_at_ms < command.accepted_at_ms {
        return Err(RuntimeStoreError::ClockRegressed {
            persisted_ms: command.accepted_at_ms,
            observed_ms: started_at_ms,
        });
    }
    if authenticated_queue_head(&transaction, key_bundle, database_id, input.conversation_id)?
        != input.command_id
    {
        return Err(RuntimeStoreError::NotQueueHead);
    }
    if authenticated_started_command(&transaction, key_bundle, database_id, input.conversation_id)?
        .is_some()
    {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }
    let conversation =
        load_conversation(&transaction, key_bundle, database_id, input.conversation_id)?;
    if started_at_ms < conversation.updated_at_ms {
        return Err(RuntimeStoreError::ClockRegressed {
            persisted_ms: conversation.updated_at_ms,
            observed_ms: started_at_ms,
        });
    }
    let previous = conversation
        .event_high_water
        .map(super::sequence::encode_sequence);
    let event_seq = next_sequence(SequenceScope::EventSeq, previous.as_deref())?;
    let turn_id = allocate_id(&transaction, config, RuntimeIdKind::Turn)?;
    let event_id = allocate_id(&transaction, config, RuntimeIdKind::Event)?;
    let critical_records = command_event::start_records(
        &command,
        CommandEventIdentity {
            conversation_id: input.conversation_id,
            command_id: input.command_id,
            turn_id,
            event_id,
            event_seq: event_seq.value,
        },
        &event_source,
    )?;
    let started_at_bytes = started_at_ms.to_be_bytes();
    let intent_plaintext = Zeroizing::new(encode_fields(
        INTENT_MAGIC,
        &[
            turn_id.as_bytes(),
            event_id.as_bytes(),
            input.daemon_boot_id.as_bytes(),
            &started_at_bytes,
            &input.execution_nonce,
            &critical_records.intent,
        ],
    )?);
    let sealed_intent = seal(
        key_bundle,
        database_id,
        b"execution_intents",
        input.command_id.as_bytes(),
        b"sealed_intent",
        intent_plaintext.as_ref(),
        MAX_SEALED_INTENT_BYTES,
    )?;
    let sealed_event = seal(
        key_bundle,
        database_id,
        b"event_journal",
        event_id.as_bytes(),
        b"sealed_event",
        &critical_records.event,
        MAX_RUNTIME_EVENT_BYTES,
    )?;
    let index_tokens = load_command_index_tokens(&transaction, input.command_id)?;
    let command_metadata_token = command_metadata_token(
        key_bundle,
        command.conversation_id,
        command.command_id,
        command.command_seq,
        &index_tokens.owner_token,
        &index_tokens.idempotency_token,
        &index_tokens.payload_token,
        index_tokens.terminal_token.as_deref(),
        CommandState::Started,
        u64::try_from(command.payload.len()).map_err(|_| RuntimeStoreError::PayloadTooLarge)?,
        command.accepted_at_ms,
        command.expires_at_ms,
        command.retain_until_ms,
        Some(started_at_ms),
        None,
        Some(turn_id),
        Some(event_id),
        None,
    )?;
    let updated = transaction.execute(
        "UPDATE commands
         SET state = 'started', turn_id = ?1, started_event_id = ?2, started_at_ms = ?3,
             metadata_token = ?4
         WHERE command_id = ?5 AND state = 'accepted' AND metadata_token = ?6",
        params![
            &turn_id.as_bytes()[..],
            &event_id.as_bytes()[..],
            started_at,
            &command_metadata_token[..],
            &input.command_id.as_bytes()[..],
            &index_tokens.metadata_token,
        ],
    )?;
    if updated != 1 {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }
    transaction.execute(
        "INSERT INTO execution_intents (
             command_id, turn_id, started_event_id, daemon_boot_id,
             execution_nonce_token, created_at_ms, sealed_intent
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            &input.command_id.as_bytes()[..],
            &turn_id.as_bytes()[..],
            &event_id.as_bytes()[..],
            &input.daemon_boot_id.as_bytes()[..],
            &nonce_token.as_bytes()[..],
            started_at,
            sealed_intent,
        ],
    )?;
    transaction.execute(
        "INSERT INTO event_journal (
             conversation_id, event_seq, event_id, command_id,
             logical_event_bytes, created_at_ms, metadata_token, sealed_event
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            &input.conversation_id.as_bytes()[..],
            event_seq.encoded,
            &event_id.as_bytes()[..],
            &input.command_id.as_bytes()[..],
            i64::try_from(critical_records.event.len())
                .map_err(|_| RuntimeStoreError::PayloadTooLarge)?,
            started_at,
            &event_metadata_token(
                key_bundle,
                input.conversation_id,
                event_id,
                event_seq.value,
                Some(input.command_id),
                u64::try_from(critical_records.event.len())
                    .map_err(|_| RuntimeStoreError::PayloadTooLarge)?,
                started_at_ms,
            )?[..],
            sealed_event,
        ],
    )?;
    update_conversation_high_water(
        &transaction,
        input.conversation_id,
        "event_high_water",
        &event_seq.encoded,
        previous.as_deref(),
        started_at,
        key_bundle,
        database_id,
        ConversationQueueDelta::Decrement,
    )?;
    let mut next_ledger = ledger.clone();
    next_ledger.intent_count = next_ledger
        .intent_count
        .checked_add(1)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    next_ledger.event_count = next_ledger
        .event_count
        .checked_add(1)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    next_ledger.accepted_count = next_ledger
        .accepted_count
        .checked_sub(1)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    next_ledger.accepted_payload_bytes = next_ledger
        .accepted_payload_bytes
        .checked_sub(
            u64::try_from(command.payload.len()).map_err(|_| RuntimeStoreError::PayloadTooLarge)?,
        )
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    next_ledger.started_without_fence_count = next_ledger
        .started_without_fence_count
        .checked_add(1)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let pending_targets = sqlite::update_runtime_ledger(
        &transaction,
        key_bundle,
        database_id,
        &ledger,
        &next_ledger,
    )?;
    config
        .fault_injector
        .before_operation(RuntimeStoreOperation::StartCommandBeforeCommit)?;
    commit_transaction_with_effects(
        transaction,
        RuntimeCommitOperation::StartCommand,
        pending_targets,
        effects,
    )?;
    sqlite::latch_post_commit_capacity(state, config);
    after_commit(
        config,
        RuntimeStoreOperation::StartCommandAfterCommit,
        RuntimeCommitOperation::StartCommand,
    )?;
    let command = CommandRecord {
        state: CommandState::Started,
        started_at_ms: Some(started_at_ms),
        turn_id: Some(turn_id),
        started_event_id: Some(event_id),
        ..command
    };
    Ok(StartOutcome::Started {
        command,
        intent: ExecutionIntentRecord {
            command_id: input.command_id,
            turn_id,
            started_event_id: event_id,
            daemon_boot_id: input.daemon_boot_id,
            execution_nonce: input.execution_nonce,
            created_at_ms: started_at_ms,
            payload: critical_records.intent,
        },
        event: EventRecord {
            conversation_id: input.conversation_id,
            event_id,
            event_seq: event_seq.value,
            command_id: Some(input.command_id),
            created_at_ms: started_at_ms,
            payload: critical_records.event,
        },
    })
}

pub(crate) fn append_execution_event(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    input: PreparedExecutionEvent,
    effects: &mut CommandStreamEffects,
) -> Result<AppendExecutionEventOutcome, RuntimeStoreError> {
    let database_id = state.database_id;
    let key_bundle = &state.key_bundle;
    let conversation_id = input.conversation_id();
    let command_id = input.command_id();
    let turn_id = input.turn_id();
    let event_id = input.event_id();
    sqlite::load_runtime_ledger(&state.connection, key_bundle, database_id)?;
    if event_id_exists(&state.connection, event_id)? {
        let event = replay_execution_event(&state.connection, key_bundle, database_id, input)?;
        return Ok(AppendExecutionEventOutcome::Replayed { event });
    }

    let preflight_command = load_command(&state.connection, key_bundle, database_id, command_id)?;
    validate_fresh_execution_event_command(&preflight_command, &input)?;
    let preflight_intent = load_intent(&state.connection, key_bundle, database_id, command_id)?;
    let preflight_started_event = load_event(
        &state.connection,
        key_bundle,
        database_id,
        preflight_intent.started_event_id,
    )?;
    validate_started_linkage(
        &preflight_command,
        &preflight_intent,
        &preflight_started_event,
    )?;
    if preflight_intent.turn_id != turn_id {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }
    require_execution_release(&state.connection, key_bundle, database_id, command_id)?;
    let preflight_conversation =
        load_conversation(&state.connection, key_bundle, database_id, conversation_id)?;
    let projected_event_seq = next_sequence(
        SequenceScope::EventSeq,
        preflight_conversation
            .event_high_water
            .map(super::sequence::encode_sequence)
            .as_deref(),
    )?;
    let projected_event_len = input.canonical_len_for_seq(projected_event_seq.value)?;
    let projected_write_bytes = projected_write_bytes(&[projected_event_len])?;
    sqlite::admit_ordinary_write(
        &state.connection,
        key_bundle,
        database_id,
        &state.storage_path,
        &mut state.admission_state,
        config.capacity_probe.as_ref(),
        projected_write_bytes,
        SafetyReserveProjection::Current,
    )?;

    let transaction = state
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    if event_id_exists(&transaction, event_id)? {
        let event = replay_execution_event(&transaction, key_bundle, database_id, input)?;
        return Ok(AppendExecutionEventOutcome::Replayed { event });
    }
    let ledger = sqlite::load_runtime_ledger(&transaction, key_bundle, database_id)?;
    let command = load_command(&transaction, key_bundle, database_id, command_id)?;
    validate_fresh_execution_event_command(&command, &input)?;
    let intent = load_intent(&transaction, key_bundle, database_id, command_id)?;
    let started_event = load_event(
        &transaction,
        key_bundle,
        database_id,
        intent.started_event_id,
    )?;
    validate_started_linkage(&command, &intent, &started_event)?;
    if intent.turn_id != turn_id {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }
    let conversation = load_conversation(&transaction, key_bundle, database_id, conversation_id)?;
    let created_at_ms = config.clock.now_ms()?;
    let release_authorized_at_ms = require_execution_released_at(
        &transaction,
        key_bundle,
        database_id,
        command_id,
        created_at_ms,
    )?;
    let persisted_boundary = conversation
        .updated_at_ms
        .max(intent.created_at_ms)
        .max(release_authorized_at_ms);
    if created_at_ms < persisted_boundary {
        return Err(RuntimeStoreError::ClockRegressed {
            persisted_ms: persisted_boundary,
            observed_ms: created_at_ms,
        });
    }
    let created_at = sqlite_time(created_at_ms)?;
    let previous = conversation
        .event_high_water
        .map(super::sequence::encode_sequence);
    let event_seq = next_sequence(SequenceScope::EventSeq, previous.as_deref())?;
    let payload = input.into_canonical_bytes_for_seq(event_seq.value)?;
    let sealed_event = seal(
        key_bundle,
        database_id,
        b"event_journal",
        event_id.as_bytes(),
        b"sealed_event",
        &payload,
        MAX_RUNTIME_EVENT_BYTES,
    )?;
    let logical_event_bytes =
        u64::try_from(payload.len()).map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
    let metadata_token = event_metadata_token(
        key_bundle,
        conversation_id,
        event_id,
        event_seq.value,
        Some(command_id),
        logical_event_bytes,
        created_at_ms,
    )?;
    transaction.execute(
        "INSERT INTO event_journal (
             conversation_id, event_seq, event_id, command_id,
             logical_event_bytes, created_at_ms, metadata_token, sealed_event
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            &conversation_id.as_bytes()[..],
            event_seq.encoded,
            &event_id.as_bytes()[..],
            &command_id.as_bytes()[..],
            i64::try_from(logical_event_bytes).map_err(|_| RuntimeStoreError::PayloadTooLarge)?,
            created_at,
            &metadata_token[..],
            sealed_event,
        ],
    )?;
    update_conversation_high_water(
        &transaction,
        conversation_id,
        "event_high_water",
        &event_seq.encoded,
        previous.as_deref(),
        created_at,
        key_bundle,
        database_id,
        ConversationQueueDelta::Unchanged,
    )?;
    let mut next_ledger = ledger.clone();
    next_ledger.event_count = next_ledger
        .event_count
        .checked_add(1)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let pending_targets = sqlite::update_runtime_ledger(
        &transaction,
        key_bundle,
        database_id,
        &ledger,
        &next_ledger,
    )?;
    config
        .fault_injector
        .before_operation(RuntimeStoreOperation::AppendExecutionEventBeforeCommit)?;
    commit_transaction_with_effects(
        transaction,
        RuntimeCommitOperation::AppendExecutionEvent,
        pending_targets,
        effects,
    )?;
    sqlite::latch_post_commit_capacity(state, config);
    after_commit(
        config,
        RuntimeStoreOperation::AppendExecutionEventAfterCommit,
        RuntimeCommitOperation::AppendExecutionEvent,
    )?;
    Ok(AppendExecutionEventOutcome::Appended {
        event: EventRecord {
            conversation_id,
            event_id,
            event_seq: event_seq.value,
            command_id: Some(command_id),
            created_at_ms,
            payload,
        },
    })
}

fn event_id_exists(
    connection: &Connection,
    event_id: RuntimeId,
) -> Result<bool, RuntimeStoreError> {
    ensure_kind(event_id, RuntimeIdKind::Event)?;
    let exists: i64 = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM event_journal WHERE event_id = ?1)",
        [&event_id.as_bytes()[..]],
        |row| row.get(0),
    )?;
    Ok(exists == 1)
}

fn validate_fresh_execution_event_command(
    command: &CommandRecord,
    input: &PreparedExecutionEvent,
) -> Result<(), RuntimeStoreError> {
    if command.conversation_id != input.conversation_id() {
        return Err(RuntimeStoreError::CommandNotFound);
    }
    if command.state != CommandState::Started || command.turn_id != Some(input.turn_id()) {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }
    Ok(())
}

fn require_execution_release(
    connection: &Connection,
    key_bundle: &super::cipher::RuntimeKeyBundle,
    database_id: [u8; 16],
    command_id: RuntimeId,
) -> Result<u64, RuntimeStoreError> {
    load_optional_fence(connection, key_bundle, database_id, command_id)?
        .ok_or(RuntimeStoreError::ExecutionFenceMissing)?
        .release_authorized_at_ms
        .ok_or(RuntimeStoreError::ExecutionReleaseMissing)
}

pub(super) fn require_execution_released_at(
    connection: &Connection,
    key_bundle: &super::cipher::RuntimeKeyBundle,
    database_id: [u8; 16],
    command_id: RuntimeId,
    observed_at_ms: u64,
) -> Result<u64, RuntimeStoreError> {
    // 威胁场景：失控 adapter 若能在 Fence/release 前写 Item/Error/approval 事件，会为
    // 从未获准执行的 vendor 伪造 durable output；所有动态事件 writer 与 open-time audit
    // 因此共用同一条 released fence + createdAt 边界。
    let release_authorized_at_ms =
        require_execution_release(connection, key_bundle, database_id, command_id)?;
    if observed_at_ms < release_authorized_at_ms {
        return Err(RuntimeStoreError::ClockRegressed {
            persisted_ms: release_authorized_at_ms,
            observed_ms: observed_at_ms,
        });
    }
    Ok(release_authorized_at_ms)
}

fn replay_execution_event(
    connection: &Connection,
    key_bundle: &super::cipher::RuntimeKeyBundle,
    database_id: [u8; 16],
    input: PreparedExecutionEvent,
) -> Result<EventRecord, RuntimeStoreError> {
    let event = load_event(connection, key_bundle, database_id, input.event_id())?;
    if event.conversation_id != input.conversation_id()
        || event.command_id != Some(input.command_id())
    {
        return Err(RuntimeStoreError::ExecutionEventConflict);
    }
    let command = load_command(connection, key_bundle, database_id, input.command_id())?;
    if command.conversation_id != input.conversation_id()
        || command.turn_id != Some(input.turn_id())
        || command.started_event_id == Some(event.event_id)
        || command.terminal_event_id == Some(event.event_id)
    {
        return Err(RuntimeStoreError::ExecutionEventConflict);
    }
    let intent = load_intent(connection, key_bundle, database_id, input.command_id())?;
    let started = load_event(connection, key_bundle, database_id, intent.started_event_id)?;
    validate_started_linkage(&command, &intent, &started)?;
    let release_authorized_at_ms = require_execution_released_at(
        connection,
        key_bundle,
        database_id,
        input.command_id(),
        event.created_at_ms,
    )?;
    if intent.turn_id != input.turn_id()
        || event.event_seq <= started.event_seq
        || event.created_at_ms < started.created_at_ms.max(release_authorized_at_ms)
    {
        return Err(RuntimeStoreError::ExecutionEventConflict);
    }
    if let Some(terminal_event_id) = command.terminal_event_id {
        let terminal = load_event(connection, key_bundle, database_id, terminal_event_id)?;
        if event.event_seq >= terminal.event_seq || event.created_at_ms > terminal.created_at_ms {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
    } else if command.state != CommandState::Started {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let expected = input.into_canonical_bytes_for_seq(event.event_seq)?;
    if event.payload != expected {
        return Err(RuntimeStoreError::ExecutionEventConflict);
    }
    Ok(event)
}

pub(crate) fn persist_execution_fence(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    input: ExecutionFence,
) -> Result<ExecutionFenceRecord, RuntimeStoreError> {
    ensure_kind(input.command_id, RuntimeIdKind::Command)?;
    ensure_kind(input.daemon_boot_id, RuntimeIdKind::DaemonBoot)?;
    if input.process_group_id <= 0
        || input.leader_pid <= 0
        || input.leader_start_time == 0
        || input.execution_nonce.is_empty()
        || input.execution_nonce.len() > MAX_EXECUTION_NONCE_BYTES
    {
        return Err(RuntimeStoreError::InvalidConfig(
            "execution fence process and nonce fields must be non-zero",
        ));
    }
    validate_payload_len(input.payload.len(), MAX_EXECUTION_FENCE_BYTES)?;
    let nonce_bytes = Zeroizing::new(canonical_fields(&[
        input.command_id.as_bytes(),
        input.daemon_boot_id.as_bytes(),
        &input.execution_nonce,
    ])?);
    let nonce_token = state
        .key_bundle
        .blind_index(b"execution.nonce.v1", nonce_bytes.as_ref())?;
    let database_id = state.database_id;
    let key_bundle = &state.key_bundle;
    let transaction = state
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let ledger = sqlite::load_runtime_ledger(&transaction, key_bundle, database_id)?;
    let command = load_command(&transaction, key_bundle, database_id, input.command_id)?;
    if command.state != CommandState::Started {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }
    let intent = load_intent(&transaction, key_bundle, database_id, input.command_id)?;
    let started_event = load_event(
        &transaction,
        key_bundle,
        database_id,
        intent.started_event_id,
    )?;
    validate_started_linkage(&command, &intent, &started_event)?;
    if intent.daemon_boot_id != input.daemon_boot_id
        || intent.execution_nonce != input.execution_nonce
    {
        return Err(RuntimeStoreError::FenceConflict);
    }
    if let Some(existing) =
        load_optional_fence(&transaction, key_bundle, database_id, input.command_id)?
    {
        if existing.daemon_boot_id == input.daemon_boot_id
            && existing.process_group_id == input.process_group_id
            && existing.leader_pid == input.leader_pid
            && existing.leader_start_time == input.leader_start_time
            && existing.payload == input.payload
        {
            return Ok(existing);
        }
        return Err(RuntimeStoreError::FenceConflict);
    }
    sqlite::admit_safety_write(
        &transaction,
        key_bundle,
        database_id,
        &state.storage_path,
        config.capacity_probe.as_ref(),
    )?;
    let process_group_bytes = input.process_group_id.to_be_bytes();
    let leader_pid_bytes = input.leader_pid.to_be_bytes();
    let leader_start_bytes = input.leader_start_time.to_be_bytes();
    let fence_plaintext = Zeroizing::new(encode_fields(
        FENCE_MAGIC,
        &[
            input.daemon_boot_id.as_bytes(),
            &input.execution_nonce,
            &process_group_bytes,
            &leader_pid_bytes,
            &leader_start_bytes,
            &input.payload,
        ],
    )?);
    let sealed_fence = seal(
        key_bundle,
        database_id,
        b"execution_fences",
        input.command_id.as_bytes(),
        b"sealed_fence",
        fence_plaintext.as_ref(),
        MAX_SEALED_FENCE_BYTES,
    )?;
    transaction.execute(
        "INSERT INTO execution_fences (
             command_id, daemon_boot_id, execution_nonce_token,
             process_group_id, leader_pid, leader_start_time,
             release_authorized_at_ms, release_token, sealed_fence
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, NULL, ?7)",
        params![
            &input.command_id.as_bytes()[..],
            &input.daemon_boot_id.as_bytes()[..],
            &nonce_token.as_bytes()[..],
            input.process_group_id,
            input.leader_pid,
            super::sequence::encode_sequence(input.leader_start_time),
            sealed_fence,
        ],
    )?;
    let mut next_ledger = ledger.clone();
    next_ledger.fence_count = next_ledger
        .fence_count
        .checked_add(1)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    next_ledger.started_without_fence_count = next_ledger
        .started_without_fence_count
        .checked_sub(1)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    next_ledger.started_without_release_count = next_ledger
        .started_without_release_count
        .checked_add(1)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let _pending_targets = sqlite::update_runtime_ledger(
        &transaction,
        key_bundle,
        database_id,
        &ledger,
        &next_ledger,
    )?;
    config
        .fault_injector
        .before_operation(RuntimeStoreOperation::PersistFenceBeforeCommit)?;
    commit_transaction(transaction, RuntimeCommitOperation::PersistFence)?;
    sqlite::latch_post_commit_capacity(state, config);
    after_commit(
        config,
        RuntimeStoreOperation::PersistFenceAfterCommit,
        RuntimeCommitOperation::PersistFence,
    )?;
    Ok(ExecutionFenceRecord {
        command_id: input.command_id,
        daemon_boot_id: input.daemon_boot_id,
        execution_nonce: input.execution_nonce,
        process_group_id: input.process_group_id,
        leader_pid: input.leader_pid,
        leader_start_time: input.leader_start_time,
        release_authorized_at_ms: None,
        payload: input.payload,
    })
}

pub(crate) fn authorize_execution_release(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    input: AuthorizeExecutionRelease,
) -> Result<ExecutionFenceRecord, RuntimeStoreError> {
    ensure_kind(input.command_id, RuntimeIdKind::Command)?;
    ensure_kind(input.daemon_boot_id, RuntimeIdKind::DaemonBoot)?;
    if input.execution_nonce.is_empty() || input.execution_nonce.len() > MAX_EXECUTION_NONCE_BYTES {
        return Err(RuntimeStoreError::InvalidConfig(
            "execution nonce must contain 1 to 1024 bytes",
        ));
    }
    let nonce_bytes = Zeroizing::new(canonical_fields(&[
        input.command_id.as_bytes(),
        input.daemon_boot_id.as_bytes(),
        &input.execution_nonce,
    ])?);
    let nonce_token = state
        .key_bundle
        .blind_index(b"execution.nonce.v1", nonce_bytes.as_ref())?;
    let database_id = state.database_id;
    let key_bundle = &state.key_bundle;
    let transaction = state
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let ledger = sqlite::load_runtime_ledger(&transaction, key_bundle, database_id)?;
    let command = load_command(&transaction, key_bundle, database_id, input.command_id)?;
    let persisted: Option<(Vec<u8>, Vec<u8>)> = transaction
        .query_row(
            "SELECT daemon_boot_id, execution_nonce_token
             FROM execution_fences WHERE command_id = ?1",
            [&input.command_id.as_bytes()[..]],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let Some((persisted_boot, persisted_nonce)) = persisted else {
        return Err(RuntimeStoreError::ExecutionFenceMissing);
    };
    if persisted_boot.as_slice() != input.daemon_boot_id.as_bytes()
        || persisted_nonce.as_slice() != nonce_token.as_bytes()
    {
        return Err(RuntimeStoreError::FenceConflict);
    }
    let existing = load_optional_fence(&transaction, key_bundle, database_id, input.command_id)?
        .ok_or(RuntimeStoreError::ExecutionFenceMissing)?;
    if existing.release_authorized_at_ms.is_some() {
        return Ok(existing);
    }
    if command.state != CommandState::Started {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }
    let intent = load_intent(&transaction, key_bundle, database_id, input.command_id)?;
    let started_event = load_event(
        &transaction,
        key_bundle,
        database_id,
        intent.started_event_id,
    )?;
    validate_started_linkage(&command, &intent, &started_event)?;
    let authorized_at_ms = config.clock.now_ms()?;
    let authorized_at = sqlite_time(authorized_at_ms)?;
    let started_at_ms = command
        .started_at_ms
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    if authorized_at_ms < started_at_ms {
        return Err(RuntimeStoreError::ClockRegressed {
            persisted_ms: started_at_ms,
            observed_ms: authorized_at_ms,
        });
    }
    sqlite::admit_safety_write(
        &transaction,
        key_bundle,
        database_id,
        &state.storage_path,
        config.capacity_probe.as_ref(),
    )?;
    let authorized_at_bytes = authorized_at_ms.to_be_bytes();
    let release_plaintext = Zeroizing::new(canonical_fields(&[
        input.command_id.as_bytes(),
        input.daemon_boot_id.as_bytes(),
        &input.execution_nonce,
        &authorized_at_bytes,
    ])?);
    let release_token = state
        .key_bundle
        .blind_index(b"execution.release.v1", release_plaintext.as_ref())?;
    if transaction.execute(
        "UPDATE execution_fences
         SET release_authorized_at_ms = ?1, release_token = ?2
         WHERE command_id = ?3 AND release_authorized_at_ms IS NULL AND release_token IS NULL",
        params![
            authorized_at,
            &release_token.as_bytes()[..],
            &input.command_id.as_bytes()[..]
        ],
    )? != 1
    {
        return Err(RuntimeStoreError::SchemaInspectionRaced);
    }
    let mut next_ledger = ledger.clone();
    next_ledger.started_without_release_count = next_ledger
        .started_without_release_count
        .checked_sub(1)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    next_ledger.started_released_count = next_ledger
        .started_released_count
        .checked_add(1)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let _pending_targets = sqlite::update_runtime_ledger(
        &transaction,
        key_bundle,
        database_id,
        &ledger,
        &next_ledger,
    )?;
    config
        .fault_injector
        .before_operation(RuntimeStoreOperation::AuthorizeExecutionReleaseBeforeCommit)?;
    commit_transaction(
        transaction,
        RuntimeCommitOperation::AuthorizeExecutionRelease,
    )?;
    sqlite::latch_post_commit_capacity(state, config);
    after_commit(
        config,
        RuntimeStoreOperation::AuthorizeExecutionReleaseAfterCommit,
        RuntimeCommitOperation::AuthorizeExecutionRelease,
    )?;
    Ok(ExecutionFenceRecord {
        release_authorized_at_ms: Some(authorized_at_ms),
        ..existing
    })
}

pub(crate) fn complete_command_with_event(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    input: CompleteCommand,
    effects: &mut CommandStreamEffects,
) -> Result<CompleteOutcome, RuntimeStoreError> {
    complete_command_with_event_inner(state, config, input, None, effects)
}

pub(crate) fn recover_started_command_with_event(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    input: RecoverStartedCommand,
    effects: &mut CommandStreamEffects,
) -> Result<CompleteOutcome, RuntimeStoreError> {
    if input.completion.terminal.terminal_state() != TerminalState::Interrupted
        || !matches!(
            &input.expected_started,
            RecoveryBlockedCommandBinding::Started { .. }
        )
    {
        return Err(RuntimeStoreError::InvalidConfig(
            "recovery completion requires an exact Started binding and Interrupted terminal",
        ));
    }
    complete_command_with_event_inner(
        state,
        config,
        input.completion,
        Some(&input.expected_started),
        effects,
    )
}

fn complete_command_with_event_inner(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    input: CompleteCommand,
    expected_started: Option<&RecoveryBlockedCommandBinding>,
    effects: &mut CommandStreamEffects,
) -> Result<CompleteOutcome, RuntimeStoreError> {
    ensure_kind(input.conversation_id, RuntimeIdKind::Conversation)?;
    ensure_kind(input.command_id, RuntimeIdKind::Command)?;
    ensure_kind(input.turn_id, RuntimeIdKind::Turn)?;
    let terminal_state = input.terminal.terminal_state();
    let database_id = state.database_id;
    let key_bundle = &state.key_bundle;
    let transaction = state
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let ledger = sqlite::load_runtime_ledger(&transaction, key_bundle, database_id)?;
    let command = load_command(&transaction, key_bundle, database_id, input.command_id)?;
    if command.conversation_id != input.conversation_id {
        return Err(RuntimeStoreError::CommandNotFound);
    }
    if let Some(expected_started) = expected_started {
        validate_exact_recovery_started_binding(
            &transaction,
            key_bundle,
            database_id,
            &command,
            expected_started,
        )?;
    }
    if command.state.is_terminal() {
        if !is_completion_terminal(command.state) || command.turn_id != Some(input.turn_id) {
            return Err(RuntimeStoreError::InvalidStateTransition);
        }
        let released_fence =
            load_optional_fence(&transaction, key_bundle, database_id, input.command_id)?;
        if released_fence
            .as_ref()
            .and_then(|fence| fence.release_authorized_at_ms)
            .is_none()
        {
            return Err(RuntimeStoreError::TerminalConflict);
        }
        let (persisted_token, event_id): (Option<Vec<u8>>, Option<Vec<u8>>) = transaction
            .query_row(
                "SELECT terminal_token, terminal_event_id FROM commands WHERE command_id = ?1",
                [&input.command_id.as_bytes()[..]],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
        let persisted_token = persisted_token.ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        let event_id = event_id.ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        approval::ensure_terminal_turn_has_no_active_approvals(
            &transaction,
            key_bundle,
            database_id,
            input.conversation_id,
            input.command_id,
            input.turn_id,
        )?;
        let event_id = runtime_id(RuntimeIdKind::Event, event_id)?;
        let event = load_event(&transaction, key_bundle, database_id, event_id)?;
        let records = command_event::terminal_records(
            CommandEventIdentity {
                conversation_id: input.conversation_id,
                command_id: input.command_id,
                turn_id: input.turn_id,
                event_id,
                event_seq: event.event_seq,
            },
            &input.terminal,
        )?;
        let terminal_token = command_terminal_token(
            key_bundle,
            input.conversation_id,
            input.command_id,
            input.turn_id,
            terminal_state,
            &records.result,
            &records.event,
        )?;
        if persisted_token.as_slice() != terminal_token.as_bytes()
            || command.result.as_deref() != Some(records.result.as_slice())
            || event.payload != records.event
        {
            return Err(RuntimeStoreError::TerminalConflict);
        }
        return Ok(CompleteOutcome::Replayed { command, event });
    }
    if command.state != CommandState::Started || command.turn_id != Some(input.turn_id) {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }
    let intent = load_intent(&transaction, key_bundle, database_id, input.command_id)?;
    let started_event = load_event(
        &transaction,
        key_bundle,
        database_id,
        intent.started_event_id,
    )?;
    validate_started_linkage(&command, &intent, &started_event)?;
    let fence = load_optional_fence(&transaction, key_bundle, database_id, input.command_id)?
        .ok_or(RuntimeStoreError::ExecutionFenceMissing)?;
    let release_authorized_at_ms = fence
        .release_authorized_at_ms
        .ok_or(RuntimeStoreError::ExecutionReleaseMissing)?;
    let terminal_at_ms = config.clock.now_ms()?;
    let started_at_ms = command
        .started_at_ms
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let persisted_boundary = started_at_ms.max(release_authorized_at_ms);
    if terminal_at_ms < persisted_boundary {
        return Err(RuntimeStoreError::ClockRegressed {
            persisted_ms: persisted_boundary,
            observed_ms: terminal_at_ms,
        });
    }
    let terminal_at = sqlite_time(terminal_at_ms)?;
    let conversation =
        load_conversation(&transaction, key_bundle, database_id, input.conversation_id)?;
    if terminal_at_ms < conversation.updated_at_ms {
        return Err(RuntimeStoreError::ClockRegressed {
            persisted_ms: conversation.updated_at_ms,
            observed_ms: terminal_at_ms,
        });
    }
    sqlite::admit_safety_write(
        &transaction,
        key_bundle,
        database_id,
        &state.storage_path,
        config.capacity_probe.as_ref(),
    )?;
    let previous = conversation
        .event_high_water
        .map(super::sequence::encode_sequence);
    let approval_expiry = approval::expire_active_approvals_for_terminal(
        &transaction,
        key_bundle,
        database_id,
        config,
        input.conversation_id,
        input.command_id,
        input.turn_id,
        terminal_at_ms,
        previous.as_deref(),
    )?;
    let event_seq = next_sequence(
        SequenceScope::EventSeq,
        approval_expiry.final_event_high_water.as_deref(),
    )?;
    let event_id = allocate_id(&transaction, config, RuntimeIdKind::Event)?;
    let records = command_event::terminal_records(
        CommandEventIdentity {
            conversation_id: input.conversation_id,
            command_id: input.command_id,
            turn_id: input.turn_id,
            event_id,
            event_seq: event_seq.value,
        },
        &input.terminal,
    )?;
    let terminal_token = command_terminal_token(
        key_bundle,
        input.conversation_id,
        input.command_id,
        input.turn_id,
        terminal_state,
        &records.result,
        &records.event,
    )?;
    let sealed_result = seal(
        key_bundle,
        database_id,
        b"commands",
        input.command_id.as_bytes(),
        b"sealed_result",
        &records.result,
        MAX_COMMAND_RESULT_BYTES,
    )?;
    let sealed_event = seal(
        key_bundle,
        database_id,
        b"event_journal",
        event_id.as_bytes(),
        b"sealed_event",
        &records.event,
        MAX_RUNTIME_EVENT_BYTES,
    )?;
    let retain_until_ms = command.retain_until_ms.max(
        terminal_at_ms
            .checked_add(COMMAND_LEDGER_RETENTION_MS)
            .ok_or(RuntimeStoreError::TimeOutOfRange)?,
    );
    let index_tokens = load_command_index_tokens(&transaction, input.command_id)?;
    let state_value = terminal_to_command_state(terminal_state);
    let command_metadata_token = command_metadata_token(
        key_bundle,
        command.conversation_id,
        command.command_id,
        command.command_seq,
        &index_tokens.owner_token,
        &index_tokens.idempotency_token,
        &index_tokens.payload_token,
        Some(terminal_token.as_bytes()),
        state_value,
        u64::try_from(command.payload.len()).map_err(|_| RuntimeStoreError::PayloadTooLarge)?,
        command.accepted_at_ms,
        command.expires_at_ms,
        retain_until_ms,
        command.started_at_ms,
        Some(terminal_at_ms),
        command.turn_id,
        command.started_event_id,
        Some(event_id),
    )?;
    let updated = transaction.execute(
        "UPDATE commands
         SET state = ?1, terminal_token = ?2, terminal_event_id = ?3,
             terminal_at_ms = ?4, retain_until_ms = ?5, sealed_result = ?6,
             metadata_token = ?7
         WHERE command_id = ?8 AND state = 'started' AND turn_id = ?9
           AND metadata_token = ?10",
        params![
            terminal_state_text(terminal_state),
            &terminal_token.as_bytes()[..],
            &event_id.as_bytes()[..],
            terminal_at,
            sqlite_time(retain_until_ms)?,
            sealed_result,
            &command_metadata_token[..],
            &input.command_id.as_bytes()[..],
            &input.turn_id.as_bytes()[..],
            &index_tokens.metadata_token,
        ],
    )?;
    if updated != 1 {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }
    transaction.execute(
        "INSERT INTO event_journal (
             conversation_id, event_seq, event_id, command_id,
             logical_event_bytes, created_at_ms, metadata_token, sealed_event
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            &input.conversation_id.as_bytes()[..],
            event_seq.encoded,
            &event_id.as_bytes()[..],
            &input.command_id.as_bytes()[..],
            i64::try_from(records.event.len()).map_err(|_| RuntimeStoreError::PayloadTooLarge)?,
            terminal_at,
            &event_metadata_token(
                key_bundle,
                input.conversation_id,
                event_id,
                event_seq.value,
                Some(input.command_id),
                u64::try_from(records.event.len())
                    .map_err(|_| RuntimeStoreError::PayloadTooLarge)?,
                terminal_at_ms,
            )?[..],
            sealed_event,
        ],
    )?;
    update_conversation_high_water(
        &transaction,
        input.conversation_id,
        "event_high_water",
        &event_seq.encoded,
        previous.as_deref(),
        terminal_at,
        key_bundle,
        database_id,
        ConversationQueueDelta::Unchanged,
    )?;
    let mut next_ledger = ledger.clone();
    next_ledger.event_count = next_ledger
        .event_count
        .checked_add(approval_expiry.expiry_event_count)
        .and_then(|count| count.checked_add(1))
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    next_ledger.active_approval_count = next_ledger
        .active_approval_count
        .checked_sub(approval_expiry.active_approval_decrement)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    next_ledger.started_released_count = next_ledger
        .started_released_count
        .checked_sub(1)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let pending_targets = sqlite::update_runtime_ledger(
        &transaction,
        key_bundle,
        database_id,
        &ledger,
        &next_ledger,
    )?;
    config
        .fault_injector
        .before_operation(RuntimeStoreOperation::CompleteCommandBeforeCommit)?;
    let commit_result = commit_transaction(transaction, RuntimeCommitOperation::CompleteCommand);
    effects.record_commit_result(pending_targets, &commit_result);
    commit_result?;
    sqlite::latch_post_commit_capacity(state, config);
    after_commit(
        config,
        RuntimeStoreOperation::CompleteCommandAfterCommit,
        RuntimeCommitOperation::CompleteCommand,
    )?;
    let command = CommandRecord {
        state: state_value,
        terminal_at_ms: Some(terminal_at_ms),
        terminal_event_id: Some(event_id),
        retain_until_ms,
        result: Some(records.result),
        ..command
    };
    Ok(CompleteOutcome::Completed {
        command,
        event: EventRecord {
            conversation_id: input.conversation_id,
            event_id,
            event_seq: event_seq.value,
            command_id: Some(input.command_id),
            created_at_ms: terminal_at_ms,
            payload: records.event,
        },
    })
}

pub(crate) fn terminate_started_before_release(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    input: TerminateStartedBeforeRelease,
    effects: &mut CommandStreamEffects,
) -> Result<TerminateStartedBeforeReleaseOutcome, RuntimeStoreError> {
    ensure_kind(input.conversation_id, RuntimeIdKind::Conversation)?;
    ensure_kind(input.command_id, RuntimeIdKind::Command)?;
    ensure_kind(input.turn_id, RuntimeIdKind::Turn)?;
    ensure_kind(input.daemon_boot_id, RuntimeIdKind::DaemonBoot)?;
    if input.execution_nonce.is_empty() || input.execution_nonce.len() > MAX_EXECUTION_NONCE_BYTES {
        return Err(RuntimeStoreError::InvalidConfig(
            "execution nonce must contain 1 to 1024 bytes",
        ));
    }
    let terminal_state = input.reason.terminal_state();
    let database_id = state.database_id;
    let key_bundle = &state.key_bundle;
    let transaction = state
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let ledger = sqlite::load_runtime_ledger(&transaction, key_bundle, database_id)?;
    let command = load_command(&transaction, key_bundle, database_id, input.command_id)?;
    if command.conversation_id != input.conversation_id {
        return Err(RuntimeStoreError::CommandNotFound);
    }
    let intent = load_intent(&transaction, key_bundle, database_id, input.command_id)?;
    let started_event = load_event(
        &transaction,
        key_bundle,
        database_id,
        intent.started_event_id,
    )?;
    validate_started_linkage(&command, &intent, &started_event)?;
    if intent.turn_id != input.turn_id
        || intent.daemon_boot_id != input.daemon_boot_id
        || intent.execution_nonce != input.execution_nonce
    {
        return Err(RuntimeStoreError::StartConflict);
    }
    let fence = load_optional_fence(&transaction, key_bundle, database_id, input.command_id)?;
    if fence
        .as_ref()
        .is_some_and(|persisted| persisted.daemon_boot_id != input.daemon_boot_id)
    {
        return Err(RuntimeStoreError::FenceConflict);
    }
    if fence
        .as_ref()
        .is_some_and(|persisted| persisted.release_authorized_at_ms.is_some())
    {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }

    let state_value = terminal_to_command_state(terminal_state);
    if command.state.is_terminal() {
        if command.state != state_value || command.turn_id != Some(input.turn_id) {
            return Err(RuntimeStoreError::InvalidStateTransition);
        }
        let (persisted_token, event_id): (Option<Vec<u8>>, Option<Vec<u8>>) = transaction
            .query_row(
                "SELECT terminal_token, terminal_event_id FROM commands WHERE command_id = ?1",
                [&input.command_id.as_bytes()[..]],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
        let persisted_token = persisted_token.ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        approval::ensure_terminal_turn_has_no_active_approvals(
            &transaction,
            key_bundle,
            database_id,
            input.conversation_id,
            input.command_id,
            input.turn_id,
        )?;
        let event_id = runtime_id(
            RuntimeIdKind::Event,
            event_id.ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?,
        )?;
        let event = load_event(&transaction, key_bundle, database_id, event_id)?;
        let records = command_event::before_release_terminal_records(
            CommandEventIdentity {
                conversation_id: input.conversation_id,
                command_id: input.command_id,
                turn_id: input.turn_id,
                event_id,
                event_seq: event.event_seq,
            },
            input.reason,
        )?;
        let terminal_token = command_terminal_token(
            key_bundle,
            input.conversation_id,
            input.command_id,
            input.turn_id,
            terminal_state,
            &records.result,
            &records.event,
        )?;
        if persisted_token.as_slice() != terminal_token.as_bytes()
            || command.result.as_deref() != Some(records.result.as_slice())
            || event.payload != records.event
        {
            return Err(RuntimeStoreError::TerminalConflict);
        }
        return Ok(TerminateStartedBeforeReleaseOutcome::Replayed { command, event });
    }
    if command.state != CommandState::Started || command.turn_id != Some(input.turn_id) {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }

    let terminal_at_ms = config.clock.now_ms()?;
    let started_at_ms = command
        .started_at_ms
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let conversation =
        load_conversation(&transaction, key_bundle, database_id, input.conversation_id)?;
    let persisted_boundary = started_at_ms.max(conversation.updated_at_ms);
    if terminal_at_ms < persisted_boundary {
        return Err(RuntimeStoreError::ClockRegressed {
            persisted_ms: persisted_boundary,
            observed_ms: terminal_at_ms,
        });
    }
    sqlite::admit_safety_write(
        &transaction,
        key_bundle,
        database_id,
        &state.storage_path,
        config.capacity_probe.as_ref(),
    )?;

    let terminal_at = sqlite_time(terminal_at_ms)?;
    let previous = conversation
        .event_high_water
        .map(super::sequence::encode_sequence);
    let approval_expiry = approval::expire_active_approvals_for_terminal(
        &transaction,
        key_bundle,
        database_id,
        config,
        input.conversation_id,
        input.command_id,
        input.turn_id,
        terminal_at_ms,
        previous.as_deref(),
    )?;
    let event_seq = next_sequence(
        SequenceScope::EventSeq,
        approval_expiry.final_event_high_water.as_deref(),
    )?;
    let event_id = allocate_id(&transaction, config, RuntimeIdKind::Event)?;
    let records = command_event::before_release_terminal_records(
        CommandEventIdentity {
            conversation_id: input.conversation_id,
            command_id: input.command_id,
            turn_id: input.turn_id,
            event_id,
            event_seq: event_seq.value,
        },
        input.reason,
    )?;
    let terminal_token = command_terminal_token(
        key_bundle,
        input.conversation_id,
        input.command_id,
        input.turn_id,
        terminal_state,
        &records.result,
        &records.event,
    )?;
    let sealed_result = seal(
        key_bundle,
        database_id,
        b"commands",
        input.command_id.as_bytes(),
        b"sealed_result",
        &records.result,
        MAX_COMMAND_RESULT_BYTES,
    )?;
    let sealed_event = seal(
        key_bundle,
        database_id,
        b"event_journal",
        event_id.as_bytes(),
        b"sealed_event",
        &records.event,
        MAX_RUNTIME_EVENT_BYTES,
    )?;
    let retain_until_ms = command.retain_until_ms.max(
        terminal_at_ms
            .checked_add(COMMAND_LEDGER_RETENTION_MS)
            .ok_or(RuntimeStoreError::TimeOutOfRange)?,
    );
    let index_tokens = load_command_index_tokens(&transaction, input.command_id)?;
    let command_metadata = command_metadata_token(
        key_bundle,
        command.conversation_id,
        command.command_id,
        command.command_seq,
        &index_tokens.owner_token,
        &index_tokens.idempotency_token,
        &index_tokens.payload_token,
        Some(terminal_token.as_bytes()),
        state_value,
        u64::try_from(command.payload.len()).map_err(|_| RuntimeStoreError::PayloadTooLarge)?,
        command.accepted_at_ms,
        command.expires_at_ms,
        retain_until_ms,
        command.started_at_ms,
        Some(terminal_at_ms),
        command.turn_id,
        command.started_event_id,
        Some(event_id),
    )?;
    if transaction.execute(
        "UPDATE commands
         SET state = ?1, terminal_token = ?2, terminal_event_id = ?3,
             terminal_at_ms = ?4, retain_until_ms = ?5, sealed_result = ?6,
             metadata_token = ?7
         WHERE command_id = ?8 AND state = 'started' AND turn_id = ?9
           AND metadata_token = ?10",
        params![
            terminal_state_text(terminal_state),
            &terminal_token.as_bytes()[..],
            &event_id.as_bytes()[..],
            terminal_at,
            sqlite_time(retain_until_ms)?,
            sealed_result,
            &command_metadata[..],
            &input.command_id.as_bytes()[..],
            &input.turn_id.as_bytes()[..],
            &index_tokens.metadata_token,
        ],
    )? != 1
    {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }
    transaction.execute(
        "INSERT INTO event_journal (
             conversation_id, event_seq, event_id, command_id,
             logical_event_bytes, created_at_ms, metadata_token, sealed_event
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            &input.conversation_id.as_bytes()[..],
            event_seq.encoded,
            &event_id.as_bytes()[..],
            &input.command_id.as_bytes()[..],
            i64::try_from(records.event.len()).map_err(|_| RuntimeStoreError::PayloadTooLarge)?,
            terminal_at,
            &event_metadata_token(
                key_bundle,
                input.conversation_id,
                event_id,
                event_seq.value,
                Some(input.command_id),
                u64::try_from(records.event.len())
                    .map_err(|_| RuntimeStoreError::PayloadTooLarge)?,
                terminal_at_ms,
            )?[..],
            sealed_event,
        ],
    )?;
    update_conversation_high_water(
        &transaction,
        input.conversation_id,
        "event_high_water",
        &event_seq.encoded,
        previous.as_deref(),
        terminal_at,
        key_bundle,
        database_id,
        ConversationQueueDelta::Unchanged,
    )?;
    let mut next_ledger = ledger.clone();
    next_ledger.event_count = next_ledger
        .event_count
        .checked_add(approval_expiry.expiry_event_count)
        .and_then(|count| count.checked_add(1))
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    next_ledger.active_approval_count = next_ledger
        .active_approval_count
        .checked_sub(approval_expiry.active_approval_decrement)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    if fence.is_some() {
        next_ledger.started_without_release_count = next_ledger
            .started_without_release_count
            .checked_sub(1)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    } else {
        next_ledger.started_without_fence_count = next_ledger
            .started_without_fence_count
            .checked_sub(1)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    }
    let pending_targets = sqlite::update_runtime_ledger(
        &transaction,
        key_bundle,
        database_id,
        &ledger,
        &next_ledger,
    )?;
    config
        .fault_injector
        .before_operation(RuntimeStoreOperation::TerminateStartedBeforeReleaseBeforeCommit)?;
    commit_transaction_with_effects(
        transaction,
        RuntimeCommitOperation::TerminateStartedBeforeRelease,
        pending_targets,
        effects,
    )?;
    sqlite::latch_post_commit_capacity(state, config);
    after_commit(
        config,
        RuntimeStoreOperation::TerminateStartedBeforeReleaseAfterCommit,
        RuntimeCommitOperation::TerminateStartedBeforeRelease,
    )?;

    let command = CommandRecord {
        state: state_value,
        terminal_at_ms: Some(terminal_at_ms),
        terminal_event_id: Some(event_id),
        retain_until_ms,
        result: Some(records.result),
        ..command
    };
    Ok(TerminateStartedBeforeReleaseOutcome::Transitioned {
        command,
        event: EventRecord {
            conversation_id: input.conversation_id,
            event_id,
            event_seq: event_seq.value,
            command_id: Some(input.command_id),
            created_at_ms: terminal_at_ms,
            payload: records.event,
        },
    })
}

pub(crate) fn terminate_accepted_command(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    input: TerminateAcceptedCommand,
    effects: &mut CommandStreamEffects,
) -> Result<TerminateAcceptedOutcome, RuntimeStoreError> {
    ensure_kind(input.conversation_id, RuntimeIdKind::Conversation)?;
    ensure_kind(input.command_id, RuntimeIdKind::Command)?;
    let event_payload = command_event::accepted_terminal_event(input.command_id, input.reason)?;

    let database_id = state.database_id;
    let key_bundle = &state.key_bundle;
    let transaction = state
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let command = load_command(&transaction, key_bundle, database_id, input.command_id)?;
    if command.conversation_id != input.conversation_id {
        return Err(RuntimeStoreError::CommandNotFound);
    }
    if command.owner != input.expected_owner {
        return Err(RuntimeStoreError::CommandOwnerMismatch);
    }
    if command.state == CommandState::Started {
        return Ok(TerminateAcceptedOutcome::AlreadyStarted { command });
    }
    let terminal_state = input.reason.command_state();
    if command.state == terminal_state
        && command.started_at_ms.is_none()
        && command.turn_id.is_none()
    {
        let event_id = command
            .terminal_event_id
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        let event = load_event(&transaction, key_bundle, database_id, event_id)?;
        let expected_token = accepted_termination_token(
            key_bundle,
            input.reason,
            input.conversation_id,
            input.command_id,
            &event_payload,
        )?;
        let persisted_token = load_command_index_tokens(&transaction, input.command_id)?
            .terminal_token
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        if event.payload != event_payload || persisted_token.as_slice() != expected_token.as_bytes()
        {
            return Err(RuntimeStoreError::TerminalConflict);
        }
        return Ok(TerminateAcceptedOutcome::Replayed { command, event });
    }
    if command.state != CommandState::Accepted {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }

    let terminal_at_ms = config.clock.now_ms()?;
    let conversation =
        load_conversation(&transaction, key_bundle, database_id, input.conversation_id)?;
    let persisted_ms = command.accepted_at_ms.max(conversation.updated_at_ms);
    if terminal_at_ms < persisted_ms {
        return Err(RuntimeStoreError::ClockRegressed {
            persisted_ms,
            observed_ms: terminal_at_ms,
        });
    }
    sqlite::admit_safety_write(
        &transaction,
        key_bundle,
        database_id,
        &state.storage_path,
        config.capacity_probe.as_ref(),
    )?;

    let ledger = sqlite::load_runtime_ledger(&transaction, key_bundle, database_id)?;
    let previous = conversation
        .event_high_water
        .map(super::sequence::encode_sequence);
    let event_seq = next_sequence(SequenceScope::EventSeq, previous.as_deref())?;
    let event_id = allocate_id(&transaction, config, RuntimeIdKind::Event)?;
    let terminal_token = accepted_termination_token(
        key_bundle,
        input.reason,
        input.conversation_id,
        input.command_id,
        &event_payload,
    )?;
    let sealed_event = seal(
        key_bundle,
        database_id,
        b"event_journal",
        event_id.as_bytes(),
        b"sealed_event",
        &event_payload,
        crate::runtime::model::MAX_CRITICAL_COMMAND_RECORD_BYTES,
    )?;
    let index_tokens = load_command_index_tokens(&transaction, input.command_id)?;
    let logical_payload_bytes =
        u64::try_from(command.payload.len()).map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
    let metadata_token = command_metadata_token(
        key_bundle,
        input.conversation_id,
        input.command_id,
        command.command_seq,
        &index_tokens.owner_token,
        &index_tokens.idempotency_token,
        &index_tokens.payload_token,
        Some(terminal_token.as_bytes()),
        terminal_state,
        logical_payload_bytes,
        command.accepted_at_ms,
        command.expires_at_ms,
        command.retain_until_ms,
        None,
        Some(terminal_at_ms),
        None,
        None,
        Some(event_id),
    )?;
    if transaction.execute(
        "UPDATE commands
         SET state = ?1, terminal_token = ?2, terminal_event_id = ?3,
             terminal_at_ms = ?4, metadata_token = ?5
         WHERE command_id = ?6 AND state = 'accepted' AND metadata_token = ?7",
        params![
            command_state_text(terminal_state),
            &terminal_token.as_bytes()[..],
            &event_id.as_bytes()[..],
            sqlite_time(terminal_at_ms)?,
            &metadata_token[..],
            &input.command_id.as_bytes()[..],
            &index_tokens.metadata_token,
        ],
    )? != 1
    {
        return Err(RuntimeStoreError::SchemaInspectionRaced);
    }
    let event_metadata = event_metadata_token(
        key_bundle,
        input.conversation_id,
        event_id,
        event_seq.value,
        Some(input.command_id),
        u64::try_from(event_payload.len()).map_err(|_| RuntimeStoreError::PayloadTooLarge)?,
        terminal_at_ms,
    )?;
    transaction.execute(
        "INSERT INTO event_journal (
             conversation_id, event_seq, event_id, command_id,
             logical_event_bytes, created_at_ms, metadata_token, sealed_event
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            &input.conversation_id.as_bytes()[..],
            event_seq.encoded,
            &event_id.as_bytes()[..],
            &input.command_id.as_bytes()[..],
            i64::try_from(event_payload.len()).map_err(|_| RuntimeStoreError::PayloadTooLarge)?,
            sqlite_time(terminal_at_ms)?,
            &event_metadata[..],
            sealed_event,
        ],
    )?;
    update_conversation_high_water(
        &transaction,
        input.conversation_id,
        "event_high_water",
        &event_seq.encoded,
        previous.as_deref(),
        sqlite_time(terminal_at_ms)?,
        key_bundle,
        database_id,
        ConversationQueueDelta::Decrement,
    )?;
    let mut next_ledger = ledger.clone();
    next_ledger.accepted_count = next_ledger
        .accepted_count
        .checked_sub(1)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    next_ledger.accepted_payload_bytes = next_ledger
        .accepted_payload_bytes
        .checked_sub(logical_payload_bytes)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    next_ledger.event_count = next_ledger
        .event_count
        .checked_add(1)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let pending_targets = sqlite::update_runtime_ledger(
        &transaction,
        key_bundle,
        database_id,
        &ledger,
        &next_ledger,
    )?;
    config
        .fault_injector
        .before_operation(RuntimeStoreOperation::TerminateAcceptedCommandBeforeCommit)?;
    commit_transaction_with_effects(
        transaction,
        RuntimeCommitOperation::TerminateAcceptedCommand,
        pending_targets,
        effects,
    )?;
    sqlite::latch_post_commit_capacity(state, config);
    after_commit(
        config,
        RuntimeStoreOperation::TerminateAcceptedCommandAfterCommit,
        RuntimeCommitOperation::TerminateAcceptedCommand,
    )?;

    let command = CommandRecord {
        state: terminal_state,
        terminal_at_ms: Some(terminal_at_ms),
        terminal_event_id: Some(event_id),
        ..command
    };
    Ok(TerminateAcceptedOutcome::Transitioned {
        command,
        event: EventRecord {
            conversation_id: input.conversation_id,
            event_id,
            event_seq: event_seq.value,
            command_id: Some(input.command_id),
            created_at_ms: terminal_at_ms,
            payload: event_payload,
        },
    })
}

pub(crate) fn query_command_receipt(
    state: &RuntimeSqlite,
    input: QueryCommandReceipt,
) -> Result<CommandReceiptRecord, RuntimeStoreError> {
    let owner_bytes = Zeroizing::new(canonical_owner_v1(&input.expected_owner));
    let expected_owner_token = state
        .key_bundle
        .blind_index(b"command.owner.v1", owner_bytes.as_ref())?;
    let (conversation_id, command_id) = match input.selector {
        CommandReceiptSelector::Command {
            conversation_id,
            command_id,
        } => {
            ensure_kind(conversation_id, RuntimeIdKind::Conversation)?;
            ensure_kind(command_id, RuntimeIdKind::Command)?;
            (conversation_id, command_id)
        }
        CommandReceiptSelector::Idempotency {
            conversation_id,
            idempotency_key,
        } => {
            ensure_kind(conversation_id, RuntimeIdKind::Conversation)?;
            if idempotency_key.is_empty() || idempotency_key.len() > MAX_IDEMPOTENCY_KEY_BYTES {
                return Err(RuntimeStoreError::InvalidConfig(
                    "idempotency key must contain 1 to 1024 UTF-8 bytes",
                ));
            }
            let idempotency_plaintext = Zeroizing::new(canonical_fields(&[
                conversation_id.as_bytes(),
                owner_bytes.as_ref(),
                idempotency_key.as_bytes(),
            ])?);
            let idempotency_token = state
                .key_bundle
                .blind_index(b"command.idempotency.v1", idempotency_plaintext.as_ref())?;
            let command_id = state
                .connection
                .query_row(
                    "SELECT command_id FROM commands WHERE idempotency_token = ?1",
                    [&idempotency_token.as_bytes()[..]],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .optional()?
                .ok_or(RuntimeStoreError::CommandNotFound)?;
            (
                conversation_id,
                runtime_id(RuntimeIdKind::Command, command_id)?,
            )
        }
    };
    load_compact_command_receipt(
        &state.connection,
        &state.key_bundle,
        conversation_id,
        command_id,
        expected_owner_token.as_bytes(),
    )
}

fn expire_accepted_commands(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    observed_at_ms: u64,
    effects: &mut CommandStreamEffects,
) -> Result<(), RuntimeStoreError> {
    let observed_at = sqlite_time(observed_at_ms)?;
    let database_id = state.database_id;
    let key_bundle = &state.key_bundle;
    let transaction = state
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let ledger = sqlite::load_runtime_ledger(&transaction, key_bundle, database_id)?;
    let mut expired_ids = Vec::new();
    {
        let mut statement = transaction.prepare(
            "SELECT command_id FROM commands
             WHERE state = 'accepted' AND expires_at_ms <= ?1
             ORDER BY conversation_id, command_seq",
        )?;
        for row in statement.query_map([observed_at], |row| row.get::<_, Vec<u8>>(0))? {
            expired_ids.push(runtime_id(RuntimeIdKind::Command, row?)?);
        }
    }
    if expired_ids.is_empty() {
        return Ok(());
    }
    sqlite::admit_safety_write(
        &transaction,
        key_bundle,
        database_id,
        &state.storage_path,
        config.capacity_probe.as_ref(),
    )?;

    let mut next_ledger = ledger.clone();
    for command_id in expired_ids {
        let command = load_command(&transaction, key_bundle, database_id, command_id)?;
        if command.state != CommandState::Accepted {
            return Err(RuntimeStoreError::SchemaInspectionRaced);
        }
        let conversation = load_conversation(
            &transaction,
            key_bundle,
            database_id,
            command.conversation_id,
        )?;
        let previous = conversation
            .event_high_water
            .map(super::sequence::encode_sequence);
        let event_seq = next_sequence(SequenceScope::EventSeq, previous.as_deref())?;
        let event_id = allocate_id(&transaction, config, RuntimeIdKind::Event)?;
        let expiry_time = command.expires_at_ms.to_be_bytes();
        let event_payload =
            encode_fields(EXPIRY_EVENT_MAGIC, &[command_id.as_bytes(), &expiry_time])?;
        let token_plaintext = Zeroizing::new(canonical_fields(&[
            command.conversation_id.as_bytes(),
            command_id.as_bytes(),
            &[5],
            &event_payload,
        ])?);
        let terminal_token =
            key_bundle.blind_index(b"command.expired.v1", token_plaintext.as_ref())?;
        let sealed_event = seal(
            key_bundle,
            database_id,
            b"event_journal",
            event_id.as_bytes(),
            b"sealed_event",
            &event_payload,
            MAX_RUNTIME_EVENT_BYTES,
        )?;
        let index_tokens = load_command_index_tokens(&transaction, command_id)?;
        let command_metadata_token = command_metadata_token(
            key_bundle,
            command.conversation_id,
            command.command_id,
            command.command_seq,
            &index_tokens.owner_token,
            &index_tokens.idempotency_token,
            &index_tokens.payload_token,
            Some(terminal_token.as_bytes()),
            CommandState::Expired,
            u64::try_from(command.payload.len()).map_err(|_| RuntimeStoreError::PayloadTooLarge)?,
            command.accepted_at_ms,
            command.expires_at_ms,
            command.retain_until_ms,
            None,
            Some(command.expires_at_ms),
            None,
            None,
            Some(event_id),
        )?;
        if transaction.execute(
            "UPDATE commands
             SET state = 'expired', terminal_token = ?1, terminal_event_id = ?2,
                 terminal_at_ms = expires_at_ms, metadata_token = ?3
             WHERE command_id = ?4 AND state = 'accepted' AND metadata_token = ?5",
            params![
                &terminal_token.as_bytes()[..],
                &event_id.as_bytes()[..],
                &command_metadata_token[..],
                &command_id.as_bytes()[..],
                &index_tokens.metadata_token,
            ],
        )? != 1
        {
            return Err(RuntimeStoreError::SchemaInspectionRaced);
        }
        transaction.execute(
            "INSERT INTO event_journal (
                 conversation_id, event_seq, event_id, command_id,
                 logical_event_bytes, created_at_ms, metadata_token, sealed_event
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                &command.conversation_id.as_bytes()[..],
                event_seq.encoded,
                &event_id.as_bytes()[..],
                &command_id.as_bytes()[..],
                i64::try_from(event_payload.len())
                    .map_err(|_| RuntimeStoreError::PayloadTooLarge)?,
                sqlite_time(command.expires_at_ms)?,
                &event_metadata_token(
                    key_bundle,
                    command.conversation_id,
                    event_id,
                    event_seq.value,
                    Some(command_id),
                    u64::try_from(event_payload.len())
                        .map_err(|_| RuntimeStoreError::PayloadTooLarge)?,
                    command.expires_at_ms,
                )?[..],
                sealed_event,
            ],
        )?;
        update_conversation_high_water(
            &transaction,
            command.conversation_id,
            "event_high_water",
            &event_seq.encoded,
            previous.as_deref(),
            sqlite_time(command.expires_at_ms)?,
            key_bundle,
            database_id,
            ConversationQueueDelta::Decrement,
        )?;
        next_ledger.accepted_count = next_ledger
            .accepted_count
            .checked_sub(1)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        next_ledger.accepted_payload_bytes = next_ledger
            .accepted_payload_bytes
            .checked_sub(
                u64::try_from(command.payload.len())
                    .map_err(|_| RuntimeStoreError::PayloadTooLarge)?,
            )
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        next_ledger.event_count = next_ledger
            .event_count
            .checked_add(1)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    }
    let pending_targets = sqlite::update_runtime_ledger(
        &transaction,
        key_bundle,
        database_id,
        &ledger,
        &next_ledger,
    )?;
    config
        .fault_injector
        .before_operation(RuntimeStoreOperation::ExpireCommandsBeforeCommit)?;
    commit_transaction_with_effects(
        transaction,
        RuntimeCommitOperation::ExpireCommands,
        pending_targets,
        effects,
    )?;
    sqlite::latch_post_commit_capacity(state, config);
    after_commit(
        config,
        RuntimeStoreOperation::ExpireCommandsAfterCommit,
        RuntimeCommitOperation::ExpireCommands,
    )
}

pub(crate) fn begin_recovery_scan(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    effects: &mut CommandStreamEffects,
) -> Result<RecoveryCursor, RuntimeStoreError> {
    begin_recovery_scan_inner(state, config, effects, true)
}

/// 第二遍 recovery verification 只冻结并校验上一遍已经选定的 durable cut，不再次
/// 推进 Accepted expiry。否则合法 command 在两遍之间恰好到期会让 daemon 被自己的
/// 时间推进击穿，无法完成启动。
pub(crate) fn begin_recovery_verification_scan(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    effects: &mut CommandStreamEffects,
) -> Result<RecoveryCursor, RuntimeStoreError> {
    begin_recovery_scan_inner(state, config, effects, false)
}

fn begin_recovery_scan_inner(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    effects: &mut CommandStreamEffects,
    sweep_expired: bool,
) -> Result<RecoveryCursor, RuntimeStoreError> {
    if let Some(scan) = state.recovery_scan.as_ref() {
        if scan.last_cursor.is_none() {
            return Ok(scan.initial_cursor.clone());
        }
        return Err(RuntimeStoreError::RecoveryInProgress);
    }

    // Integrity validation is streaming and holds no cross-call transaction. Expiry is the only
    // mutation before the catalog barrier freezes; afterwards the worker rejects every mutation
    // until finish_recovery_scan verifies the cumulative authenticated ledger counts.
    validate_store_integrity(&state.connection, &state.key_bundle, state.database_id)?;
    if sweep_expired {
        let observed_at_ms = config.clock.now_ms()?;
        expire_accepted_commands(state, config, observed_at_ms, effects)?;
    }
    validate_store_integrity(&state.connection, &state.key_bundle, state.database_id)?;

    let ledger =
        sqlite::load_runtime_ledger(&state.connection, &state.key_bundle, state.database_id)?;
    let replay_through = ledger
        .catalog_high_water
        .as_deref()
        .map(|value| decode_sequence(SequenceScope::CatalogRevision, value))
        .transpose()?;
    let conversations = ledger.conversation_count;
    if (replay_through.is_none() && conversations != 0)
        || (replay_through.is_some() && conversations == 0)
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }

    let scan_id = new_recovery_scan_id()?;
    let initial_cursor = RecoveryCursor {
        scan_id,
        after_catalog_revision: None,
        after_conversation_id: None,
    };
    state.recovery_scan = Some(RecoveryScanState {
        scan_id,
        replay_through,
        expected_counts: RecoveryScanCounts {
            conversations,
            accepted_count: ledger.accepted_count,
            accepted_payload_bytes: ledger.accepted_payload_bytes,
            started_without_fence_count: ledger.started_without_fence_count,
            started_without_release_count: ledger.started_without_release_count,
            started_released_count: ledger.started_released_count,
        },
        observed_counts: RecoveryScanCounts::default(),
        initial_cursor: initial_cursor.clone(),
        next_cursor: Some(initial_cursor.clone()),
        last_cursor: None,
        last_next_cursor: None,
        last_completion: None,
    });
    state.last_finished_recovery = None;
    Ok(initial_cursor)
}

pub(crate) fn load_recovery_page(
    state: &mut RuntimeSqlite,
    cursor: RecoveryCursor,
) -> Result<RecoveryPage, RuntimeStoreError> {
    let (is_retry, replay_through, previous_next, previous_completion) = {
        let scan = state
            .recovery_scan
            .as_ref()
            .ok_or(RuntimeStoreError::RecoveryNotActive)?;
        if cursor.scan_id != scan.scan_id {
            return Err(RuntimeStoreError::InvalidRecoveryCursor);
        }
        if scan.last_cursor.as_ref() == Some(&cursor) {
            (
                true,
                scan.replay_through,
                scan.last_next_cursor.clone(),
                scan.last_completion.clone(),
            )
        } else if scan.next_cursor.as_ref() == Some(&cursor) {
            (false, scan.replay_through, None, None)
        } else {
            return Err(RuntimeStoreError::InvalidRecoveryCursor);
        }
    };

    let loaded = load_next_recovery_conversation(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        replay_through,
        &cursor,
    )?;
    let (conversation, next_cursor, completion) = match loaded {
        None => {
            if replay_through.is_some() {
                return Err(RuntimeStoreError::UnknownOrCorruptSchema);
            }
            (
                None,
                None,
                Some(RecoveryCompletion {
                    scan_id: cursor.scan_id,
                    final_after_catalog_revision: None,
                    final_after_conversation_id: None,
                }),
            )
        }
        Some((catalog_revision, conversation_id, record)) => {
            let replay_through = replay_through.ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
            if catalog_revision > replay_through {
                return Err(RuntimeStoreError::UnknownOrCorruptSchema);
            }
            if catalog_revision == replay_through {
                (
                    Some(record),
                    None,
                    Some(RecoveryCompletion {
                        scan_id: cursor.scan_id,
                        final_after_catalog_revision: Some(catalog_revision),
                        final_after_conversation_id: Some(conversation_id),
                    }),
                )
            } else {
                (
                    Some(record),
                    Some(RecoveryCursor {
                        scan_id: cursor.scan_id,
                        after_catalog_revision: Some(catalog_revision),
                        after_conversation_id: Some(conversation_id),
                    }),
                    None,
                )
            }
        }
    };
    let page = RecoveryPage {
        conversation,
        next_cursor,
        completion,
    };
    ensure_recovery_page_budget(recovery_page_retained_bytes(&page)?)?;

    if is_retry {
        if page.next_cursor != previous_next || page.completion != previous_completion {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        return Ok(page);
    }

    let delta = recovery_page_counts(&page)?;
    let scan = state
        .recovery_scan
        .as_mut()
        .ok_or(RuntimeStoreError::RecoveryNotActive)?;
    scan.observed_counts = checked_add_recovery_counts(scan.observed_counts, delta)?;
    if recovery_counts_exceed(scan.observed_counts, scan.expected_counts) {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    scan.last_cursor = Some(cursor);
    scan.last_next_cursor = page.next_cursor.clone();
    scan.last_completion = page.completion.clone();
    scan.next_cursor = page.next_cursor.clone();
    Ok(page)
}

pub(crate) fn finish_recovery_scan(
    state: &mut RuntimeSqlite,
    completion: RecoveryCompletion,
) -> Result<(), RuntimeStoreError> {
    let Some(scan) = state.recovery_scan.as_ref() else {
        return if state.last_finished_recovery.as_ref() == Some(&completion) {
            Ok(())
        } else if state.last_finished_recovery.is_some() {
            Err(RuntimeStoreError::InvalidRecoveryCursor)
        } else {
            Err(RuntimeStoreError::RecoveryNotActive)
        };
    };
    let Some(expected_completion) = scan.last_completion.as_ref() else {
        return Err(RuntimeStoreError::RecoveryNotReady);
    };
    if completion != *expected_completion || completion.scan_id != scan.scan_id {
        return Err(RuntimeStoreError::InvalidRecoveryCursor);
    }
    if scan.next_cursor.is_some() || scan.observed_counts != scan.expected_counts {
        return Err(RuntimeStoreError::RecoveryNotReady);
    }
    // No cross-call transaction pins WAL, so revalidate immediately before opening mutations.
    // This catches same-UID/offline tooling changes that may have landed after begin/page.
    validate_store_integrity(&state.connection, &state.key_bundle, state.database_id)?;
    state.recovery_scan = None;
    state.last_finished_recovery = Some(completion);
    Ok(())
}

fn new_recovery_scan_id() -> Result<[u8; 16], RuntimeStoreError> {
    for _ in 0..MAX_RUNTIME_ID_COLLISION_ATTEMPTS {
        let mut scan_id = [0_u8; 16];
        getrandom::fill(&mut scan_id)
            .map_err(|_| RuntimeStoreError::InvalidConfig("OS entropy unavailable"))?;
        if scan_id != [0; 16] {
            return Ok(scan_id);
        }
    }
    Err(RuntimeStoreError::InvalidConfig(
        "recovery scan id generation exhausted",
    ))
}

fn load_next_recovery_conversation(
    connection: &Connection,
    key_bundle: &super::cipher::RuntimeKeyBundle,
    database_id: [u8; 16],
    replay_through: Option<u64>,
    cursor: &RecoveryCursor,
) -> Result<Option<(u64, RuntimeId, ConversationRecoveryRecord)>, RuntimeStoreError> {
    let Some(replay_through) = replay_through else {
        return Ok(None);
    };
    let replay_through = super::sequence::encode_sequence(replay_through);
    let raw = match (cursor.after_catalog_revision, cursor.after_conversation_id) {
        (None, None) => connection
            .query_row(
                "SELECT catalog_revision, conversation_id FROM conversations
                 WHERE catalog_revision <= ?1
                 ORDER BY catalog_revision, conversation_id LIMIT 1",
                [&replay_through],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()?,
        (Some(after_revision), Some(after_conversation_id)) => {
            let after_revision = super::sequence::encode_sequence(after_revision);
            connection
                .query_row(
                    "SELECT catalog_revision, conversation_id FROM conversations
                     WHERE catalog_revision <= ?1
                       AND (catalog_revision > ?2
                            OR (catalog_revision = ?2 AND conversation_id > ?3))
                     ORDER BY catalog_revision, conversation_id LIMIT 1",
                    params![
                        replay_through,
                        after_revision,
                        &after_conversation_id.as_bytes()[..],
                    ],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)),
                )
                .optional()?
        }
        _ => return Err(RuntimeStoreError::InvalidRecoveryCursor),
    };
    let Some((catalog_revision, conversation_id)) = raw else {
        return Ok(None);
    };
    let catalog_revision = decode_sequence(SequenceScope::CatalogRevision, &catalog_revision)?;
    let conversation_id = runtime_id(RuntimeIdKind::Conversation, conversation_id)?;
    let conversation = load_conversation(connection, key_bundle, database_id, conversation_id)?;
    if conversation.catalog_revision != catalog_revision {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }

    let mut accepted_ids = Vec::new();
    let mut statement = connection.prepare(
        "SELECT command_id FROM commands
         WHERE conversation_id = ?1 AND state = 'accepted'
         ORDER BY command_seq",
    )?;
    for row in statement.query_map([&conversation_id.as_bytes()[..]], |row| {
        row.get::<_, Vec<u8>>(0)
    })? {
        accepted_ids.push(runtime_id(RuntimeIdKind::Command, row?)?);
    }
    if accepted_ids.len()
        != usize::try_from(conversation.accepted_command_count)
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let accepted = accepted_ids
        .into_iter()
        .map(|command_id| load_command(connection, key_bundle, database_id, command_id))
        .collect::<Result<Vec<_>, _>>()?;
    if accepted
        .iter()
        .any(|command| command.conversation_id != conversation_id)
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }

    let mut started_ids = Vec::new();
    let mut statement = connection.prepare(
        "SELECT command_id FROM commands
         WHERE conversation_id = ?1 AND state = 'started'
         ORDER BY command_seq LIMIT 2",
    )?;
    for row in statement.query_map([&conversation_id.as_bytes()[..]], |row| {
        row.get::<_, Vec<u8>>(0)
    })? {
        started_ids.push(runtime_id(RuntimeIdKind::Command, row?)?);
    }
    if started_ids.len() > 1 {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let started = started_ids
        .into_iter()
        .next()
        .map(|command_id| {
            let command = load_command(connection, key_bundle, database_id, command_id)?;
            if command.conversation_id != conversation_id {
                return Err(RuntimeStoreError::UnknownOrCorruptSchema);
            }
            let intent = load_intent(connection, key_bundle, database_id, command_id)?;
            let event = load_event(connection, key_bundle, database_id, intent.started_event_id)?;
            validate_started_linkage(&command, &intent, &event)?;
            let fence = load_optional_fence(connection, key_bundle, database_id, command_id)?;
            Ok(StartedRecoveryRecord {
                command,
                intent,
                event,
                fence,
            })
        })
        .transpose()?;

    Ok(Some((
        catalog_revision,
        conversation_id,
        ConversationRecoveryRecord {
            conversation,
            accepted,
            started,
        },
    )))
}

fn recovery_page_counts(page: &RecoveryPage) -> Result<RecoveryScanCounts, RuntimeStoreError> {
    let Some(record) = page.conversation.as_ref() else {
        return Ok(RecoveryScanCounts::default());
    };
    let accepted_count = u64::try_from(record.accepted.len())
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let accepted_payload_bytes = record.accepted.iter().try_fold(0_u64, |total, command| {
        total
            .checked_add(
                u64::try_from(command.payload.len())
                    .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            )
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)
    })?;
    let mut counts = RecoveryScanCounts {
        conversations: 1,
        accepted_count,
        accepted_payload_bytes,
        ..RecoveryScanCounts::default()
    };
    if let Some(started) = record.started.as_ref() {
        match started.fence.as_ref() {
            None => counts.started_without_fence_count = 1,
            Some(fence) if fence.release_authorized_at_ms.is_none() => {
                counts.started_without_release_count = 1;
            }
            Some(_) => counts.started_released_count = 1,
        }
    }
    Ok(counts)
}

fn checked_add_recovery_counts(
    left: RecoveryScanCounts,
    right: RecoveryScanCounts,
) -> Result<RecoveryScanCounts, RuntimeStoreError> {
    Ok(RecoveryScanCounts {
        conversations: left
            .conversations
            .checked_add(right.conversations)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?,
        accepted_count: left
            .accepted_count
            .checked_add(right.accepted_count)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?,
        accepted_payload_bytes: left
            .accepted_payload_bytes
            .checked_add(right.accepted_payload_bytes)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?,
        started_without_fence_count: left
            .started_without_fence_count
            .checked_add(right.started_without_fence_count)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?,
        started_without_release_count: left
            .started_without_release_count
            .checked_add(right.started_without_release_count)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?,
        started_released_count: left
            .started_released_count
            .checked_add(right.started_released_count)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?,
    })
}

fn recovery_counts_exceed(left: RecoveryScanCounts, right: RecoveryScanCounts) -> bool {
    left.conversations > right.conversations
        || left.accepted_count > right.accepted_count
        || left.accepted_payload_bytes > right.accepted_payload_bytes
        || left.started_without_fence_count > right.started_without_fence_count
        || left.started_without_release_count > right.started_without_release_count
        || left.started_released_count > right.started_released_count
}

fn recovery_page_retained_bytes(page: &RecoveryPage) -> Result<u64, RuntimeStoreError> {
    let mut total = u64::try_from(size_of::<RecoveryPage>()).map_err(|_| {
        RuntimeStoreError::CapacityArithmeticOverflow {
            field: "recovery page retained bytes",
        }
    })?;
    let Some(record) = page.conversation.as_ref() else {
        return Ok(total);
    };
    let mut add = |bytes: usize| -> Result<(), RuntimeStoreError> {
        total = total
            .checked_add(u64::try_from(bytes).map_err(|_| {
                RuntimeStoreError::CapacityArithmeticOverflow {
                    field: "recovery page retained bytes",
                }
            })?)
            .ok_or(RuntimeStoreError::CapacityArithmeticOverflow {
                field: "recovery page retained bytes",
            })?;
        Ok(())
    };
    add(size_of::<ConversationRecoveryRecord>())?;
    add(record
        .conversation
        .descriptor
        .title
        .as_ref()
        .map_or(0, String::capacity))?;
    add(record.conversation.descriptor.cwd.capacity())?;
    add(record
        .accepted
        .capacity()
        .checked_mul(size_of::<CommandRecord>())
        .ok_or(RuntimeStoreError::CapacityArithmeticOverflow {
            field: "recovery page retained bytes",
        })?)?;
    for command in &record.accepted {
        add(command.payload.capacity())?;
        add(command.result.as_ref().map_or(0, Vec::capacity))?;
    }
    if let Some(started) = record.started.as_ref() {
        add(size_of::<StartedRecoveryRecord>())?;
        add(started.command.payload.capacity())?;
        add(started.command.result.as_ref().map_or(0, Vec::capacity))?;
        add(started.intent.execution_nonce.capacity())?;
        add(started.intent.payload.capacity())?;
        add(started.event.payload.capacity())?;
        if let Some(fence) = started.fence.as_ref() {
            add(size_of::<ExecutionFenceRecord>())?;
            add(fence.payload.capacity())?;
        }
    }
    Ok(total)
}

fn ensure_recovery_page_budget(projected_bytes: u64) -> Result<(), RuntimeStoreError> {
    let limit_bytes = u64::try_from(MAX_RECOVERY_PAGE_RETAINED_BYTES)
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    if projected_bytes > limit_bytes {
        return Err(RuntimeStoreError::RecoveryPageTooLarge {
            projected_bytes,
            limit_bytes,
        });
    }
    Ok(())
}

fn load_optional_conversation(
    connection: &Connection,
    key_bundle: &super::cipher::RuntimeKeyBundle,
    database_id: [u8; 16],
    conversation_id: RuntimeId,
) -> Result<Option<ConversationRecord>, RuntimeStoreError> {
    ensure_kind(conversation_id, RuntimeIdKind::Conversation)?;
    let exists: i64 = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM conversations WHERE conversation_id = ?1)",
        [&conversation_id.as_bytes()[..]],
        |row| row.get(0),
    )?;
    if exists == 0 {
        Ok(None)
    } else {
        load_conversation(connection, key_bundle, database_id, conversation_id).map(Some)
    }
}

const AUTHENTICATED_EVENT_HIGH_WATER_QUERY: &str =
    "SELECT adapter_state_key, catalog_revision, command_high_water,
            event_high_water, lifecycle, created_at_ms, updated_at_ms,
            accepted_count, metadata_token
     FROM conversations WHERE conversation_id = ?1";

#[cfg(test)]
std::thread_local! {
    static AUTHENTICATED_EVENT_HIGH_WATER_QUERY_COUNT: std::cell::Cell<u64> = const {
        std::cell::Cell::new(0)
    };
}

#[cfg(test)]
pub(super) fn reset_authenticated_event_high_water_query_count() {
    AUTHENTICATED_EVENT_HIGH_WATER_QUERY_COUNT.with(|count| count.set(0));
}

#[cfg(test)]
pub(super) fn authenticated_event_high_water_query_count() -> u64 {
    AUTHENTICATED_EVENT_HIGH_WATER_QUERY_COUNT.with(std::cell::Cell::get)
}

#[cfg(test)]
fn observe_authenticated_event_high_water_query() {
    AUTHENTICATED_EVENT_HIGH_WATER_QUERY_COUNT.with(|count| count.set(count.get() + 1));
}

#[cfg(not(test))]
fn observe_authenticated_event_high_water_query() {}

struct RawConversationEventHighWaterMetadata {
    adapter_state_key: Vec<u8>,
    catalog_revision: String,
    command_high_water: Option<String>,
    event_high_water: Option<String>,
    lifecycle: String,
    created_at_ms: i64,
    updated_at_ms: i64,
    accepted_count: i64,
    metadata_token: Vec<u8>,
}

fn read_conversation_event_high_water_metadata(
    row: &rusqlite::Row<'_>,
    offset: usize,
) -> rusqlite::Result<RawConversationEventHighWaterMetadata> {
    Ok(RawConversationEventHighWaterMetadata {
        adapter_state_key: row.get(offset)?,
        catalog_revision: row.get(offset + 1)?,
        command_high_water: row.get(offset + 2)?,
        event_high_water: row.get(offset + 3)?,
        lifecycle: row.get(offset + 4)?,
        created_at_ms: row.get(offset + 5)?,
        updated_at_ms: row.get(offset + 6)?,
        accepted_count: row.get(offset + 7)?,
        metadata_token: row.get(offset + 8)?,
    })
}

fn authenticate_conversation_event_high_water_metadata(
    key_bundle: &super::cipher::RuntimeKeyBundle,
    conversation_id: RuntimeId,
    raw: RawConversationEventHighWaterMetadata,
) -> Result<Option<u64>, RuntimeStoreError> {
    let adapter_state_key = runtime_id(RuntimeIdKind::AdapterState, raw.adapter_state_key)?;
    let catalog_revision = decode_sequence(SequenceScope::CatalogRevision, &raw.catalog_revision)?;
    let command_high_water = raw
        .command_high_water
        .as_deref()
        .map(|value| decode_sequence(SequenceScope::CommandSeq, value))
        .transpose()?;
    let event_high_water = raw
        .event_high_water
        .as_deref()
        .map(|value| decode_sequence(SequenceScope::EventSeq, value))
        .transpose()?;
    let lifecycle = parse_lifecycle(&raw.lifecycle)?;
    let created_at_ms = runtime_time(raw.created_at_ms)?;
    let updated_at_ms = runtime_time(raw.updated_at_ms)?;
    let accepted_command_count =
        u32::try_from(raw.accepted_count).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let expected = conversation_metadata_token(
        key_bundle,
        conversation_id,
        adapter_state_key,
        catalog_revision,
        command_high_water,
        event_high_water,
        accepted_command_count,
        lifecycle,
        created_at_ms,
        updated_at_ms,
    )?;
    if raw.metadata_token.as_slice() != expected {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(event_high_water)
}

/// Snapshot directory 只需要 parent 的 authenticated event HWM。该读取复用
/// conversation metadata MAC，但不选择、复制或解密 `sealed_descriptor`；请求
/// target 的完整 cut 仍由 `load_conversation` 认证。
pub(super) fn load_authenticated_conversation_event_high_water(
    connection: &Connection,
    key_bundle: &super::cipher::RuntimeKeyBundle,
    conversation_id: RuntimeId,
) -> Result<Option<u64>, RuntimeStoreError> {
    ensure_kind(conversation_id, RuntimeIdKind::Conversation)?;
    observe_authenticated_event_high_water_query();
    let raw = connection
        .query_row(
            AUTHENTICATED_EVENT_HIGH_WATER_QUERY,
            [&conversation_id.as_bytes()[..]],
            |row| read_conversation_event_high_water_metadata(row, 0),
        )
        .map_err(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => RuntimeStoreError::ConversationNotFound,
            other => RuntimeStoreError::Sqlite(other),
        })?;
    authenticate_conversation_event_high_water_metadata(key_bundle, conversation_id, raw)
}

/// Snapshot directory 的 conversation parents 已经受 1,024 行硬上界约束；
/// 用一个 bounded `IN` query 读回并逐行认证 metadata MAC，避免唯一 worker
/// 对同一 directory 执行 N 次独立 SELECT。
pub(super) fn load_authenticated_conversation_event_high_waters(
    connection: &Connection,
    key_bundle: &super::cipher::RuntimeKeyBundle,
    conversation_ids: &[RuntimeId],
) -> Result<HashMap<RuntimeId, Option<u64>>, RuntimeStoreError> {
    if conversation_ids.is_empty() {
        return Ok(HashMap::new());
    }
    let mut expected_ids = HashSet::with_capacity(conversation_ids.len());
    for conversation_id in conversation_ids {
        ensure_kind(*conversation_id, RuntimeIdKind::Conversation)?;
        if !expected_ids.insert(*conversation_id) {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
    }
    let placeholders = std::iter::repeat_n("?", conversation_ids.len())
        .collect::<Vec<_>>()
        .join(", ");
    let query = format!(
        "SELECT conversation_id, adapter_state_key, catalog_revision, command_high_water,
                event_high_water, lifecycle, created_at_ms, updated_at_ms,
                accepted_count, metadata_token
         FROM conversations
         WHERE conversation_id IN ({placeholders})
         ORDER BY conversation_id"
    );
    observe_authenticated_event_high_water_query();
    let mut statement = connection.prepare(&query)?;
    let rows = statement.query_map(
        rusqlite::params_from_iter(
            conversation_ids
                .iter()
                .map(|conversation_id| &conversation_id.as_bytes()[..]),
        ),
        |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                read_conversation_event_high_water_metadata(row, 1)?,
            ))
        },
    )?;
    let mut high_waters = HashMap::with_capacity(conversation_ids.len());
    for row in rows {
        let (conversation_id, raw) = row?;
        let conversation_id = runtime_id(RuntimeIdKind::Conversation, conversation_id)?;
        if !expected_ids.contains(&conversation_id)
            || high_waters
                .insert(
                    conversation_id,
                    authenticate_conversation_event_high_water_metadata(
                        key_bundle,
                        conversation_id,
                        raw,
                    )?,
                )
                .is_some()
        {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
    }
    if high_waters.len() != expected_ids.len() {
        return Err(RuntimeStoreError::ConversationNotFound);
    }
    Ok(high_waters)
}

pub(super) fn load_conversation(
    connection: &Connection,
    key_bundle: &super::cipher::RuntimeKeyBundle,
    database_id: [u8; 16],
    conversation_id: RuntimeId,
) -> Result<ConversationRecord, RuntimeStoreError> {
    ensure_kind(conversation_id, RuntimeIdKind::Conversation)?;
    let raw = connection
        .query_row(
            "SELECT adapter_state_key, catalog_revision, command_high_water,
                    event_high_water, lifecycle, created_at_ms, updated_at_ms,
                    accepted_count, metadata_token, sealed_descriptor
             FROM conversations WHERE conversation_id = ?1",
            [&conversation_id.as_bytes()[..]],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, Vec<u8>>(8)?,
                    row.get::<_, Vec<u8>>(9)?,
                ))
            },
        )
        .map_err(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => RuntimeStoreError::ConversationNotFound,
            other => RuntimeStoreError::Sqlite(other),
        })?;
    let descriptor = open(
        key_bundle,
        database_id,
        b"conversations",
        conversation_id.as_bytes(),
        b"sealed_descriptor",
        &raw.9,
        MAX_CONVERSATION_DESCRIPTOR_BYTES,
    )?;
    let record = ConversationRecord {
        conversation_id,
        adapter_state_key: runtime_id(RuntimeIdKind::AdapterState, raw.0)?,
        catalog_revision: decode_sequence(SequenceScope::CatalogRevision, &raw.1)?,
        command_high_water: raw
            .2
            .as_deref()
            .map(|value| decode_sequence(SequenceScope::CommandSeq, value))
            .transpose()?,
        event_high_water: raw
            .3
            .as_deref()
            .map(|value| decode_sequence(SequenceScope::EventSeq, value))
            .transpose()?,
        accepted_command_count: u32::try_from(raw.7)
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
        lifecycle: parse_lifecycle(&raw.4)?,
        created_at_ms: runtime_time(raw.5)?,
        updated_at_ms: runtime_time(raw.6)?,
        descriptor: parse_canonical_conversation_descriptor(descriptor.expose_secret())?,
    };
    let expected = conversation_metadata_token(
        key_bundle,
        record.conversation_id,
        record.adapter_state_key,
        record.catalog_revision,
        record.command_high_water,
        record.event_high_water,
        record.accepted_command_count,
        record.lifecycle,
        record.created_at_ms,
        record.updated_at_ms,
    )?;
    if raw.8.as_slice() != expected {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(record)
}

/// Snapshot materialization 的最小 authenticated parent context。必须复用
/// `load_conversation`，从而同时验证 metadata MAC、descriptor AEAD 与 canonical
/// descriptor re-encode；禁止只读明文列或从 actor cache 猜 agent kind。
pub(super) fn load_authenticated_conversation_snapshot_context(
    connection: &Connection,
    key_bundle: &super::cipher::RuntimeKeyBundle,
    database_id: [u8; 16],
    conversation_id: RuntimeId,
) -> Result<super::AuthenticatedConversationSnapshotContext, RuntimeStoreError> {
    let conversation = load_conversation(connection, key_bundle, database_id, conversation_id)?;
    Ok(super::AuthenticatedConversationSnapshotContext {
        conversation_id: conversation.conversation_id,
        agent_kind: conversation.descriptor.agent_kind,
        event_high_water: conversation.event_high_water,
    })
}

fn load_compact_command_receipt(
    connection: &Connection,
    key_bundle: &super::cipher::RuntimeKeyBundle,
    expected_conversation_id: RuntimeId,
    command_id: RuntimeId,
    expected_owner_token: &[u8; 32],
) -> Result<CommandReceiptRecord, RuntimeStoreError> {
    struct RawReceipt {
        conversation_id: Vec<u8>,
        command_seq: String,
        state: String,
        logical_payload_bytes: i64,
        accepted_at_ms: i64,
        expires_at_ms: i64,
        retain_until_ms: i64,
        started_at_ms: Option<i64>,
        terminal_at_ms: Option<i64>,
        turn_id: Option<Vec<u8>>,
        started_event_id: Option<Vec<u8>>,
        terminal_event_id: Option<Vec<u8>>,
        owner_token: Vec<u8>,
        idempotency_token: Vec<u8>,
        payload_token: Vec<u8>,
        terminal_token: Option<Vec<u8>>,
        metadata_token: Vec<u8>,
        result_present: bool,
    }

    ensure_kind(expected_conversation_id, RuntimeIdKind::Conversation)?;
    ensure_kind(command_id, RuntimeIdKind::Command)?;
    let raw = connection
        .query_row(
            "SELECT conversation_id, command_seq, state, logical_payload_bytes,
                    accepted_at_ms, expires_at_ms, retain_until_ms,
                    started_at_ms, terminal_at_ms, turn_id,
                    started_event_id, terminal_event_id,
                    owner_token, idempotency_token, payload_token, terminal_token,
                    metadata_token, sealed_result IS NOT NULL
             FROM commands WHERE command_id = ?1 AND conversation_id = ?2",
            params![
                &command_id.as_bytes()[..],
                &expected_conversation_id.as_bytes()[..]
            ],
            |row| {
                Ok(RawReceipt {
                    conversation_id: row.get(0)?,
                    command_seq: row.get(1)?,
                    state: row.get(2)?,
                    logical_payload_bytes: row.get(3)?,
                    accepted_at_ms: row.get(4)?,
                    expires_at_ms: row.get(5)?,
                    retain_until_ms: row.get(6)?,
                    started_at_ms: row.get(7)?,
                    terminal_at_ms: row.get(8)?,
                    turn_id: row.get(9)?,
                    started_event_id: row.get(10)?,
                    terminal_event_id: row.get(11)?,
                    owner_token: row.get(12)?,
                    idempotency_token: row.get(13)?,
                    payload_token: row.get(14)?,
                    terminal_token: row.get(15)?,
                    metadata_token: row.get(16)?,
                    result_present: row.get::<_, i64>(17)? != 0,
                })
            },
        )
        .map_err(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => RuntimeStoreError::CommandNotFound,
            other => RuntimeStoreError::Sqlite(other),
        })?;
    let conversation_id = runtime_id(RuntimeIdKind::Conversation, raw.conversation_id)?;
    if conversation_id != expected_conversation_id {
        return Err(RuntimeStoreError::CommandNotFound);
    }
    let command_seq = decode_sequence(SequenceScope::CommandSeq, &raw.command_seq)?;
    let configuration_revision = super::command_configuration::load_revision(
        connection,
        key_bundle,
        conversation_id,
        command_seq,
    )?;
    let state = parse_command_state(&raw.state)?;
    let logical_payload_bytes = u64::try_from(raw.logical_payload_bytes)
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let accepted_at_ms = runtime_time(raw.accepted_at_ms)?;
    let expires_at_ms = runtime_time(raw.expires_at_ms)?;
    let retain_until_ms = runtime_time(raw.retain_until_ms)?;
    let started_at_ms = raw.started_at_ms.map(runtime_time).transpose()?;
    let terminal_at_ms = raw.terminal_at_ms.map(runtime_time).transpose()?;
    let turn_id = raw
        .turn_id
        .map(|value| runtime_id(RuntimeIdKind::Turn, value))
        .transpose()?;
    let started_event_id = raw
        .started_event_id
        .map(|value| runtime_id(RuntimeIdKind::Event, value))
        .transpose()?;
    let terminal_event_id = raw
        .terminal_event_id
        .map(|value| runtime_id(RuntimeIdKind::Event, value))
        .transpose()?;
    let metadata_token = command_metadata_token(
        key_bundle,
        conversation_id,
        command_id,
        command_seq,
        &raw.owner_token,
        &raw.idempotency_token,
        &raw.payload_token,
        raw.terminal_token.as_deref(),
        state,
        logical_payload_bytes,
        accepted_at_ms,
        expires_at_ms,
        retain_until_ms,
        started_at_ms,
        terminal_at_ms,
        turn_id,
        started_event_id,
        terminal_event_id,
    )?;
    if raw.metadata_token.as_slice() != metadata_token {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let result_marker: Option<&[u8]> = raw.result_present.then_some(&[]);
    validate_command_invariants(
        state,
        accepted_at_ms,
        expires_at_ms,
        retain_until_ms,
        started_at_ms,
        terminal_at_ms,
        turn_id,
        started_event_id,
        terminal_event_id,
        raw.terminal_token.as_deref(),
        result_marker,
    )?;
    if raw.owner_token.as_slice() != expected_owner_token {
        return Err(RuntimeStoreError::CommandOwnerMismatch);
    }
    Ok(CommandReceiptRecord {
        command_id,
        configuration_revision,
        state,
        turn_id,
    })
}

fn load_command(
    connection: &Connection,
    key_bundle: &super::cipher::RuntimeKeyBundle,
    database_id: [u8; 16],
    command_id: RuntimeId,
) -> Result<CommandRecord, RuntimeStoreError> {
    struct RawCommand {
        conversation_id: Vec<u8>,
        command_seq: String,
        state: String,
        accepted_at_ms: i64,
        expires_at_ms: i64,
        retain_until_ms: i64,
        started_at_ms: Option<i64>,
        terminal_at_ms: Option<i64>,
        turn_id: Option<Vec<u8>>,
        started_event_id: Option<Vec<u8>>,
        terminal_event_id: Option<Vec<u8>>,
        owner_token: Vec<u8>,
        idempotency_token: Vec<u8>,
        payload_token: Vec<u8>,
        terminal_token: Option<Vec<u8>>,
        logical_payload_bytes: i64,
        metadata_token: Vec<u8>,
        sealed_command: Vec<u8>,
        sealed_result: Option<Vec<u8>>,
    }

    ensure_kind(command_id, RuntimeIdKind::Command)?;
    let raw = connection
        .query_row(
            "SELECT conversation_id, command_seq, state,
                    accepted_at_ms, expires_at_ms, retain_until_ms,
                    started_at_ms, terminal_at_ms, turn_id,
                    started_event_id, terminal_event_id,
                    owner_token, idempotency_token, payload_token, terminal_token,
                    logical_payload_bytes, metadata_token, sealed_command, sealed_result
             FROM commands WHERE command_id = ?1",
            [&command_id.as_bytes()[..]],
            |row| {
                Ok(RawCommand {
                    conversation_id: row.get(0)?,
                    command_seq: row.get(1)?,
                    state: row.get(2)?,
                    accepted_at_ms: row.get(3)?,
                    expires_at_ms: row.get(4)?,
                    retain_until_ms: row.get(5)?,
                    started_at_ms: row.get(6)?,
                    terminal_at_ms: row.get(7)?,
                    turn_id: row.get(8)?,
                    started_event_id: row.get(9)?,
                    terminal_event_id: row.get(10)?,
                    owner_token: row.get(11)?,
                    idempotency_token: row.get(12)?,
                    payload_token: row.get(13)?,
                    terminal_token: row.get(14)?,
                    logical_payload_bytes: row.get(15)?,
                    metadata_token: row.get(16)?,
                    sealed_command: row.get(17)?,
                    sealed_result: row.get(18)?,
                })
            },
        )
        .map_err(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => RuntimeStoreError::CommandNotFound,
            other => RuntimeStoreError::Sqlite(other),
        })?;
    let command_plaintext = open(
        key_bundle,
        database_id,
        b"commands",
        command_id.as_bytes(),
        b"sealed_command",
        &raw.sealed_command,
        MAX_CONVERSATION_DESCRIPTOR_BYTES,
    )?;
    let fields = decode_fields(COMMAND_MAGIC, command_plaintext.expose_secret(), 3)?;
    if fields[0].is_empty()
        || fields[1].is_empty()
        || fields[1].len() > MAX_IDEMPOTENCY_KEY_BYTES
        || fields[2].len() > MAX_COMMAND_PAYLOAD_BYTES
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let owner = decode_canonical_owner(fields[0])?;
    let conversation_id = runtime_id(RuntimeIdKind::Conversation, raw.conversation_id)?;
    let command_seq = decode_sequence(SequenceScope::CommandSeq, &raw.command_seq)?;
    let configuration_revision = super::command_configuration::load_revision(
        connection,
        key_bundle,
        conversation_id,
        command_seq,
    )?;
    let expected_owner_token = key_bundle.blind_index(b"command.owner.v1", fields[0])?;
    let idempotency_plaintext = Zeroizing::new(canonical_fields(&[
        conversation_id.as_bytes(),
        fields[0],
        fields[1],
    ])?);
    let expected_idempotency_token =
        key_bundle.blind_index(b"command.idempotency.v1", idempotency_plaintext.as_ref())?;
    let expected_payload_token = super::command_configuration::command_payload_token(
        key_bundle,
        configuration_revision,
        fields[2],
    )?;
    let logical_payload_bytes = u64::try_from(raw.logical_payload_bytes)
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    if raw.owner_token.as_slice() != expected_owner_token.as_bytes()
        || raw.idempotency_token.as_slice() != expected_idempotency_token.as_bytes()
        || raw.payload_token.as_slice() != expected_payload_token
        || logical_payload_bytes
            != u64::try_from(fields[2].len())
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let result = raw
        .sealed_result
        .as_deref()
        .map(|sealed| {
            open(
                key_bundle,
                database_id,
                b"commands",
                command_id.as_bytes(),
                b"sealed_result",
                sealed,
                MAX_COMMAND_RESULT_BYTES,
            )
            .map(|value| value.expose_secret().to_vec())
        })
        .transpose()?;
    let state = parse_command_state(&raw.state)?;
    let accepted_at_ms = runtime_time(raw.accepted_at_ms)?;
    let expires_at_ms = runtime_time(raw.expires_at_ms)?;
    let retain_until_ms = runtime_time(raw.retain_until_ms)?;
    let started_at_ms = raw.started_at_ms.map(runtime_time).transpose()?;
    let terminal_at_ms = raw.terminal_at_ms.map(runtime_time).transpose()?;
    let turn_id = raw
        .turn_id
        .map(|value| runtime_id(RuntimeIdKind::Turn, value))
        .transpose()?;
    let started_event_id = raw
        .started_event_id
        .map(|value| runtime_id(RuntimeIdKind::Event, value))
        .transpose()?;
    let terminal_event_id = raw
        .terminal_event_id
        .map(|value| runtime_id(RuntimeIdKind::Event, value))
        .transpose()?;
    let expected_metadata_token = command_metadata_token(
        key_bundle,
        conversation_id,
        command_id,
        command_seq,
        &raw.owner_token,
        &raw.idempotency_token,
        &raw.payload_token,
        raw.terminal_token.as_deref(),
        state,
        logical_payload_bytes,
        accepted_at_ms,
        expires_at_ms,
        retain_until_ms,
        started_at_ms,
        terminal_at_ms,
        turn_id,
        started_event_id,
        terminal_event_id,
    )?;
    if raw.metadata_token.as_slice() != expected_metadata_token {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    validate_command_invariants(
        state,
        accepted_at_ms,
        expires_at_ms,
        retain_until_ms,
        started_at_ms,
        terminal_at_ms,
        turn_id,
        started_event_id,
        terminal_event_id,
        raw.terminal_token.as_deref(),
        result.as_deref(),
    )?;
    verify_terminal_integrity(
        connection,
        key_bundle,
        database_id,
        conversation_id,
        command_id,
        state,
        expires_at_ms,
        terminal_at_ms,
        turn_id,
        terminal_event_id,
        raw.terminal_token.as_deref(),
        result.as_deref(),
    )?;
    Ok(CommandRecord {
        conversation_id,
        command_id,
        command_seq,
        configuration_revision,
        owner,
        state,
        accepted_at_ms,
        expires_at_ms,
        retain_until_ms,
        started_at_ms,
        terminal_at_ms,
        turn_id,
        started_event_id,
        terminal_event_id,
        payload: fields[2].to_vec(),
        result,
    })
}

fn load_intent(
    connection: &Connection,
    key_bundle: &super::cipher::RuntimeKeyBundle,
    database_id: [u8; 16],
    command_id: RuntimeId,
) -> Result<ExecutionIntentRecord, RuntimeStoreError> {
    let raw = connection
        .query_row(
            "SELECT turn_id, started_event_id, daemon_boot_id, execution_nonce_token,
                    created_at_ms, sealed_intent
             FROM execution_intents WHERE command_id = ?1",
            [&command_id.as_bytes()[..]],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                ))
            },
        )
        .map_err(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => RuntimeStoreError::UnknownOrCorruptSchema,
            other => RuntimeStoreError::Sqlite(other),
        })?;
    let plaintext = open(
        key_bundle,
        database_id,
        b"execution_intents",
        command_id.as_bytes(),
        b"sealed_intent",
        &raw.5,
        MAX_SEALED_INTENT_BYTES,
    )?;
    let fields = decode_fields(INTENT_MAGIC, plaintext.expose_secret(), 6)?;
    if fields[0].len() != 16
        || fields[1].len() != 16
        || fields[2].len() != 16
        || fields[3].len() != 8
        || fields[4].is_empty()
        || fields[4].len() > MAX_EXECUTION_NONCE_BYTES
        || fields[5].len() > MAX_EXECUTION_INTENT_BYTES
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let turn_id = runtime_id(RuntimeIdKind::Turn, raw.0)?;
    let started_event_id = runtime_id(RuntimeIdKind::Event, raw.1)?;
    let daemon_boot_id = runtime_id(RuntimeIdKind::DaemonBoot, raw.2)?;
    let created_at_ms = runtime_time(raw.4)?;
    if fields[0] != turn_id.as_bytes()
        || fields[1] != started_event_id.as_bytes()
        || fields[2] != daemon_boot_id.as_bytes()
        || fields[3] != created_at_ms.to_be_bytes()
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let nonce_plaintext = Zeroizing::new(canonical_fields(&[
        command_id.as_bytes(),
        daemon_boot_id.as_bytes(),
        fields[4],
    ])?);
    let expected_nonce_token =
        key_bundle.blind_index(b"execution.nonce.v1", nonce_plaintext.as_ref())?;
    if raw.3.as_slice() != expected_nonce_token.as_bytes() {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(ExecutionIntentRecord {
        command_id,
        turn_id,
        started_event_id,
        daemon_boot_id,
        execution_nonce: fields[4].to_vec(),
        created_at_ms,
        payload: fields[5].to_vec(),
    })
}

pub(super) fn load_event(
    connection: &Connection,
    key_bundle: &super::cipher::RuntimeKeyBundle,
    database_id: [u8; 16],
    event_id: RuntimeId,
) -> Result<EventRecord, RuntimeStoreError> {
    let raw = connection
        .query_row(
            "SELECT conversation_id, event_seq, command_id, logical_event_bytes,
                    created_at_ms, metadata_token, sealed_event
             FROM event_journal WHERE event_id = ?1",
            [&event_id.as_bytes()[..]],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<Vec<u8>>>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, Vec<u8>>(6)?,
                ))
            },
        )
        .map_err(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => RuntimeStoreError::UnknownOrCorruptSchema,
            other => RuntimeStoreError::Sqlite(other),
        })?;
    let payload = open(
        key_bundle,
        database_id,
        b"event_journal",
        event_id.as_bytes(),
        b"sealed_event",
        &raw.6,
        MAX_RUNTIME_EVENT_BYTES,
    )?;
    let logical_event_bytes =
        u64::try_from(raw.3).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    if logical_event_bytes
        != u64::try_from(payload.expose_secret().len())
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let conversation_id = runtime_id(RuntimeIdKind::Conversation, raw.0)?;
    let event_seq = decode_sequence(SequenceScope::EventSeq, &raw.1)?;
    let command_id = raw
        .2
        .map(|value| runtime_id(RuntimeIdKind::Command, value))
        .transpose()?;
    let created_at_ms = runtime_time(raw.4)?;
    let expected_metadata_token = event_metadata_token(
        key_bundle,
        conversation_id,
        event_id,
        event_seq,
        command_id,
        logical_event_bytes,
        created_at_ms,
    )?;
    if raw.5.as_slice() != expected_metadata_token {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(EventRecord {
        conversation_id,
        event_id,
        event_seq,
        command_id,
        created_at_ms,
        payload: payload.expose_secret().to_vec(),
    })
}

pub(super) fn load_event_read(
    connection: &Connection,
    read_crypto: &super::cipher::RuntimeReadCryptoCapability,
    database_id: [u8; 16],
    event_id: RuntimeId,
) -> Result<EventRecord, RuntimeStoreError> {
    let raw = connection
        .query_row(
            "SELECT conversation_id, event_seq, command_id, logical_event_bytes,
                    created_at_ms, metadata_token, sealed_event
             FROM event_journal WHERE event_id = ?1",
            [&event_id.as_bytes()[..]],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<Vec<u8>>>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, Vec<u8>>(6)?,
                ))
            },
        )
        .map_err(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => RuntimeStoreError::UnknownOrCorruptSchema,
            other => RuntimeStoreError::Sqlite(other),
        })?;
    let payload = read_crypto.open_bounded(
        &RowAad {
            schema_family: RUNTIME_SCHEMA_FAMILY.as_bytes(),
            schema_version: RUNTIME_CRYPTO_CONTEXT_VERSION,
            database_id: &database_id,
            table: b"event_journal",
            primary_key: event_id.as_bytes(),
            column: b"sealed_event",
        },
        &raw.6,
        MAX_RUNTIME_EVENT_BYTES,
    )?;
    let logical_event_bytes =
        u64::try_from(raw.3).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    if logical_event_bytes
        != u64::try_from(payload.expose_secret().len())
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let conversation_id = runtime_id(RuntimeIdKind::Conversation, raw.0)?;
    let event_seq = decode_sequence(SequenceScope::EventSeq, &raw.1)?;
    let command_id = raw
        .2
        .map(|value| runtime_id(RuntimeIdKind::Command, value))
        .transpose()?;
    let created_at_ms = runtime_time(raw.4)?;
    let event_seq_encoded = super::sequence::encode_sequence(event_seq);
    let command = optional_field(command_id.as_ref().map(|value| &value.as_bytes()[..]));
    let encoded = Zeroizing::new(canonical_fields(&[
        conversation_id.as_bytes(),
        event_id.as_bytes(),
        event_seq_encoded.as_bytes(),
        &command,
        &logical_event_bytes.to_be_bytes(),
        &created_at_ms.to_be_bytes(),
    ])?);
    if !read_crypto.verify_blind_index(b"event.metadata.v1", encoded.as_ref(), &raw.5)? {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(EventRecord {
        conversation_id,
        event_id,
        event_seq,
        command_id,
        created_at_ms,
        payload: payload.expose_secret().to_vec(),
    })
}

fn load_optional_fence(
    connection: &Connection,
    key_bundle: &super::cipher::RuntimeKeyBundle,
    database_id: [u8; 16],
    command_id: RuntimeId,
) -> Result<Option<ExecutionFenceRecord>, RuntimeStoreError> {
    let raw = connection
        .query_row(
            "SELECT daemon_boot_id, execution_nonce_token, process_group_id, leader_pid,
                    leader_start_time, release_authorized_at_ms, release_token, sealed_fence
             FROM execution_fences WHERE command_id = ?1",
            [&command_id.as_bytes()[..]],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Option<i64>>(5)?,
                    row.get::<_, Option<Vec<u8>>>(6)?,
                    row.get::<_, Vec<u8>>(7)?,
                ))
            },
        )
        .optional()?;
    raw.map(|raw| {
        let plaintext = open(
            key_bundle,
            database_id,
            b"execution_fences",
            command_id.as_bytes(),
            b"sealed_fence",
            &raw.7,
            MAX_SEALED_FENCE_BYTES,
        )?;
        let fields = decode_fields(FENCE_MAGIC, plaintext.expose_secret(), 6)?;
        if fields[0].len() != 16
            || fields[1].is_empty()
            || fields[1].len() > MAX_EXECUTION_NONCE_BYTES
            || fields[2].len() != 8
            || fields[3].len() != 8
            || fields[4].len() != 8
            || fields[5].len() > MAX_EXECUTION_FENCE_BYTES
        {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        let daemon_boot_id = runtime_id(RuntimeIdKind::DaemonBoot, raw.0)?;
        let process_group_id = i64::from_be_bytes(
            fields[2]
                .try_into()
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
        );
        let leader_pid = i64::from_be_bytes(
            fields[3]
                .try_into()
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
        );
        let leader_start_time = u64::from_be_bytes(
            fields[4]
                .try_into()
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
        );
        if fields[0] != daemon_boot_id.as_bytes()
            || process_group_id != raw.2
            || leader_pid != raw.3
            || leader_start_time != decode_sequence(SequenceScope::LeaderStartTime, &raw.4)?
        {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        let intent = load_intent(connection, key_bundle, database_id, command_id)?;
        if intent.daemon_boot_id != daemon_boot_id || intent.execution_nonce != fields[1] {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        let nonce_plaintext = Zeroizing::new(canonical_fields(&[
            command_id.as_bytes(),
            daemon_boot_id.as_bytes(),
            fields[1],
        ])?);
        let expected_nonce_token =
            key_bundle.blind_index(b"execution.nonce.v1", nonce_plaintext.as_ref())?;
        if raw.1.as_slice() != expected_nonce_token.as_bytes() {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        let release_authorized_at_ms = raw.5.map(runtime_time).transpose()?;
        match (release_authorized_at_ms, raw.6.as_deref()) {
            (None, None) => {}
            (Some(authorized_at_ms), Some(persisted_token)) => {
                let authorized_at_bytes = authorized_at_ms.to_be_bytes();
                let release_plaintext = Zeroizing::new(canonical_fields(&[
                    command_id.as_bytes(),
                    daemon_boot_id.as_bytes(),
                    fields[1],
                    &authorized_at_bytes,
                ])?);
                let expected_release_token =
                    key_bundle.blind_index(b"execution.release.v1", release_plaintext.as_ref())?;
                if persisted_token != expected_release_token.as_bytes() {
                    return Err(RuntimeStoreError::UnknownOrCorruptSchema);
                }
            }
            _ => return Err(RuntimeStoreError::UnknownOrCorruptSchema),
        }
        Ok(ExecutionFenceRecord {
            command_id,
            daemon_boot_id,
            execution_nonce: fields[1].to_vec(),
            process_group_id,
            leader_pid,
            leader_start_time,
            release_authorized_at_ms,
            payload: fields[5].to_vec(),
        })
    })
    .transpose()
}

pub(super) fn allocate_id(
    transaction: &Transaction<'_>,
    config: &RuntimeStoreConfig,
    kind: RuntimeIdKind,
) -> Result<RuntimeId, RuntimeStoreError> {
    let mut source = config
        .id_source
        .lock()
        .map_err(|_| RuntimeStoreError::WorkerStopped)?;
    for _ in 0..MAX_RUNTIME_ID_COLLISION_ATTEMPTS {
        let candidate = source.next_id(kind)?;
        if candidate.kind() != kind {
            return Err(RuntimeIdError::SourceKindMismatch {
                kind,
                actual: candidate.kind(),
            }
            .into());
        }
        if !id_exists(transaction, candidate)? {
            return Ok(candidate);
        }
    }
    Err(RuntimeIdError::CollisionExhausted {
        kind,
        attempts: MAX_RUNTIME_ID_COLLISION_ATTEMPTS,
    }
    .into())
}

fn id_exists(transaction: &Transaction<'_>, id: RuntimeId) -> Result<bool, RuntimeStoreError> {
    let sql = match id.kind() {
        RuntimeIdKind::Conversation => {
            "SELECT EXISTS(SELECT 1 FROM conversations WHERE conversation_id = ?1)"
        }
        RuntimeIdKind::AdapterState => {
            "SELECT EXISTS(SELECT 1 FROM conversations WHERE adapter_state_key = ?1)"
        }
        RuntimeIdKind::Command => "SELECT EXISTS(SELECT 1 FROM commands WHERE command_id = ?1)",
        RuntimeIdKind::Turn => "SELECT EXISTS(SELECT 1 FROM commands WHERE turn_id = ?1)",
        RuntimeIdKind::Event => "SELECT EXISTS(SELECT 1 FROM event_journal WHERE event_id = ?1)",
        RuntimeIdKind::Approval => {
            "SELECT EXISTS(SELECT 1 FROM approval_ledger WHERE approval_id = ?1)"
        }
        RuntimeIdKind::Database | RuntimeIdKind::DaemonBoot => {
            return Err(RuntimeStoreError::InvalidConfig(
                "this runtime id kind is not allocated by the journal",
            ));
        }
    };
    let exists: i64 = transaction.query_row(sql, [&id.as_bytes()[..]], |row| row.get(0))?;
    Ok(exists != 0)
}

fn seal(
    key_bundle: &super::cipher::RuntimeKeyBundle,
    database_id: [u8; 16],
    table: &[u8],
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
            table,
            primary_key,
            column,
        },
        plaintext,
        maximum_plaintext_len,
    )?)
}

fn open(
    key_bundle: &super::cipher::RuntimeKeyBundle,
    database_id: [u8; 16],
    table: &[u8],
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
            table,
            primary_key,
            column,
        },
        ciphertext,
        maximum_plaintext_len,
    )?)
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

pub(crate) fn canonical_conversation_descriptor(
    descriptor: &ConversationDescriptor,
) -> Result<Zeroizing<Vec<u8>>, RuntimeStoreError> {
    let encoded = serde_json::to_vec(descriptor).map_err(|_| {
        RuntimeStoreError::InvalidConfig(
            "conversation descriptor must serialize as canonical neutral JSON",
        )
    })?;
    validate_payload_len(encoded.len(), MAX_CONVERSATION_DESCRIPTOR_BYTES)?;
    Ok(Zeroizing::new(encoded))
}

fn parse_canonical_conversation_descriptor(
    encoded: &[u8],
) -> Result<ConversationDescriptor, RuntimeStoreError> {
    validate_payload_len(encoded.len(), MAX_CONVERSATION_DESCRIPTOR_BYTES)
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let descriptor: ConversationDescriptor =
        serde_json::from_slice(encoded).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let canonical = Zeroizing::new(
        serde_json::to_vec(&descriptor).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
    );
    if canonical.as_slice() != encoded {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(descriptor)
}

fn canonical_fields(fields: &[&[u8]]) -> Result<Vec<u8>, RuntimeStoreError> {
    encode_fields(b"ADF1", fields)
}

fn metadata_mac(
    key_bundle: &super::cipher::RuntimeKeyBundle,
    domain: &[u8],
    fields: &[&[u8]],
) -> Result<[u8; 32], RuntimeStoreError> {
    let encoded = Zeroizing::new(canonical_fields(fields)?);
    let token = key_bundle.blind_index(domain, encoded.as_ref())?;
    Ok(*token.as_bytes())
}

fn optional_field(value: Option<&[u8]>) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(1 + value.map_or(0, <[u8]>::len));
    match value {
        None => encoded.push(0),
        Some(value) => {
            encoded.push(1);
            encoded.extend_from_slice(value);
        }
    }
    encoded
}

#[allow(clippy::too_many_arguments)]
fn conversation_metadata_token(
    key_bundle: &super::cipher::RuntimeKeyBundle,
    conversation_id: RuntimeId,
    adapter_state_key: RuntimeId,
    catalog_revision: u64,
    command_high_water: Option<u64>,
    event_high_water: Option<u64>,
    accepted_command_count: u32,
    lifecycle: ConversationLifecycle,
    created_at_ms: u64,
    updated_at_ms: u64,
) -> Result<[u8; 32], RuntimeStoreError> {
    let catalog_revision = super::sequence::encode_sequence(catalog_revision);
    let command_high_water = command_high_water.map(super::sequence::encode_sequence);
    let event_high_water = event_high_water.map(super::sequence::encode_sequence);
    let command_high_water = optional_field(command_high_water.as_deref().map(str::as_bytes));
    let event_high_water = optional_field(event_high_water.as_deref().map(str::as_bytes));
    let accepted_command_count = accepted_command_count.to_be_bytes();
    let created_at_ms = created_at_ms.to_be_bytes();
    let updated_at_ms = updated_at_ms.to_be_bytes();
    metadata_mac(
        key_bundle,
        b"conversation.metadata.v1",
        &[
            conversation_id.as_bytes(),
            adapter_state_key.as_bytes(),
            catalog_revision.as_bytes(),
            &command_high_water,
            &event_high_water,
            &accepted_command_count,
            lifecycle_text(lifecycle).as_bytes(),
            &created_at_ms,
            &updated_at_ms,
        ],
    )
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn conversation_metadata_token_for_test(
    key_bundle: &super::cipher::RuntimeKeyBundle,
    conversation_id: RuntimeId,
    adapter_state_key: RuntimeId,
    catalog_revision: u64,
    command_high_water: Option<u64>,
    event_high_water: Option<u64>,
    accepted_command_count: u32,
    lifecycle: ConversationLifecycle,
    created_at_ms: u64,
    updated_at_ms: u64,
) -> Result<[u8; 32], RuntimeStoreError> {
    conversation_metadata_token(
        key_bundle,
        conversation_id,
        adapter_state_key,
        catalog_revision,
        command_high_water,
        event_high_water,
        accepted_command_count,
        lifecycle,
        created_at_ms,
        updated_at_ms,
    )
}

#[allow(clippy::too_many_arguments)]
fn command_metadata_token(
    key_bundle: &super::cipher::RuntimeKeyBundle,
    conversation_id: RuntimeId,
    command_id: RuntimeId,
    command_seq: u64,
    owner_token: &[u8],
    idempotency_token: &[u8],
    payload_token: &[u8],
    terminal_token: Option<&[u8]>,
    state: CommandState,
    logical_payload_bytes: u64,
    accepted_at_ms: u64,
    expires_at_ms: u64,
    retain_until_ms: u64,
    started_at_ms: Option<u64>,
    terminal_at_ms: Option<u64>,
    turn_id: Option<RuntimeId>,
    started_event_id: Option<RuntimeId>,
    terminal_event_id: Option<RuntimeId>,
) -> Result<[u8; 32], RuntimeStoreError> {
    let command_seq = super::sequence::encode_sequence(command_seq);
    let terminal_token = optional_field(terminal_token);
    let logical_payload_bytes = logical_payload_bytes.to_be_bytes();
    let accepted_at_ms = accepted_at_ms.to_be_bytes();
    let expires_at_ms = expires_at_ms.to_be_bytes();
    let retain_until_ms = retain_until_ms.to_be_bytes();
    let started_at_ms = started_at_ms.map(u64::to_be_bytes);
    let terminal_at_ms = terminal_at_ms.map(u64::to_be_bytes);
    let started_at_ms = optional_field(started_at_ms.as_ref().map(|value| &value[..]));
    let terminal_at_ms = optional_field(terminal_at_ms.as_ref().map(|value| &value[..]));
    let turn_id = optional_field(turn_id.as_ref().map(|value| &value.as_bytes()[..]));
    let started_event_id =
        optional_field(started_event_id.as_ref().map(|value| &value.as_bytes()[..]));
    let terminal_event_id = optional_field(
        terminal_event_id
            .as_ref()
            .map(|value| &value.as_bytes()[..]),
    );
    metadata_mac(
        key_bundle,
        b"command.metadata.v1",
        &[
            conversation_id.as_bytes(),
            command_id.as_bytes(),
            command_seq.as_bytes(),
            owner_token,
            idempotency_token,
            payload_token,
            &terminal_token,
            command_state_text(state).as_bytes(),
            &logical_payload_bytes,
            &accepted_at_ms,
            &expires_at_ms,
            &retain_until_ms,
            &started_at_ms,
            &terminal_at_ms,
            &turn_id,
            &started_event_id,
            &terminal_event_id,
        ],
    )
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn command_metadata_token_for_test(
    key_bundle: &super::cipher::RuntimeKeyBundle,
    conversation_id: RuntimeId,
    command_id: RuntimeId,
    command_seq: u64,
    owner_token: &[u8],
    idempotency_token: &[u8],
    payload_token: &[u8],
    terminal_token: Option<&[u8]>,
    state: CommandState,
    logical_payload_bytes: u64,
    accepted_at_ms: u64,
    expires_at_ms: u64,
    retain_until_ms: u64,
    started_at_ms: Option<u64>,
    terminal_at_ms: Option<u64>,
    turn_id: Option<RuntimeId>,
    started_event_id: Option<RuntimeId>,
    terminal_event_id: Option<RuntimeId>,
) -> Result<[u8; 32], RuntimeStoreError> {
    command_metadata_token(
        key_bundle,
        conversation_id,
        command_id,
        command_seq,
        owner_token,
        idempotency_token,
        payload_token,
        terminal_token,
        state,
        logical_payload_bytes,
        accepted_at_ms,
        expires_at_ms,
        retain_until_ms,
        started_at_ms,
        terminal_at_ms,
        turn_id,
        started_event_id,
        terminal_event_id,
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn event_metadata_token(
    key_bundle: &super::cipher::RuntimeKeyBundle,
    conversation_id: RuntimeId,
    event_id: RuntimeId,
    event_seq: u64,
    command_id: Option<RuntimeId>,
    logical_event_bytes: u64,
    created_at_ms: u64,
) -> Result<[u8; 32], RuntimeStoreError> {
    let event_seq = super::sequence::encode_sequence(event_seq);
    let command_id = optional_field(command_id.as_ref().map(|value| &value.as_bytes()[..]));
    let logical_event_bytes = logical_event_bytes.to_be_bytes();
    let created_at_ms = created_at_ms.to_be_bytes();
    metadata_mac(
        key_bundle,
        b"event.metadata.v1",
        &[
            conversation_id.as_bytes(),
            event_id.as_bytes(),
            event_seq.as_bytes(),
            &command_id,
            &logical_event_bytes,
            &created_at_ms,
        ],
    )
}

fn decode_fields<'a>(
    magic: &[u8; 4],
    encoded: &'a [u8],
    count: usize,
) -> Result<Vec<&'a [u8]>, RuntimeStoreError> {
    if encoded.len() < 4 || &encoded[..4] != magic {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let mut cursor: usize = 4;
    let mut fields = Vec::with_capacity(count);
    for _ in 0..count {
        let end = cursor
            .checked_add(4)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        let length_bytes: [u8; 4] = encoded
            .get(cursor..end)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?
            .try_into()
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
        cursor = end;
        let length = usize::try_from(u32::from_be_bytes(length_bytes))
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
        let end = cursor
            .checked_add(length)
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

/// Runtime store 与 Start identity derivation 共用的 owner v1 canonical codec。
///
/// 这是 blind-index、sealed command 与稳定 Start ID 的共同安全边界；禁止在调用点复制
/// 编码规则，否则一次字段/version 漂移会让两条持久化身份路径静默分叉。
pub(super) fn canonical_owner_v1(owner: &IdempotencyOwner) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(96);
    encoded.extend_from_slice(b"ADO1");
    match owner {
        IdempotencyOwner::Local {
            machine_trust_domain,
            uid,
            client_installation_id,
        } => {
            encoded.push(1);
            encoded.extend_from_slice(machine_trust_domain);
            encoded.extend_from_slice(&uid.to_be_bytes());
            encoded.extend_from_slice(client_installation_id);
        }
        IdempotencyOwner::Remote {
            machine_trust_domain,
            device_route,
            device_sign_fingerprint,
        } => {
            encoded.push(2);
            encoded.extend_from_slice(machine_trust_domain);
            encoded.extend_from_slice(device_route);
            encoded.extend_from_slice(device_sign_fingerprint);
        }
    }
    encoded
}

pub(super) fn decode_canonical_owner(
    encoded: &[u8],
) -> Result<IdempotencyOwner, RuntimeStoreError> {
    if encoded.get(..4) != Some(b"ADO1") {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let owner = match encoded.get(4).copied() {
        Some(1) if encoded.len() == 57 => IdempotencyOwner::Local {
            machine_trust_domain: encoded[5..37]
                .try_into()
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            uid: u32::from_be_bytes(
                encoded[37..41]
                    .try_into()
                    .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            ),
            client_installation_id: encoded[41..57]
                .try_into()
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
        },
        Some(2) if encoded.len() == 85 => IdempotencyOwner::Remote {
            machine_trust_domain: encoded[5..37]
                .try_into()
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            device_route: encoded[37..53]
                .try_into()
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            device_sign_fingerprint: encoded[53..85]
                .try_into()
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
        },
        _ => return Err(RuntimeStoreError::UnknownOrCorruptSchema),
    };
    if canonical_owner_v1(&owner) != encoded {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(owner)
}

fn load_command_index_tokens(
    connection: &Connection,
    command_id: RuntimeId,
) -> Result<CommandIndexTokens, RuntimeStoreError> {
    connection
        .query_row(
            "SELECT owner_token, idempotency_token, payload_token, terminal_token,
                    metadata_token
             FROM commands WHERE command_id = ?1",
            [&command_id.as_bytes()[..]],
            |row| {
                Ok(CommandIndexTokens {
                    owner_token: row.get(0)?,
                    idempotency_token: row.get(1)?,
                    payload_token: row.get(2)?,
                    terminal_token: row.get(3)?,
                    metadata_token: row.get(4)?,
                })
            },
        )
        .map_err(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => RuntimeStoreError::CommandNotFound,
            other => RuntimeStoreError::Sqlite(other),
        })
}

fn validate_conversation_catalog(
    connection: &Connection,
    key_bundle: &super::cipher::RuntimeKeyBundle,
    database_id: [u8; 16],
    adapter_state_key: Option<RuntimeId>,
    full_integrity: bool,
) -> Result<ConversationCatalogSummary, RuntimeStoreError> {
    let mut summary = ConversationCatalogSummary::default();
    let sealed_descriptor_column = if full_integrity {
        "sealed_descriptor"
    } else {
        "NULL"
    };
    let sql = format!(
        "SELECT conversation_id, adapter_state_key, catalog_revision,
                command_high_water, event_high_water, lifecycle,
                created_at_ms, updated_at_ms, accepted_count, metadata_token,
                {sealed_descriptor_column}
         FROM conversations"
    );
    let mut statement = connection.prepare(&sql)?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, Vec<u8>>(0)?,
            row.get::<_, Vec<u8>>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, Option<String>>(3)?,
            row.get::<_, Option<String>>(4)?,
            row.get::<_, String>(5)?,
            row.get::<_, i64>(6)?,
            row.get::<_, i64>(7)?,
            row.get::<_, i64>(8)?,
            row.get::<_, Vec<u8>>(9)?,
            row.get::<_, Option<Vec<u8>>>(10)?,
        ))
    })?;
    for row in rows {
        let raw = row?;
        let conversation_id = runtime_id(RuntimeIdKind::Conversation, raw.0)?;
        let persisted_adapter_state_key = runtime_id(RuntimeIdKind::AdapterState, raw.1)?;
        let catalog_revision = decode_sequence(SequenceScope::CatalogRevision, &raw.2)?;
        let command_high_water = raw
            .3
            .as_deref()
            .map(|value| decode_sequence(SequenceScope::CommandSeq, value))
            .transpose()?;
        let event_high_water = raw
            .4
            .as_deref()
            .map(|value| decode_sequence(SequenceScope::EventSeq, value))
            .transpose()?;
        let lifecycle = parse_lifecycle(&raw.5)?;
        let created_at_ms = runtime_time(raw.6)?;
        let updated_at_ms = runtime_time(raw.7)?;
        let accepted_command_count =
            u32::try_from(raw.8).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
        let expected = conversation_metadata_token(
            key_bundle,
            conversation_id,
            persisted_adapter_state_key,
            catalog_revision,
            command_high_water,
            event_high_water,
            accepted_command_count,
            lifecycle,
            created_at_ms,
            updated_at_ms,
        )?;
        if raw.9.as_slice() != expected {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        if full_integrity {
            let descriptor = open(
                key_bundle,
                database_id,
                b"conversations",
                conversation_id.as_bytes(),
                b"sealed_descriptor",
                raw.10
                    .as_deref()
                    .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?,
                MAX_CONVERSATION_DESCRIPTOR_BYTES,
            )?;
            parse_canonical_conversation_descriptor(descriptor.expose_secret())?;
            let actual_command_high_water: Option<String> = connection.query_row(
                "SELECT MAX(command_seq) FROM commands WHERE conversation_id = ?1",
                [&conversation_id.as_bytes()[..]],
                |row| row.get(0),
            )?;
            let actual_event_high_water: Option<String> = connection.query_row(
                "SELECT MAX(event_seq) FROM event_journal WHERE conversation_id = ?1",
                [&conversation_id.as_bytes()[..]],
                |row| row.get(0),
            )?;
            let actual_accepted_count: i64 = connection.query_row(
                "SELECT COUNT(*) FROM commands
                 WHERE conversation_id = ?1 AND state = 'accepted'",
                [&conversation_id.as_bytes()[..]],
                |row| row.get(0),
            )?;
            if actual_command_high_water != command_high_water.map(super::sequence::encode_sequence)
                || actual_event_high_water != event_high_water.map(super::sequence::encode_sequence)
                || u32::try_from(actual_accepted_count)
                    .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
                    != accepted_command_count
            {
                return Err(RuntimeStoreError::UnknownOrCorruptSchema);
            }
        }
        summary.latest_updated_at_ms = Some(
            summary
                .latest_updated_at_ms
                .map_or(updated_at_ms, |latest| latest.max(updated_at_ms)),
        );
        summary.max_catalog_revision = Some(
            summary
                .max_catalog_revision
                .map_or(catalog_revision, |current| current.max(catalog_revision)),
        );
        summary.conversation_count = summary
            .conversation_count
            .checked_add(1)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        summary.accepted_count = summary
            .accepted_count
            .checked_add(u64::from(accepted_command_count))
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        if adapter_state_key == Some(persisted_adapter_state_key) {
            summary.adapter_owner = Some(conversation_id);
        }
    }
    Ok(summary)
}

pub(crate) fn validate_all_command_metadata(
    connection: &Connection,
    key_bundle: &super::cipher::RuntimeKeyBundle,
    _database_id: [u8; 16],
) -> Result<CommandLedgerSummary, RuntimeStoreError> {
    let mut summary = CommandLedgerSummary::default();
    let mut statement = connection.prepare(
        "SELECT conversation_id, command_seq, command_id, owner_token,
                idempotency_token, payload_token, terminal_token, turn_id,
                started_event_id, terminal_event_id, state, logical_payload_bytes,
                accepted_at_ms, expires_at_ms, retain_until_ms, started_at_ms,
                terminal_at_ms, metadata_token, sealed_result IS NOT NULL
         FROM commands",
    )?;
    let rows = statement.query_map([], |row| {
        Ok(RawCommandMetadata {
            conversation_id: row.get(0)?,
            command_seq: row.get(1)?,
            command_id: row.get(2)?,
            owner_token: row.get(3)?,
            idempotency_token: row.get(4)?,
            payload_token: row.get(5)?,
            terminal_token: row.get(6)?,
            turn_id: row.get(7)?,
            started_event_id: row.get(8)?,
            terminal_event_id: row.get(9)?,
            state: row.get(10)?,
            logical_payload_bytes: row.get(11)?,
            accepted_at_ms: row.get(12)?,
            expires_at_ms: row.get(13)?,
            retain_until_ms: row.get(14)?,
            started_at_ms: row.get(15)?,
            terminal_at_ms: row.get(16)?,
            metadata_token: row.get(17)?,
            sealed_result_present: row.get(18)?,
        })
    })?;
    for row in rows {
        let (state, logical_payload_bytes) = validate_command_metadata_row(key_bundle, &row?)?;
        summary.total_count = summary
            .total_count
            .checked_add(1)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        match state {
            CommandState::Accepted => {
                summary.accepted_count = summary
                    .accepted_count
                    .checked_add(1)
                    .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
                summary.accepted_payload_bytes = summary
                    .accepted_payload_bytes
                    .checked_add(logical_payload_bytes)
                    .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
            }
            CommandState::Started => {
                summary.started_count = summary
                    .started_count
                    .checked_add(1)
                    .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
            }
            _ => {}
        }
    }
    Ok(summary)
}

fn validate_command_metadata_row(
    key_bundle: &super::cipher::RuntimeKeyBundle,
    raw: &RawCommandMetadata,
) -> Result<(CommandState, u64), RuntimeStoreError> {
    let conversation_id = runtime_id(RuntimeIdKind::Conversation, raw.conversation_id.clone())?;
    let command_id = runtime_id(RuntimeIdKind::Command, raw.command_id.clone())?;
    let command_seq = decode_sequence(SequenceScope::CommandSeq, &raw.command_seq)?;
    let state = parse_command_state(&raw.state)?;
    let logical_payload_bytes = u64::try_from(raw.logical_payload_bytes)
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let accepted_at_ms = runtime_time(raw.accepted_at_ms)?;
    let expires_at_ms = runtime_time(raw.expires_at_ms)?;
    let retain_until_ms = runtime_time(raw.retain_until_ms)?;
    let started_at_ms = raw.started_at_ms.map(runtime_time).transpose()?;
    let terminal_at_ms = raw.terminal_at_ms.map(runtime_time).transpose()?;
    let turn_id = raw
        .turn_id
        .as_ref()
        .map(|value| runtime_id(RuntimeIdKind::Turn, value.clone()))
        .transpose()?;
    let started_event_id = raw
        .started_event_id
        .as_ref()
        .map(|value| runtime_id(RuntimeIdKind::Event, value.clone()))
        .transpose()?;
    let terminal_event_id = raw
        .terminal_event_id
        .as_ref()
        .map(|value| runtime_id(RuntimeIdKind::Event, value.clone()))
        .transpose()?;
    let result_marker = raw.sealed_result_present.then_some(&[][..]);
    validate_command_invariants(
        state,
        accepted_at_ms,
        expires_at_ms,
        retain_until_ms,
        started_at_ms,
        terminal_at_ms,
        turn_id,
        started_event_id,
        terminal_event_id,
        raw.terminal_token.as_deref(),
        result_marker,
    )?;
    let expected = command_metadata_token(
        key_bundle,
        conversation_id,
        command_id,
        command_seq,
        &raw.owner_token,
        &raw.idempotency_token,
        &raw.payload_token,
        raw.terminal_token.as_deref(),
        state,
        logical_payload_bytes,
        accepted_at_ms,
        expires_at_ms,
        retain_until_ms,
        started_at_ms,
        terminal_at_ms,
        turn_id,
        started_event_id,
        terminal_event_id,
    )?;
    if raw.metadata_token.as_slice() != expected {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok((state, logical_payload_bytes))
}

fn validate_all_event_metadata(
    connection: &Connection,
    key_bundle: &super::cipher::RuntimeKeyBundle,
) -> Result<(), RuntimeStoreError> {
    let mut statement = connection.prepare(
        "SELECT conversation_id, event_seq, event_id, command_id,
                logical_event_bytes, created_at_ms, metadata_token
         FROM event_journal",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, Vec<u8>>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, Vec<u8>>(2)?,
            row.get::<_, Option<Vec<u8>>>(3)?,
            row.get::<_, i64>(4)?,
            row.get::<_, i64>(5)?,
            row.get::<_, Vec<u8>>(6)?,
        ))
    })?;
    for row in rows {
        let raw = row?;
        let conversation_id = runtime_id(RuntimeIdKind::Conversation, raw.0)?;
        let event_seq = decode_sequence(SequenceScope::EventSeq, &raw.1)?;
        let event_id = runtime_id(RuntimeIdKind::Event, raw.2)?;
        let command_id = raw
            .3
            .map(|value| runtime_id(RuntimeIdKind::Command, value))
            .transpose()?;
        let logical_event_bytes =
            u64::try_from(raw.4).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
        let created_at_ms = runtime_time(raw.5)?;
        let expected = event_metadata_token(
            key_bundle,
            conversation_id,
            event_id,
            event_seq,
            command_id,
            logical_event_bytes,
            created_at_ms,
        )?;
        if raw.6.as_slice() != expected {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
    }
    Ok(())
}

/// 动态审计真实 authenticated event rows，而不是从 command state 固定推导每条命令
/// 必须恰有一或两条事件。这样 Item/Error/approval 事件可以增长，同时 orphan、gap、
/// 错 command/turn 与 pointer body 漂移仍然 fail-close。
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct DynamicEventIntegritySummary {
    event_count: u64,
    approval_event_count: u64,
    configuration_event_count: u64,
}

fn validate_dynamic_event_ledger(
    connection: &Connection,
    key_bundle: &super::cipher::RuntimeKeyBundle,
    database_id: [u8; 16],
) -> Result<DynamicEventIntegritySummary, RuntimeStoreError> {
    let mut statement = connection.prepare(
        "SELECT conversation_id, event_seq, event_id
         FROM event_journal
         ORDER BY conversation_id, event_seq",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, Vec<u8>>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, Vec<u8>>(2)?,
        ))
    })?;
    let mut current_conversation = None;
    let mut next_event_seq = 0_u64;
    let mut last_created_at_ms = None;
    let mut summary = DynamicEventIntegritySummary::default();
    for row in rows {
        let (conversation, encoded_seq, event) = row?;
        let conversation_id = runtime_id(RuntimeIdKind::Conversation, conversation)?;
        let event_seq = decode_sequence(SequenceScope::EventSeq, &encoded_seq)?;
        let event_id = runtime_id(RuntimeIdKind::Event, event)?;
        if current_conversation != Some(conversation_id) {
            current_conversation = Some(conversation_id);
            next_event_seq = 0;
            last_created_at_ms = None;
        }
        if event_seq != next_event_seq {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        next_event_seq = next_event_seq
            .checked_add(1)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        summary.event_count = summary
            .event_count
            .checked_add(1)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;

        let event = load_event(connection, key_bundle, database_id, event_id)?;
        if last_created_at_ms.is_some_and(|previous| event.created_at_ms < previous) {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        last_created_at_ms = Some(event.created_at_ms);
        if event.conversation_id != conversation_id || event.event_seq != event_seq {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        let Some(command_id) = event.command_id else {
            let PersistedRuntimeEvent::Canonical(decoded) = decode_persisted_runtime_event(&event)?
            else {
                return Err(RuntimeStoreError::UnknownOrCorruptSchema);
            };
            if !matches!(
                decoded.body,
                agentdeck_protocol::runtime::RuntimeEventBody::ConfigurationChanged { .. }
            ) || !super::configuration::configuration_row_exists_for_event(
                connection,
                conversation_id,
                &encoded_seq,
            )? {
                return Err(RuntimeStoreError::UnknownOrCorruptSchema);
            }
            summary.configuration_event_count = summary
                .configuration_event_count
                .checked_add(1)
                .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
            continue;
        };
        let command = load_command(connection, key_bundle, database_id, command_id)?;
        if command.conversation_id != conversation_id {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }

        if command.started_event_id == Some(event_id) {
            let intent = load_intent(connection, key_bundle, database_id, command_id)?;
            validate_started_linkage(&command, &intent, &event)?;
            match decode_persisted_runtime_event(&event)? {
                PersistedRuntimeEvent::Canonical(decoded) => match decoded.body {
                    agentdeck_protocol::runtime::RuntimeEventBody::TurnStarted { turn_id }
                        if turn_id.as_str() == intent.turn_id.to_canonical_string() => {}
                    _ => return Err(RuntimeStoreError::UnknownOrCorruptSchema),
                },
                // v1 允许 authenticated noncanonical Started payload；migration/readback
                // 不改写旧 ciphertext。所有当前 writer 只会产生 canonical TurnStarted。
                PersistedRuntimeEvent::NonCanonical => {}
            }
            continue;
        }

        if command.terminal_event_id == Some(event_id) {
            if let Some(turn_id) = command.turn_id {
                let intent = load_intent(connection, key_bundle, database_id, command_id)?;
                let started =
                    load_event(connection, key_bundle, database_id, intent.started_event_id)?;
                if turn_id != intent.turn_id || event_seq <= started.event_seq {
                    return Err(RuntimeStoreError::UnknownOrCorruptSchema);
                }
            }
            // load_command 已对 accepted/expired/started terminal 的 fixed body、state、
            // turn、origin、result 与 terminal token 做逐字节验证。
            continue;
        }

        let turn_id = command
            .turn_id
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        let intent = load_intent(connection, key_bundle, database_id, command_id)?;
        let started = load_event(connection, key_bundle, database_id, intent.started_event_id)?;
        if intent.turn_id != turn_id
            || event_seq <= started.event_seq
            || event.created_at_ms < intent.created_at_ms
        {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        if let Some(terminal_event_id) = command.terminal_event_id {
            let terminal = load_event(connection, key_bundle, database_id, terminal_event_id)?;
            if event_seq >= terminal.event_seq || event.created_at_ms > terminal.created_at_ms {
                return Err(RuntimeStoreError::UnknownOrCorruptSchema);
            }
        } else if command.state != CommandState::Started {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }

        let PersistedRuntimeEvent::Canonical(decoded) = decode_persisted_runtime_event(&event)?
        else {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        };
        require_execution_released_at(
            connection,
            key_bundle,
            database_id,
            command_id,
            event.created_at_ms,
        )
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
        if matches!(
            &decoded.body,
            agentdeck_protocol::runtime::RuntimeEventBody::ActionRequest { .. }
                | agentdeck_protocol::runtime::RuntimeEventBody::ApprovalResolved { .. }
        ) {
            summary.approval_event_count = summary
                .approval_event_count
                .checked_add(1)
                .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        }
        match decoded.body {
            agentdeck_protocol::runtime::RuntimeEventBody::Item { item } => {
                let item_id = decoded
                    .item_id
                    .as_ref()
                    .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
                let entity_id = decoded
                    .entity_id
                    .as_ref()
                    .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
                super::execution_event::validate_durable_item(item_id, entity_id, &item)
                    .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
            }
            agentdeck_protocol::runtime::RuntimeEventBody::Error { failure }
                if failure.code
                    == agentdeck_protocol::runtime::failure::DAEMON_RUNTIME_EXECUTION_FAILED
                    && failure.message == "agent execution failed"
                    && failure.diagnostic_ref.is_none() => {}
            agentdeck_protocol::runtime::RuntimeEventBody::ActionRequest {
                turn_id: event_turn,
                ..
            }
            | agentdeck_protocol::runtime::RuntimeEventBody::ApprovalResolved {
                turn_id: event_turn,
                ..
            } if event_turn.as_str() == turn_id.to_canonical_string() => {}
            _ => return Err(RuntimeStoreError::UnknownOrCorruptSchema),
        }
    }
    Ok(summary)
}

pub(crate) fn validate_store_integrity(
    connection: &Connection,
    key_bundle: &super::cipher::RuntimeKeyBundle,
    database_id: [u8; 16],
) -> Result<(), RuntimeStoreError> {
    let ledger = sqlite::load_runtime_ledger(connection, key_bundle, database_id)?;
    validate_store_integrity_against_ledger(connection, key_bundle, database_id, &ledger, true)
}

pub(crate) fn validate_store_integrity_v1(
    connection: &Connection,
    key_bundle: &super::cipher::RuntimeKeyBundle,
    database_id: [u8; 16],
    ledger: &sqlite::RuntimeLedger,
) -> Result<(), RuntimeStoreError> {
    validate_store_integrity_against_ledger(connection, key_bundle, database_id, ledger, false)
}

fn validate_store_integrity_against_ledger(
    connection: &Connection,
    key_bundle: &super::cipher::RuntimeKeyBundle,
    database_id: [u8; 16],
    ledger: &sqlite::RuntimeLedger,
    validate_adapter_state: bool,
) -> Result<(), RuntimeStoreError> {
    let catalog = validate_conversation_catalog(connection, key_bundle, database_id, None, true)?;
    let commands = validate_all_command_metadata(connection, key_bundle, database_id)?;
    validate_all_event_metadata(connection, key_bundle)?;
    // v1/v2 migration 前 `approval_ledger` 尚不存在；approval validator 对缺表返回
    // 严格零摘要，避免在旧 schema authentication 阶段误查 v3 表。
    let approvals =
        super::approval::validate_all_approval_metadata(connection, key_bundle, database_id)?;
    let authenticated_configuration_count =
        super::configuration::validate_v5_integrity(connection, key_bundle, database_id, ledger)?;
    let mut started_without_fence_count = 0_u64;
    let mut started_without_release_count = 0_u64;
    let mut started_released_count = 0_u64;
    let mut expected_intent_count = 0_u64;
    let mut expected_fence_count = 0_u64;
    let mut statement = connection.prepare("SELECT command_id FROM commands")?;
    let rows = statement.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
    for row in rows {
        let command_id = runtime_id(RuntimeIdKind::Command, row?)?;
        let command = load_command(connection, key_bundle, database_id, command_id)?;
        match command.state {
            CommandState::Accepted => {}
            CommandState::Started => {
                expected_intent_count += 1;
                let intent = load_intent(connection, key_bundle, database_id, command_id)?;
                let event =
                    load_event(connection, key_bundle, database_id, intent.started_event_id)?;
                validate_started_linkage(&command, &intent, &event)?;
                match load_optional_fence(connection, key_bundle, database_id, command_id)? {
                    None => {
                        started_without_fence_count = started_without_fence_count
                            .checked_add(1)
                            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
                    }
                    Some(fence) if fence.release_authorized_at_ms.is_none() => {
                        expected_fence_count += 1;
                        started_without_release_count = started_without_release_count
                            .checked_add(1)
                            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
                    }
                    Some(fence) => {
                        validate_release_time_window(&fence, &event, None)?;
                        expected_fence_count += 1;
                        started_released_count = started_released_count
                            .checked_add(1)
                            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
                    }
                }
            }
            CommandState::Completed | CommandState::Failed => {
                expected_intent_count += 1;
                expected_fence_count += 1;
                let intent = load_intent(connection, key_bundle, database_id, command_id)?;
                let started_event =
                    load_event(connection, key_bundle, database_id, intent.started_event_id)?;
                let terminal_event = load_event(
                    connection,
                    key_bundle,
                    database_id,
                    command
                        .terminal_event_id
                        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?,
                )?;
                validate_started_terminal_linkage(
                    &command,
                    &intent,
                    &started_event,
                    &terminal_event,
                )?;
                let fence = load_optional_fence(connection, key_bundle, database_id, command_id)?
                    .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
                if fence.release_authorized_at_ms.is_none() {
                    return Err(RuntimeStoreError::UnknownOrCorruptSchema);
                }
                validate_release_time_window(&fence, &started_event, Some(&terminal_event))?;
            }
            CommandState::Interrupted | CommandState::Canceled => {
                if command.turn_id.is_some() {
                    expected_intent_count += 1;
                    let intent = load_intent(connection, key_bundle, database_id, command_id)?;
                    let started_event =
                        load_event(connection, key_bundle, database_id, intent.started_event_id)?;
                    let terminal_event = load_event(
                        connection,
                        key_bundle,
                        database_id,
                        command
                            .terminal_event_id
                            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?,
                    )?;
                    validate_started_terminal_linkage(
                        &command,
                        &intent,
                        &started_event,
                        &terminal_event,
                    )?;
                    if let Some(fence) =
                        load_optional_fence(connection, key_bundle, database_id, command_id)?
                    {
                        validate_release_time_window(
                            &fence,
                            &started_event,
                            Some(&terminal_event),
                        )?;
                        expected_fence_count += 1;
                    }
                }
            }
            CommandState::Expired | CommandState::RevokedBeforeStart => {}
        }
    }
    let authenticated_events = validate_dynamic_event_ledger(connection, key_bundle, database_id)?;
    if authenticated_events.approval_event_count != approvals.approval_event_count
        || authenticated_events.configuration_event_count != authenticated_configuration_count
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let (actual_intent_count, actual_fence_count, actual_event_count): (i64, i64, i64) = connection
        .query_row(
            "SELECT
                 (SELECT COUNT(*) FROM execution_intents),
                 (SELECT COUNT(*) FROM execution_fences),
                 (SELECT COUNT(*) FROM event_journal)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
    if u64::try_from(actual_intent_count).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
        != expected_intent_count
        || u64::try_from(actual_fence_count)
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
            != expected_fence_count
        || u64::try_from(actual_event_count)
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
            != authenticated_events.event_count
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let expected_catalog_high_water = catalog
        .max_catalog_revision
        .map(super::sequence::encode_sequence);
    if ledger.catalog_high_water != expected_catalog_high_water
        || ledger.conversation_count != catalog.conversation_count
        || ledger.command_count != commands.total_count
        || ledger.intent_count
            != u64::try_from(actual_intent_count)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
        || ledger.fence_count
            != u64::try_from(actual_fence_count)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
        || ledger.event_count
            != u64::try_from(actual_event_count)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
        || ledger.approval_count != approvals.approval_count
        || ledger.active_approval_count != approvals.active_approval_count
        || ledger.accepted_count != catalog.accepted_count
        || ledger.accepted_count != commands.accepted_count
        || ledger.accepted_payload_bytes != commands.accepted_payload_bytes
        || commands.started_count
            != started_without_fence_count + started_without_release_count + started_released_count
        || ledger.started_without_fence_count != started_without_fence_count
        || ledger.started_without_release_count != started_without_release_count
        || ledger.started_released_count != started_released_count
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    if validate_adapter_state {
        validate_adapter_state_integrity(connection, key_bundle, database_id, ledger)?;
    } else if ledger.codex_adapter_state_count != 0 || ledger.claude_code_adapter_state_count != 0 {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    super::stream::validate_v4_integrity(connection, key_bundle, database_id, ledger)?;
    Ok(())
}

fn validate_release_time_window(
    fence: &ExecutionFenceRecord,
    started_event: &EventRecord,
    terminal_event: Option<&EventRecord>,
) -> Result<(), RuntimeStoreError> {
    let Some(release_authorized_at_ms) = fence.release_authorized_at_ms else {
        return Ok(());
    };
    if release_authorized_at_ms < started_event.created_at_ms
        || terminal_event.is_some_and(|terminal| release_authorized_at_ms > terminal.created_at_ms)
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(())
}

fn validate_adapter_state_integrity(
    connection: &Connection,
    key_bundle: &super::cipher::RuntimeKeyBundle,
    database_id: [u8; 16],
    ledger: &sqlite::RuntimeLedger,
) -> Result<(), RuntimeStoreError> {
    let mut counts = [0_u64; 2];
    for (index, namespace) in [
        AdapterStateNamespace::Codex,
        AdapterStateNamespace::ClaudeCode,
    ]
    .into_iter()
    .enumerate()
    {
        let sql = match namespace {
            AdapterStateNamespace::Codex => {
                "SELECT conversation_id FROM codex_adapter_state ORDER BY conversation_id"
            }
            AdapterStateNamespace::ClaudeCode => {
                "SELECT conversation_id FROM claude_code_adapter_state ORDER BY conversation_id"
            }
        };
        let mut statement = connection.prepare(sql)?;
        let rows = statement.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
        for row in rows {
            let conversation_id = runtime_id(RuntimeIdKind::Conversation, row?)?;
            let conversation =
                load_conversation(connection, key_bundle, database_id, conversation_id)?;
            if conversation.descriptor.agent_kind != namespace.agent_kind() {
                return Err(RuntimeStoreError::UnknownOrCorruptSchema);
            }
            load_adapter_state_binding_for_conversation(
                connection,
                key_bundle,
                database_id,
                namespace,
                &conversation,
            )?
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
            counts[index] = counts[index]
                .checked_add(1)
                .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        }
    }
    let cross_namespace_rows: i64 = connection.query_row(
        "SELECT COUNT(*)
         FROM codex_adapter_state AS codex
         JOIN claude_code_adapter_state AS claude
           ON codex.conversation_id = claude.conversation_id
           OR codex.state_key_token = claude.state_key_token",
        [],
        |row| row.get(0),
    )?;
    if cross_namespace_rows != 0
        || counts[0] != ledger.codex_adapter_state_count
        || counts[1] != ledger.claude_code_adapter_state_count
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(())
}

fn load_new_command_queue_state(
    connection: &Connection,
    key_bundle: &super::cipher::RuntimeKeyBundle,
    database_id: [u8; 16],
    conversation_id: RuntimeId,
    new_payload_bytes: usize,
) -> Result<(ConversationRecord, sqlite::RuntimeLedger, QueueAdmission), RuntimeStoreError> {
    let conversation = load_conversation(connection, key_bundle, database_id, conversation_id)?;
    if conversation.lifecycle != ConversationLifecycle::Active {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }
    let ledger = sqlite::load_runtime_ledger(connection, key_bundle, database_id)?;
    let (global_count, global_payload): (i64, i64) = connection.query_row(
        "SELECT COUNT(*), COALESCE(SUM(logical_payload_bytes), 0)
         FROM commands WHERE state = 'accepted'",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let conversation_count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM commands WHERE conversation_id = ?1 AND state = 'accepted'",
        [&conversation_id.as_bytes()[..]],
        |row| row.get(0),
    )?;
    let global_count =
        u64::try_from(global_count).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let global_payload =
        u64::try_from(global_payload).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let conversation_count =
        u32::try_from(conversation_count).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    if global_count != ledger.accepted_count
        || global_payload != ledger.accepted_payload_bytes
        || conversation_count != conversation.accepted_command_count
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let queue = evaluate_queue_admission(
        conversation_count,
        u32::try_from(global_count).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
        global_payload,
        u64::try_from(new_payload_bytes).map_err(|_| RuntimeStoreError::PayloadTooLarge)?,
    )
    .map_err(|scope| RuntimeStoreError::QueueFull { scope })?;
    Ok((conversation, ledger, queue))
}

fn authenticated_queue_head(
    connection: &Connection,
    key_bundle: &super::cipher::RuntimeKeyBundle,
    database_id: [u8; 16],
    conversation_id: RuntimeId,
) -> Result<RuntimeId, RuntimeStoreError> {
    let conversation = load_conversation(connection, key_bundle, database_id, conversation_id)?;
    let mut ids = Vec::new();
    let mut statement = connection.prepare(
        "SELECT command_id FROM commands
         WHERE conversation_id = ?1 AND state = 'accepted'",
    )?;
    for row in statement.query_map([&conversation_id.as_bytes()[..]], |row| {
        row.get::<_, Vec<u8>>(0)
    })? {
        ids.push(runtime_id(RuntimeIdKind::Command, row?)?);
    }
    if ids.len()
        != usize::try_from(conversation.accepted_command_count)
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let mut commands = ids
        .into_iter()
        .map(|id| load_command(connection, key_bundle, database_id, id))
        .collect::<Result<Vec<_>, _>>()?;
    commands.sort_by_key(|command| command.command_seq);
    commands
        .first()
        .map(|command| command.command_id)
        .ok_or(RuntimeStoreError::InvalidStateTransition)
}

fn authenticated_started_command(
    connection: &Connection,
    key_bundle: &super::cipher::RuntimeKeyBundle,
    database_id: [u8; 16],
    conversation_id: RuntimeId,
) -> Result<Option<RuntimeId>, RuntimeStoreError> {
    let mut ids = Vec::new();
    let mut statement = connection.prepare(
        "SELECT command_id FROM commands
         WHERE conversation_id = ?1 AND state = 'started' LIMIT 2",
    )?;
    for row in statement.query_map([&conversation_id.as_bytes()[..]], |row| {
        row.get::<_, Vec<u8>>(0)
    })? {
        ids.push(runtime_id(RuntimeIdKind::Command, row?)?);
    }
    if ids.len() > 1 {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let Some(command_id) = ids.into_iter().next() else {
        return Ok(None);
    };
    let command = load_command(connection, key_bundle, database_id, command_id)?;
    if command.conversation_id != conversation_id || command.state != CommandState::Started {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(Some(command_id))
}

#[derive(Clone, Copy)]
enum ConversationQueueDelta {
    Unchanged,
    Increment,
    Decrement,
}

#[allow(clippy::too_many_arguments)]
fn update_conversation_high_water(
    transaction: &Transaction<'_>,
    conversation_id: RuntimeId,
    column: &'static str,
    next: &str,
    previous: Option<&str>,
    updated_at_ms: i64,
    key_bundle: &super::cipher::RuntimeKeyBundle,
    database_id: [u8; 16],
    queue_delta: ConversationQueueDelta,
) -> Result<(), RuntimeStoreError> {
    let current = load_conversation(transaction, key_bundle, database_id, conversation_id)?;
    let current_previous = match column {
        "command_high_water" => current
            .command_high_water
            .map(super::sequence::encode_sequence),
        "event_high_water" => current
            .event_high_water
            .map(super::sequence::encode_sequence),
        _ => {
            return Err(RuntimeStoreError::InvalidConfig(
                "unsupported conversation high-water column",
            ));
        }
    };
    if current_previous.as_deref() != previous {
        return Err(RuntimeStoreError::SchemaInspectionRaced);
    }
    let mut command_high_water = current.command_high_water;
    let mut event_high_water = current.event_high_water;
    match column {
        "command_high_water" => {
            command_high_water = Some(decode_sequence(SequenceScope::CommandSeq, next)?);
        }
        "event_high_water" => {
            event_high_water = Some(decode_sequence(SequenceScope::EventSeq, next)?);
        }
        _ => unreachable!("column checked above"),
    }
    let accepted_command_count = match queue_delta {
        ConversationQueueDelta::Unchanged => current.accepted_command_count,
        ConversationQueueDelta::Increment => current
            .accepted_command_count
            .checked_add(1)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?,
        ConversationQueueDelta::Decrement => current
            .accepted_command_count
            .checked_sub(1)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?,
    };
    let updated_at_ms = runtime_time(updated_at_ms)?.max(current.updated_at_ms);
    let old_token = conversation_metadata_token(
        key_bundle,
        current.conversation_id,
        current.adapter_state_key,
        current.catalog_revision,
        current.command_high_water,
        current.event_high_water,
        current.accepted_command_count,
        current.lifecycle,
        current.created_at_ms,
        current.updated_at_ms,
    )?;
    let new_token = conversation_metadata_token(
        key_bundle,
        current.conversation_id,
        current.adapter_state_key,
        current.catalog_revision,
        command_high_water,
        event_high_water,
        accepted_command_count,
        current.lifecycle,
        current.created_at_ms,
        updated_at_ms,
    )?;
    let sql = match column {
        "command_high_water" => {
            "UPDATE conversations
             SET command_high_water = ?1, updated_at_ms = ?2, accepted_count = ?3,
                 metadata_token = ?4
             WHERE conversation_id = ?5
               AND ((?6 IS NULL AND command_high_water IS NULL) OR command_high_water = ?6)
               AND metadata_token = ?7"
        }
        "event_high_water" => {
            "UPDATE conversations
             SET event_high_water = ?1, updated_at_ms = ?2, accepted_count = ?3,
                 metadata_token = ?4
             WHERE conversation_id = ?5
               AND ((?6 IS NULL AND event_high_water IS NULL) OR event_high_water = ?6)
               AND metadata_token = ?7"
        }
        _ => {
            return Err(RuntimeStoreError::InvalidConfig(
                "unsupported conversation high-water column",
            ));
        }
    };
    if transaction.execute(
        sql,
        params![
            next,
            sqlite_time(updated_at_ms)?,
            i64::from(accepted_command_count),
            &new_token[..],
            &conversation_id.as_bytes()[..],
            previous,
            &old_token[..],
        ],
    )? != 1
    {
        return Err(RuntimeStoreError::SchemaInspectionRaced);
    }
    Ok(())
}

/// ConfigureConversation 只推进 conversation event HWM；它不改变 catalog-visible
/// `updated_at_ms`、queue count 或 descriptor/lifecycle。独立窄入口防止配置写入误用
/// 普通 command/event helper 后制造没有 CatalogDelta 的 last-active 漂移。
pub(super) fn update_conversation_event_high_water_preserving_activity(
    transaction: &Transaction<'_>,
    conversation_id: RuntimeId,
    next: &str,
    previous: Option<&str>,
    key_bundle: &super::cipher::RuntimeKeyBundle,
    database_id: [u8; 16],
) -> Result<(), RuntimeStoreError> {
    let current = load_conversation(transaction, key_bundle, database_id, conversation_id)?;
    let current_previous = current
        .event_high_water
        .map(super::sequence::encode_sequence);
    if current_previous.as_deref() != previous {
        return Err(RuntimeStoreError::SchemaInspectionRaced);
    }
    let next_value = decode_sequence(SequenceScope::EventSeq, next)?;
    let old_token = conversation_metadata_token(
        key_bundle,
        current.conversation_id,
        current.adapter_state_key,
        current.catalog_revision,
        current.command_high_water,
        current.event_high_water,
        current.accepted_command_count,
        current.lifecycle,
        current.created_at_ms,
        current.updated_at_ms,
    )?;
    let new_token = conversation_metadata_token(
        key_bundle,
        current.conversation_id,
        current.adapter_state_key,
        current.catalog_revision,
        current.command_high_water,
        Some(next_value),
        current.accepted_command_count,
        current.lifecycle,
        current.created_at_ms,
        current.updated_at_ms,
    )?;
    if transaction.execute(
        "UPDATE conversations
         SET event_high_water = ?1, metadata_token = ?2
         WHERE conversation_id = ?3
           AND ((?4 IS NULL AND event_high_water IS NULL) OR event_high_water = ?4)
           AND metadata_token = ?5",
        params![
            next,
            &new_token[..],
            &conversation_id.as_bytes()[..],
            previous,
            &old_token[..],
        ],
    )? != 1
    {
        return Err(RuntimeStoreError::SchemaInspectionRaced);
    }
    Ok(())
}

fn commit_transaction(
    transaction: Transaction<'_>,
    operation: RuntimeCommitOperation,
) -> Result<(), RuntimeStoreError> {
    sqlite::commit_transaction(transaction, operation)
}

fn commit_transaction_with_effects(
    transaction: Transaction<'_>,
    operation: RuntimeCommitOperation,
    pending_targets: PendingStreamTargets,
    effects: &mut CommandStreamEffects,
) -> Result<(), RuntimeStoreError> {
    let result = sqlite::commit_transaction(transaction, operation);
    effects.record_commit_result(pending_targets, &result);
    result
}

fn after_commit(
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

fn ensure_kind(id: RuntimeId, expected: RuntimeIdKind) -> Result<(), RuntimeStoreError> {
    if id.kind() == expected {
        Ok(())
    } else {
        Err(RuntimeStoreError::IdKindMismatch {
            expected,
            actual: id.kind(),
        })
    }
}

fn runtime_id(kind: RuntimeIdKind, value: Vec<u8>) -> Result<RuntimeId, RuntimeStoreError> {
    let bytes: [u8; 16] = value
        .try_into()
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    Ok(RuntimeId::from_bytes(kind, bytes)?)
}

fn sqlite_time(value: u64) -> Result<i64, RuntimeStoreError> {
    i64::try_from(value).map_err(|_| RuntimeStoreError::TimeOutOfRange)
}

fn runtime_time(value: i64) -> Result<u64, RuntimeStoreError> {
    u64::try_from(value).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)
}

fn validate_payload_len(actual: usize, maximum: usize) -> Result<(), RuntimeStoreError> {
    if actual > maximum {
        Err(RuntimeStoreError::PayloadTooLarge)
    } else {
        Ok(())
    }
}

pub(super) fn projected_write_bytes(lengths: &[usize]) -> Result<u64, RuntimeStoreError> {
    lengths
        .iter()
        .try_fold(RUNTIME_WRITE_FIXED_OVERHEAD_BYTES, |projected, length| {
            let length = u64::try_from(*length).map_err(|_| {
                RuntimeStoreError::CapacityArithmeticOverflow {
                    field: "projected_write_bytes",
                }
            })?;
            projected
                .checked_add(length)
                .ok_or(RuntimeStoreError::CapacityArithmeticOverflow {
                    field: "projected_write_bytes",
                })
        })
}

fn parse_lifecycle(value: &str) -> Result<ConversationLifecycle, RuntimeStoreError> {
    match value {
        "active" => Ok(ConversationLifecycle::Active),
        "archived" => Ok(ConversationLifecycle::Archived),
        "recoveryBlocked" => Ok(ConversationLifecycle::RecoveryBlocked),
        _ => Err(RuntimeStoreError::UnknownOrCorruptSchema),
    }
}

const fn lifecycle_text(value: ConversationLifecycle) -> &'static str {
    match value {
        ConversationLifecycle::Active => "active",
        ConversationLifecycle::Archived => "archived",
        ConversationLifecycle::RecoveryBlocked => "recoveryBlocked",
    }
}

fn parse_command_state(value: &str) -> Result<CommandState, RuntimeStoreError> {
    match value {
        "accepted" => Ok(CommandState::Accepted),
        "started" => Ok(CommandState::Started),
        "completed" => Ok(CommandState::Completed),
        "failed" => Ok(CommandState::Failed),
        "interrupted" => Ok(CommandState::Interrupted),
        "expired" => Ok(CommandState::Expired),
        "canceled" => Ok(CommandState::Canceled),
        "revokedBeforeStart" => Ok(CommandState::RevokedBeforeStart),
        _ => Err(RuntimeStoreError::UnknownOrCorruptSchema),
    }
}

const fn command_state_text(value: CommandState) -> &'static str {
    match value {
        CommandState::Accepted => "accepted",
        CommandState::Started => "started",
        CommandState::Completed => "completed",
        CommandState::Failed => "failed",
        CommandState::Interrupted => "interrupted",
        CommandState::Expired => "expired",
        CommandState::Canceled => "canceled",
        CommandState::RevokedBeforeStart => "revokedBeforeStart",
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_command_invariants(
    state: CommandState,
    accepted_at_ms: u64,
    expires_at_ms: u64,
    retain_until_ms: u64,
    started_at_ms: Option<u64>,
    terminal_at_ms: Option<u64>,
    turn_id: Option<RuntimeId>,
    started_event_id: Option<RuntimeId>,
    terminal_event_id: Option<RuntimeId>,
    terminal_token: Option<&[u8]>,
    result: Option<&[u8]>,
) -> Result<(), RuntimeStoreError> {
    let expected_expiry = accepted_at_ms
        .checked_add(COMMAND_QUEUE_TTL_MS)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let minimum_retention = expires_at_ms
        .checked_add(COMMAND_LEDGER_RETENTION_MS)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    if expires_at_ms != expected_expiry || retain_until_ms < minimum_retention {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    if started_at_ms.is_some_and(|started| started < accepted_at_ms)
        || terminal_at_ms.is_some_and(|terminal| terminal < accepted_at_ms)
        || matches!((started_at_ms, terminal_at_ms), (Some(started), Some(terminal)) if terminal < started)
        || terminal_token.is_some_and(|token| token.len() != 32)
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let valid = match state {
        CommandState::Accepted => {
            started_at_ms.is_none()
                && terminal_at_ms.is_none()
                && turn_id.is_none()
                && started_event_id.is_none()
                && terminal_event_id.is_none()
                && terminal_token.is_none()
                && result.is_none()
        }
        CommandState::Started => {
            started_at_ms.is_some()
                && terminal_at_ms.is_none()
                && turn_id.is_some()
                && started_event_id.is_some()
                && terminal_event_id.is_none()
                && terminal_token.is_none()
                && result.is_none()
        }
        CommandState::Completed | CommandState::Failed | CommandState::Interrupted => {
            started_at_ms.is_some()
                && terminal_at_ms.is_some()
                && turn_id.is_some()
                && started_event_id.is_some()
                && terminal_event_id.is_some()
                && terminal_token.is_some()
                && result.is_some()
        }
        CommandState::Canceled => {
            let started_terminal = started_at_ms.is_some()
                && terminal_at_ms.is_some()
                && turn_id.is_some()
                && started_event_id.is_some()
                && terminal_event_id.is_some()
                && terminal_token.is_some()
                && result.is_some();
            let accepted_terminal = started_at_ms.is_none()
                && terminal_at_ms.is_some()
                && turn_id.is_none()
                && started_event_id.is_none()
                && terminal_event_id.is_some()
                && terminal_token.is_some()
                && result.is_none();
            started_terminal || accepted_terminal
        }
        CommandState::Expired | CommandState::RevokedBeforeStart => {
            started_at_ms.is_none()
                && terminal_at_ms.is_some()
                && turn_id.is_none()
                && started_event_id.is_none()
                && terminal_event_id.is_some()
                && terminal_token.is_some()
                && result.is_none()
        }
    };
    if valid {
        Ok(())
    } else {
        Err(RuntimeStoreError::UnknownOrCorruptSchema)
    }
}

const fn is_completion_terminal(state: CommandState) -> bool {
    matches!(
        state,
        CommandState::Completed
            | CommandState::Failed
            | CommandState::Interrupted
            | CommandState::Canceled
    )
}

fn accepted_termination_reason(
    state: CommandState,
    turn_id: Option<RuntimeId>,
) -> Option<AcceptedTerminationReason> {
    if turn_id.is_some() {
        return None;
    }
    match state {
        CommandState::Canceled => Some(AcceptedTerminationReason::Canceled),
        CommandState::RevokedBeforeStart => Some(AcceptedTerminationReason::RevokedBeforeStart),
        _ => None,
    }
}

fn accepted_termination_token(
    key_bundle: &super::cipher::RuntimeKeyBundle,
    reason: AcceptedTerminationReason,
    conversation_id: RuntimeId,
    command_id: RuntimeId,
    event_payload: &[u8],
) -> Result<super::cipher::BlindIndex, RuntimeStoreError> {
    let (domain, tag) = match reason {
        AcceptedTerminationReason::Canceled => (CANCELED_BEFORE_START_TOKEN_DOMAIN_V2, 1_u8),
        AcceptedTerminationReason::RevokedBeforeStart => {
            (REVOKED_BEFORE_START_TOKEN_DOMAIN_V2, 2_u8)
        }
    };
    let plaintext = Zeroizing::new(canonical_fields(&[
        conversation_id.as_bytes(),
        command_id.as_bytes(),
        &[tag],
        event_payload,
    ])?);
    Ok(key_bundle.blind_index(domain, plaintext.as_ref())?)
}

fn legacy_accepted_termination_token_v1(
    key_bundle: &super::cipher::RuntimeKeyBundle,
    reason: AcceptedTerminationReason,
    conversation_id: RuntimeId,
    command_id: RuntimeId,
    event_payload: &[u8],
) -> Result<super::cipher::BlindIndex, RuntimeStoreError> {
    let (domain, tag) = match reason {
        AcceptedTerminationReason::Canceled => (CANCELED_BEFORE_START_TOKEN_DOMAIN_V1, 1_u8),
        AcceptedTerminationReason::RevokedBeforeStart => {
            (REVOKED_BEFORE_START_TOKEN_DOMAIN_V1, 2_u8)
        }
    };
    let plaintext = Zeroizing::new(canonical_fields(&[
        conversation_id.as_bytes(),
        command_id.as_bytes(),
        &[tag],
        event_payload,
    ])?);
    Ok(key_bundle.blind_index(domain, plaintext.as_ref())?)
}

#[allow(clippy::too_many_arguments)]
fn verify_terminal_integrity(
    connection: &Connection,
    key_bundle: &super::cipher::RuntimeKeyBundle,
    database_id: [u8; 16],
    conversation_id: RuntimeId,
    command_id: RuntimeId,
    state: CommandState,
    expires_at_ms: u64,
    terminal_at_ms: Option<u64>,
    turn_id: Option<RuntimeId>,
    terminal_event_id: Option<RuntimeId>,
    terminal_token: Option<&[u8]>,
    result: Option<&[u8]>,
) -> Result<(), RuntimeStoreError> {
    if !state.is_terminal() {
        return Ok(());
    }
    let event_id = terminal_event_id.ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let event = load_event(connection, key_bundle, database_id, event_id)?;
    if event.conversation_id != conversation_id || event.command_id != Some(command_id) {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let expected = if let Some(reason) = accepted_termination_reason(state, turn_id) {
        if result.is_some()
            || event.created_at_ms
                != terminal_at_ms.ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?
        {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        let expected_event = command_event::accepted_terminal_event(command_id, reason)?;
        let typed_token = accepted_termination_token(
            key_bundle,
            reason,
            conversation_id,
            command_id,
            &expected_event,
        )?;
        if terminal_token == Some(typed_token.as_bytes().as_slice()) {
            if event.payload != expected_event {
                return Err(RuntimeStoreError::UnknownOrCorruptSchema);
            }
            typed_token
        } else {
            let legacy_token = legacy_accepted_termination_token_v1(
                key_bundle,
                reason,
                conversation_id,
                command_id,
                &event.payload,
            )?;
            if terminal_token != Some(legacy_token.as_bytes().as_slice())
                || matches!(
                    decode_persisted_runtime_event(&event)?,
                    PersistedRuntimeEvent::Canonical(_)
                )
            {
                return Err(RuntimeStoreError::UnknownOrCorruptSchema);
            }
            legacy_token
        }
    } else if is_completion_terminal(state) {
        let turn_id = turn_id.ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        let result = result.ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        let legacy_token = legacy_command_terminal_token_v1(
            key_bundle,
            conversation_id,
            command_id,
            turn_id,
            state,
            result,
            &event.payload,
        )?;
        if terminal_token == Some(legacy_token.as_bytes().as_slice()) {
            let released_fence =
                load_optional_fence(connection, key_bundle, database_id, command_id)?;
            if matches!(state, CommandState::Completed | CommandState::Failed)
                && released_fence
                    .as_ref()
                    .and_then(|fence| fence.release_authorized_at_ms)
                    .is_none()
            {
                return Err(RuntimeStoreError::UnknownOrCorruptSchema);
            }
            validate_legacy_canonical_terminal_body(state, turn_id, &event)?;
            legacy_token
        } else {
            let identity = CommandEventIdentity {
                conversation_id,
                command_id,
                turn_id,
                event_id,
                event_seq: event.event_seq,
            };
            let fence = load_optional_fence(connection, key_bundle, database_id, command_id)?;
            let expected_records = match fence
                .as_ref()
                .and_then(|record| record.release_authorized_at_ms)
            {
                Some(_) => {
                    let decoded: agentdeck_protocol::runtime::RuntimeEvent =
                        serde_json::from_slice(&event.payload)
                            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
                    let terminal = match (state, decoded.body) {
                        (
                            CommandState::Completed,
                            agentdeck_protocol::runtime::RuntimeEventBody::TurnCompleted {
                                turn_id: decoded_turn,
                                summary,
                            },
                        ) if decoded_turn.as_str() == turn_id.to_canonical_string() => {
                            crate::runtime::model::CommandTerminal::completed(summary)
                        }
                        (
                            CommandState::Failed,
                            agentdeck_protocol::runtime::RuntimeEventBody::Error { failure },
                        ) if failure.code
                            == agentdeck_protocol::runtime::failure::DAEMON_RUNTIME_EXECUTION_FAILED
                            && failure.message == "agent execution failed"
                            && failure.diagnostic_ref.is_none() =>
                        {
                            crate::runtime::model::CommandTerminal::failed(
                                SanitizedTerminalFailure::execution_failed(),
                            )
                        }
                        (
                            CommandState::Interrupted,
                            agentdeck_protocol::runtime::RuntimeEventBody::TurnInterrupted {
                                turn_id: decoded_turn,
                            },
                        ) if decoded_turn.as_str() == turn_id.to_canonical_string() => {
                            crate::runtime::model::CommandTerminal::interrupted()
                        }
                        (
                            CommandState::Canceled,
                            agentdeck_protocol::runtime::RuntimeEventBody::TurnInterrupted {
                                turn_id: decoded_turn,
                            },
                        ) if decoded_turn.as_str() == turn_id.to_canonical_string() => {
                            crate::runtime::model::CommandTerminal::canceled()
                        }
                        _ => return Err(RuntimeStoreError::UnknownOrCorruptSchema),
                    };
                    command_event::terminal_records(identity, &terminal)?
                }
                None => {
                    let reason = match state {
                        CommandState::Interrupted => StartedBeforeReleaseTermination::Interrupted,
                        CommandState::Canceled => StartedBeforeReleaseTermination::Canceled,
                        _ => return Err(RuntimeStoreError::UnknownOrCorruptSchema),
                    };
                    command_event::before_release_terminal_records(identity, reason)?
                }
            };
            if expected_records.result != result || expected_records.event != event.payload {
                return Err(RuntimeStoreError::UnknownOrCorruptSchema);
            }
            command_terminal_token(
                key_bundle,
                conversation_id,
                command_id,
                turn_id,
                command_state_to_terminal(state)
                    .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?,
                result,
                &event.payload,
            )?
        }
    } else if state == CommandState::Expired {
        let fields = decode_fields(EXPIRY_EVENT_MAGIC, &event.payload, 2)?;
        if fields[0] != command_id.as_bytes() || fields[1] != expires_at_ms.to_be_bytes() {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        let plaintext = Zeroizing::new(canonical_fields(&[
            conversation_id.as_bytes(),
            command_id.as_bytes(),
            &[5],
            &event.payload,
        ])?);
        key_bundle.blind_index(b"command.expired.v1", plaintext.as_ref())?
    } else {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    };
    if terminal_token != Some(expected.as_bytes().as_slice()) {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(())
}

const fn command_state_to_terminal(state: CommandState) -> Option<TerminalState> {
    match state {
        CommandState::Completed => Some(TerminalState::Completed),
        CommandState::Failed => Some(TerminalState::Failed),
        CommandState::Interrupted => Some(TerminalState::Interrupted),
        CommandState::Canceled => Some(TerminalState::Canceled),
        _ => None,
    }
}

fn validate_legacy_canonical_terminal_body(
    state: CommandState,
    turn_id: RuntimeId,
    event: &EventRecord,
) -> Result<(), RuntimeStoreError> {
    let PersistedRuntimeEvent::Canonical(decoded) = decode_persisted_runtime_event(event)? else {
        return Ok(());
    };
    let valid = match (state, decoded.body) {
        (
            CommandState::Completed,
            agentdeck_protocol::runtime::RuntimeEventBody::TurnCompleted {
                turn_id: event_turn,
                ..
            },
        )
        | (
            CommandState::Interrupted | CommandState::Canceled,
            agentdeck_protocol::runtime::RuntimeEventBody::TurnInterrupted {
                turn_id: event_turn,
            },
        ) => event_turn.as_str() == turn_id.to_canonical_string(),
        (CommandState::Failed, agentdeck_protocol::runtime::RuntimeEventBody::Error { .. }) => true,
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(RuntimeStoreError::UnknownOrCorruptSchema)
    }
}

fn validate_started_linkage(
    command: &CommandRecord,
    intent: &ExecutionIntentRecord,
    event: &EventRecord,
) -> Result<(), RuntimeStoreError> {
    if !(command.state == CommandState::Started || is_completion_terminal(command.state))
        || command.turn_id != Some(intent.turn_id)
        || command.started_event_id != Some(intent.started_event_id)
        || command.started_at_ms != Some(intent.created_at_ms)
        || event.event_id != intent.started_event_id
        || event.conversation_id != command.conversation_id
        || event.command_id != Some(command.command_id)
        || event.created_at_ms != intent.created_at_ms
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(())
}

fn validate_exact_recovery_started_binding(
    connection: &Connection,
    key_bundle: &super::cipher::RuntimeKeyBundle,
    database_id: [u8; 16],
    command: &CommandRecord,
    expected: &RecoveryBlockedCommandBinding,
) -> Result<(), RuntimeStoreError> {
    let RecoveryBlockedCommandBinding::Started {
        command_id,
        turn_id,
        daemon_boot_id,
        execution_nonce,
        fence,
    } = expected
    else {
        return Err(RuntimeStoreError::InvalidConfig(
            "exact recovery Started validation requires a Started binding",
        ));
    };
    if command.command_id != *command_id
        || command.turn_id != Some(*turn_id)
        || !(command.state == CommandState::Started || is_completion_terminal(command.state))
    {
        return Err(RuntimeStoreError::StartConflict);
    }
    let intent = load_intent(connection, key_bundle, database_id, *command_id)?;
    let started_event = load_event(connection, key_bundle, database_id, intent.started_event_id)?;
    validate_started_linkage(command, &intent, &started_event)?;
    if intent.turn_id != *turn_id
        || intent.daemon_boot_id != *daemon_boot_id
        || intent.execution_nonce != *execution_nonce
    {
        return Err(RuntimeStoreError::StartConflict);
    }
    let observed_fence = load_optional_fence(connection, key_bundle, database_id, *command_id)?;
    let observed_binding = observed_fence
        .as_ref()
        .map(RecoveryFenceBinding::from_record);
    if observed_binding.as_ref() != fence.as_deref()
        || fence.as_ref().is_some_and(|fence| {
            fence.command_id != *command_id
                || fence.daemon_boot_id != *daemon_boot_id
                || fence.execution_nonce != *execution_nonce
        })
    {
        return Err(RuntimeStoreError::FenceConflict);
    }
    Ok(())
}

fn load_authenticated_started_linkage(
    connection: &Connection,
    key_bundle: &super::cipher::RuntimeKeyBundle,
    database_id: [u8; 16],
    command_id: RuntimeId,
) -> Result<(CommandRecord, ExecutionIntentRecord), RuntimeStoreError> {
    let command = load_command(connection, key_bundle, database_id, command_id)?;
    let intent = load_intent(connection, key_bundle, database_id, command_id)?;
    let started_event = load_event(connection, key_bundle, database_id, intent.started_event_id)?;
    validate_started_linkage(&command, &intent, &started_event)?;
    Ok((command, intent))
}

pub(super) fn require_authenticated_started_turn(
    connection: &Connection,
    key_bundle: &super::cipher::RuntimeKeyBundle,
    database_id: [u8; 16],
    conversation_id: RuntimeId,
    command_id: RuntimeId,
    turn_id: RuntimeId,
    observed_at_ms: u64,
) -> Result<(), RuntimeStoreError> {
    let (command, intent) =
        load_authenticated_started_linkage(connection, key_bundle, database_id, command_id)?;
    if command.conversation_id != conversation_id
        || command.state != CommandState::Started
        || command.turn_id != Some(turn_id)
        || intent.turn_id != turn_id
    {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }
    let started_at_ms = command
        .started_at_ms
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    if observed_at_ms < started_at_ms {
        return Err(RuntimeStoreError::ClockRegressed {
            persisted_ms: started_at_ms,
            observed_ms: observed_at_ms,
        });
    }
    Ok(())
}

pub(super) fn is_authenticated_exact_started_turn(
    connection: &Connection,
    key_bundle: &super::cipher::RuntimeKeyBundle,
    database_id: [u8; 16],
    conversation_id: RuntimeId,
    command_id: RuntimeId,
    turn_id: RuntimeId,
) -> Result<bool, RuntimeStoreError> {
    let (command, intent) =
        load_authenticated_started_linkage(connection, key_bundle, database_id, command_id)?;
    Ok(command.conversation_id == conversation_id
        && command.state == CommandState::Started
        && command.turn_id == Some(turn_id)
        && intent.turn_id == turn_id)
}

fn validate_started_terminal_linkage(
    command: &CommandRecord,
    intent: &ExecutionIntentRecord,
    started_event: &EventRecord,
    terminal_event: &EventRecord,
) -> Result<(), RuntimeStoreError> {
    validate_started_linkage(command, intent, started_event)?;
    if terminal_event.event_id
        != command
            .terminal_event_id
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?
        || terminal_event.conversation_id != command.conversation_id
        || terminal_event.command_id != Some(command.command_id)
        || terminal_event.created_at_ms
            != command
                .terminal_at_ms
                .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(())
}

fn command_terminal_token(
    key_bundle: &super::cipher::RuntimeKeyBundle,
    conversation_id: RuntimeId,
    command_id: RuntimeId,
    turn_id: RuntimeId,
    terminal_state: TerminalState,
    result: &[u8],
    event: &[u8],
) -> Result<super::cipher::BlindIndex, RuntimeStoreError> {
    let terminal_bytes = Zeroizing::new(canonical_fields(&[
        conversation_id.as_bytes(),
        command_id.as_bytes(),
        turn_id.as_bytes(),
        &[terminal_state_tag(terminal_state)],
        result,
        event,
    ])?);
    Ok(key_bundle.blind_index(b"command.terminal.v2", terminal_bytes.as_ref())?)
}

#[allow(clippy::too_many_arguments)]
fn legacy_command_terminal_token_v1(
    key_bundle: &super::cipher::RuntimeKeyBundle,
    conversation_id: RuntimeId,
    command_id: RuntimeId,
    turn_id: RuntimeId,
    state: CommandState,
    result: &[u8],
    event: &[u8],
) -> Result<super::cipher::BlindIndex, RuntimeStoreError> {
    let terminal =
        command_state_to_terminal(state).ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let terminal_bytes = Zeroizing::new(canonical_fields(&[
        conversation_id.as_bytes(),
        command_id.as_bytes(),
        turn_id.as_bytes(),
        &[terminal_state_tag(terminal)],
        result,
        event,
    ])?);
    Ok(key_bundle.blind_index(b"command.terminal.v1", terminal_bytes.as_ref())?)
}

const fn terminal_state_text(state: TerminalState) -> &'static str {
    match state {
        TerminalState::Completed => "completed",
        TerminalState::Failed => "failed",
        TerminalState::Interrupted => "interrupted",
        TerminalState::Canceled => "canceled",
    }
}

const fn terminal_state_tag(state: TerminalState) -> u8 {
    match state {
        TerminalState::Completed => 1,
        TerminalState::Failed => 2,
        TerminalState::Interrupted => 3,
        TerminalState::Canceled => 4,
    }
}

const fn terminal_to_command_state(state: TerminalState) -> CommandState {
    match state {
        TerminalState::Completed => CommandState::Completed,
        TerminalState::Failed => CommandState::Failed,
        TerminalState::Interrupted => CommandState::Interrupted,
        TerminalState::Canceled => CommandState::Canceled,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authenticated_event_high_water_query_is_metadata_only() {
        assert!(AUTHENTICATED_EVENT_HIGH_WATER_QUERY.contains("metadata_token"));
        assert!(AUTHENTICATED_EVENT_HIGH_WATER_QUERY.contains("event_high_water"));
        assert!(!AUTHENTICATED_EVENT_HIGH_WATER_QUERY.contains("sealed_descriptor"));
    }

    #[test]
    fn recovery_page_budget_accepts_exact_limit_and_rejects_plus_one() {
        let limit = u64::try_from(MAX_RECOVERY_PAGE_RETAINED_BYTES).expect("page limit fits u64");
        ensure_recovery_page_budget(limit).expect("exact recovery page limit is legal");
        assert!(matches!(
            ensure_recovery_page_budget(limit + 1),
            Err(RuntimeStoreError::RecoveryPageTooLarge {
                projected_bytes,
                limit_bytes,
            }) if projected_bytes == limit + 1 && limit_bytes == limit
        ));
    }

    #[test]
    fn failed_commit_with_confirmed_rollback_preserves_the_sqlite_error() {
        let mut connection = Connection::open_in_memory().expect("open SQLite");
        connection
            .execute_batch(
                "PRAGMA foreign_keys = ON;
                 CREATE TABLE parent (id INTEGER PRIMARY KEY);
                 CREATE TABLE child (
                     parent_id INTEGER NOT NULL,
                     FOREIGN KEY (parent_id) REFERENCES parent(id)
                         DEFERRABLE INITIALLY DEFERRED
                 );",
            )
            .expect("create deferred foreign key fixture");

        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("begin transaction");
        transaction
            .execute("INSERT INTO child (parent_id) VALUES (7)", [])
            .expect("deferred constraint permits the write before COMMIT");

        let error = commit_transaction(transaction, RuntimeCommitOperation::StartCommand)
            .expect_err("deferred constraint must reject COMMIT");
        assert!(
            matches!(error, RuntimeStoreError::Sqlite(_)),
            "confirmed rollback must preserve the original SQLite error: {error:?}"
        );
        assert!(connection.is_autocommit());
        let rows: i64 = connection
            .query_row("SELECT COUNT(*) FROM child", [], |row| row.get(0))
            .expect("count rolled-back rows");
        assert_eq!(rows, 0, "failed transaction must be fully rolled back");
    }

    #[test]
    fn commit_error_seen_in_autocommit_state_is_conservatively_unknown() {
        let mut connection = Connection::open_in_memory().expect("open SQLite");
        connection
            .execute_batch("CREATE TABLE item (value INTEGER NOT NULL)")
            .expect("create fixture");
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("begin transaction");
        transaction
            .execute("INSERT INTO item (value) VALUES (1)", [])
            .expect("insert fixture row");
        transaction
            .execute_batch("ROLLBACK")
            .expect("put the connection in autocommit before the failing COMMIT");

        let error = commit_transaction(transaction, RuntimeCommitOperation::CompleteCommand)
            .expect_err("COMMIT without an active transaction must fail");
        assert!(matches!(
            error,
            RuntimeStoreError::CommitOutcomeUnknown {
                operation: RuntimeCommitOperation::CompleteCommand
            }
        ));
        assert!(connection.is_autocommit());
        let rows: i64 = connection
            .query_row("SELECT COUNT(*) FROM item", [], |row| row.get(0))
            .expect("count fixture rows");
        assert_eq!(rows, 0);

        connection
            .execute("INSERT INTO item (value) VALUES (2)", [])
            .expect("Drop must not issue another rollback or poison the connection");
    }
}
