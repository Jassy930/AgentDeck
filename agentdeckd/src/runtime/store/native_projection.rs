//! Native history projection 的原子导入、authenticated read/audit 与 metadata effect fence。
//!
//! private adapter reference 只由 vault loader 解密认证，Runtime store 不解释其格式；
//! effect spec 同样只作为有界 opaque bytes 参与认证。

use std::collections::HashSet;

use agentdeck_protocol::runtime::ConversationConfiguration;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use zeroize::Zeroizing;

use super::cipher::{ROW_BLOB_V1_OVERHEAD_LEN, RuntimeKeyBundle};
use super::configuration::{ConfigurationRecord, PreparedNativeProjectionConfiguration};
use super::identity::{
    MAX_RUNTIME_ID_COLLISION_ATTEMPTS, RuntimeId, RuntimeIdError, RuntimeIdKind,
};
use super::sequence::{SequenceScope, decode_sequence, next_sequence};
use super::sqlite::{RuntimeLedger, RuntimeSqlite, SafetyReserveProjection};
use super::stream::{metadata_mac, open_v4_row, optional_field};
use super::{ConversationDescriptor, ConversationRecord, RuntimeStoreError};
use crate::runtime::adapter_state::AdapterStateNamespace;
use crate::runtime::events::CommandStreamEffects;
use crate::runtime::model::{
    NativeProjectionLimitScope, NewConversation, RuntimeCommitOperation, RuntimeStoreConfig,
    RuntimeStoreOperation,
};
use crate::runtime::process_identity::ProcessIdentity;
use crate::security::SecretBytes;

const PROJECTION_METADATA_DOMAIN: &[u8] = b"native.projection.metadata.v1";
const EFFECT_FENCE_METADATA_DOMAIN: &[u8] = b"native.metadata-effect-fence.metadata.v1";
const EFFECT_NONCE_DOMAIN: &[u8] = b"native.metadata-effect-fence.nonce.v1";
const EFFECT_SPEC_DOMAIN: &[u8] = b"native.metadata-effect-fence.spec.v1";
const EFFECT_RELEASE_DOMAIN: &[u8] = b"native.metadata-effect-fence.release.v1";
const EFFECT_FENCE_TABLE: &[u8] = b"native_metadata_effect_fences";
const EFFECT_FENCE_COLUMN: &[u8] = b"sealed_fence";
const EFFECT_FENCE_PAYLOAD_MAGIC: &[u8; 4] = b"ADN1";
const EFFECT_FENCE_PRIMARY_KEY_MAGIC: &[u8; 4] = b"ADNF";
const MAX_EFFECT_NONCE_BYTES: usize = 1024;
const MAX_EFFECT_SPEC_BYTES: usize = 16 * 1024;
const MAX_EFFECT_FENCE_PLAINTEXT_BYTES: usize = 17_532;
const MAX_NATIVE_PROJECTION_ROWS: u64 = 9_216;
const MAX_METADATA_EFFECT_FENCE_ROWS: u64 = 65_536;
const MAX_RUNTIME_LIVE_CONVERSATIONS: u64 = 1_024;
const MAX_NATIVE_NONLIVE_IDENTITIES: u64 = 8_192;
const MAX_NATIVE_REFERENCE_CHARGED_BYTES: u64 = 16 * 1024 * 1024;
#[allow(dead_code)] // C-f projector lifecycle 接线后由 production capability 强制。
pub(super) const MAX_NATIVE_PRIVATE_REFERENCE_BYTES: usize = 523;
#[allow(dead_code)] // C-f projector lifecycle 接线后由 production capability 强制。
pub(super) const MIN_NATIVE_PRIVATE_REFERENCE_BYTES: usize = 20;

/// 已验证 native source 交给固定 namespace projector 的最小导入输入。
///
/// private reference 不实现可见 Debug；Store 只把它当作 versioned opaque bytes。
#[allow(dead_code)] // C-f projector lifecycle 接线后由 verified native source 构造。
pub(crate) struct ImportNativeProjection {
    pub(crate) descriptor: ConversationDescriptor,
    pub(crate) default_configuration: ConversationConfiguration,
    pub(crate) private_reference: SecretBytes,
    pub(crate) scan_generation: [u8; 16],
}

impl std::fmt::Debug for ImportNativeProjection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ImportNativeProjection")
            .field("descriptor", &"[REDACTED]")
            .field("default_configuration", &"[REDACTED]")
            .field("private_reference", &"[REDACTED]")
            .field("scan_generation", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ImportNativeProjectionOutcome {
    Imported {
        conversation: ConversationRecord,
        configuration: ConfigurationRecord,
    },
    Replayed {
        conversation: ConversationRecord,
        configuration: ConfigurationRecord,
    },
    Reobserved {
        conversation: ConversationRecord,
        configuration: ConfigurationRecord,
    },
}

#[derive(Clone, Copy)]
pub(super) struct NativeProjectionIdentityCandidate {
    pub(super) conversation_id: RuntimeId,
    pub(super) adapter_state_key: RuntimeId,
}

pub(super) struct PreparedNativeProjectionImport {
    pub(super) descriptor: ConversationDescriptor,
    pub(super) descriptor_bytes: Zeroizing<Vec<u8>>,
    pub(super) default_configuration: PreparedNativeProjectionConfiguration,
    pub(super) private_reference: SecretBytes,
    #[allow(dead_code)] // C-f production caller 接线前只由 focused test command 计费。
    pub(super) private_reference_capacity: usize,
    pub(super) scan_generation: [u8; 16],
    pub(super) observation_token: [u8; 32],
    pub(super) identity_candidates: Vec<NativeProjectionIdentityCandidate>,
}

impl PreparedNativeProjectionImport {
    #[allow(dead_code)] // C-f projector lifecycle 接线后进入 normal lane admission。
    pub(super) fn retained_capacity(&self) -> Result<usize, RuntimeStoreError> {
        self.descriptor
            .title
            .as_ref()
            .map_or(0, String::capacity)
            .checked_add(self.descriptor.cwd.capacity())
            .and_then(|value| value.checked_add(self.descriptor_bytes.capacity()))
            .and_then(|value| {
                value.checked_add(self.default_configuration.retained_capacity().ok()?)
            })
            .and_then(|value| value.checked_add(self.private_reference_capacity))
            .and_then(|value| {
                value.checked_add(
                    self.identity_candidates
                        .capacity()
                        .checked_mul(std::mem::size_of::<NativeProjectionIdentityCandidate>())?,
                )
            })
            .ok_or(RuntimeStoreError::PayloadTooLarge)
    }
}

pub(crate) fn import_native_projection(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    prepared: PreparedNativeProjectionImport,
    effects: &mut CommandStreamEffects,
) -> Result<ImportNativeProjectionOutcome, RuntimeStoreError> {
    let namespace = prepared.default_configuration.namespace();
    if namespace.agent_kind() != prepared.descriptor.agent_kind
        || prepared.scan_generation == [0; 16]
        || prepared.identity_candidates.is_empty()
        || prepared.identity_candidates.len() > MAX_RUNTIME_ID_COLLISION_ATTEMPTS
    {
        return Err(RuntimeStoreError::InvalidConfig(
            "native projection import preparation is invalid",
        ));
    }
    let reference_token = super::journal::adapter_state_reference_token(
        &state.key_bundle,
        namespace,
        &prepared.private_reference,
    )?;
    let existing = load_existing_native_projection(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        namespace,
        &reference_token,
        &prepared.private_reference,
    )?;
    if let Some(existing) = existing.as_ref()
        && existing.projection.state != ProjectionState::Present
    {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }
    if let Some(existing) = existing.as_ref()
        && existing.projection.scan_generation == prepared.scan_generation
    {
        if existing.projection.observation_token != prepared.observation_token {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        return Ok(ImportNativeProjectionOutcome::Replayed {
            conversation: existing.conversation.clone(),
            configuration: existing.configuration.clone(),
        });
    }

    let is_reobserve = existing.is_some();
    if !is_reobserve {
        let preflight_ledger = super::sqlite::load_runtime_ledger(
            &state.connection,
            &state.key_bundle,
            state.database_id,
        )?;
        validate_fresh_import_capacity(
            &preflight_ledger,
            config,
            projected_reference_sealed_bytes(&prepared.private_reference)?,
        )?;
    }
    let projected_write_bytes = if is_reobserve {
        super::journal::projected_write_bytes(&[4 * 1024])?
    } else {
        super::journal::projected_write_bytes(&[
            prepared.descriptor_bytes.len(),
            prepared.descriptor_bytes.len(),
            prepared.private_reference.expose_secret().len(),
            prepared.private_reference.expose_secret().len(),
            prepared.default_configuration.configuration_bytes().len(),
            prepared
                .default_configuration
                .configuration_bytes()
                .len()
                .checked_add(2 * 1024)
                .ok_or(RuntimeStoreError::PayloadTooLarge)?,
            4 * 1024,
        ])?
    };
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
    let observed_at_ms = config.clock.now_ms()?;
    let database_id = state.database_id;
    let key_bundle = &state.key_bundle;
    let transaction = state
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let existing = load_existing_native_projection(
        &transaction,
        key_bundle,
        database_id,
        namespace,
        &reference_token,
        &prepared.private_reference,
    )?;
    if let Some(existing) = existing {
        if existing.projection.state != ProjectionState::Present {
            return Err(RuntimeStoreError::InvalidStateTransition);
        }
        if existing.projection.scan_generation == prepared.scan_generation {
            if existing.projection.observation_token != prepared.observation_token {
                return Err(RuntimeStoreError::UnknownOrCorruptSchema);
            }
            return Ok(ImportNativeProjectionOutcome::Replayed {
                conversation: existing.conversation,
                configuration: existing.configuration,
            });
        }
        if observed_at_ms < existing.projection.reconciled_at_ms {
            return Err(RuntimeStoreError::ClockRegressed {
                persisted_ms: existing.projection.reconciled_at_ms,
                observed_ms: observed_at_ms,
            });
        }
        let catalog_revision =
            super::sequence::encode_sequence(existing.projection.projection_catalog_revision);
        let metadata_token = projection_metadata_token(
            key_bundle,
            existing.conversation.conversation_id,
            namespace.origin_namespace(),
            &reference_token,
            ProjectionState::Present,
            &prepared.scan_generation,
            &prepared.observation_token,
            &catalog_revision,
            observed_at_ms,
            existing.projection.state_changed_at_ms,
            existing.projection.retain_until_ms,
            existing.projection.charged_reference_bytes,
        )?;
        if transaction.execute(
            "UPDATE native_projection_state
             SET scan_generation = ?1, observation_token = ?2, reconciled_at_ms = ?3,
                 metadata_token = ?4
             WHERE conversation_id = ?5 AND metadata_token = ?6",
            params![
                &prepared.scan_generation[..],
                &prepared.observation_token[..],
                sqlite_time(observed_at_ms)?,
                &metadata_token[..],
                &existing.conversation.conversation_id.as_bytes()[..],
                &existing.projection.metadata_token[..],
            ],
        )? != 1
        {
            return Err(RuntimeStoreError::SchemaInspectionRaced);
        }
        config
            .fault_injector
            .before_operation(RuntimeStoreOperation::ImportNativeProjectionBeforeCommit)?;
        super::sqlite::commit_transaction(
            transaction,
            RuntimeCommitOperation::ImportNativeProjection,
        )?;
        super::sqlite::latch_post_commit_capacity(state, config);
        native_projection_after_commit(config)?;
        return Ok(ImportNativeProjectionOutcome::Reobserved {
            conversation: existing.conversation,
            configuration: existing.configuration,
        });
    }

    let ledger = super::sqlite::load_runtime_ledger(&transaction, key_bundle, database_id)?;
    let projected_reference_bytes = projected_reference_sealed_bytes(&prepared.private_reference)?;
    validate_fresh_import_capacity(&ledger, config, projected_reference_bytes)?;
    let identity = prepared
        .identity_candidates
        .iter()
        .copied()
        .find_map(|candidate| {
            match super::journal::conversation_identity_pair_is_occupied(
                &transaction,
                key_bundle,
                database_id,
                candidate.conversation_id,
                candidate.adapter_state_key,
            ) {
                Ok(false) => Some(Ok(candidate)),
                Ok(true) => None,
                Err(error) => Some(Err(error)),
            }
        })
        .transpose()?
        .ok_or_else(|| {
            RuntimeStoreError::IdGeneration(RuntimeIdError::CollisionExhausted {
                kind: RuntimeIdKind::Conversation,
                attempts: MAX_RUNTIME_ID_COLLISION_ATTEMPTS,
            })
        })?;
    validate_catalog_clock(&transaction, key_bundle, database_id, observed_at_ms)?;
    let catalog_revision = next_sequence(
        SequenceScope::CatalogRevision,
        ledger.catalog_high_water.as_deref(),
    )?;
    let conversation = super::journal::insert_conversation_row(
        &transaction,
        key_bundle,
        database_id,
        NewConversation {
            conversation_id: identity.conversation_id,
            adapter_state_key: identity.adapter_state_key,
            descriptor: prepared.descriptor,
        },
        prepared.descriptor_bytes.as_ref(),
        catalog_revision.value,
        observed_at_ms,
        observed_at_ms,
    )?;
    let binding = super::journal::insert_adapter_state_binding(
        &transaction,
        key_bundle,
        database_id,
        namespace,
        &conversation,
        &prepared.private_reference,
    )?;
    if binding.reference_token() != &reference_token
        || binding.sealed_reference_bytes() != projected_reference_bytes
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let (configuration, mut next_ledger) =
        super::configuration::append_initial_native_projection_configuration(
            &transaction,
            key_bundle,
            database_id,
            config,
            &conversation,
            &prepared.default_configuration,
            &ledger,
        )?;
    let projection_token = projection_metadata_token(
        key_bundle,
        conversation.conversation_id,
        namespace.origin_namespace(),
        &reference_token,
        ProjectionState::Present,
        &prepared.scan_generation,
        &prepared.observation_token,
        &catalog_revision.encoded,
        observed_at_ms,
        observed_at_ms,
        None,
        projected_reference_bytes,
    )?;
    if transaction.execute(
        "INSERT INTO native_projection_state (
             conversation_id, origin_namespace, state_reference_token,
             projection_state, scan_generation, observation_token,
             projection_catalog_revision, reconciled_at_ms, state_changed_at_ms,
             private_binding_retain_until_ms, charged_reference_bytes, metadata_token
         ) VALUES (?1, ?2, ?3, 'present', ?4, ?5, ?6, ?7, ?7, NULL, ?8, ?9)",
        params![
            &conversation.conversation_id.as_bytes()[..],
            namespace.origin_namespace(),
            &reference_token[..],
            &prepared.scan_generation[..],
            &prepared.observation_token[..],
            &catalog_revision.encoded,
            sqlite_time(observed_at_ms)?,
            sqlite_u64(projected_reference_bytes)?,
            &projection_token[..],
        ],
    )? != 1
    {
        return Err(RuntimeStoreError::SchemaInspectionRaced);
    }
    next_ledger.catalog_high_water = Some(catalog_revision.encoded);
    next_ledger.conversation_count = checked_add(next_ledger.conversation_count, 1)?;
    match namespace {
        AdapterStateNamespace::Codex => {
            next_ledger.codex_adapter_state_count =
                checked_add(next_ledger.codex_adapter_state_count, 1)?;
        }
        AdapterStateNamespace::ClaudeCode => {
            next_ledger.claude_code_adapter_state_count =
                checked_add(next_ledger.claude_code_adapter_state_count, 1)?;
        }
    }
    next_ledger.native_projection_present_count =
        checked_add(next_ledger.native_projection_present_count, 1)?;
    next_ledger.native_projection_physical_count =
        checked_add(next_ledger.native_projection_physical_count, 1)?;
    next_ledger.native_projection_charged_bytes = checked_add(
        next_ledger.native_projection_charged_bytes,
        projected_reference_bytes,
    )?;
    let pending_targets = super::sqlite::update_runtime_ledger(
        &transaction,
        key_bundle,
        database_id,
        &ledger,
        &next_ledger,
    )?;
    config
        .fault_injector
        .before_operation(RuntimeStoreOperation::ImportNativeProjectionBeforeCommit)?;
    let commit_result = super::sqlite::commit_transaction(
        transaction,
        RuntimeCommitOperation::ImportNativeProjection,
    );
    effects.record_commit_result(pending_targets, &commit_result);
    commit_result?;
    super::sqlite::latch_post_commit_capacity(state, config);
    native_projection_after_commit(config)?;
    let conversation = super::journal::load_conversation(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        conversation.conversation_id,
    )?;
    Ok(ImportNativeProjectionOutcome::Imported {
        conversation,
        configuration,
    })
}

fn validate_fresh_import_capacity(
    ledger: &RuntimeLedger,
    config: &RuntimeStoreConfig,
    projected_reference_bytes: u64,
) -> Result<(), RuntimeStoreError> {
    let nonlive = ledger
        .native_projection_tombstone_count
        .checked_add(ledger.native_projection_retired_count)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let live = ledger
        .conversation_count
        .checked_sub(nonlive)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    if live >= config.conversation_capacity {
        return Err(RuntimeStoreError::ConversationLimit);
    }
    if ledger.conversation_count >= MAX_NATIVE_PROJECTION_ROWS
        || ledger.native_projection_physical_count >= MAX_NATIVE_PROJECTION_ROWS
    {
        return Err(RuntimeStoreError::NativeProjectionLimit {
            scope: NativeProjectionLimitScope::PhysicalIdentities,
        });
    }
    if ledger
        .native_projection_charged_bytes
        .checked_add(projected_reference_bytes)
        .is_none_or(|bytes| bytes > MAX_NATIVE_REFERENCE_CHARGED_BYTES)
    {
        return Err(RuntimeStoreError::NativeProjectionLimit {
            scope: NativeProjectionLimitScope::ChargedReferenceBytes,
        });
    }
    Ok(())
}

fn projected_reference_sealed_bytes(
    private_reference: &SecretBytes,
) -> Result<u64, RuntimeStoreError> {
    private_reference
        .expose_secret()
        .len()
        .checked_add(ROW_BLOB_V1_OVERHEAD_LEN)
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or(RuntimeStoreError::PayloadTooLarge)
}

fn validate_catalog_clock(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    observed_at_ms: u64,
) -> Result<(), RuntimeStoreError> {
    let raw_conversation_id = connection
        .query_row(
            "SELECT conversation_id FROM conversations
             ORDER BY updated_at_ms DESC, conversation_id DESC LIMIT 1",
            [],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?;
    let Some(raw_conversation_id) = raw_conversation_id else {
        return Ok(());
    };
    let conversation_id = runtime_id(RuntimeIdKind::Conversation, raw_conversation_id)?;
    let latest =
        super::journal::load_conversation(connection, key_bundle, database_id, conversation_id)?;
    if observed_at_ms < latest.updated_at_ms {
        return Err(RuntimeStoreError::ClockRegressed {
            persisted_ms: latest.updated_at_ms,
            observed_ms: observed_at_ms,
        });
    }
    Ok(())
}

fn native_projection_after_commit(config: &RuntimeStoreConfig) -> Result<(), RuntimeStoreError> {
    if config
        .fault_injector
        .before_operation(RuntimeStoreOperation::ImportNativeProjectionAfterCommit)
        .is_err()
    {
        Err(RuntimeStoreError::CommitOutcomeUnknown {
            operation: RuntimeCommitOperation::ImportNativeProjection,
        })
    } else {
        Ok(())
    }
}

fn sqlite_time(value: u64) -> Result<i64, RuntimeStoreError> {
    i64::try_from(value).map_err(|_| RuntimeStoreError::TimeOutOfRange)
}

fn sqlite_u64(value: u64) -> Result<i64, RuntimeStoreError> {
    i64::try_from(value).map_err(|_| RuntimeStoreError::PayloadTooLarge)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProjectionState {
    Present,
    Tombstone,
    Retired,
}

impl ProjectionState {
    fn parse(value: &str) -> Result<Self, RuntimeStoreError> {
        match value {
            "present" => Ok(Self::Present),
            "tombstone" => Ok(Self::Tombstone),
            "retired" => Ok(Self::Retired),
            _ => Err(RuntimeStoreError::UnknownOrCorruptSchema),
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Present => "present",
            Self::Tombstone => "tombstone",
            Self::Retired => "retired",
        }
    }
}

struct RawProjectionRow {
    conversation_id: Vec<u8>,
    origin_namespace: String,
    state_reference_token: Vec<u8>,
    projection_state: String,
    scan_generation: Vec<u8>,
    observation_token: Vec<u8>,
    projection_catalog_revision: String,
    reconciled_at_ms: i64,
    state_changed_at_ms: i64,
    private_binding_retain_until_ms: Option<i64>,
    charged_reference_bytes: i64,
    metadata_token: Vec<u8>,
}

struct AuthenticatedProjectionRow {
    conversation_id: RuntimeId,
    origin_namespace: String,
    state_reference_token: [u8; 32],
    state: ProjectionState,
    scan_generation: [u8; 16],
    observation_token: [u8; 32],
    projection_catalog_revision: u64,
    reconciled_at_ms: u64,
    state_changed_at_ms: u64,
    retain_until_ms: Option<u64>,
    charged_reference_bytes: u64,
    metadata_token: [u8; 32],
}

#[derive(Default)]
struct ProjectionTotals {
    present: u64,
    tombstone: u64,
    retired: u64,
    physical: u64,
    charged_bytes: u64,
}

struct RawEffectFenceRow {
    conversation_id: Vec<u8>,
    idempotency_token: Vec<u8>,
    daemon_boot_id: Vec<u8>,
    effect_nonce_token: Vec<u8>,
    effect_spec_token: Vec<u8>,
    process_group_id: i64,
    leader_pid: i64,
    leader_start_time: String,
    release_authorized_at_ms: Option<i64>,
    release_token_commitment: Option<Vec<u8>>,
    logical_fence_bytes: i64,
    metadata_token: Vec<u8>,
    sealed_fence: Vec<u8>,
}

struct AuthenticatedEffectFenceRow {
    conversation_id: RuntimeId,
    idempotency_token: [u8; 32],
    release_authorized_at_ms: Option<u64>,
}

#[derive(Default)]
struct EffectFenceTotals {
    total: u64,
    unreleased: u64,
    released: u64,
}

pub(super) fn validate_v6_integrity(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    ledger: &RuntimeLedger,
) -> Result<(), RuntimeStoreError> {
    let projection_totals =
        validate_projection_integrity(connection, key_bundle, database_id, ledger)?;
    if projection_totals.present != ledger.native_projection_present_count
        || projection_totals.tombstone != ledger.native_projection_tombstone_count
        || projection_totals.retired != ledger.native_projection_retired_count
        || projection_totals.physical != ledger.native_projection_physical_count
        || projection_totals.charged_bytes != ledger.native_projection_charged_bytes
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }

    let effect_totals =
        validate_effect_fence_integrity(connection, key_bundle, database_id, ledger)?;
    if effect_totals.total != ledger.native_metadata_effect_fence_count
        || effect_totals.unreleased != ledger.native_metadata_effect_unreleased_count
        || effect_totals.released != ledger.native_metadata_effect_released_count
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(())
}

fn validate_projection_integrity(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    ledger: &RuntimeLedger,
) -> Result<ProjectionTotals, RuntimeStoreError> {
    let mut statement = connection.prepare(
        "SELECT conversation_id, origin_namespace, state_reference_token,
                projection_state, scan_generation, observation_token,
                projection_catalog_revision, reconciled_at_ms, state_changed_at_ms,
                private_binding_retain_until_ms, charged_reference_bytes, metadata_token
         FROM native_projection_state ORDER BY conversation_id",
    )?;
    let rows = statement.query_map([], raw_projection_row)?;
    let mut totals = ProjectionTotals::default();
    let mut projected_conversations = HashSet::new();
    for raw in rows {
        let projection = authenticate_projection_row(key_bundle, raw?)?;
        totals.physical = checked_add(totals.physical, 1)?;
        if totals.physical > MAX_NATIVE_PROJECTION_ROWS
            || !projected_conversations.insert(projection.conversation_id)
        {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }

        let conversation = super::journal::load_conversation(
            connection,
            key_bundle,
            database_id,
            projection.conversation_id,
        )
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
        let state = super::configuration::load_conversation_state(
            connection,
            key_bundle,
            projection.conversation_id,
        )?;
        let origin_namespace = state
            .origin_namespace()
            .filter(|_| state.is_native_projected())
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        if origin_namespace != projection.origin_namespace
            || projection.projection_catalog_revision != conversation.catalog_revision
        {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        let namespace = AdapterStateNamespace::from_origin_namespace(origin_namespace)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        if namespace.origin_namespace() != origin_namespace
            || conversation.descriptor.agent_kind != namespace.agent_kind()
        {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        let binding = super::journal::load_adapter_state_binding_evidence_for_conversation(
            connection,
            key_bundle,
            database_id,
            namespace,
            &conversation,
        )?;
        match (projection.state, binding) {
            (ProjectionState::Present, Some(binding)) => {
                validate_projection_binding(&projection, &binding)?;
                totals.present = checked_add(totals.present, 1)?;
            }
            (ProjectionState::Tombstone, Some(binding)) => {
                validate_projection_binding(&projection, &binding)?;
                totals.tombstone = checked_add(totals.tombstone, 1)?;
            }
            (ProjectionState::Retired, None) if projection.charged_reference_bytes == 0 => {
                totals.retired = checked_add(totals.retired, 1)?;
            }
            _ => return Err(RuntimeStoreError::UnknownOrCorruptSchema),
        }
        totals.charged_bytes =
            checked_add(totals.charged_bytes, projection.charged_reference_bytes)?;
    }
    drop(statement);

    let mut state_statement = connection
        .prepare("SELECT conversation_id FROM conversation_state ORDER BY conversation_id")?;
    let state_rows = state_statement.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
    let mut state_count = 0_u64;
    let mut native_count = 0_u64;
    for raw_conversation_id in state_rows {
        state_count = checked_add(state_count, 1)?;
        let conversation_id = runtime_id(RuntimeIdKind::Conversation, raw_conversation_id?)?;
        let state =
            super::configuration::load_conversation_state(connection, key_bundle, conversation_id)?;
        let has_projection = projected_conversations.contains(&conversation_id);
        if state.is_native_projected() {
            native_count = checked_add(native_count, 1)?;
            if !has_projection {
                return Err(RuntimeStoreError::UnknownOrCorruptSchema);
            }
        } else if !state.is_managed() || has_projection {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
    }
    if state_count != ledger.conversation_count
        || native_count != totals.physical
        || totals
            .tombstone
            .checked_add(totals.retired)
            .is_none_or(|value| value > MAX_NATIVE_NONLIVE_IDENTITIES)
        || state_count
            .checked_sub(totals.tombstone + totals.retired)
            .is_none_or(|live| live > MAX_RUNTIME_LIVE_CONVERSATIONS)
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(totals)
}

fn validate_projection_binding(
    projection: &AuthenticatedProjectionRow,
    binding: &super::journal::AuthenticatedAdapterStateBindingEvidence,
) -> Result<(), RuntimeStoreError> {
    if binding.reference_token() != &projection.state_reference_token
        || binding.sealed_reference_bytes() != projection.charged_reference_bytes
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(())
}

fn raw_projection_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawProjectionRow> {
    Ok(RawProjectionRow {
        conversation_id: row.get(0)?,
        origin_namespace: row.get(1)?,
        state_reference_token: row.get(2)?,
        projection_state: row.get(3)?,
        scan_generation: row.get(4)?,
        observation_token: row.get(5)?,
        projection_catalog_revision: row.get(6)?,
        reconciled_at_ms: row.get(7)?,
        state_changed_at_ms: row.get(8)?,
        private_binding_retain_until_ms: row.get(9)?,
        charged_reference_bytes: row.get(10)?,
        metadata_token: row.get(11)?,
    })
}

fn authenticate_projection_row(
    key_bundle: &RuntimeKeyBundle,
    raw: RawProjectionRow,
) -> Result<AuthenticatedProjectionRow, RuntimeStoreError> {
    let conversation_id = runtime_id(RuntimeIdKind::Conversation, raw.conversation_id)?;
    let state_reference_token = fixed::<32>(raw.state_reference_token)?;
    let scan_generation = fixed::<16>(raw.scan_generation)?;
    let observation_token = fixed::<32>(raw.observation_token)?;
    let metadata_token = fixed::<32>(raw.metadata_token)?;
    let state = ProjectionState::parse(&raw.projection_state)?;
    let projection_catalog_revision = decode_sequence(
        SequenceScope::CatalogRevision,
        &raw.projection_catalog_revision,
    )?;
    let reconciled_at_ms = nonnegative(raw.reconciled_at_ms)?;
    let state_changed_at_ms = nonnegative(raw.state_changed_at_ms)?;
    let retain_until_ms = raw
        .private_binding_retain_until_ms
        .map(nonnegative)
        .transpose()?;
    let charged_reference_bytes = nonnegative(raw.charged_reference_bytes)?;
    if scan_generation == [0; 16] {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    match state {
        ProjectionState::Present
            if state_changed_at_ms <= reconciled_at_ms
                && retain_until_ms.is_none()
                && (60..=563).contains(&charged_reference_bytes) => {}
        ProjectionState::Tombstone
            if state_changed_at_ms <= reconciled_at_ms
                && state_changed_at_ms
                    .checked_add(2_592_000_000)
                    .is_some_and(|expected| retain_until_ms == Some(expected))
                && (60..=563).contains(&charged_reference_bytes) => {}
        ProjectionState::Retired
            if retain_until_ms.is_some_and(|retain| state_changed_at_ms >= retain)
                && charged_reference_bytes == 0 => {}
        _ => return Err(RuntimeStoreError::UnknownOrCorruptSchema),
    }
    let expected = projection_metadata_token(
        key_bundle,
        conversation_id,
        &raw.origin_namespace,
        &state_reference_token,
        state,
        &scan_generation,
        &observation_token,
        &raw.projection_catalog_revision,
        reconciled_at_ms,
        state_changed_at_ms,
        retain_until_ms,
        charged_reference_bytes,
    )?;
    if metadata_token != expected {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(AuthenticatedProjectionRow {
        conversation_id,
        origin_namespace: raw.origin_namespace,
        state_reference_token,
        state,
        scan_generation,
        observation_token,
        projection_catalog_revision,
        reconciled_at_ms,
        state_changed_at_ms,
        retain_until_ms,
        charged_reference_bytes,
        metadata_token,
    })
}

fn load_projection_by_reference_token(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    namespace: AdapterStateNamespace,
    reference_token: &[u8; 32],
) -> Result<Option<AuthenticatedProjectionRow>, RuntimeStoreError> {
    let raw = connection
        .query_row(
            "SELECT conversation_id, origin_namespace, state_reference_token,
                    projection_state, scan_generation, observation_token,
                    projection_catalog_revision, reconciled_at_ms, state_changed_at_ms,
                    private_binding_retain_until_ms, charged_reference_bytes, metadata_token
             FROM native_projection_state
             WHERE origin_namespace = ?1 AND state_reference_token = ?2",
            params![namespace.origin_namespace(), &reference_token[..]],
            raw_projection_row,
        )
        .optional()?;
    raw.map(|row| authenticate_projection_row(key_bundle, row))
        .transpose()
}

struct ExistingNativeProjection {
    projection: AuthenticatedProjectionRow,
    conversation: ConversationRecord,
    configuration: ConfigurationRecord,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum NativeCatalogChange {
    Upsert,
    Removed,
}

pub(super) fn authenticated_native_catalog_change(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    conversation: &ConversationRecord,
) -> Result<Option<NativeCatalogChange>, RuntimeStoreError> {
    let raw = connection
        .query_row(
            "SELECT conversation_id, origin_namespace, state_reference_token,
                    projection_state, scan_generation, observation_token,
                    projection_catalog_revision, reconciled_at_ms, state_changed_at_ms,
                    private_binding_retain_until_ms, charged_reference_bytes, metadata_token
             FROM native_projection_state WHERE conversation_id = ?1",
            [&conversation.conversation_id.as_bytes()[..]],
            raw_projection_row,
        )
        .optional()?;
    let state = super::configuration::load_conversation_state(
        connection,
        key_bundle,
        conversation.conversation_id,
    )?;
    if state.is_managed() {
        return if raw.is_none() {
            Ok(None)
        } else {
            Err(RuntimeStoreError::UnknownOrCorruptSchema)
        };
    }
    let projection = raw
        .map(|row| authenticate_projection_row(key_bundle, row))
        .transpose()?
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let namespace = state
        .origin_namespace()
        .and_then(AdapterStateNamespace::from_origin_namespace)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    if !state.is_native_projected()
        || projection.conversation_id != conversation.conversation_id
        || projection.origin_namespace != namespace.origin_namespace()
        || projection.projection_catalog_revision != conversation.catalog_revision
        || conversation.descriptor.agent_kind != namespace.agent_kind()
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let binding = super::journal::load_adapter_state_binding_evidence_for_conversation(
        connection,
        key_bundle,
        database_id,
        namespace,
        conversation,
    )?;
    match (projection.state, binding) {
        (ProjectionState::Present, Some(binding)) | (ProjectionState::Tombstone, Some(binding)) => {
            validate_projection_binding(&projection, &binding)?;
        }
        (ProjectionState::Retired, None) if projection.charged_reference_bytes == 0 => {}
        _ => return Err(RuntimeStoreError::UnknownOrCorruptSchema),
    }
    Ok(Some(match projection.state {
        ProjectionState::Present => NativeCatalogChange::Upsert,
        ProjectionState::Tombstone | ProjectionState::Retired => NativeCatalogChange::Removed,
    }))
}

fn load_existing_native_projection(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    namespace: AdapterStateNamespace,
    reference_token: &[u8; 32],
    private_reference: &SecretBytes,
) -> Result<Option<ExistingNativeProjection>, RuntimeStoreError> {
    let projection =
        load_projection_by_reference_token(connection, key_bundle, namespace, reference_token)?;
    let owner = super::journal::load_authenticated_adapter_state_owner_by_reference_token(
        connection,
        key_bundle,
        database_id,
        namespace,
        reference_token,
    )?;
    let (projection, (conversation, stored_reference)) = match (projection, owner) {
        (None, None) => return Ok(None),
        (Some(projection), Some(owner)) => (projection, owner),
        _ => return Err(RuntimeStoreError::UnknownOrCorruptSchema),
    };
    if stored_reference.expose_secret() != private_reference.expose_secret()
        || projection.conversation_id != conversation.conversation_id
        || projection.origin_namespace != namespace.origin_namespace()
        || projection.state_reference_token != *reference_token
        || projection.projection_catalog_revision != conversation.catalog_revision
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let state = super::configuration::load_conversation_state(
        connection,
        key_bundle,
        conversation.conversation_id,
    )?;
    if !state.is_native_projected()
        || state.origin_namespace() != Some(namespace.origin_namespace())
        || conversation.descriptor.agent_kind != namespace.agent_kind()
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let current_revision = state.current_revision()?;
    if current_revision == 0 {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let configuration = super::configuration::load_authenticated_configuration_at_revision(
        connection,
        key_bundle,
        database_id,
        conversation.conversation_id,
        current_revision,
    )?;
    Ok(Some(ExistingNativeProjection {
        projection,
        conversation,
        configuration,
    }))
}

#[allow(clippy::too_many_arguments)]
fn projection_metadata_token(
    key_bundle: &RuntimeKeyBundle,
    conversation_id: RuntimeId,
    origin_namespace: &str,
    state_reference_token: &[u8; 32],
    state: ProjectionState,
    scan_generation: &[u8; 16],
    observation_token: &[u8; 32],
    projection_catalog_revision: &str,
    reconciled_at_ms: u64,
    state_changed_at_ms: u64,
    retain_until_ms: Option<u64>,
    charged_reference_bytes: u64,
) -> Result<[u8; 32], RuntimeStoreError> {
    let retain_bytes = retain_until_ms.map(u64::to_be_bytes);
    let retain_field = optional_field(retain_bytes.as_ref().map(|value| &value[..]));
    metadata_mac(
        key_bundle,
        PROJECTION_METADATA_DOMAIN,
        &[
            conversation_id.as_bytes(),
            origin_namespace.as_bytes(),
            state_reference_token,
            state.as_str().as_bytes(),
            scan_generation,
            observation_token,
            projection_catalog_revision.as_bytes(),
            &reconciled_at_ms.to_be_bytes(),
            &state_changed_at_ms.to_be_bytes(),
            &retain_field,
            &charged_reference_bytes.to_be_bytes(),
        ],
    )
}

fn validate_effect_fence_integrity(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    ledger: &RuntimeLedger,
) -> Result<EffectFenceTotals, RuntimeStoreError> {
    let mut statement = connection.prepare(
        "SELECT conversation_id, idempotency_token, daemon_boot_id,
                effect_nonce_token, effect_spec_token, process_group_id,
                leader_pid, leader_start_time, release_authorized_at_ms,
                release_token_commitment, logical_fence_bytes, metadata_token, sealed_fence
         FROM native_metadata_effect_fences
         ORDER BY conversation_id, idempotency_token",
    )?;
    let rows = statement.query_map([], raw_effect_fence_row)?;
    let mut totals = EffectFenceTotals::default();
    let mut fence_keys = HashSet::new();
    for raw in rows {
        let fence = authenticate_effect_fence_row(key_bundle, database_id, raw?)?;
        totals.total = checked_add(totals.total, 1)?;
        if totals.total > MAX_METADATA_EFFECT_FENCE_ROWS
            || !fence_keys.insert((fence.conversation_id, fence.idempotency_token))
        {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        let parent = super::metadata::load_authenticated_metadata_mutation_parent(
            connection,
            key_bundle,
            database_id,
            fence.conversation_id,
            &fence.idempotency_token,
        )?
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        let conversation_state = super::configuration::load_conversation_state(
            connection,
            key_bundle,
            fence.conversation_id,
        )?;
        if !conversation_state.is_native_projected()
            || !parent.is_rename()
            || parent.is_claimed()
            || parent.conversation_id() != fence.conversation_id
            || parent.idempotency_token() != &fence.idempotency_token
        {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        match fence.release_authorized_at_ms {
            None if parent.is_applying() => {
                totals.unreleased = checked_add(totals.unreleased, 1)?;
            }
            None => return Err(RuntimeStoreError::UnknownOrCorruptSchema),
            Some(released_at)
                if released_at >= parent.created_at_ms()
                    && ((parent.is_applying() && released_at >= parent.state_changed_at_ms())
                        || ((parent.is_outcome_unknown()
                            || parent.is_applied()
                            || parent.is_failed())
                            && released_at <= parent.state_changed_at_ms())) =>
            {
                totals.released = checked_add(totals.released, 1)?;
            }
            Some(_) => return Err(RuntimeStoreError::UnknownOrCorruptSchema),
        }
    }
    drop(statement);

    let mut parent_statement = connection.prepare(
        "SELECT conversation_id, idempotency_token
         FROM metadata_mutation_ledger ORDER BY conversation_id, idempotency_token",
    )?;
    let parents = parent_statement.query_map([], |row| {
        Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
    })?;
    let mut parent_count = 0_u64;
    for parent_key in parents {
        parent_count = checked_add(parent_count, 1)?;
        if parent_count > ledger.metadata_mutation_count {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        let (conversation_id, idempotency_token) = parent_key?;
        let conversation_id = runtime_id(RuntimeIdKind::Conversation, conversation_id)?;
        let idempotency_token = fixed::<32>(idempotency_token)?;
        let parent = super::metadata::load_authenticated_metadata_mutation_parent(
            connection,
            key_bundle,
            database_id,
            conversation_id,
            &idempotency_token,
        )?
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        let has_fence = fence_keys.contains(&(conversation_id, idempotency_token));
        let conversation_state =
            super::configuration::load_conversation_state(connection, key_bundle, conversation_id)?;
        if conversation_state.is_managed() {
            if has_fence {
                return Err(RuntimeStoreError::UnknownOrCorruptSchema);
            }
            continue;
        }
        if !conversation_state.is_native_projected() || !parent.is_rename() {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        let valid_presence = if parent.is_claimed() {
            !has_fence
        } else if parent.is_applying() || parent.is_outcome_unknown() || parent.is_applied() {
            has_fence
        } else {
            parent.is_failed()
        };
        if !valid_presence {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
    }
    if parent_count != ledger.metadata_mutation_count {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(totals)
}

fn raw_effect_fence_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawEffectFenceRow> {
    Ok(RawEffectFenceRow {
        conversation_id: row.get(0)?,
        idempotency_token: row.get(1)?,
        daemon_boot_id: row.get(2)?,
        effect_nonce_token: row.get(3)?,
        effect_spec_token: row.get(4)?,
        process_group_id: row.get(5)?,
        leader_pid: row.get(6)?,
        leader_start_time: row.get(7)?,
        release_authorized_at_ms: row.get(8)?,
        release_token_commitment: row.get(9)?,
        logical_fence_bytes: row.get(10)?,
        metadata_token: row.get(11)?,
        sealed_fence: row.get(12)?,
    })
}

fn authenticate_effect_fence_row(
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    raw: RawEffectFenceRow,
) -> Result<AuthenticatedEffectFenceRow, RuntimeStoreError> {
    let conversation_id = runtime_id(RuntimeIdKind::Conversation, raw.conversation_id)?;
    let idempotency_token = fixed::<32>(raw.idempotency_token)?;
    let daemon_boot_id = runtime_id(RuntimeIdKind::DaemonBoot, raw.daemon_boot_id)?;
    let effect_nonce_token = fixed::<32>(raw.effect_nonce_token)?;
    let effect_spec_token = fixed::<32>(raw.effect_spec_token)?;
    let leader_start_time =
        decode_sequence(SequenceScope::LeaderStartTime, &raw.leader_start_time)?;
    let process_identity =
        ProcessIdentity::new(raw.process_group_id, raw.leader_pid, leader_start_time)
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let process_group_id = u64::try_from(process_identity.process_group_id())
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let leader_pid = u64::try_from(process_identity.leader_pid())
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let release_authorized_at_ms = raw.release_authorized_at_ms.map(nonnegative).transpose()?;
    let release_token_commitment = raw.release_token_commitment.map(fixed::<32>).transpose()?;
    if release_authorized_at_ms.is_some() != release_token_commitment.is_some() {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let logical_fence_bytes = nonnegative(raw.logical_fence_bytes)?;
    let sealed_fence_bytes = u64::try_from(raw.sealed_fence.len())
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let release_time_bytes = release_authorized_at_ms.map(u64::to_be_bytes);
    let release_time_field = optional_field(release_time_bytes.as_ref().map(|value| &value[..]));
    let release_commitment_field =
        optional_field(release_token_commitment.as_ref().map(|value| &value[..]));
    let expected_metadata_token = metadata_mac(
        key_bundle,
        EFFECT_FENCE_METADATA_DOMAIN,
        &[
            conversation_id.as_bytes(),
            &idempotency_token,
            daemon_boot_id.as_bytes(),
            &effect_nonce_token,
            &effect_spec_token,
            &process_group_id.to_be_bytes(),
            &leader_pid.to_be_bytes(),
            raw.leader_start_time.as_bytes(),
            &release_time_field,
            &release_commitment_field,
            &logical_fence_bytes.to_be_bytes(),
            &sealed_fence_bytes.to_be_bytes(),
        ],
    )?;
    if fixed::<32>(raw.metadata_token)? != expected_metadata_token {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let primary_key = effect_fence_primary_key(conversation_id, &idempotency_token);
    let plaintext = open_v4_row(
        key_bundle,
        database_id,
        EFFECT_FENCE_TABLE,
        &primary_key,
        EFFECT_FENCE_COLUMN,
        &raw.sealed_fence,
        MAX_EFFECT_FENCE_PLAINTEXT_BYTES,
    )?;
    if u64::try_from(plaintext.expose_secret().len())
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
        != logical_fence_bytes
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let fields = decode_effect_fence_payload(plaintext.expose_secret())?;
    if fields[0] != conversation_id.as_bytes()
        || fields[1] != idempotency_token
        || fields[2] != daemon_boot_id.as_bytes()
        || fields[3].is_empty()
        || fields[3].len() > MAX_EFFECT_NONCE_BYTES
        || fields[4].is_empty()
        || fields[4].len() > MAX_EFFECT_SPEC_BYTES
        || decode_u64_field(fields[5])? != process_group_id
        || decode_u64_field(fields[6])? != leader_pid
        || decode_u64_field(fields[7])? != leader_start_time
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let expected_nonce_token = metadata_mac(
        key_bundle,
        EFFECT_NONCE_DOMAIN,
        &[
            conversation_id.as_bytes(),
            &idempotency_token,
            daemon_boot_id.as_bytes(),
            fields[3],
        ],
    )?;
    let expected_spec_token = metadata_mac(
        key_bundle,
        EFFECT_SPEC_DOMAIN,
        &[conversation_id.as_bytes(), &idempotency_token, fields[4]],
    )?;
    let expected_release_commitment = release_authorized_at_ms
        .map(|released_at| {
            metadata_mac(
                key_bundle,
                EFFECT_RELEASE_DOMAIN,
                &[
                    conversation_id.as_bytes(),
                    &idempotency_token,
                    daemon_boot_id.as_bytes(),
                    fields[3],
                    &released_at.to_be_bytes(),
                ],
            )
        })
        .transpose()?;
    if effect_nonce_token != expected_nonce_token
        || effect_spec_token != expected_spec_token
        || release_token_commitment != expected_release_commitment
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(AuthenticatedEffectFenceRow {
        conversation_id,
        idempotency_token,
        release_authorized_at_ms,
    })
}

fn effect_fence_primary_key(conversation_id: RuntimeId, idempotency_token: &[u8; 32]) -> Vec<u8> {
    let mut primary_key = Vec::with_capacity(4 + 16 + 32);
    primary_key.extend_from_slice(EFFECT_FENCE_PRIMARY_KEY_MAGIC);
    primary_key.extend_from_slice(conversation_id.as_bytes());
    primary_key.extend_from_slice(idempotency_token);
    primary_key
}

fn decode_effect_fence_payload(payload: &[u8]) -> Result<Vec<&[u8]>, RuntimeStoreError> {
    if payload.len() < EFFECT_FENCE_PAYLOAD_MAGIC.len()
        || &payload[..EFFECT_FENCE_PAYLOAD_MAGIC.len()] != EFFECT_FENCE_PAYLOAD_MAGIC
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let mut cursor = EFFECT_FENCE_PAYLOAD_MAGIC.len();
    let mut fields = Vec::with_capacity(8);
    while cursor < payload.len() {
        let length_end = cursor
            .checked_add(4)
            .filter(|end| *end <= payload.len())
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        let length = u32::from_be_bytes(
            payload[cursor..length_end]
                .try_into()
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
        );
        cursor = length_end;
        let field_end = cursor
            .checked_add(
                usize::try_from(length).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            )
            .filter(|end| *end <= payload.len())
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        fields.push(&payload[cursor..field_end]);
        cursor = field_end;
        if fields.len() > 8 {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
    }
    if cursor != payload.len() || fields.len() != 8 {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(fields)
}

fn decode_u64_field(field: &[u8]) -> Result<u64, RuntimeStoreError> {
    Ok(u64::from_be_bytes(
        field
            .try_into()
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
    ))
}

fn runtime_id(kind: RuntimeIdKind, value: Vec<u8>) -> Result<RuntimeId, RuntimeStoreError> {
    Ok(RuntimeId::from_bytes(
        kind,
        value
            .try_into()
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
    )?)
}

fn fixed<const N: usize>(value: Vec<u8>) -> Result<[u8; N], RuntimeStoreError> {
    value
        .try_into()
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)
}

fn nonnegative(value: i64) -> Result<u64, RuntimeStoreError> {
    u64::try_from(value).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)
}

fn checked_add(left: u64, right: u64) -> Result<u64, RuntimeStoreError> {
    left.checked_add(right)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use agentdeck_protocol::AgentKind;
    use rusqlite::{Connection, params};

    use super::*;
    use crate::runtime::events::CommandStreamEffects;
    use crate::runtime::model::{ConversationDescriptor, NewConversation, RuntimeStoreConfig};
    use crate::runtime::store::schema::{
        RUNTIME_DDL_V1, RUNTIME_MIGRATION_V2, RUNTIME_MIGRATION_V3, RUNTIME_MIGRATION_V4,
        RUNTIME_MIGRATION_V5, RUNTIME_MIGRATION_V6,
    };
    use crate::runtime::store::sequence::encode_sequence;
    use crate::security::{MemoryKeyStore, SecretBytes, load_or_create_storage_kek};

    static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new(label: &str) -> Self {
            let sequence = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "agentdeck-native-projection-{label}-{}-{sequence}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir(&path).expect("create native projection test root");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                    .expect("secure native projection test root");
            }
            Self(path)
        }

        fn database(&self) -> PathBuf {
            self.0.join("runtime.db")
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn test_runtime_id(kind: RuntimeIdKind, byte: u8) -> RuntimeId {
        RuntimeId::from_bytes(kind, [byte; 16]).expect("valid fixture RuntimeId")
    }

    fn encode_effect_fence_payload(fields: &[&[u8]]) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(EFFECT_FENCE_PAYLOAD_MAGIC);
        for field in fields {
            payload.extend_from_slice(
                &u32::try_from(field.len())
                    .expect("bounded effect fixture field")
                    .to_be_bytes(),
            );
            payload.extend_from_slice(field);
        }
        payload
    }

    fn install_valid_projection_and_released_fence(
        state: &mut super::super::sqlite::RuntimeSqlite,
        config: &RuntimeStoreConfig,
    ) -> (RuntimeId, [u8; 32]) {
        let conversation_id = test_runtime_id(RuntimeIdKind::Conversation, 0x31);
        let adapter_state_key = test_runtime_id(RuntimeIdKind::AdapterState, 0x32);
        let descriptor = ConversationDescriptor {
            agent_kind: AgentKind::ClaudeCode,
            title: Some("native projection fixture".to_owned()),
            cwd: PathBuf::from("/tmp/native-projection-fixture"),
        };
        let descriptor_bytes =
            super::super::journal::canonical_conversation_descriptor(&descriptor)
                .expect("encode fixture descriptor");
        let mut effects = CommandStreamEffects::default();
        super::super::journal::create_conversation(
            state,
            config,
            NewConversation {
                conversation_id,
                adapter_state_key,
                descriptor,
            },
            descriptor_bytes,
            &mut effects,
        )
        .expect("create projection fixture conversation");
        super::super::journal::bind_adapter_state(
            state,
            config,
            AdapterStateNamespace::ClaudeCode,
            adapter_state_key,
            SecretBytes::new(vec![0x33; 20]),
        )
        .expect("bind opaque fixture reference");

        let conversation = super::super::journal::load_conversation(
            &state.connection,
            &state.key_bundle,
            state.database_id,
            conversation_id,
        )
        .expect("load authenticated fixture conversation");
        let binding = super::super::journal::load_adapter_state_binding_evidence_for_conversation(
            &state.connection,
            &state.key_bundle,
            state.database_id,
            AdapterStateNamespace::ClaudeCode,
            &conversation,
        )
        .expect("authenticate fixture binding")
        .expect("fixture binding exists");
        let reference_token = *binding.reference_token();
        let charged_reference_bytes = binding.sealed_reference_bytes();
        let key_bundle = state.key_bundle.clone();
        let database_id = state.database_id;
        let transaction = state
            .connection
            .transaction()
            .expect("start native fixture transaction");

        let (current_revision, entry_revision, cutoff): (Option<String>, String, Option<String>) =
            transaction
                .query_row(
                    "SELECT current_configuration_revision, entry_revision,
                        legacy_command_high_water
                 FROM conversation_state WHERE conversation_id = ?1",
                    [&conversation_id.as_bytes()[..]],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .expect("read fixture origin state");
        let origin_token = super::super::configuration::conversation_state_metadata_token(
            &key_bundle,
            conversation_id.as_bytes(),
            current_revision.as_deref(),
            &entry_revision,
            "nativeProjected",
            Some("claude-code"),
            cutoff.as_deref(),
        )
        .expect("authenticate fixture origin");
        transaction
            .execute(
                "UPDATE conversation_state
                 SET origin_kind = 'nativeProjected', origin_namespace = 'claude-code',
                     metadata_token = ?1 WHERE conversation_id = ?2",
                params![&origin_token[..], &conversation_id.as_bytes()[..]],
            )
            .expect("publish fixture native origin");

        let scan_generation = [0x34; 16];
        let observation_token = [0x35; 32];
        let catalog_revision = encode_sequence(conversation.catalog_revision);
        let projection_token = projection_metadata_token(
            &key_bundle,
            conversation_id,
            "claude-code",
            &reference_token,
            ProjectionState::Present,
            &scan_generation,
            &observation_token,
            &catalog_revision,
            101,
            100,
            None,
            charged_reference_bytes,
        )
        .expect("authenticate projection fixture row");
        transaction
            .execute(
                "INSERT INTO native_projection_state (
                     conversation_id, origin_namespace, state_reference_token,
                     projection_state, scan_generation, observation_token,
                     projection_catalog_revision, reconciled_at_ms, state_changed_at_ms,
                     private_binding_retain_until_ms, charged_reference_bytes, metadata_token
                 ) VALUES (?1, 'claude-code', ?2, 'present', ?3, ?4, ?5, 101, 100, NULL, ?6, ?7)",
                params![
                    &conversation_id.as_bytes()[..],
                    &reference_token[..],
                    &scan_generation[..],
                    &observation_token[..],
                    catalog_revision,
                    i64::try_from(charged_reference_bytes).expect("charged bytes fit SQLite"),
                    &projection_token[..],
                ],
            )
            .expect("insert authenticated projection fixture");

        let (idempotency_token, metadata_charged_bytes) =
            super::super::metadata::insert_native_metadata_parent_fixture(
                &transaction,
                &key_bundle,
                database_id,
                conversation_id,
                "native-effect-fixture",
                "applying",
                100,
                110,
            )
            .expect("insert authenticated native metadata parent");
        let daemon_boot_id = test_runtime_id(RuntimeIdKind::DaemonBoot, 0x36);
        let effect_nonce = b"opaque-effect-nonce";
        let effect_spec = br#"{"kind":"rename"}"#;
        let process_group_id = 71_u64;
        let leader_pid = 71_u64;
        let leader_start_time = 73_u64;
        let release_authorized_at_ms = 120_u64;
        let payload = encode_effect_fence_payload(&[
            conversation_id.as_bytes(),
            &idempotency_token,
            daemon_boot_id.as_bytes(),
            effect_nonce,
            effect_spec,
            &process_group_id.to_be_bytes(),
            &leader_pid.to_be_bytes(),
            &leader_start_time.to_be_bytes(),
        ]);
        let effect_nonce_token = metadata_mac(
            &key_bundle,
            EFFECT_NONCE_DOMAIN,
            &[
                conversation_id.as_bytes(),
                &idempotency_token,
                daemon_boot_id.as_bytes(),
                effect_nonce,
            ],
        )
        .expect("authenticate effect nonce");
        let effect_spec_token = metadata_mac(
            &key_bundle,
            EFFECT_SPEC_DOMAIN,
            &[conversation_id.as_bytes(), &idempotency_token, effect_spec],
        )
        .expect("authenticate effect spec");
        let release_commitment = metadata_mac(
            &key_bundle,
            EFFECT_RELEASE_DOMAIN,
            &[
                conversation_id.as_bytes(),
                &idempotency_token,
                daemon_boot_id.as_bytes(),
                effect_nonce,
                &release_authorized_at_ms.to_be_bytes(),
            ],
        )
        .expect("authenticate effect release");
        let primary_key = effect_fence_primary_key(conversation_id, &idempotency_token);
        let sealed_fence = super::super::stream::seal_v4_row(
            &key_bundle,
            database_id,
            EFFECT_FENCE_TABLE,
            &primary_key,
            EFFECT_FENCE_COLUMN,
            &payload,
            MAX_EFFECT_FENCE_PLAINTEXT_BYTES,
        )
        .expect("seal effect fence fixture");
        let logical_fence_bytes = u64::try_from(payload.len()).expect("payload length fits u64");
        let sealed_fence_bytes = u64::try_from(sealed_fence.len()).expect("sealed length fits u64");
        let release_time_field = optional_field(Some(&release_authorized_at_ms.to_be_bytes()));
        let release_commitment_field = optional_field(Some(&release_commitment));
        let leader_start_time_text = encode_sequence(leader_start_time);
        let fence_metadata_token = metadata_mac(
            &key_bundle,
            EFFECT_FENCE_METADATA_DOMAIN,
            &[
                conversation_id.as_bytes(),
                &idempotency_token,
                daemon_boot_id.as_bytes(),
                &effect_nonce_token,
                &effect_spec_token,
                &process_group_id.to_be_bytes(),
                &leader_pid.to_be_bytes(),
                leader_start_time_text.as_bytes(),
                &release_time_field,
                &release_commitment_field,
                &logical_fence_bytes.to_be_bytes(),
                &sealed_fence_bytes.to_be_bytes(),
            ],
        )
        .expect("authenticate effect fence fixture row");
        transaction
            .execute(
                "INSERT INTO native_metadata_effect_fences (
                     conversation_id, idempotency_token, daemon_boot_id,
                     effect_nonce_token, effect_spec_token, process_group_id, leader_pid,
                     leader_start_time, release_authorized_at_ms, release_token_commitment,
                     logical_fence_bytes, metadata_token, sealed_fence
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                params![
                    &conversation_id.as_bytes()[..],
                    &idempotency_token[..],
                    &daemon_boot_id.as_bytes()[..],
                    &effect_nonce_token[..],
                    &effect_spec_token[..],
                    i64::try_from(process_group_id).expect("PGID fits SQLite"),
                    i64::try_from(leader_pid).expect("PID fits SQLite"),
                    leader_start_time_text,
                    i64::try_from(release_authorized_at_ms).expect("release time fits SQLite"),
                    &release_commitment[..],
                    i64::try_from(logical_fence_bytes).expect("logical bytes fit SQLite"),
                    &fence_metadata_token[..],
                    sealed_fence,
                ],
            )
            .expect("insert authenticated effect fence fixture");

        let ledger =
            super::super::sqlite::load_runtime_ledger(&transaction, &key_bundle, database_id)
                .expect("load fixture ledger");
        let mut next = ledger.clone();
        next.native_projection_present_count = 1;
        next.native_projection_physical_count = 1;
        next.native_projection_charged_bytes = charged_reference_bytes;
        next.metadata_mutation_count += 1;
        next.active_metadata_mutation_count += 1;
        next.metadata_mutation_charged_bytes += metadata_charged_bytes;
        next.native_metadata_effect_fence_count = 1;
        next.native_metadata_effect_released_count = 1;
        let _pending_targets = super::super::sqlite::update_runtime_ledger(
            &transaction,
            &key_bundle,
            database_id,
            &ledger,
            &next,
        )
        .expect("publish fixture ledger totals");
        transaction.commit().expect("commit native fixture");
        (conversation_id, idempotency_token)
    }

    fn rewrite_effect_fence_release(
        connection: &Connection,
        key_bundle: &RuntimeKeyBundle,
        conversation_id: RuntimeId,
        idempotency_token: &[u8; 32],
        release_authorized_at_ms: Option<u64>,
    ) {
        let daemon_boot_id = test_runtime_id(RuntimeIdKind::DaemonBoot, 0x36);
        let effect_nonce = b"opaque-effect-nonce";
        let effect_spec = br#"{"kind":"rename"}"#;
        let process_group_id = 71_u64;
        let leader_pid = 71_u64;
        let leader_start_time_text = encode_sequence(73);
        let effect_nonce_token = metadata_mac(
            key_bundle,
            EFFECT_NONCE_DOMAIN,
            &[
                conversation_id.as_bytes(),
                idempotency_token,
                daemon_boot_id.as_bytes(),
                effect_nonce,
            ],
        )
        .expect("recompute fixture nonce token");
        let effect_spec_token = metadata_mac(
            key_bundle,
            EFFECT_SPEC_DOMAIN,
            &[conversation_id.as_bytes(), idempotency_token, effect_spec],
        )
        .expect("recompute fixture spec token");
        let release_commitment = release_authorized_at_ms.map(|released_at| {
            metadata_mac(
                key_bundle,
                EFFECT_RELEASE_DOMAIN,
                &[
                    conversation_id.as_bytes(),
                    idempotency_token,
                    daemon_boot_id.as_bytes(),
                    effect_nonce,
                    &released_at.to_be_bytes(),
                ],
            )
            .expect("recompute fixture release commitment")
        });
        let (logical_fence_bytes, sealed_fence_bytes): (i64, i64) = connection
            .query_row(
                "SELECT logical_fence_bytes, length(sealed_fence)
                 FROM native_metadata_effect_fences
                 WHERE conversation_id = ?1 AND idempotency_token = ?2",
                params![&conversation_id.as_bytes()[..], &idempotency_token[..]],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("read fixture fence lengths");
        let logical_fence_bytes =
            u64::try_from(logical_fence_bytes).expect("logical fixture bytes fit u64");
        let sealed_fence_bytes =
            u64::try_from(sealed_fence_bytes).expect("sealed fixture bytes fit u64");
        let release_time_bytes = release_authorized_at_ms.map(u64::to_be_bytes);
        let release_time_field =
            optional_field(release_time_bytes.as_ref().map(|value| &value[..]));
        let release_commitment_field =
            optional_field(release_commitment.as_ref().map(|value| &value[..]));
        let metadata_token = metadata_mac(
            key_bundle,
            EFFECT_FENCE_METADATA_DOMAIN,
            &[
                conversation_id.as_bytes(),
                idempotency_token,
                daemon_boot_id.as_bytes(),
                &effect_nonce_token,
                &effect_spec_token,
                &process_group_id.to_be_bytes(),
                &leader_pid.to_be_bytes(),
                leader_start_time_text.as_bytes(),
                &release_time_field,
                &release_commitment_field,
                &logical_fence_bytes.to_be_bytes(),
                &sealed_fence_bytes.to_be_bytes(),
            ],
        )
        .expect("recompute fixture fence metadata token");
        connection
            .execute(
                "UPDATE native_metadata_effect_fences
                 SET release_authorized_at_ms = ?1, release_token_commitment = ?2,
                     metadata_token = ?3
                 WHERE conversation_id = ?4 AND idempotency_token = ?5",
                params![
                    release_authorized_at_ms
                        .map(|value| i64::try_from(value).expect("release time fits SQLite")),
                    release_commitment.as_ref().map(|value| &value[..]),
                    &metadata_token[..],
                    &conversation_id.as_bytes()[..],
                    &idempotency_token[..],
                ],
            )
            .expect("rewrite fixture release state");
    }

    #[allow(clippy::too_many_arguments)]
    fn rewrite_projection_row(
        connection: &Connection,
        key_bundle: &RuntimeKeyBundle,
        conversation_id: RuntimeId,
        state: ProjectionState,
        state_reference_token: &[u8; 32],
        catalog_revision: &str,
        scan_generation: &[u8; 16],
        charged_reference_bytes: u64,
    ) {
        let observation_token = [0x35; 32];
        let (reconciled_at_ms, state_changed_at_ms, retain_until_ms) = match state {
            ProjectionState::Present => (101, 100, None),
            ProjectionState::Tombstone => (101, 100, Some(2_592_000_100)),
            ProjectionState::Retired => (101, 2_592_000_100, Some(2_592_000_100)),
        };
        let metadata_token = projection_metadata_token(
            key_bundle,
            conversation_id,
            "claude-code",
            state_reference_token,
            state,
            scan_generation,
            &observation_token,
            catalog_revision,
            reconciled_at_ms,
            state_changed_at_ms,
            retain_until_ms,
            charged_reference_bytes,
        )
        .expect("recompute projection fixture metadata token");
        connection
            .execute(
                "UPDATE native_projection_state
                 SET state_reference_token = ?1, projection_state = ?2,
                     scan_generation = ?3, projection_catalog_revision = ?4,
                     reconciled_at_ms = ?5, state_changed_at_ms = ?6,
                     private_binding_retain_until_ms = ?7,
                     charged_reference_bytes = ?8, metadata_token = ?9
                 WHERE conversation_id = ?10",
                params![
                    &state_reference_token[..],
                    state.as_str(),
                    &scan_generation[..],
                    catalog_revision,
                    i64::try_from(reconciled_at_ms).expect("reconcile time fits SQLite"),
                    i64::try_from(state_changed_at_ms).expect("state time fits SQLite"),
                    retain_until_ms
                        .map(|value| i64::try_from(value).expect("retain time fits SQLite")),
                    i64::try_from(charged_reference_bytes)
                        .expect("charged projection bytes fit SQLite"),
                    &metadata_token[..],
                    &conversation_id.as_bytes()[..],
                ],
            )
            .expect("rewrite projection fixture row");
    }

    fn v6_connection() -> Connection {
        let connection = Connection::open_in_memory().expect("open v6 integrity fixture");
        for schema in [
            RUNTIME_DDL_V1,
            RUNTIME_MIGRATION_V2,
            RUNTIME_MIGRATION_V3,
            RUNTIME_MIGRATION_V4,
            RUNTIME_MIGRATION_V5,
            RUNTIME_MIGRATION_V6,
        ] {
            connection
                .execute_batch(schema)
                .expect("install v6 integrity fixture schema");
        }
        connection
            .pragma_update(None, "foreign_keys", false)
            .expect("disable fixture foreign keys");
        connection
    }

    #[test]
    fn unauthenticated_sidecar_rows_are_rejected() {
        let key_bundle = RuntimeKeyBundle::fresh(1).expect("create fixture key bundle");
        let database_id = [0xA1; 16];

        let projection = v6_connection();
        projection
            .execute(
                "INSERT INTO native_projection_state (
                     conversation_id, origin_namespace, state_reference_token,
                     projection_state, scan_generation, observation_token,
                     projection_catalog_revision, reconciled_at_ms,
                     state_changed_at_ms, private_binding_retain_until_ms,
                     charged_reference_bytes, metadata_token
                 ) VALUES (
                     ?1, 'claude-code', ?2, 'present', ?3, ?4,
                     '00000000000000000000', 1, 1, NULL, 60, ?5
                 )",
                params![
                    &[0x11_u8; 16][..],
                    &[0x12_u8; 32][..],
                    &[0x13_u8; 16][..],
                    &[0x14_u8; 32][..],
                    &[0x15_u8; 32][..],
                ],
            )
            .expect("insert unauthenticated projection row");
        assert!(matches!(
            validate_v6_integrity(
                &projection,
                &key_bundle,
                database_id,
                &RuntimeLedger::default(),
            ),
            Err(RuntimeStoreError::UnknownOrCorruptSchema)
        ));

        let fence = v6_connection();
        fence
            .execute(
                "INSERT INTO native_metadata_effect_fences (
                     conversation_id, idempotency_token, daemon_boot_id,
                     effect_nonce_token, effect_spec_token, process_group_id,
                     leader_pid, leader_start_time, release_authorized_at_ms,
                     release_token_commitment, logical_fence_bytes,
                     metadata_token, sealed_fence
                 ) VALUES (
                     ?1, ?2, ?3, ?4, ?5, 71, 72,
                     '00000000000000000073', NULL, NULL, 126, ?6, zeroblob(166)
                 )",
                params![
                    &[0x21_u8; 16][..],
                    &[0x22_u8; 32][..],
                    &[0x23_u8; 16][..],
                    &[0x24_u8; 32][..],
                    &[0x25_u8; 32][..],
                    &[0x26_u8; 32][..],
                ],
            )
            .expect("insert unauthenticated effect fence row");
        assert!(matches!(
            validate_v6_integrity(&fence, &key_bundle, database_id, &RuntimeLedger::default(),),
            Err(RuntimeStoreError::UnknownOrCorruptSchema)
        ));
    }

    #[test]
    fn authenticated_projection_and_released_effect_fence_survive_reopen_and_recovery() {
        let root = TestRoot::new("valid-reopen-recovery");
        let database = root.database();
        let keys = MemoryKeyStore::new();
        let config = RuntimeStoreConfig::new(database.clone());
        let mut state = super::super::sqlite::open(
            &config,
            load_or_create_storage_kek(&keys, &database).expect("create fixture StorageKEK"),
        )
        .expect("open native projection fixture store");
        install_valid_projection_and_released_fence(&mut state, &config);
        super::super::journal::validate_store_integrity(
            &state.connection,
            &state.key_bundle,
            state.database_id,
        )
        .expect("authenticate populated projection/fence store");

        let mut effects = CommandStreamEffects::default();
        let cursor = super::super::journal::begin_recovery_scan(&mut state, &config, &mut effects)
            .expect("begin authenticated native recovery");
        let page = super::super::journal::load_recovery_page(&mut state, cursor)
            .expect("load authenticated native recovery page");
        super::super::journal::finish_recovery_scan(
            &mut state,
            page.completion.expect("single native recovery completion"),
        )
        .expect("finish authenticated native recovery");
        drop(state);

        let reopened = super::super::sqlite::open(
            &config,
            load_or_create_storage_kek(&keys, &database).expect("reload fixture StorageKEK"),
        )
        .expect("reopen authenticated projection/fence store");
        super::super::journal::validate_store_integrity(
            &reopened.connection,
            &reopened.key_bundle,
            reopened.database_id,
        )
        .expect("authenticate reopened projection/fence store");
    }

    #[test]
    fn projection_and_effect_fence_authenticated_fields_and_presence_are_fail_closed() {
        for (label, tamper_sql) in [
            (
                "projection-observation",
                "UPDATE native_projection_state SET observation_token = zeroblob(32)",
            ),
            (
                "projection-generation",
                "UPDATE native_projection_state
                 SET scan_generation = X'41414141414141414141414141414141'",
            ),
            (
                "projection-namespace",
                "UPDATE native_projection_state SET origin_namespace = 'codex'",
            ),
            (
                "projection-catalog-revision",
                "UPDATE native_projection_state
                 SET projection_catalog_revision = '00000000000000000001'",
            ),
            (
                "projection-reference-token",
                "UPDATE native_projection_state SET state_reference_token = zeroblob(32)",
            ),
            (
                "projection-charged-bytes",
                "UPDATE native_projection_state SET charged_reference_bytes = 61",
            ),
            (
                "effect-spec-token",
                "UPDATE native_metadata_effect_fences SET effect_spec_token = zeroblob(32)",
            ),
            (
                "effect-nonce-token",
                "UPDATE native_metadata_effect_fences SET effect_nonce_token = zeroblob(32)",
            ),
            (
                "effect-daemon-boot",
                "UPDATE native_metadata_effect_fences
                 SET daemon_boot_id = X'51515151515151515151515151515151'",
            ),
            (
                "effect-process-identity",
                "UPDATE native_metadata_effect_fences SET leader_pid = 73",
            ),
            (
                "effect-leader-start-time",
                "UPDATE native_metadata_effect_fences
                 SET leader_start_time = '00000000000000000074'",
            ),
            (
                "effect-release-commitment",
                "UPDATE native_metadata_effect_fences
                 SET release_token_commitment = zeroblob(32)",
            ),
            (
                "effect-sealed-payload",
                "UPDATE native_metadata_effect_fences
                 SET sealed_fence = zeroblob(length(sealed_fence))",
            ),
            ("projection-delete", "DELETE FROM native_projection_state"),
            (
                "effect-fence-delete",
                "DELETE FROM native_metadata_effect_fences",
            ),
        ] {
            let root = TestRoot::new(label);
            let database = root.database();
            let keys = MemoryKeyStore::new();
            let config = RuntimeStoreConfig::new(database.clone());
            let mut state = super::super::sqlite::open(
                &config,
                load_or_create_storage_kek(&keys, &database).expect("create tamper StorageKEK"),
            )
            .expect("open tamper fixture store");
            install_valid_projection_and_released_fence(&mut state, &config);
            state
                .connection
                .execute_batch(tamper_sql)
                .unwrap_or_else(|error| panic!("apply {label} tamper: {error}"));
            assert!(
                super::super::journal::validate_store_integrity(
                    &state.connection,
                    &state.key_bundle,
                    state.database_id,
                )
                .is_err(),
                "{label} tamper must fail closed"
            );
        }
    }

    #[test]
    fn authenticated_projection_and_fence_ledger_divergence_is_rejected() {
        for fence_divergence in [false, true] {
            let label = if fence_divergence {
                "fence-ledger"
            } else {
                "projection-ledger"
            };
            let root = TestRoot::new(label);
            let database = root.database();
            let keys = MemoryKeyStore::new();
            let config = RuntimeStoreConfig::new(database.clone());
            let mut state = super::super::sqlite::open(
                &config,
                load_or_create_storage_kek(&keys, &database).expect("create ledger StorageKEK"),
            )
            .expect("open ledger fixture store");
            install_valid_projection_and_released_fence(&mut state, &config);
            let key_bundle = state.key_bundle.clone();
            let database_id = state.database_id;
            let transaction = state
                .connection
                .transaction()
                .expect("start resigned ledger divergence");
            let ledger =
                super::super::sqlite::load_runtime_ledger(&transaction, &key_bundle, database_id)
                    .expect("load authenticated fixture ledger");
            let mut next = ledger.clone();
            if fence_divergence {
                next.native_metadata_effect_unreleased_count = 1;
                next.native_metadata_effect_released_count = 0;
            } else {
                next.native_projection_present_count = 0;
                next.native_projection_tombstone_count = 1;
            }
            let _pending_targets = super::super::sqlite::update_runtime_ledger(
                &transaction,
                &key_bundle,
                database_id,
                &ledger,
                &next,
            )
            .expect("publish authenticated divergent totals");
            transaction.commit().expect("commit divergent totals");
            assert!(
                super::super::journal::validate_store_integrity(
                    &state.connection,
                    &state.key_bundle,
                    state.database_id,
                )
                .is_err(),
                "{label} authenticated divergence must fail closed"
            );
        }
    }

    #[test]
    fn native_metadata_effect_parent_lifecycle_matrix_is_enforced() {
        for (case, expected_valid) in [
            ("applying-unreleased", true),
            ("claimed-none", true),
            ("claimed-fence", false),
            ("outcome-unknown-released", true),
            ("outcome-unknown-unreleased", false),
            ("failed-released", true),
            ("failed-none", true),
            ("failed-unreleased", false),
        ] {
            let root = TestRoot::new(case);
            let database = root.database();
            let keys = MemoryKeyStore::new();
            let config = RuntimeStoreConfig::new(database.clone());
            let mut state = super::super::sqlite::open(
                &config,
                load_or_create_storage_kek(&keys, &database).expect("create lifecycle StorageKEK"),
            )
            .expect("open lifecycle fixture store");
            let (conversation_id, idempotency_token) =
                install_valid_projection_and_released_fence(&mut state, &config);
            let key_bundle = state.key_bundle.clone();
            let database_id = state.database_id;
            let transaction = state
                .connection
                .transaction()
                .expect("start lifecycle fixture rewrite");
            let ledger =
                super::super::sqlite::load_runtime_ledger(&transaction, &key_bundle, database_id)
                    .expect("load lifecycle fixture ledger");
            let mut next = ledger.clone();
            match case {
                "applying-unreleased" => {
                    rewrite_effect_fence_release(
                        &transaction,
                        &key_bundle,
                        conversation_id,
                        &idempotency_token,
                        None,
                    );
                    next.native_metadata_effect_released_count = 0;
                    next.native_metadata_effect_unreleased_count = 1;
                }
                "claimed-none" | "claimed-fence" => {
                    super::super::metadata::rewrite_native_metadata_parent_active_state_fixture(
                        &transaction,
                        &key_bundle,
                        database_id,
                        &idempotency_token,
                        "claimed",
                        105,
                    )
                    .expect("rewrite claimed parent");
                    if case == "claimed-none" {
                        transaction
                            .execute("DELETE FROM native_metadata_effect_fences", [])
                            .expect("remove claimed fixture fence");
                        next.native_metadata_effect_fence_count = 0;
                        next.native_metadata_effect_released_count = 0;
                    }
                }
                "outcome-unknown-released" | "outcome-unknown-unreleased" => {
                    super::super::metadata::rewrite_native_metadata_parent_active_state_fixture(
                        &transaction,
                        &key_bundle,
                        database_id,
                        &idempotency_token,
                        "outcomeUnknown",
                        130,
                    )
                    .expect("rewrite outcome-unknown parent");
                    if case == "outcome-unknown-unreleased" {
                        rewrite_effect_fence_release(
                            &transaction,
                            &key_bundle,
                            conversation_id,
                            &idempotency_token,
                            None,
                        );
                        next.native_metadata_effect_released_count = 0;
                        next.native_metadata_effect_unreleased_count = 1;
                    }
                }
                "failed-released" | "failed-none" | "failed-unreleased" => {
                    let (old_charged, new_charged) =
                        super::super::metadata::rewrite_native_metadata_parent_failed_fixture(
                            &transaction,
                            &key_bundle,
                            database_id,
                            &idempotency_token,
                            130,
                        )
                        .expect("rewrite failed parent");
                    next.active_metadata_mutation_count = next
                        .active_metadata_mutation_count
                        .checked_sub(1)
                        .expect("active fixture count");
                    next.metadata_mutation_charged_bytes = next
                        .metadata_mutation_charged_bytes
                        .checked_sub(old_charged)
                        .and_then(|value| value.checked_add(new_charged))
                        .expect("failed fixture charged bytes");
                    if case == "failed-none" {
                        transaction
                            .execute("DELETE FROM native_metadata_effect_fences", [])
                            .expect("remove failed fixture fence");
                        next.native_metadata_effect_fence_count = 0;
                        next.native_metadata_effect_released_count = 0;
                    } else if case == "failed-unreleased" {
                        rewrite_effect_fence_release(
                            &transaction,
                            &key_bundle,
                            conversation_id,
                            &idempotency_token,
                            None,
                        );
                        next.native_metadata_effect_released_count = 0;
                        next.native_metadata_effect_unreleased_count = 1;
                    }
                }
                _ => unreachable!("fixed lifecycle case"),
            }
            let _pending_targets = super::super::sqlite::update_runtime_ledger(
                &transaction,
                &key_bundle,
                database_id,
                &ledger,
                &next,
            )
            .expect("publish lifecycle fixture totals");
            transaction.commit().expect("commit lifecycle fixture");
            let result = super::super::journal::validate_store_integrity(
                &state.connection,
                &state.key_bundle,
                state.database_id,
            );
            assert_eq!(
                result.is_ok(),
                expected_valid,
                "{case} lifecycle matrix mismatch: {result:?}"
            );
        }
    }

    #[test]
    fn projection_present_tombstone_retired_and_vault_matrix_is_enforced() {
        for projection_state in [
            ProjectionState::Present,
            ProjectionState::Tombstone,
            ProjectionState::Retired,
        ] {
            let root = TestRoot::new(projection_state.as_str());
            let database = root.database();
            let keys = MemoryKeyStore::new();
            let config = RuntimeStoreConfig::new(database.clone());
            let mut state = super::super::sqlite::open(
                &config,
                load_or_create_storage_kek(&keys, &database).expect("create projection StorageKEK"),
            )
            .expect("open projection state fixture");
            let (conversation_id, _) =
                install_valid_projection_and_released_fence(&mut state, &config);
            if projection_state != ProjectionState::Present {
                let key_bundle = state.key_bundle.clone();
                let database_id = state.database_id;
                let transaction = state
                    .connection
                    .transaction()
                    .expect("start projection state rewrite");
                let (reference_token, charged_reference_bytes, catalog_revision): (
                    Vec<u8>,
                    i64,
                    String,
                ) = transaction
                    .query_row(
                        "SELECT state_reference_token, charged_reference_bytes,
                                projection_catalog_revision
                         FROM native_projection_state WHERE conversation_id = ?1",
                        [&conversation_id.as_bytes()[..]],
                        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                    )
                    .expect("read projection state fixture");
                let reference_token: [u8; 32] =
                    reference_token.try_into().expect("fixed reference token");
                let charged_reference_bytes = u64::try_from(charged_reference_bytes)
                    .expect("charged reference bytes fit u64");
                rewrite_projection_row(
                    &transaction,
                    &key_bundle,
                    conversation_id,
                    projection_state,
                    &reference_token,
                    &catalog_revision,
                    &[0x34; 16],
                    if projection_state == ProjectionState::Retired {
                        0
                    } else {
                        charged_reference_bytes
                    },
                );
                let ledger = super::super::sqlite::load_runtime_ledger(
                    &transaction,
                    &key_bundle,
                    database_id,
                )
                .expect("load projection state ledger");
                let mut next = ledger.clone();
                next.native_projection_present_count = 0;
                match projection_state {
                    ProjectionState::Tombstone => {
                        next.native_projection_tombstone_count = 1;
                    }
                    ProjectionState::Retired => {
                        transaction
                            .execute("DELETE FROM claude_code_adapter_state", [])
                            .expect("retire private fixture binding");
                        next.claude_code_adapter_state_count = 0;
                        next.native_projection_retired_count = 1;
                        next.native_projection_charged_bytes = 0;
                    }
                    ProjectionState::Present => unreachable!("handled before transaction"),
                }
                let _pending_targets = super::super::sqlite::update_runtime_ledger(
                    &transaction,
                    &key_bundle,
                    database_id,
                    &ledger,
                    &next,
                )
                .expect("publish projection state totals");
                transaction
                    .commit()
                    .expect("commit projection state fixture");
            }
            super::super::journal::validate_store_integrity(
                &state.connection,
                &state.key_bundle,
                state.database_id,
            )
            .unwrap_or_else(|error| {
                panic!(
                    "{} projection must authenticate: {error:?}",
                    projection_state.as_str()
                )
            });
            drop(state);
            let reopened = super::super::sqlite::open(
                &config,
                load_or_create_storage_kek(&keys, &database).expect("reload projection StorageKEK"),
            )
            .unwrap_or_else(|error| {
                panic!(
                    "{} projection reopen failed: {error:?}",
                    projection_state.as_str()
                )
            });
            drop(reopened);
        }

        for case in [
            "present-missing-binding",
            "present-reference-mismatch",
            "present-charged-mismatch",
            "present-catalog-mismatch",
            "retired-retains-binding",
        ] {
            let root = TestRoot::new(case);
            let database = root.database();
            let keys = MemoryKeyStore::new();
            let config = RuntimeStoreConfig::new(database.clone());
            let mut state = super::super::sqlite::open(
                &config,
                load_or_create_storage_kek(&keys, &database).expect("create vault matrix KEK"),
            )
            .expect("open vault matrix fixture");
            let (conversation_id, _) =
                install_valid_projection_and_released_fence(&mut state, &config);
            let key_bundle = state.key_bundle.clone();
            let database_id = state.database_id;
            let transaction = state
                .connection
                .transaction()
                .expect("start vault matrix rewrite");
            let (reference_token, charged_reference_bytes, catalog_revision): (
                Vec<u8>,
                i64,
                String,
            ) = transaction
                .query_row(
                    "SELECT state_reference_token, charged_reference_bytes,
                            projection_catalog_revision
                     FROM native_projection_state WHERE conversation_id = ?1",
                    [&conversation_id.as_bytes()[..]],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .expect("read vault matrix projection");
            let reference_token: [u8; 32] = reference_token
                .try_into()
                .expect("fixed vault matrix token");
            let charged_reference_bytes =
                u64::try_from(charged_reference_bytes).expect("charged bytes fit u64");
            let ledger =
                super::super::sqlite::load_runtime_ledger(&transaction, &key_bundle, database_id)
                    .expect("load vault matrix ledger");
            let mut next = ledger.clone();
            match case {
                "present-missing-binding" => {
                    transaction
                        .execute("DELETE FROM claude_code_adapter_state", [])
                        .expect("remove present binding");
                    next.claude_code_adapter_state_count = 0;
                }
                "present-reference-mismatch" => rewrite_projection_row(
                    &transaction,
                    &key_bundle,
                    conversation_id,
                    ProjectionState::Present,
                    &[0x91; 32],
                    &catalog_revision,
                    &[0x34; 16],
                    charged_reference_bytes,
                ),
                "present-charged-mismatch" => {
                    rewrite_projection_row(
                        &transaction,
                        &key_bundle,
                        conversation_id,
                        ProjectionState::Present,
                        &reference_token,
                        &catalog_revision,
                        &[0x34; 16],
                        charged_reference_bytes + 1,
                    );
                    next.native_projection_charged_bytes = charged_reference_bytes + 1;
                }
                "present-catalog-mismatch" => rewrite_projection_row(
                    &transaction,
                    &key_bundle,
                    conversation_id,
                    ProjectionState::Present,
                    &reference_token,
                    "00000000000000000001",
                    &[0x34; 16],
                    charged_reference_bytes,
                ),
                "retired-retains-binding" => {
                    rewrite_projection_row(
                        &transaction,
                        &key_bundle,
                        conversation_id,
                        ProjectionState::Retired,
                        &reference_token,
                        &catalog_revision,
                        &[0x34; 16],
                        0,
                    );
                    next.native_projection_present_count = 0;
                    next.native_projection_retired_count = 1;
                    next.native_projection_charged_bytes = 0;
                }
                _ => unreachable!("fixed vault case"),
            }
            let _pending_targets = super::super::sqlite::update_runtime_ledger(
                &transaction,
                &key_bundle,
                database_id,
                &ledger,
                &next,
            )
            .expect("publish vault matrix ledger");
            transaction.commit().expect("commit vault matrix fixture");
            assert!(
                super::super::journal::validate_store_integrity(
                    &state.connection,
                    &state.key_bundle,
                    state.database_id,
                )
                .is_err(),
                "{case} must fail closed"
            );
        }
    }

    #[test]
    fn effect_fence_process_identity_uses_exec_gate_invariants() {
        for (case, tamper_sql) in [
            (
                "broadcast-pgid",
                "UPDATE native_metadata_effect_fences
                 SET process_group_id = 1, leader_pid = 1",
            ),
            (
                "nonleader-pgid",
                "UPDATE native_metadata_effect_fences
                 SET process_group_id = 71, leader_pid = 72",
            ),
            (
                "pid-overflow",
                "UPDATE native_metadata_effect_fences
                 SET process_group_id = 2147483648, leader_pid = 2147483648",
            ),
            (
                "zero-start-time",
                "UPDATE native_metadata_effect_fences
                 SET leader_start_time = '00000000000000000000'",
            ),
        ] {
            let root = TestRoot::new(case);
            let database = root.database();
            let keys = MemoryKeyStore::new();
            let config = RuntimeStoreConfig::new(database.clone());
            let mut state = super::super::sqlite::open(
                &config,
                load_or_create_storage_kek(&keys, &database).expect("create identity KEK"),
            )
            .expect("open identity fixture");
            install_valid_projection_and_released_fence(&mut state, &config);
            state
                .connection
                .execute_batch(tamper_sql)
                .expect("apply invalid process identity");
            assert!(
                super::super::journal::validate_store_integrity(
                    &state.connection,
                    &state.key_bundle,
                    state.database_id,
                )
                .is_err(),
                "{case} must be rejected by ProcessIdentity"
            );
        }
    }

    #[test]
    fn effect_fence_aad_and_decrypted_inner_anchors_are_enforced() {
        for case in [
            "aad-primary-key",
            "sealed-boot",
            "sealed-nonce",
            "sealed-spec",
            "sealed-process",
            "sealed-start-time",
            "resigned-release-commitment",
        ] {
            let root = TestRoot::new(case);
            let database = root.database();
            let keys = MemoryKeyStore::new();
            let config = RuntimeStoreConfig::new(database.clone());
            let mut state = super::super::sqlite::open(
                &config,
                load_or_create_storage_kek(&keys, &database).expect("create inner-anchor KEK"),
            )
            .expect("open inner-anchor fixture");
            let (conversation_id, idempotency_token) =
                install_valid_projection_and_released_fence(&mut state, &config);
            let daemon_boot_id = test_runtime_id(RuntimeIdKind::DaemonBoot, 0x36);
            let mut effect_nonce = b"opaque-effect-nonce".to_vec();
            let mut effect_spec = br#"{"kind":"rename"}"#.to_vec();
            let mut sealed_boot_id = daemon_boot_id;
            let mut process_group_id = 71_u64;
            let mut leader_pid = 71_u64;
            let mut leader_start_time = 73_u64;
            if case == "sealed-boot" {
                sealed_boot_id = test_runtime_id(RuntimeIdKind::DaemonBoot, 0x37);
            } else if case == "sealed-nonce" {
                effect_nonce[0] ^= 0x20;
            } else if case == "sealed-spec" {
                effect_spec[0] ^= 0x01;
            } else if case == "sealed-process" {
                process_group_id = 72;
                leader_pid = 72;
            } else if case == "sealed-start-time" {
                leader_start_time = 74;
            }
            if case == "resigned-release-commitment" {
                let arbitrary_commitment = [0xA7; 32];
                let (logical_fence_bytes, sealed_fence_bytes): (i64, i64) = state
                    .connection
                    .query_row(
                        "SELECT logical_fence_bytes, length(sealed_fence)
                         FROM native_metadata_effect_fences",
                        [],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .expect("read release commitment fixture lengths");
                let release_at = 120_u64;
                let effect_nonce_token = metadata_mac(
                    &state.key_bundle,
                    EFFECT_NONCE_DOMAIN,
                    &[
                        conversation_id.as_bytes(),
                        &idempotency_token,
                        daemon_boot_id.as_bytes(),
                        b"opaque-effect-nonce",
                    ],
                )
                .expect("recompute nonce token for release tamper");
                let effect_spec_token = metadata_mac(
                    &state.key_bundle,
                    EFFECT_SPEC_DOMAIN,
                    &[
                        conversation_id.as_bytes(),
                        &idempotency_token,
                        br#"{"kind":"rename"}"#,
                    ],
                )
                .expect("recompute spec token for release tamper");
                let release_time_field = optional_field(Some(&release_at.to_be_bytes()));
                let release_commitment_field = optional_field(Some(&arbitrary_commitment));
                let metadata_token = metadata_mac(
                    &state.key_bundle,
                    EFFECT_FENCE_METADATA_DOMAIN,
                    &[
                        conversation_id.as_bytes(),
                        &idempotency_token,
                        daemon_boot_id.as_bytes(),
                        &effect_nonce_token,
                        &effect_spec_token,
                        &71_u64.to_be_bytes(),
                        &71_u64.to_be_bytes(),
                        encode_sequence(73).as_bytes(),
                        &release_time_field,
                        &release_commitment_field,
                        &u64::try_from(logical_fence_bytes)
                            .expect("logical bytes fit u64")
                            .to_be_bytes(),
                        &u64::try_from(sealed_fence_bytes)
                            .expect("sealed bytes fit u64")
                            .to_be_bytes(),
                    ],
                )
                .expect("resign arbitrary release commitment");
                state
                    .connection
                    .execute(
                        "UPDATE native_metadata_effect_fences
                         SET release_token_commitment = ?1, metadata_token = ?2",
                        params![&arbitrary_commitment[..], &metadata_token[..]],
                    )
                    .expect("publish resigned arbitrary release commitment");
            } else {
                let payload = encode_effect_fence_payload(&[
                    conversation_id.as_bytes(),
                    &idempotency_token,
                    sealed_boot_id.as_bytes(),
                    &effect_nonce,
                    &effect_spec,
                    &process_group_id.to_be_bytes(),
                    &leader_pid.to_be_bytes(),
                    &leader_start_time.to_be_bytes(),
                ]);
                let primary_key = if case == "aad-primary-key" {
                    effect_fence_primary_key(conversation_id, &[0xA8; 32])
                } else {
                    effect_fence_primary_key(conversation_id, &idempotency_token)
                };
                let transplanted = super::super::stream::seal_v4_row(
                    &state.key_bundle,
                    state.database_id,
                    EFFECT_FENCE_TABLE,
                    &primary_key,
                    EFFECT_FENCE_COLUMN,
                    &payload,
                    MAX_EFFECT_FENCE_PLAINTEXT_BYTES,
                )
                .expect("seal inner-anchor transplant");
                state
                    .connection
                    .execute(
                        "UPDATE native_metadata_effect_fences SET sealed_fence = ?1",
                        [transplanted],
                    )
                    .expect("publish inner-anchor transplant");
            }
            assert!(
                super::super::journal::validate_store_integrity(
                    &state.connection,
                    &state.key_bundle,
                    state.database_id,
                )
                .is_err(),
                "{case} inner anchor must fail closed"
            );
        }
    }

    #[test]
    fn origin_namespace_agent_and_managed_fence_cross_links_are_enforced() {
        for case in ["namespace-agent-mismatch", "managed-with-fence"] {
            let root = TestRoot::new(case);
            let database = root.database();
            let keys = MemoryKeyStore::new();
            let config = RuntimeStoreConfig::new(database.clone());
            let mut state = super::super::sqlite::open(
                &config,
                load_or_create_storage_kek(&keys, &database).expect("create origin KEK"),
            )
            .expect("open origin fixture");
            let (conversation_id, _) =
                install_valid_projection_and_released_fence(&mut state, &config);
            let key_bundle = state.key_bundle.clone();
            let database_id = state.database_id;
            let transaction = state
                .connection
                .transaction()
                .expect("start origin cross-link rewrite");
            let (current_revision, entry_revision, cutoff): (
                Option<String>,
                String,
                Option<String>,
            ) = transaction
                .query_row(
                    "SELECT current_configuration_revision, entry_revision,
                            legacy_command_high_water
                     FROM conversation_state WHERE conversation_id = ?1",
                    [&conversation_id.as_bytes()[..]],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .expect("read origin cross-link state");
            let (origin_kind, origin_namespace) = if case == "managed-with-fence" {
                ("managed", None)
            } else {
                ("nativeProjected", Some("codex"))
            };
            let origin_token = super::super::configuration::conversation_state_metadata_token(
                &key_bundle,
                conversation_id.as_bytes(),
                current_revision.as_deref(),
                &entry_revision,
                origin_kind,
                origin_namespace,
                cutoff.as_deref(),
            )
            .expect("authenticate origin cross-link rewrite");
            transaction
                .execute(
                    "UPDATE conversation_state
                     SET origin_kind = ?1, origin_namespace = ?2, metadata_token = ?3
                     WHERE conversation_id = ?4",
                    params![
                        origin_kind,
                        origin_namespace,
                        &origin_token[..],
                        &conversation_id.as_bytes()[..],
                    ],
                )
                .expect("publish origin cross-link rewrite");
            let ledger =
                super::super::sqlite::load_runtime_ledger(&transaction, &key_bundle, database_id)
                    .expect("load origin cross-link ledger");
            let mut next = ledger.clone();
            if case == "managed-with-fence" {
                transaction
                    .execute("DELETE FROM native_projection_state", [])
                    .expect("remove managed projection row");
                next.native_projection_present_count = 0;
                next.native_projection_physical_count = 0;
                next.native_projection_charged_bytes = 0;
            } else {
                let (reference_token, catalog_revision, charged_reference_bytes): (
                    Vec<u8>,
                    String,
                    i64,
                ) = transaction
                    .query_row(
                        "SELECT state_reference_token, projection_catalog_revision,
                                charged_reference_bytes
                         FROM native_projection_state WHERE conversation_id = ?1",
                        [&conversation_id.as_bytes()[..]],
                        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                    )
                    .expect("read namespace projection row");
                let reference_token: [u8; 32] = reference_token
                    .try_into()
                    .expect("fixed namespace ref token");
                let charged_reference_bytes = u64::try_from(charged_reference_bytes)
                    .expect("namespace charged bytes fit u64");
                let projection_token = projection_metadata_token(
                    &key_bundle,
                    conversation_id,
                    "codex",
                    &reference_token,
                    ProjectionState::Present,
                    &[0x34; 16],
                    &[0x35; 32],
                    &catalog_revision,
                    101,
                    100,
                    None,
                    charged_reference_bytes,
                )
                .expect("authenticate namespace projection rewrite");
                transaction
                    .execute(
                        "UPDATE native_projection_state
                         SET origin_namespace = 'codex', metadata_token = ?1
                         WHERE conversation_id = ?2",
                        params![&projection_token[..], &conversation_id.as_bytes()[..]],
                    )
                    .expect("publish namespace projection rewrite");
            }
            let _pending_targets = super::super::sqlite::update_runtime_ledger(
                &transaction,
                &key_bundle,
                database_id,
                &ledger,
                &next,
            )
            .expect("publish origin cross-link totals");
            transaction
                .commit()
                .expect("commit origin cross-link rewrite");
            let ledger = super::super::sqlite::load_runtime_ledger(
                &state.connection,
                &state.key_bundle,
                state.database_id,
            )
            .expect("authenticate origin cross-link ledger");
            assert!(
                validate_v6_integrity(
                    &state.connection,
                    &state.key_bundle,
                    state.database_id,
                    &ledger,
                )
                .is_err(),
                "{case} must fail C-b2 cross-link audit"
            );
        }
    }
}
