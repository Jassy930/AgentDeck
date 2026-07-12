//! Approval durable ledger：Pending 注册与 first-wins Claim。

use std::mem::size_of;

use agentdeck_protocol::runtime::identity::{ApprovalId, ConversationId, EventId, TurnId};
use agentdeck_protocol::runtime::{ApprovalDeliveryState, RuntimeEvent, RuntimeEventBody};
use agentdeck_protocol::{ActionDecision, ActionRequest};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use zeroize::Zeroizing;

use crate::runtime::approval::ApprovalPolicySnapshot;
use crate::runtime::model::{
    ApprovalMutationOutcome, ApprovalRecord, ApprovalRequestEnvelope, ApprovalState,
    BeginApprovalAttempt, BeginApprovalAttemptOutcome, ClaimApproval, ConversationLifecycle,
    EventRecord, ExpireApproval, MAX_ACTIVE_APPROVALS_GLOBAL, MAX_ACTIVE_APPROVALS_PER_TURN,
    MAX_APPROVAL_DECISION_BYTES, MAX_APPROVAL_REQUEST_BYTES, MAX_APPROVAL_STATUS_DETAIL_BYTES,
    MAX_DURABLE_APPROVALS, MAX_RUNTIME_EVENT_BYTES, MarkApprovalApplied,
    MarkApprovalDeliveryFailed, RegisterApproval, RegisterApprovalOutcome, RetryApprovalDelivery,
    RuntimeCommitOperation, RuntimeStoreConfig, RuntimeStoreError, RuntimeStoreOperation,
};
use crate::security::SecretBytes;

use super::cipher::{RowAad, RuntimeKeyBundle};
use super::identity::{
    MAX_RUNTIME_ID_COLLISION_ATTEMPTS, RuntimeId, RuntimeIdError, RuntimeIdKind,
};
use super::schema::{RUNTIME_CRYPTO_CONTEXT_VERSION, RUNTIME_SCHEMA_FAMILY};
use super::sequence::{AllocatedSequence, SequenceScope, decode_sequence, next_sequence};
use super::sqlite::{self, RuntimeLedger, RuntimeSqlite, SafetyReserveProjection};

const RUNTIME_WRITE_FIXED_OVERHEAD_BYTES: u64 = 64 * 1024;
const MAX_APPROVAL_TRANSITION_EVENT_BYTES: usize = 64 * 1024;
const APPROVAL_REQUEST_TOKEN_DOMAIN: &[u8] = b"approval.request-id.v1";
const APPROVAL_DECISION_TOKEN_DOMAIN: &[u8] = b"approval.decision.v1";
const APPROVAL_CLAIMANT_TOKEN_DOMAIN: &[u8] = b"approval.claimant-token.v1";
const APPROVAL_METADATA_TOKEN_DOMAIN: &[u8] = b"approval.metadata.v1";
const APPROVAL_INTEGRITY_REQUEST_TOKEN_DOMAIN: &[u8] = b"approval.integrity-request.v1";
const MAX_APPROVAL_INTEGRITY_PROJECTION_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone)]
struct ConversationMetadata {
    conversation_id: RuntimeId,
    adapter_state_key: RuntimeId,
    catalog_revision: u64,
    command_high_water: Option<u64>,
    event_high_water: Option<u64>,
    accepted_command_count: u32,
    lifecycle: ConversationLifecycle,
    created_at_ms: u64,
    updated_at_ms: u64,
    metadata_token: Vec<u8>,
}

#[allow(clippy::too_many_arguments)]
struct ApprovalMetadataFields<'a> {
    approval_id: RuntimeId,
    conversation_id: RuntimeId,
    command_id: RuntimeId,
    turn_id: RuntimeId,
    request_token: &'a [u8],
    decision_token: Option<&'a [u8]>,
    claimant_token: Option<&'a [u8]>,
    state: ApprovalState,
    requested_at_ms: u64,
    deadline_at_ms: u64,
    claimed_at_ms: Option<u64>,
    state_changed_at_ms: u64,
    delivery_round: u32,
    attempts_in_round: u8,
    round_started_at_ms: Option<u64>,
    last_attempt_at_ms: Option<u64>,
    state_version: u64,
    last_event_id: RuntimeId,
    logical_request_bytes: u64,
    logical_decision_bytes: u64,
    sealed_request_len: usize,
    sealed_decision_len: Option<usize>,
    sealed_status_detail_len: Option<usize>,
}

struct ApprovalPhysical {
    request_token: Vec<u8>,
    decision_token: Option<Vec<u8>>,
    claimant_token: Option<Vec<u8>>,
    logical_request_bytes: u64,
    metadata_token: Vec<u8>,
    sealed_request_len: usize,
    sealed_decision: Option<Vec<u8>>,
    sealed_status_detail_len: Option<usize>,
}

struct ApprovalTransition {
    state: ApprovalState,
    delivery_round: u32,
    attempts_in_round: u8,
    round_started_at_ms: Option<u64>,
    last_attempt_at_ms: Option<u64>,
    status_detail: Option<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct ApprovalIntegritySummary {
    pub(super) approval_count: u64,
    pub(super) active_approval_count: u64,
    pub(super) approval_event_count: u64,
}

enum ApprovalEventKind {
    Requested,
    Resolved {
        decision: Option<agentdeck_protocol::ActionDecisionKind>,
        state: ApprovalDeliveryState,
    },
}

#[derive(Default)]
struct ApprovalEventChainAccumulator {
    event_count: u64,
    state: Option<ApprovalState>,
    last_event_id: Option<RuntimeId>,
    last_event_seq: Option<u64>,
}

struct ApprovalIntegrityRecord {
    approval_id: RuntimeId,
    command_id: RuntimeId,
    turn_id: RuntimeId,
    expected_state: ApprovalState,
    winner: Option<agentdeck_protocol::ActionDecisionKind>,
    requested_at_ms: u64,
    state_version: u64,
    expected_last_event_id: RuntimeId,
    request_token: [u8; 32],
    chain: ApprovalEventChainAccumulator,
}

pub(crate) fn register_approval(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    input: RegisterApproval,
) -> Result<RegisterApprovalOutcome, RuntimeStoreError> {
    ensure_kind(input.conversation_id, RuntimeIdKind::Conversation)?;
    ensure_kind(input.command_id, RuntimeIdKind::Command)?;
    ensure_kind(input.turn_id, RuntimeIdKind::Turn)?;
    input
        .policy
        .validate_request(&input.request)
        .map_err(|_| RuntimeStoreError::InvalidStateTransition)?;
    let request_bytes = canonical_request(&input.request)?;
    let envelope_bytes = canonical_request_envelope(&input.request, &input.policy)?;
    validate_nonempty_maximum(envelope_bytes.len(), MAX_APPROVAL_REQUEST_BYTES)?;
    let projected_write_bytes = projected_write_bytes(&[
        envelope_bytes.len(),
        request_bytes.len(),
        size_of::<ApprovalRecord>(),
    ])?;
    let requested_at_ms = config.clock.now_ms()?;
    let database_id = state.database_id;
    let key_bundle = &state.key_bundle;
    let request_token = key_bundle.blind_index(
        APPROVAL_REQUEST_TOKEN_DOMAIN,
        input.request.request_id.as_bytes(),
    )?;
    sqlite::admit_ordinary_write(
        &state.connection,
        key_bundle,
        database_id,
        &state.storage_path,
        &mut state.admission_state,
        config.capacity_probe.as_ref(),
        projected_write_bytes,
        SafetyReserveProjection::RegisterApproval,
    )?;
    let transaction = state
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let ledger = sqlite::load_runtime_ledger(&transaction, key_bundle, database_id)?;
    ensure_exact_started_turn(
        &transaction,
        input.conversation_id,
        input.command_id,
        input.turn_id,
        requested_at_ms,
    )?;
    if let Some(existing_id) =
        approval_id_for_request(&transaction, input.turn_id, request_token.as_bytes())?
    {
        let approval = load_approval(&transaction, key_bundle, database_id, existing_id)?;
        if approval.conversation_id != input.conversation_id
            || approval.command_id != input.command_id
            || approval.turn_id != input.turn_id
            || canonical_request_envelope(&approval.request, &approval.policy)?.as_slice()
                != envelope_bytes.as_slice()
        {
            return Err(RuntimeStoreError::IdempotencyConflict);
        }
        let event = load_event(
            &transaction,
            key_bundle,
            database_id,
            approval.last_event_id,
        )?;
        return Ok(RegisterApprovalOutcome::Replayed { approval, event });
    }
    if ledger.approval_count >= MAX_DURABLE_APPROVALS
        || ledger.active_approval_count >= MAX_ACTIVE_APPROVALS_GLOBAL
    {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }
    let active_for_turn: i64 = transaction.query_row(
        "SELECT COUNT(*) FROM approval_ledger
         WHERE turn_id = ?1 AND state IN ('pending', 'claimed', 'applying', 'deliveryFailed')",
        [&input.turn_id.as_bytes()[..]],
        |row| row.get(0),
    )?;
    if u32::try_from(active_for_turn).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
        >= MAX_ACTIVE_APPROVALS_PER_TURN
    {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }
    let deadline_at_ms = input
        .policy
        .effective_deadline_at_ms(requested_at_ms)
        .map_err(|_| RuntimeStoreError::InvalidStateTransition)?;
    let conversation =
        load_conversation_metadata(&transaction, key_bundle, database_id, input.conversation_id)?;
    if requested_at_ms < conversation.updated_at_ms {
        return Err(RuntimeStoreError::ClockRegressed {
            persisted_ms: conversation.updated_at_ms,
            observed_ms: requested_at_ms,
        });
    }
    let previous_event_high_water = conversation
        .event_high_water
        .map(super::sequence::encode_sequence);
    let event_seq = next_sequence(
        SequenceScope::EventSeq,
        previous_event_high_water.as_deref(),
    )?;
    let approval_id = allocate_id(&transaction, config, RuntimeIdKind::Approval)?;
    let event_id = allocate_id(&transaction, config, RuntimeIdKind::Event)?;
    let event_payload = canonical_action_request_event(
        input.conversation_id,
        event_id,
        event_seq.value,
        input.turn_id,
        approval_id,
        &input.request,
    )?;
    validate_nonempty_maximum(event_payload.len(), MAX_RUNTIME_EVENT_BYTES)?;
    let sealed_request = seal(
        key_bundle,
        database_id,
        b"approval_ledger",
        approval_id.as_bytes(),
        b"sealed_request",
        envelope_bytes.as_ref(),
        MAX_APPROVAL_REQUEST_BYTES,
    )?;
    let sealed_event = seal(
        key_bundle,
        database_id,
        b"event_journal",
        event_id.as_bytes(),
        b"sealed_event",
        event_payload.as_ref(),
        MAX_RUNTIME_EVENT_BYTES,
    )?;
    let event_metadata_token = event_metadata_token(
        key_bundle,
        input.conversation_id,
        event_id,
        event_seq.value,
        Some(input.command_id),
        u64::try_from(event_payload.len()).map_err(|_| RuntimeStoreError::PayloadTooLarge)?,
        requested_at_ms,
    )?;
    let approval_metadata_token = approval_metadata_token(
        key_bundle,
        ApprovalMetadataFields {
            approval_id,
            conversation_id: input.conversation_id,
            command_id: input.command_id,
            turn_id: input.turn_id,
            request_token: request_token.as_bytes(),
            decision_token: None,
            claimant_token: None,
            state: ApprovalState::Pending,
            requested_at_ms,
            deadline_at_ms,
            claimed_at_ms: None,
            state_changed_at_ms: requested_at_ms,
            delivery_round: 0,
            attempts_in_round: 0,
            round_started_at_ms: None,
            last_attempt_at_ms: None,
            state_version: 1,
            last_event_id: event_id,
            logical_request_bytes: u64::try_from(envelope_bytes.len())
                .map_err(|_| RuntimeStoreError::PayloadTooLarge)?,
            logical_decision_bytes: 0,
            sealed_request_len: sealed_request.len(),
            sealed_decision_len: None,
            sealed_status_detail_len: None,
        },
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
            sqlite_time(
                u64::try_from(event_payload.len())
                    .map_err(|_| RuntimeStoreError::PayloadTooLarge)?
            )?,
            sqlite_time(requested_at_ms)?,
            &event_metadata_token[..],
            sealed_event,
        ],
    )?;
    transaction.execute(
        "INSERT INTO approval_ledger (
             approval_id, conversation_id, command_id, turn_id,
             request_token, decision_token, claimant_token, state,
             requested_at_ms, deadline_at_ms, claimed_at_ms, state_changed_at_ms,
             delivery_round, attempts_in_round, round_started_at_ms, last_attempt_at_ms,
             state_version, last_event_id, logical_request_bytes, logical_decision_bytes,
             metadata_token, sealed_request, sealed_decision, sealed_status_detail
         ) VALUES (
             ?1, ?2, ?3, ?4, ?5, NULL, NULL, 'pending',
             ?6, ?7, NULL, ?6, 0, 0, NULL, NULL,
             1, ?8, ?9, 0, ?10, ?11, NULL, NULL
         )",
        params![
            &approval_id.as_bytes()[..],
            &input.conversation_id.as_bytes()[..],
            &input.command_id.as_bytes()[..],
            &input.turn_id.as_bytes()[..],
            &request_token.as_bytes()[..],
            sqlite_time(requested_at_ms)?,
            sqlite_time(deadline_at_ms)?,
            &event_id.as_bytes()[..],
            sqlite_time(
                u64::try_from(envelope_bytes.len())
                    .map_err(|_| RuntimeStoreError::PayloadTooLarge)?
            )?,
            &approval_metadata_token[..],
            sealed_request,
        ],
    )?;
    update_conversation_event_high_water(
        &transaction,
        key_bundle,
        conversation,
        &event_seq.encoded,
        previous_event_high_water.as_deref(),
        requested_at_ms,
    )?;
    let mut next_ledger = copy_ledger(&ledger);
    next_ledger.event_count = next_ledger
        .event_count
        .checked_add(1)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    next_ledger.approval_count = next_ledger
        .approval_count
        .checked_add(1)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    next_ledger.active_approval_count = next_ledger
        .active_approval_count
        .checked_add(1)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    sqlite::update_runtime_ledger(&transaction, key_bundle, database_id, &ledger, &next_ledger)?;
    config
        .fault_injector
        .before_operation(RuntimeStoreOperation::RegisterApprovalBeforeCommit)?;
    sqlite::commit_transaction(transaction, RuntimeCommitOperation::RegisterApproval)?;
    sqlite::latch_post_commit_capacity(state, config);
    if config
        .fault_injector
        .before_operation(RuntimeStoreOperation::RegisterApprovalAfterCommit)
        .is_err()
    {
        return Err(RuntimeStoreError::CommitOutcomeUnknown {
            operation: RuntimeCommitOperation::RegisterApproval,
        });
    }
    let approval = ApprovalRecord {
        approval_id,
        conversation_id: input.conversation_id,
        command_id: input.command_id,
        turn_id: input.turn_id,
        state: ApprovalState::Pending,
        request: input.request,
        policy: input.policy,
        decision: None,
        requested_at_ms,
        deadline_at_ms,
        claimed_at_ms: None,
        state_changed_at_ms: requested_at_ms,
        delivery_round: 0,
        attempts_in_round: 0,
        round_started_at_ms: None,
        last_attempt_at_ms: None,
        state_version: 1,
        last_event_id: event_id,
        status_detail: None,
    };
    let event = EventRecord {
        conversation_id: input.conversation_id,
        event_id,
        event_seq: event_seq.value,
        command_id: Some(input.command_id),
        created_at_ms: requested_at_ms,
        payload: event_payload.to_vec(),
    };
    Ok(RegisterApprovalOutcome::Registered { approval, event })
}

pub(crate) fn claim_approval(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    input: ClaimApproval,
) -> Result<ApprovalMutationOutcome, RuntimeStoreError> {
    ensure_kind(input.conversation_id, RuntimeIdKind::Conversation)?;
    ensure_kind(input.turn_id, RuntimeIdKind::Turn)?;
    ensure_kind(input.approval_id, RuntimeIdKind::Approval)?;
    let decision_bytes = canonical_decision(&input.decision)?;
    validate_nonempty_maximum(decision_bytes.len(), MAX_APPROVAL_DECISION_BYTES)?;
    let database_id = state.database_id;
    let key_bundle = &state.key_bundle;
    let decision_token = key_bundle.blind_index(APPROVAL_DECISION_TOKEN_DOMAIN, &decision_bytes)?;
    let claimant_token = key_bundle.blind_index(
        APPROVAL_CLAIMANT_TOKEN_DOMAIN,
        input.claimant_binding.as_bytes(),
    )?;
    let projected_write_bytes = projected_write_bytes(&[
        decision_bytes.len(),
        input.claimant_binding.as_bytes().len(),
        size_of::<ApprovalRecord>(),
    ])?;
    let (_, preflight) = load_authenticated_approval_target(
        &state.connection,
        key_bundle,
        database_id,
        input.approval_id,
    )?;
    if preflight.conversation_id != input.conversation_id || preflight.turn_id != input.turn_id {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }
    preflight
        .policy
        .validate_decision(&preflight.request, &input.decision)
        .map_err(|_| RuntimeStoreError::InvalidStateTransition)?;
    let preflight_at_ms = config.clock.now_ms()?;
    if preflight_at_ms < preflight.state_changed_at_ms {
        return Err(RuntimeStoreError::ClockRegressed {
            persisted_ms: preflight.state_changed_at_ms,
            observed_ms: preflight_at_ms,
        });
    }
    let preflight_stale = preflight_at_ms >= preflight.deadline_at_ms
        || !is_exact_started_turn(
            &state.connection,
            preflight.conversation_id,
            preflight.command_id,
            preflight.turn_id,
        )?;
    if !preflight_stale && preflight.state != ApprovalState::Pending {
        let physical = load_approval_physical(&state.connection, input.approval_id)?;
        return Ok(
            if physical.decision_token.as_deref() == Some(decision_token.as_bytes())
                && physical.claimant_token.as_deref() == Some(claimant_token.as_bytes())
            {
                ApprovalMutationOutcome::Replayed {
                    event: Some(load_event(
                        &state.connection,
                        key_bundle,
                        database_id,
                        preflight.last_event_id,
                    )?),
                    approval: preflight,
                }
            } else {
                ApprovalMutationOutcome::AlreadyHandled {
                    approval: preflight,
                }
            },
        );
    }
    if preflight_stale {
        sqlite::admit_safety_write(
            &state.connection,
            key_bundle,
            database_id,
            &state.storage_path,
            config.capacity_probe.as_ref(),
        )?;
    } else {
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
    }
    let transaction = state
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let (ledger, approval) = load_authenticated_approval_target(
        &transaction,
        key_bundle,
        database_id,
        input.approval_id,
    )?;
    let claimed_at_ms = config.clock.now_ms()?;
    if approval.conversation_id != input.conversation_id || approval.turn_id != input.turn_id {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }
    approval
        .policy
        .validate_decision(&approval.request, &input.decision)
        .map_err(|_| RuntimeStoreError::InvalidStateTransition)?;
    if claimed_at_ms < approval.state_changed_at_ms {
        return Err(RuntimeStoreError::ClockRegressed {
            persisted_ms: approval.state_changed_at_ms,
            observed_ms: claimed_at_ms,
        });
    }
    if claimed_at_ms >= approval.deadline_at_ms
        || !is_exact_started_turn(
            &transaction,
            approval.conversation_id,
            approval.command_id,
            approval.turn_id,
        )?
    {
        if approval.state.is_terminal() {
            return Ok(ApprovalMutationOutcome::ExpiredOrStale { approval });
        }
        let physical = load_approval_physical(&transaction, input.approval_id)?;
        let transition = ApprovalTransition {
            state: ApprovalState::Expired,
            delivery_round: approval.delivery_round,
            attempts_in_round: approval.attempts_in_round,
            round_started_at_ms: approval.round_started_at_ms,
            last_attempt_at_ms: approval.last_attempt_at_ms,
            status_detail: approval.status_detail.clone(),
        };
        let (expired, _) = commit_approval_transition(
            transaction,
            key_bundle,
            database_id,
            config,
            ledger,
            approval,
            physical,
            claimed_at_ms,
            transition,
            RuntimeStoreOperation::ClaimApprovalBeforeCommit,
            RuntimeCommitOperation::ClaimApproval,
        )?;
        finish_approval_commit(
            state,
            config,
            RuntimeStoreOperation::ClaimApprovalAfterCommit,
            RuntimeCommitOperation::ClaimApproval,
        )?;
        return Ok(ApprovalMutationOutcome::ExpiredOrStale { approval: expired });
    }
    let physical = load_approval_physical(&transaction, input.approval_id)?;
    if approval.state != ApprovalState::Pending {
        let outcome = if physical.decision_token.as_deref() == Some(decision_token.as_bytes())
            && physical.claimant_token.as_deref() == Some(claimant_token.as_bytes())
        {
            ApprovalMutationOutcome::Replayed {
                event: Some(load_event(
                    &transaction,
                    key_bundle,
                    database_id,
                    approval.last_event_id,
                )?),
                approval,
            }
        } else {
            ApprovalMutationOutcome::AlreadyHandled { approval }
        };
        return Ok(outcome);
    }
    if physical.decision_token.is_some()
        || physical.claimant_token.is_some()
        || physical.sealed_decision.is_some()
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let conversation = load_conversation_metadata(
        &transaction,
        key_bundle,
        database_id,
        approval.conversation_id,
    )?;
    if claimed_at_ms < conversation.updated_at_ms {
        return Err(RuntimeStoreError::ClockRegressed {
            persisted_ms: conversation.updated_at_ms,
            observed_ms: claimed_at_ms,
        });
    }
    let previous_event_high_water = conversation
        .event_high_water
        .map(super::sequence::encode_sequence);
    let event_seq = next_sequence(
        SequenceScope::EventSeq,
        previous_event_high_water.as_deref(),
    )?;
    let event_id = allocate_id(&transaction, config, RuntimeIdKind::Event)?;
    let event_payload = canonical_claimed_event(
        approval.conversation_id,
        event_id,
        event_seq.value,
        approval.turn_id,
        approval.approval_id,
        input.decision.decision,
    )?;
    validate_nonempty_maximum(event_payload.len(), MAX_RUNTIME_EVENT_BYTES)?;
    let sealed_event = seal(
        key_bundle,
        database_id,
        b"event_journal",
        event_id.as_bytes(),
        b"sealed_event",
        event_payload.as_ref(),
        MAX_RUNTIME_EVENT_BYTES,
    )?;
    let sealed_decision = seal(
        key_bundle,
        database_id,
        b"approval_ledger",
        approval.approval_id.as_bytes(),
        b"sealed_decision",
        decision_bytes.as_ref(),
        MAX_APPROVAL_DECISION_BYTES,
    )?;
    let next_state_version = approval
        .state_version
        .checked_add(1)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let next_metadata_token = approval_metadata_token(
        key_bundle,
        ApprovalMetadataFields {
            approval_id: approval.approval_id,
            conversation_id: approval.conversation_id,
            command_id: approval.command_id,
            turn_id: approval.turn_id,
            request_token: &physical.request_token,
            decision_token: Some(decision_token.as_bytes()),
            claimant_token: Some(claimant_token.as_bytes()),
            state: ApprovalState::Claimed,
            requested_at_ms: approval.requested_at_ms,
            deadline_at_ms: approval.deadline_at_ms,
            claimed_at_ms: Some(claimed_at_ms),
            state_changed_at_ms: claimed_at_ms,
            delivery_round: 0,
            attempts_in_round: 0,
            round_started_at_ms: None,
            last_attempt_at_ms: None,
            state_version: next_state_version,
            last_event_id: event_id,
            logical_request_bytes: physical.logical_request_bytes,
            logical_decision_bytes: u64::try_from(decision_bytes.len())
                .map_err(|_| RuntimeStoreError::PayloadTooLarge)?,
            sealed_request_len: physical.sealed_request_len,
            sealed_decision_len: Some(sealed_decision.len()),
            sealed_status_detail_len: physical.sealed_status_detail_len,
        },
    )?;
    let event_metadata_token = event_metadata_token(
        key_bundle,
        approval.conversation_id,
        event_id,
        event_seq.value,
        Some(approval.command_id),
        u64::try_from(event_payload.len()).map_err(|_| RuntimeStoreError::PayloadTooLarge)?,
        claimed_at_ms,
    )?;
    transaction.execute(
        "INSERT INTO event_journal (
             conversation_id, event_seq, event_id, command_id,
             logical_event_bytes, created_at_ms, metadata_token, sealed_event
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            &approval.conversation_id.as_bytes()[..],
            event_seq.encoded,
            &event_id.as_bytes()[..],
            &approval.command_id.as_bytes()[..],
            sqlite_time(
                u64::try_from(event_payload.len())
                    .map_err(|_| RuntimeStoreError::PayloadTooLarge)?
            )?,
            sqlite_time(claimed_at_ms)?,
            &event_metadata_token[..],
            sealed_event,
        ],
    )?;
    let updated = transaction.execute(
        "UPDATE approval_ledger
         SET decision_token = ?1, claimant_token = ?2, state = 'claimed',
             claimed_at_ms = ?3, state_changed_at_ms = ?3,
             state_version = ?4, last_event_id = ?5,
             logical_decision_bytes = ?6, metadata_token = ?7, sealed_decision = ?8
         WHERE approval_id = ?9 AND state = 'pending' AND metadata_token = ?10",
        params![
            &decision_token.as_bytes()[..],
            &claimant_token.as_bytes()[..],
            sqlite_time(claimed_at_ms)?,
            sqlite_time(next_state_version)?,
            &event_id.as_bytes()[..],
            sqlite_time(
                u64::try_from(decision_bytes.len())
                    .map_err(|_| RuntimeStoreError::PayloadTooLarge)?
            )?,
            &next_metadata_token[..],
            sealed_decision,
            &approval.approval_id.as_bytes()[..],
            &physical.metadata_token,
        ],
    )?;
    if updated != 1 {
        return Err(RuntimeStoreError::SchemaInspectionRaced);
    }
    update_conversation_event_high_water(
        &transaction,
        key_bundle,
        conversation,
        &event_seq.encoded,
        previous_event_high_water.as_deref(),
        claimed_at_ms,
    )?;
    let mut next_ledger = copy_ledger(&ledger);
    next_ledger.event_count = next_ledger
        .event_count
        .checked_add(1)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    sqlite::update_runtime_ledger(&transaction, key_bundle, database_id, &ledger, &next_ledger)?;
    config
        .fault_injector
        .before_operation(RuntimeStoreOperation::ClaimApprovalBeforeCommit)?;
    sqlite::commit_transaction(transaction, RuntimeCommitOperation::ClaimApproval)?;
    sqlite::latch_post_commit_capacity(state, config);
    if config
        .fault_injector
        .before_operation(RuntimeStoreOperation::ClaimApprovalAfterCommit)
        .is_err()
    {
        return Err(RuntimeStoreError::CommitOutcomeUnknown {
            operation: RuntimeCommitOperation::ClaimApproval,
        });
    }
    let claimed = ApprovalRecord {
        state: ApprovalState::Claimed,
        decision: Some(input.decision),
        claimed_at_ms: Some(claimed_at_ms),
        state_changed_at_ms: claimed_at_ms,
        state_version: next_state_version,
        last_event_id: event_id,
        ..approval
    };
    let event = EventRecord {
        conversation_id: claimed.conversation_id,
        event_id,
        event_seq: event_seq.value,
        command_id: Some(claimed.command_id),
        created_at_ms: claimed_at_ms,
        payload: event_payload.to_vec(),
    };
    Ok(ApprovalMutationOutcome::Transitioned {
        approval: claimed,
        event,
    })
}

pub(crate) fn begin_approval_attempt(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    input: BeginApprovalAttempt,
) -> Result<BeginApprovalAttemptOutcome, RuntimeStoreError> {
    ensure_kind(input.approval_id, RuntimeIdKind::Approval)?;
    if input.expected_attempts_in_round > 8 {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }
    let database_id = state.database_id;
    let key_bundle = &state.key_bundle;
    let (_, preflight) = load_authenticated_approval_target(
        &state.connection,
        key_bundle,
        database_id,
        input.approval_id,
    )?;
    if matches!(
        preflight.state,
        ApprovalState::Applied | ApprovalState::Expired | ApprovalState::DeliveryFailed
    ) {
        return Ok(BeginApprovalAttemptOutcome::AlreadyHandled {
            approval: preflight,
        });
    }
    let observed_at_ms = config.clock.now_ms()?;
    ensure_approval_timeline_not_regressed(&preflight, observed_at_ms)?;
    if observed_at_ms >= preflight.deadline_at_ms
        || !is_exact_started_turn(
            &state.connection,
            preflight.conversation_id,
            preflight.command_id,
            preflight.turn_id,
        )?
    {
        return expire_for_begin(state, config, preflight);
    }
    if begin_is_exact_replay(&preflight, &input) {
        return Ok(BeginApprovalAttemptOutcome::Permitted {
            approval: preflight,
            event: None,
            replayed: true,
        });
    }
    let projected = projected_write_bytes(&[
        size_of::<ApprovalRecord>(),
        MAX_APPROVAL_TRANSITION_EVENT_BYTES,
    ])?;
    let admission = sqlite::admit_ordinary_write(
        &state.connection,
        key_bundle,
        database_id,
        &state.storage_path,
        &mut state.admission_state,
        config.capacity_probe.as_ref(),
        projected,
        SafetyReserveProjection::Current,
    );
    if let Err(error) = admission {
        let now_ms = config.clock.now_ms()?;
        if now_ms >= preflight.deadline_at_ms
            || !is_exact_started_turn(
                &state.connection,
                preflight.conversation_id,
                preflight.command_id,
                preflight.turn_id,
            )?
        {
            return expire_for_begin(state, config, preflight);
        }
        return Err(error);
    }
    let transaction = state
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let (ledger, approval) = load_authenticated_approval_target(
        &transaction,
        key_bundle,
        database_id,
        input.approval_id,
    )?;
    let observed_at_ms = config.clock.now_ms()?;
    if matches!(
        approval.state,
        ApprovalState::Applied | ApprovalState::Expired | ApprovalState::DeliveryFailed
    ) {
        return Ok(BeginApprovalAttemptOutcome::AlreadyHandled { approval });
    }
    ensure_approval_timeline_not_regressed(&approval, observed_at_ms)?;
    if observed_at_ms >= approval.deadline_at_ms
        || !is_exact_started_turn(
            &transaction,
            approval.conversation_id,
            approval.command_id,
            approval.turn_id,
        )?
    {
        let physical = load_approval_physical(&transaction, input.approval_id)?;
        let transition = ApprovalTransition {
            state: ApprovalState::Expired,
            delivery_round: approval.delivery_round,
            attempts_in_round: approval.attempts_in_round,
            round_started_at_ms: approval.round_started_at_ms,
            last_attempt_at_ms: approval.last_attempt_at_ms,
            status_detail: approval.status_detail.clone(),
        };
        let (expired, _) = commit_approval_transition(
            transaction,
            key_bundle,
            database_id,
            config,
            ledger,
            approval,
            physical,
            observed_at_ms,
            transition,
            RuntimeStoreOperation::ExpireApprovalBeforeCommit,
            RuntimeCommitOperation::ExpireApproval,
        )?;
        finish_approval_commit(
            state,
            config,
            RuntimeStoreOperation::ExpireApprovalAfterCommit,
            RuntimeCommitOperation::ExpireApproval,
        )?;
        return Ok(BeginApprovalAttemptOutcome::ExpiredOrStale { approval: expired });
    }
    if begin_is_exact_replay(&approval, &input) {
        return Ok(BeginApprovalAttemptOutcome::Permitted {
            approval,
            event: None,
            replayed: true,
        });
    }
    let physical = load_approval_physical(&transaction, input.approval_id)?;
    let (next, event) = match approval.state {
        ApprovalState::Claimed
            if input.delivery_round == 0 && input.expected_attempts_in_round == 0 =>
        {
            let (next, event) = commit_approval_transition(
                transaction,
                key_bundle,
                database_id,
                config,
                ledger,
                approval,
                physical,
                observed_at_ms,
                ApprovalTransition {
                    state: ApprovalState::Applying,
                    delivery_round: 1,
                    attempts_in_round: 1,
                    round_started_at_ms: Some(observed_at_ms),
                    last_attempt_at_ms: Some(observed_at_ms),
                    status_detail: None,
                },
                RuntimeStoreOperation::BeginApprovalAttemptBeforeCommit,
                RuntimeCommitOperation::BeginApprovalAttempt,
            )?;
            (next, Some(event))
        }
        ApprovalState::Applying
            if input.delivery_round == approval.delivery_round
                && input.expected_attempts_in_round == approval.attempts_in_round
                && approval.attempts_in_round < 8 =>
        {
            let next = commit_followup_attempt(
                transaction,
                key_bundle,
                config,
                approval,
                physical,
                observed_at_ms,
            )?;
            (next, None)
        }
        ApprovalState::Applied | ApprovalState::Expired | ApprovalState::DeliveryFailed => {
            return Ok(BeginApprovalAttemptOutcome::AlreadyHandled { approval });
        }
        _ => return Err(RuntimeStoreError::InvalidStateTransition),
    };
    finish_approval_commit(
        state,
        config,
        RuntimeStoreOperation::BeginApprovalAttemptAfterCommit,
        RuntimeCommitOperation::BeginApprovalAttempt,
    )?;
    Ok(BeginApprovalAttemptOutcome::Permitted {
        approval: next,
        event,
        replayed: false,
    })
}

pub(crate) fn mark_approval_applied(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    input: MarkApprovalApplied,
) -> Result<ApprovalMutationOutcome, RuntimeStoreError> {
    ensure_kind(input.approval_id, RuntimeIdKind::Approval)?;
    validate_attempt_coordinates(input.delivery_round, input.attempt)?;
    sqlite::admit_safety_write(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        &state.storage_path,
        config.capacity_probe.as_ref(),
    )?;
    let database_id = state.database_id;
    let key_bundle = &state.key_bundle;
    let transaction = state
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let (ledger, approval) = load_authenticated_approval_target(
        &transaction,
        key_bundle,
        database_id,
        input.approval_id,
    )?;
    let observed_at_ms = config.clock.now_ms()?;
    if approval.state == ApprovalState::Applied
        && approval.delivery_round == input.delivery_round
        && approval.attempts_in_round == input.attempt
    {
        let event = load_event(
            &transaction,
            key_bundle,
            database_id,
            approval.last_event_id,
        )?;
        return Ok(ApprovalMutationOutcome::Replayed {
            approval,
            event: Some(event),
        });
    }
    if approval.state != ApprovalState::Applying {
        return Ok(ApprovalMutationOutcome::AlreadyHandled { approval });
    }
    require_current_attempt(&approval, input.delivery_round, input.attempt)?;
    let physical = load_approval_physical(&transaction, input.approval_id)?;
    let transition = ApprovalTransition {
        state: ApprovalState::Applied,
        delivery_round: approval.delivery_round,
        attempts_in_round: approval.attempts_in_round,
        round_started_at_ms: approval.round_started_at_ms,
        last_attempt_at_ms: approval.last_attempt_at_ms,
        status_detail: None,
    };
    let (approval, event) = commit_approval_transition(
        transaction,
        key_bundle,
        database_id,
        config,
        ledger,
        approval,
        physical,
        observed_at_ms,
        transition,
        RuntimeStoreOperation::MarkApprovalAppliedBeforeCommit,
        RuntimeCommitOperation::MarkApprovalApplied,
    )?;
    finish_approval_commit(
        state,
        config,
        RuntimeStoreOperation::MarkApprovalAppliedAfterCommit,
        RuntimeCommitOperation::MarkApprovalApplied,
    )?;
    Ok(ApprovalMutationOutcome::Transitioned { approval, event })
}

pub(crate) fn mark_approval_delivery_failed(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    input: MarkApprovalDeliveryFailed,
) -> Result<ApprovalMutationOutcome, RuntimeStoreError> {
    ensure_kind(input.approval_id, RuntimeIdKind::Approval)?;
    validate_attempt_coordinates(input.delivery_round, input.attempt)?;
    validate_nonempty_maximum(input.status_detail.len(), MAX_APPROVAL_STATUS_DETAIL_BYTES)?;
    sqlite::admit_safety_write(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        &state.storage_path,
        config.capacity_probe.as_ref(),
    )?;
    let database_id = state.database_id;
    let key_bundle = &state.key_bundle;
    let transaction = state
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let (ledger, approval) = load_authenticated_approval_target(
        &transaction,
        key_bundle,
        database_id,
        input.approval_id,
    )?;
    let observed_at_ms = config.clock.now_ms()?;
    if approval.state == ApprovalState::DeliveryFailed
        && approval.delivery_round == input.delivery_round
        && approval.attempts_in_round == input.attempt
        && approval.status_detail.as_deref() == Some(input.status_detail.as_slice())
    {
        let event = load_event(
            &transaction,
            key_bundle,
            database_id,
            approval.last_event_id,
        )?;
        return Ok(ApprovalMutationOutcome::Replayed {
            approval,
            event: Some(event),
        });
    }
    if approval.state != ApprovalState::Applying {
        return Ok(ApprovalMutationOutcome::AlreadyHandled { approval });
    }
    require_current_attempt(&approval, input.delivery_round, input.attempt)?;
    let physical = load_approval_physical(&transaction, input.approval_id)?;
    let transition = ApprovalTransition {
        state: ApprovalState::DeliveryFailed,
        delivery_round: approval.delivery_round,
        attempts_in_round: approval.attempts_in_round,
        round_started_at_ms: approval.round_started_at_ms,
        last_attempt_at_ms: approval.last_attempt_at_ms,
        status_detail: Some(input.status_detail),
    };
    let (approval, event) = commit_approval_transition(
        transaction,
        key_bundle,
        database_id,
        config,
        ledger,
        approval,
        physical,
        observed_at_ms,
        transition,
        RuntimeStoreOperation::MarkApprovalDeliveryFailedBeforeCommit,
        RuntimeCommitOperation::MarkApprovalDeliveryFailed,
    )?;
    finish_approval_commit(
        state,
        config,
        RuntimeStoreOperation::MarkApprovalDeliveryFailedAfterCommit,
        RuntimeCommitOperation::MarkApprovalDeliveryFailed,
    )?;
    Ok(ApprovalMutationOutcome::Transitioned { approval, event })
}

pub(crate) fn retry_approval_delivery(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    input: RetryApprovalDelivery,
) -> Result<ApprovalMutationOutcome, RuntimeStoreError> {
    ensure_kind(input.conversation_id, RuntimeIdKind::Conversation)?;
    ensure_kind(input.approval_id, RuntimeIdKind::Approval)?;
    let database_id = state.database_id;
    let key_bundle = &state.key_bundle;
    let (_, preflight) = load_authenticated_approval_target(
        &state.connection,
        key_bundle,
        database_id,
        input.approval_id,
    )?;
    if preflight.conversation_id != input.conversation_id {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }
    let preflight_at_ms = config.clock.now_ms()?;
    if preflight_at_ms < preflight.state_changed_at_ms {
        return Err(RuntimeStoreError::ClockRegressed {
            persisted_ms: preflight.state_changed_at_ms,
            observed_ms: preflight_at_ms,
        });
    }
    let preflight_stale = preflight_at_ms >= preflight.deadline_at_ms
        || !is_exact_started_turn(
            &state.connection,
            preflight.conversation_id,
            preflight.command_id,
            preflight.turn_id,
        )?;
    if !preflight_stale {
        if preflight.state == ApprovalState::Applying
            && preflight.delivery_round >= 2
            && preflight.attempts_in_round == 0
        {
            let event = load_event(
                &state.connection,
                key_bundle,
                database_id,
                preflight.last_event_id,
            )?;
            return Ok(ApprovalMutationOutcome::Replayed {
                approval: preflight,
                event: Some(event),
            });
        }
        if matches!(
            preflight.state,
            ApprovalState::Applied | ApprovalState::Expired
        ) {
            return Ok(ApprovalMutationOutcome::AlreadyHandled {
                approval: preflight,
            });
        }
        if preflight.state != ApprovalState::DeliveryFailed {
            return Err(RuntimeStoreError::InvalidStateTransition);
        }
    }
    if preflight_stale {
        if preflight.state.is_terminal() {
            return Ok(ApprovalMutationOutcome::AlreadyHandled {
                approval: preflight,
            });
        }
        sqlite::admit_safety_write(
            &state.connection,
            key_bundle,
            database_id,
            &state.storage_path,
            config.capacity_probe.as_ref(),
        )?;
    } else {
        sqlite::admit_ordinary_write(
            &state.connection,
            key_bundle,
            database_id,
            &state.storage_path,
            &mut state.admission_state,
            config.capacity_probe.as_ref(),
            projected_write_bytes(&[
                size_of::<ApprovalRecord>(),
                MAX_APPROVAL_TRANSITION_EVENT_BYTES,
            ])?,
            SafetyReserveProjection::Current,
        )?;
    }
    let transaction = state
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let (ledger, approval) = load_authenticated_approval_target(
        &transaction,
        key_bundle,
        database_id,
        input.approval_id,
    )?;
    let observed_at_ms = config.clock.now_ms()?;
    if approval.conversation_id != input.conversation_id {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }
    if observed_at_ms < approval.state_changed_at_ms {
        return Err(RuntimeStoreError::ClockRegressed {
            persisted_ms: approval.state_changed_at_ms,
            observed_ms: observed_at_ms,
        });
    }
    let stale = observed_at_ms >= approval.deadline_at_ms
        || !is_exact_started_turn(
            &transaction,
            approval.conversation_id,
            approval.command_id,
            approval.turn_id,
        )?;
    if stale {
        if approval.state.is_terminal() {
            return Ok(ApprovalMutationOutcome::AlreadyHandled { approval });
        }
        let physical = load_approval_physical(&transaction, input.approval_id)?;
        let transition = ApprovalTransition {
            state: ApprovalState::Expired,
            delivery_round: approval.delivery_round,
            attempts_in_round: approval.attempts_in_round,
            round_started_at_ms: approval.round_started_at_ms,
            last_attempt_at_ms: approval.last_attempt_at_ms,
            status_detail: approval.status_detail.clone(),
        };
        let (expired, _) = commit_approval_transition(
            transaction,
            key_bundle,
            database_id,
            config,
            ledger,
            approval,
            physical,
            observed_at_ms,
            transition,
            RuntimeStoreOperation::RetryApprovalDeliveryBeforeCommit,
            RuntimeCommitOperation::RetryApprovalDelivery,
        )?;
        finish_approval_commit(
            state,
            config,
            RuntimeStoreOperation::RetryApprovalDeliveryAfterCommit,
            RuntimeCommitOperation::RetryApprovalDelivery,
        )?;
        return Ok(ApprovalMutationOutcome::ExpiredOrStale { approval: expired });
    }
    if approval.state == ApprovalState::Applying
        && approval.delivery_round >= 2
        && approval.attempts_in_round == 0
    {
        let event = load_event(
            &transaction,
            key_bundle,
            database_id,
            approval.last_event_id,
        )?;
        return Ok(ApprovalMutationOutcome::Replayed {
            approval,
            event: Some(event),
        });
    }
    if approval.state != ApprovalState::DeliveryFailed {
        return Ok(ApprovalMutationOutcome::AlreadyHandled { approval });
    }
    let physical = load_approval_physical(&transaction, input.approval_id)?;
    let next_round = approval
        .delivery_round
        .checked_add(1)
        .ok_or(RuntimeStoreError::InvalidStateTransition)?;
    let transition = ApprovalTransition {
        state: ApprovalState::Applying,
        delivery_round: next_round,
        attempts_in_round: 0,
        round_started_at_ms: Some(observed_at_ms),
        last_attempt_at_ms: None,
        status_detail: None,
    };
    let (approval, event) = commit_approval_transition(
        transaction,
        key_bundle,
        database_id,
        config,
        ledger,
        approval,
        physical,
        observed_at_ms,
        transition,
        RuntimeStoreOperation::RetryApprovalDeliveryBeforeCommit,
        RuntimeCommitOperation::RetryApprovalDelivery,
    )?;
    finish_approval_commit(
        state,
        config,
        RuntimeStoreOperation::RetryApprovalDeliveryAfterCommit,
        RuntimeCommitOperation::RetryApprovalDelivery,
    )?;
    Ok(ApprovalMutationOutcome::Transitioned { approval, event })
}

pub(crate) fn expire_approval(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    input: ExpireApproval,
) -> Result<ApprovalMutationOutcome, RuntimeStoreError> {
    ensure_kind(input.conversation_id, RuntimeIdKind::Conversation)?;
    ensure_kind(input.approval_id, RuntimeIdKind::Approval)?;
    sqlite::admit_safety_write(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        &state.storage_path,
        config.capacity_probe.as_ref(),
    )?;
    let database_id = state.database_id;
    let key_bundle = &state.key_bundle;
    let transaction = state
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let (ledger, approval) = load_authenticated_approval_target(
        &transaction,
        key_bundle,
        database_id,
        input.approval_id,
    )?;
    let observed_at_ms = config.clock.now_ms()?;
    if approval.conversation_id != input.conversation_id {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }
    if approval.state == ApprovalState::Expired {
        let event = load_event(
            &transaction,
            key_bundle,
            database_id,
            approval.last_event_id,
        )?;
        return Ok(ApprovalMutationOutcome::Replayed {
            approval,
            event: Some(event),
        });
    }
    if approval.state == ApprovalState::Applied {
        return Ok(ApprovalMutationOutcome::AlreadyHandled { approval });
    }
    if observed_at_ms < approval.deadline_at_ms
        && is_exact_started_turn(
            &transaction,
            approval.conversation_id,
            approval.command_id,
            approval.turn_id,
        )?
    {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }
    let physical = load_approval_physical(&transaction, input.approval_id)?;
    let transition = ApprovalTransition {
        state: ApprovalState::Expired,
        delivery_round: approval.delivery_round,
        attempts_in_round: approval.attempts_in_round,
        round_started_at_ms: approval.round_started_at_ms,
        last_attempt_at_ms: approval.last_attempt_at_ms,
        status_detail: approval.status_detail.clone(),
    };
    let (approval, event) = commit_approval_transition(
        transaction,
        key_bundle,
        database_id,
        config,
        ledger,
        approval,
        physical,
        observed_at_ms,
        transition,
        RuntimeStoreOperation::ExpireApprovalBeforeCommit,
        RuntimeCommitOperation::ExpireApproval,
    )?;
    finish_approval_commit(
        state,
        config,
        RuntimeStoreOperation::ExpireApprovalAfterCommit,
        RuntimeCommitOperation::ExpireApproval,
    )?;
    Ok(ApprovalMutationOutcome::Transitioned { approval, event })
}

fn expire_for_begin(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    current: ApprovalRecord,
) -> Result<BeginApprovalAttemptOutcome, RuntimeStoreError> {
    match expire_approval(
        state,
        config,
        ExpireApproval {
            conversation_id: current.conversation_id,
            approval_id: current.approval_id,
        },
    )? {
        ApprovalMutationOutcome::Transitioned { approval, .. }
        | ApprovalMutationOutcome::Replayed { approval, .. }
        | ApprovalMutationOutcome::ExpiredOrStale { approval } => {
            Ok(BeginApprovalAttemptOutcome::ExpiredOrStale { approval })
        }
        ApprovalMutationOutcome::AlreadyHandled { approval } => {
            Ok(BeginApprovalAttemptOutcome::AlreadyHandled { approval })
        }
    }
}

fn begin_is_exact_replay(approval: &ApprovalRecord, input: &BeginApprovalAttempt) -> bool {
    approval.state == ApprovalState::Applying
        && ((input.delivery_round == 0
            && input.expected_attempts_in_round == 0
            && approval.delivery_round == 1
            && approval.attempts_in_round == 1)
            || (input.delivery_round == approval.delivery_round
                && input
                    .expected_attempts_in_round
                    .checked_add(1)
                    .is_some_and(|attempt| attempt == approval.attempts_in_round)))
}

fn ensure_approval_timeline_not_regressed(
    approval: &ApprovalRecord,
    observed_at_ms: u64,
) -> Result<(), RuntimeStoreError> {
    let persisted_boundary = approval
        .state_changed_at_ms
        .max(approval.round_started_at_ms.unwrap_or(0))
        .max(approval.last_attempt_at_ms.unwrap_or(0));
    if observed_at_ms < persisted_boundary {
        Err(RuntimeStoreError::ClockRegressed {
            persisted_ms: persisted_boundary,
            observed_ms: observed_at_ms,
        })
    } else {
        Ok(())
    }
}

fn validate_attempt_coordinates(delivery_round: u32, attempt: u8) -> Result<(), RuntimeStoreError> {
    if delivery_round == 0 || !(1..=8).contains(&attempt) {
        Err(RuntimeStoreError::InvalidStateTransition)
    } else {
        Ok(())
    }
}

fn require_current_attempt(
    approval: &ApprovalRecord,
    delivery_round: u32,
    attempt: u8,
) -> Result<(), RuntimeStoreError> {
    if approval.delivery_round == delivery_round
        && approval.attempts_in_round == attempt
        && approval.last_attempt_at_ms.is_some()
    {
        Ok(())
    } else {
        Err(RuntimeStoreError::InvalidStateTransition)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct TerminalApprovalExpiry {
    pub(super) final_event_high_water: Option<String>,
    pub(super) expiry_event_count: u64,
    pub(super) active_approval_decrement: u64,
}

/// 在 command terminal 所属的外层事务里收口该 turn 的全部 active approval。
///
/// 此 helper 故意不更新 conversation high-water、runtime ledger，也不 COMMIT；调用方必须在
/// 写完 command terminal event 后，用返回的 final HWM/count 一次性提交三者。active query
/// 固定走 turn index、32+1 上界和 approval_id 稳定顺序，不能依赖 SQLite 未定义行序。
#[allow(clippy::too_many_arguments)]
pub(super) fn expire_active_approvals_for_terminal(
    transaction: &Transaction<'_>,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    config: &RuntimeStoreConfig,
    conversation_id: RuntimeId,
    command_id: RuntimeId,
    turn_id: RuntimeId,
    observed_at_ms: u64,
    previous_event_high_water: Option<&str>,
) -> Result<TerminalApprovalExpiry, RuntimeStoreError> {
    let approval_ids = active_approval_ids_for_turn(transaction, conversation_id, turn_id)?;
    let mut final_event_high_water = previous_event_high_water.map(str::to_owned);
    let mut expiry_event_count = 0_u64;
    for approval_id in approval_ids {
        let approval = load_approval(transaction, key_bundle, database_id, approval_id)
            .map_err(map_integrity_error)?;
        validate_approval_record_linkage(transaction, &approval)?;
        if approval.conversation_id != conversation_id
            || approval.command_id != command_id
            || approval.turn_id != turn_id
            || !approval.state.is_active()
        {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        let physical =
            load_approval_physical(transaction, approval_id).map_err(map_integrity_error)?;
        let event_seq = next_sequence(SequenceScope::EventSeq, final_event_high_water.as_deref())?;
        let transition = ApprovalTransition {
            state: ApprovalState::Expired,
            delivery_round: approval.delivery_round,
            attempts_in_round: approval.attempts_in_round,
            round_started_at_ms: approval.round_started_at_ms,
            last_attempt_at_ms: approval.last_attempt_at_ms,
            status_detail: approval.status_detail.clone(),
        };
        apply_approval_transition_in_transaction(
            transaction,
            key_bundle,
            database_id,
            config,
            approval,
            physical,
            observed_at_ms,
            transition,
            &event_seq,
        )?;
        final_event_high_water = Some(event_seq.encoded);
        expiry_event_count = expiry_event_count
            .checked_add(1)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    }
    Ok(TerminalApprovalExpiry {
        final_event_high_water,
        expiry_event_count,
        active_approval_decrement: expiry_event_count,
    })
}

/// terminal exact replay 不能掩盖“command 已 terminal 但 approval 仍 active”的 crash gap。
/// 发现候选时先逐行认证 bounded rows，再统一 fail closed。
pub(super) fn ensure_terminal_turn_has_no_active_approvals(
    transaction: &Transaction<'_>,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    conversation_id: RuntimeId,
    command_id: RuntimeId,
    turn_id: RuntimeId,
) -> Result<(), RuntimeStoreError> {
    let approval_ids = active_approval_ids_for_turn(transaction, conversation_id, turn_id)?;
    if approval_ids.is_empty() {
        return Ok(());
    }
    for approval_id in approval_ids {
        let approval = load_approval(transaction, key_bundle, database_id, approval_id)
            .map_err(map_integrity_error)?;
        if approval.conversation_id != conversation_id
            || approval.command_id != command_id
            || approval.turn_id != turn_id
            || !approval.state.is_active()
        {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
    }
    Err(RuntimeStoreError::UnknownOrCorruptSchema)
}

fn active_approval_ids_for_turn(
    transaction: &Transaction<'_>,
    conversation_id: RuntimeId,
    turn_id: RuntimeId,
) -> Result<Vec<RuntimeId>, RuntimeStoreError> {
    let query_limit = i64::from(MAX_ACTIVE_APPROVALS_PER_TURN)
        .checked_add(1)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let mut statement = transaction.prepare(
        "SELECT approval_id
         FROM approval_ledger INDEXED BY idx_approval_active_turn
         WHERE conversation_id = ?1 AND turn_id = ?2
           AND state IN ('pending', 'claimed', 'applying', 'deliveryFailed')
         ORDER BY approval_id ASC
         LIMIT ?3",
    )?;
    let rows = statement.query_map(
        params![
            &conversation_id.as_bytes()[..],
            &turn_id.as_bytes()[..],
            query_limit,
        ],
        |row| row.get::<_, Vec<u8>>(0),
    )?;
    let mut approval_ids = Vec::new();
    for row in rows {
        approval_ids.push(runtime_id(RuntimeIdKind::Approval, row?)?);
    }
    if approval_ids.len()
        > usize::try_from(MAX_ACTIVE_APPROVALS_PER_TURN)
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(approval_ids)
}

#[allow(clippy::too_many_arguments)]
fn commit_approval_transition(
    transaction: Transaction<'_>,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    config: &RuntimeStoreConfig,
    ledger: RuntimeLedger,
    approval: ApprovalRecord,
    physical: ApprovalPhysical,
    observed_at_ms: u64,
    transition: ApprovalTransition,
    before_operation: RuntimeStoreOperation,
    commit_operation: RuntimeCommitOperation,
) -> Result<(ApprovalRecord, EventRecord), RuntimeStoreError> {
    if observed_at_ms < approval.state_changed_at_ms {
        return Err(RuntimeStoreError::ClockRegressed {
            persisted_ms: approval.state_changed_at_ms,
            observed_ms: observed_at_ms,
        });
    }
    let conversation = load_conversation_metadata(
        &transaction,
        key_bundle,
        database_id,
        approval.conversation_id,
    )?;
    if observed_at_ms < conversation.updated_at_ms {
        return Err(RuntimeStoreError::ClockRegressed {
            persisted_ms: conversation.updated_at_ms,
            observed_ms: observed_at_ms,
        });
    }
    let previous_event_high_water = conversation
        .event_high_water
        .map(super::sequence::encode_sequence);
    let event_seq = next_sequence(
        SequenceScope::EventSeq,
        previous_event_high_water.as_deref(),
    )?;
    let decrements_active = approval.state.is_active() && transition.state.is_terminal();
    let (next, event) = apply_approval_transition_in_transaction(
        &transaction,
        key_bundle,
        database_id,
        config,
        approval,
        physical,
        observed_at_ms,
        transition,
        &event_seq,
    )?;
    update_conversation_event_high_water(
        &transaction,
        key_bundle,
        conversation,
        &event_seq.encoded,
        previous_event_high_water.as_deref(),
        observed_at_ms,
    )?;
    let mut next_ledger = copy_ledger(&ledger);
    next_ledger.event_count = next_ledger
        .event_count
        .checked_add(1)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    if decrements_active {
        next_ledger.active_approval_count = next_ledger
            .active_approval_count
            .checked_sub(1)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    }
    sqlite::update_runtime_ledger(&transaction, key_bundle, database_id, &ledger, &next_ledger)?;
    config.fault_injector.before_operation(before_operation)?;
    sqlite::commit_transaction(transaction, commit_operation)?;
    Ok((next, event))
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn apply_approval_transition_in_transaction(
    transaction: &Transaction<'_>,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    config: &RuntimeStoreConfig,
    approval: ApprovalRecord,
    physical: ApprovalPhysical,
    observed_at_ms: u64,
    transition: ApprovalTransition,
    event_seq: &AllocatedSequence,
) -> Result<(ApprovalRecord, EventRecord), RuntimeStoreError> {
    ensure_approval_timeline_not_regressed(&approval, observed_at_ms)?;
    let event_id = allocate_id(transaction, config, RuntimeIdKind::Event)?;
    let decision = approval.decision.as_ref().map(|value| value.decision);
    if transition.state != ApprovalState::Expired && decision.is_none() {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }
    let delivery_state = match transition.state {
        ApprovalState::Claimed => ApprovalDeliveryState::Claimed,
        ApprovalState::Applying => ApprovalDeliveryState::Applying,
        ApprovalState::Applied => ApprovalDeliveryState::Applied,
        ApprovalState::DeliveryFailed => ApprovalDeliveryState::DeliveryFailed,
        ApprovalState::Expired => ApprovalDeliveryState::Expired,
        ApprovalState::Pending => return Err(RuntimeStoreError::InvalidStateTransition),
    };
    let event_payload = canonical_resolved_event(
        approval.conversation_id,
        event_id,
        event_seq.value,
        approval.turn_id,
        approval.approval_id,
        decision,
        delivery_state,
    )?;
    validate_nonempty_maximum(event_payload.len(), MAX_APPROVAL_TRANSITION_EVENT_BYTES)?;
    let sealed_event = seal(
        key_bundle,
        database_id,
        b"event_journal",
        event_id.as_bytes(),
        b"sealed_event",
        event_payload.as_ref(),
        MAX_RUNTIME_EVENT_BYTES,
    )?;
    let sealed_status_detail = transition
        .status_detail
        .as_deref()
        .map(|detail| {
            validate_nonempty_maximum(detail.len(), MAX_APPROVAL_STATUS_DETAIL_BYTES)?;
            seal(
                key_bundle,
                database_id,
                b"approval_ledger",
                approval.approval_id.as_bytes(),
                b"sealed_status_detail",
                detail,
                MAX_APPROVAL_STATUS_DETAIL_BYTES,
            )
        })
        .transpose()?;
    let logical_decision_bytes = approval
        .decision
        .as_ref()
        .map(canonical_decision)
        .transpose()?
        .map_or(0, |value| u64::try_from(value.len()).unwrap_or(u64::MAX));
    if logical_decision_bytes == u64::MAX {
        return Err(RuntimeStoreError::PayloadTooLarge);
    }
    let next_state_version = approval
        .state_version
        .checked_add(1)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let next_metadata_token = approval_metadata_token(
        key_bundle,
        ApprovalMetadataFields {
            approval_id: approval.approval_id,
            conversation_id: approval.conversation_id,
            command_id: approval.command_id,
            turn_id: approval.turn_id,
            request_token: &physical.request_token,
            decision_token: physical.decision_token.as_deref(),
            claimant_token: physical.claimant_token.as_deref(),
            state: transition.state,
            requested_at_ms: approval.requested_at_ms,
            deadline_at_ms: approval.deadline_at_ms,
            claimed_at_ms: approval.claimed_at_ms,
            state_changed_at_ms: observed_at_ms,
            delivery_round: transition.delivery_round,
            attempts_in_round: transition.attempts_in_round,
            round_started_at_ms: transition.round_started_at_ms,
            last_attempt_at_ms: transition.last_attempt_at_ms,
            state_version: next_state_version,
            last_event_id: event_id,
            logical_request_bytes: physical.logical_request_bytes,
            logical_decision_bytes,
            sealed_request_len: physical.sealed_request_len,
            sealed_decision_len: physical.sealed_decision.as_ref().map(Vec::len),
            sealed_status_detail_len: sealed_status_detail.as_ref().map(Vec::len),
        },
    )?;
    let event_metadata_token = event_metadata_token(
        key_bundle,
        approval.conversation_id,
        event_id,
        event_seq.value,
        Some(approval.command_id),
        u64::try_from(event_payload.len()).map_err(|_| RuntimeStoreError::PayloadTooLarge)?,
        observed_at_ms,
    )?;
    transaction.execute(
        "INSERT INTO event_journal (
             conversation_id, event_seq, event_id, command_id,
             logical_event_bytes, created_at_ms, metadata_token, sealed_event
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            &approval.conversation_id.as_bytes()[..],
            event_seq.encoded,
            &event_id.as_bytes()[..],
            &approval.command_id.as_bytes()[..],
            sqlite_time(
                u64::try_from(event_payload.len())
                    .map_err(|_| RuntimeStoreError::PayloadTooLarge)?
            )?,
            sqlite_time(observed_at_ms)?,
            &event_metadata_token[..],
            sealed_event,
        ],
    )?;
    let updated = transaction.execute(
        "UPDATE approval_ledger
         SET state = ?1, state_changed_at_ms = ?2,
             delivery_round = ?3, attempts_in_round = ?4,
             round_started_at_ms = ?5, last_attempt_at_ms = ?6,
             state_version = ?7, last_event_id = ?8,
             metadata_token = ?9, sealed_status_detail = ?10
         WHERE approval_id = ?11 AND state = ?12 AND metadata_token = ?13",
        params![
            approval_state_text(transition.state),
            sqlite_time(observed_at_ms)?,
            i64::from(transition.delivery_round),
            i64::from(transition.attempts_in_round),
            transition
                .round_started_at_ms
                .map(sqlite_time)
                .transpose()?,
            transition.last_attempt_at_ms.map(sqlite_time).transpose()?,
            sqlite_time(next_state_version)?,
            &event_id.as_bytes()[..],
            &next_metadata_token[..],
            sealed_status_detail,
            &approval.approval_id.as_bytes()[..],
            approval_state_text(approval.state),
            &physical.metadata_token,
        ],
    )?;
    if updated != 1 {
        return Err(RuntimeStoreError::SchemaInspectionRaced);
    }
    let next = ApprovalRecord {
        state: transition.state,
        state_changed_at_ms: observed_at_ms,
        delivery_round: transition.delivery_round,
        attempts_in_round: transition.attempts_in_round,
        round_started_at_ms: transition.round_started_at_ms,
        last_attempt_at_ms: transition.last_attempt_at_ms,
        state_version: next_state_version,
        last_event_id: event_id,
        status_detail: transition.status_detail,
        ..approval
    };
    let event = EventRecord {
        conversation_id: next.conversation_id,
        event_id,
        event_seq: event_seq.value,
        command_id: Some(next.command_id),
        created_at_ms: observed_at_ms,
        payload: event_payload.to_vec(),
    };
    Ok((next, event))
}

fn finish_approval_commit(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    after_operation: RuntimeStoreOperation,
    commit_operation: RuntimeCommitOperation,
) -> Result<(), RuntimeStoreError> {
    sqlite::latch_post_commit_capacity(state, config);
    if config
        .fault_injector
        .before_operation(after_operation)
        .is_err()
    {
        Err(RuntimeStoreError::CommitOutcomeUnknown {
            operation: commit_operation,
        })
    } else {
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
fn commit_followup_attempt(
    transaction: Transaction<'_>,
    key_bundle: &RuntimeKeyBundle,
    config: &RuntimeStoreConfig,
    approval: ApprovalRecord,
    physical: ApprovalPhysical,
    observed_at_ms: u64,
) -> Result<ApprovalRecord, RuntimeStoreError> {
    ensure_approval_timeline_not_regressed(&approval, observed_at_ms)?;
    let attempts_in_round = approval
        .attempts_in_round
        .checked_add(1)
        .filter(|attempts| *attempts <= 8)
        .ok_or(RuntimeStoreError::InvalidStateTransition)?;
    let logical_decision_bytes = approval
        .decision
        .as_ref()
        .map(canonical_decision)
        .transpose()?
        .map(|value| u64::try_from(value.len()))
        .transpose()
        .map_err(|_| RuntimeStoreError::PayloadTooLarge)?
        .unwrap_or(0);
    let next_metadata_token = approval_metadata_token(
        key_bundle,
        ApprovalMetadataFields {
            approval_id: approval.approval_id,
            conversation_id: approval.conversation_id,
            command_id: approval.command_id,
            turn_id: approval.turn_id,
            request_token: &physical.request_token,
            decision_token: physical.decision_token.as_deref(),
            claimant_token: physical.claimant_token.as_deref(),
            state: approval.state,
            requested_at_ms: approval.requested_at_ms,
            deadline_at_ms: approval.deadline_at_ms,
            claimed_at_ms: approval.claimed_at_ms,
            state_changed_at_ms: approval.state_changed_at_ms,
            delivery_round: approval.delivery_round,
            attempts_in_round,
            round_started_at_ms: approval.round_started_at_ms,
            last_attempt_at_ms: Some(observed_at_ms),
            state_version: approval.state_version,
            last_event_id: approval.last_event_id,
            logical_request_bytes: physical.logical_request_bytes,
            logical_decision_bytes,
            sealed_request_len: physical.sealed_request_len,
            sealed_decision_len: physical.sealed_decision.as_ref().map(Vec::len),
            sealed_status_detail_len: physical.sealed_status_detail_len,
        },
    )?;
    if transaction.execute(
        "UPDATE approval_ledger
         SET attempts_in_round = ?1, last_attempt_at_ms = ?2, metadata_token = ?3
         WHERE approval_id = ?4 AND state = 'applying' AND metadata_token = ?5",
        params![
            i64::from(attempts_in_round),
            sqlite_time(observed_at_ms)?,
            &next_metadata_token[..],
            &approval.approval_id.as_bytes()[..],
            &physical.metadata_token,
        ],
    )? != 1
    {
        return Err(RuntimeStoreError::SchemaInspectionRaced);
    }
    config
        .fault_injector
        .before_operation(RuntimeStoreOperation::BeginApprovalAttemptBeforeCommit)?;
    sqlite::commit_transaction(transaction, RuntimeCommitOperation::BeginApprovalAttempt)?;
    Ok(ApprovalRecord {
        attempts_in_round,
        last_attempt_at_ms: Some(observed_at_ms),
        ..approval
    })
}

pub(super) fn validate_all_approval_metadata(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
) -> Result<ApprovalIntegritySummary, RuntimeStoreError> {
    let table_exists: i64 = connection.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM sqlite_master
             WHERE type = 'table' AND name = 'approval_ledger'
         )",
        [],
        |row| row.get(0),
    )?;
    if table_exists == 0 {
        return Ok(ApprovalIntegritySummary::default());
    }

    let mut summary = ApprovalIntegritySummary::default();
    // 逐 conversation 扫描 catalog，不能只遍历含 approval row 的集合：否则一条
    // 指向不存在 approval 的合法认证 ActionRequest/ApprovalResolved event 会逃过审计。
    let mut statement =
        connection.prepare("SELECT conversation_id FROM conversations ORDER BY conversation_id")?;
    let rows = statement.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
    for row in rows {
        let conversation_id = runtime_id(RuntimeIdKind::Conversation, row?)?;
        validate_approval_conversation(
            connection,
            key_bundle,
            database_id,
            conversation_id,
            &mut summary,
        )?;
    }
    Ok(summary)
}

fn validate_approval_conversation(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    conversation_id: RuntimeId,
    summary: &mut ApprovalIntegritySummary,
) -> Result<(), RuntimeStoreError> {
    let approval_count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM approval_ledger WHERE conversation_id = ?1",
        [&conversation_id.as_bytes()[..]],
        |row| row.get(0),
    )?;
    let approval_count =
        usize::try_from(approval_count).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    if u64::try_from(approval_count).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
        > MAX_DURABLE_APPROVALS
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let projection_bytes = approval_count
        .checked_mul(size_of::<ApprovalIntegrityRecord>())
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    if projection_bytes > MAX_APPROVAL_INTEGRITY_PROJECTION_BYTES {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let mut approvals: Vec<ApprovalIntegrityRecord> = Vec::new();
    approvals
        .try_reserve_exact(approval_count)
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let mut statement = connection.prepare(
        "SELECT approval_id FROM approval_ledger
         WHERE conversation_id = ?1
         ORDER BY approval_id",
    )?;
    let rows = statement.query_map([&conversation_id.as_bytes()[..]], |row| {
        row.get::<_, Vec<u8>>(0)
    })?;
    for row in rows {
        let approval_id = runtime_id(RuntimeIdKind::Approval, row?)?;
        let approval = load_approval(connection, key_bundle, database_id, approval_id)
            .map_err(map_integrity_error)?;
        validate_approval_record_linkage(connection, &approval)?;
        summary.approval_count = summary
            .approval_count
            .checked_add(1)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        if approval.state.is_active() {
            summary.active_approval_count = summary
                .active_approval_count
                .checked_add(1)
                .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        }
        summary.approval_event_count = summary
            .approval_event_count
            .checked_add(approval.state_version)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        let request = canonical_request(&approval.request)?;
        let request_token =
            key_bundle.blind_index(APPROVAL_INTEGRITY_REQUEST_TOKEN_DOMAIN, request.as_slice())?;
        approvals.push(ApprovalIntegrityRecord {
            approval_id,
            command_id: approval.command_id,
            turn_id: approval.turn_id,
            expected_state: approval.state,
            winner: approval.decision.as_ref().map(|decision| decision.decision),
            requested_at_ms: approval.requested_at_ms,
            state_version: approval.state_version,
            expected_last_event_id: approval.last_event_id,
            request_token: *request_token.as_bytes(),
            chain: ApprovalEventChainAccumulator::default(),
        });
    }
    drop(statement);
    if approvals.len() != approval_count {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }

    let mut statement = connection.prepare(
        "SELECT event_id FROM event_journal
         WHERE conversation_id = ?1
         ORDER BY event_seq",
    )?;
    let rows = statement.query_map([&conversation_id.as_bytes()[..]], |row| {
        row.get::<_, Vec<u8>>(0)
    })?;
    for row in rows {
        let event_id = runtime_id(RuntimeIdKind::Event, row?)?;
        let event = load_event(connection, key_bundle, database_id, event_id)
            .map_err(map_integrity_error)?;
        let Ok(decoded) = serde_json::from_slice::<RuntimeEvent>(&event.payload) else {
            continue;
        };
        if serde_json::to_vec(&decoded).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
            != event.payload
            || decoded.conversation_id.as_str() != event.conversation_id.to_canonical_string()
            || decoded.event_id.as_str() != event.event_id.to_canonical_string()
            || decoded.event_seq != event.event_seq
        {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        let (approval_index, turn_id, kind) = match decoded.body {
            RuntimeEventBody::ActionRequest {
                turn_id,
                approval_id,
                request,
            } => {
                let approval_id =
                    RuntimeId::parse_canonical(RuntimeIdKind::Approval, approval_id.as_str())?;
                let approval_index = approvals
                    .binary_search_by_key(&approval_id, |approval| approval.approval_id)
                    .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
                let request = canonical_request(&request)?;
                let request_token = key_bundle
                    .blind_index(APPROVAL_INTEGRITY_REQUEST_TOKEN_DOMAIN, request.as_slice())?;
                if request_token.as_bytes() != &approvals[approval_index].request_token
                    || event.created_at_ms != approvals[approval_index].requested_at_ms
                {
                    return Err(RuntimeStoreError::UnknownOrCorruptSchema);
                }
                (
                    approval_index,
                    RuntimeId::parse_canonical(RuntimeIdKind::Turn, turn_id.as_str())?,
                    ApprovalEventKind::Requested,
                )
            }
            RuntimeEventBody::ApprovalResolved {
                turn_id,
                approval_id,
                decision,
                state,
            } => {
                let approval_id =
                    RuntimeId::parse_canonical(RuntimeIdKind::Approval, approval_id.as_str())?;
                let approval_index = approvals
                    .binary_search_by_key(&approval_id, |approval| approval.approval_id)
                    .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
                (
                    approval_index,
                    RuntimeId::parse_canonical(RuntimeIdKind::Turn, turn_id.as_str())?,
                    ApprovalEventKind::Resolved { decision, state },
                )
            }
            _ => continue,
        };
        let approval = &mut approvals[approval_index];
        if event.conversation_id != conversation_id
            || event.command_id != Some(approval.command_id)
            || turn_id != approval.turn_id
        {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        fold_approval_event_chain(
            &mut approval.chain,
            event_id,
            event.event_seq,
            kind,
            approval.winner,
        )?;
    }

    for approval in approvals {
        validate_approval_event_chain(&approval)?;
    }
    Ok(())
}

fn canonical_request(request: &ActionRequest) -> Result<Zeroizing<Vec<u8>>, RuntimeStoreError> {
    let encoded = serde_json::to_vec(request)
        .map_err(|_| RuntimeStoreError::InvalidConfig("approval request encoding failed"))?;
    validate_nonempty_maximum(encoded.len(), MAX_APPROVAL_REQUEST_BYTES)?;
    Ok(Zeroizing::new(encoded))
}

fn map_integrity_error(error: RuntimeStoreError) -> RuntimeStoreError {
    match error {
        RuntimeStoreError::Cipher(_) => RuntimeStoreError::UnknownOrCorruptSchema,
        other => other,
    }
}

fn validate_approval_record_linkage(
    connection: &Connection,
    approval: &ApprovalRecord,
) -> Result<(), RuntimeStoreError> {
    if approval.deadline_at_ms <= approval.requested_at_ms
        || approval.state_changed_at_ms < approval.requested_at_ms
        || approval.state_version == 0
        || approval.attempts_in_round > 8
        || (matches!(
            approval.state,
            ApprovalState::Applied | ApprovalState::DeliveryFailed | ApprovalState::Expired
        ) && approval
            .last_attempt_at_ms
            .is_some_and(|last_attempt_at_ms| approval.state_changed_at_ms < last_attempt_at_ms))
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let row = connection
        .query_row(
            "SELECT conversation_id, state, turn_id FROM commands WHERE command_id = ?1",
            [&approval.command_id.as_bytes()[..]],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<Vec<u8>>>(2)?,
                ))
            },
        )
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let conversation_id = runtime_id(RuntimeIdKind::Conversation, row.0)?;
    let turn_id = row
        .2
        .map(|value| runtime_id(RuntimeIdKind::Turn, value))
        .transpose()?;
    if conversation_id != approval.conversation_id || turn_id != Some(approval.turn_id) {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let linked_command: Vec<u8> = connection
        .query_row(
            "SELECT command_id FROM execution_intents WHERE turn_id = ?1",
            [&approval.turn_id.as_bytes()[..]],
            |row| row.get(0),
        )
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    if runtime_id(RuntimeIdKind::Command, linked_command)? != approval.command_id
        || (approval.state.is_active() && row.1 != "started")
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    match approval.state {
        ApprovalState::Pending => {
            if approval.decision.is_some()
                || approval.claimed_at_ms.is_some()
                || approval.delivery_round != 0
                || approval.attempts_in_round != 0
                || approval.round_started_at_ms.is_some()
                || approval.last_attempt_at_ms.is_some()
                || approval.state_version != 1
                || approval.status_detail.is_some()
            {
                return Err(RuntimeStoreError::UnknownOrCorruptSchema);
            }
        }
        ApprovalState::Claimed => {
            if approval.decision.is_none()
                || approval.claimed_at_ms.is_none()
                || approval.delivery_round != 0
                || approval.attempts_in_round != 0
                || approval.round_started_at_ms.is_some()
                || approval.last_attempt_at_ms.is_some()
                || approval.state_version < 2
                || approval.status_detail.is_some()
                || approval
                    .claimed_at_ms
                    .is_some_and(|claimed_at_ms| claimed_at_ms >= approval.deadline_at_ms)
            {
                return Err(RuntimeStoreError::UnknownOrCorruptSchema);
            }
        }
        ApprovalState::Applying => {
            if approval.decision.is_none()
                || approval.claimed_at_ms.is_none()
                || approval.delivery_round == 0
                || approval.round_started_at_ms.is_none()
                || approval.state_version < 3
                || approval.status_detail.is_some()
                || (approval.attempts_in_round == 0) != approval.last_attempt_at_ms.is_none()
            {
                return Err(RuntimeStoreError::UnknownOrCorruptSchema);
            }
        }
        ApprovalState::Applied => {
            if approval.decision.is_none()
                || approval.claimed_at_ms.is_none()
                || approval.delivery_round == 0
                || approval.round_started_at_ms.is_none()
                || !(1..=8).contains(&approval.attempts_in_round)
                || approval.last_attempt_at_ms.is_none()
                || approval.status_detail.is_some()
                || approval.state_version < 4
            {
                return Err(RuntimeStoreError::UnknownOrCorruptSchema);
            }
        }
        ApprovalState::DeliveryFailed => {
            if approval.decision.is_none()
                || approval.claimed_at_ms.is_none()
                || approval.delivery_round == 0
                || approval.round_started_at_ms.is_none()
                || !(1..=8).contains(&approval.attempts_in_round)
                || approval.last_attempt_at_ms.is_none()
                || approval.status_detail.as_ref().is_none_or(Vec::is_empty)
                || approval.state_version < 4
            {
                return Err(RuntimeStoreError::UnknownOrCorruptSchema);
            }
        }
        ApprovalState::Expired => match approval.decision.as_ref() {
            None => {
                if approval.claimed_at_ms.is_some()
                    || approval.delivery_round != 0
                    || approval.attempts_in_round != 0
                    || approval.round_started_at_ms.is_some()
                    || approval.last_attempt_at_ms.is_some()
                    || approval.status_detail.is_some()
                    || approval.state_version != 2
                {
                    return Err(RuntimeStoreError::UnknownOrCorruptSchema);
                }
            }
            Some(_) => {
                if approval.claimed_at_ms.is_none()
                    || (approval.delivery_round == 0
                        && (approval.attempts_in_round != 0
                            || approval.round_started_at_ms.is_some()
                            || approval.last_attempt_at_ms.is_some()
                            || approval.status_detail.is_some()))
                    || (approval.delivery_round > 0
                        && (approval.round_started_at_ms.is_none()
                            || (approval.attempts_in_round == 0)
                                != approval.last_attempt_at_ms.is_none()))
                    || approval.state_version < 3
                {
                    return Err(RuntimeStoreError::UnknownOrCorruptSchema);
                }
            }
        },
    }
    if approval
        .claimed_at_ms
        .is_some_and(|claimed_at_ms| claimed_at_ms < approval.requested_at_ms)
        || approval
            .round_started_at_ms
            .zip(approval.claimed_at_ms)
            .is_some_and(|(round_started_at_ms, claimed_at_ms)| round_started_at_ms < claimed_at_ms)
        || approval
            .last_attempt_at_ms
            .zip(approval.round_started_at_ms)
            .is_some_and(|(last_attempt_at_ms, round_started_at_ms)| {
                last_attempt_at_ms < round_started_at_ms
            })
        || approval
            .round_started_at_ms
            .is_some_and(|round_started_at_ms| round_started_at_ms >= approval.deadline_at_ms)
        || approval
            .last_attempt_at_ms
            .is_some_and(|last_attempt_at_ms| last_attempt_at_ms >= approval.deadline_at_ms)
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(())
}

fn validate_approval_event_chain(
    approval: &ApprovalIntegrityRecord,
) -> Result<(), RuntimeStoreError> {
    if approval.chain.event_count != approval.state_version
        || approval.chain.last_event_id != Some(approval.expected_last_event_id)
        || approval.chain.state != Some(approval.expected_state)
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(())
}

fn fold_approval_event_chain(
    chain: &mut ApprovalEventChainAccumulator,
    event_id: RuntimeId,
    event_seq: u64,
    kind: ApprovalEventKind,
    winner: Option<agentdeck_protocol::ActionDecisionKind>,
) -> Result<(), RuntimeStoreError> {
    if chain
        .last_event_seq
        .is_some_and(|last_event_seq| event_seq <= last_event_seq)
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let next_state = match (chain.state, kind) {
        (None, ApprovalEventKind::Requested) => ApprovalState::Pending,
        (
            Some(state),
            ApprovalEventKind::Resolved {
                decision,
                state: next,
            },
        ) => {
            let next_state = match next {
                ApprovalDeliveryState::Claimed => ApprovalState::Claimed,
                ApprovalDeliveryState::Applying => ApprovalState::Applying,
                ApprovalDeliveryState::Applied => ApprovalState::Applied,
                ApprovalDeliveryState::DeliveryFailed => ApprovalState::DeliveryFailed,
                ApprovalDeliveryState::Expired => ApprovalState::Expired,
            };
            let legal = matches!(
                (state, next_state),
                (ApprovalState::Pending, ApprovalState::Claimed)
                    | (ApprovalState::Pending, ApprovalState::Expired)
                    | (ApprovalState::Claimed, ApprovalState::Applying)
                    | (ApprovalState::Claimed, ApprovalState::Expired)
                    | (ApprovalState::Applying, ApprovalState::Applied)
                    | (ApprovalState::Applying, ApprovalState::DeliveryFailed)
                    | (ApprovalState::Applying, ApprovalState::Expired)
                    | (ApprovalState::DeliveryFailed, ApprovalState::Applying)
                    | (ApprovalState::DeliveryFailed, ApprovalState::Expired)
            );
            if !legal {
                return Err(RuntimeStoreError::UnknownOrCorruptSchema);
            }
            if next_state == ApprovalState::Expired && state == ApprovalState::Pending {
                if decision.is_some() || winner.is_some() {
                    return Err(RuntimeStoreError::UnknownOrCorruptSchema);
                }
            } else if decision != winner || winner.is_none() {
                return Err(RuntimeStoreError::UnknownOrCorruptSchema);
            }
            next_state
        }
        _ => {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
    };
    chain.event_count = chain
        .event_count
        .checked_add(1)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    chain.state = Some(next_state);
    chain.last_event_id = Some(event_id);
    chain.last_event_seq = Some(event_seq);
    Ok(())
}

fn canonical_decision(decision: &ActionDecision) -> Result<Zeroizing<Vec<u8>>, RuntimeStoreError> {
    let encoded = serde_json::to_vec(decision)
        .map_err(|_| RuntimeStoreError::InvalidConfig("approval decision encoding failed"))?;
    validate_nonempty_maximum(encoded.len(), MAX_APPROVAL_DECISION_BYTES)?;
    Ok(Zeroizing::new(encoded))
}

fn parse_decision(encoded: &[u8]) -> Result<ActionDecision, RuntimeStoreError> {
    validate_nonempty_maximum(encoded.len(), MAX_APPROVAL_DECISION_BYTES)
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let decision: ActionDecision =
        serde_json::from_slice(encoded).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let canonical =
        serde_json::to_vec(&decision).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    if canonical != encoded {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(decision)
}

fn canonical_request_envelope(
    request: &ActionRequest,
    policy: &ApprovalPolicySnapshot,
) -> Result<Zeroizing<Vec<u8>>, RuntimeStoreError> {
    let envelope = ApprovalRequestEnvelope {
        request: request.clone(),
        policy: policy.clone(),
    };
    let encoded = serde_json::to_vec(&envelope)
        .map_err(|_| RuntimeStoreError::InvalidConfig("approval request encoding failed"))?;
    validate_nonempty_maximum(encoded.len(), MAX_APPROVAL_REQUEST_BYTES)?;
    Ok(Zeroizing::new(encoded))
}

fn parse_request_envelope(encoded: &[u8]) -> Result<ApprovalRequestEnvelope, RuntimeStoreError> {
    validate_nonempty_maximum(encoded.len(), MAX_APPROVAL_REQUEST_BYTES)
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let envelope: ApprovalRequestEnvelope =
        serde_json::from_slice(encoded).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    envelope
        .policy
        .validate_request(&envelope.request)
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let canonical =
        serde_json::to_vec(&envelope).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    if canonical != encoded {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(envelope)
}

fn canonical_action_request_event(
    conversation_id: RuntimeId,
    event_id: RuntimeId,
    event_seq: u64,
    turn_id: RuntimeId,
    approval_id: RuntimeId,
    request: &ActionRequest,
) -> Result<Zeroizing<Vec<u8>>, RuntimeStoreError> {
    let event = RuntimeEvent {
        conversation_id: ConversationId::new(conversation_id.to_canonical_string()),
        event_id: EventId::new(event_id.to_canonical_string()),
        event_seq,
        item_id: None,
        entity_id: None,
        body: RuntimeEventBody::ActionRequest {
            turn_id: TurnId::new(turn_id.to_canonical_string()),
            approval_id: ApprovalId::new(approval_id.to_canonical_string()),
            request: request.clone(),
        },
    };
    Ok(Zeroizing::new(serde_json::to_vec(&event).map_err(
        |_| RuntimeStoreError::InvalidConfig("approval event encoding failed"),
    )?))
}

fn canonical_claimed_event(
    conversation_id: RuntimeId,
    event_id: RuntimeId,
    event_seq: u64,
    turn_id: RuntimeId,
    approval_id: RuntimeId,
    decision: agentdeck_protocol::ActionDecisionKind,
) -> Result<Zeroizing<Vec<u8>>, RuntimeStoreError> {
    canonical_resolved_event(
        conversation_id,
        event_id,
        event_seq,
        turn_id,
        approval_id,
        Some(decision),
        ApprovalDeliveryState::Claimed,
    )
}

#[allow(clippy::too_many_arguments)]
fn canonical_resolved_event(
    conversation_id: RuntimeId,
    event_id: RuntimeId,
    event_seq: u64,
    turn_id: RuntimeId,
    approval_id: RuntimeId,
    decision: Option<agentdeck_protocol::ActionDecisionKind>,
    state: ApprovalDeliveryState,
) -> Result<Zeroizing<Vec<u8>>, RuntimeStoreError> {
    let event = RuntimeEvent {
        conversation_id: ConversationId::new(conversation_id.to_canonical_string()),
        event_id: EventId::new(event_id.to_canonical_string()),
        event_seq,
        item_id: None,
        entity_id: None,
        body: RuntimeEventBody::ApprovalResolved {
            turn_id: TurnId::new(turn_id.to_canonical_string()),
            approval_id: ApprovalId::new(approval_id.to_canonical_string()),
            decision,
            state,
        },
    };
    Ok(Zeroizing::new(serde_json::to_vec(&event).map_err(
        |_| RuntimeStoreError::InvalidConfig("approval event encoding failed"),
    )?))
}

fn ensure_exact_started_turn(
    connection: &Connection,
    conversation_id: RuntimeId,
    command_id: RuntimeId,
    turn_id: RuntimeId,
    observed_at_ms: u64,
) -> Result<(), RuntimeStoreError> {
    let row = connection
        .query_row(
            "SELECT conversation_id, state, turn_id, started_at_ms
             FROM commands WHERE command_id = ?1",
            [&command_id.as_bytes()[..]],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<Vec<u8>>>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                ))
            },
        )
        .map_err(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => RuntimeStoreError::CommandNotFound,
            other => RuntimeStoreError::Sqlite(other),
        })?;
    let persisted_conversation = runtime_id(RuntimeIdKind::Conversation, row.0)?;
    let persisted_turn = row
        .2
        .map(|value| runtime_id(RuntimeIdKind::Turn, value))
        .transpose()?;
    if persisted_conversation != conversation_id
        || row.1 != "started"
        || persisted_turn != Some(turn_id)
    {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }
    let started_at_ms = row
        .3
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)
        .and_then(runtime_time)?;
    if observed_at_ms < started_at_ms {
        return Err(RuntimeStoreError::ClockRegressed {
            persisted_ms: started_at_ms,
            observed_ms: observed_at_ms,
        });
    }
    let linked_command: Vec<u8> = connection
        .query_row(
            "SELECT command_id FROM execution_intents WHERE turn_id = ?1",
            [&turn_id.as_bytes()[..]],
            |row| row.get(0),
        )
        .map_err(|_| RuntimeStoreError::InvalidStateTransition)?;
    if runtime_id(RuntimeIdKind::Command, linked_command)? != command_id {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }
    Ok(())
}

fn is_exact_started_turn(
    connection: &Connection,
    conversation_id: RuntimeId,
    command_id: RuntimeId,
    turn_id: RuntimeId,
) -> Result<bool, RuntimeStoreError> {
    let exists: i64 = connection.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM commands AS command
             JOIN execution_intents AS intent
               ON intent.command_id = command.command_id
              AND intent.turn_id = command.turn_id
             WHERE command.command_id = ?1
               AND command.conversation_id = ?2
               AND command.turn_id = ?3
               AND command.state = 'started'
         )",
        params![
            &command_id.as_bytes()[..],
            &conversation_id.as_bytes()[..],
            &turn_id.as_bytes()[..],
        ],
        |row| row.get(0),
    )?;
    Ok(exists == 1)
}

fn approval_id_for_request(
    connection: &Connection,
    turn_id: RuntimeId,
    request_token: &[u8],
) -> Result<Option<RuntimeId>, RuntimeStoreError> {
    connection
        .query_row(
            "SELECT approval_id FROM approval_ledger
             WHERE turn_id = ?1 AND request_token = ?2",
            params![&turn_id.as_bytes()[..], request_token],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?
        .map(|value| runtime_id(RuntimeIdKind::Approval, value))
        .transpose()
}

fn load_approval_physical(
    connection: &Connection,
    approval_id: RuntimeId,
) -> Result<ApprovalPhysical, RuntimeStoreError> {
    connection
        .query_row(
            "SELECT request_token, decision_token, claimant_token,
                    logical_request_bytes, metadata_token, sealed_request,
                    sealed_decision, sealed_status_detail
             FROM approval_ledger WHERE approval_id = ?1",
            [&approval_id.as_bytes()[..]],
            |row| {
                let sealed_request = row.get::<_, Vec<u8>>(5)?;
                let sealed_status_detail = row.get::<_, Option<Vec<u8>>>(7)?;
                Ok(ApprovalPhysical {
                    request_token: row.get(0)?,
                    decision_token: row.get(1)?,
                    claimant_token: row.get(2)?,
                    logical_request_bytes: u64::try_from(row.get::<_, i64>(3)?).map_err(
                        |error| {
                            rusqlite::Error::FromSqlConversionFailure(
                                3,
                                rusqlite::types::Type::Integer,
                                Box::new(error),
                            )
                        },
                    )?,
                    metadata_token: row.get(4)?,
                    sealed_request_len: sealed_request.len(),
                    sealed_decision: row.get(6)?,
                    sealed_status_detail_len: sealed_status_detail.as_ref().map(Vec::len),
                })
            },
        )
        .map_err(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => RuntimeStoreError::InvalidStateTransition,
            other => RuntimeStoreError::Sqlite(other),
        })
}

fn load_conversation_metadata(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    _database_id: [u8; 16],
    conversation_id: RuntimeId,
) -> Result<ConversationMetadata, RuntimeStoreError> {
    let raw = connection
        .query_row(
            "SELECT adapter_state_key, catalog_revision, command_high_water,
                    event_high_water, accepted_count, lifecycle,
                    created_at_ms, updated_at_ms, metadata_token
             FROM conversations WHERE conversation_id = ?1",
            [&conversation_id.as_bytes()[..]],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, Vec<u8>>(8)?,
                ))
            },
        )
        .map_err(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => RuntimeStoreError::ConversationNotFound,
            other => RuntimeStoreError::Sqlite(other),
        })?;
    let metadata = ConversationMetadata {
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
        accepted_command_count: u32::try_from(raw.4)
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
        lifecycle: parse_lifecycle(&raw.5)?,
        created_at_ms: runtime_time(raw.6)?,
        updated_at_ms: runtime_time(raw.7)?,
        metadata_token: raw.8,
    };
    let expected = conversation_metadata_token(key_bundle, &metadata)?;
    if metadata.metadata_token.as_slice() != expected {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(metadata)
}

fn update_conversation_event_high_water(
    transaction: &Transaction<'_>,
    key_bundle: &RuntimeKeyBundle,
    mut current: ConversationMetadata,
    next: &str,
    previous: Option<&str>,
    observed_at_ms: u64,
) -> Result<(), RuntimeStoreError> {
    if current
        .event_high_water
        .map(super::sequence::encode_sequence)
        .as_deref()
        != previous
    {
        return Err(RuntimeStoreError::SchemaInspectionRaced);
    }
    let old_token = conversation_metadata_token(key_bundle, &current)?;
    current.event_high_water = Some(decode_sequence(SequenceScope::EventSeq, next)?);
    current.updated_at_ms = current.updated_at_ms.max(observed_at_ms);
    let new_token = conversation_metadata_token(key_bundle, &current)?;
    if transaction.execute(
        "UPDATE conversations
         SET event_high_water = ?1, updated_at_ms = ?2, metadata_token = ?3
         WHERE conversation_id = ?4
           AND ((?5 IS NULL AND event_high_water IS NULL) OR event_high_water = ?5)
           AND metadata_token = ?6",
        params![
            next,
            sqlite_time(current.updated_at_ms)?,
            &new_token[..],
            &current.conversation_id.as_bytes()[..],
            previous,
            &old_token[..],
        ],
    )? != 1
    {
        return Err(RuntimeStoreError::SchemaInspectionRaced);
    }
    Ok(())
}

fn conversation_metadata_token(
    key_bundle: &RuntimeKeyBundle,
    value: &ConversationMetadata,
) -> Result<[u8; 32], RuntimeStoreError> {
    let catalog_revision = super::sequence::encode_sequence(value.catalog_revision);
    let command_high_water = value
        .command_high_water
        .map(super::sequence::encode_sequence);
    let event_high_water = value.event_high_water.map(super::sequence::encode_sequence);
    let command_high_water = optional_field(command_high_water.as_deref().map(str::as_bytes));
    let event_high_water = optional_field(event_high_water.as_deref().map(str::as_bytes));
    metadata_mac(
        key_bundle,
        b"conversation.metadata.v1",
        &[
            value.conversation_id.as_bytes(),
            value.adapter_state_key.as_bytes(),
            catalog_revision.as_bytes(),
            &command_high_water,
            &event_high_water,
            &value.accepted_command_count.to_be_bytes(),
            lifecycle_text(value.lifecycle).as_bytes(),
            &value.created_at_ms.to_be_bytes(),
            &value.updated_at_ms.to_be_bytes(),
        ],
    )
}

#[allow(clippy::too_many_lines)]
fn load_approval(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    approval_id: RuntimeId,
) -> Result<ApprovalRecord, RuntimeStoreError> {
    let raw = connection
        .query_row(
            "SELECT conversation_id, command_id, turn_id, request_token,
                    decision_token, claimant_token, state, requested_at_ms,
                    deadline_at_ms, claimed_at_ms, state_changed_at_ms,
                    delivery_round, attempts_in_round, round_started_at_ms,
                    last_attempt_at_ms, state_version, last_event_id,
                    logical_request_bytes, logical_decision_bytes, metadata_token,
                    sealed_request, sealed_decision, sealed_status_detail
             FROM approval_ledger WHERE approval_id = ?1",
            [&approval_id.as_bytes()[..]],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Option<Vec<u8>>>(4)?,
                    row.get::<_, Option<Vec<u8>>>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, Option<i64>>(9)?,
                    row.get::<_, i64>(10)?,
                    row.get::<_, i64>(11)?,
                    row.get::<_, i64>(12)?,
                    row.get::<_, Option<i64>>(13)?,
                    row.get::<_, Option<i64>>(14)?,
                    row.get::<_, i64>(15)?,
                    row.get::<_, Vec<u8>>(16)?,
                    row.get::<_, i64>(17)?,
                    row.get::<_, i64>(18)?,
                    row.get::<_, Vec<u8>>(19)?,
                    row.get::<_, Vec<u8>>(20)?,
                    row.get::<_, Option<Vec<u8>>>(21)?,
                    row.get::<_, Option<Vec<u8>>>(22)?,
                ))
            },
        )
        .map_err(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => RuntimeStoreError::InvalidStateTransition,
            other => RuntimeStoreError::Sqlite(other),
        })?;
    let conversation_id = runtime_id(RuntimeIdKind::Conversation, raw.0)?;
    let command_id = runtime_id(RuntimeIdKind::Command, raw.1)?;
    let turn_id = runtime_id(RuntimeIdKind::Turn, raw.2)?;
    let state = parse_approval_state(&raw.6)?;
    let requested_at_ms = runtime_time(raw.7)?;
    let deadline_at_ms = runtime_time(raw.8)?;
    let claimed_at_ms = raw.9.map(runtime_time).transpose()?;
    let state_changed_at_ms = runtime_time(raw.10)?;
    let delivery_round =
        u32::try_from(raw.11).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let attempts_in_round =
        u8::try_from(raw.12).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let round_started_at_ms = raw.13.map(runtime_time).transpose()?;
    let last_attempt_at_ms = raw.14.map(runtime_time).transpose()?;
    let state_version =
        u64::try_from(raw.15).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let last_event_id = runtime_id(RuntimeIdKind::Event, raw.16)?;
    let logical_request_bytes =
        u64::try_from(raw.17).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let logical_decision_bytes =
        u64::try_from(raw.18).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let expected_metadata = approval_metadata_token(
        key_bundle,
        ApprovalMetadataFields {
            approval_id,
            conversation_id,
            command_id,
            turn_id,
            request_token: &raw.3,
            decision_token: raw.4.as_deref(),
            claimant_token: raw.5.as_deref(),
            state,
            requested_at_ms,
            deadline_at_ms,
            claimed_at_ms,
            state_changed_at_ms,
            delivery_round,
            attempts_in_round,
            round_started_at_ms,
            last_attempt_at_ms,
            state_version,
            last_event_id,
            logical_request_bytes,
            logical_decision_bytes,
            sealed_request_len: raw.20.len(),
            sealed_decision_len: raw.21.as_ref().map(Vec::len),
            sealed_status_detail_len: raw.22.as_ref().map(Vec::len),
        },
    )?;
    if raw.19.as_slice() != expected_metadata {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let request_plaintext = open(
        key_bundle,
        database_id,
        b"approval_ledger",
        approval_id.as_bytes(),
        b"sealed_request",
        &raw.20,
        MAX_APPROVAL_REQUEST_BYTES,
    )?;
    if logical_request_bytes
        != u64::try_from(request_plaintext.expose_secret().len())
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let envelope = parse_request_envelope(request_plaintext.expose_secret())?;
    envelope
        .policy
        .validate_request(&envelope.request)
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let expected_deadline_at_ms = envelope
        .policy
        .effective_deadline_at_ms(requested_at_ms)
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    if deadline_at_ms != expected_deadline_at_ms {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let expected_request_token = key_bundle.blind_index(
        APPROVAL_REQUEST_TOKEN_DOMAIN,
        envelope.request.request_id.as_bytes(),
    )?;
    if raw.3.as_slice() != expected_request_token.as_bytes() {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let decision = match (
        raw.4.as_deref(),
        raw.5.as_deref(),
        raw.21.as_deref(),
        claimed_at_ms,
    ) {
        (None, None, None, None)
            if matches!(state, ApprovalState::Pending | ApprovalState::Expired) =>
        {
            if logical_decision_bytes != 0
                || (state == ApprovalState::Pending && state_version != 1)
                || (state == ApprovalState::Expired && state_version < 2)
            {
                return Err(RuntimeStoreError::UnknownOrCorruptSchema);
            }
            None
        }
        (Some(decision_token), Some(_claimant_token), Some(sealed_decision), Some(_))
            if state != ApprovalState::Pending =>
        {
            let plaintext = open(
                key_bundle,
                database_id,
                b"approval_ledger",
                approval_id.as_bytes(),
                b"sealed_decision",
                sealed_decision,
                MAX_APPROVAL_DECISION_BYTES,
            )?;
            if logical_decision_bytes
                != u64::try_from(plaintext.expose_secret().len())
                    .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
            {
                return Err(RuntimeStoreError::UnknownOrCorruptSchema);
            }
            let parsed = parse_decision(plaintext.expose_secret())?;
            envelope
                .policy
                .validate_decision(&envelope.request, &parsed)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
            let expected = key_bundle
                .blind_index(APPROVAL_DECISION_TOKEN_DOMAIN, plaintext.expose_secret())?;
            if decision_token != expected.as_bytes() || state_version < 2 {
                return Err(RuntimeStoreError::UnknownOrCorruptSchema);
            }
            Some(parsed)
        }
        _ => return Err(RuntimeStoreError::UnknownOrCorruptSchema),
    };
    let status_detail = raw
        .22
        .as_deref()
        .map(|sealed| {
            open(
                key_bundle,
                database_id,
                b"approval_ledger",
                approval_id.as_bytes(),
                b"sealed_status_detail",
                sealed,
                MAX_APPROVAL_STATUS_DETAIL_BYTES,
            )
            .map(|plaintext| plaintext.expose_secret().to_vec())
        })
        .transpose()?;
    Ok(ApprovalRecord {
        approval_id,
        conversation_id,
        command_id,
        turn_id,
        state,
        request: envelope.request,
        policy: envelope.policy,
        decision,
        requested_at_ms,
        deadline_at_ms,
        claimed_at_ms,
        state_changed_at_ms,
        delivery_round,
        attempts_in_round,
        round_started_at_ms,
        last_attempt_at_ms,
        state_version,
        last_event_id,
        status_detail,
    })
}

/// 热路径只认证全局 ledger MAC、目标 approval row 及其 command/turn 绑定。
/// 全库 approval/event 解密扫描只属于 open/recovery/integrity audit，不能进入每次 delivery mutation。
fn load_authenticated_approval_target(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    approval_id: RuntimeId,
) -> Result<(RuntimeLedger, ApprovalRecord), RuntimeStoreError> {
    let ledger = sqlite::load_runtime_ledger(connection, key_bundle, database_id)?;
    let approval = load_approval(connection, key_bundle, database_id, approval_id)?;
    validate_approval_target_linkage(connection, &approval)?;
    Ok((ledger, approval))
}

/// Mutation target 只验证不可变 command/turn 绑定；command 已 terminal 正是 stale approval
/// 需要被安全收口的合法输入，不能误判为数据库损坏。
fn validate_approval_target_linkage(
    connection: &Connection,
    approval: &ApprovalRecord,
) -> Result<(), RuntimeStoreError> {
    let row = connection
        .query_row(
            "SELECT conversation_id, turn_id FROM commands WHERE command_id = ?1",
            [&approval.command_id.as_bytes()[..]],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Option<Vec<u8>>>(1)?)),
        )
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let conversation_id = runtime_id(RuntimeIdKind::Conversation, row.0)?;
    let turn_id = row
        .1
        .map(|value| runtime_id(RuntimeIdKind::Turn, value))
        .transpose()?;
    let linked_command: Vec<u8> = connection
        .query_row(
            "SELECT command_id FROM execution_intents WHERE turn_id = ?1",
            [&approval.turn_id.as_bytes()[..]],
            |row| row.get(0),
        )
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    if conversation_id != approval.conversation_id
        || turn_id != Some(approval.turn_id)
        || runtime_id(RuntimeIdKind::Command, linked_command)? != approval.command_id
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(())
}

fn load_event(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
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
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let conversation_id = runtime_id(RuntimeIdKind::Conversation, raw.0)?;
    let event_seq = decode_sequence(SequenceScope::EventSeq, &raw.1)?;
    let command_id = raw
        .2
        .map(|value| runtime_id(RuntimeIdKind::Command, value))
        .transpose()?;
    let logical_event_bytes =
        u64::try_from(raw.3).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let created_at_ms = runtime_time(raw.4)?;
    let expected_metadata = event_metadata_token(
        key_bundle,
        conversation_id,
        event_id,
        event_seq,
        command_id,
        logical_event_bytes,
        created_at_ms,
    )?;
    if raw.5.as_slice() != expected_metadata {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let payload = open(
        key_bundle,
        database_id,
        b"event_journal",
        event_id.as_bytes(),
        b"sealed_event",
        &raw.6,
        MAX_RUNTIME_EVENT_BYTES,
    )?;
    if logical_event_bytes
        != u64::try_from(payload.expose_secret().len())
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
    {
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

fn approval_metadata_token(
    key_bundle: &RuntimeKeyBundle,
    fields: ApprovalMetadataFields<'_>,
) -> Result<[u8; 32], RuntimeStoreError> {
    let decision_token = optional_field(fields.decision_token);
    let claimant_token = optional_field(fields.claimant_token);
    let claimed_at_ms = optional_u64(fields.claimed_at_ms);
    let round_started_at_ms = optional_u64(fields.round_started_at_ms);
    let last_attempt_at_ms = optional_u64(fields.last_attempt_at_ms);
    let sealed_decision_len = optional_usize(fields.sealed_decision_len)?;
    let sealed_status_detail_len = optional_usize(fields.sealed_status_detail_len)?;
    metadata_mac(
        key_bundle,
        APPROVAL_METADATA_TOKEN_DOMAIN,
        &[
            fields.approval_id.as_bytes(),
            fields.conversation_id.as_bytes(),
            fields.command_id.as_bytes(),
            fields.turn_id.as_bytes(),
            fields.request_token,
            &decision_token,
            &claimant_token,
            approval_state_text(fields.state).as_bytes(),
            &fields.requested_at_ms.to_be_bytes(),
            &fields.deadline_at_ms.to_be_bytes(),
            &claimed_at_ms,
            &fields.state_changed_at_ms.to_be_bytes(),
            &fields.delivery_round.to_be_bytes(),
            &[fields.attempts_in_round],
            &round_started_at_ms,
            &last_attempt_at_ms,
            &fields.state_version.to_be_bytes(),
            fields.last_event_id.as_bytes(),
            &fields.logical_request_bytes.to_be_bytes(),
            &fields.logical_decision_bytes.to_be_bytes(),
            &u64::try_from(fields.sealed_request_len)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
                .to_be_bytes(),
            &sealed_decision_len,
            &sealed_status_detail_len,
        ],
    )
}

#[allow(clippy::too_many_arguments)]
fn event_metadata_token(
    key_bundle: &RuntimeKeyBundle,
    conversation_id: RuntimeId,
    event_id: RuntimeId,
    event_seq: u64,
    command_id: Option<RuntimeId>,
    logical_event_bytes: u64,
    created_at_ms: u64,
) -> Result<[u8; 32], RuntimeStoreError> {
    let event_seq = super::sequence::encode_sequence(event_seq);
    let command_id = optional_field(command_id.as_ref().map(|value| &value.as_bytes()[..]));
    metadata_mac(
        key_bundle,
        b"event.metadata.v1",
        &[
            conversation_id.as_bytes(),
            event_id.as_bytes(),
            event_seq.as_bytes(),
            &command_id,
            &logical_event_bytes.to_be_bytes(),
            &created_at_ms.to_be_bytes(),
        ],
    )
}

fn metadata_mac(
    key_bundle: &RuntimeKeyBundle,
    domain: &[u8],
    fields: &[&[u8]],
) -> Result<[u8; 32], RuntimeStoreError> {
    let encoded = Zeroizing::new(encode_fields(b"ADF1", fields)?);
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

fn optional_u64(value: Option<u64>) -> Vec<u8> {
    match value {
        None => optional_field(None),
        Some(value) => optional_field(Some(&value.to_be_bytes())),
    }
}

fn optional_usize(value: Option<usize>) -> Result<Vec<u8>, RuntimeStoreError> {
    let value = value
        .map(u64::try_from)
        .transpose()
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    Ok(optional_u64(value))
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

fn allocate_id(
    transaction: &Transaction<'_>,
    config: &RuntimeStoreConfig,
    kind: RuntimeIdKind,
) -> Result<RuntimeId, RuntimeStoreError> {
    let mut source = config
        .id_source
        .lock()
        .map_err(|_| RuntimeStoreError::WorkerStopped)?;
    let sql = match kind {
        RuntimeIdKind::Approval => {
            "SELECT EXISTS(SELECT 1 FROM approval_ledger WHERE approval_id = ?1)"
        }
        RuntimeIdKind::Event => "SELECT EXISTS(SELECT 1 FROM event_journal WHERE event_id = ?1)",
        _ => {
            return Err(RuntimeStoreError::InvalidConfig(
                "approval store cannot allocate this id kind",
            ));
        }
    };
    for _ in 0..MAX_RUNTIME_ID_COLLISION_ATTEMPTS {
        let candidate = source.next_id(kind)?;
        if candidate.kind() != kind {
            return Err(RuntimeIdError::SourceKindMismatch {
                kind,
                actual: candidate.kind(),
            }
            .into());
        }
        let exists: i64 =
            transaction.query_row(sql, [&candidate.as_bytes()[..]], |row| row.get(0))?;
        if exists == 0 {
            return Ok(candidate);
        }
    }
    Err(RuntimeIdError::CollisionExhausted {
        kind,
        attempts: MAX_RUNTIME_ID_COLLISION_ATTEMPTS,
    }
    .into())
}

fn seal(
    key_bundle: &RuntimeKeyBundle,
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
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    table: &[u8],
    primary_key: &[u8],
    column: &[u8],
    ciphertext: &[u8],
    maximum_plaintext_len: usize,
) -> Result<SecretBytes, RuntimeStoreError> {
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

fn parse_approval_state(value: &str) -> Result<ApprovalState, RuntimeStoreError> {
    match value {
        "pending" => Ok(ApprovalState::Pending),
        "claimed" => Ok(ApprovalState::Claimed),
        "applying" => Ok(ApprovalState::Applying),
        "applied" => Ok(ApprovalState::Applied),
        "deliveryFailed" => Ok(ApprovalState::DeliveryFailed),
        "expired" => Ok(ApprovalState::Expired),
        _ => Err(RuntimeStoreError::UnknownOrCorruptSchema),
    }
}

const fn approval_state_text(state: ApprovalState) -> &'static str {
    match state {
        ApprovalState::Pending => "pending",
        ApprovalState::Claimed => "claimed",
        ApprovalState::Applying => "applying",
        ApprovalState::Applied => "applied",
        ApprovalState::DeliveryFailed => "deliveryFailed",
        ApprovalState::Expired => "expired",
    }
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

fn validate_nonempty_maximum(actual: usize, maximum: usize) -> Result<(), RuntimeStoreError> {
    if actual == 0 {
        Err(RuntimeStoreError::InvalidConfig(
            "approval payload must not be empty",
        ))
    } else if actual > maximum {
        Err(RuntimeStoreError::PayloadTooLarge)
    } else {
        Ok(())
    }
}

fn projected_write_bytes(lengths: &[usize]) -> Result<u64, RuntimeStoreError> {
    lengths
        .iter()
        .try_fold(RUNTIME_WRITE_FIXED_OVERHEAD_BYTES, |total, length| {
            total
                .checked_add(u64::try_from(*length).map_err(|_| {
                    RuntimeStoreError::CapacityArithmeticOverflow {
                        field: "approval projected write bytes",
                    }
                })?)
                .ok_or(RuntimeStoreError::CapacityArithmeticOverflow {
                    field: "approval projected write bytes",
                })
        })
}

fn copy_ledger(ledger: &RuntimeLedger) -> RuntimeLedger {
    RuntimeLedger {
        catalog_high_water: ledger.catalog_high_water.clone(),
        conversation_count: ledger.conversation_count,
        command_count: ledger.command_count,
        event_count: ledger.event_count,
        intent_count: ledger.intent_count,
        fence_count: ledger.fence_count,
        codex_adapter_state_count: ledger.codex_adapter_state_count,
        claude_code_adapter_state_count: ledger.claude_code_adapter_state_count,
        approval_count: ledger.approval_count,
        active_approval_count: ledger.active_approval_count,
        accepted_count: ledger.accepted_count,
        accepted_payload_bytes: ledger.accepted_payload_bytes,
        started_without_fence_count: ledger.started_without_fence_count,
        started_without_release_count: ledger.started_without_release_count,
        started_released_count: ledger.started_released_count,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ApprovalEventChainAccumulator, ApprovalEventKind, ApprovalIntegrityRecord,
        MAX_APPROVAL_INTEGRITY_PROJECTION_BYTES, fold_approval_event_chain,
        validate_approval_record_linkage,
    };
    use std::collections::VecDeque;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};

    use agentdeck_protocol::runtime::identity::{ApprovalId, ConversationId, EventId, TurnId};
    use agentdeck_protocol::runtime::{RuntimeEvent, RuntimeEventBody};
    use agentdeck_protocol::{
        ActionDecision, ActionDecisionKind, ActionKind, ActionRequest, ActionRequestVendor,
        AgentKind, CodexApprovalPolicy, CodexSandboxMode,
    };

    use crate::runtime::approval::{
        ApprovalPermissionGrant, ApprovalPolicySnapshot, ApprovalPrincipalCapability,
    };
    use crate::runtime::connection::PrincipalIssuer;
    use crate::runtime::model::{
        AcceptCommand, AcceptOutcome, ApprovalMutationOutcome, ApprovalRecord, ApprovalState,
        AuthorizeExecutionRelease, BeginApprovalAttempt, BeginApprovalAttemptOutcome,
        ClaimApproval, CompleteCommand, CompleteOutcome, ConversationDescriptor, ExecutionFence,
        ExpireApproval, IdempotencyOwner, MarkApprovalApplied, MarkApprovalDeliveryFailed,
        NewConversation, RegisterApproval, RegisterApprovalOutcome, RetryApprovalDelivery,
        RuntimeCapacityObservation, RuntimeCapacityProbe, RuntimeCapacityProbeError, RuntimeClock,
        RuntimeClockError, RuntimeCommitOperation, RuntimeStoreConfig, RuntimeStoreError,
        RuntimeStoreFaultInjector, RuntimeStoreOperation, StartCommand, StartOutcome,
        StartedBeforeReleaseTermination, TerminalState, TerminateStartedBeforeRelease,
        TerminateStartedBeforeReleaseOutcome,
    };
    use crate::runtime::store::cipher::{KeyWrapAad, RuntimeKeyBundle};
    use crate::runtime::store::schema::{RUNTIME_CRYPTO_CONTEXT_VERSION, RUNTIME_SCHEMA_FAMILY};
    use crate::runtime::store::sequence::{SequenceScope, decode_sequence};
    use crate::runtime::store::{RuntimeId, RuntimeIdKind, RuntimeStoreHandle};
    use crate::security::{MemoryKeyStore, StorageKek, load_or_create_storage_kek};

    static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new(label: &str) -> Self {
            let sequence = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "agentdeckd-runtime-approval-{label}-{}-{sequence}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir(&path).expect("create approval test root");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                    .expect("secure approval test root");
            }
            Self(path)
        }

        fn database(&self) -> PathBuf {
            self.0.join("runtime.db")
        }

        fn storage_kek(&self, keys: &MemoryKeyStore) -> StorageKek {
            load_or_create_storage_kek(keys, &self.0.join("key-state.db"))
                .expect("load approval test StorageKEK")
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[derive(Clone, Debug)]
    struct ManualClock(Arc<AtomicU64>);

    impl ManualClock {
        fn new(now_ms: u64) -> Self {
            Self(Arc::new(AtomicU64::new(now_ms)))
        }

        fn set(&self, now_ms: u64) {
            self.0.store(now_ms, Ordering::SeqCst);
        }
    }

    impl RuntimeClock for ManualClock {
        fn now_ms(&self) -> Result<u64, RuntimeClockError> {
            Ok(self.0.load(Ordering::SeqCst))
        }
    }

    #[derive(Clone, Debug)]
    struct ArmableClock {
        steady_ms: Arc<AtomicU64>,
        scripted_reads: Arc<Mutex<VecDeque<u64>>>,
    }

    impl ArmableClock {
        fn new(now_ms: u64) -> Self {
            Self {
                steady_ms: Arc::new(AtomicU64::new(now_ms)),
                scripted_reads: Arc::new(Mutex::new(VecDeque::new())),
            }
        }

        fn set(&self, now_ms: u64) {
            self.steady_ms.store(now_ms, Ordering::SeqCst);
        }

        fn arm(&self, reads: impl IntoIterator<Item = u64>) {
            let mut scripted = self.scripted_reads.lock().expect("scripted clock lock");
            assert!(
                scripted.is_empty(),
                "previous clock script was not consumed"
            );
            scripted.extend(reads);
        }

        fn pending_reads(&self) -> usize {
            self.scripted_reads
                .lock()
                .expect("scripted clock lock")
                .len()
        }
    }

    impl RuntimeClock for ArmableClock {
        fn now_ms(&self) -> Result<u64, RuntimeClockError> {
            Ok(self
                .scripted_reads
                .lock()
                .expect("scripted clock lock")
                .pop_front()
                .unwrap_or_else(|| self.steady_ms.load(Ordering::SeqCst)))
        }
    }

    struct FailOnce {
        operation: RuntimeStoreOperation,
        fired: AtomicBool,
    }

    impl FailOnce {
        fn new(operation: RuntimeStoreOperation) -> Self {
            Self {
                operation,
                fired: AtomicBool::new(false),
            }
        }
    }

    impl RuntimeStoreFaultInjector for FailOnce {
        fn before_operation(
            &self,
            operation: RuntimeStoreOperation,
        ) -> Result<(), RuntimeStoreError> {
            if operation == self.operation && !self.fired.swap(true, Ordering::SeqCst) {
                Err(RuntimeStoreError::InvalidStateTransition)
            } else {
                Ok(())
            }
        }
    }

    #[derive(Clone)]
    struct MutableCapacityProbe(Arc<Mutex<RuntimeCapacityObservation>>);

    impl MutableCapacityProbe {
        fn new(observation: RuntimeCapacityObservation) -> Self {
            Self(Arc::new(Mutex::new(observation)))
        }

        fn set(&self, observation: RuntimeCapacityObservation) {
            *self.0.lock().expect("capacity probe lock") = observation;
        }
    }

    impl RuntimeCapacityProbe for MutableCapacityProbe {
        fn observe(
            &self,
            _storage_path: &std::path::Path,
        ) -> Result<RuntimeCapacityObservation, RuntimeCapacityProbeError> {
            Ok(*self.0.lock().expect("capacity probe lock"))
        }
    }

    fn healthy_capacity() -> RuntimeCapacityObservation {
        RuntimeCapacityObservation {
            main_bytes: 8 * 1024 * 1024,
            wal_bytes: 2 * 1024 * 1024,
            shm_bytes: 32 * 1024,
            filesystem_total_bytes: 20 * 1024 * 1024 * 1024,
            filesystem_available_bytes: 4 * 1024 * 1024 * 1024,
        }
    }

    fn over_limit_capacity() -> RuntimeCapacityObservation {
        RuntimeCapacityObservation {
            main_bytes: 2 * 1024 * 1024 * 1024 + 1,
            wal_bytes: 0,
            shm_bytes: 0,
            filesystem_available_bytes: 8 * 1024 * 1024 * 1024,
            ..healthy_capacity()
        }
    }

    fn runtime_id(kind: RuntimeIdKind, seed: u8) -> RuntimeId {
        RuntimeId::from_bytes(kind, [seed; 16]).expect("valid typed runtime id")
    }

    fn sequenced_event_id(sequence: u64) -> RuntimeId {
        let mut bytes = [0_u8; 16];
        bytes[..8].copy_from_slice(&sequence.to_be_bytes());
        bytes[8..].copy_from_slice(&(!sequence).to_be_bytes());
        RuntimeId::from_bytes(RuntimeIdKind::Event, bytes).expect("nonzero event id")
    }

    #[test]
    fn approval_integrity_validator_retains_only_bounded_compact_state() {
        let source = include_str!("approval.rs");
        let validator = source
            .split_once("pub(super) fn validate_all_approval_metadata(")
            .expect("approval validator exists")
            .1
            .split_once("fn canonical_request(")
            .expect("approval validator boundary exists")
            .0;
        assert!(validator.contains("Vec<ApprovalIntegrityRecord>"));
        assert!(validator.contains("try_reserve_exact"));
        assert!(validator.contains("MAX_APPROVAL_INTEGRITY_PROJECTION_BYTES"));
        assert!(validator.contains("ORDER BY approval_id"));
        assert!(validator.contains("ORDER BY event_seq"));
        assert!(!validator.contains("HashMap"));
        assert!(!validator.contains("Vec<AuthenticatedApprovalEvent>"));
        assert!(!validator.contains("events.entry(approval_id)"));
        let maximum_projection = std::mem::size_of::<ApprovalIntegrityRecord>()
            * usize::try_from(crate::runtime::model::MAX_DURABLE_APPROVALS)
                .expect("approval cap fits usize");
        assert!(maximum_projection <= MAX_APPROVAL_INTEGRITY_PROJECTION_BYTES);
    }

    #[test]
    fn approval_event_chain_folds_many_manual_retries_in_constant_space() {
        assert!(std::mem::size_of::<ApprovalEventChainAccumulator>() <= 64);
        let winner = Some(ActionDecisionKind::Approve);
        let mut chain = ApprovalEventChainAccumulator::default();
        let mut sequence = 1_u64;
        fold_approval_event_chain(
            &mut chain,
            sequenced_event_id(sequence),
            sequence,
            ApprovalEventKind::Requested,
            winner,
        )
        .expect("fold request");
        sequence += 1;
        fold_approval_event_chain(
            &mut chain,
            sequenced_event_id(sequence),
            sequence,
            ApprovalEventKind::Resolved {
                decision: winner,
                state: agentdeck_protocol::runtime::ApprovalDeliveryState::Claimed,
            },
            winner,
        )
        .expect("fold winner");

        for _ in 0..50_000 {
            for state in [
                agentdeck_protocol::runtime::ApprovalDeliveryState::Applying,
                agentdeck_protocol::runtime::ApprovalDeliveryState::DeliveryFailed,
            ] {
                sequence += 1;
                fold_approval_event_chain(
                    &mut chain,
                    sequenced_event_id(sequence),
                    sequence,
                    ApprovalEventKind::Resolved {
                        decision: winner,
                        state,
                    },
                    winner,
                )
                .expect("manual retry transition remains legal");
            }
        }

        assert_eq!(chain.event_count, sequence);
        assert_eq!(chain.state, Some(ApprovalState::DeliveryFailed));
        assert_eq!(chain.last_event_id, Some(sequenced_event_id(sequence)));
    }

    #[tokio::test]
    async fn approval_integrity_rejects_orphan_event_in_conversation_without_approval_rows() {
        let root = TestRoot::new("orphan-event-without-row");
        let keys = MemoryKeyStore::new();
        let clock = ManualClock::new(1_000);
        let (store, conversation_id, command_id, turn_id) =
            open_started(&root, &keys, &clock).await;
        store.shutdown().await.expect("shutdown orphan fixture");

        let connection = rusqlite::Connection::open(root.database()).expect("open orphan DB");
        let (database_id, wrapped_key_bundle): (Vec<u8>, Vec<u8>) = connection
            .query_row(
                "SELECT database_id, wrapped_key_bundle FROM runtime_meta WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("read runtime key metadata");
        let database_id: [u8; 16] = database_id.try_into().expect("fixed database id");
        let storage_kek = root.storage_kek(&keys);
        let key_bundle = RuntimeKeyBundle::unwrap(
            &storage_kek,
            &KeyWrapAad {
                schema_family: RUNTIME_SCHEMA_FAMILY.as_bytes(),
                schema_version: RUNTIME_CRYPTO_CONTEXT_VERSION,
                database_id: &database_id,
            },
            &wrapped_key_bundle,
        )
        .expect("unwrap runtime keys");
        let (event_id, event_seq, created_at_ms): (Vec<u8>, String, i64) = connection
            .query_row(
                "SELECT event_id, event_seq, created_at_ms
                 FROM event_journal WHERE conversation_id = ?1 ORDER BY event_seq LIMIT 1",
                [&conversation_id.as_bytes()[..]],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("read started event");
        let event_id = super::runtime_id(RuntimeIdKind::Event, event_id).expect("event id");
        let event_seq = decode_sequence(SequenceScope::EventSeq, &event_seq).expect("event seq");
        let created_at_ms = u64::try_from(created_at_ms).expect("created timestamp");
        let orphan_approval_id = runtime_id(RuntimeIdKind::Approval, 0x71);
        let payload = serde_json::to_vec(&RuntimeEvent {
            conversation_id: ConversationId::new(conversation_id.to_canonical_string()),
            event_id: EventId::new(event_id.to_canonical_string()),
            event_seq,
            item_id: None,
            entity_id: None,
            body: RuntimeEventBody::ActionRequest {
                turn_id: TurnId::new(turn_id.to_canonical_string()),
                approval_id: ApprovalId::new(orphan_approval_id.to_canonical_string()),
                request: request(),
            },
        })
        .expect("encode canonical orphan event");
        let sealed_event = super::seal(
            &key_bundle,
            database_id,
            b"event_journal",
            event_id.as_bytes(),
            b"sealed_event",
            &payload,
            super::MAX_RUNTIME_EVENT_BYTES,
        )
        .expect("seal orphan event");
        let metadata_token = super::event_metadata_token(
            &key_bundle,
            conversation_id,
            event_id,
            event_seq,
            Some(command_id),
            u64::try_from(payload.len()).expect("payload length"),
            created_at_ms,
        )
        .expect("authenticate orphan event");
        connection
            .execute(
                "UPDATE event_journal
                 SET logical_event_bytes = ?1, metadata_token = ?2, sealed_event = ?3
                 WHERE event_id = ?4",
                rusqlite::params![
                    i64::try_from(payload.len()).expect("sqlite payload length"),
                    &metadata_token[..],
                    sealed_event,
                    &event_id.as_bytes()[..],
                ],
            )
            .expect("replace started payload with authenticated orphan event");

        assert!(matches!(
            super::validate_all_approval_metadata(&connection, &key_bundle, database_id),
            Err(RuntimeStoreError::UnknownOrCorruptSchema)
        ));
    }

    fn assert_store_files_do_not_contain(database: &std::path::Path, sentinel: &[u8]) {
        for path in [
            database.to_path_buf(),
            PathBuf::from(format!("{}-wal", database.display())),
            PathBuf::from(format!("{}-shm", database.display())),
        ] {
            let Ok(bytes) = fs::read(&path) else {
                continue;
            };
            assert!(
                !bytes
                    .windows(sentinel.len())
                    .any(|window| window == sentinel),
                "approval plaintext leaked into {}",
                path.display()
            );
        }
    }

    fn request() -> ActionRequest {
        ActionRequest {
            request_id: "approval-request-sentinel".to_owned(),
            kind: ActionKind::ExecuteCommand,
            summary: "approval-summary-sentinel".to_owned(),
            vendor: ActionRequestVendor::Codex {
                approval_policy_at_decision: CodexApprovalPolicy::OnRequest,
                sandbox_at_decision: CodexSandboxMode::WorkspaceWrite,
                can_persist: true,
            },
        }
    }

    fn request_named(name: &str) -> ActionRequest {
        let mut request = request();
        request.request_id = format!("approval-request-{name}");
        request.summary = format!("approval-summary-{name}");
        request
    }

    fn policy() -> ApprovalPolicySnapshot {
        ApprovalPolicySnapshot {
            agent_kind: AgentKind::Codex,
            action_kind: ActionKind::ExecuteCommand,
            allow_approve: true,
            allow_deny: true,
            allow_persist: true,
            deadline_at_ms: None,
        }
    }

    async fn open_started(
        root: &TestRoot,
        keys: &MemoryKeyStore,
        clock: &ManualClock,
    ) -> (RuntimeStoreHandle, RuntimeId, RuntimeId, RuntimeId) {
        open_started_with_config(
            root,
            keys,
            RuntimeStoreConfig::new(root.database()).with_clock(clock.clone()),
        )
        .await
    }

    async fn open_started_with_config(
        root: &TestRoot,
        keys: &MemoryKeyStore,
        config: RuntimeStoreConfig,
    ) -> (RuntimeStoreHandle, RuntimeId, RuntimeId, RuntimeId) {
        let store = RuntimeStoreHandle::open(config, root.storage_kek(keys))
            .await
            .expect("open approval store");
        let conversation_id = runtime_id(RuntimeIdKind::Conversation, 1);
        store
            .create_conversation(NewConversation {
                conversation_id,
                adapter_state_key: runtime_id(RuntimeIdKind::AdapterState, 2),
                descriptor: ConversationDescriptor {
                    agent_kind: AgentKind::Codex,
                    title: Some("approval-title-sentinel".to_owned()),
                    cwd: PathBuf::from("/approval-cwd-sentinel"),
                },
            })
            .await
            .expect("create approval conversation");
        let owner = IdempotencyOwner::Local {
            machine_trust_domain: [3; 32],
            uid: 501,
            client_installation_id: [4; 16],
        };
        let command = match store
            .accept_command(AcceptCommand {
                conversation_id,
                owner,
                idempotency_key: "approval-command".to_owned(),
                payload: b"approval-prompt-sentinel".to_vec(),
            })
            .await
            .expect("accept approval command")
        {
            AcceptOutcome::Accepted { command, .. } => command,
            AcceptOutcome::Replayed { .. } => panic!("fresh command cannot replay"),
        };
        let started = store
            .mark_started_with_event(StartCommand {
                conversation_id,
                command_id: command.command_id,
                daemon_boot_id: runtime_id(RuntimeIdKind::DaemonBoot, 5),
                execution_nonce: b"approval-execution-nonce".to_vec(),
                intent_payload: b"approval-intent-sentinel".to_vec(),
                event_payload: b"approval-started-event".to_vec(),
            })
            .await
            .expect("start approval command");
        let turn_id = match started {
            StartOutcome::Started { intent, .. } => intent.turn_id,
            StartOutcome::Replayed { .. } => panic!("fresh start cannot replay"),
        };
        (store, conversation_id, command.command_id, turn_id)
    }

    async fn register_and_claim(
        store: &RuntimeStoreHandle,
        conversation_id: RuntimeId,
        command_id: RuntimeId,
        turn_id: RuntimeId,
    ) -> crate::runtime::model::ApprovalRecord {
        let approval_id = match store
            .register_approval(RegisterApproval {
                conversation_id,
                command_id,
                turn_id,
                request: request(),
                policy: policy(),
            })
            .await
            .expect("register approval")
        {
            RegisterApprovalOutcome::Registered { approval, .. } => approval.approval_id,
            RegisterApprovalOutcome::Replayed { .. } => panic!("fresh register cannot replay"),
        };
        let claimant = PrincipalIssuer::local_only([0x61; 32])
            .issue_verified_local_with_approval_permissions(
                501,
                [0x62; 16],
                ApprovalPermissionGrant::ResolveOnly,
            )
            .expect("issue claimant");
        match store
            .claim_approval(ClaimApproval {
                conversation_id,
                turn_id,
                approval_id,
                decision: ActionDecision {
                    request_id: request().request_id,
                    decision: ActionDecisionKind::Approve,
                    persist: true,
                },
                claimant_binding: claimant
                    .try_enter_approval()
                    .expect("claimant active")
                    .claimant_binding(),
            })
            .await
            .expect("claim approval")
        {
            ApprovalMutationOutcome::Transitioned { approval, .. } => approval,
            other => panic!("fresh claim must transition, got {other:?}"),
        }
    }

    async fn register_named(
        store: &RuntimeStoreHandle,
        conversation_id: RuntimeId,
        command_id: RuntimeId,
        turn_id: RuntimeId,
        name: &str,
    ) -> ApprovalRecord {
        match store
            .register_approval(RegisterApproval {
                conversation_id,
                command_id,
                turn_id,
                request: request_named(name),
                policy: policy(),
            })
            .await
            .expect("register named approval")
        {
            RegisterApprovalOutcome::Registered { approval, .. } => approval,
            RegisterApprovalOutcome::Replayed { .. } => {
                panic!("fresh named approval cannot replay")
            }
        }
    }

    async fn claim_named(
        store: &RuntimeStoreHandle,
        conversation_id: RuntimeId,
        turn_id: RuntimeId,
        approval: ApprovalRecord,
    ) -> ApprovalRecord {
        let claimant = PrincipalIssuer::local_only([0x91; 32])
            .issue_verified_local_with_approval_permissions(
                501,
                [0x92; 16],
                ApprovalPermissionGrant::ResolveOnly,
            )
            .expect("issue named approval claimant");
        match store
            .claim_approval(ClaimApproval {
                conversation_id,
                turn_id,
                approval_id: approval.approval_id,
                decision: ActionDecision {
                    request_id: approval.request.request_id.clone(),
                    decision: ActionDecisionKind::Approve,
                    persist: true,
                },
                claimant_binding: claimant
                    .try_enter_approval()
                    .expect("named claimant active")
                    .claimant_binding(),
            })
            .await
            .expect("claim named approval")
        {
            ApprovalMutationOutcome::Transitioned { approval, .. } => approval,
            other => panic!("fresh named claim must transition, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn turn_terminal_expires_every_non_applied_approval_atomically() {
        let root = TestRoot::new("terminal-expiry-complete");
        let keys = MemoryKeyStore::new();
        let clock = ManualClock::new(40_000);
        let (store, conversation_id, command_id, turn_id) =
            open_started(&root, &keys, &clock).await;

        clock.set(40_001);
        let pending = register_named(&store, conversation_id, command_id, turn_id, "pending").await;
        clock.set(40_002);
        let applied = register_named(&store, conversation_id, command_id, turn_id, "applied").await;
        clock.set(40_003);
        let applied = claim_named(&store, conversation_id, turn_id, applied).await;
        clock.set(40_004);
        let applied = match store
            .begin_approval_attempt(BeginApprovalAttempt {
                approval_id: applied.approval_id,
                delivery_round: 0,
                expected_attempts_in_round: 0,
            })
            .await
            .expect("begin applied fixture")
        {
            BeginApprovalAttemptOutcome::Permitted { approval, .. } => approval,
            other => panic!("applied fixture must enter Applying, got {other:?}"),
        };
        clock.set(40_005);
        let applied = match store
            .mark_approval_applied(MarkApprovalApplied {
                approval_id: applied.approval_id,
                delivery_round: 1,
                attempt: 1,
            })
            .await
            .expect("apply terminal fixture")
        {
            ApprovalMutationOutcome::Transitioned { approval, .. } => approval,
            other => panic!("fixture must become Applied, got {other:?}"),
        };

        clock.set(40_006);
        store
            .persist_execution_fence(ExecutionFence {
                command_id,
                daemon_boot_id: runtime_id(RuntimeIdKind::DaemonBoot, 5),
                execution_nonce: b"approval-execution-nonce".to_vec(),
                process_group_id: 70,
                leader_pid: 71,
                leader_start_time: 72,
                payload: b"terminal-expiry-fence".to_vec(),
            })
            .await
            .expect("persist completion fence");
        clock.set(40_007);
        store
            .authorize_execution_release(AuthorizeExecutionRelease {
                command_id,
                daemon_boot_id: runtime_id(RuntimeIdKind::DaemonBoot, 5),
                execution_nonce: b"approval-execution-nonce".to_vec(),
            })
            .await
            .expect("authorize completion release");
        clock.set(40_008);
        let terminal = match store
            .complete_command_with_event(CompleteCommand {
                conversation_id,
                command_id,
                turn_id,
                terminal_state: TerminalState::Completed,
                terminal_payload: b"terminal-expiry-result".to_vec(),
                event_payload: b"terminal-expiry-command-event".to_vec(),
            })
            .await
            .expect("complete command and expire approvals")
        {
            CompleteOutcome::Completed { event, .. } => event,
            CompleteOutcome::Replayed { .. } => panic!("fresh completion cannot replay"),
        };
        store.shutdown().await.expect("shutdown terminal fixture");

        let connection = rusqlite::Connection::open(root.database()).expect("open completed DB");
        let pending_state: String = connection
            .query_row(
                "SELECT state FROM approval_ledger WHERE approval_id = ?1",
                [&pending.approval_id.as_bytes()[..]],
                |row| row.get(0),
            )
            .expect("read pending terminal state");
        let applied_state: String = connection
            .query_row(
                "SELECT state FROM approval_ledger WHERE approval_id = ?1",
                [&applied.approval_id.as_bytes()[..]],
                |row| row.get(0),
            )
            .expect("read applied terminal state");
        assert_eq!(pending_state, "expired");
        assert_eq!(applied_state, "applied");

        let pending_expiry_seq: String = connection
            .query_row(
                "SELECT event.event_seq
                 FROM event_journal AS event
                 JOIN approval_ledger AS approval ON approval.last_event_id = event.event_id
                 WHERE approval.approval_id = ?1",
                [&pending.approval_id.as_bytes()[..]],
                |row| row.get(0),
            )
            .expect("read expiry sequence");
        assert_eq!(
            decode_sequence(SequenceScope::EventSeq, &pending_expiry_seq)
                .expect("decode expiry sequence")
                + 1,
            terminal.event_seq,
            "approval expiry event must precede the command terminal event"
        );
        let (event_count, active_approval_count): (i64, i64) = connection
            .query_row(
                "SELECT event_count, active_approval_count FROM runtime_meta WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("read terminal ledger");
        let actual_event_count: i64 = connection
            .query_row("SELECT COUNT(*) FROM event_journal", [], |row| row.get(0))
            .expect("count terminal events");
        let event_high_water: String = connection
            .query_row(
                "SELECT event_high_water FROM conversations WHERE conversation_id = ?1",
                [&conversation_id.as_bytes()[..]],
                |row| row.get(0),
            )
            .expect("read terminal high-water");
        assert_eq!(event_count, actual_event_count);
        assert_eq!(active_approval_count, 0);
        assert_eq!(
            decode_sequence(SequenceScope::EventSeq, &event_high_water)
                .expect("decode terminal high-water"),
            terminal.event_seq
        );
        drop(connection);

        RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.database()).with_clock(clock),
            root.storage_kek(&keys),
        )
        .await
        .expect("authenticated terminal+expiry store reopens")
        .shutdown()
        .await
        .expect("shutdown reopened terminal store");

        // started-before-release 的取消/中断必须复用同一事务原语，并覆盖所有 active state。
        let terminate_root = TestRoot::new("terminal-expiry-before-release");
        let terminate_keys = MemoryKeyStore::new();
        let terminate_clock = ManualClock::new(50_000);
        let (terminate_store, terminate_conversation, terminate_command, terminate_turn) =
            open_started(&terminate_root, &terminate_keys, &terminate_clock).await;

        terminate_clock.set(50_001);
        let pending = register_named(
            &terminate_store,
            terminate_conversation,
            terminate_command,
            terminate_turn,
            "terminate-pending",
        )
        .await;
        terminate_clock.set(50_002);
        let claimed = register_named(
            &terminate_store,
            terminate_conversation,
            terminate_command,
            terminate_turn,
            "terminate-claimed",
        )
        .await;
        terminate_clock.set(50_003);
        let claimed = claim_named(
            &terminate_store,
            terminate_conversation,
            terminate_turn,
            claimed,
        )
        .await;
        terminate_clock.set(50_004);
        let applying = register_named(
            &terminate_store,
            terminate_conversation,
            terminate_command,
            terminate_turn,
            "terminate-applying",
        )
        .await;
        terminate_clock.set(50_005);
        let applying = claim_named(
            &terminate_store,
            terminate_conversation,
            terminate_turn,
            applying,
        )
        .await;
        terminate_clock.set(50_006);
        let applying = match terminate_store
            .begin_approval_attempt(BeginApprovalAttempt {
                approval_id: applying.approval_id,
                delivery_round: 0,
                expected_attempts_in_round: 0,
            })
            .await
            .expect("begin terminate Applying fixture")
        {
            BeginApprovalAttemptOutcome::Permitted { approval, .. } => approval,
            other => panic!("terminate fixture must become Applying, got {other:?}"),
        };
        terminate_clock.set(50_007);
        let failed = register_named(
            &terminate_store,
            terminate_conversation,
            terminate_command,
            terminate_turn,
            "terminate-failed",
        )
        .await;
        terminate_clock.set(50_008);
        let failed = claim_named(
            &terminate_store,
            terminate_conversation,
            terminate_turn,
            failed,
        )
        .await;
        terminate_clock.set(50_009);
        let failed = match terminate_store
            .begin_approval_attempt(BeginApprovalAttempt {
                approval_id: failed.approval_id,
                delivery_round: 0,
                expected_attempts_in_round: 0,
            })
            .await
            .expect("begin terminate DeliveryFailed fixture")
        {
            BeginApprovalAttemptOutcome::Permitted { approval, .. } => approval,
            other => panic!("terminate failed fixture must apply first, got {other:?}"),
        };
        terminate_clock.set(50_010);
        let failed = match terminate_store
            .mark_approval_delivery_failed(MarkApprovalDeliveryFailed {
                approval_id: failed.approval_id,
                delivery_round: 1,
                attempt: 1,
                status_detail: b"terminate-delivery-failed".to_vec(),
            })
            .await
            .expect("mark terminate DeliveryFailed fixture")
        {
            ApprovalMutationOutcome::Transitioned { approval, .. } => approval,
            other => panic!("terminate fixture must become DeliveryFailed, got {other:?}"),
        };
        terminate_clock.set(50_011);
        let preserved = register_named(
            &terminate_store,
            terminate_conversation,
            terminate_command,
            terminate_turn,
            "terminate-applied",
        )
        .await;
        terminate_clock.set(50_012);
        let preserved = claim_named(
            &terminate_store,
            terminate_conversation,
            terminate_turn,
            preserved,
        )
        .await;
        terminate_clock.set(50_013);
        let preserved = match terminate_store
            .begin_approval_attempt(BeginApprovalAttempt {
                approval_id: preserved.approval_id,
                delivery_round: 0,
                expected_attempts_in_round: 0,
            })
            .await
            .expect("begin preserved Applied fixture")
        {
            BeginApprovalAttemptOutcome::Permitted { approval, .. } => approval,
            other => panic!("preserved fixture must become Applying, got {other:?}"),
        };
        terminate_clock.set(50_014);
        let preserved = match terminate_store
            .mark_approval_applied(MarkApprovalApplied {
                approval_id: preserved.approval_id,
                delivery_round: 1,
                attempt: 1,
            })
            .await
            .expect("mark preserved Applied fixture")
        {
            ApprovalMutationOutcome::Transitioned { approval, .. } => approval,
            other => panic!("preserved fixture must become Applied, got {other:?}"),
        };
        let active_ids = [
            pending.approval_id,
            claimed.approval_id,
            applying.approval_id,
            failed.approval_id,
        ];

        terminate_clock.set(50_015);
        let terminal = match terminate_store
            .terminate_started_before_release(TerminateStartedBeforeRelease {
                conversation_id: terminate_conversation,
                command_id: terminate_command,
                turn_id: terminate_turn,
                daemon_boot_id: runtime_id(RuntimeIdKind::DaemonBoot, 5),
                execution_nonce: b"approval-execution-nonce".to_vec(),
                reason: StartedBeforeReleaseTermination::Interrupted,
                terminal_payload: b"terminate-before-release-result".to_vec(),
                event_payload: b"terminate-before-release-event".to_vec(),
            })
            .await
            .expect("terminate started command and expire approvals")
        {
            TerminateStartedBeforeReleaseOutcome::Transitioned { event, .. } => event,
            TerminateStartedBeforeReleaseOutcome::Replayed { .. } => {
                panic!("fresh started termination cannot replay")
            }
        };
        terminate_store
            .shutdown()
            .await
            .expect("shutdown started termination fixture");

        let connection =
            rusqlite::Connection::open(terminate_root.database()).expect("open terminated DB");
        let mut observed_order = Vec::new();
        for approval_id in active_ids {
            let (state, event_seq, decision_is_null): (String, String, bool) = connection
                .query_row(
                    "SELECT approval.state, event.event_seq,
                            approval.decision_token IS NULL
                     FROM approval_ledger AS approval
                     JOIN event_journal AS event ON event.event_id = approval.last_event_id
                     WHERE approval.approval_id = ?1",
                    [&approval_id.as_bytes()[..]],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .expect("read terminated approval");
            assert_eq!(state, "expired");
            assert_eq!(decision_is_null, approval_id == pending.approval_id);
            observed_order.push((
                approval_id,
                decode_sequence(SequenceScope::EventSeq, &event_seq)
                    .expect("decode stable expiry sequence"),
            ));
        }
        let preserved_state: String = connection
            .query_row(
                "SELECT state FROM approval_ledger WHERE approval_id = ?1",
                [&preserved.approval_id.as_bytes()[..]],
                |row| row.get(0),
            )
            .expect("read preserved Applied approval");
        assert_eq!(preserved_state, "applied");
        let mut expected_order = active_ids;
        expected_order.sort_by_key(|id| *id.as_bytes());
        observed_order.sort_by_key(|(_, sequence)| *sequence);
        assert_eq!(
            observed_order.iter().map(|(id, _)| *id).collect::<Vec<_>>(),
            expected_order,
            "terminal expiry events must use stable approval_id order"
        );
        assert_eq!(
            observed_order.last().expect("at least one expiry").1 + 1,
            terminal.event_seq
        );
        let (active_count, ledger_events): (i64, i64) = connection
            .query_row(
                "SELECT active_approval_count, event_count
                 FROM runtime_meta WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("read terminated ledger");
        let actual_events: i64 = connection
            .query_row("SELECT COUNT(*) FROM event_journal", [], |row| row.get(0))
            .expect("count terminated events");
        assert_eq!(active_count, 0);
        assert_eq!(ledger_events, actual_events);
        drop(connection);

        RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(terminate_root.database()).with_clock(terminate_clock),
            terminate_root.storage_kek(&terminate_keys),
        )
        .await
        .expect("authenticated started terminal+expiry store reopens")
        .shutdown()
        .await
        .expect("shutdown reopened started terminal store");
    }

    async fn open_claimed_with_fault(
        label: &str,
        operation: RuntimeStoreOperation,
        base_ms: u64,
    ) -> (
        TestRoot,
        MemoryKeyStore,
        ManualClock,
        RuntimeStoreHandle,
        RuntimeId,
        crate::runtime::model::ApprovalRecord,
    ) {
        let root = TestRoot::new(label);
        let keys = MemoryKeyStore::new();
        let clock = ManualClock::new(base_ms);
        let config = RuntimeStoreConfig::new(root.database())
            .with_clock(clock.clone())
            .with_fault_injector(Arc::new(FailOnce::new(operation)));
        let (store, conversation_id, command_id, turn_id) =
            open_started_with_config(&root, &keys, config).await;
        clock.set(base_ms + 1);
        let approval = register_and_claim(&store, conversation_id, command_id, turn_id).await;
        (root, keys, clock, store, conversation_id, approval)
    }

    fn assert_fault_result(
        error: RuntimeStoreError,
        operation: RuntimeCommitOperation,
        after_commit: bool,
    ) {
        assert_eq!(
            matches!(
                error,
                RuntimeStoreError::CommitOutcomeUnknown { operation: actual }
                    if actual == operation
            ),
            after_commit
        );
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum TerminalFaultPath {
        Complete,
        TerminateStartedBeforeRelease,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum TerminalFaultOutcome {
        Transitioned(RuntimeId),
        Replayed(RuntimeId),
    }

    async fn invoke_terminal_fault_path(
        store: &RuntimeStoreHandle,
        path: TerminalFaultPath,
        conversation_id: RuntimeId,
        command_id: RuntimeId,
        turn_id: RuntimeId,
    ) -> Result<TerminalFaultOutcome, RuntimeStoreError> {
        match path {
            TerminalFaultPath::Complete => store
                .complete_command_with_event(CompleteCommand {
                    conversation_id,
                    command_id,
                    turn_id,
                    terminal_state: TerminalState::Completed,
                    terminal_payload: b"terminal-fault-result".to_vec(),
                    event_payload: b"terminal-fault-event".to_vec(),
                })
                .await
                .map(|outcome| match outcome {
                    CompleteOutcome::Completed { event, .. } => {
                        TerminalFaultOutcome::Transitioned(event.event_id)
                    }
                    CompleteOutcome::Replayed { event, .. } => {
                        TerminalFaultOutcome::Replayed(event.event_id)
                    }
                }),
            TerminalFaultPath::TerminateStartedBeforeRelease => store
                .terminate_started_before_release(TerminateStartedBeforeRelease {
                    conversation_id,
                    command_id,
                    turn_id,
                    daemon_boot_id: runtime_id(RuntimeIdKind::DaemonBoot, 5),
                    execution_nonce: b"approval-execution-nonce".to_vec(),
                    reason: StartedBeforeReleaseTermination::Interrupted,
                    terminal_payload: b"terminal-fault-result".to_vec(),
                    event_payload: b"terminal-fault-event".to_vec(),
                })
                .await
                .map(|outcome| match outcome {
                    TerminateStartedBeforeReleaseOutcome::Transitioned { event, .. } => {
                        TerminalFaultOutcome::Transitioned(event.event_id)
                    }
                    TerminateStartedBeforeReleaseOutcome::Replayed { event, .. } => {
                        TerminalFaultOutcome::Replayed(event.event_id)
                    }
                }),
        }
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct RawTerminalSnapshot {
        command_state: String,
        approval_state: String,
        terminal_event_id: Option<Vec<u8>>,
        event_high_water: Option<String>,
        ledger_event_count: i64,
        active_approval_count: i64,
        actual_event_count: i64,
    }

    fn read_raw_terminal_snapshot(
        database: &std::path::Path,
        conversation_id: RuntimeId,
        command_id: RuntimeId,
        approval_id: RuntimeId,
    ) -> RawTerminalSnapshot {
        let connection = rusqlite::Connection::open(database).expect("open terminal fault DB");
        let (command_state, terminal_event_id) = connection
            .query_row(
                "SELECT state, terminal_event_id FROM commands WHERE command_id = ?1",
                [&command_id.as_bytes()[..]],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("read fault command");
        let approval_state = connection
            .query_row(
                "SELECT state FROM approval_ledger WHERE approval_id = ?1",
                [&approval_id.as_bytes()[..]],
                |row| row.get(0),
            )
            .expect("read fault approval");
        let event_high_water = connection
            .query_row(
                "SELECT event_high_water FROM conversations WHERE conversation_id = ?1",
                [&conversation_id.as_bytes()[..]],
                |row| row.get(0),
            )
            .expect("read fault high-water");
        let (ledger_event_count, active_approval_count) = connection
            .query_row(
                "SELECT event_count, active_approval_count
                 FROM runtime_meta WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("read fault ledger");
        let actual_event_count = connection
            .query_row("SELECT COUNT(*) FROM event_journal", [], |row| row.get(0))
            .expect("count fault events");
        RawTerminalSnapshot {
            command_state,
            approval_state,
            terminal_event_id,
            event_high_water,
            ledger_event_count,
            active_approval_count,
            actual_event_count,
        }
    }

    #[tokio::test]
    async fn terminal_expiry_before_and_after_commit_converges_without_crash_gap() {
        for (index, path, fault, commit_operation, after_commit) in [
            (
                0_u64,
                TerminalFaultPath::Complete,
                RuntimeStoreOperation::CompleteCommandBeforeCommit,
                RuntimeCommitOperation::CompleteCommand,
                false,
            ),
            (
                1,
                TerminalFaultPath::Complete,
                RuntimeStoreOperation::CompleteCommandAfterCommit,
                RuntimeCommitOperation::CompleteCommand,
                true,
            ),
            (
                2,
                TerminalFaultPath::TerminateStartedBeforeRelease,
                RuntimeStoreOperation::TerminateStartedBeforeReleaseBeforeCommit,
                RuntimeCommitOperation::TerminateStartedBeforeRelease,
                false,
            ),
            (
                3,
                TerminalFaultPath::TerminateStartedBeforeRelease,
                RuntimeStoreOperation::TerminateStartedBeforeReleaseAfterCommit,
                RuntimeCommitOperation::TerminateStartedBeforeRelease,
                true,
            ),
        ] {
            let root = TestRoot::new(&format!("terminal-fault-{index}"));
            let keys = MemoryKeyStore::new();
            let base_ms = 60_000 + index * 100;
            let clock = ManualClock::new(base_ms);
            let config = RuntimeStoreConfig::new(root.database())
                .with_clock(clock.clone())
                .with_fault_injector(Arc::new(FailOnce::new(fault)));
            let (store, conversation_id, command_id, turn_id) =
                open_started_with_config(&root, &keys, config).await;
            clock.set(base_ms + 1);
            let pending = register_named(
                &store,
                conversation_id,
                command_id,
                turn_id,
                &format!("fault-{index}"),
            )
            .await;
            if path == TerminalFaultPath::Complete {
                clock.set(base_ms + 2);
                store
                    .persist_execution_fence(ExecutionFence {
                        command_id,
                        daemon_boot_id: runtime_id(RuntimeIdKind::DaemonBoot, 5),
                        execution_nonce: b"approval-execution-nonce".to_vec(),
                        process_group_id: 80,
                        leader_pid: 81,
                        leader_start_time: 82,
                        payload: b"terminal-fault-fence".to_vec(),
                    })
                    .await
                    .expect("persist fault completion fence");
                clock.set(base_ms + 3);
                store
                    .authorize_execution_release(AuthorizeExecutionRelease {
                        command_id,
                        daemon_boot_id: runtime_id(RuntimeIdKind::DaemonBoot, 5),
                        execution_nonce: b"approval-execution-nonce".to_vec(),
                    })
                    .await
                    .expect("authorize fault completion release");
            }
            let before = read_raw_terminal_snapshot(
                &root.database(),
                conversation_id,
                command_id,
                pending.approval_id,
            );
            assert_eq!(before.command_state, "started");
            assert_eq!(before.approval_state, "pending");
            assert_eq!(before.active_approval_count, 1);
            assert_eq!(before.ledger_event_count, before.actual_event_count);

            clock.set(base_ms + 4);
            let error =
                invoke_terminal_fault_path(&store, path, conversation_id, command_id, turn_id)
                    .await
                    .expect_err("faulted terminal transaction must not return a receipt");
            assert_fault_result(error, commit_operation, after_commit);
            let after_fault = read_raw_terminal_snapshot(
                &root.database(),
                conversation_id,
                command_id,
                pending.approval_id,
            );
            if after_commit {
                assert_eq!(after_fault.approval_state, "expired");
                assert_eq!(after_fault.active_approval_count, 0);
                assert_eq!(
                    after_fault.ledger_event_count,
                    before.ledger_event_count + 2
                );
                assert_eq!(
                    after_fault.ledger_event_count,
                    after_fault.actual_event_count
                );
                assert_eq!(
                    decode_sequence(
                        SequenceScope::EventSeq,
                        after_fault
                            .event_high_water
                            .as_deref()
                            .expect("terminal high-water exists"),
                    )
                    .expect("decode post-commit high-water"),
                    decode_sequence(
                        SequenceScope::EventSeq,
                        before
                            .event_high_water
                            .as_deref()
                            .expect("pre-terminal high-water exists"),
                    )
                    .expect("decode pre-terminal high-water")
                        + 2,
                );
            } else {
                assert_eq!(after_fault, before, "BeforeCommit must roll back every row");
            }

            let retry =
                invoke_terminal_fault_path(&store, path, conversation_id, command_id, turn_id)
                    .await
                    .expect("exact terminal retry converges");
            assert_eq!(
                matches!(retry, TerminalFaultOutcome::Replayed(_)),
                after_commit
            );
            let final_snapshot = read_raw_terminal_snapshot(
                &root.database(),
                conversation_id,
                command_id,
                pending.approval_id,
            );
            assert_eq!(
                final_snapshot.command_state,
                match path {
                    TerminalFaultPath::Complete => "completed",
                    TerminalFaultPath::TerminateStartedBeforeRelease => "interrupted",
                }
            );
            assert_eq!(final_snapshot.approval_state, "expired");
            assert_eq!(final_snapshot.active_approval_count, 0);
            assert_eq!(
                final_snapshot.ledger_event_count,
                before.ledger_event_count + 2
            );
            assert_eq!(
                final_snapshot.ledger_event_count,
                final_snapshot.actual_event_count
            );
            let outcome_event_id = match retry {
                TerminalFaultOutcome::Transitioned(event_id)
                | TerminalFaultOutcome::Replayed(event_id) => event_id,
            };
            assert_eq!(
                final_snapshot.terminal_event_id.as_deref(),
                Some(&outcome_event_id.as_bytes()[..])
            );

            store
                .shutdown()
                .await
                .expect("shutdown terminal fault store");
            RuntimeStoreHandle::open(
                RuntimeStoreConfig::new(root.database()).with_clock(clock),
                root.storage_kek(&keys),
            )
            .await
            .expect("authenticated terminal fault store reopens")
            .shutdown()
            .await
            .expect("shutdown reopened terminal fault store");
        }
    }

    #[tokio::test]
    async fn terminal_replay_fails_closed_if_an_authenticated_active_approval_reappears() {
        let root = TestRoot::new("terminal-replay-active-gap");
        let keys = MemoryKeyStore::new();
        let clock = ManualClock::new(61_000);
        let (store, conversation_id, command_id, turn_id) =
            open_started(&root, &keys, &clock).await;
        clock.set(61_001);
        let pending =
            register_named(&store, conversation_id, command_id, turn_id, "replay-gap").await;

        let authenticated_pending_fields = {
            let connection =
                rusqlite::Connection::open(root.database()).expect("open pre-terminal gap DB");
            connection
                .query_row(
                    "SELECT state_changed_at_ms, state_version, last_event_id,
                            metadata_token, sealed_status_detail
                     FROM approval_ledger WHERE approval_id = ?1",
                    [&pending.approval_id.as_bytes()[..]],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, Vec<u8>>(2)?,
                            row.get::<_, Vec<u8>>(3)?,
                            row.get::<_, Option<Vec<u8>>>(4)?,
                        ))
                    },
                )
                .expect("capture authenticated Pending fields")
        };
        clock.set(61_002);
        store
            .persist_execution_fence(ExecutionFence {
                command_id,
                daemon_boot_id: runtime_id(RuntimeIdKind::DaemonBoot, 5),
                execution_nonce: b"approval-execution-nonce".to_vec(),
                process_group_id: 90,
                leader_pid: 91,
                leader_start_time: 92,
                payload: b"terminal-replay-gap-fence".to_vec(),
            })
            .await
            .expect("persist replay-gap fence");
        clock.set(61_003);
        store
            .authorize_execution_release(AuthorizeExecutionRelease {
                command_id,
                daemon_boot_id: runtime_id(RuntimeIdKind::DaemonBoot, 5),
                execution_nonce: b"approval-execution-nonce".to_vec(),
            })
            .await
            .expect("authorize replay-gap release");
        let input = || CompleteCommand {
            conversation_id,
            command_id,
            turn_id,
            terminal_state: TerminalState::Completed,
            terminal_payload: b"terminal-replay-gap-result".to_vec(),
            event_payload: b"terminal-replay-gap-event".to_vec(),
        };
        clock.set(61_004);
        store
            .complete_command_with_event(input())
            .await
            .expect("commit terminal before simulating old crash gap");

        // 精确恢复 terminal 前的 authenticated Pending row，模拟旧实现可能留下的双事务 gap。
        // runtime_meta/event journal 故意保持 terminal 后事实；hot replay 必须仅凭 bounded active
        // row authentication 就 fail closed，不能返回一个看似成功的 terminal receipt。
        {
            let connection =
                rusqlite::Connection::open(root.database()).expect("open terminal gap DB");
            connection
                .execute(
                    "UPDATE approval_ledger
                     SET state = 'pending', state_changed_at_ms = ?1,
                         state_version = ?2, last_event_id = ?3,
                         metadata_token = ?4, sealed_status_detail = ?5
                     WHERE approval_id = ?6",
                    rusqlite::params![
                        authenticated_pending_fields.0,
                        authenticated_pending_fields.1,
                        authenticated_pending_fields.2,
                        authenticated_pending_fields.3,
                        authenticated_pending_fields.4,
                        &pending.approval_id.as_bytes()[..],
                    ],
                )
                .expect("restore authenticated active row");
        }
        assert!(matches!(
            store.complete_command_with_event(input()).await,
            Err(RuntimeStoreError::UnknownOrCorruptSchema)
        ));
        store.shutdown().await.expect("shutdown crash-gap fixture");
    }

    #[tokio::test]
    async fn terminal_expiry_consumes_the_pre_reserved_safety_lane() {
        let root = TestRoot::new("terminal-expiry-safety-only");
        let keys = MemoryKeyStore::new();
        let clock = ManualClock::new(62_000);
        let probe = MutableCapacityProbe::new(healthy_capacity());
        let config = RuntimeStoreConfig::new(root.database())
            .with_clock(clock.clone())
            .with_capacity_probe(probe.clone());
        let (store, conversation_id, command_id, turn_id) =
            open_started_with_config(&root, &keys, config).await;
        clock.set(62_001);
        let pending =
            register_named(&store, conversation_id, command_id, turn_id, "safety-only").await;

        probe.set(over_limit_capacity());
        assert!(matches!(
            store
                .accept_command(AcceptCommand {
                    conversation_id,
                    owner: IdempotencyOwner::Local {
                        machine_trust_domain: [0xa1; 32],
                        uid: 501,
                        client_installation_id: [0xa2; 16],
                    },
                    idempotency_key: "latch-terminal-safety-only".to_owned(),
                    payload: b"must-not-commit".to_vec(),
                })
                .await,
            Err(RuntimeStoreError::StoreFull { .. })
        ));
        probe.set(healthy_capacity());
        assert!(matches!(
            store
                .accept_command(AcceptCommand {
                    conversation_id,
                    owner: IdempotencyOwner::Local {
                        machine_trust_domain: [0xa1; 32],
                        uid: 501,
                        client_installation_id: [0xa2; 16],
                    },
                    idempotency_key: "confirm-terminal-safety-only".to_owned(),
                    payload: b"still-must-not-commit".to_vec(),
                })
                .await,
            Err(RuntimeStoreError::SafetyOnly)
        ));

        clock.set(62_002);
        assert!(matches!(
            store
                .terminate_started_before_release(TerminateStartedBeforeRelease {
                    conversation_id,
                    command_id,
                    turn_id,
                    daemon_boot_id: runtime_id(RuntimeIdKind::DaemonBoot, 5),
                    execution_nonce: b"approval-execution-nonce".to_vec(),
                    reason: StartedBeforeReleaseTermination::Canceled,
                    terminal_payload: b"safety-only-terminal-result".to_vec(),
                    event_payload: b"safety-only-terminal-event".to_vec(),
                })
                .await
                .expect("reserved Safety lane closes terminal turn"),
            TerminateStartedBeforeReleaseOutcome::Transitioned { .. }
        ));
        store
            .shutdown()
            .await
            .expect("shutdown safety-only terminal store");

        let connection =
            rusqlite::Connection::open(root.database()).expect("open safety-only terminal DB");
        let (state, active_count): (String, i64) = connection
            .query_row(
                "SELECT approval.state, runtime.active_approval_count
                 FROM approval_ledger AS approval CROSS JOIN runtime_meta AS runtime
                 WHERE approval.approval_id = ?1 AND runtime.singleton = 1",
                [&pending.approval_id.as_bytes()[..]],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("read safety-only terminal closure");
        assert_eq!(state, "expired");
        assert_eq!(active_count, 0);
    }

    #[tokio::test]
    async fn complete_terminal_rolls_back_when_clock_precedes_the_last_delivery_attempt() {
        let root = TestRoot::new("complete-terminal-attempt-clock-regression");
        let keys = MemoryKeyStore::new();
        let clock = ManualClock::new(63_000);
        let (store, conversation_id, command_id, turn_id) =
            open_started(&root, &keys, &clock).await;

        clock.set(63_001);
        store
            .persist_execution_fence(ExecutionFence {
                command_id,
                daemon_boot_id: runtime_id(RuntimeIdKind::DaemonBoot, 5),
                execution_nonce: b"approval-execution-nonce".to_vec(),
                process_group_id: 101,
                leader_pid: 102,
                leader_start_time: 103,
                payload: b"clock-regression-fence".to_vec(),
            })
            .await
            .expect("persist clock-regression fence");
        clock.set(63_002);
        store
            .authorize_execution_release(AuthorizeExecutionRelease {
                command_id,
                daemon_boot_id: runtime_id(RuntimeIdKind::DaemonBoot, 5),
                execution_nonce: b"approval-execution-nonce".to_vec(),
            })
            .await
            .expect("authorize clock-regression release");
        clock.set(63_003);
        let claimed = register_and_claim(&store, conversation_id, command_id, turn_id).await;
        clock.set(63_004);
        let first_attempt = match store
            .begin_approval_attempt(BeginApprovalAttempt {
                approval_id: claimed.approval_id,
                delivery_round: 0,
                expected_attempts_in_round: 0,
            })
            .await
            .expect("begin first completion attempt")
        {
            BeginApprovalAttemptOutcome::Permitted { approval, .. } => approval,
            other => panic!("first completion attempt must be permitted, got {other:?}"),
        };
        clock.set(63_006);
        let second_attempt = match store
            .begin_approval_attempt(BeginApprovalAttempt {
                approval_id: claimed.approval_id,
                delivery_round: first_attempt.delivery_round,
                expected_attempts_in_round: first_attempt.attempts_in_round,
            })
            .await
            .expect("begin second completion attempt")
        {
            BeginApprovalAttemptOutcome::Permitted { approval, .. } => approval,
            other => panic!("second completion attempt must be permitted, got {other:?}"),
        };
        assert_eq!(second_attempt.last_attempt_at_ms, Some(63_006));
        let before = read_raw_terminal_snapshot(
            &root.database(),
            conversation_id,
            command_id,
            claimed.approval_id,
        );

        clock.set(63_005);
        assert!(matches!(
            store
                .complete_command_with_event(CompleteCommand {
                    conversation_id,
                    command_id,
                    turn_id,
                    terminal_state: TerminalState::Completed,
                    terminal_payload: b"clock-regression-result".to_vec(),
                    event_payload: b"clock-regression-terminal-event".to_vec(),
                })
                .await,
            Err(RuntimeStoreError::ClockRegressed {
                persisted_ms: 63_006,
                observed_ms: 63_005,
            })
        ));
        let after = read_raw_terminal_snapshot(
            &root.database(),
            conversation_id,
            command_id,
            claimed.approval_id,
        );
        assert_eq!(
            after, before,
            "clock regression must roll back the entire Safety transaction"
        );
        store
            .shutdown()
            .await
            .expect("shutdown completion regression store");
    }

    #[tokio::test]
    async fn terminate_before_release_rolls_back_when_clock_precedes_the_last_delivery_attempt() {
        let root = TestRoot::new("terminate-terminal-attempt-clock-regression");
        let keys = MemoryKeyStore::new();
        let clock = ManualClock::new(64_000);
        let (store, conversation_id, command_id, turn_id) =
            open_started(&root, &keys, &clock).await;

        clock.set(64_001);
        let claimed = register_and_claim(&store, conversation_id, command_id, turn_id).await;
        clock.set(64_002);
        let first_attempt = match store
            .begin_approval_attempt(BeginApprovalAttempt {
                approval_id: claimed.approval_id,
                delivery_round: 0,
                expected_attempts_in_round: 0,
            })
            .await
            .expect("begin first termination attempt")
        {
            BeginApprovalAttemptOutcome::Permitted { approval, .. } => approval,
            other => panic!("first termination attempt must be permitted, got {other:?}"),
        };
        clock.set(64_004);
        let second_attempt = match store
            .begin_approval_attempt(BeginApprovalAttempt {
                approval_id: claimed.approval_id,
                delivery_round: first_attempt.delivery_round,
                expected_attempts_in_round: first_attempt.attempts_in_round,
            })
            .await
            .expect("begin second termination attempt")
        {
            BeginApprovalAttemptOutcome::Permitted { approval, .. } => approval,
            other => panic!("second termination attempt must be permitted, got {other:?}"),
        };
        assert_eq!(second_attempt.last_attempt_at_ms, Some(64_004));
        let before = read_raw_terminal_snapshot(
            &root.database(),
            conversation_id,
            command_id,
            claimed.approval_id,
        );

        clock.set(64_003);
        assert!(matches!(
            store
                .terminate_started_before_release(TerminateStartedBeforeRelease {
                    conversation_id,
                    command_id,
                    turn_id,
                    daemon_boot_id: runtime_id(RuntimeIdKind::DaemonBoot, 5),
                    execution_nonce: b"approval-execution-nonce".to_vec(),
                    reason: StartedBeforeReleaseTermination::Interrupted,
                    terminal_payload: b"terminate-clock-regression-result".to_vec(),
                    event_payload: b"terminate-clock-regression-event".to_vec(),
                })
                .await,
            Err(RuntimeStoreError::ClockRegressed {
                persisted_ms: 64_004,
                observed_ms: 64_003,
            })
        ));
        let after = read_raw_terminal_snapshot(
            &root.database(),
            conversation_id,
            command_id,
            claimed.approval_id,
        );
        assert_eq!(
            after, before,
            "clock regression must roll back the entire Safety transaction"
        );
        store
            .shutdown()
            .await
            .expect("shutdown termination regression store");
    }

    #[tokio::test]
    async fn terminal_attempt_timeline_rejects_state_change_before_last_attempt() {
        let root = TestRoot::new("terminal-attempt-timeline-integrity");
        let keys = MemoryKeyStore::new();
        let clock = ManualClock::new(65_000);
        let (store, conversation_id, command_id, turn_id) =
            open_started(&root, &keys, &clock).await;
        clock.set(65_001);
        let claimed = register_and_claim(&store, conversation_id, command_id, turn_id).await;
        clock.set(65_002);
        let first_attempt = match store
            .begin_approval_attempt(BeginApprovalAttempt {
                approval_id: claimed.approval_id,
                delivery_round: 0,
                expected_attempts_in_round: 0,
            })
            .await
            .expect("begin first integrity attempt")
        {
            BeginApprovalAttemptOutcome::Permitted { approval, .. } => approval,
            other => panic!("first integrity attempt must be permitted, got {other:?}"),
        };
        clock.set(65_004);
        let applying = match store
            .begin_approval_attempt(BeginApprovalAttempt {
                approval_id: claimed.approval_id,
                delivery_round: first_attempt.delivery_round,
                expected_attempts_in_round: first_attempt.attempts_in_round,
            })
            .await
            .expect("begin second integrity attempt")
        {
            BeginApprovalAttemptOutcome::Permitted { approval, .. } => approval,
            other => panic!("second integrity attempt must be permitted, got {other:?}"),
        };
        assert_eq!(applying.state_changed_at_ms, 65_002);
        assert_eq!(applying.last_attempt_at_ms, Some(65_004));

        let connection = rusqlite::Connection::open(root.database()).expect("open integrity DB");
        validate_approval_record_linkage(&connection, &applying)
            .expect("Applying may retain the round's earlier state-change timestamp");
        for (state, status_detail) in [
            (ApprovalState::Applied, None),
            (
                ApprovalState::DeliveryFailed,
                Some(b"delivery failed".to_vec()),
            ),
            (ApprovalState::Expired, None),
        ] {
            let terminal = ApprovalRecord {
                state,
                state_changed_at_ms: 65_003,
                state_version: 4,
                status_detail,
                ..applying.clone()
            };
            assert!(matches!(
                validate_approval_record_linkage(&connection, &terminal),
                Err(RuntimeStoreError::UnknownOrCorruptSchema)
            ));
        }
        drop(connection);
        store
            .shutdown()
            .await
            .expect("shutdown timeline integrity store");
    }

    #[tokio::test]
    async fn claimed_begin_attempt_then_applied_is_durable_and_terminal() {
        let root = TestRoot::new("delivery-applied");
        let keys = MemoryKeyStore::new();
        let clock = ManualClock::new(10_000);
        let (store, conversation_id, command_id, turn_id) =
            open_started(&root, &keys, &clock).await;
        clock.set(10_001);
        let claimed = register_and_claim(&store, conversation_id, command_id, turn_id).await;
        clock.set(10_002);
        let applying = match store
            .begin_approval_attempt(BeginApprovalAttempt {
                approval_id: claimed.approval_id,
                delivery_round: 0,
                expected_attempts_in_round: 0,
            })
            .await
            .expect("begin first delivery attempt")
        {
            BeginApprovalAttemptOutcome::Permitted {
                approval,
                event: Some(_),
                replayed: false,
            } => approval,
            other => panic!("first begin must permit and emit Applying, got {other:?}"),
        };
        assert_eq!(applying.state, ApprovalState::Applying);
        assert_eq!(
            (applying.delivery_round, applying.attempts_in_round),
            (1, 1)
        );
        clock.set(10_003);
        let applied = match store
            .mark_approval_applied(MarkApprovalApplied {
                approval_id: applying.approval_id,
                delivery_round: 1,
                attempt: 1,
            })
            .await
            .expect("mark delivery applied")
        {
            ApprovalMutationOutcome::Transitioned { approval, .. } => approval,
            other => panic!("fresh apply must transition, got {other:?}"),
        };
        assert_eq!(applied.state, ApprovalState::Applied);
        assert!(applied.state.is_terminal());
        store.shutdown().await.expect("shutdown before reopen");
        RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.database()).with_clock(clock),
            root.storage_kek(&keys),
        )
        .await
        .expect("authenticated applied row reopens")
        .shutdown()
        .await
        .expect("shutdown reopened store");
    }

    #[tokio::test]
    async fn applying_attempts_cap_at_eight_without_new_state_events() {
        let root = TestRoot::new("delivery-attempt-cap");
        let keys = MemoryKeyStore::new();
        let clock = ManualClock::new(11_000);
        let (store, conversation_id, command_id, turn_id) =
            open_started(&root, &keys, &clock).await;
        clock.set(11_001);
        let claimed = register_and_claim(&store, conversation_id, command_id, turn_id).await;
        let mut approval = claimed;
        let mut applying_version = None;
        let mut applying_event = None;
        for expected in 0..8 {
            clock.set(11_002 + u64::from(expected));
            approval = match store
                .begin_approval_attempt(BeginApprovalAttempt {
                    approval_id: approval.approval_id,
                    delivery_round: if expected == 0 { 0 } else { 1 },
                    expected_attempts_in_round: expected,
                })
                .await
                .expect("begin bounded attempt")
            {
                BeginApprovalAttemptOutcome::Permitted { approval, .. } => approval,
                other => panic!("attempt {expected} must be permitted, got {other:?}"),
            };
            if expected == 0 {
                applying_version = Some(approval.state_version);
                applying_event = Some(approval.last_event_id);
            } else {
                assert_eq!(Some(approval.state_version), applying_version);
                assert_eq!(Some(approval.last_event_id), applying_event);
            }
        }
        assert_eq!(approval.attempts_in_round, 8);
        assert!(matches!(
            store
                .begin_approval_attempt(BeginApprovalAttempt {
                    approval_id: approval.approval_id,
                    delivery_round: 1,
                    expected_attempts_in_round: 8,
                })
                .await,
            Err(RuntimeStoreError::InvalidStateTransition)
        ));
        assert_eq!(Some(approval.state_version), applying_version);
        store.shutdown().await.expect("shutdown approval store");
    }

    #[tokio::test]
    async fn failed_retry_reuses_sealed_winner_and_starts_fresh_round() {
        let root = TestRoot::new("delivery-retry");
        let keys = MemoryKeyStore::new();
        let clock = ManualClock::new(12_000);
        let (store, conversation_id, command_id, turn_id) =
            open_started(&root, &keys, &clock).await;
        clock.set(12_001);
        let claimed = register_and_claim(&store, conversation_id, command_id, turn_id).await;
        clock.set(12_002);
        let applying = match store
            .begin_approval_attempt(BeginApprovalAttempt {
                approval_id: claimed.approval_id,
                delivery_round: 0,
                expected_attempts_in_round: 0,
            })
            .await
            .expect("begin attempt")
        {
            BeginApprovalAttemptOutcome::Permitted { approval, .. } => approval,
            other => panic!("begin must permit, got {other:?}"),
        };
        clock.set(12_003);
        let failed = match store
            .mark_approval_delivery_failed(MarkApprovalDeliveryFailed {
                approval_id: applying.approval_id,
                delivery_round: 1,
                attempt: 1,
                status_detail: b"delivery-failed-sentinel".to_vec(),
            })
            .await
            .expect("mark failed")
        {
            ApprovalMutationOutcome::Transitioned { approval, .. } => approval,
            other => panic!("failed must transition, got {other:?}"),
        };
        assert_eq!(failed.state, ApprovalState::DeliveryFailed);
        assert_eq!(
            failed.status_detail.as_deref(),
            Some(&b"delivery-failed-sentinel"[..])
        );
        clock.set(12_004);
        let retried = match store
            .retry_approval_delivery(RetryApprovalDelivery {
                conversation_id,
                approval_id: failed.approval_id,
            })
            .await
            .expect("retry failed delivery")
        {
            ApprovalMutationOutcome::Transitioned { approval, .. } => approval,
            other => panic!("retry must transition, got {other:?}"),
        };
        assert_eq!(retried.state, ApprovalState::Applying);
        assert_eq!((retried.delivery_round, retried.attempts_in_round), (2, 0));
        assert!(retried.status_detail.is_none());
        assert_eq!(
            retried.decision.as_ref().map(|decision| (
                decision.request_id.as_str(),
                decision.decision,
                decision.persist,
            )),
            failed.decision.as_ref().map(|decision| (
                decision.request_id.as_str(),
                decision.decision,
                decision.persist,
            ))
        );
        store.shutdown().await.expect("shutdown approval store");
    }

    #[tokio::test]
    async fn explicit_expiry_preserves_claimed_winner_but_pending_expiry_has_none() {
        for claimed_first in [false, true] {
            let root = TestRoot::new(if claimed_first {
                "claimed-expiry"
            } else {
                "pending-expiry"
            });
            let keys = MemoryKeyStore::new();
            let clock = ManualClock::new(13_000);
            let (store, conversation_id, command_id, turn_id) =
                open_started(&root, &keys, &clock).await;
            let mut expiry_policy = policy();
            expiry_policy.deadline_at_ms = Some(13_002);
            clock.set(13_001);
            let approval_id = match store
                .register_approval(RegisterApproval {
                    conversation_id,
                    command_id,
                    turn_id,
                    request: request(),
                    policy: expiry_policy,
                })
                .await
                .expect("register expiring approval")
            {
                RegisterApprovalOutcome::Registered { approval, .. } => approval.approval_id,
                RegisterApprovalOutcome::Replayed { .. } => panic!("fresh register cannot replay"),
            };
            if claimed_first {
                let claimant = PrincipalIssuer::local_only([0x71; 32])
                    .issue_verified_local_with_approval_permissions(
                        501,
                        [0x72; 16],
                        ApprovalPermissionGrant::ResolveOnly,
                    )
                    .expect("issue claimant");
                store
                    .claim_approval(ClaimApproval {
                        conversation_id,
                        turn_id,
                        approval_id,
                        decision: ActionDecision {
                            request_id: request().request_id,
                            decision: ActionDecisionKind::Deny,
                            persist: false,
                        },
                        claimant_binding: claimant
                            .try_enter_approval()
                            .expect("claimant active")
                            .claimant_binding(),
                    })
                    .await
                    .expect("claim before deadline");
            }
            clock.set(13_002);
            let expired = match store
                .expire_approval(ExpireApproval {
                    conversation_id,
                    approval_id,
                })
                .await
                .expect("expire approval")
            {
                ApprovalMutationOutcome::Transitioned { approval, .. } => approval,
                other => panic!("expiry must transition, got {other:?}"),
            };
            assert_eq!(expired.state, ApprovalState::Expired);
            assert_eq!(expired.decision.is_some(), claimed_first);
            store
                .shutdown()
                .await
                .expect("shutdown before expiry reopen");
            RuntimeStoreHandle::open(
                RuntimeStoreConfig::new(root.database()).with_clock(clock),
                root.storage_kek(&keys),
            )
            .await
            .expect("authenticated expired row reopens")
            .shutdown()
            .await
            .expect("shutdown reopened store");
        }
    }

    #[tokio::test]
    async fn begin_exact_replay_rejects_clock_regression_before_issuing_permit() {
        let (_root, _keys, clock, store, _conversation_id, claimed) = open_claimed_with_fault(
            "begin-exact-replay-clock-regression",
            RuntimeStoreOperation::BeginApprovalAttemptAfterCommit,
            66_000,
        )
        .await;

        let first_input = || BeginApprovalAttempt {
            approval_id: claimed.approval_id,
            delivery_round: 0,
            expected_attempts_in_round: 0,
        };
        clock.set(66_002);
        assert!(matches!(
            store.begin_approval_attempt(first_input()).await,
            Err(RuntimeStoreError::CommitOutcomeUnknown {
                operation: RuntimeCommitOperation::BeginApprovalAttempt,
            })
        ));

        clock.set(66_001);
        assert!(matches!(
            store.begin_approval_attempt(first_input()).await,
            Err(RuntimeStoreError::ClockRegressed {
                persisted_ms: 66_002,
                observed_ms: 66_001,
            })
        ));

        clock.set(66_002);
        let first = match store
            .begin_approval_attempt(first_input())
            .await
            .expect("exact first attempt retry recovers one permit")
        {
            BeginApprovalAttemptOutcome::Permitted {
                approval,
                replayed: true,
                ..
            } => approval,
            other => panic!("exact first attempt retry must recover one permit, got {other:?}"),
        };
        assert_eq!(first.state_changed_at_ms, 66_002);
        assert_eq!(first.round_started_at_ms, Some(66_002));
        assert_eq!(first.last_attempt_at_ms, Some(66_002));

        let second_input = || BeginApprovalAttempt {
            approval_id: first.approval_id,
            delivery_round: first.delivery_round,
            expected_attempts_in_round: first.attempts_in_round,
        };
        clock.set(66_003);
        let second = match store
            .begin_approval_attempt(second_input())
            .await
            .expect("begin second delivery attempt")
        {
            BeginApprovalAttemptOutcome::Permitted {
                approval,
                replayed: false,
                ..
            } => approval,
            other => panic!("second attempt must mint one permit, got {other:?}"),
        };
        assert_eq!(second.state_changed_at_ms, 66_002);
        assert_eq!(second.round_started_at_ms, Some(66_002));
        assert_eq!(second.last_attempt_at_ms, Some(66_003));

        clock.set(66_002);
        assert!(matches!(
            store.begin_approval_attempt(second_input()).await,
            Err(RuntimeStoreError::ClockRegressed {
                persisted_ms: 66_003,
                observed_ms: 66_002,
            })
        ));
        store.shutdown().await.expect("shutdown approval store");
    }

    #[tokio::test]
    async fn begin_transaction_recheck_rejects_clock_regression_without_mutating_attempt() {
        let root = TestRoot::new("begin-transaction-clock-regression");
        let keys = MemoryKeyStore::new();
        let clock = ArmableClock::new(67_000);
        let config = RuntimeStoreConfig::new(root.database()).with_clock(clock.clone());
        let (store, conversation_id, command_id, turn_id) =
            open_started_with_config(&root, &keys, config).await;
        clock.set(67_001);
        let claimed = register_and_claim(&store, conversation_id, command_id, turn_id).await;
        clock.set(67_002);
        let first = match store
            .begin_approval_attempt(BeginApprovalAttempt {
                approval_id: claimed.approval_id,
                delivery_round: 0,
                expected_attempts_in_round: 0,
            })
            .await
            .expect("begin first delivery attempt")
        {
            BeginApprovalAttemptOutcome::Permitted {
                approval,
                replayed: false,
                ..
            } => approval,
            other => panic!("first attempt must mint one permit, got {other:?}"),
        };
        assert_eq!(first.attempts_in_round, 1);
        assert_eq!(first.state_version, 3);
        assert_eq!(first.last_attempt_at_ms, Some(67_002));

        let raw_snapshot = || {
            let connection =
                rusqlite::Connection::open(root.database()).expect("open attempt snapshot DB");
            let (state, attempts_in_round, state_version): (String, i64, i64) = connection
                .query_row(
                    "SELECT state, attempts_in_round, state_version
                     FROM approval_ledger WHERE approval_id = ?1",
                    [&first.approval_id.as_bytes()[..]],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .expect("read approval attempt snapshot");
            let ledger_event_count: i64 = connection
                .query_row(
                    "SELECT event_count FROM runtime_meta WHERE singleton = 1",
                    [],
                    |row| row.get(0),
                )
                .expect("read attempt ledger event count");
            let actual_event_count: i64 = connection
                .query_row("SELECT COUNT(*) FROM event_journal", [], |row| row.get(0))
                .expect("count attempt events");
            (
                state,
                attempts_in_round,
                state_version,
                ledger_event_count,
                actual_event_count,
            )
        };
        let before = raw_snapshot();
        assert_eq!(before.0, "applying");
        assert_eq!(before.1, 1);
        assert_eq!(before.2, 3);
        assert_eq!(before.3, before.4);

        // 第一次读取供无锁 preflight，通过 persisted boundary；第二次读取发生在
        // BEGIN IMMEDIATE + authenticated reload 之后并回退，必须在签发 permit 前拒绝。
        clock.arm([67_003, 67_001]);
        assert!(matches!(
            store
                .begin_approval_attempt(BeginApprovalAttempt {
                    approval_id: first.approval_id,
                    delivery_round: first.delivery_round,
                    expected_attempts_in_round: first.attempts_in_round,
                })
                .await,
            Err(RuntimeStoreError::ClockRegressed {
                persisted_ms: 67_002,
                observed_ms: 67_001,
            })
        ));
        assert_eq!(
            clock.pending_reads(),
            0,
            "transaction must consume the second scripted clock read"
        );
        let after = raw_snapshot();
        assert_eq!(after.0, before.0, "approval state changed on rejection");
        assert_eq!(after.1, before.1, "attempt count changed on rejection");
        assert_eq!(after.2, before.2, "stateVersion changed on rejection");
        assert_eq!(after.3, before.3, "ledger eventCount changed on rejection");
        assert_eq!(after.4, before.4, "event journal changed on rejection");
        store.shutdown().await.expect("shutdown approval store");
    }

    #[tokio::test]
    async fn five_delivery_mutations_before_and_after_commit_converge_exactly() {
        for (after_commit, fault) in [
            (
                false,
                RuntimeStoreOperation::BeginApprovalAttemptBeforeCommit,
            ),
            (true, RuntimeStoreOperation::BeginApprovalAttemptAfterCommit),
        ] {
            let (_root, _keys, clock, store, _conversation_id, claimed) =
                open_claimed_with_fault("fault-begin", fault, 20_000).await;
            clock.set(20_002);
            let input = || BeginApprovalAttempt {
                approval_id: claimed.approval_id,
                delivery_round: 0,
                expected_attempts_in_round: 0,
            };
            assert_fault_result(
                store
                    .begin_approval_attempt(input())
                    .await
                    .expect_err("faulted begin"),
                RuntimeCommitOperation::BeginApprovalAttempt,
                after_commit,
            );
            let recovered = store
                .begin_approval_attempt(input())
                .await
                .expect("exact begin retry recovers permit");
            assert!(matches!(
                recovered,
                BeginApprovalAttemptOutcome::Permitted {
                    replayed,
                    ref approval,
                    ..
                } if replayed == after_commit
                    && approval.state == ApprovalState::Applying
                    && approval.attempts_in_round == 1
            ));
            store.shutdown().await.expect("shutdown begin fault store");
        }

        for (after_commit, fault) in [
            (
                false,
                RuntimeStoreOperation::MarkApprovalAppliedBeforeCommit,
            ),
            (true, RuntimeStoreOperation::MarkApprovalAppliedAfterCommit),
        ] {
            let (_root, _keys, clock, store, _conversation_id, claimed) =
                open_claimed_with_fault("fault-applied", fault, 21_000).await;
            clock.set(21_002);
            let applying = match store
                .begin_approval_attempt(BeginApprovalAttempt {
                    approval_id: claimed.approval_id,
                    delivery_round: 0,
                    expected_attempts_in_round: 0,
                })
                .await
                .expect("begin before applied fault")
            {
                BeginApprovalAttemptOutcome::Permitted { approval, .. } => approval,
                other => panic!("expected permit, got {other:?}"),
            };
            clock.set(21_003);
            let input = || MarkApprovalApplied {
                approval_id: applying.approval_id,
                delivery_round: 1,
                attempt: 1,
            };
            assert_fault_result(
                store
                    .mark_approval_applied(input())
                    .await
                    .expect_err("faulted applied"),
                RuntimeCommitOperation::MarkApprovalApplied,
                after_commit,
            );
            let retry = store
                .mark_approval_applied(input())
                .await
                .expect("exact applied retry");
            assert_eq!(
                matches!(retry, ApprovalMutationOutcome::Replayed { .. }),
                after_commit
            );
            store
                .shutdown()
                .await
                .expect("shutdown applied fault store");
        }

        for (after_commit, fault) in [
            (
                false,
                RuntimeStoreOperation::MarkApprovalDeliveryFailedBeforeCommit,
            ),
            (
                true,
                RuntimeStoreOperation::MarkApprovalDeliveryFailedAfterCommit,
            ),
        ] {
            let (_root, _keys, clock, store, _conversation_id, claimed) =
                open_claimed_with_fault("fault-failed", fault, 22_000).await;
            clock.set(22_002);
            let applying = match store
                .begin_approval_attempt(BeginApprovalAttempt {
                    approval_id: claimed.approval_id,
                    delivery_round: 0,
                    expected_attempts_in_round: 0,
                })
                .await
                .expect("begin before failed fault")
            {
                BeginApprovalAttemptOutcome::Permitted { approval, .. } => approval,
                other => panic!("expected permit, got {other:?}"),
            };
            clock.set(22_003);
            let input = || MarkApprovalDeliveryFailed {
                approval_id: applying.approval_id,
                delivery_round: 1,
                attempt: 1,
                status_detail: b"fault-delivery-detail".to_vec(),
            };
            assert_fault_result(
                store
                    .mark_approval_delivery_failed(input())
                    .await
                    .expect_err("faulted delivery failed"),
                RuntimeCommitOperation::MarkApprovalDeliveryFailed,
                after_commit,
            );
            let retry = store
                .mark_approval_delivery_failed(input())
                .await
                .expect("exact failed retry");
            assert_eq!(
                matches!(retry, ApprovalMutationOutcome::Replayed { .. }),
                after_commit
            );
            store.shutdown().await.expect("shutdown failed fault store");
        }

        for (after_commit, fault) in [
            (
                false,
                RuntimeStoreOperation::RetryApprovalDeliveryBeforeCommit,
            ),
            (
                true,
                RuntimeStoreOperation::RetryApprovalDeliveryAfterCommit,
            ),
        ] {
            let (_root, _keys, clock, store, conversation_id, claimed) =
                open_claimed_with_fault("fault-retry", fault, 23_000).await;
            clock.set(23_002);
            let applying = match store
                .begin_approval_attempt(BeginApprovalAttempt {
                    approval_id: claimed.approval_id,
                    delivery_round: 0,
                    expected_attempts_in_round: 0,
                })
                .await
                .expect("begin before retry fault")
            {
                BeginApprovalAttemptOutcome::Permitted { approval, .. } => approval,
                other => panic!("expected permit, got {other:?}"),
            };
            clock.set(23_003);
            store
                .mark_approval_delivery_failed(MarkApprovalDeliveryFailed {
                    approval_id: applying.approval_id,
                    delivery_round: 1,
                    attempt: 1,
                    status_detail: b"retry-fault-detail".to_vec(),
                })
                .await
                .expect("mark failed before retry fault");
            clock.set(23_004);
            let input = || RetryApprovalDelivery {
                conversation_id,
                approval_id: applying.approval_id,
            };
            assert_fault_result(
                store
                    .retry_approval_delivery(input())
                    .await
                    .expect_err("faulted retry"),
                RuntimeCommitOperation::RetryApprovalDelivery,
                after_commit,
            );
            let retry = store
                .retry_approval_delivery(input())
                .await
                .expect("exact retry retry");
            assert_eq!(
                matches!(retry, ApprovalMutationOutcome::Replayed { .. }),
                after_commit
            );
            store.shutdown().await.expect("shutdown retry fault store");
        }

        for (after_commit, fault) in [
            (false, RuntimeStoreOperation::ExpireApprovalBeforeCommit),
            (true, RuntimeStoreOperation::ExpireApprovalAfterCommit),
        ] {
            let root = TestRoot::new("fault-expire");
            let keys = MemoryKeyStore::new();
            let clock = ManualClock::new(24_000);
            let config = RuntimeStoreConfig::new(root.database())
                .with_clock(clock.clone())
                .with_fault_injector(Arc::new(FailOnce::new(fault)));
            let (store, conversation_id, command_id, turn_id) =
                open_started_with_config(&root, &keys, config).await;
            let mut short = policy();
            short.deadline_at_ms = Some(24_002);
            clock.set(24_001);
            let approval_id = match store
                .register_approval(RegisterApproval {
                    conversation_id,
                    command_id,
                    turn_id,
                    request: request(),
                    policy: short,
                })
                .await
                .expect("register expire fault target")
            {
                RegisterApprovalOutcome::Registered { approval, .. } => approval.approval_id,
                RegisterApprovalOutcome::Replayed { .. } => panic!("fresh register cannot replay"),
            };
            clock.set(24_002);
            let input = || ExpireApproval {
                conversation_id,
                approval_id,
            };
            assert_fault_result(
                store
                    .expire_approval(input())
                    .await
                    .expect_err("faulted expiry"),
                RuntimeCommitOperation::ExpireApproval,
                after_commit,
            );
            let retry = store
                .expire_approval(input())
                .await
                .expect("exact expiry retry");
            assert_eq!(
                matches!(retry, ApprovalMutationOutcome::Replayed { .. }),
                after_commit
            );
            store.shutdown().await.expect("shutdown expiry fault store");
        }
    }

    #[tokio::test]
    async fn begin_after_commit_unknown_crossing_deadline_expires_without_reissuing_permit() {
        let root = TestRoot::new("begin-unknown-deadline");
        let keys = MemoryKeyStore::new();
        let clock = ManualClock::new(25_000);
        let config = RuntimeStoreConfig::new(root.database())
            .with_clock(clock.clone())
            .with_fault_injector(Arc::new(FailOnce::new(
                RuntimeStoreOperation::BeginApprovalAttemptAfterCommit,
            )));
        let (store, conversation_id, command_id, turn_id) =
            open_started_with_config(&root, &keys, config).await;
        let mut short = policy();
        short.deadline_at_ms = Some(25_003);
        clock.set(25_001);
        let approval_id = match store
            .register_approval(RegisterApproval {
                conversation_id,
                command_id,
                turn_id,
                request: request(),
                policy: short,
            })
            .await
            .expect("register short approval")
        {
            RegisterApprovalOutcome::Registered { approval, .. } => approval.approval_id,
            RegisterApprovalOutcome::Replayed { .. } => panic!("fresh register cannot replay"),
        };
        let claimant = PrincipalIssuer::local_only([0x81; 32])
            .issue_verified_local_with_approval_permissions(
                501,
                [0x82; 16],
                ApprovalPermissionGrant::ResolveOnly,
            )
            .expect("issue claimant");
        clock.set(25_002);
        store
            .claim_approval(ClaimApproval {
                conversation_id,
                turn_id,
                approval_id,
                decision: ActionDecision {
                    request_id: request().request_id,
                    decision: ActionDecisionKind::Approve,
                    persist: true,
                },
                claimant_binding: claimant
                    .try_enter_approval()
                    .expect("claimant active")
                    .claimant_binding(),
            })
            .await
            .expect("claim short approval");
        let input = || BeginApprovalAttempt {
            approval_id,
            delivery_round: 0,
            expected_attempts_in_round: 0,
        };
        assert!(matches!(
            store.begin_approval_attempt(input()).await,
            Err(RuntimeStoreError::CommitOutcomeUnknown {
                operation: RuntimeCommitOperation::BeginApprovalAttempt
            })
        ));
        clock.set(25_003);
        assert!(matches!(
            store
                .begin_approval_attempt(input())
                .await
                .expect("deadline retry converges to expiry"),
            BeginApprovalAttemptOutcome::ExpiredOrStale { approval }
                if approval.state == ApprovalState::Expired
        ));
        store.shutdown().await.expect("shutdown before reopen");
        RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.database()).with_clock(clock),
            root.storage_kek(&keys),
        )
        .await
        .expect("deadline expiry after unknown is durable")
        .shutdown()
        .await
        .expect("shutdown reopened store");
    }

    #[tokio::test]
    async fn retry_after_commit_unknown_crossing_deadline_durably_expires_before_reply() {
        let root = TestRoot::new("retry-unknown-deadline");
        let keys = MemoryKeyStore::new();
        let clock = ManualClock::new(26_000);
        let config = RuntimeStoreConfig::new(root.database())
            .with_clock(clock.clone())
            .with_fault_injector(Arc::new(FailOnce::new(
                RuntimeStoreOperation::RetryApprovalDeliveryAfterCommit,
            )));
        let (store, conversation_id, command_id, turn_id) =
            open_started_with_config(&root, &keys, config).await;
        let mut short = policy();
        short.deadline_at_ms = Some(26_010);
        clock.set(26_001);
        let approval_id = match store
            .register_approval(RegisterApproval {
                conversation_id,
                command_id,
                turn_id,
                request: request(),
                policy: short,
            })
            .await
            .expect("register retry deadline approval")
        {
            RegisterApprovalOutcome::Registered { approval, .. } => approval.approval_id,
            RegisterApprovalOutcome::Replayed { .. } => panic!("fresh register cannot replay"),
        };
        let claimant = PrincipalIssuer::local_only([0x83; 32])
            .issue_verified_local_with_approval_permissions(
                501,
                [0x84; 16],
                ApprovalPermissionGrant::ResolveOnly,
            )
            .expect("issue retry deadline claimant");
        clock.set(26_002);
        store
            .claim_approval(ClaimApproval {
                conversation_id,
                turn_id,
                approval_id,
                decision: ActionDecision {
                    request_id: request().request_id,
                    decision: ActionDecisionKind::Approve,
                    persist: true,
                },
                claimant_binding: claimant
                    .try_enter_approval()
                    .expect("retry deadline claimant active")
                    .claimant_binding(),
            })
            .await
            .expect("claim retry deadline approval");
        clock.set(26_003);
        let applying = match store
            .begin_approval_attempt(BeginApprovalAttempt {
                approval_id,
                delivery_round: 0,
                expected_attempts_in_round: 0,
            })
            .await
            .expect("begin retry deadline attempt")
        {
            BeginApprovalAttemptOutcome::Permitted { approval, .. } => approval,
            other => panic!("retry deadline fixture must apply, got {other:?}"),
        };
        clock.set(26_004);
        store
            .mark_approval_delivery_failed(MarkApprovalDeliveryFailed {
                approval_id,
                delivery_round: applying.delivery_round,
                attempt: applying.attempts_in_round,
                status_detail: b"retry-deadline-failed".to_vec(),
            })
            .await
            .expect("mark retry deadline DeliveryFailed");
        let input = || RetryApprovalDelivery {
            conversation_id,
            approval_id,
        };
        clock.set(26_005);
        assert!(matches!(
            store.retry_approval_delivery(input()).await,
            Err(RuntimeStoreError::CommitOutcomeUnknown {
                operation: RuntimeCommitOperation::RetryApprovalDelivery
            })
        ));

        clock.set(26_010);
        assert!(matches!(
            store
                .retry_approval_delivery(input())
                .await
                .expect("deadline retry must close before replying"),
            ApprovalMutationOutcome::ExpiredOrStale { approval }
                if approval.state == ApprovalState::Expired
                    && approval.delivery_round == 2
                    && approval.attempts_in_round == 0
        ));
        store
            .shutdown()
            .await
            .expect("shutdown retry deadline store");

        let connection =
            rusqlite::Connection::open(root.database()).expect("open retry deadline DB");
        let (state, active_count): (String, i64) = connection
            .query_row(
                "SELECT approval.state, runtime.active_approval_count
                 FROM approval_ledger AS approval CROSS JOIN runtime_meta AS runtime
                 WHERE approval.approval_id = ?1 AND runtime.singleton = 1",
                [&approval_id.as_bytes()[..]],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("read durable retry deadline closure");
        assert_eq!(state, "expired");
        assert_eq!(active_count, 0);
        drop(connection);

        RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.database()).with_clock(clock),
            root.storage_kek(&keys),
        )
        .await
        .expect("authenticated retry deadline closure reopens")
        .shutdown()
        .await
        .expect("shutdown reopened retry deadline closure");
    }

    #[tokio::test]
    async fn pending_registration_is_atomic_with_action_request_event() {
        let root = TestRoot::new("pending-registration");
        let keys = MemoryKeyStore::new();
        let clock = ManualClock::new(1_000);
        let (store, conversation_id, command_id, turn_id) =
            open_started(&root, &keys, &clock).await;
        clock.set(1_001);

        let registered = store
            .register_approval(RegisterApproval {
                conversation_id,
                command_id,
                turn_id,
                request: request(),
                policy: policy(),
            })
            .await
            .expect("register pending approval");
        let (approval, event) = match registered {
            RegisterApprovalOutcome::Registered { approval, event } => (approval, event),
            RegisterApprovalOutcome::Replayed { .. } => panic!("fresh register cannot replay"),
        };
        assert_eq!(
            approval.state,
            super::super::super::model::ApprovalState::Pending
        );
        assert_eq!(approval.last_event_id, event.event_id);
        assert_eq!(approval.requested_at_ms, 1_001);
        assert_eq!(approval.deadline_at_ms, 1_801_001);
        assert_eq!(event.conversation_id, conversation_id);
        assert_eq!(event.command_id, Some(command_id));

        let replay = store
            .register_approval(RegisterApproval {
                conversation_id,
                command_id,
                turn_id,
                request: request(),
                policy: policy(),
            })
            .await
            .expect("replay pending approval");
        assert!(matches!(
            replay,
            RegisterApprovalOutcome::Replayed { approval: replayed, event: replayed_event }
                if replayed.approval_id == approval.approval_id
                    && replayed_event.event_id == event.event_id
        ));
        store.shutdown().await.expect("shutdown approval store");
    }

    #[tokio::test]
    async fn claim_is_first_wins_and_exact_same_claimant_decision_replays() {
        let root = TestRoot::new("first-wins");
        let keys = MemoryKeyStore::new();
        let clock = ManualClock::new(2_000);
        let (store, conversation_id, command_id, turn_id) =
            open_started(&root, &keys, &clock).await;
        clock.set(2_001);
        let approval_id = match store
            .register_approval(RegisterApproval {
                conversation_id,
                command_id,
                turn_id,
                request: request(),
                policy: policy(),
            })
            .await
            .expect("register approval")
        {
            RegisterApprovalOutcome::Registered { approval, .. } => approval.approval_id,
            RegisterApprovalOutcome::Replayed { .. } => panic!("fresh register cannot replay"),
        };

        let issuer = PrincipalIssuer::local_only([0x91; 32]);
        let winner = issuer
            .issue_verified_local_with_approval_permissions(
                501,
                [0x92; 16],
                ApprovalPermissionGrant::ResolveOnly,
            )
            .expect("issue winner");
        let loser = issuer
            .issue_verified_local_with_approval_permissions(
                501,
                [0x93; 16],
                ApprovalPermissionGrant::ResolveOnly,
            )
            .expect("issue loser");
        let approve = ActionDecision {
            request_id: request().request_id,
            decision: ActionDecisionKind::Approve,
            persist: true,
        };
        clock.set(2_002);
        let transitioned = store
            .claim_approval(ClaimApproval {
                conversation_id,
                turn_id,
                approval_id,
                decision: approve.clone(),
                claimant_binding: winner
                    .try_enter_approval()
                    .expect("winner active")
                    .claimant_binding(),
            })
            .await
            .expect("winner claim");
        let winner_approval = match transitioned {
            ApprovalMutationOutcome::Transitioned { approval, .. } => approval,
            other => panic!("first claim must transition, got {other:?}"),
        };
        assert_eq!(
            winner_approval.state,
            super::super::super::model::ApprovalState::Claimed
        );
        assert!(matches!(
            winner_approval.decision.as_ref(),
            Some(decision)
                if decision.request_id == approve.request_id
                    && decision.decision == ActionDecisionKind::Approve
                    && decision.persist
        ));

        let replay = store
            .claim_approval(ClaimApproval {
                conversation_id,
                turn_id,
                approval_id,
                decision: approve,
                claimant_binding: winner
                    .try_enter_approval()
                    .expect("winner still active")
                    .claimant_binding(),
            })
            .await
            .expect("exact retry");
        assert!(matches!(replay, ApprovalMutationOutcome::Replayed { .. }));

        let already_handled = store
            .claim_approval(ClaimApproval {
                conversation_id,
                turn_id,
                approval_id,
                decision: ActionDecision {
                    request_id: request().request_id,
                    decision: ActionDecisionKind::Deny,
                    persist: false,
                },
                claimant_binding: loser
                    .try_enter_approval()
                    .expect("loser active")
                    .claimant_binding(),
            })
            .await
            .expect("loser observes winner");
        assert!(matches!(
            already_handled,
            ApprovalMutationOutcome::AlreadyHandled { approval }
                if matches!(
                    approval.decision,
                    Some(ref decision) if decision.decision == ActionDecisionKind::Approve
                )
        ));
        assert_store_files_do_not_contain(&root.database(), b"approval-request-sentinel");
        assert_store_files_do_not_contain(&root.database(), b"approval-summary-sentinel");
        assert_store_files_do_not_contain(&root.database(), &[0x91; 32]);
        store.shutdown().await.expect("shutdown approval store");
    }

    #[tokio::test]
    async fn claimed_approval_survives_authenticated_reopen() {
        let root = TestRoot::new("claimed-reopen");
        let keys = MemoryKeyStore::new();
        let clock = ManualClock::new(3_000);
        let (store, conversation_id, command_id, turn_id) =
            open_started(&root, &keys, &clock).await;
        clock.set(3_001);
        let approval_id = match store
            .register_approval(RegisterApproval {
                conversation_id,
                command_id,
                turn_id,
                request: request(),
                policy: policy(),
            })
            .await
            .expect("register approval")
        {
            RegisterApprovalOutcome::Registered { approval, .. } => approval.approval_id,
            RegisterApprovalOutcome::Replayed { .. } => panic!("fresh register cannot replay"),
        };
        let issuer = PrincipalIssuer::local_only([0xa1; 32]);
        let winner = issuer
            .issue_verified_local_with_approval_permissions(
                501,
                [0xa2; 16],
                ApprovalPermissionGrant::ResolveOnly,
            )
            .expect("issue winner");
        clock.set(3_002);
        assert!(matches!(
            store
                .claim_approval(ClaimApproval {
                    conversation_id,
                    turn_id,
                    approval_id,
                    decision: ActionDecision {
                        request_id: request().request_id,
                        decision: ActionDecisionKind::Approve,
                        persist: true,
                    },
                    claimant_binding: winner
                        .try_enter_approval()
                        .expect("winner active")
                        .claimant_binding(),
                })
                .await
                .expect("claim approval"),
            ApprovalMutationOutcome::Transitioned { .. }
        ));
        store.shutdown().await.expect("shutdown before reopen");

        let reopened = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.database()).with_clock(clock),
            root.storage_kek(&keys),
        )
        .await
        .expect("authenticated approval rows reopen");
        reopened.shutdown().await.expect("shutdown reopened store");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn one_of_100_concurrent_claims_wins_and_every_loser_observes_that_winner() {
        let root = TestRoot::new("hundred-claimants");
        let keys = MemoryKeyStore::new();
        let clock = ManualClock::new(4_000);
        let config = RuntimeStoreConfig::new(root.database())
            .with_clock(clock.clone())
            .with_command_capacity(128);
        let (store, conversation_id, command_id, turn_id) =
            open_started_with_config(&root, &keys, config).await;
        clock.set(4_001);
        let approval_id = match store
            .register_approval(RegisterApproval {
                conversation_id,
                command_id,
                turn_id,
                request: request(),
                policy: policy(),
            })
            .await
            .expect("register approval")
        {
            RegisterApprovalOutcome::Registered { approval, .. } => approval.approval_id,
            RegisterApprovalOutcome::Replayed { .. } => panic!("fresh register cannot replay"),
        };
        clock.set(4_002);
        let issuer = PrincipalIssuer::local_only([0xb1; 32]);
        let barrier = Arc::new(tokio::sync::Barrier::new(101));
        let mut tasks = tokio::task::JoinSet::new();
        for index in 0_u8..100 {
            let principal = issuer
                .issue_verified_local_with_approval_permissions(
                    501,
                    [index.wrapping_add(1); 16],
                    ApprovalPermissionGrant::ResolveOnly,
                )
                .expect("issue claimant");
            let claimant_binding = principal
                .try_enter_approval()
                .expect("claimant active")
                .claimant_binding();
            let store = store.clone();
            let barrier = barrier.clone();
            tasks.spawn(async move {
                barrier.wait().await;
                store
                    .claim_approval(ClaimApproval {
                        conversation_id,
                        turn_id,
                        approval_id,
                        decision: ActionDecision {
                            request_id: "approval-request-sentinel".to_owned(),
                            decision: if index % 2 == 0 {
                                ActionDecisionKind::Approve
                            } else {
                                ActionDecisionKind::Deny
                            },
                            persist: index % 2 == 0,
                        },
                        claimant_binding,
                    })
                    .await
            });
        }
        barrier.wait().await;

        let mut transitioned = 0;
        let mut already_handled = 0;
        let mut winner = None;
        while let Some(result) = tasks.join_next().await {
            match result.expect("claim task joined").expect("claim outcome") {
                ApprovalMutationOutcome::Transitioned { approval, .. } => {
                    transitioned += 1;
                    winner = approval
                        .decision
                        .map(|decision| (decision.decision, decision.persist));
                }
                ApprovalMutationOutcome::AlreadyHandled { approval } => {
                    already_handled += 1;
                    let observed = approval
                        .decision
                        .map(|decision| (decision.decision, decision.persist))
                        .expect("loser observes immutable winner");
                    if let Some(winner) = winner {
                        assert_eq!(observed, winner);
                    } else {
                        winner = Some(observed);
                    }
                }
                other => panic!("concurrent first-wins returned {other:?}"),
            }
        }
        assert_eq!(transitioned, 1);
        assert_eq!(already_handled, 99);
        store.shutdown().await.expect("shutdown approval store");
    }

    #[tokio::test]
    async fn register_before_commit_rolls_back_and_after_commit_exact_retry_replays() {
        for (label, operation, expect_unknown) in [
            (
                "register-before-commit",
                RuntimeStoreOperation::RegisterApprovalBeforeCommit,
                false,
            ),
            (
                "register-after-commit",
                RuntimeStoreOperation::RegisterApprovalAfterCommit,
                true,
            ),
        ] {
            let root = TestRoot::new(label);
            let keys = MemoryKeyStore::new();
            let clock = ManualClock::new(5_000);
            let config = RuntimeStoreConfig::new(root.database())
                .with_clock(clock.clone())
                .with_fault_injector(Arc::new(FailOnce::new(operation)));
            let (store, conversation_id, command_id, turn_id) =
                open_started_with_config(&root, &keys, config).await;
            clock.set(5_001);
            let first = store
                .register_approval(RegisterApproval {
                    conversation_id,
                    command_id,
                    turn_id,
                    request: request(),
                    policy: policy(),
                })
                .await
                .expect_err("faulted register does not return an outcome");
            assert_eq!(
                matches!(
                    first,
                    RuntimeStoreError::CommitOutcomeUnknown {
                        operation: RuntimeCommitOperation::RegisterApproval
                    }
                ),
                expect_unknown
            );
            let retry = store
                .register_approval(RegisterApproval {
                    conversation_id,
                    command_id,
                    turn_id,
                    request: request(),
                    policy: policy(),
                })
                .await
                .expect("identical register retry converges");
            assert_eq!(
                matches!(&retry, RegisterApprovalOutcome::Replayed { .. }),
                expect_unknown
            );
            assert_eq!(
                matches!(&retry, RegisterApprovalOutcome::Registered { .. }),
                !expect_unknown
            );
            store.shutdown().await.expect("shutdown approval store");
        }
    }

    #[tokio::test]
    async fn claim_before_commit_rolls_back_and_after_commit_exact_retry_replays() {
        for (label, operation, expect_unknown) in [
            (
                "claim-before-commit",
                RuntimeStoreOperation::ClaimApprovalBeforeCommit,
                false,
            ),
            (
                "claim-after-commit",
                RuntimeStoreOperation::ClaimApprovalAfterCommit,
                true,
            ),
        ] {
            let root = TestRoot::new(label);
            let keys = MemoryKeyStore::new();
            let clock = ManualClock::new(6_000);
            let config = RuntimeStoreConfig::new(root.database())
                .with_clock(clock.clone())
                .with_fault_injector(Arc::new(FailOnce::new(operation)));
            let (store, conversation_id, command_id, turn_id) =
                open_started_with_config(&root, &keys, config).await;
            clock.set(6_001);
            let approval_id = match store
                .register_approval(RegisterApproval {
                    conversation_id,
                    command_id,
                    turn_id,
                    request: request(),
                    policy: policy(),
                })
                .await
                .expect("register approval")
            {
                RegisterApprovalOutcome::Registered { approval, .. } => approval.approval_id,
                RegisterApprovalOutcome::Replayed { .. } => panic!("fresh register cannot replay"),
            };
            let issuer = PrincipalIssuer::local_only([0xc1; 32]);
            let claimant = issuer
                .issue_verified_local_with_approval_permissions(
                    501,
                    [0xc2; 16],
                    ApprovalPermissionGrant::ResolveOnly,
                )
                .expect("issue claimant");
            let decision = ActionDecision {
                request_id: request().request_id,
                decision: ActionDecisionKind::Approve,
                persist: true,
            };
            clock.set(6_002);
            let first = store
                .claim_approval(ClaimApproval {
                    conversation_id,
                    turn_id,
                    approval_id,
                    decision: decision.clone(),
                    claimant_binding: claimant
                        .try_enter_approval()
                        .expect("claimant active")
                        .claimant_binding(),
                })
                .await
                .expect_err("faulted claim does not return an outcome");
            assert_eq!(
                matches!(
                    first,
                    RuntimeStoreError::CommitOutcomeUnknown {
                        operation: RuntimeCommitOperation::ClaimApproval
                    }
                ),
                expect_unknown
            );
            let retry = store
                .claim_approval(ClaimApproval {
                    conversation_id,
                    turn_id,
                    approval_id,
                    decision,
                    claimant_binding: claimant
                        .try_enter_approval()
                        .expect("claimant remains active")
                        .claimant_binding(),
                })
                .await
                .expect("identical claim retry converges");
            assert_eq!(
                matches!(&retry, ApprovalMutationOutcome::Replayed { .. }),
                expect_unknown
            );
            assert_eq!(
                matches!(&retry, ApprovalMutationOutcome::Transitioned { .. }),
                !expect_unknown
            );
            store.shutdown().await.expect("shutdown approval store");
        }
    }

    #[tokio::test]
    async fn claim_requires_exact_ids_request_and_frozen_policy() {
        let root = TestRoot::new("claim-validation");
        let keys = MemoryKeyStore::new();
        let clock = ManualClock::new(7_000);
        let (store, conversation_id, command_id, turn_id) =
            open_started(&root, &keys, &clock).await;
        clock.set(7_001);
        let approval_id = match store
            .register_approval(RegisterApproval {
                conversation_id,
                command_id,
                turn_id,
                request: request(),
                policy: policy(),
            })
            .await
            .expect("register approval")
        {
            RegisterApprovalOutcome::Registered { approval, .. } => approval.approval_id,
            RegisterApprovalOutcome::Replayed { .. } => panic!("fresh register cannot replay"),
        };
        let issuer = PrincipalIssuer::local_only([0xd1; 32]);
        let claimant = issuer
            .issue_verified_local_with_approval_permissions(
                501,
                [0xd2; 16],
                ApprovalPermissionGrant::ResolveOnly,
            )
            .expect("issue claimant");
        let binding = || {
            claimant
                .try_enter_approval()
                .expect("claimant active")
                .claimant_binding()
        };
        let approve = || ActionDecision {
            request_id: "approval-request-sentinel".to_owned(),
            decision: ActionDecisionKind::Approve,
            persist: true,
        };
        for invalid in [
            ClaimApproval {
                conversation_id: runtime_id(RuntimeIdKind::Conversation, 0xe1),
                turn_id,
                approval_id,
                decision: approve(),
                claimant_binding: binding(),
            },
            ClaimApproval {
                conversation_id,
                turn_id: runtime_id(RuntimeIdKind::Turn, 0xe2),
                approval_id,
                decision: approve(),
                claimant_binding: binding(),
            },
            ClaimApproval {
                conversation_id,
                turn_id,
                approval_id: runtime_id(RuntimeIdKind::Approval, 0xe3),
                decision: approve(),
                claimant_binding: binding(),
            },
            ClaimApproval {
                conversation_id,
                turn_id,
                approval_id,
                decision: ActionDecision {
                    request_id: "wrong-request-id".to_owned(),
                    decision: ActionDecisionKind::Approve,
                    persist: true,
                },
                claimant_binding: binding(),
            },
        ] {
            assert!(matches!(
                store.claim_approval(invalid).await,
                Err(RuntimeStoreError::InvalidStateTransition)
            ));
        }
        assert!(matches!(
            store
                .claim_approval(ClaimApproval {
                    conversation_id,
                    turn_id,
                    approval_id,
                    decision: approve(),
                    claimant_binding: binding(),
                })
                .await
                .expect("valid claim still wins after mismatches"),
            ApprovalMutationOutcome::Transitioned { .. }
        ));
        store.shutdown().await.expect("shutdown approval store");
    }

    #[tokio::test]
    async fn claim_at_deadline_atomically_persists_pending_as_expired() {
        let root = TestRoot::new("claim-deadline");
        let keys = MemoryKeyStore::new();
        let clock = ManualClock::new(8_000);
        let (store, conversation_id, command_id, turn_id) =
            open_started(&root, &keys, &clock).await;
        let mut deadline_policy = policy();
        deadline_policy.deadline_at_ms = Some(8_002);
        clock.set(8_001);
        let approval_id = match store
            .register_approval(RegisterApproval {
                conversation_id,
                command_id,
                turn_id,
                request: request(),
                policy: deadline_policy,
            })
            .await
            .expect("register short approval")
        {
            RegisterApprovalOutcome::Registered { approval, .. } => approval.approval_id,
            RegisterApprovalOutcome::Replayed { .. } => panic!("fresh register cannot replay"),
        };
        let issuer = PrincipalIssuer::local_only([0xf1; 32]);
        let claimant = issuer
            .issue_verified_local_with_approval_permissions(
                501,
                [0xf2; 16],
                ApprovalPermissionGrant::ResolveOnly,
            )
            .expect("issue claimant");
        clock.set(8_002);
        assert!(matches!(
            store
                .claim_approval(ClaimApproval {
                    conversation_id,
                    turn_id,
                    approval_id,
                    decision: ActionDecision {
                        request_id: request().request_id,
                        decision: ActionDecisionKind::Approve,
                        persist: true,
                    },
                    claimant_binding: claimant
                        .try_enter_approval()
                        .expect("claimant active")
                        .claimant_binding(),
                })
                .await
                .expect("deadline outcome"),
            ApprovalMutationOutcome::ExpiredOrStale { approval }
                if approval.state == super::super::super::model::ApprovalState::Expired
                    && approval.decision.is_none()
        ));
        store.shutdown().await.expect("shutdown before reopen");
        RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.database()).with_clock(clock),
            root.storage_kek(&keys),
        )
        .await
        .expect("deadline expiry is durable and authenticated")
        .shutdown()
        .await
        .expect("shutdown reopened store");
    }

    #[tokio::test]
    async fn deadline_claim_uses_reserved_safety_lane_after_ordinary_writes_are_latched_off() {
        let root = TestRoot::new("claim-deadline-safety-only");
        let keys = MemoryKeyStore::new();
        let clock = ManualClock::new(8_100);
        let probe = MutableCapacityProbe::new(healthy_capacity());
        let config = RuntimeStoreConfig::new(root.database())
            .with_clock(clock.clone())
            .with_capacity_probe(probe.clone());
        let (store, conversation_id, command_id, turn_id) =
            open_started_with_config(&root, &keys, config).await;
        let mut deadline_policy = policy();
        deadline_policy.deadline_at_ms = Some(8_102);
        clock.set(8_101);
        let approval_id = match store
            .register_approval(RegisterApproval {
                conversation_id,
                command_id,
                turn_id,
                request: request(),
                policy: deadline_policy,
            })
            .await
            .expect("register short approval")
        {
            RegisterApprovalOutcome::Registered { approval, .. } => approval.approval_id,
            RegisterApprovalOutcome::Replayed { .. } => panic!("fresh register cannot replay"),
        };
        let owner = IdempotencyOwner::Local {
            machine_trust_domain: [0x31; 32],
            uid: 501,
            client_installation_id: [0x32; 16],
        };
        probe.set(over_limit_capacity());
        store
            .accept_command(AcceptCommand {
                conversation_id,
                owner: owner.clone(),
                idempotency_key: "latch-safety-only".to_owned(),
                payload: b"must-not-commit".to_vec(),
            })
            .await
            .expect_err("hard limit latches ordinary writes off");
        probe.set(healthy_capacity());
        assert!(matches!(
            store
                .accept_command(AcceptCommand {
                    conversation_id,
                    owner,
                    idempotency_key: "confirm-safety-only".to_owned(),
                    payload: b"still-must-not-commit".to_vec(),
                })
                .await,
            Err(RuntimeStoreError::SafetyOnly)
        ));
        let claimant = PrincipalIssuer::local_only([0x33; 32])
            .issue_verified_local_with_approval_permissions(
                501,
                [0x34; 16],
                ApprovalPermissionGrant::ResolveOnly,
            )
            .expect("issue claimant");
        clock.set(8_102);
        assert!(matches!(
            store
                .claim_approval(ClaimApproval {
                    conversation_id,
                    turn_id,
                    approval_id,
                    decision: ActionDecision {
                        request_id: request().request_id,
                        decision: ActionDecisionKind::Approve,
                        persist: true,
                    },
                    claimant_binding: claimant
                        .try_enter_approval()
                        .expect("claimant active")
                        .claimant_binding(),
                })
                .await
                .expect("reserved safety lane closes deadline approval"),
            ApprovalMutationOutcome::ExpiredOrStale { approval }
                if approval.state == ApprovalState::Expired && approval.decision.is_none()
        ));
        store.shutdown().await.expect("shutdown approval store");
    }

    #[tokio::test]
    async fn approval_row_aead_metadata_null_state_and_ledger_tampering_are_rejected() {
        for case in ["metadata", "sealed-request", "null-state", "ledger"] {
            let root = TestRoot::new(case);
            let keys = MemoryKeyStore::new();
            let clock = ManualClock::new(9_000);
            let (store, conversation_id, command_id, turn_id) =
                open_started(&root, &keys, &clock).await;
            clock.set(9_001);
            store
                .register_approval(RegisterApproval {
                    conversation_id,
                    command_id,
                    turn_id,
                    request: request(),
                    policy: policy(),
                })
                .await
                .expect("register tamper target");
            store.shutdown().await.expect("shutdown before tamper");

            let connection = rusqlite::Connection::open(root.database()).expect("open tamper DB");
            match case {
                "metadata" => {
                    connection
                        .execute(
                            "UPDATE approval_ledger SET metadata_token = zeroblob(32)",
                            [],
                        )
                        .expect("tamper approval metadata");
                }
                "sealed-request" => {
                    let mut sealed: Vec<u8> = connection
                        .query_row(
                            "SELECT sealed_request FROM approval_ledger LIMIT 1",
                            [],
                            |row| row.get(0),
                        )
                        .expect("load sealed request");
                    let last = sealed.last_mut().expect("sealed request is nonempty");
                    *last ^= 0x80;
                    connection
                        .execute("UPDATE approval_ledger SET sealed_request = ?1", [&sealed])
                        .expect("tamper sealed request");
                }
                "null-state" => {
                    connection
                        .pragma_update(None, "ignore_check_constraints", true)
                        .expect("allow physical NULL-state tamper fixture");
                    connection
                        .execute(
                            "UPDATE approval_ledger
                             SET decision_token = zeroblob(32), claimant_token = zeroblob(32)",
                            [],
                        )
                        .expect("tamper pending NULL-state invariant");
                }
                "ledger" => {
                    connection
                        .execute(
                            "UPDATE runtime_meta SET approval_count = approval_count + 1",
                            [],
                        )
                        .expect("tamper approval ledger count");
                }
                _ => unreachable!(),
            }
            drop(connection);

            let error = RuntimeStoreHandle::open(
                RuntimeStoreConfig::new(root.database()).with_clock(clock.clone()),
                root.storage_kek(&keys),
            )
            .await
            .expect_err("tampered approval store must fail closed");
            assert!(matches!(error, RuntimeStoreError::UnknownOrCorruptSchema));
        }
    }

    #[tokio::test]
    async fn delivery_row_event_deadline_and_active_ledger_tampering_are_rejected_on_reopen() {
        for case in ["attempt", "event", "deadline", "active-ledger"] {
            let root = TestRoot::new(case);
            let keys = MemoryKeyStore::new();
            let clock = ManualClock::new(30_000);
            let (store, conversation_id, command_id, turn_id) =
                open_started(&root, &keys, &clock).await;
            clock.set(30_001);
            let claimed = register_and_claim(&store, conversation_id, command_id, turn_id).await;
            clock.set(30_002);
            let applying = match store
                .begin_approval_attempt(BeginApprovalAttempt {
                    approval_id: claimed.approval_id,
                    delivery_round: 0,
                    expected_attempts_in_round: 0,
                })
                .await
                .expect("begin tamper target")
            {
                BeginApprovalAttemptOutcome::Permitted { approval, .. } => approval,
                other => panic!("expected permit, got {other:?}"),
            };
            clock.set(30_003);
            store
                .mark_approval_applied(MarkApprovalApplied {
                    approval_id: applying.approval_id,
                    delivery_round: 1,
                    attempt: 1,
                })
                .await
                .expect("apply tamper target");
            store.shutdown().await.expect("shutdown before tamper");

            let connection = rusqlite::Connection::open(root.database()).expect("open tamper DB");
            match case {
                "attempt" => {
                    connection
                        .execute("UPDATE approval_ledger SET attempts_in_round = 2", [])
                        .expect("tamper attempt");
                }
                "event" => {
                    connection
                        .execute(
                            "UPDATE event_journal SET metadata_token = zeroblob(32)
                             WHERE event_id = (SELECT last_event_id FROM approval_ledger LIMIT 1)",
                            [],
                        )
                        .expect("tamper transition event");
                }
                "deadline" => {
                    connection
                        .execute(
                            "UPDATE approval_ledger SET deadline_at_ms = deadline_at_ms + 1",
                            [],
                        )
                        .expect("tamper frozen deadline");
                }
                "active-ledger" => {
                    connection
                        .execute(
                            "UPDATE runtime_meta
                             SET active_approval_count = active_approval_count + 1",
                            [],
                        )
                        .expect("tamper active approval ledger");
                }
                _ => unreachable!(),
            }
            drop(connection);
            assert!(matches!(
                RuntimeStoreHandle::open(
                    RuntimeStoreConfig::new(root.database()).with_clock(clock.clone()),
                    root.storage_kek(&keys),
                )
                .await,
                Err(RuntimeStoreError::UnknownOrCorruptSchema)
            ));
        }
    }
}
