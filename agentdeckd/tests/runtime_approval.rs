//! P3.5 approval 可执行 integration gate。
//!
//! approval 的 SQLite mutation、authorization capability 与 supervisor 都是 daemon-private，
//! integration crate 不能绕过可见性直接构造它们。本文件因此只做两类跨边界检查：
//! 1. 对公开 Runtime v1 receipt/request/event 做真实 serde round-trip；
//! 2. 对 production transaction/worker/supervisor/DDL 做有语义的 shape 检查，并要求对应
//!    daemon-private unit/store test 仍在其拥有模块内。
//!
//! 这些检查不是内部行为测试的替代品；它们把批准计划的 16 个固定名字变成单独可执行的
//! gate，同时防止实现只留下同名空测试、把安全事务拆开，或悄悄改变公开 receipt 语义。

use agentdeck_protocol::ActionDecisionKind;
use agentdeck_protocol::runtime::identity::{
    ApprovalId, CommandId, ConversationId, EventId, TurnId,
};
use agentdeck_protocol::runtime::{
    ApprovalDeliveryState, ApprovalReceipt, RuntimeEvent, RuntimeEventBody, RuntimeRequest,
};

const APPROVAL_SOURCE: &str = include_str!("../src/runtime/approval.rs");
const CONNECTION_SOURCE: &str = include_str!("../src/runtime/connection.rs");
const CONVERSATION_SOURCE: &str = include_str!("../src/runtime/conversation.rs");
const CORE_SOURCE: &str = include_str!("../src/runtime/core.rs");
const STORE_APPROVAL_SOURCE: &str = include_str!("../src/runtime/store/approval.rs");
const STORE_JOURNAL_SOURCE: &str = include_str!("../src/runtime/store/journal.rs");
const STORE_SCHEMA_SOURCE: &str = include_str!("../src/runtime/store/schema.rs");
const STORE_SQLITE_SOURCE: &str = include_str!("../src/runtime/store/sqlite.rs");
const STORE_WORKER_SOURCE: &str = include_str!("../src/runtime/store/worker.rs");

fn assert_contract(label: &str, source: &str, required: &[&str]) {
    for needle in required {
        assert!(
            source.contains(needle),
            "{label} 缺少安全契约片段 `{needle}`"
        );
    }
}

fn assert_ordered(label: &str, source: &str, required: &[&str]) {
    let mut cursor = 0;
    for needle in required {
        let relative = source[cursor..]
            .find(needle)
            .unwrap_or_else(|| panic!("{label} 缺少有序契约片段 `{needle}`"));
        cursor += relative + needle.len();
    }
}

fn section<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    let start_offset = source
        .find(start)
        .unwrap_or_else(|| panic!("缺少 section 起点 `{start}`"));
    let after_start = &source[start_offset..];
    let end_offset = after_start
        .find(end)
        .unwrap_or_else(|| panic!("缺少 section 终点 `{end}`"));
    &after_start[..end_offset]
}

fn wire_approval_id() -> ApprovalId {
    ApprovalId::new("approval-gate-0001")
}

fn assert_already_handled_wire(state: ApprovalDeliveryState) {
    let receipt = ApprovalReceipt::AlreadyHandled {
        approval_id: wire_approval_id(),
        decision: ActionDecisionKind::Approve,
        state,
    };
    let bytes = serde_json::to_vec(&receipt).expect("serialize approval receipt");
    let decoded: ApprovalReceipt =
        serde_json::from_slice(&bytes).expect("deserialize approval receipt");
    assert!(matches!(
        decoded,
        ApprovalReceipt::AlreadyHandled {
            approval_id,
            decision: ActionDecisionKind::Approve,
            state: decoded_state,
        } if approval_id == wire_approval_id() && decoded_state == state
    ));
}

#[test]
fn pending_registration_is_atomic_with_action_request_event() {
    let register = section(
        STORE_APPROVAL_SOURCE,
        "pub(crate) fn register_approval(",
        "pub(crate) fn claim_approval(",
    );
    assert_ordered(
        "Pending 注册事务",
        register,
        &[
            "transaction_with_behavior(TransactionBehavior::Immediate)",
            "INSERT INTO event_journal",
            "INSERT INTO approval_ledger",
            "update_conversation_event_high_water(",
            "next_ledger.event_count",
            "next_ledger.approval_count",
            "next_ledger.active_approval_count",
            "RuntimeStoreOperation::RegisterApprovalBeforeCommit",
            "sqlite::commit_transaction(transaction, RuntimeCommitOperation::RegisterApproval)",
        ],
    );
    assert_contract(
        "Pending 注册内部 store tests",
        STORE_APPROVAL_SOURCE,
        &[
            "async fn pending_registration_is_atomic_with_action_request_event()",
            "RuntimeStoreOperation::RegisterApprovalBeforeCommit",
            "register_before_commit_rolls_back_and_after_commit_exact_retry_replays",
        ],
    );
}

#[test]
fn principal_without_approval_permission_cannot_claim() {
    let resolve = section(
        CORE_SOURCE,
        "RuntimeRequest::ResolveApproval {",
        "RuntimeRequest::RetryApproval {",
    );
    assert_ordered(
        "resolve authorization",
        resolve,
        &[
            "principal.try_enter_approval()?",
            "authorization.require_resolve()?",
            ".resolve_approval(",
        ],
    );
    assert_contract(
        "approval permission capability",
        CONNECTION_SOURCE,
        &[
            "pub(crate) struct ApprovalAuthorizationGuard",
            "_authorization: AuthorizationGuard",
            "Err(PrincipalAccessError::PermissionDenied)",
            "fn approval_permissions_are_explicit_and_fail_closed_per_operation()",
        ],
    );
    assert_contract(
        "permission integration owner test",
        CORE_SOURCE,
        &[
            "async fn principal_without_approval_permission_cannot_claim()",
            "DAEMON_AUTHORIZATION_PERMISSION_DENIED",
        ],
    );
}

#[test]
fn resolve_requires_exact_conversation_turn_approval_and_request_id() {
    let claim = section(
        STORE_APPROVAL_SOURCE,
        "pub(crate) fn claim_approval(",
        "pub(crate) fn begin_approval_attempt(",
    );
    assert_contract(
        "claim exact target",
        claim,
        &[
            "ensure_kind(input.conversation_id, RuntimeIdKind::Conversation)",
            "ensure_kind(input.turn_id, RuntimeIdKind::Turn)",
            "ensure_kind(input.approval_id, RuntimeIdKind::Approval)",
            "preflight.conversation_id != input.conversation_id",
            "preflight.turn_id != input.turn_id",
            ".validate_decision(&preflight.request, &input.decision)",
            "is_exact_started_turn(",
            "WHERE approval_id = ?9 AND state = 'pending' AND metadata_token = ?10",
        ],
    );
    assert_contract(
        "claim exact target internal test",
        STORE_APPROVAL_SOURCE,
        &["async fn claim_requires_exact_ids_request_and_frozen_policy()"],
    );
    assert_contract(
        "request id policy binding",
        APPROVAL_SOURCE,
        &[
            "if decision.request_id != request.request_id",
            "ApprovalPolicyError::RequestIdMismatch",
        ],
    );
}

#[test]
fn decision_must_match_bound_action_capability() {
    let policy = section(
        APPROVAL_SOURCE,
        "impl ApprovalPolicySnapshot {",
        "pub(crate) fn approval_delivery_delay_before_attempt(",
    );
    assert_contract(
        "bound approval policy",
        policy,
        &[
            "CapabilityId::Approval",
            "ApprovalPolicyError::ApprovalCapabilityMissing",
            "capabilities.agent_kind != request_agent",
            "request.kind != self.action_kind",
            "ActionDecisionKind::Approve if !self.allow_approve",
            "ActionDecisionKind::Deny if !self.allow_deny",
            "if decision.persist",
            "CapabilityId::CodexApprovalPersistence",
            "can_persist: true",
        ],
    );
    assert_contract(
        "bound decision internal tests",
        APPROVAL_SOURCE,
        &[
            "fn decision_must_match_the_exact_bound_request_and_frozen_policy()",
            "fn policy_is_minted_only_from_the_bound_session_capabilities()",
        ],
    );
}

#[test]
fn one_of_100_concurrent_resolves_wins_sqlite_cas() {
    let claim = section(
        STORE_APPROVAL_SOURCE,
        "pub(crate) fn claim_approval(",
        "pub(crate) fn begin_approval_attempt(",
    );
    assert_ordered(
        "first-wins SQLite CAS",
        claim,
        &[
            "transaction_with_behavior(TransactionBehavior::Immediate)",
            "load_authenticated_approval_target(",
            "UPDATE approval_ledger",
            "WHERE approval_id = ?9 AND state = 'pending' AND metadata_token = ?10",
            "if updated != 1",
            "RuntimeStoreOperation::ClaimApprovalBeforeCommit",
            "sqlite::commit_transaction(transaction, RuntimeCommitOperation::ClaimApproval)",
        ],
    );
    assert_contract(
        "100-way store race",
        STORE_APPROVAL_SOURCE,
        &[
            "async fn one_of_100_concurrent_claims_wins_and_every_loser_observes_that_winner()",
            "for index in 0_u8..100",
            "let barrier = Arc::new(tokio::sync::Barrier::new(101))",
        ],
    );
}

#[test]
fn claim_after_commit_unknown_replays_and_starts_one_worker() {
    let claim = section(
        STORE_APPROVAL_SOURCE,
        "pub(crate) fn claim_approval(",
        "pub(crate) fn begin_approval_attempt(",
    );
    assert_contract(
        "claim COMMIT unknown replay",
        claim,
        &[
            "RuntimeStoreOperation::ClaimApprovalAfterCommit",
            "RuntimeCommitOperation::ClaimApproval",
            "physical.decision_token.as_deref() == Some(decision_token.as_bytes())",
            "physical.claimant_token.as_deref() == Some(claimant_token.as_bytes())",
            "ApprovalMutationOutcome::Replayed",
            "ApprovalMutationOutcome::AlreadyHandled",
        ],
    );
    let start_delivery = section(
        CONVERSATION_SOURCE,
        "fn start_approval_delivery(",
        "async fn finish_approval_task(",
    );
    assert_contract(
        "conversation-owned delivery single-flight",
        start_delivery,
        &[
            ".approval_deliveries",
            "if route.delivery_task.is_some()",
            "return Ok(())",
            "route.delivery_task = Some(spawn_approval_task(",
        ],
    );
    assert_contract(
        "claim fault owner test",
        STORE_APPROVAL_SOURCE,
        &[
            "RuntimeStoreOperation::ClaimApprovalAfterCommit",
            "claim_before_commit_rolls_back_and_after_commit_exact_retry_replays",
        ],
    );
}

#[test]
fn delivery_transitions_claimed_applying_applied_and_survives_disconnect() {
    let worker = section(
        APPROVAL_SOURCE,
        "pub(crate) async fn run_approval_delivery_round(",
        "pub(crate) async fn run_approval_deadline(",
    );
    assert_ordered(
        "delivery state closure",
        worker,
        &[
            "ApprovalState::Claimed | ApprovalState::Applying",
            "begin_attempt_store_only(",
            "ApprovalState::Applying",
            "let delivery_for_attempt = delivery.clone()",
            ".deliver(key, &decision_for_attempt)",
            "ApprovalDeliveryOutcome::AppliedAck",
            "mark_applied_store_only(",
        ],
    );
    let control = section(
        CONVERSATION_SOURCE,
        "async fn handle_control(",
        "fn enter_recovery_blocked(",
    );
    assert_ordered(
        "client-independent worker ownership",
        control,
        &[
            "resolve_approval_control(input, &_authorization_guard)",
            "drop(_authorization_guard)",
            "reply.send(outcome)",
        ],
    );
    assert_contract(
        "daemon-owned supervisor",
        CONVERSATION_SOURCE,
        &[
            "approval_deliveries: HashMap<RuntimeId, ApprovalRoute>",
            "Adapter delivery is never awaited in this handler",
            "the spawned daemon worker is independent of the client/connection afterwards",
            "async fn delivery_transitions_to_applied_after_resolver_capability_is_dropped()",
        ],
    );
    assert_already_handled_wire(ApprovalDeliveryState::Applied);
}

#[test]
fn delivery_budget_is_eight_attempts_and_never_exceeds_sixty_seconds() {
    assert_contract(
        "delivery budget constants",
        APPROVAL_SOURCE,
        &[
            "APPROVAL_DELIVERY_ATTEMPTS_PER_ROUND: u8 = 8",
            "APPROVAL_DELIVERY_ROUND_BUDGET: Duration = Duration::from_secs(60)",
            "Duration::from_millis(500)",
            "Duration::from_secs(16)",
            "async fn delivery_budget_is_eight_attempts_and_never_exceeds_sixty_seconds()",
        ],
    );
    let worker = section(
        APPROVAL_SOURCE,
        "pub(crate) async fn run_approval_delivery_round(",
        "pub(crate) async fn run_approval_deadline(",
    );
    assert_contract(
        "delivery budget enforcement",
        worker,
        &[
            "while approval.attempts_in_round < APPROVAL_DELIVERY_ATTEMPTS_PER_ROUND",
            "round_started_at_ms.checked_add(",
            "APPROVAL_DELIVERY_ROUND_BUDGET.as_millis()",
            "if next_attempt_at_ms > round_budget_end_ms",
            "if observed_ms > round_budget_end_ms",
            "if attempt < APPROVAL_DELIVERY_ATTEMPTS_PER_ROUND",
        ],
    );
}

#[test]
fn delivery_failed_retains_winner_and_exact_receipt() {
    assert_already_handled_wire(ApprovalDeliveryState::DeliveryFailed);
    let receipt = section(
        CONVERSATION_SOURCE,
        "fn receipt_for_exact_winner(",
        "fn wire_approval_delivery_state(",
    );
    assert_contract(
        "exact loser receipt",
        receipt,
        &[
            "ApprovalState::DeliveryFailed if exact_replay",
            ".decision",
            "ApprovalReceipt::AlreadyHandled",
            "state: wire_approval_delivery_state(state)?",
        ],
    );
    assert_contract(
        "durable immutable winner",
        STORE_APPROVAL_SOURCE,
        &[
            "async fn failed_retry_reuses_sealed_winner_and_starts_fresh_round()",
            "ApprovalMutationOutcome::AlreadyHandled { approval }",
        ],
    );
}

#[test]
fn retry_delivery_reuses_exact_sealed_decision_and_new_budget() {
    let retry = RuntimeRequest::RetryApproval {
        conversation_id: ConversationId::new("conversation-gate-0001"),
        approval_id: wire_approval_id(),
    };
    let wire = serde_json::to_string(&retry).expect("serialize RetryApproval");
    assert!(wire.contains("retryApproval"));
    assert!(wire.contains("conversation-gate-0001"));
    assert!(wire.contains("approval-gate-0001"));
    assert!(!wire.contains("decision"));
    assert!(!wire.contains("requestId"));
    assert!(!wire.contains("persist"));

    let retry_store = section(
        STORE_APPROVAL_SOURCE,
        "pub(crate) fn retry_approval_delivery(",
        "pub(crate) fn expire_approval(",
    );
    assert_contract(
        "same-decision manual retry",
        retry_store,
        &[
            "ApprovalState::DeliveryFailed",
            "let next_round = approval",
            ".delivery_round",
            ".checked_add(1)",
            "attempts_in_round: 0",
            "load_authenticated_approval_target(",
            "load_approval_physical(",
            "commit_approval_transition(",
        ],
    );
    assert!(
        !retry_store.contains("input.decision"),
        "RetryApproval store input must not accept a replacement decision"
    );
    assert_contract(
        "same-decision retry owner test",
        STORE_APPROVAL_SOURCE,
        &["async fn failed_retry_reuses_sealed_winner_and_starts_fresh_round()"],
    );
}

#[test]
fn default_deadline_is_request_time_plus_thirty_minutes() {
    assert_contract(
        "default deadline",
        APPROVAL_SOURCE,
        &[
            "DEFAULT_APPROVAL_DEADLINE_MS: u64 = 30 * 60 * 1_000",
            "created_at_ms",
            ".checked_add(DEFAULT_APPROVAL_DEADLINE_MS)",
            "fn default_deadline_is_exactly_thirty_minutes_and_explicit_deadline_wins()",
        ],
    );
    assert_contract(
        "deadline terminal event",
        STORE_APPROVAL_SOURCE,
        &[
            "async fn explicit_expiry_preserves_claimed_winner_but_pending_expiry_has_none()",
            "async fn claim_at_deadline_atomically_persists_pending_as_expired()",
            "ApprovalState::Expired",
        ],
    );

    let event = RuntimeEvent {
        conversation_id: ConversationId::new("conversation-gate-0001"),
        event_id: EventId::new("event-gate-expired"),
        event_seq: 7,
        command_id: Some(CommandId::new("command-gate-expired")),
        item_id: None,
        entity_id: None,
        body: RuntimeEventBody::ApprovalResolved {
            turn_id: TurnId::new("turn-gate-0001"),
            approval_id: wire_approval_id(),
            decision: None,
            state: ApprovalDeliveryState::Expired,
        },
    };
    let encoded = serde_json::to_vec(&event).expect("serialize pending expiry event");
    let decoded: RuntimeEvent =
        serde_json::from_slice(&encoded).expect("deserialize pending expiry event");
    assert!(matches!(
        decoded.body,
        RuntimeEventBody::ApprovalResolved {
            decision: None,
            state: ApprovalDeliveryState::Expired,
            ..
        }
    ));
}

#[test]
fn capability_deadline_overrides_default_and_stops_backoff() {
    let worker = section(
        APPROVAL_SOURCE,
        "pub(crate) async fn run_approval_delivery_round(",
        "pub(crate) async fn run_approval_deadline(",
    );
    assert_contract(
        "capability deadline gate",
        APPROVAL_SOURCE,
        &[
            "deadline_at_ms: Option<u64>",
            "Some(deadline_at_ms) => deadline_at_ms",
            "explicit.deadline_at_ms = Some(created_at_ms + 7_000)",
        ],
    );
    assert_ordered(
        "deadline before backoff attempt",
        worker,
        &[
            "let next_attempt_at_ms",
            "if next_attempt_at_ms >= approval.deadline_at_ms",
            "sleeper.sleep(remaining).await",
            "expire_store_only(",
            "if !delay.is_zero()",
            "sleeper.sleep(delay).await",
            "if observed_ms >= approval.deadline_at_ms",
            "begin_attempt_store_only(",
        ],
    );
}

#[test]
fn turn_terminal_expires_every_non_applied_approval_atomically() {
    // 这是 P3.5 最关键的 crash-gap gate：不能由 actor 先后调用多个 expiry mutation。
    // CompleteCommand 的单个 Safety transaction 必须同时：筛出所有非 Applied approval、
    // 写 canonical Expired events、递减 active ledger count，再提交 command terminal。
    let completion = section(
        STORE_JOURNAL_SOURCE,
        "pub(crate) fn complete_command_with_event(",
        "pub(crate) fn terminate_started_before_release(",
    );
    assert_ordered(
        "CompleteCommand terminal + approval expiry single transaction",
        completion,
        &[
            "transaction_with_behavior(TransactionBehavior::Immediate)",
            "approval::expire_active_approvals_for_terminal(",
            "INSERT INTO event_journal",
            "next_ledger.active_approval_count",
            "RuntimeStoreOperation::CompleteCommandBeforeCommit",
            "commit_transaction(transaction, RuntimeCommitOperation::CompleteCommand)",
        ],
    );
    let terminate = section(
        STORE_JOURNAL_SOURCE,
        "pub(crate) fn terminate_started_before_release(",
        "pub(crate) fn terminate_accepted_command(",
    );
    assert_ordered(
        "TerminateStartedBeforeRelease terminal + approval expiry single transaction",
        terminate,
        &[
            "transaction_with_behavior(TransactionBehavior::Immediate)",
            "approval::expire_active_approvals_for_terminal(",
            "INSERT INTO event_journal",
            "next_ledger.active_approval_count",
            "RuntimeStoreOperation::TerminateStartedBeforeReleaseBeforeCommit",
            "RuntimeCommitOperation::TerminateStartedBeforeRelease",
        ],
    );

    let terminal_expiry = section(
        STORE_APPROVAL_SOURCE,
        "pub(super) fn expire_active_approvals_for_terminal(",
        "fn commit_approval_transition(",
    );
    assert_ordered(
        "bounded deterministic approval terminal expiry helper",
        terminal_expiry,
        &[
            "active_approval_ids_for_turn(",
            "load_approval(",
            "validate_approval_record_linkage(",
            "ApprovalState::Expired",
            "apply_approval_transition_in_transaction(",
            "final_event_high_water = Some(event_seq.encoded)",
            "expiry_event_count",
            "active_approval_decrement: expiry_event_count",
            "FROM approval_ledger INDEXED BY idx_approval_active_turn",
            "state IN ('pending', 'claimed', 'applying', 'deliveryFailed')",
            "ORDER BY approval_id ASC",
            "MAX_ACTIVE_APPROVALS_PER_TURN",
        ],
    );
    let transition_primitive = section(
        STORE_APPROVAL_SOURCE,
        "fn apply_approval_transition_in_transaction(",
        "fn finish_approval_commit(",
    );
    assert_ordered(
        "uncommitted canonical approval transition primitive",
        transition_primitive,
        &[
            "canonical_resolved_event(",
            "INSERT INTO event_journal",
            "UPDATE approval_ledger",
        ],
    );
    assert_contract(
        "terminal replay fail-closed and internal owner tests",
        STORE_APPROVAL_SOURCE,
        &[
            "pub(super) fn ensure_terminal_turn_has_no_active_approvals(",
            "async fn turn_terminal_expires_every_non_applied_approval_atomically()",
            "async fn terminal_expiry_before_and_after_commit_converges_without_crash_gap()",
            "async fn terminal_replay_fails_closed_if_an_authenticated_active_approval_reappears()",
            "async fn terminal_expiry_consumes_the_pre_reserved_safety_lane()",
        ],
    );
    assert_contract(
        "terminal mutation is Safety-lane owned",
        STORE_WORKER_SOURCE,
        &[
            "SafetyCommand::CompleteCommand",
            "journal::complete_command_with_event(state, config, input)",
            "SafetyCommand::TerminateStartedBeforeRelease",
            "journal::terminate_started_before_release(",
        ],
    );
}

#[test]
fn applied_commit_unknown_retries_store_only() {
    let closure = section(
        APPROVAL_SOURCE,
        "async fn mark_applied_store_only(",
        "async fn mark_delivery_failed_store_only(",
    );
    assert_contract(
        "Applied store-only closure",
        closure,
        &[
            ".mark_applied(MarkApprovalApplied",
            "RuntimeCommitOperation::MarkApprovalApplied",
            "tokio::task::yield_now().await",
            "is_retryable_safety_closure_error",
            "ApprovalWorkerResult::Applied",
        ],
    );
    assert_contract(
        "Applied no-redelivery unit test",
        APPROVAL_SOURCE,
        &["async fn applied_ack_retries_transient_store_closure_without_redelivery()"],
    );
    assert_contract(
        "Applied AfterCommit fault",
        STORE_APPROVAL_SOURCE,
        &[
            "RuntimeStoreOperation::MarkApprovalAppliedAfterCommit",
            "RuntimeCommitOperation::MarkApprovalApplied",
        ],
    );
}

#[test]
fn restart_never_resumes_active_approval_delivery() {
    let recovery = section(
        CORE_SOURCE,
        "async fn recover_inner(",
        "pub async fn disconnect(",
    );
    assert_ordered(
        "started recovery fail-closed",
        recovery,
        &[
            "if recovery.started.is_some()",
            "return Err(RuntimeCoreError::RecoveryBlocked)",
            ".install(recovery.conversation, recovery.accepted)",
        ],
    );
    let blocked = section(
        CONVERSATION_SOURCE,
        "async fn enter_recovery_blocked_and_stop_approvals(",
        "async fn begin_shutdown(",
    );
    assert_contract(
        "recovery blocks active delivery",
        blocked,
        &[
            "self.enter_recovery_blocked()",
            "finish_approval_turn(turn_id).await",
            "停止所有 adapter delivery",
        ],
    );
    assert!(!recovery.contains("run_approval_delivery_round"));
    assert!(!recovery.contains("start_approval_delivery"));
}

#[test]
fn approval_row_and_ledger_tampering_is_rejected() {
    assert_contract(
        "approval DDL authenticated fields",
        STORE_SCHEMA_SOURCE,
        &[
            "approval_count INTEGER NOT NULL DEFAULT 0",
            "active_approval_count INTEGER NOT NULL DEFAULT 0",
            "CREATE TABLE approval_ledger",
            "decision_token BLOB",
            "metadata_token BLOB NOT NULL",
            "CHECK(typeof(metadata_token) = 'blob' AND length(metadata_token) = 32)",
            "CHECK(attempts_in_round BETWEEN 0 AND 8)",
        ],
    );
    assert_contract(
        "approval metadata validator",
        STORE_APPROVAL_SOURCE,
        &[
            "pub(super) fn validate_all_approval_metadata(",
            "approval_metadata_token(",
            "if raw.19.as_slice() != expected_metadata",
            "RuntimeStoreError::UnknownOrCorruptSchema",
            "async fn approval_row_aead_metadata_null_state_and_ledger_tampering_are_rejected()",
        ],
    );
    assert_contract(
        "v3 ledger MAC",
        STORE_SQLITE_SOURCE,
        &[
            "runtime.meta.ledger.v3",
            "message.extend_from_slice(&ledger.approval_count.to_be_bytes())",
            "message.extend_from_slice(&ledger.active_approval_count.to_be_bytes())",
        ],
    );
    assert_contract(
        "global integrity ties rows to ledger",
        STORE_JOURNAL_SOURCE,
        &[
            "ledger.approval_count != approvals.approval_count",
            "ledger.active_approval_count != approvals.active_approval_count",
            "RuntimeStoreError::UnknownOrCorruptSchema",
        ],
    );
}
