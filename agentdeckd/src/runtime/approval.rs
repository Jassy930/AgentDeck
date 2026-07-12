#![allow(dead_code)] // P3.5 common policy/delivery 基座，后续 store/actor 子任务接线。

use std::time::Duration;

use std::sync::Arc;
use tokio::task::{JoinError, JoinHandle};

use agentdeck_protocol::{
    ActionDecision, ActionDecisionKind, ActionKind, ActionRequest, ActionRequestVendor, AgentKind,
    CapabilityId, SessionCapabilities,
};
use serde::{Deserialize, Serialize};

use super::model::{
    ApprovalMutationOutcome, ApprovalRecord, ApprovalState, BeginApprovalAttempt,
    BeginApprovalAttemptOutcome, ExpireApproval, MarkApprovalApplied, MarkApprovalDeliveryFailed,
    RuntimeClock, RuntimeCommitOperation, RuntimeStoreError,
};

#[allow(unused_imports)]
// P3.5 Core/store 子任务通过 approval common 层消费这些 capabilities。
pub(crate) use super::connection::{
    ApprovalAuthorizationGuard, ApprovalClaimantBinding, ApprovalPermissionGrant,
    ApprovalPrincipalCapability,
};

pub(crate) const DEFAULT_APPROVAL_DEADLINE_MS: u64 = 30 * 60 * 1_000;
pub(crate) const APPROVAL_DELIVERY_ATTEMPTS_PER_ROUND: u8 = 8;
pub(crate) const APPROVAL_DELIVERY_ROUND_BUDGET: Duration = Duration::from_secs(60);
pub(crate) const APPROVAL_DELIVERY_BACKOFF: [Duration; 7] = [
    Duration::from_millis(500),
    Duration::from_secs(1),
    Duration::from_secs(2),
    Duration::from_secs(4),
    Duration::from_secs(8),
    Duration::from_secs(16),
    Duration::from_secs(16),
];

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub(crate) struct ApprovalAttemptKey {
    pub(crate) approval_id: super::store::RuntimeId,
    pub(crate) delivery_round: u32,
    pub(crate) attempt: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ApprovalDeliveryOutcome {
    AppliedAck,
    DefinitelyNotDelivered { retryable: bool },
    OutcomeUnknown,
    PermanentlyRejected,
}

#[async_trait::async_trait]
pub(crate) trait BoundApprovalDelivery: Send + Sync + 'static {
    fn policy(&self) -> &ApprovalPolicySnapshot;

    /// 只在精确 adapter route 的完整 response write/newline/flush 已确认后返回
    /// `AppliedAck`。不明确结果必须返回 `OutcomeUnknown`，禁止自动重投。
    async fn deliver(
        &self,
        key: ApprovalAttemptKey,
        decision: &ActionDecision,
    ) -> ApprovalDeliveryOutcome;
}

pub(crate) type SharedApprovalDelivery = Arc<dyn BoundApprovalDelivery>;

#[async_trait::async_trait]
pub(crate) trait ApprovalSleeper: Send + Sync + 'static {
    async fn sleep(&self, duration: Duration);
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct TokioApprovalSleeper;

#[async_trait::async_trait]
impl ApprovalSleeper for TokioApprovalSleeper {
    async fn sleep(&self, duration: Duration) {
        tokio::time::sleep(duration).await;
    }
}

pub(crate) trait ApprovalBackoff: Send + Sync + 'static {
    fn delay_before_attempt(&self, attempt: u8) -> Option<Duration>;
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct FixedApprovalBackoff;

impl ApprovalBackoff for FixedApprovalBackoff {
    fn delay_before_attempt(&self, attempt: u8) -> Option<Duration> {
        approval_delivery_delay_before_attempt(attempt)
    }
}

/// Delivery worker 所需的最小 durable journal capability。RuntimeStoreHandle 的正式实现
/// 由 B3 transition API 接线；测试 fake 只实现这一窄接口，不得绕过实际 adapter capability。
#[async_trait::async_trait]
pub(crate) trait ApprovalDeliveryJournal: Send + Sync + 'static {
    async fn begin_attempt(
        &self,
        input: BeginApprovalAttempt,
    ) -> Result<ApprovalRecord, RuntimeStoreError>;

    async fn mark_applied(
        &self,
        input: MarkApprovalApplied,
    ) -> Result<ApprovalRecord, RuntimeStoreError>;

    async fn mark_delivery_failed(
        &self,
        input: MarkApprovalDeliveryFailed,
    ) -> Result<ApprovalRecord, RuntimeStoreError>;

    async fn expire(&self, input: ExpireApproval) -> Result<ApprovalRecord, RuntimeStoreError>;
}

#[async_trait::async_trait]
impl ApprovalDeliveryJournal for super::store::RuntimeStoreHandle {
    async fn begin_attempt(
        &self,
        input: BeginApprovalAttempt,
    ) -> Result<ApprovalRecord, RuntimeStoreError> {
        match super::store::RuntimeStoreHandle::begin_approval_attempt(self, input).await? {
            BeginApprovalAttemptOutcome::Permitted { approval, .. }
            | BeginApprovalAttemptOutcome::AlreadyHandled { approval }
            | BeginApprovalAttemptOutcome::ExpiredOrStale { approval } => Ok(approval),
        }
    }

    async fn mark_applied(
        &self,
        input: MarkApprovalApplied,
    ) -> Result<ApprovalRecord, RuntimeStoreError> {
        approval_record_from_mutation(
            super::store::RuntimeStoreHandle::mark_approval_applied(self, input).await?,
        )
    }

    async fn mark_delivery_failed(
        &self,
        input: MarkApprovalDeliveryFailed,
    ) -> Result<ApprovalRecord, RuntimeStoreError> {
        approval_record_from_mutation(
            super::store::RuntimeStoreHandle::mark_approval_delivery_failed(self, input).await?,
        )
    }

    async fn expire(&self, input: ExpireApproval) -> Result<ApprovalRecord, RuntimeStoreError> {
        approval_record_from_mutation(
            super::store::RuntimeStoreHandle::expire_approval(self, input).await?,
        )
    }
}

fn approval_record_from_mutation(
    outcome: ApprovalMutationOutcome,
) -> Result<ApprovalRecord, RuntimeStoreError> {
    Ok(match outcome {
        ApprovalMutationOutcome::Transitioned { approval, .. }
        | ApprovalMutationOutcome::Replayed { approval, .. }
        | ApprovalMutationOutcome::AlreadyHandled { approval }
        | ApprovalMutationOutcome::ExpiredOrStale { approval } => approval,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ApprovalWorkerResult {
    Applied,
    DeliveryFailed,
    Expired,
    StoreBlocked,
    /// Adapter 已经返回 AppliedAck、OutcomeUnknown 或其他不可自动重投结果，但
    /// durable closure 遇到不可安全重试的错误。actor 必须进入 RecoveryBlocked，
    /// 不能把仍为 Applying 的 row 当成一张可重新投递的 route。
    FatalClosure,
}

struct AbortOnDropApprovalTask<T> {
    task: JoinHandle<T>,
}

impl<T> AbortOnDropApprovalTask<T> {
    fn new(task: JoinHandle<T>) -> Self {
        Self { task }
    }

    fn abort(&self) {
        self.task.abort();
    }

    async fn join(&mut self) -> Result<T, JoinError> {
        (&mut self.task).await
    }
}

impl<T> Drop for AbortOnDropApprovalTask<T> {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub(crate) async fn run_approval_delivery_round(
    journal: Arc<dyn ApprovalDeliveryJournal>,
    delivery: SharedApprovalDelivery,
    mut approval: ApprovalRecord,
    clock: Arc<dyn RuntimeClock>,
    sleeper: Arc<dyn ApprovalSleeper>,
    backoff: Arc<dyn ApprovalBackoff>,
) -> ApprovalWorkerResult {
    if delivery.policy() != &approval.policy
        || delivery
            .policy()
            .validate_request(&approval.request)
            .is_err()
    {
        return ApprovalWorkerResult::StoreBlocked;
    }
    let Some(decision) = approval.decision.clone() else {
        return ApprovalWorkerResult::StoreBlocked;
    };
    if approval
        .policy
        .validate_decision(&approval.request, &decision)
        .is_err()
    {
        return ApprovalWorkerResult::StoreBlocked;
    }
    match approval.state {
        ApprovalState::Claimed | ApprovalState::Applying => {}
        ApprovalState::Applied => return ApprovalWorkerResult::Applied,
        ApprovalState::DeliveryFailed => return ApprovalWorkerResult::DeliveryFailed,
        ApprovalState::Expired => return ApprovalWorkerResult::Expired,
        ApprovalState::Pending => return ApprovalWorkerResult::StoreBlocked,
    }

    while approval.attempts_in_round < APPROVAL_DELIVERY_ATTEMPTS_PER_ROUND {
        let now_ms = match clock.now_ms() {
            Ok(now_ms) => now_ms,
            Err(_) => return ApprovalWorkerResult::StoreBlocked,
        };
        if now_ms >= approval.deadline_at_ms {
            return expire_store_only(journal.as_ref(), &approval, sleeper.as_ref()).await;
        }
        let delay = match backoff.delay_before_attempt(approval.attempts_in_round) {
            Some(delay) => delay,
            None => {
                return mark_delivery_failed_store_only(
                    journal.as_ref(),
                    &approval,
                    b"budget-exhausted",
                    sleeper.as_ref(),
                )
                .await;
            }
        };
        let delay_ms = match u64::try_from(delay.as_millis()) {
            Ok(delay_ms) => delay_ms,
            Err(_) => return ApprovalWorkerResult::StoreBlocked,
        };
        let round_started_at_ms = approval.round_started_at_ms.unwrap_or(now_ms);
        let round_budget_end_ms = match round_started_at_ms.checked_add(
            u64::try_from(APPROVAL_DELIVERY_ROUND_BUDGET.as_millis())
                .expect("fixed approval budget fits u64"),
        ) {
            Some(end) => end,
            None => return ApprovalWorkerResult::StoreBlocked,
        };
        let next_attempt_at_ms = match now_ms.checked_add(delay_ms) {
            Some(next) => next,
            None => return ApprovalWorkerResult::StoreBlocked,
        };
        if next_attempt_at_ms > round_budget_end_ms {
            return mark_delivery_failed_store_only(
                journal.as_ref(),
                &approval,
                b"round-budget-exhausted",
                sleeper.as_ref(),
            )
            .await;
        }
        if next_attempt_at_ms >= approval.deadline_at_ms {
            let remaining = Duration::from_millis(approval.deadline_at_ms - now_ms);
            sleeper.sleep(remaining).await;
            return expire_store_only(journal.as_ref(), &approval, sleeper.as_ref()).await;
        }
        if !delay.is_zero() {
            sleeper.sleep(delay).await;
        }
        let observed_ms = match clock.now_ms() {
            Ok(now_ms) => now_ms,
            Err(_) => return ApprovalWorkerResult::StoreBlocked,
        };
        if observed_ms >= approval.deadline_at_ms {
            return expire_store_only(journal.as_ref(), &approval, sleeper.as_ref()).await;
        }
        if observed_ms > round_budget_end_ms {
            return mark_delivery_failed_store_only(
                journal.as_ref(),
                &approval,
                b"round-budget-exhausted",
                sleeper.as_ref(),
            )
            .await;
        }

        let expected_attempts = approval.attempts_in_round;
        approval = match begin_attempt_store_only(
            journal.as_ref(),
            approval.approval_id,
            approval.delivery_round,
            expected_attempts,
        )
        .await
        {
            Ok(record) => record,
            Err(()) => return ApprovalWorkerResult::StoreBlocked,
        };
        match approval.state {
            ApprovalState::Applying
                if approval.attempts_in_round == expected_attempts.saturating_add(1) => {}
            ApprovalState::Applied => return ApprovalWorkerResult::Applied,
            ApprovalState::DeliveryFailed => return ApprovalWorkerResult::DeliveryFailed,
            ApprovalState::Expired => return ApprovalWorkerResult::Expired,
            _ => return ApprovalWorkerResult::StoreBlocked,
        }
        let delivery_started_at_ms = match clock.now_ms() {
            Ok(now_ms) => now_ms,
            Err(_) => return ApprovalWorkerResult::StoreBlocked,
        };
        if delivery_started_at_ms >= approval.deadline_at_ms {
            return expire_store_only(journal.as_ref(), &approval, sleeper.as_ref()).await;
        }
        let Some(persisted_round_started_at_ms) = approval.round_started_at_ms else {
            return ApprovalWorkerResult::StoreBlocked;
        };
        let persisted_round_budget_end_ms = match persisted_round_started_at_ms.checked_add(
            u64::try_from(APPROVAL_DELIVERY_ROUND_BUDGET.as_millis())
                .expect("fixed approval budget fits u64"),
        ) {
            Some(end) => end,
            None => return ApprovalWorkerResult::StoreBlocked,
        };
        if delivery_started_at_ms >= persisted_round_budget_end_ms {
            return mark_delivery_failed_store_only(
                journal.as_ref(),
                &approval,
                b"round-budget-exhausted",
                sleeper.as_ref(),
            )
            .await;
        }
        if approval
            .last_attempt_at_ms
            .is_some_and(|last_attempt_at_ms| delivery_started_at_ms < last_attempt_at_ms)
        {
            return ApprovalWorkerResult::StoreBlocked;
        }
        let attempt = approval.attempts_in_round;
        let key = ApprovalAttemptKey {
            approval_id: approval.approval_id,
            delivery_round: approval.delivery_round,
            attempt,
        };
        let delivery_timeout_ms = approval
            .deadline_at_ms
            .min(persisted_round_budget_end_ms)
            .saturating_sub(delivery_started_at_ms);
        if delivery_timeout_ms == 0 {
            if delivery_started_at_ms >= approval.deadline_at_ms {
                return expire_store_only(journal.as_ref(), &approval, sleeper.as_ref()).await;
            }
            return mark_delivery_failed_store_only(
                journal.as_ref(),
                &approval,
                b"round-budget-exhausted",
                sleeper.as_ref(),
            )
            .await;
        }
        let delivery_for_attempt = delivery.clone();
        let decision_for_attempt = decision.clone();
        let mut delivery_task = AbortOnDropApprovalTask::new(tokio::spawn(async move {
            delivery_for_attempt
                .deliver(key, &decision_for_attempt)
                .await
        }));
        // Give the isolated adapter future one scheduling point so an injected/manual timeout
        // cannot win before the attempt has actually entered the bound route.
        tokio::task::yield_now().await;
        let invocation = tokio::select! {
            biased;
            outcome = delivery_task.join() => match outcome {
                Ok(outcome) => DeliveryInvocation::Outcome(outcome),
                Err(_) => DeliveryInvocation::Panicked,
            },
            () = sleeper.sleep(Duration::from_millis(delivery_timeout_ms)) => {
                delivery_task.abort();
                let _ = delivery_task.join().await;
                DeliveryInvocation::Outcome(ApprovalDeliveryOutcome::OutcomeUnknown)
            }
        };
        let outcome = match invocation {
            DeliveryInvocation::Outcome(outcome) => outcome,
            DeliveryInvocation::Panicked => {
                let closed = mark_delivery_failed_store_only(
                    journal.as_ref(),
                    &approval,
                    b"delivery-panicked",
                    sleeper.as_ref(),
                )
                .await;
                return match closed {
                    ApprovalWorkerResult::DeliveryFailed => ApprovalWorkerResult::StoreBlocked,
                    other => other,
                };
            }
        };
        match outcome {
            ApprovalDeliveryOutcome::AppliedAck => {
                return mark_applied_store_only(journal.as_ref(), &approval, sleeper.as_ref())
                    .await;
            }
            ApprovalDeliveryOutcome::DefinitelyNotDelivered { retryable: true }
                if attempt < APPROVAL_DELIVERY_ATTEMPTS_PER_ROUND => {}
            ApprovalDeliveryOutcome::DefinitelyNotDelivered { retryable: true } => {
                return mark_delivery_failed_store_only(
                    journal.as_ref(),
                    &approval,
                    b"budget-exhausted",
                    sleeper.as_ref(),
                )
                .await;
            }
            ApprovalDeliveryOutcome::DefinitelyNotDelivered { retryable: false } => {
                return mark_delivery_failed_store_only(
                    journal.as_ref(),
                    &approval,
                    b"definitely-not-delivered",
                    sleeper.as_ref(),
                )
                .await;
            }
            ApprovalDeliveryOutcome::OutcomeUnknown => {
                return mark_delivery_failed_store_only(
                    journal.as_ref(),
                    &approval,
                    b"outcome-unknown",
                    sleeper.as_ref(),
                )
                .await;
            }
            ApprovalDeliveryOutcome::PermanentlyRejected => {
                return mark_delivery_failed_store_only(
                    journal.as_ref(),
                    &approval,
                    b"permanently-rejected",
                    sleeper.as_ref(),
                )
                .await;
            }
        }
    }
    mark_delivery_failed_store_only(
        journal.as_ref(),
        &approval,
        b"budget-exhausted",
        sleeper.as_ref(),
    )
    .await
}

enum DeliveryInvocation {
    Outcome(ApprovalDeliveryOutcome),
    Panicked,
}

pub(crate) async fn run_approval_deadline(
    journal: Arc<dyn ApprovalDeliveryJournal>,
    approval: ApprovalRecord,
    clock: Arc<dyn RuntimeClock>,
    sleeper: Arc<dyn ApprovalSleeper>,
) -> ApprovalWorkerResult {
    loop {
        let now_ms = match clock.now_ms() {
            Ok(now_ms) => now_ms,
            Err(_) => return ApprovalWorkerResult::StoreBlocked,
        };
        if now_ms >= approval.deadline_at_ms {
            return expire_store_only(journal.as_ref(), &approval, sleeper.as_ref()).await;
        }
        sleeper
            .sleep(Duration::from_millis(approval.deadline_at_ms - now_ms))
            .await;
    }
}

async fn begin_attempt_store_only(
    journal: &dyn ApprovalDeliveryJournal,
    approval_id: super::store::RuntimeId,
    delivery_round: u32,
    expected_attempts_in_round: u8,
) -> Result<ApprovalRecord, ()> {
    loop {
        match journal
            .begin_attempt(BeginApprovalAttempt {
                approval_id,
                delivery_round,
                expected_attempts_in_round,
            })
            .await
        {
            Ok(record) => return Ok(record),
            Err(RuntimeStoreError::CommitOutcomeUnknown {
                operation: RuntimeCommitOperation::BeginApprovalAttempt,
            }) => tokio::task::yield_now().await,
            Err(_) => return Err(()),
        }
    }
}

async fn mark_applied_store_only(
    journal: &dyn ApprovalDeliveryJournal,
    approval: &ApprovalRecord,
    sleeper: &dyn ApprovalSleeper,
) -> ApprovalWorkerResult {
    loop {
        match journal
            .mark_applied(MarkApprovalApplied {
                approval_id: approval.approval_id,
                delivery_round: approval.delivery_round,
                attempt: approval.attempts_in_round,
            })
            .await
        {
            Ok(record) if record.state == ApprovalState::Applied => {
                return ApprovalWorkerResult::Applied;
            }
            Ok(record) if record.state == ApprovalState::Expired => {
                return ApprovalWorkerResult::Expired;
            }
            Ok(_) => return ApprovalWorkerResult::FatalClosure,
            Err(RuntimeStoreError::CommitOutcomeUnknown {
                operation: RuntimeCommitOperation::MarkApprovalApplied,
            }) => tokio::task::yield_now().await,
            Err(error) if is_retryable_safety_closure_error(&error) => {
                sleeper.sleep(Duration::from_millis(100)).await;
            }
            Err(_) => return ApprovalWorkerResult::FatalClosure,
        }
    }
}

async fn mark_delivery_failed_store_only(
    journal: &dyn ApprovalDeliveryJournal,
    approval: &ApprovalRecord,
    detail: &[u8],
    sleeper: &dyn ApprovalSleeper,
) -> ApprovalWorkerResult {
    loop {
        match journal
            .mark_delivery_failed(MarkApprovalDeliveryFailed {
                approval_id: approval.approval_id,
                delivery_round: approval.delivery_round,
                attempt: approval.attempts_in_round,
                status_detail: detail.to_vec(),
            })
            .await
        {
            Ok(record) if record.state == ApprovalState::DeliveryFailed => {
                return ApprovalWorkerResult::DeliveryFailed;
            }
            Ok(record) if record.state == ApprovalState::Expired => {
                return ApprovalWorkerResult::Expired;
            }
            Ok(_) => return ApprovalWorkerResult::FatalClosure,
            Err(RuntimeStoreError::CommitOutcomeUnknown {
                operation: RuntimeCommitOperation::MarkApprovalDeliveryFailed,
            }) => tokio::task::yield_now().await,
            Err(error) if is_retryable_safety_closure_error(&error) => {
                sleeper.sleep(Duration::from_millis(100)).await;
            }
            Err(_) => return ApprovalWorkerResult::FatalClosure,
        }
    }
}

async fn expire_store_only(
    journal: &dyn ApprovalDeliveryJournal,
    approval: &ApprovalRecord,
    sleeper: &dyn ApprovalSleeper,
) -> ApprovalWorkerResult {
    loop {
        match journal
            .expire(ExpireApproval {
                conversation_id: approval.conversation_id,
                approval_id: approval.approval_id,
            })
            .await
        {
            Ok(record) if record.state == ApprovalState::Expired => {
                return ApprovalWorkerResult::Expired;
            }
            Ok(record) if record.state == ApprovalState::Applied => {
                return ApprovalWorkerResult::Applied;
            }
            Ok(_) => return ApprovalWorkerResult::StoreBlocked,
            Err(RuntimeStoreError::CommitOutcomeUnknown {
                operation: RuntimeCommitOperation::ExpireApproval,
            }) => tokio::task::yield_now().await,
            Err(error) if is_retryable_safety_closure_error(&error) => {
                sleeper.sleep(Duration::from_millis(100)).await;
            }
            Err(_) => return ApprovalWorkerResult::StoreBlocked,
        }
    }
}

fn is_retryable_safety_closure_error(error: &RuntimeStoreError) -> bool {
    matches!(
        error,
        RuntimeStoreError::WorkerBusy { .. }
            | RuntimeStoreError::WorkerStopped
            | RuntimeStoreError::SafetyOnly
            | RuntimeStoreError::DiskLow { .. }
            | RuntimeStoreError::StoreFull { .. }
            | RuntimeStoreError::PageLimit { .. }
            | RuntimeStoreError::CheckpointBlocked { .. }
            | RuntimeStoreError::CapacityProbe(_)
            | RuntimeStoreError::RecoveryInProgress
            | RuntimeStoreError::ClockRegressed { .. }
            | RuntimeStoreError::Clock(_)
            | RuntimeStoreError::Io(_)
            | RuntimeStoreError::Sqlite(_)
    )
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ApprovalPolicySnapshot {
    pub(crate) agent_kind: AgentKind,
    pub(crate) action_kind: ActionKind,
    pub(crate) allow_approve: bool,
    pub(crate) allow_deny: bool,
    pub(crate) allow_persist: bool,
    pub(crate) deadline_at_ms: Option<u64>,
}

impl ApprovalPolicySnapshot {
    pub(crate) fn from_bound_capabilities(
        request: &ActionRequest,
        capabilities: &SessionCapabilities,
        allow_approve: bool,
        allow_deny: bool,
        deadline_at_ms: Option<u64>,
    ) -> Result<Self, ApprovalPolicyError> {
        if !capabilities.features.contains(&CapabilityId::Approval) {
            return Err(ApprovalPolicyError::ApprovalCapabilityMissing);
        }
        let request_agent = match &request.vendor {
            ActionRequestVendor::Codex { .. } => AgentKind::Codex,
            ActionRequestVendor::ClaudeCode { .. } => AgentKind::ClaudeCode,
        };
        if capabilities.agent_kind != request_agent {
            return Err(ApprovalPolicyError::AgentKindMismatch);
        }
        let allow_persist = matches!(
            &request.vendor,
            ActionRequestVendor::Codex {
                can_persist: true,
                ..
            }
        ) && capabilities
            .features
            .contains(&CapabilityId::CodexApprovalPersistence);
        let snapshot = Self {
            agent_kind: request_agent,
            action_kind: request.kind,
            allow_approve,
            allow_deny,
            allow_persist,
            deadline_at_ms,
        };
        snapshot.validate_request(request)?;
        Ok(snapshot)
    }

    pub(crate) fn validate(&self) -> Result<(), ApprovalPolicyError> {
        if !self.allow_approve && !self.allow_deny {
            return Err(ApprovalPolicyError::NoDecisionAllowed);
        }
        if self.allow_persist && !self.allow_approve {
            return Err(ApprovalPolicyError::PersistRequiresApprove);
        }
        if self.allow_persist && self.agent_kind != AgentKind::Codex {
            return Err(ApprovalPolicyError::PersistUnsupportedForAgent);
        }
        Ok(())
    }

    pub(crate) fn effective_deadline_at_ms(
        &self,
        created_at_ms: u64,
    ) -> Result<u64, ApprovalPolicyError> {
        self.validate()?;
        let deadline_at_ms = match self.deadline_at_ms {
            Some(deadline_at_ms) => deadline_at_ms,
            None => created_at_ms
                .checked_add(DEFAULT_APPROVAL_DEADLINE_MS)
                .ok_or(ApprovalPolicyError::DeadlineOverflow)?,
        };
        if deadline_at_ms <= created_at_ms {
            return Err(ApprovalPolicyError::DeadlineNotAfterCreation);
        }
        Ok(deadline_at_ms)
    }

    pub(crate) fn canonical_encode(&self) -> Result<Vec<u8>, ApprovalPolicyError> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|_| ApprovalPolicyError::Encode)
    }

    pub(crate) fn canonical_decode(encoded: &[u8]) -> Result<Self, ApprovalPolicyError> {
        let policy: Self =
            serde_json::from_slice(encoded).map_err(|_| ApprovalPolicyError::Decode)?;
        policy.validate()?;
        let canonical = serde_json::to_vec(&policy).map_err(|_| ApprovalPolicyError::Encode)?;
        if canonical != encoded {
            return Err(ApprovalPolicyError::NonCanonical);
        }
        Ok(policy)
    }

    pub(crate) fn validate_request(
        &self,
        request: &ActionRequest,
    ) -> Result<(), ApprovalPolicyError> {
        self.validate()?;
        if request.kind != self.action_kind {
            return Err(ApprovalPolicyError::ActionKindMismatch);
        }
        let (request_agent, request_can_persist) = match &request.vendor {
            ActionRequestVendor::Codex { can_persist, .. } => (AgentKind::Codex, *can_persist),
            ActionRequestVendor::ClaudeCode { .. } => (AgentKind::ClaudeCode, false),
        };
        if request_agent != self.agent_kind {
            return Err(ApprovalPolicyError::AgentKindMismatch);
        }
        if self.allow_persist && !request_can_persist {
            return Err(ApprovalPolicyError::RequestCannotPersist);
        }
        Ok(())
    }

    pub(crate) fn validate_decision(
        &self,
        request: &ActionRequest,
        decision: &ActionDecision,
    ) -> Result<(), ApprovalPolicyError> {
        self.validate_request(request)?;
        if decision.request_id != request.request_id {
            return Err(ApprovalPolicyError::RequestIdMismatch);
        }
        match decision.decision {
            ActionDecisionKind::Approve if !self.allow_approve => {
                return Err(ApprovalPolicyError::ApproveNotAllowed);
            }
            ActionDecisionKind::Deny if !self.allow_deny => {
                return Err(ApprovalPolicyError::DenyNotAllowed);
            }
            _ => {}
        }
        if decision.persist {
            if decision.decision != ActionDecisionKind::Approve {
                return Err(ApprovalPolicyError::PersistRequiresApproveDecision);
            }
            if !self.allow_persist {
                return Err(ApprovalPolicyError::PersistNotAllowed);
            }
            match &request.vendor {
                ActionRequestVendor::Codex {
                    can_persist: true, ..
                } => {}
                _ => return Err(ApprovalPolicyError::RequestCannotPersist),
            }
        }
        Ok(())
    }
}

pub(crate) fn approval_delivery_delay_before_attempt(attempt: u8) -> Option<Duration> {
    match attempt {
        0 => Some(Duration::ZERO),
        1..=7 => Some(APPROVAL_DELIVERY_BACKOFF[usize::from(attempt - 1)]),
        _ => None,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum ApprovalPolicyError {
    #[error("approval policy must allow approve or deny")]
    NoDecisionAllowed,
    #[error("approval persistence requires approve permission")]
    PersistRequiresApprove,
    #[error("approval persistence is only supported for Codex")]
    PersistUnsupportedForAgent,
    #[error("the bound session does not advertise approval")]
    ApprovalCapabilityMissing,
    #[error("approval request agent kind does not match the frozen policy")]
    AgentKindMismatch,
    #[error("approval request action kind does not match the frozen policy")]
    ActionKindMismatch,
    #[error("approval request id does not match the decision")]
    RequestIdMismatch,
    #[error("approval policy does not allow approve")]
    ApproveNotAllowed,
    #[error("approval policy does not allow deny")]
    DenyNotAllowed,
    #[error("approval persistence requires an approve decision")]
    PersistRequiresApproveDecision,
    #[error("approval persistence is not allowed by the frozen policy")]
    PersistNotAllowed,
    #[error("the bound action request cannot persist a decision")]
    RequestCannotPersist,
    #[error("approval deadline must be after request creation")]
    DeadlineNotAfterCreation,
    #[error("default approval deadline overflowed")]
    DeadlineOverflow,
    #[error("approval policy encoding failed")]
    Encode,
    #[error("approval policy decoding failed")]
    Decode,
    #[error("approval policy encoding is not canonical")]
    NonCanonical,
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeSet, VecDeque};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;
    use crate::runtime::model::{
        ApprovalRecord, ApprovalState, BeginApprovalAttempt, ExpireApproval, MarkApprovalApplied,
        MarkApprovalDeliveryFailed, RuntimeClock, RuntimeClockError, RuntimeStoreError,
    };
    use crate::runtime::store::{RuntimeId, RuntimeIdKind};
    use agentdeck_protocol::{
        CodexApprovalPolicy, CodexCapabilities, CodexSandboxMode, VendorCapabilities,
    };

    fn valid_policy() -> ApprovalPolicySnapshot {
        ApprovalPolicySnapshot {
            agent_kind: AgentKind::Codex,
            action_kind: ActionKind::ExecuteCommand,
            allow_approve: true,
            allow_deny: true,
            allow_persist: true,
            deadline_at_ms: None,
        }
    }

    fn valid_request() -> ActionRequest {
        ActionRequest {
            request_id: "request-approval-policy".to_owned(),
            kind: ActionKind::ExecuteCommand,
            summary: "sensitive summary".to_owned(),
            vendor: ActionRequestVendor::Codex {
                approval_policy_at_decision: CodexApprovalPolicy::OnRequest,
                sandbox_at_decision: CodexSandboxMode::WorkspaceWrite,
                can_persist: true,
            },
        }
    }

    #[derive(Clone)]
    struct ManualClock(Arc<AtomicU64>);

    impl ManualClock {
        fn new(now_ms: u64) -> Self {
            Self(Arc::new(AtomicU64::new(now_ms)))
        }

        fn advance(&self, duration: Duration) {
            self.0.fetch_add(
                u64::try_from(duration.as_millis()).expect("test duration fits u64"),
                Ordering::SeqCst,
            );
        }
    }

    impl RuntimeClock for ManualClock {
        fn now_ms(&self) -> Result<u64, RuntimeClockError> {
            Ok(self.0.load(Ordering::SeqCst))
        }
    }

    struct AdvancingSleeper {
        clock: ManualClock,
        sleeps: Arc<Mutex<Vec<Duration>>>,
    }

    #[async_trait::async_trait]
    impl ApprovalSleeper for AdvancingSleeper {
        async fn sleep(&self, duration: Duration) {
            self.sleeps.lock().expect("sleeps lock").push(duration);
            self.clock.advance(duration);
        }
    }

    struct FakeDelivery {
        policy: ApprovalPolicySnapshot,
        outcomes: Mutex<VecDeque<ApprovalDeliveryOutcome>>,
        calls: Arc<Mutex<Vec<ApprovalAttemptKey>>>,
    }

    #[async_trait::async_trait]
    impl BoundApprovalDelivery for FakeDelivery {
        fn policy(&self) -> &ApprovalPolicySnapshot {
            &self.policy
        }

        async fn deliver(
            &self,
            key: ApprovalAttemptKey,
            _decision: &ActionDecision,
        ) -> ApprovalDeliveryOutcome {
            self.calls.lock().expect("delivery calls lock").push(key);
            self.outcomes
                .lock()
                .expect("delivery outcomes lock")
                .pop_front()
                .expect("one fake outcome per expected call")
        }
    }

    struct FakeApprovalJournal {
        clock: ManualClock,
        record: Mutex<ApprovalRecord>,
        begin_return_advance: Duration,
        failed_writes: AtomicU64,
        failed_fatal_failures: AtomicU64,
        applied_transient_failures: AtomicU64,
        applied_clock_regressions: AtomicU64,
        applied_fatal_failures: AtomicU64,
    }

    #[async_trait::async_trait]
    impl ApprovalDeliveryJournal for FakeApprovalJournal {
        async fn begin_attempt(
            &self,
            input: BeginApprovalAttempt,
        ) -> Result<ApprovalRecord, RuntimeStoreError> {
            let mut record = self.record.lock().expect("approval record lock");
            assert_eq!(input.approval_id, record.approval_id);
            assert_eq!(input.delivery_round, record.delivery_round);
            assert_eq!(input.expected_attempts_in_round, record.attempts_in_round);
            let now_ms = self.clock.now_ms().expect("manual clock");
            if record.state == ApprovalState::Claimed && record.delivery_round == 0 {
                record.delivery_round = 1;
            }
            record.state = ApprovalState::Applying;
            record.attempts_in_round += 1;
            record.round_started_at_ms.get_or_insert(now_ms);
            record.last_attempt_at_ms = Some(now_ms);
            self.clock.advance(self.begin_return_advance);
            Ok(record.clone())
        }

        async fn mark_applied(
            &self,
            _input: MarkApprovalApplied,
        ) -> Result<ApprovalRecord, RuntimeStoreError> {
            if self.applied_fatal_failures.load(Ordering::SeqCst) == u64::MAX {
                return Ok(self.record.lock().expect("approval record lock").clone());
            }
            if self
                .applied_clock_regressions
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                    remaining.checked_sub(1)
                })
                .is_ok()
            {
                let observed_ms = self.clock.now_ms().expect("manual clock");
                return Err(RuntimeStoreError::ClockRegressed {
                    persisted_ms: observed_ms.saturating_add(1),
                    observed_ms,
                });
            }
            if self
                .applied_fatal_failures
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                    remaining.checked_sub(1)
                })
                .is_ok()
            {
                return Err(RuntimeStoreError::UnknownOrCorruptSchema);
            }
            if self
                .applied_transient_failures
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                    remaining.checked_sub(1)
                })
                .is_ok()
            {
                return Err(RuntimeStoreError::WorkerBusy {
                    lane: crate::runtime::model::RuntimeStoreLane::Safety,
                });
            }
            let mut record = self.record.lock().expect("approval record lock");
            record.state = ApprovalState::Applied;
            Ok(record.clone())
        }

        async fn mark_delivery_failed(
            &self,
            _input: MarkApprovalDeliveryFailed,
        ) -> Result<ApprovalRecord, RuntimeStoreError> {
            if self.failed_fatal_failures.load(Ordering::SeqCst) == u64::MAX {
                return Ok(self.record.lock().expect("approval record lock").clone());
            }
            if self
                .failed_fatal_failures
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                    remaining.checked_sub(1)
                })
                .is_ok()
            {
                return Err(RuntimeStoreError::UnknownOrCorruptSchema);
            }
            self.failed_writes.fetch_add(1, Ordering::SeqCst);
            let mut record = self.record.lock().expect("approval record lock");
            record.state = ApprovalState::DeliveryFailed;
            Ok(record.clone())
        }

        async fn expire(
            &self,
            _input: ExpireApproval,
        ) -> Result<ApprovalRecord, RuntimeStoreError> {
            let mut record = self.record.lock().expect("approval record lock");
            record.state = ApprovalState::Expired;
            Ok(record.clone())
        }
    }

    fn runtime_id(kind: RuntimeIdKind, seed: u8) -> RuntimeId {
        RuntimeId::from_bytes(kind, [seed; 16]).expect("synthetic runtime id")
    }

    fn claimed_approval(now_ms: u64) -> ApprovalRecord {
        ApprovalRecord {
            approval_id: runtime_id(RuntimeIdKind::Approval, 1),
            conversation_id: runtime_id(RuntimeIdKind::Conversation, 2),
            command_id: runtime_id(RuntimeIdKind::Command, 3),
            turn_id: runtime_id(RuntimeIdKind::Turn, 4),
            state: ApprovalState::Claimed,
            request: valid_request(),
            policy: valid_policy(),
            decision: Some(ActionDecision {
                request_id: "request-approval-policy".to_owned(),
                decision: ActionDecisionKind::Approve,
                persist: false,
            }),
            requested_at_ms: now_ms,
            deadline_at_ms: now_ms + DEFAULT_APPROVAL_DEADLINE_MS,
            claimed_at_ms: Some(now_ms),
            state_changed_at_ms: now_ms,
            delivery_round: 0,
            attempts_in_round: 0,
            round_started_at_ms: None,
            last_attempt_at_ms: None,
            state_version: 2,
            last_event_id: runtime_id(RuntimeIdKind::Event, 5),
            status_detail: None,
        }
    }

    #[tokio::test]
    async fn delivery_budget_is_eight_attempts_and_never_exceeds_sixty_seconds() {
        let clock = ManualClock::new(10_000);
        let sleeps = Arc::new(Mutex::new(Vec::new()));
        let calls = Arc::new(Mutex::new(Vec::new()));
        let journal = Arc::new(FakeApprovalJournal {
            clock: clock.clone(),
            record: Mutex::new(claimed_approval(10_000)),
            begin_return_advance: Duration::ZERO,
            failed_writes: AtomicU64::new(0),
            failed_fatal_failures: AtomicU64::new(0),
            applied_transient_failures: AtomicU64::new(0),
            applied_clock_regressions: AtomicU64::new(0),
            applied_fatal_failures: AtomicU64::new(0),
        });
        let delivery: SharedApprovalDelivery = Arc::new(FakeDelivery {
            policy: valid_policy(),
            outcomes: Mutex::new(VecDeque::from(vec![
                ApprovalDeliveryOutcome::DefinitelyNotDelivered { retryable: true };
                8
            ])),
            calls: calls.clone(),
        });

        let result = run_approval_delivery_round(
            journal.clone(),
            delivery,
            claimed_approval(10_000),
            Arc::new(clock.clone()),
            Arc::new(AdvancingSleeper {
                clock,
                sleeps: sleeps.clone(),
            }),
            Arc::new(FixedApprovalBackoff),
        )
        .await;

        assert_eq!(result, ApprovalWorkerResult::DeliveryFailed);
        let calls = calls.lock().expect("delivery calls lock");
        assert_eq!(calls.len(), 8);
        assert_eq!(
            calls.iter().map(|key| key.attempt).collect::<Vec<_>>(),
            (1_u8..=8).collect::<Vec<_>>()
        );
        assert_eq!(
            *sleeps.lock().expect("sleeps lock"),
            APPROVAL_DELIVERY_BACKOFF
        );
        assert_eq!(journal.failed_writes.load(Ordering::SeqCst), 1);
    }

    struct HangingDelivery {
        policy: ApprovalPolicySnapshot,
        calls: Arc<AtomicU64>,
    }

    #[async_trait::async_trait]
    impl BoundApprovalDelivery for HangingDelivery {
        fn policy(&self) -> &ApprovalPolicySnapshot {
            &self.policy
        }

        async fn deliver(
            &self,
            _key: ApprovalAttemptKey,
            _decision: &ActionDecision,
        ) -> ApprovalDeliveryOutcome {
            self.calls.fetch_add(1, Ordering::SeqCst);
            std::future::pending().await
        }
    }

    #[tokio::test]
    async fn hanging_adapter_is_timed_out_as_unknown_and_never_retried() {
        let clock = ManualClock::new(20_000);
        let calls = Arc::new(AtomicU64::new(0));
        let journal = Arc::new(FakeApprovalJournal {
            clock: clock.clone(),
            record: Mutex::new(claimed_approval(20_000)),
            begin_return_advance: Duration::ZERO,
            failed_writes: AtomicU64::new(0),
            failed_fatal_failures: AtomicU64::new(0),
            applied_transient_failures: AtomicU64::new(0),
            applied_clock_regressions: AtomicU64::new(0),
            applied_fatal_failures: AtomicU64::new(0),
        });
        let result = run_approval_delivery_round(
            journal.clone(),
            Arc::new(HangingDelivery {
                policy: valid_policy(),
                calls: calls.clone(),
            }),
            claimed_approval(20_000),
            Arc::new(clock.clone()),
            Arc::new(AdvancingSleeper {
                clock,
                sleeps: Arc::new(Mutex::new(Vec::new())),
            }),
            Arc::new(FixedApprovalBackoff),
        )
        .await;

        assert_eq!(result, ApprovalWorkerResult::DeliveryFailed);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(journal.failed_writes.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn applied_ack_retries_transient_store_closure_without_redelivery() {
        let clock = ManualClock::new(30_000);
        let calls = Arc::new(Mutex::new(Vec::new()));
        let journal = Arc::new(FakeApprovalJournal {
            clock: clock.clone(),
            record: Mutex::new(claimed_approval(30_000)),
            begin_return_advance: Duration::ZERO,
            failed_writes: AtomicU64::new(0),
            failed_fatal_failures: AtomicU64::new(0),
            applied_transient_failures: AtomicU64::new(1),
            applied_clock_regressions: AtomicU64::new(0),
            applied_fatal_failures: AtomicU64::new(0),
        });
        let result = run_approval_delivery_round(
            journal,
            Arc::new(FakeDelivery {
                policy: valid_policy(),
                outcomes: Mutex::new(VecDeque::from([ApprovalDeliveryOutcome::AppliedAck])),
                calls: calls.clone(),
            }),
            claimed_approval(30_000),
            Arc::new(clock.clone()),
            Arc::new(AdvancingSleeper {
                clock,
                sleeps: Arc::new(Mutex::new(Vec::new())),
            }),
            Arc::new(FixedApprovalBackoff),
        )
        .await;

        assert_eq!(result, ApprovalWorkerResult::Applied);
        assert_eq!(calls.lock().expect("delivery calls lock").len(), 1);
    }

    #[tokio::test]
    async fn begin_return_crossing_deadline_expires_without_calling_adapter() {
        let now_ms = 40_000;
        let clock = ManualClock::new(now_ms);
        let calls = Arc::new(Mutex::new(Vec::new()));
        let journal = Arc::new(FakeApprovalJournal {
            clock: clock.clone(),
            record: Mutex::new(claimed_approval(now_ms)),
            begin_return_advance: Duration::from_millis(DEFAULT_APPROVAL_DEADLINE_MS),
            failed_writes: AtomicU64::new(0),
            failed_fatal_failures: AtomicU64::new(0),
            applied_transient_failures: AtomicU64::new(0),
            applied_clock_regressions: AtomicU64::new(0),
            applied_fatal_failures: AtomicU64::new(0),
        });
        let result = run_approval_delivery_round(
            journal,
            Arc::new(FakeDelivery {
                policy: valid_policy(),
                outcomes: Mutex::new(VecDeque::from([ApprovalDeliveryOutcome::AppliedAck])),
                calls: calls.clone(),
            }),
            claimed_approval(now_ms),
            Arc::new(clock.clone()),
            Arc::new(AdvancingSleeper {
                clock,
                sleeps: Arc::new(Mutex::new(Vec::new())),
            }),
            Arc::new(FixedApprovalBackoff),
        )
        .await;

        assert_eq!(result, ApprovalWorkerResult::Expired);
        assert!(calls.lock().expect("delivery calls lock").is_empty());
    }

    #[tokio::test]
    async fn begin_return_crossing_round_budget_fails_without_calling_adapter() {
        let now_ms = 50_000;
        let clock = ManualClock::new(now_ms);
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut applying = claimed_approval(now_ms);
        applying.state = ApprovalState::Applying;
        applying.delivery_round = 1;
        applying.attempts_in_round = 1;
        applying.round_started_at_ms = Some(now_ms);
        applying.last_attempt_at_ms = Some(now_ms);
        applying.state_version = 3;
        let journal = Arc::new(FakeApprovalJournal {
            clock: clock.clone(),
            record: Mutex::new(applying.clone()),
            begin_return_advance: Duration::from_millis(59_500),
            failed_writes: AtomicU64::new(0),
            failed_fatal_failures: AtomicU64::new(0),
            applied_transient_failures: AtomicU64::new(0),
            applied_clock_regressions: AtomicU64::new(0),
            applied_fatal_failures: AtomicU64::new(0),
        });
        let result = run_approval_delivery_round(
            journal,
            Arc::new(FakeDelivery {
                policy: valid_policy(),
                outcomes: Mutex::new(VecDeque::from([ApprovalDeliveryOutcome::AppliedAck])),
                calls: calls.clone(),
            }),
            applying,
            Arc::new(clock.clone()),
            Arc::new(AdvancingSleeper {
                clock,
                sleeps: Arc::new(Mutex::new(Vec::new())),
            }),
            Arc::new(FixedApprovalBackoff),
        )
        .await;

        assert_eq!(result, ApprovalWorkerResult::DeliveryFailed);
        assert!(calls.lock().expect("delivery calls lock").is_empty());
    }

    #[tokio::test]
    async fn applied_ack_retries_clock_regression_without_redelivery() {
        let now_ms = 60_000;
        let clock = ManualClock::new(now_ms);
        let calls = Arc::new(Mutex::new(Vec::new()));
        let journal = Arc::new(FakeApprovalJournal {
            clock: clock.clone(),
            record: Mutex::new(claimed_approval(now_ms)),
            begin_return_advance: Duration::ZERO,
            failed_writes: AtomicU64::new(0),
            failed_fatal_failures: AtomicU64::new(0),
            applied_transient_failures: AtomicU64::new(0),
            applied_clock_regressions: AtomicU64::new(1),
            applied_fatal_failures: AtomicU64::new(0),
        });
        let result = run_approval_delivery_round(
            journal,
            Arc::new(FakeDelivery {
                policy: valid_policy(),
                outcomes: Mutex::new(VecDeque::from([ApprovalDeliveryOutcome::AppliedAck])),
                calls: calls.clone(),
            }),
            claimed_approval(now_ms),
            Arc::new(clock.clone()),
            Arc::new(AdvancingSleeper {
                clock,
                sleeps: Arc::new(Mutex::new(Vec::new())),
            }),
            Arc::new(FixedApprovalBackoff),
        )
        .await;

        assert_eq!(result, ApprovalWorkerResult::Applied);
        assert_eq!(calls.lock().expect("delivery calls lock").len(), 1);
    }

    #[tokio::test]
    async fn applied_ack_fatal_closure_is_not_restartable_store_block() {
        let now_ms = 70_000;
        let clock = ManualClock::new(now_ms);
        let calls = Arc::new(Mutex::new(Vec::new()));
        let journal = Arc::new(FakeApprovalJournal {
            clock: clock.clone(),
            record: Mutex::new(claimed_approval(now_ms)),
            begin_return_advance: Duration::ZERO,
            failed_writes: AtomicU64::new(0),
            failed_fatal_failures: AtomicU64::new(0),
            applied_transient_failures: AtomicU64::new(0),
            applied_clock_regressions: AtomicU64::new(0),
            applied_fatal_failures: AtomicU64::new(1),
        });
        let result = run_approval_delivery_round(
            journal,
            Arc::new(FakeDelivery {
                policy: valid_policy(),
                outcomes: Mutex::new(VecDeque::from([ApprovalDeliveryOutcome::AppliedAck])),
                calls: calls.clone(),
            }),
            claimed_approval(now_ms),
            Arc::new(clock.clone()),
            Arc::new(AdvancingSleeper {
                clock,
                sleeps: Arc::new(Mutex::new(Vec::new())),
            }),
            Arc::new(FixedApprovalBackoff),
        )
        .await;

        assert_ne!(result, ApprovalWorkerResult::StoreBlocked);
        assert_eq!(calls.lock().expect("delivery calls lock").len(), 1);
    }

    #[tokio::test]
    async fn outcome_unknown_fatal_closure_is_not_restartable_store_block() {
        let now_ms = 80_000;
        let clock = ManualClock::new(now_ms);
        let calls = Arc::new(Mutex::new(Vec::new()));
        let journal = Arc::new(FakeApprovalJournal {
            clock: clock.clone(),
            record: Mutex::new(claimed_approval(now_ms)),
            begin_return_advance: Duration::ZERO,
            failed_writes: AtomicU64::new(0),
            failed_fatal_failures: AtomicU64::new(1),
            applied_transient_failures: AtomicU64::new(0),
            applied_clock_regressions: AtomicU64::new(0),
            applied_fatal_failures: AtomicU64::new(0),
        });
        let result = run_approval_delivery_round(
            journal,
            Arc::new(FakeDelivery {
                policy: valid_policy(),
                outcomes: Mutex::new(VecDeque::from([ApprovalDeliveryOutcome::OutcomeUnknown])),
                calls: calls.clone(),
            }),
            claimed_approval(now_ms),
            Arc::new(clock.clone()),
            Arc::new(AdvancingSleeper {
                clock,
                sleeps: Arc::new(Mutex::new(Vec::new())),
            }),
            Arc::new(FixedApprovalBackoff),
        )
        .await;

        assert_ne!(result, ApprovalWorkerResult::StoreBlocked);
        assert_eq!(calls.lock().expect("delivery calls lock").len(), 1);
    }

    #[tokio::test]
    async fn applied_ack_unexpected_closure_state_is_fatal() {
        let now_ms = 90_000;
        let clock = ManualClock::new(now_ms);
        let calls = Arc::new(Mutex::new(Vec::new()));
        let journal = Arc::new(FakeApprovalJournal {
            clock: clock.clone(),
            record: Mutex::new(claimed_approval(now_ms)),
            begin_return_advance: Duration::ZERO,
            failed_writes: AtomicU64::new(0),
            failed_fatal_failures: AtomicU64::new(0),
            applied_transient_failures: AtomicU64::new(0),
            applied_clock_regressions: AtomicU64::new(0),
            applied_fatal_failures: AtomicU64::new(u64::MAX),
        });
        let result = run_approval_delivery_round(
            journal,
            Arc::new(FakeDelivery {
                policy: valid_policy(),
                outcomes: Mutex::new(VecDeque::from([ApprovalDeliveryOutcome::AppliedAck])),
                calls: calls.clone(),
            }),
            claimed_approval(now_ms),
            Arc::new(clock.clone()),
            Arc::new(AdvancingSleeper {
                clock,
                sleeps: Arc::new(Mutex::new(Vec::new())),
            }),
            Arc::new(FixedApprovalBackoff),
        )
        .await;

        assert_eq!(result, ApprovalWorkerResult::FatalClosure);
        assert_eq!(calls.lock().expect("delivery calls lock").len(), 1);
    }

    #[tokio::test]
    async fn outcome_unknown_unexpected_closure_state_is_fatal() {
        let now_ms = 100_000;
        let clock = ManualClock::new(now_ms);
        let calls = Arc::new(Mutex::new(Vec::new()));
        let journal = Arc::new(FakeApprovalJournal {
            clock: clock.clone(),
            record: Mutex::new(claimed_approval(now_ms)),
            begin_return_advance: Duration::ZERO,
            failed_writes: AtomicU64::new(0),
            failed_fatal_failures: AtomicU64::new(u64::MAX),
            applied_transient_failures: AtomicU64::new(0),
            applied_clock_regressions: AtomicU64::new(0),
            applied_fatal_failures: AtomicU64::new(0),
        });
        let result = run_approval_delivery_round(
            journal,
            Arc::new(FakeDelivery {
                policy: valid_policy(),
                outcomes: Mutex::new(VecDeque::from([ApprovalDeliveryOutcome::OutcomeUnknown])),
                calls: calls.clone(),
            }),
            claimed_approval(now_ms),
            Arc::new(clock.clone()),
            Arc::new(AdvancingSleeper {
                clock,
                sleeps: Arc::new(Mutex::new(Vec::new())),
            }),
            Arc::new(FixedApprovalBackoff),
        )
        .await;

        assert_eq!(result, ApprovalWorkerResult::FatalClosure);
        assert_eq!(calls.lock().expect("delivery calls lock").len(), 1);
    }

    #[test]
    fn policy_snapshot_validates_neutral_decision_and_persist_invariants() {
        valid_policy().validate().expect("valid policy");

        let mut no_decision = valid_policy();
        no_decision.allow_approve = false;
        no_decision.allow_deny = false;
        no_decision.allow_persist = false;
        assert_eq!(
            no_decision.validate(),
            Err(ApprovalPolicyError::NoDecisionAllowed)
        );

        let mut persist_without_approve = valid_policy();
        persist_without_approve.allow_approve = false;
        assert_eq!(
            persist_without_approve.validate(),
            Err(ApprovalPolicyError::PersistRequiresApprove)
        );

        let mut non_codex_persist = valid_policy();
        non_codex_persist.agent_kind = AgentKind::ClaudeCode;
        assert_eq!(
            non_codex_persist.validate(),
            Err(ApprovalPolicyError::PersistUnsupportedForAgent)
        );
    }

    #[test]
    fn default_deadline_is_exactly_thirty_minutes_and_explicit_deadline_wins() {
        let created_at_ms = 1_000_u64;
        assert_eq!(
            valid_policy().effective_deadline_at_ms(created_at_ms),
            Ok(created_at_ms + DEFAULT_APPROVAL_DEADLINE_MS)
        );

        let mut explicit = valid_policy();
        explicit.deadline_at_ms = Some(created_at_ms + 7_000);
        assert_eq!(
            explicit.effective_deadline_at_ms(created_at_ms),
            Ok(created_at_ms + 7_000)
        );
        explicit.deadline_at_ms = Some(created_at_ms);
        assert_eq!(
            explicit.effective_deadline_at_ms(created_at_ms),
            Err(ApprovalPolicyError::DeadlineNotAfterCreation)
        );
        assert_eq!(
            valid_policy().effective_deadline_at_ms(u64::MAX),
            Err(ApprovalPolicyError::DeadlineOverflow)
        );
    }

    #[test]
    fn policy_snapshot_has_one_canonical_json_encoding_and_rejects_unknown_fields() {
        let policy = valid_policy();
        let encoded = policy.canonical_encode().expect("encode policy");
        assert_eq!(
            std::str::from_utf8(&encoded).expect("UTF-8 JSON"),
            r#"{"agentKind":"codex","actionKind":"executeCommand","allowApprove":true,"allowDeny":true,"allowPersist":true,"deadlineAtMs":null}"#
        );
        assert_eq!(
            ApprovalPolicySnapshot::canonical_decode(&encoded),
            Ok(policy.clone())
        );
        assert_eq!(
            ApprovalPolicySnapshot::canonical_decode(
                br#"{"agentKind":"codex","actionKind":"executeCommand","allowApprove":true,"allowDeny":true,"allowPersist":true,"deadlineAtMs":null,"route":"forbidden"}"#
            ),
            Err(ApprovalPolicyError::Decode)
        );
        let pretty = serde_json::to_vec_pretty(&policy).expect("pretty policy");
        assert_eq!(
            ApprovalPolicySnapshot::canonical_decode(&pretty),
            Err(ApprovalPolicyError::NonCanonical)
        );
    }

    #[test]
    fn delivery_budget_is_eight_attempts_with_fixed_backoff_under_sixty_seconds() {
        assert_eq!(APPROVAL_DELIVERY_ATTEMPTS_PER_ROUND, 8);
        assert_eq!(APPROVAL_DELIVERY_ROUND_BUDGET, Duration::from_secs(60));
        assert_eq!(
            APPROVAL_DELIVERY_BACKOFF,
            [
                Duration::from_millis(500),
                Duration::from_secs(1),
                Duration::from_secs(2),
                Duration::from_secs(4),
                Duration::from_secs(8),
                Duration::from_secs(16),
                Duration::from_secs(16),
            ]
        );
        let delays = (0_u8..APPROVAL_DELIVERY_ATTEMPTS_PER_ROUND)
            .map(approval_delivery_delay_before_attempt)
            .collect::<Option<Vec<_>>>()
            .expect("all eight attempts are admitted");
        assert_eq!(delays[0], Duration::ZERO);
        assert_eq!(&delays[1..], &APPROVAL_DELIVERY_BACKOFF);
        assert_eq!(
            delays.into_iter().sum::<Duration>(),
            Duration::from_millis(47_500)
        );
        assert_eq!(approval_delivery_delay_before_attempt(8), None);
    }

    #[test]
    fn decision_must_match_the_exact_bound_request_and_frozen_policy() {
        let policy = valid_policy();
        let request = valid_request();
        let decision = ActionDecision {
            request_id: request.request_id.clone(),
            decision: ActionDecisionKind::Approve,
            persist: true,
        };
        policy
            .validate_decision(&request, &decision)
            .expect("exact persisted approve");

        let mut wrong_request = decision.clone();
        wrong_request.request_id = "other-request".to_owned();
        assert_eq!(
            policy.validate_decision(&request, &wrong_request),
            Err(ApprovalPolicyError::RequestIdMismatch)
        );

        let mut deny_persist = decision.clone();
        deny_persist.decision = ActionDecisionKind::Deny;
        assert_eq!(
            policy.validate_decision(&request, &deny_persist),
            Err(ApprovalPolicyError::PersistRequiresApproveDecision)
        );

        let mut deny_disabled = policy.clone();
        deny_disabled.allow_deny = false;
        let deny = ActionDecision {
            request_id: request.request_id.clone(),
            decision: ActionDecisionKind::Deny,
            persist: false,
        };
        assert_eq!(
            deny_disabled.validate_decision(&request, &deny),
            Err(ApprovalPolicyError::DenyNotAllowed)
        );

        let mut cannot_persist = valid_request();
        if let ActionRequestVendor::Codex { can_persist, .. } = &mut cannot_persist.vendor {
            *can_persist = false;
        }
        assert_eq!(
            policy.validate_request(&cannot_persist),
            Err(ApprovalPolicyError::RequestCannotPersist)
        );
    }

    #[test]
    fn delivery_capabilities_are_send_sync_and_backoff_is_injectable() {
        fn assert_send_sync<T: Send + Sync + 'static>() {}
        assert_send_sync::<TokioApprovalSleeper>();
        assert_send_sync::<FixedApprovalBackoff>();
        assert_eq!(
            FixedApprovalBackoff.delay_before_attempt(7),
            Some(Duration::from_secs(16))
        );
        assert_eq!(FixedApprovalBackoff.delay_before_attempt(8), None);
    }

    #[test]
    fn policy_is_minted_only_from_the_bound_session_capabilities() {
        let request = valid_request();
        let mut capabilities = SessionCapabilities {
            agent_kind: AgentKind::Codex,
            agent_version: "test".to_owned(),
            features: BTreeSet::from([
                CapabilityId::Approval,
                CapabilityId::CodexApprovalPersistence,
            ]),
            vendor: VendorCapabilities::Codex(CodexCapabilities::default()),
        };
        let policy = ApprovalPolicySnapshot::from_bound_capabilities(
            &request,
            &capabilities,
            true,
            true,
            None,
        )
        .expect("bound approval capability");
        assert!(policy.allow_persist);

        capabilities
            .features
            .remove(&CapabilityId::CodexApprovalPersistence);
        let without_persistence = ApprovalPolicySnapshot::from_bound_capabilities(
            &request,
            &capabilities,
            true,
            true,
            None,
        )
        .expect("approval remains available without persistence");
        assert!(!without_persistence.allow_persist);

        capabilities.features.remove(&CapabilityId::Approval);
        assert_eq!(
            ApprovalPolicySnapshot::from_bound_capabilities(
                &request,
                &capabilities,
                true,
                true,
                None,
            ),
            Err(ApprovalPolicyError::ApprovalCapabilityMissing)
        );
    }
}
