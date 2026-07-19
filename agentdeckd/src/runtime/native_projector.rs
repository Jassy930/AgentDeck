//! Daemon-owned native history projector lifecycle。
//!
//! Adapter scanner 是同步、opaque continuation，因此所有 source 操作都在
//! blocking worker 上执行。Runtime 只在 Store import exact convergence 且 actor 安装
//! 成功后归还 ACK；只有按值消费 completed witness 后才会进入 Removed。

use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use agentdeck_protocol::AgentKind;
use tokio::sync::{Mutex, oneshot, watch};
use tokio::task::JoinHandle;

use super::conversation::ConversationRegistry;
use super::history_receipt::HistoryOnlyReceiptRegistry;
use super::model::NativeProjectionLimitScope;
use super::router::AgentRouter;
use super::store::{
    ClaudeCodeNativeProjectionStore, CompletedNativeProjectionGeneration, ImportNativeProjection,
    ImportNativeProjectionOutcome, NativeProjectionReconcileCursor, NativeProjectionReconcilePlan,
    NativeProjectionRetirementCursor, NativeProjectionRetirementPlan, RuntimeStoreError,
    RuntimeStoreHandle,
};
use crate::agent::{
    CompletedNativeProjectionScan, DynNativeProjectionScan, NATIVE_PROJECTION_ROUND_TIME_LIMIT,
    NativeProjectionSourceError, NativeProjectionStep,
};

const PROJECTOR_RETRY_DELAY: Duration = Duration::from_millis(250);
const PROJECTOR_REFRESH_DELAY: Duration = Duration::from_secs(30);
const EXACT_STORE_RETRY_LIMIT: usize = 3;

#[derive(Clone, Copy)]
struct NativeProjectorTimings {
    retry_delay: Duration,
    refresh_delay: Duration,
}

impl NativeProjectorTimings {
    const PRODUCTION: Self = Self {
        retry_delay: PROJECTOR_RETRY_DELAY,
        refresh_delay: PROJECTOR_REFRESH_DELAY,
    };
}

enum ProjectorWork {
    Cold,
    Scanning {
        generation: [u8; 16],
        scan: DynNativeProjectionScan,
        paused: bool,
    },
    Completed {
        generation: [u8; 16],
        witness: CompletedNativeProjectionScan,
    },
    Dormant,
    Stopped,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RoundDisposition {
    Yielded(crate::agent::NativeProjectionYieldReason),
    Completed,
    Deferred,
    Abandoned,
    Refresh,
    Unavailable,
    Stopped,
}

struct NativeProjectorShared {
    router: Arc<AgentRouter>,
    store: ClaudeCodeNativeProjectionStore,
    conversations: Arc<ConversationRegistry>,
    history_receipts: HistoryOnlyReceiptRegistry,
    work: Mutex<ProjectorWork>,
    timings: NativeProjectorTimings,
}

/// RuntimeCore 拥有的唯一 projector。初始 round 同步收口，后续任务
/// 持有 generation + opaque continuation，shutdown 必须先 cancel/join 它。
pub(crate) struct NativeProjector {
    shared: Arc<NativeProjectorShared>,
    cancel: watch::Sender<bool>,
    background_start: watch::Sender<bool>,
    task: StdMutex<Option<JoinHandle<()>>>,
}

impl NativeProjector {
    pub(crate) fn new(
        router: Arc<AgentRouter>,
        store: RuntimeStoreHandle,
        conversations: Arc<ConversationRegistry>,
        history_receipts: HistoryOnlyReceiptRegistry,
    ) -> Self {
        Self::with_timings(
            router,
            store,
            conversations,
            history_receipts,
            NativeProjectorTimings::PRODUCTION,
        )
    }

    fn with_timings(
        router: Arc<AgentRouter>,
        store: RuntimeStoreHandle,
        conversations: Arc<ConversationRegistry>,
        history_receipts: HistoryOnlyReceiptRegistry,
        timings: NativeProjectorTimings,
    ) -> Self {
        let (cancel, _) = watch::channel(false);
        let (background_start, _) = watch::channel(false);
        Self {
            shared: Arc::new(NativeProjectorShared {
                router,
                store: store.claude_code_native_projection_store(),
                conversations,
                history_receipts,
                work: Mutex::new(ProjectorWork::Cold),
                timings,
            }),
            cancel,
            background_start,
            task: StdMutex::new(None),
        }
    }

    /// Store recovery 完成后、Core Ready 前只执行 scanner 的一个固定 round。
    /// Yielded/Complete 都把 continuation/witness 留给后台，不在启动路径遍历
    /// reconciliation 或 retirement 页。
    pub(crate) async fn run_initial_round(&self) {
        let (initial_done, initial_waiter) = oneshot::channel();
        {
            let mut task = self
                .task
                .lock()
                .expect("native projector task lock poisoned");
            if task.is_some() {
                return;
            }
            let shared = self.shared.clone();
            let mut cancel = self.cancel.subscribe();
            let mut background_start = self.background_start.subscribe();
            *task = Some(tokio::spawn(async move {
                let _ = shared.drive_scan_round(false).await;
                let _ = initial_done.send(());
                if wait_for_background_start(&mut background_start, &mut cancel).await {
                    shared.run_background(cancel).await;
                }
            }));
        }
        // timeout 只停止 bootstrap waiter，不丢弃 owner future。未完成的 blocking/
        // Store 操作继续由 task field 追踪，并在 shutdown 被 cancel/join。
        let _ = tokio::time::timeout(NATIVE_PROJECTION_ROUND_TIME_LIMIT, initial_waiter).await;
    }

    pub(crate) fn start_background(&self) {
        self.background_start.send_replace(true);
        let mut task = self
            .task
            .lock()
            .expect("native projector task lock poisoned");
        if task.is_none() {
            let shared = self.shared.clone();
            let cancel = self.cancel.subscribe();
            *task = Some(tokio::spawn(async move {
                shared.run_background(cancel).await;
            }));
        }
    }

    pub(crate) async fn shutdown(&self) {
        self.cancel.send_replace(true);
        self.background_start.send_replace(true);
        let task = self
            .task
            .lock()
            .expect("native projector task lock poisoned")
            .take();
        if let Some(task) = task {
            let _ = task.await;
        }
        *self.shared.work.lock().await = ProjectorWork::Stopped;
    }
}

impl Drop for NativeProjector {
    fn drop(&mut self) {
        self.cancel.send_replace(true);
        self.background_start.send_replace(true);
        if let Ok(task) = self.task.get_mut()
            && let Some(task) = task.take()
        {
            task.abort();
        }
    }
}

impl NativeProjectorShared {
    async fn run_background(self: Arc<Self>, mut cancel: watch::Receiver<bool>) {
        loop {
            if *cancel.borrow() {
                return;
            }
            let disposition = {
                let work = self.work.lock().await;
                matches!(&*work, ProjectorWork::Completed { .. })
            };
            if disposition {
                self.finish_completed_generation(&mut cancel).await;
                if wait_or_cancel(&mut cancel, self.timings.refresh_delay).await {
                    return;
                }
                continue;
            }

            match self.drive_scan_round(true).await {
                RoundDisposition::Yielded(reason) => match reason {
                    crate::agent::NativeProjectionYieldReason::CandidateLimit
                    | crate::agent::NativeProjectionYieldReason::ImportLimit
                    | crate::agent::NativeProjectionYieldReason::ByteLimit
                    | crate::agent::NativeProjectionYieldReason::Deadline => {
                        tokio::task::yield_now().await
                    }
                },
                RoundDisposition::Completed => continue,
                RoundDisposition::Deferred | RoundDisposition::Abandoned => {
                    if wait_or_cancel(&mut cancel, self.timings.retry_delay).await {
                        return;
                    }
                }
                RoundDisposition::Refresh => {
                    if wait_or_cancel(&mut cancel, self.timings.refresh_delay).await {
                        return;
                    }
                }
                RoundDisposition::Unavailable => {
                    if wait_or_cancel(&mut cancel, self.timings.refresh_delay).await {
                        return;
                    }
                    let mut work = self.work.lock().await;
                    if matches!(&*work, ProjectorWork::Dormant) {
                        *work = ProjectorWork::Cold;
                    }
                }
                RoundDisposition::Stopped => return,
            }
        }
    }

    async fn drive_scan_round(&self, resume_yielded: bool) -> RoundDisposition {
        let mut work = self.work.lock().await;
        if matches!(&*work, ProjectorWork::Cold) {
            let generation = fresh_generation();
            match blocking_begin_scan(self.router.clone(), generation).await {
                Ok(scan) => {
                    *work = ProjectorWork::Scanning {
                        generation,
                        scan,
                        paused: false,
                    };
                }
                Err(NativeProjectionSourceError::Unavailable) => {
                    *work = ProjectorWork::Dormant;
                    return RoundDisposition::Unavailable;
                }
                Err(error) => return source_error_disposition(error),
            }
        }

        let ProjectorWork::Scanning {
            generation: _,
            scan,
            paused,
        } = &mut *work
        else {
            return match &*work {
                ProjectorWork::Completed { .. } => RoundDisposition::Completed,
                ProjectorWork::Dormant => RoundDisposition::Unavailable,
                ProjectorWork::Stopped => RoundDisposition::Stopped,
                ProjectorWork::Cold | ProjectorWork::Scanning { .. } => RoundDisposition::Abandoned,
            };
        };

        if *paused {
            if !resume_yielded {
                return RoundDisposition::Yielded(
                    crate::agent::NativeProjectionYieldReason::Deadline,
                );
            }
            let owned = std::mem::replace(scan, empty_scan_sentinel());
            match blocking_resume(owned).await {
                Ok(resumed) => {
                    *scan = resumed;
                    *paused = false;
                }
                Err(_) => {
                    *work = ProjectorWork::Cold;
                    return RoundDisposition::Abandoned;
                }
            }
        }

        loop {
            let owned = match &mut *work {
                ProjectorWork::Scanning { scan, .. } => {
                    std::mem::replace(scan, empty_scan_sentinel())
                }
                _ => return RoundDisposition::Abandoned,
            };
            let (returned, step) = match blocking_next(owned).await {
                Ok(value) => value,
                Err(_) => {
                    *work = ProjectorWork::Cold;
                    return RoundDisposition::Abandoned;
                }
            };
            let (generation, scan) = match &mut *work {
                ProjectorWork::Scanning {
                    generation, scan, ..
                } => {
                    *scan = returned;
                    (*generation, scan)
                }
                _ => return RoundDisposition::Abandoned,
            };
            match step {
                Ok(NativeProjectionStep::Candidate(candidate)) => {
                    let (descriptor, default_configuration, private_reference, acknowledgement) =
                        candidate.into_parts();
                    let outcome = self
                        .store
                        .import(ImportNativeProjection {
                            descriptor,
                            default_configuration,
                            private_reference,
                            scan_generation: generation,
                        })
                        .await;
                    let outcome = match outcome {
                        Ok(outcome) => outcome,
                        Err(RuntimeStoreError::NativeProjectionLimit { scope }) => {
                            crate::diag::log(
                                "runtime_native_projection_truncated",
                                projection_limit_diagnostic(scope),
                            );
                            return RoundDisposition::Refresh;
                        }
                        Err(_) => return RoundDisposition::Deferred,
                    };
                    let conversation = imported_conversation(outcome);
                    if self
                        .conversations
                        .install(conversation, Vec::new())
                        .await
                        .is_err()
                    {
                        return RoundDisposition::Deferred;
                    }
                    let owned = std::mem::replace(scan, empty_scan_sentinel());
                    match blocking_acknowledge(owned, acknowledgement).await {
                        Ok(acknowledged) => *scan = acknowledged,
                        Err(error) => {
                            *work = ProjectorWork::Cold;
                            return source_error_disposition(error);
                        }
                    }
                }
                Ok(NativeProjectionStep::Yielded(reason)) => {
                    if let ProjectorWork::Scanning { paused, .. } = &mut *work {
                        *paused = true;
                    }
                    return RoundDisposition::Yielded(reason);
                }
                Ok(NativeProjectionStep::Complete) => {
                    let (generation, owned) =
                        match std::mem::replace(&mut *work, ProjectorWork::Cold) {
                            ProjectorWork::Scanning {
                                generation, scan, ..
                            } => (generation, scan),
                            _ => return RoundDisposition::Abandoned,
                        };
                    match blocking_complete(owned).await {
                        Ok(witness) => {
                            *work = ProjectorWork::Completed {
                                generation,
                                witness,
                            };
                            return RoundDisposition::Completed;
                        }
                        Err(error) => return source_error_disposition(error),
                    }
                }
                Err(error) => {
                    *work = ProjectorWork::Cold;
                    return source_error_disposition(error);
                }
            }
        }
    }

    async fn finish_completed_generation(&self, cancel: &mut watch::Receiver<bool>) {
        if *cancel.borrow() {
            return;
        }
        let completed = {
            let mut work = self.work.lock().await;
            match std::mem::replace(&mut *work, ProjectorWork::Cold) {
                ProjectorWork::Completed {
                    generation,
                    witness,
                } => (generation, witness),
                other => {
                    *work = other;
                    return;
                }
            }
        };
        let Ok(completed_generation) = self.store.accept_completed_scan(completed.1).await else {
            return;
        };
        if *cancel.borrow() {
            return;
        }
        if self
            .reconcile_completed(completed_generation, cancel)
            .await
            .is_err()
        {
            return;
        }
        let _ = self.retire_expired(cancel).await;
    }

    async fn reconcile_completed(
        &self,
        completed: Arc<CompletedNativeProjectionGeneration>,
        cancel: &mut watch::Receiver<bool>,
    ) -> Result<(), ()> {
        let mut cursor: Option<NativeProjectionReconcileCursor> = None;
        loop {
            if *cancel.borrow() {
                return Err(());
            }
            let plan = self
                .store
                .plan_completed_page(completed.clone(), cursor)
                .await
                .map_err(|_| ())?;
            if *cancel.borrow() {
                return Err(());
            }
            let next = plan.next_cursor();
            let ids = plan.candidate_ids().collect::<Vec<_>>();
            let lease = self
                .conversations
                .prepare_projection_reconciliation(ids)
                .await;
            let dispositions = lease.dispositions();
            let removed_conversation_ids = lease.removed_conversation_ids().collect::<Vec<_>>();
            if *cancel.borrow() {
                return Err(());
            }
            apply_reconciliation_exact(&self.store, plan, dispositions, cancel).await?;
            // 只有 Store 已 durable Applied/Replayed 的 Removed 才能失效最近一次
            // verified dynamic receipt。apply 失败或 cancel 保留 Present conversation
            // 的 last-successful set；Busy/partial generation 也拿不到 quiescent lease。
            for conversation_id in removed_conversation_ids {
                self.history_receipts
                    .clear(conversation_id)
                    .map_err(|_| ())?;
            }
            // Store durable Applied/Replayed 后必须先卸载同页 Removed actor；此处
            // 不再观察 cancel，下一页顶部再退出。
            self.conversations
                .uninstall_reconciled(lease)
                .await
                .map_err(|_| ())?;
            let Some(next) = next else {
                return Ok(());
            };
            cursor = Some(next);
        }
    }

    async fn retire_expired(&self, cancel: &mut watch::Receiver<bool>) -> Result<(), ()> {
        let mut cursor: Option<NativeProjectionRetirementCursor> = None;
        loop {
            if *cancel.borrow() {
                return Err(());
            }
            let plan = self
                .store
                .plan_retirement_page(cursor)
                .await
                .map_err(|_| ())?;
            if *cancel.borrow() {
                return Err(());
            }
            let next = plan.next_cursor();
            apply_retirement_exact(&self.store, plan, cancel).await?;
            let Some(next) = next else {
                return Ok(());
            };
            cursor = Some(next);
        }
    }
}

fn imported_conversation(
    outcome: ImportNativeProjectionOutcome,
) -> super::store::ConversationRecord {
    match outcome {
        ImportNativeProjectionOutcome::Imported { conversation, .. }
        | ImportNativeProjectionOutcome::Replayed { conversation, .. }
        | ImportNativeProjectionOutcome::Reobserved { conversation, .. }
        | ImportNativeProjectionOutcome::Reappeared { conversation, .. } => conversation,
    }
}

fn projection_limit_diagnostic(scope: NativeProjectionLimitScope) -> &'static str {
    match scope {
        NativeProjectionLimitScope::LiveConversations => {
            "daemon.runtime.store_full:live_conversations"
        }
        NativeProjectionLimitScope::PhysicalIdentities => {
            "daemon.runtime.store_full:physical_identities"
        }
        NativeProjectionLimitScope::NonliveIdentities => {
            "daemon.runtime.store_full:nonlive_identities"
        }
        NativeProjectionLimitScope::ChargedReferenceBytes => {
            "daemon.runtime.store_full:charged_reference_bytes"
        }
    }
}

fn source_error_disposition(error: NativeProjectionSourceError) -> RoundDisposition {
    let detail = match error {
        NativeProjectionSourceError::Unavailable => "unavailable",
        NativeProjectionSourceError::InvalidGeneration => "invalid_generation",
        NativeProjectionSourceError::InvalidSource => "invalid_source",
        NativeProjectionSourceError::PayloadTooLarge => "payload_too_large",
        NativeProjectionSourceError::ReadUnavailable => "read_unavailable",
        NativeProjectionSourceError::InvalidAcknowledgement => "invalid_acknowledgement",
        NativeProjectionSourceError::InvalidState => "invalid_state",
        NativeProjectionSourceError::ScanIncomplete => "scan_incomplete",
    };
    crate::diag::log("runtime_native_projection_refresh", detail);
    RoundDisposition::Refresh
}

async fn apply_reconciliation_exact(
    store: &ClaudeCodeNativeProjectionStore,
    plan: NativeProjectionReconcilePlan,
    dispositions: Vec<super::store::NativeProjectionCandidateDisposition>,
    cancel: &mut watch::Receiver<bool>,
) -> Result<(), ()> {
    for attempt in 0..EXACT_STORE_RETRY_LIMIT {
        if *cancel.borrow() {
            return Err(());
        }
        if store
            .apply_completed_page(plan.clone(), dispositions.clone())
            .await
            .is_ok()
        {
            return Ok(());
        }
        if attempt + 1 == EXACT_STORE_RETRY_LIMIT || *cancel.borrow() {
            return Err(());
        }
        tokio::task::yield_now().await;
    }
    Err(())
}

async fn apply_retirement_exact(
    store: &ClaudeCodeNativeProjectionStore,
    plan: NativeProjectionRetirementPlan,
    cancel: &mut watch::Receiver<bool>,
) -> Result<(), ()> {
    for attempt in 0..EXACT_STORE_RETRY_LIMIT {
        if *cancel.borrow() {
            return Err(());
        }
        if store.apply_retirement_page(plan.clone()).await.is_ok() {
            return Ok(());
        }
        if attempt + 1 == EXACT_STORE_RETRY_LIMIT || *cancel.borrow() {
            return Err(());
        }
        tokio::task::yield_now().await;
    }
    Err(())
}

fn fresh_generation() -> [u8; 16] {
    let mut generation = *uuid::Uuid::new_v4().as_bytes();
    if generation == [0; 16] {
        generation[0] = 1;
    }
    generation
}

async fn wait_or_cancel(cancel: &mut watch::Receiver<bool>, duration: Duration) -> bool {
    if *cancel.borrow() {
        return true;
    }
    tokio::select! {
        _ = tokio::time::sleep(duration) => false,
        changed = cancel.changed() => changed.is_err() || *cancel.borrow_and_update(),
    }
}

async fn wait_for_background_start(
    background_start: &mut watch::Receiver<bool>,
    cancel: &mut watch::Receiver<bool>,
) -> bool {
    loop {
        if *cancel.borrow() {
            return false;
        }
        if *background_start.borrow() {
            return true;
        }
        tokio::select! {
            changed = background_start.changed() => {
                if changed.is_err() {
                    return false;
                }
            }
            changed = cancel.changed() => {
                if changed.is_err() || *cancel.borrow_and_update() {
                    return false;
                }
            }
        }
    }
}

async fn blocking_begin_scan(
    router: Arc<AgentRouter>,
    generation: [u8; 16],
) -> Result<DynNativeProjectionScan, NativeProjectionSourceError> {
    tokio::task::spawn_blocking(move || {
        router.begin_native_projection_scan(AgentKind::ClaudeCode, generation)
    })
    .await
    .map_err(|_| NativeProjectionSourceError::ReadUnavailable)?
}

async fn blocking_next(
    mut scan: DynNativeProjectionScan,
) -> Result<
    (
        DynNativeProjectionScan,
        Result<NativeProjectionStep, NativeProjectionSourceError>,
    ),
    (),
> {
    tokio::task::spawn_blocking(move || {
        let step = scan.next();
        (scan, step)
    })
    .await
    .map_err(|_| ())
}

async fn blocking_resume(
    mut scan: DynNativeProjectionScan,
) -> Result<DynNativeProjectionScan, NativeProjectionSourceError> {
    tokio::task::spawn_blocking(move || {
        scan.resume_after_yield()?;
        Ok(scan)
    })
    .await
    .map_err(|_| NativeProjectionSourceError::ReadUnavailable)?
}

async fn blocking_acknowledge(
    mut scan: DynNativeProjectionScan,
    acknowledgement: crate::agent::NativeProjectionAcknowledgement,
) -> Result<DynNativeProjectionScan, NativeProjectionSourceError> {
    tokio::task::spawn_blocking(move || {
        scan.acknowledge(acknowledgement)?;
        Ok(scan)
    })
    .await
    .map_err(|_| NativeProjectionSourceError::ReadUnavailable)?
}

async fn blocking_complete(
    scan: DynNativeProjectionScan,
) -> Result<CompletedNativeProjectionScan, NativeProjectionSourceError> {
    tokio::task::spawn_blocking(move || scan.into_completed())
        .await
        .map_err(|_| NativeProjectionSourceError::ReadUnavailable)?
}

/// 只用于在 move 跨 blocking boundary 时短暂占位，任何路径都不能调用它。
fn empty_scan_sentinel() -> DynNativeProjectionScan {
    Box::new(EmptyScanSentinel)
}

struct EmptyScanSentinel;

impl crate::agent::NativeProjectionScan for EmptyScanSentinel {
    fn next(&mut self) -> Result<NativeProjectionStep, NativeProjectionSourceError> {
        Err(NativeProjectionSourceError::InvalidState)
    }

    fn acknowledge(
        &mut self,
        _acknowledgement: crate::agent::NativeProjectionAcknowledgement,
    ) -> Result<(), NativeProjectionSourceError> {
        Err(NativeProjectionSourceError::InvalidState)
    }

    fn resume_after_yield(&mut self) -> Result<(), NativeProjectionSourceError> {
        Err(NativeProjectionSourceError::InvalidState)
    }

    fn into_completed(
        self: Box<Self>,
    ) -> Result<CompletedNativeProjectionScan, NativeProjectionSourceError> {
        Err(NativeProjectionSourceError::ScanIncomplete)
    }
}

#[cfg(test)]
#[path = "native_projector_tests.rs"]
mod tests;
