//! 单 connection gate 上的 snapshot/backfill → SyncComplete → catchup/live pump。

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use agentdeck_protocol::SessionCapabilities;
use agentdeck_protocol::runtime::identity::{ConversationId, MessageId};
use agentdeck_protocol::runtime::{
    BackfillChunk, BackfillRange, RUNTIME_PROTOCOL_VERSION, RuntimeEnvelope, RuntimeFailure,
    RuntimeInnerCursor, RuntimeMessage, RuntimeReply, RuntimeStreamItem, RuntimeSyncComplete,
    StreamCursor, SubscriptionReceipt,
};
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard, Semaphore};

use super::super::backfill::BarrierDecision;
use super::super::catalog_snapshot::{CatalogSnapshotProvider, CatalogSnapshotProviderError};
use super::super::connection::{
    AuthenticatedPrincipal, ConnectionError, ConnectionId, ConnectionRegistry, EncodedRuntimeFrame,
};
use super::super::events::{PinnedBackfillSource, RuntimeStreamTarget, StreamBarrierRegistration};
use super::super::history_receipt::{HistoryOnlyReceiptError, HistoryOnlyReceiptRegistry};
use super::super::model::RuntimeStoreError;
use super::super::store::key_transition::{RemoteTransitionIngressClass, TransitionSnapshotPermit};
use super::super::store::{
    RuntimeBackfillPlan, RuntimeBackfillTarget, RuntimeId, RuntimeIdKind, RuntimeStoreHandle,
};
use super::super::transfer_identity::DurableStreamSource;
use super::coordinator::PendingSubscriptionPermit;
use super::egress::TransferEgressControl;
use super::{SubscriptionLease, SubscriptionRegistry, SubscriptionRegistryError};
use crate::runtime::AgentRouter;

mod reply;

pub(super) use reply::PumpSendError as OneShotSendError;

/// One-shot CatalogRequest 与 subscription pump 共用的唯一 directed egress 入口。
/// 小页走 paced frame，大页由 `reply` 按 connection profile 进入真实
/// JSON 或 compact TransferPart/FlushReceipt 链。
pub(super) async fn send_one_shot_reply(
    connections: &ConnectionRegistry,
    connection_id: ConnectionId,
    message_id: MessageId,
    reply: RuntimeReply,
    transfer_payload: Option<&[u8]>,
    control: &TransferEgressControl,
) -> Result<(), OneShotSendError> {
    reply::reply(
        connections,
        connection_id,
        message_id,
        reply,
        transfer_payload,
        control,
    )
    .await
}

pub(super) struct PumpJob {
    pub(super) store: RuntimeStoreHandle,
    pub(super) router: Arc<AgentRouter>,
    pub(super) connections: ConnectionRegistry,
    pub(super) connection_id: ConnectionId,
    pub(super) message_id: MessageId,
    pub(super) target: RuntimeStreamTarget,
    pub(super) registration: Option<StreamBarrierRegistration>,
    pub(super) lease: SubscriptionLease,
    pub(super) registry: SubscriptionRegistry,
    pub(super) control: TransferEgressControl,
    pub(super) gate: Arc<AsyncMutex<()>>,
    pub(super) coordination_gate: Arc<AsyncMutex<()>>,
    pub(super) snapshot_build_budget: Arc<Semaphore>,
    pub(super) snapshot_build_gate: Arc<AsyncMutex<()>>,
    pub(super) catalog_snapshots: CatalogSnapshotProvider,
    pub(super) history_receipts: HistoryOnlyReceiptRegistry,
    pub(super) principal: AuthenticatedPrincipal,
    pub(super) flushed_business_frame: bool,
    pub(super) emit_subscription_receipt: bool,
    pub(super) transition_snapshot: Option<TransitionSnapshotPermit>,
    pub(super) pending_permit: Option<PendingSubscriptionPermit>,
}

#[derive(Debug, thiserror::Error)]
enum PumpError {
    #[error(transparent)]
    Store(#[from] RuntimeStoreError),
    #[error(transparent)]
    Registry(#[from] SubscriptionRegistryError),
    #[error(transparent)]
    Send(#[from] reply::PumpSendError),
    #[error(transparent)]
    Connection(#[from] ConnectionError),
    #[error(transparent)]
    Snapshot(#[from] super::reducer::SnapshotReducerError),
    #[error(transparent)]
    Catalog(#[from] CatalogSnapshotProviderError),
    #[error(transparent)]
    HistoryReceipt(#[from] HistoryOnlyReceiptError),
    #[error("subscription barrier has no exact source")]
    MissingSource,
    #[error("subscription DTO construction failed")]
    InvalidDto,
    #[error("subscription clock is outside the representable range")]
    Clock,
    #[error("subscription was cancelled")]
    Cancelled,
    #[error("subscription barrier reached its absolute deadline")]
    Expired,
}

/// 返回 true 表示本 job 已 fail-close connection，coordinator 必须在 exact job
/// cleanup 后级联取消同 connection 的 sibling jobs/watch。
pub(super) async fn run(mut job: PumpJob) -> bool {
    let gate = job.gate.clone();
    let mut initial_guard = None;
    let result = match controlled(&job, gate.lock_owned()).await {
        Ok(guard) => {
            initial_guard = Some(guard);
            match activate_subscription(&mut job).await {
                Ok(()) => run_inner(&mut job, &mut initial_guard).await,
                Err(error) => Err(error),
            }
        }
        Err(error) => Err(error),
    };
    if let Err(error) = result {
        if job.lease.is_cancelled() || job.control.is_cancelled() {
            return false;
        }
        crate::diag::log("runtime_subscription_pump_failed", &error.to_string());
        // 任一 Send error 都可能发生在 commit_paced 成功、FlushReceipt 尚未 ACK
        // 之后；此时客户端已经可能看到 frame/首个 TransferPart。保守 fail-close，
        // 绝不再发送同 messageId 的 terminal Failure。
        let partial_delivery = job.flushed_business_frame
            || error.has_partial_transfer()
            || matches!(error, PumpError::Send(_) | PumpError::Connection(_));
        if partial_delivery {
            let _ = job.connections.fail_close(job.connection_id);
            return true;
        }
        // 威胁场景：barrier 已到 absolute TTL、但慢读者不 ACK terminal Failure；
        // 若 registry lease 跟随无 deadline writer wait，两个超时 snapshot job 就能
        // 永久占满 global snapshot-sender 配额。此时 payload/pin/build permit 已由
        // 失败栈释放，先 exact 归还本 generation 的 registry 配额；terminal frame
        // 与 connection writer ownership 继续独立存活到 flush 或 disconnect。
        if let Err(release_error) = job.lease.release() {
            crate::diag::log(
                "runtime_subscription_quota_release_failed",
                &release_error.to_string(),
            );
            let _ = job.connections.fail_close(job.connection_id);
            return true;
        }
        // gate wait 自身也可能到期，此时 source/watch 仍在 PumpJob 字段而不在
        // run_inner 的失败栈。进入无 deadline terminal writer 前显式 drop 整份
        // registration，确保 watch、TEMP pin 与 frozen payload cleanup 立即交回 store。
        drop(job.registration.take());
        let terminal_control = job.control.without_deadline();
        // 威胁场景：一个 pre-delivery job 在 gate 内超时后若先释放 gate，再在 gate
        // 外发送 terminal Failure，等待中的另一 target 会进入 gate；Failure 持有
        // 单槽 paced reservation 等 ACK 时，sibling 的 try-reserve 会得到 Lagged 并
        // 错误 fail-close 整条 connection。初始 guard 因此必须覆盖 terminal flush；
        // 若 absolute TTL 发生在等 gate 阶段，则用同一 cancellation、无 deadline
        // 的 control 重新取得 gate，unsubscribe/disconnect 仍可终止旧 generation。
        if initial_guard.is_none() {
            let gate = job.gate.clone();
            match controlled_with(&terminal_control, gate.lock_owned()).await {
                Ok(guard) => initial_guard = Some(guard),
                Err(PumpError::Cancelled) => return false,
                Err(gate_error) => {
                    crate::diag::log(
                        "runtime_subscription_terminal_gate_failed",
                        &gate_error.to_string(),
                    );
                    let _ = job.connections.fail_close(job.connection_id);
                    return true;
                }
            }
        }
        let failure = error.failure();
        if reply::reply(
            &job.connections,
            job.connection_id,
            job.message_id.clone(),
            RuntimeReply::Failure(failure),
            None,
            &terminal_control,
        )
        .await
        .is_err()
        {
            // resubscribe/unsubscribe/disconnect 通过同一 control 显式取消旧 terminal
            // wait；这属于 generation handoff，不是 transport failure，不能让旧 job
            // fail-close 已经安装的新 generation。
            if job.control.is_cancelled() {
                return false;
            }
            let _ = job.connections.fail_close(job.connection_id);
            return true;
        }
        drop(initial_guard.take());
    }
    false
}

impl PumpError {
    fn has_partial_transfer(&self) -> bool {
        matches!(
            self,
            Self::Send(reply::PumpSendError::Transfer(error)) if error.flushed_parts() > 0
        )
    }

    fn failure(&self) -> RuntimeFailure {
        use agentdeck_protocol::runtime::failure::{
            DAEMON_RUNTIME_CONNECTION_UNAVAILABLE, DAEMON_RUNTIME_IDENTITY_UNAVAILABLE,
            DAEMON_RUNTIME_READ_UNAVAILABLE,
        };
        let code = match self {
            Self::Store(error) => error.code(),
            Self::Send(reply::PumpSendError::Connection(_)) => {
                DAEMON_RUNTIME_CONNECTION_UNAVAILABLE
            }
            Self::Connection(_) => DAEMON_RUNTIME_CONNECTION_UNAVAILABLE,
            // 威胁场景：合法 Runtime v1 snapshot 恰好占满 64 MiB，补入 v2
            // 必填字段后超限；若 pump 抹掉 materializer 的 typed code，客户端
            // 会把确定性的 payload 边界误判为可重试 read failure。
            Self::Snapshot(super::reducer::SnapshotReducerError::Materialize(error)) => {
                error.code()
            }
            Self::Snapshot(super::reducer::SnapshotReducerError::Identity) => {
                DAEMON_RUNTIME_IDENTITY_UNAVAILABLE
            }
            _ => DAEMON_RUNTIME_READ_UNAVAILABLE,
        };
        RuntimeFailure::new(code, "runtime subscription could not complete")
    }
}

async fn activate_subscription(job: &mut PumpJob) -> Result<(), PumpError> {
    // egress → coordination 是唯一双锁顺序。replacement/disconnect 在
    // coordination 内只做同步 detach/cancel，绝不等待 egress，因此 receipt 的
    // current-generation 检查与 enqueue 可线性化且不会形成锁环。
    let coordination_gate = job.coordination_gate.clone();
    let _coordination_guard = controlled(job, coordination_gate.lock()).await?;
    job.registry.require_current(&job.lease)?;
    let _ = job.connections.principal(job.connection_id)?;
    if job.emit_subscription_receipt {
        let stream_generation = job.transition_snapshot.as_ref().map_or_else(
            || job.lease.generation().wire_generation(),
            transition_wire_generation,
        );
        let envelope = RuntimeEnvelope {
            version: RUNTIME_PROTOCOL_VERSION,
            message_id: job.message_id.clone(),
            body: RuntimeMessage::Reply(RuntimeReply::Subscription(
                SubscriptionReceipt::Subscribed { stream_generation },
            )),
        };
        let frame = EncodedRuntimeFrame::from_envelope(&envelope)?;
        job.connections.try_enqueue(job.connection_id, frame)?;
    }
    // 此刻 job 已取得唯一 egress gate，并在 coordination gate 内确认仍是 registry
    // current；从这里起真实 registry quota 接管资源记账，隐藏 pending permit 可释放。
    drop(job.pending_permit.take());
    Ok(())
}

async fn run_inner(
    job: &mut PumpJob,
    initial_guard: &mut Option<OwnedMutexGuard<()>>,
) -> Result<(), PumpError> {
    debug_assert!(initial_guard.is_some());
    ensure_current(job)?;
    let decision = job
        .registration
        .as_ref()
        .ok_or(PumpError::MissingSource)?
        .decision;
    match decision {
        BarrierDecision::Snapshot { base, through, .. } => {
            if let Some(permit) = job.transition_snapshot.as_ref() {
                let registration = job.registration.as_ref().ok_or(PumpError::MissingSource)?;
                validate_transition_registration(job.target, registration, permit)?;
            }
            let snapshot_base = send_snapshot(job).await?;
            if job.transition_snapshot.is_some() && snapshot_base != through {
                return Err(PumpError::InvalidDto);
            }
            if base != through {
                let mut source = job
                    .registration
                    .as_mut()
                    .ok_or(PumpError::MissingSource)?
                    .take_backfill_source()
                    .ok_or(PumpError::MissingSource)?;
                if snapshot_base != through {
                    debug_assert_eq!(snapshot_base, base);
                    send_pinned(job, source, true).await?;
                } else {
                    let pin_id = source.pin().pin_id;
                    controlled(job, job.store.release_backfill_pin(pin_id)).await??;
                    source.disarm_after_release();
                }
            }
        }
        BarrierDecision::Backfill { .. } => {
            let source = job
                .registration
                .as_mut()
                .ok_or(PumpError::MissingSource)?
                .take_backfill_source()
                .ok_or(PumpError::MissingSource)?;
            send_pinned(job, source, true).await?;
        }
        BarrierDecision::SyncComplete { .. } => {}
        BarrierDecision::NeedSnapshot { .. } => {
            send_failure(job, "retained range requires a new snapshot").await?;
            return Ok(());
        }
        BarrierDecision::CursorAhead { .. } => {
            send_failure(job, "requested cursor is ahead of durable high-water").await?;
            return Ok(());
        }
    }
    ensure_current(job)?;
    let registration = job.registration.as_ref().ok_or(PumpError::MissingSource)?;
    let inner = registration.high_water;
    let sync = match job.transition_snapshot.as_ref() {
        Some(permit) => {
            validate_transition_registration(job.target, registration, permit)?;
            RuntimeSyncComplete {
                stream_generation: transition_wire_generation(permit),
                stream_cursor: StreamCursor::from_high_water(permit.relay_committed_outer()),
                inner_cursor: inner_cursor(job.target, inner),
                key_directory_revision: permit.key_directory_revision(),
            }
        }
        None => RuntimeSyncComplete {
            stream_generation: job.lease.generation().wire_generation(),
            stream_cursor: registration.relay_committed.outer,
            inner_cursor: inner_cursor(job.target, inner),
            key_directory_revision: 0,
        },
    };
    reply::reply_with_stream_binding(
        &job.connections,
        job.connection_id,
        job.message_id.clone(),
        RuntimeReply::SyncComplete(sync),
        None,
        registration.relay_committed.stream_binding,
        &job.control,
    )
    .await?;
    job.flushed_business_frame = true;

    if job.transition_snapshot.is_some() {
        // 两个 transition scopes 可能共享同一 connection。首个 SyncComplete 后必须
        // 释放 egress gate，让 sibling snapshot 也能 flush 并取得 StreamAppliedAck；
        // registry barrier 仍保持 active，所以任何 live enqueue 都不会抢跑。
        drop(initial_guard.take());
        job.registry
            .release_snapshot_sender(&job.lease, epoch_ms()?)?;
        wait_transition_business_ready(job).await?;
        let gate = job.gate.clone();
        let _continuation_guard = controlled(job, gate.lock_owned()).await?;
        ensure_current(job)?;
        job.registry.complete_barrier(&job.lease, epoch_ms()?)?;
        let live_control = job.control.without_deadline();
        let mut cursor = inner;
        let pinned = job
            .registration
            .as_mut()
            .ok_or(PumpError::MissingSource)?
            .take_backfill_source();
        if let Some(source) = pinned {
            cursor = send_pinned_with_control(job, source, false, &live_control).await?;
        }
        cursor = send_latest_catchup(job, cursor, &live_control).await?;
        drop(_continuation_guard);
        return run_live(job, cursor, live_control).await;
    }

    job.registry.complete_barrier(&job.lease, epoch_ms()?)?;
    drop(initial_guard.take());

    let live_control = job.control.without_deadline();
    run_live(job, inner, live_control).await
}

async fn run_live(
    job: &mut PumpJob,
    mut cursor: StreamCursor,
    live_control: TransferEgressControl,
) -> Result<(), PumpError> {
    loop {
        ensure_current(job)?;
        let high_water = {
            let registration = job.registration.as_mut().ok_or(PumpError::MissingSource)?;
            tokio::select! {
                biased;
                _ = live_control.cancelled() => return Ok(()),
                result = registration.watch.next_committed() => {
                    result.map_err(|_| PumpError::Cancelled)?
                }
            }
        };
        if !cursor_is_newer(high_water, cursor) {
            continue;
        }
        job.registry.admit_live_enqueue(&job.lease, epoch_ms()?)?;
        let plan = controlled_with(
            &live_control,
            job.store
                .acquire_backfill_pin(backfill_target(job.target), cursor.high_water()),
        )
        .await??;
        let RuntimeBackfillPlan::Pinned(pin) = plan else {
            cursor = high_water;
            continue;
        };
        let cleanup = job
            .registration
            .as_ref()
            .ok_or(PumpError::MissingSource)?
            .watch
            .backfill_pin_cleanup(pin.pin_id);
        let source = PinnedBackfillSource::new(pin.clone(), cleanup);
        let gate = job.gate.clone();
        let _live_guard = controlled_with(&live_control, gate.lock()).await?;
        ensure_current(job)?;
        cursor = send_pinned_with_control(job, source, false, &live_control).await?;
    }
}

async fn send_latest_catchup(
    job: &mut PumpJob,
    cursor: StreamCursor,
    control: &TransferEgressControl,
) -> Result<StreamCursor, PumpError> {
    let latest = job
        .registration
        .as_ref()
        .ok_or(PumpError::MissingSource)?
        .watch
        .latest();
    if !cursor_is_newer(latest, cursor) {
        return Ok(cursor);
    }
    job.registry.admit_live_enqueue(&job.lease, epoch_ms()?)?;
    let plan = controlled_with(
        control,
        job.store
            .acquire_backfill_pin(backfill_target(job.target), cursor.high_water()),
    )
    .await??;
    let RuntimeBackfillPlan::Pinned(pin) = plan else {
        return Ok(latest);
    };
    let cleanup = job
        .registration
        .as_ref()
        .ok_or(PumpError::MissingSource)?
        .watch
        .backfill_pin_cleanup(pin.pin_id);
    send_pinned_with_control(job, PinnedBackfillSource::new(pin, cleanup), false, control).await
}

async fn wait_transition_business_ready(job: &PumpJob) -> Result<(), PumpError> {
    loop {
        ensure_current(job)?;
        match job
            .store
            .check_remote_transition_ingress(RemoteTransitionIngressClass::Business)
            .await
        {
            Ok(()) => return Ok(()),
            Err(RuntimeStoreError::InvalidStateTransition) => {
                controlled(
                    job,
                    tokio::time::sleep(std::time::Duration::from_millis(10)),
                )
                .await?;
            }
            Err(error) => return Err(PumpError::Store(error)),
        }
    }
}

fn validate_transition_registration(
    target: RuntimeStreamTarget,
    registration: &StreamBarrierRegistration,
    permit: &TransitionSnapshotPermit,
) -> Result<(), PumpError> {
    let scope_matches = match (target, permit.scope()) {
        (
            RuntimeStreamTarget::Catalog,
            super::super::store::key_transition::KeyTransitionStreamScope::Catalog,
        ) => true,
        (
            RuntimeStreamTarget::Conversation(conversation_id),
            super::super::store::key_transition::KeyTransitionStreamScope::Conversation(bytes),
        ) => conversation_id.as_bytes() == &bytes,
        _ => false,
    };
    let frozen = StreamCursor::from_high_water(permit.relay_committed_inner());
    if !scope_matches
        || registration.target != target
        || registration.high_water != frozen
        || registration.relay_committed.publication_stream_id
            != Some(permit.publication_stream_id())
        || registration.relay_committed.generation != Some(permit.generation())
        || registration.relay_committed.outer
            != StreamCursor::from_high_water(permit.relay_committed_outer())
        || registration.relay_committed.inner != frozen
    {
        return Err(PumpError::MissingSource);
    }
    Ok(())
}

fn transition_wire_generation(
    permit: &TransitionSnapshotPermit,
) -> agentdeck_protocol::runtime::identity::StreamGeneration {
    agentdeck_protocol::runtime::identity::StreamGeneration::new(
        uuid::Uuid::from_bytes(permit.generation())
            .hyphenated()
            .to_string(),
    )
}

fn validate_transition_conversation_snapshot(
    target: RuntimeId,
    snapshot: &agentdeck_protocol::runtime::ConversationSnapshot,
    permit: &TransitionSnapshotPermit,
) -> Result<(), PumpError> {
    let super::super::store::key_transition::KeyTransitionStreamScope::Conversation(expected) =
        permit.scope()
    else {
        return Err(PumpError::InvalidDto);
    };
    if target.as_bytes() != &expected
        || snapshot.conversation_id.as_str() != target.to_canonical_string()
        || snapshot.base_event_cursor
            != StreamCursor::from_high_water(permit.relay_committed_inner())
    {
        return Err(PumpError::InvalidDto);
    }
    Ok(())
}

fn validate_transition_catalog_snapshot(
    snapshot: &agentdeck_protocol::runtime::CatalogSnapshot,
    permit: &TransitionSnapshotPermit,
) -> Result<(), PumpError> {
    if permit.scope() != super::super::store::key_transition::KeyTransitionStreamScope::Catalog
        || snapshot.base_catalog_cursor
            != StreamCursor::from_high_water(permit.relay_committed_inner())
    {
        return Err(PumpError::InvalidDto);
    }
    Ok(())
}

async fn send_snapshot(job: &mut PumpJob) -> Result<StreamCursor, PumpError> {
    match job.target {
        RuntimeStreamTarget::Conversation(conversation_id) => {
            let source = job
                .registration
                .as_mut()
                .ok_or(PumpError::MissingSource)?
                .take_snapshot_source()
                .ok_or(PumpError::MissingSource)?;
            let control = job.control.clone();
            let reduced = controlled_with(
                &control,
                super::reducer::materialize(
                    &job.store,
                    job.router.clone(),
                    source,
                    job.snapshot_build_budget.clone(),
                    job.snapshot_build_gate.clone(),
                ),
            )
            .await??;
            let (snapshot, payload, history_command_ids, memory_permit) = reduced.into_parts();
            let base = snapshot.base_event_cursor;
            if let Some(permit) = job.transition_snapshot.as_ref() {
                validate_transition_conversation_snapshot(conversation_id, &snapshot, permit)?;
            }
            ensure_current(job)?;
            if let Some(command_ids) = history_command_ids {
                // 只有完整 adapter read、identity collision gate 与 canonical serialize
                // 全部成功后才原子替换。它必须先于任何不可逆 egress，确保客户端一旦
                // 看到 history commandId，其他连接的 QueryReceipt 已可稳定命中。
                job.history_receipts.replace(conversation_id, command_ids)?;
            }
            ensure_current(job)?;
            reply::reply(
                &job.connections,
                job.connection_id,
                job.message_id.clone(),
                RuntimeReply::Snapshot(snapshot),
                Some(payload.canonical_payload()),
                &job.control,
            )
            .await?;
            job.flushed_business_frame = true;
            // FlushReceipt 前 durable/ephemeral payload owner、typed snapshot 与共享
            // build permit 始终共同存活；Dynamic 成功后再显式释放 exact TEMP pin。
            payload
                .release_after_flush(&job.store, job.router.clone())
                .await?;
            drop(memory_permit);
            Ok(base)
        }
        RuntimeStreamTarget::Catalog => {
            let provider = job.catalog_snapshots.clone();
            let principal = job.principal.clone();
            let control = job.control.clone();
            let mut page = controlled_with(
                &control,
                provider.first_page(
                    job.registration.as_mut().ok_or(PumpError::MissingSource)?,
                    &principal,
                ),
            )
            .await??;
            let base = page.snapshot().base_catalog_cursor;
            if let Some(permit) = job.transition_snapshot.as_ref() {
                validate_transition_catalog_snapshot(page.snapshot(), permit)?;
            }
            loop {
                let next = page.snapshot().next_page_cursor().cloned();
                ensure_current(job)?;
                reply::reply(
                    &job.connections,
                    job.connection_id,
                    job.message_id.clone(),
                    RuntimeReply::Catalog(page.snapshot().clone()),
                    Some(page.payload()),
                    &job.control,
                )
                .await?;
                job.flushed_business_frame = true;
                let Some(next) = next else {
                    break;
                };
                drop(page);
                page = controlled_with(&control, provider.page_for_cursor(&next, &principal))
                    .await??;
                if page.snapshot().base_catalog_cursor != base {
                    return Err(PumpError::InvalidDto);
                }
            }
            Ok(base)
        }
    }
}

async fn send_pinned(
    job: &mut PumpJob,
    source: PinnedBackfillSource,
    directed: bool,
) -> Result<StreamCursor, PumpError> {
    let control = job.control.clone();
    send_pinned_with_control(job, source, directed, &control).await
}

async fn send_pinned_with_control(
    job: &mut PumpJob,
    mut source: PinnedBackfillSource,
    directed: bool,
    control: &TransferEgressControl,
) -> Result<StreamCursor, PumpError> {
    let pin = source.pin().clone();
    let mut after = pin.after;
    let capabilities = match pin.target {
        RuntimeBackfillTarget::Conversation(conversation_id) => {
            Some(controlled_with(control, conversation_capabilities(job, conversation_id)).await??)
        }
        RuntimeBackfillTarget::Catalog => None,
    };
    loop {
        ensure_current(job)?;
        match pin.target {
            RuntimeBackfillTarget::Conversation(conversation_id) => {
                let page = controlled_with(
                    control,
                    job.store.load_event_backfill_page(pin.clone(), after),
                )
                .await??;
                let completion = page.completion().clone();
                if directed {
                    let range = BackfillRange::new(
                        StreamCursor::from_high_water(after),
                        StreamCursor::At(page.next_after),
                    )
                    .map_err(|_| PumpError::InvalidDto)?;
                    let chunk = BackfillChunk::conversation(
                        ConversationId::new(conversation_id.to_canonical_string()),
                        capabilities.clone().ok_or(PumpError::InvalidDto)?,
                        range,
                        page.events,
                    )
                    .map_err(|_| PumpError::InvalidDto)?;
                    let payload = serde_json::to_vec(&chunk).map_err(|_| PumpError::InvalidDto)?;
                    ensure_current(job)?;
                    reply::reply(
                        &job.connections,
                        job.connection_id,
                        job.message_id.clone(),
                        RuntimeReply::Backfill(chunk),
                        Some(&payload),
                        control,
                    )
                    .await?;
                    job.flushed_business_frame = true;
                } else {
                    for event in page.events {
                        ensure_current(job)?;
                        let event_id = RuntimeId::parse_canonical(
                            RuntimeIdKind::Event,
                            event.event_id.as_str(),
                        )
                        .map_err(|_| PumpError::InvalidDto)?;
                        let durable_source = DurableStreamSource::Event {
                            conversation_id,
                            event_id,
                            event_seq: event.event_seq,
                        };
                        let payload =
                            serde_json::to_vec(&event).map_err(|_| PumpError::InvalidDto)?;
                        reply::stream(
                            &job.connections,
                            job.connection_id,
                            durable_source,
                            RuntimeStreamItem::Event(event),
                            Some(&payload),
                            control,
                        )
                        .await?;
                        job.flushed_business_frame = true;
                    }
                }
                let complete = page.complete;
                after = Some(page.next_after);
                controlled_with(control, job.store.complete_backfill_page(completion)).await??;
                if complete {
                    break;
                }
            }
            RuntimeBackfillTarget::Catalog => {
                let page = controlled_with(
                    control,
                    job.store.load_catalog_backfill_page(pin.clone(), after),
                )
                .await??;
                let completion = page.completion().clone();
                if directed {
                    let range = BackfillRange::new(
                        StreamCursor::from_high_water(after),
                        StreamCursor::At(page.next_after),
                    )
                    .map_err(|_| PumpError::InvalidDto)?;
                    let chunk = BackfillChunk::catalog(range, page.deltas)
                        .map_err(|_| PumpError::InvalidDto)?;
                    let payload = serde_json::to_vec(&chunk).map_err(|_| PumpError::InvalidDto)?;
                    ensure_current(job)?;
                    reply::reply(
                        &job.connections,
                        job.connection_id,
                        job.message_id.clone(),
                        RuntimeReply::Backfill(chunk),
                        Some(&payload),
                        control,
                    )
                    .await?;
                    job.flushed_business_frame = true;
                } else {
                    for delta in page.deltas {
                        ensure_current(job)?;
                        let durable_source = DurableStreamSource::Catalog {
                            first_revision: delta.catalog_revision,
                            through_revision: delta.catalog_revision,
                        };
                        let payload =
                            serde_json::to_vec(&delta).map_err(|_| PumpError::InvalidDto)?;
                        reply::stream(
                            &job.connections,
                            job.connection_id,
                            durable_source,
                            RuntimeStreamItem::CatalogDelta(delta),
                            Some(&payload),
                            control,
                        )
                        .await?;
                        job.flushed_business_frame = true;
                    }
                }
                let complete = page.complete;
                after = Some(page.next_after);
                controlled_with(control, job.store.complete_backfill_page(completion)).await??;
                if complete {
                    break;
                }
            }
        }
    }
    controlled_with(control, job.store.release_backfill_pin(pin.pin_id)).await??;
    source.disarm_after_release();
    Ok(StreamCursor::At(pin.through))
}

async fn conversation_capabilities(
    job: &PumpJob,
    conversation_id: RuntimeId,
) -> Result<SessionCapabilities, PumpError> {
    let context = job
        .store
        .load_authenticated_conversation_snapshot_context(conversation_id)
        .await?;
    job.router
        .capabilities(context.agent_kind)
        .filter(|value| value.agent_kind == context.agent_kind)
        .ok_or(PumpError::InvalidDto)
}

async fn send_failure(job: &mut PumpJob, message: &str) -> Result<(), PumpError> {
    use agentdeck_protocol::runtime::failure::DAEMON_RUNTIME_READ_UNAVAILABLE;
    reply::reply(
        &job.connections,
        job.connection_id,
        job.message_id.clone(),
        RuntimeReply::Failure(RuntimeFailure::new(
            DAEMON_RUNTIME_READ_UNAVAILABLE,
            message,
        )),
        None,
        &job.control,
    )
    .await?;
    job.flushed_business_frame = true;
    Ok(())
}

fn ensure_current(job: &PumpJob) -> Result<(), PumpError> {
    if job.lease.is_cancelled() || job.control.is_cancelled() {
        Err(PumpError::Cancelled)
    } else {
        Ok(())
    }
}

async fn controlled<T>(
    job: &PumpJob,
    operation: impl std::future::Future<Output = T>,
) -> Result<T, PumpError> {
    controlled_with(&job.control, operation).await
}

async fn controlled_with<T>(
    control: &TransferEgressControl,
    operation: impl std::future::Future<Output = T>,
) -> Result<T, PumpError> {
    if let Some(deadline) = control.absolute_deadline() {
        tokio::select! {
            biased;
            _ = control.cancelled() => Err(PumpError::Cancelled),
            _ = tokio::time::sleep_until(deadline) => Err(PumpError::Expired),
            value = operation => Ok(value),
        }
    } else {
        tokio::select! {
            biased;
            _ = control.cancelled() => Err(PumpError::Cancelled),
            value = operation => Ok(value),
        }
    }
}

fn inner_cursor(target: RuntimeStreamTarget, cursor: StreamCursor) -> RuntimeInnerCursor {
    match target {
        RuntimeStreamTarget::Catalog => RuntimeInnerCursor::Catalog { cursor },
        RuntimeStreamTarget::Conversation(conversation_id) => RuntimeInnerCursor::Conversation {
            conversation_id: ConversationId::new(conversation_id.to_canonical_string()),
            cursor,
        },
    }
}

fn backfill_target(target: RuntimeStreamTarget) -> RuntimeBackfillTarget {
    match target {
        RuntimeStreamTarget::Catalog => RuntimeBackfillTarget::Catalog,
        RuntimeStreamTarget::Conversation(conversation_id) => {
            RuntimeBackfillTarget::Conversation(conversation_id)
        }
    }
}

fn cursor_is_newer(candidate: StreamCursor, current: StreamCursor) -> bool {
    match (candidate.high_water(), current.high_water()) {
        (Some(_), None) => true,
        (Some(candidate), Some(current)) => candidate > current,
        _ => false,
    }
}

fn epoch_ms() -> Result<u64, PumpError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| PumpError::Clock)?;
    u64::try_from(duration.as_millis()).map_err(|_| PumpError::Clock)
}

#[cfg(test)]
mod tests {
    use agentdeck_protocol::runtime::failure::DAEMON_PAYLOAD_ITEM_TOO_LARGE;

    use super::*;
    use crate::runtime::snapshot::SnapshotMaterializationError;
    use crate::runtime::subscription::reducer::SnapshotReducerError;

    #[test]
    fn legacy_v1_snapshot_expansion_keeps_payload_too_large_wire_code() {
        let error = PumpError::Snapshot(SnapshotReducerError::Materialize(
            SnapshotMaterializationError::PayloadTooLarge,
        ));

        assert_eq!(error.failure().code, DAEMON_PAYLOAD_ITEM_TOO_LARGE);
    }
}
