//! Persistent `remote watch` 的 authenticated subscription 编排。
//!
//! 本层持有 paired device lease，使用 sealed paired-state 中的 exact conversation
//! cursor 恢复订阅，并且只在 Runtime 已完成 reducer COMMIT 与 cumulative ACK 后把
//! JSONL record 交给调用方。Relay `RouteAccepted`、EOF 或 transport close 都不能冒充
//! daemon receipt / stream apply success。

#![cfg(unix)]

use std::fmt;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;

use agentdeck_crypto::rand_core::CryptoRng;
use agentdeck_protocol::runtime::{
    BackfillChunk, ConversationId, RuntimeEvent, RuntimeInnerCursor, RuntimeStreamItem,
    RuntimeSyncComplete, StreamCursor, SubscriptionReceipt,
};
use async_trait::async_trait;
use serde::Serialize;
use serde_json::value::RawValue;
use thiserror::Error;

use super::paired_machine::{
    PairedMachineIdentity, PairedPromotionError, VerifiedRevocationTerminal,
};
use super::production::PersistentRemoteComposition;
use super::relay_transport::{
    PairedRuntimeConnectError, PairedRuntimeConnectOutcome, RelayRuntimeTransport,
    connect_paired_runtime,
};
use super::runtime::{
    RemoteRuntime, RemoteRuntimeError, RemoteRuntimeInterruptible, RemoteStreamFrameOutcome,
    RemoteSubscriptionBootstrap, RemoteSubscriptionBootstrapItem, RemoteSubscriptionReducer,
    take_ready_interrupt,
};
use super::selector::PersistentMachineSelector;

const MAX_WATCH_REDUCER_RETAINED_BYTES: usize = 64 * 1024 * 1024;
pub(super) const MAX_WATCH_BOOTSTRAP_BYTES: usize = 63 * 1024 * 1024;
pub(super) const MAX_WATCH_BOOTSTRAP_RECORDS: usize = 4_096;

/// `ArcInner<Box<RawValue>>` 的两枚引用计数与 fat Box pointer。Vec slot 另行按
/// `size_of::<BufferedBootstrapRecord>()` 计入；allocator 私有 metadata 不属于 Rust
/// retained allocation contract。
const FROZEN_PAYLOAD_SHARED_ALLOCATION_OVERHEAD: usize =
    (2 * std::mem::size_of::<usize>()) + std::mem::size_of::<Box<RawValue>>();

/// Bootstrap payload 的 canonical JSON 冻结表示。它只保留一份 exact bytes；Reducer
/// clone 共享同一 allocation，CLI writer 必须通过 `Serialize`/`canonical_json` 直接嵌入，
/// 不能先转成 `serde_json::Value` 后再编码。
#[derive(Clone)]
pub struct FrozenWatchBootstrapPayload {
    raw: Arc<Box<RawValue>>,
}

impl FrozenWatchBootstrapPayload {
    #[must_use]
    pub fn canonical_json(&self) -> &[u8] {
        self.raw.get().as_bytes()
    }
}

impl fmt::Debug for FrozenWatchBootstrapPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FrozenWatchBootstrapPayload([REDACTED])")
    }
}

impl Serialize for FrozenWatchBootstrapPayload {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.raw.as_ref().serialize(serializer)
    }
}

/// 已通过 authenticated reducer/receipt 边界、可安全写入 CLI JSONL 的记录。
pub enum PersistentRemoteWatchRecord {
    BootstrapSnapshot {
        snapshot: FrozenWatchBootstrapPayload,
    },
    BootstrapBackfill {
        chunk: FrozenWatchBootstrapPayload,
    },
    Synchronized {
        requested_cursor: RuntimeInnerCursor,
        route_accepted: bool,
        subscription: SubscriptionReceipt,
        sync_complete: RuntimeSyncComplete,
    },
    Event {
        event: RuntimeEvent,
    },
    Control {
        control: PersistentRemoteWatchControl,
    },
    Stopped,
    Revoked,
}

impl fmt::Debug for PersistentRemoteWatchRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::BootstrapSnapshot { .. } => {
                "PersistentRemoteWatchRecord::BootstrapSnapshot([REDACTED])"
            }
            Self::BootstrapBackfill { .. } => {
                "PersistentRemoteWatchRecord::BootstrapBackfill([REDACTED])"
            }
            Self::Synchronized { .. } => "PersistentRemoteWatchRecord::Synchronized([REDACTED])",
            Self::Event { .. } => "PersistentRemoteWatchRecord::Event([REDACTED])",
            Self::Control { .. } => "PersistentRemoteWatchRecord::Control([REDACTED])",
            Self::Stopped => "PersistentRemoteWatchRecord::Stopped",
            Self::Revoked => "PersistentRemoteWatchRecord::Revoked",
        })
    }
}

/// 不携带 opaque route、key material 或 sealed bytes 的 stream control 观测。
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum PersistentRemoteWatchControl {
    AuthenticatedOverlap,
    AppliedDuplicate,
    TransferBuffered {
        received_parts: u32,
        part_count: u32,
    },
    TransferAlreadyComplete,
    Gap {
        need_stream_seq: u64,
        oldest_stream_seq: u64,
    },
    ReplayComplete {
        current_cursor: StreamCursor,
    },
    TransferBootstrapRequired {
        code: &'static str,
    },
    KeySyncPending {
        attempt: u8,
    },
    KeySyncRouteAccepted {
        attempt: u8,
    },
    KeyUpdateInstalled {
        key_directory_revision: u64,
        next_attempt: Option<u8>,
    },
    KeyUpdateAckRouteAccepted {
        key_directory_revision: u64,
    },
    EpochBarrierApplied {
        stream_seq: u64,
        key_directory_revision: u64,
        key_epoch: u64,
        already_applied: bool,
    },
    StreamAppliedAckRouteAccepted {
        applied_stream_seq: u64,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PersistentRemoteWatchExit {
    Interrupted,
    Revoked,
}

#[derive(Debug, Error)]
pub enum PersistentRemoteWatchError {
    #[error("persistent paired-machine recovery or open failed")]
    Paired(#[from] PairedPromotionError),
    #[error("persistent paired-machine Relay connection failed")]
    Connect(#[from] PairedRuntimeConnectError),
    #[error("persistent remote watch failed")]
    Runtime(#[from] RemoteRuntimeError),
    #[error("persistent remote watch output failed")]
    Output(#[source] io::Error),
    #[error("persistent remote watch signal handling failed")]
    Signal(#[source] io::Error),
}

impl PersistentRemoteWatchError {
    #[must_use]
    pub fn code(&self) -> &str {
        match self {
            Self::Paired(error) => error.code(),
            Self::Connect(error) => error.code(),
            Self::Runtime(error) => error.code(),
            Self::Output(_) => "remote.watch.output_failed",
            Self::Signal(_) => "remote.watch.signal_failed",
        }
    }
}

pub(super) enum WatchRuntimeConnectOutcome<T> {
    Connected(T),
    Revoked,
}

pub(super) struct WatchBootstrap {
    route_accepted: bool,
    subscription: SubscriptionReceipt,
    sync_complete: RuntimeSyncComplete,
}

impl WatchBootstrap {
    pub(super) const fn new(
        route_accepted: bool,
        subscription: SubscriptionReceipt,
        sync_complete: RuntimeSyncComplete,
    ) -> Self {
        Self {
            route_accepted,
            subscription,
            sync_complete,
        }
    }

    fn from_runtime(bootstrap: RemoteSubscriptionBootstrap) -> Result<Self, RemoteRuntimeError> {
        if !matches!(
            bootstrap.subscription(),
            SubscriptionReceipt::Subscribed { .. }
        ) {
            return Err(RemoteRuntimeError::InvalidReply(
                "remote watch subscription did not return Subscribed",
            ));
        }
        Ok(Self::new(
            bootstrap.route_accepted(),
            bootstrap.subscription().clone(),
            bootstrap.sync_complete().clone(),
        ))
    }
}

pub(super) enum WatchSubscribeOutcome<Revocation> {
    Bootstrapped(WatchBootstrap),
    RevocationCommitted(Revocation),
}

pub(super) enum WatchStreamOutcome<Revocation = ()> {
    Runtime(RemoteStreamFrameOutcome),
    RevocationCommitted(Revocation),
}

#[async_trait(?Send)]
pub(super) trait ConnectedWatchRuntime<R>: Sized
where
    R: CryptoRng,
{
    type Revocation;

    fn subscription_restart_cursor(
        &self,
        fresh_target: RuntimeInnerCursor,
    ) -> Result<RuntimeInnerCursor, RemoteRuntimeError>;

    async fn subscribe<C>(
        &mut self,
        cursor: RuntimeInnerCursor,
        reducer: &mut WatchReducer,
        rng: &mut R,
        cancel: Pin<&mut C>,
    ) -> Result<
        RemoteRuntimeInterruptible<WatchSubscribeOutcome<Self::Revocation>, io::Result<()>>,
        RemoteRuntimeError,
    >
    where
        C: Future<Output = io::Result<()>> + ?Sized;

    async fn receive<C>(
        &mut self,
        reducer: &mut WatchReducer,
        cancel: Pin<&mut C>,
    ) -> Result<
        RemoteRuntimeInterruptible<WatchStreamOutcome<Self::Revocation>, io::Result<()>>,
        RemoteRuntimeError,
    >
    where
        C: Future<Output = io::Result<()>> + ?Sized;

    async fn commit_live_revocation(
        self,
        terminal: Self::Revocation,
    ) -> Result<(), RemoteRuntimeError>;

    async fn shutdown(self);
}

#[async_trait(?Send)]
impl<'a, R> ConnectedWatchRuntime<R> for Box<RemoteRuntime<'a, RelayRuntimeTransport>>
where
    R: CryptoRng,
{
    type Revocation = VerifiedRevocationTerminal;

    fn subscription_restart_cursor(
        &self,
        fresh_target: RuntimeInnerCursor,
    ) -> Result<RuntimeInnerCursor, RemoteRuntimeError> {
        RemoteRuntime::subscription_restart_cursor(self.as_ref(), fresh_target)
    }

    async fn subscribe<C>(
        &mut self,
        cursor: RuntimeInnerCursor,
        reducer: &mut WatchReducer,
        rng: &mut R,
        cancel: Pin<&mut C>,
    ) -> Result<
        RemoteRuntimeInterruptible<WatchSubscribeOutcome<Self::Revocation>, io::Result<()>>,
        RemoteRuntimeError,
    >
    where
        C: Future<Output = io::Result<()>> + ?Sized,
    {
        match RemoteRuntime::subscribe_interruptible(self.as_mut(), cursor, reducer, rng, cancel)
            .await
        {
            Ok(RemoteRuntimeInterruptible::Completed(bootstrap)) => {
                Ok(RemoteRuntimeInterruptible::Completed(
                    WatchSubscribeOutcome::Bootstrapped(WatchBootstrap::from_runtime(bootstrap)?),
                ))
            }
            Ok(RemoteRuntimeInterruptible::CompletedAndInterrupted {
                output: bootstrap,
                interrupt,
            }) => Ok(RemoteRuntimeInterruptible::CompletedAndInterrupted {
                output: WatchSubscribeOutcome::Bootstrapped(WatchBootstrap::from_runtime(
                    bootstrap,
                )?),
                interrupt,
            }),
            Ok(RemoteRuntimeInterruptible::Interrupted(interrupt)) => {
                Ok(RemoteRuntimeInterruptible::Interrupted(interrupt))
            }
            Ok(RemoteRuntimeInterruptible::FailedAndInterrupted { error, interrupt }) => {
                Ok(RemoteRuntimeInterruptible::FailedAndInterrupted { error, interrupt })
            }
            Err(RemoteRuntimeError::RevocationCommitted(terminal)) => {
                Ok(RemoteRuntimeInterruptible::Completed(
                    WatchSubscribeOutcome::RevocationCommitted(terminal),
                ))
            }
            Err(error) => Err(error),
        }
    }

    async fn receive<C>(
        &mut self,
        reducer: &mut WatchReducer,
        cancel: Pin<&mut C>,
    ) -> Result<
        RemoteRuntimeInterruptible<WatchStreamOutcome<Self::Revocation>, io::Result<()>>,
        RemoteRuntimeError,
    >
    where
        C: Future<Output = io::Result<()>> + ?Sized,
    {
        match RemoteRuntime::receive_stream_frame_interruptible(self.as_mut(), reducer, cancel)
            .await?
        {
            RemoteRuntimeInterruptible::Completed(
                RemoteStreamFrameOutcome::RevocationCommitted { terminal },
            ) => Ok(RemoteRuntimeInterruptible::Completed(
                WatchStreamOutcome::RevocationCommitted(terminal),
            )),
            RemoteRuntimeInterruptible::Completed(outcome) => Ok(
                RemoteRuntimeInterruptible::Completed(WatchStreamOutcome::Runtime(outcome)),
            ),
            RemoteRuntimeInterruptible::CompletedAndInterrupted {
                output: RemoteStreamFrameOutcome::RevocationCommitted { terminal },
                interrupt,
            } => Ok(RemoteRuntimeInterruptible::CompletedAndInterrupted {
                output: WatchStreamOutcome::RevocationCommitted(terminal),
                interrupt,
            }),
            RemoteRuntimeInterruptible::CompletedAndInterrupted { output, interrupt } => {
                Ok(RemoteRuntimeInterruptible::CompletedAndInterrupted {
                    output: WatchStreamOutcome::Runtime(output),
                    interrupt,
                })
            }
            RemoteRuntimeInterruptible::Interrupted(interrupt) => {
                Ok(RemoteRuntimeInterruptible::Interrupted(interrupt))
            }
            RemoteRuntimeInterruptible::FailedAndInterrupted { error, interrupt } => {
                Ok(RemoteRuntimeInterruptible::FailedAndInterrupted { error, interrupt })
            }
        }
    }

    async fn commit_live_revocation(
        self,
        terminal: Self::Revocation,
    ) -> Result<(), RemoteRuntimeError> {
        RemoteRuntime::commit_live_revocation(*self, terminal).await
    }

    async fn shutdown(self) {
        RemoteRuntime::shutdown(*self).await;
    }
}

enum BufferedBootstrapRecord {
    Snapshot(FrozenWatchBootstrapPayload),
    Backfill(FrozenWatchBootstrapPayload),
}

pub(super) struct WatchReducer {
    conversation_id: ConversationId,
    cursor: RuntimeInnerCursor,
    buffered: Vec<BufferedBootstrapRecord>,
    retained_encoded_bytes: usize,
}

impl Clone for WatchReducer {
    fn clone(&self) -> Self {
        // Payload 由 Arc 共享；clone 只新分配固定上界的 slot array 与两个短 target ID，
        // 不会复制至多 63 MiB 的 bootstrap bytes。
        let mut buffered = Vec::with_capacity(MAX_WATCH_BOOTSTRAP_RECORDS);
        buffered.extend(self.buffered.iter().map(|record| match record {
            BufferedBootstrapRecord::Snapshot(payload) => {
                BufferedBootstrapRecord::Snapshot(payload.clone())
            }
            BufferedBootstrapRecord::Backfill(payload) => {
                BufferedBootstrapRecord::Backfill(payload.clone())
            }
        }));
        Self {
            conversation_id: self.conversation_id.clone(),
            cursor: self.cursor.clone(),
            buffered,
            retained_encoded_bytes: self.retained_encoded_bytes,
        }
    }
}

#[derive(Clone, Copy)]
enum BufferedBootstrapKind {
    Snapshot,
    Backfill,
}

#[derive(Default)]
struct SerializedLength(usize);

impl io::Write for SerializedLength {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 = self
            .0
            .checked_add(bytes.len())
            .ok_or_else(|| io::Error::other("serialized watch payload length overflow"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum WatchOutputBudgetError {
    RecordLimit,
    ByteLimit,
}

pub(super) fn checked_bootstrap_output_budget(
    current_records: usize,
    current_bytes: usize,
    next_bytes: usize,
) -> Result<(usize, usize), WatchOutputBudgetError> {
    let records = current_records
        .checked_add(1)
        .filter(|records| *records <= MAX_WATCH_BOOTSTRAP_RECORDS)
        .ok_or(WatchOutputBudgetError::RecordLimit)?;
    let bytes = current_bytes
        .checked_add(next_bytes)
        .filter(|bytes| *bytes <= MAX_WATCH_BOOTSTRAP_BYTES)
        .ok_or(WatchOutputBudgetError::ByteLimit)?;
    Ok((records, bytes))
}

impl WatchReducer {
    #[cfg(test)]
    pub(super) fn new(conversation_id: ConversationId) -> Self {
        Self {
            cursor: RuntimeInnerCursor::Conversation {
                conversation_id: conversation_id.clone(),
                cursor: StreamCursor::BeforeFirst,
            },
            conversation_id,
            buffered: Vec::with_capacity(MAX_WATCH_BOOTSTRAP_RECORDS),
            retained_encoded_bytes: 0,
        }
    }

    fn from_cursor(cursor: RuntimeInnerCursor) -> Result<Self, RemoteRuntimeError> {
        let RuntimeInnerCursor::Conversation {
            conversation_id, ..
        } = &cursor
        else {
            return Err(RemoteRuntimeError::InvalidDurableState);
        };
        Ok(Self {
            conversation_id: conversation_id.clone(),
            cursor,
            buffered: Vec::with_capacity(MAX_WATCH_BOOTSTRAP_RECORDS),
            retained_encoded_bytes: 0,
        })
    }

    fn cursor(&self) -> &RuntimeInnerCursor {
        &self.cursor
    }

    pub(super) fn take_bootstrap_records(&mut self) -> Vec<PersistentRemoteWatchRecord> {
        self.retained_encoded_bytes = 0;
        self.buffered
            .drain(..)
            .map(|record| match record {
                BufferedBootstrapRecord::Snapshot(snapshot) => {
                    PersistentRemoteWatchRecord::BootstrapSnapshot { snapshot }
                }
                BufferedBootstrapRecord::Backfill(chunk) => {
                    PersistentRemoteWatchRecord::BootstrapBackfill { chunk }
                }
            })
            .collect()
    }

    fn retained_structural_bytes(&self) -> Result<usize, WatchOutputBudgetError> {
        let cursor_target_bytes = match &self.cursor {
            RuntimeInnerCursor::Conversation {
                conversation_id, ..
            } => conversation_id.0.capacity(),
            RuntimeInnerCursor::Catalog { .. } => return Err(WatchOutputBudgetError::ByteLimit),
        };
        std::mem::size_of::<Self>()
            .checked_add(
                self.buffered
                    .capacity()
                    .checked_mul(std::mem::size_of::<BufferedBootstrapRecord>())
                    .ok_or(WatchOutputBudgetError::ByteLimit)?,
            )
            .and_then(|bytes| bytes.checked_add(self.conversation_id.0.capacity()))
            .and_then(|bytes| bytes.checked_add(cursor_target_bytes))
            .ok_or(WatchOutputBudgetError::ByteLimit)
    }

    pub(super) fn checked_retain_budget(
        &self,
        next_encoded_bytes: usize,
    ) -> Result<(usize, usize, usize), WatchOutputBudgetError> {
        let (records, encoded_bytes) = checked_bootstrap_output_budget(
            self.buffered.len(),
            self.retained_encoded_bytes,
            next_encoded_bytes,
        )?;
        let shared_allocation_bytes = records
            .checked_mul(FROZEN_PAYLOAD_SHARED_ALLOCATION_OVERHEAD)
            .ok_or(WatchOutputBudgetError::ByteLimit)?;
        let retained_bytes = self
            .retained_structural_bytes()?
            .checked_add(encoded_bytes)
            .and_then(|bytes| bytes.checked_add(shared_allocation_bytes))
            .filter(|bytes| *bytes <= MAX_WATCH_REDUCER_RETAINED_BYTES)
            .ok_or(WatchOutputBudgetError::ByteLimit)?;
        Ok((records, encoded_bytes, retained_bytes))
    }

    fn retain_bootstrap<T: Serialize>(
        &mut self,
        value: &T,
        kind: BufferedBootstrapKind,
    ) -> Result<(), RemoteRuntimeError> {
        // 第一遍只计数，不分配 payload buffer；预算通过后才做唯一一次 exact encoding。
        let mut length = SerializedLength::default();
        serde_json::to_writer(&mut length, value)?;
        let (_, retained_encoded_bytes, _) = self
            .checked_retain_budget(length.0)
            .map_err(|_| RemoteRuntimeError::ReducerCapacity)?;

        let mut encoded = Vec::with_capacity(length.0);
        serde_json::to_writer(&mut encoded, value)?;
        if encoded.len() != length.0 {
            return Err(RemoteRuntimeError::InvalidReply(
                "remote watch payload changed between canonical length and freeze passes",
            ));
        }
        let encoded = String::from_utf8(encoded).map_err(|_| {
            RemoteRuntimeError::InvalidReply("remote watch payload is not UTF-8 JSON")
        })?;
        let raw = RawValue::from_string(encoded)?;
        if raw.get().len() != length.0 {
            return Err(RemoteRuntimeError::InvalidReply(
                "remote watch payload changed while freezing canonical JSON",
            ));
        }
        let payload = FrozenWatchBootstrapPayload { raw: Arc::new(raw) };
        let record = match kind {
            BufferedBootstrapKind::Snapshot => BufferedBootstrapRecord::Snapshot(payload),
            BufferedBootstrapKind::Backfill => BufferedBootstrapRecord::Backfill(payload),
        };
        self.retained_encoded_bytes = retained_encoded_bytes;
        self.buffered.push(record);
        Ok(())
    }
}

impl RemoteSubscriptionReducer for WatchReducer {
    const MAX_RETAINED_BYTES: usize = MAX_WATCH_REDUCER_RETAINED_BYTES;

    fn inner_cursor(&self) -> &RuntimeInnerCursor {
        &self.cursor
    }

    fn apply(&mut self, item: &RemoteSubscriptionBootstrapItem) -> Result<(), RemoteRuntimeError> {
        match item {
            RemoteSubscriptionBootstrapItem::ConversationSnapshot(snapshot)
                if snapshot.conversation_id == self.conversation_id =>
            {
                self.retain_bootstrap(snapshot, BufferedBootstrapKind::Snapshot)?;
                self.cursor = RuntimeInnerCursor::Conversation {
                    conversation_id: self.conversation_id.clone(),
                    cursor: snapshot.base_event_cursor,
                };
                Ok(())
            }
            RemoteSubscriptionBootstrapItem::Backfill(
                chunk @ BackfillChunk::Conversation {
                    conversation_id,
                    range,
                    ..
                },
            ) if conversation_id == &self.conversation_id
                && matches!(
                    &self.cursor,
                    RuntimeInnerCursor::Conversation { cursor, .. } if *cursor == range.after()
                ) =>
            {
                self.retain_bootstrap(chunk, BufferedBootstrapKind::Backfill)?;
                self.cursor = RuntimeInnerCursor::Conversation {
                    conversation_id: self.conversation_id.clone(),
                    cursor: range.through(),
                };
                Ok(())
            }
            RemoteSubscriptionBootstrapItem::CatalogSnapshot(_)
            | RemoteSubscriptionBootstrapItem::ConversationSnapshot(_)
            | RemoteSubscriptionBootstrapItem::Backfill(_) => {
                Err(RemoteRuntimeError::InvalidReply(
                    "remote watch reducer rejected a cross-target or discontinuous bootstrap item",
                ))
            }
        }
    }

    fn apply_live(&mut self, item: &RuntimeStreamItem) -> Result<(), RemoteRuntimeError> {
        let RuntimeStreamItem::Event(event) = item else {
            return Err(RemoteRuntimeError::InvalidReply(
                "remote watch received a non-conversation live item",
            ));
        };
        let RuntimeInnerCursor::Conversation {
            conversation_id,
            cursor,
        } = &self.cursor
        else {
            return Err(RemoteRuntimeError::InvalidDurableState);
        };
        if &event.conversation_id != conversation_id
            || cursor.checked_next().ok() != Some(event.event_seq)
        {
            return Err(RemoteRuntimeError::InvalidReply(
                "remote watch received a cross-target or discontinuous event",
            ));
        }
        self.cursor = RuntimeInnerCursor::Conversation {
            conversation_id: self.conversation_id.clone(),
            cursor: StreamCursor::At(event.event_seq),
        };
        Ok(())
    }
}

fn interruption(
    result: io::Result<()>,
) -> Result<PersistentRemoteWatchExit, PersistentRemoteWatchError> {
    result
        .map(|()| PersistentRemoteWatchExit::Interrupted)
        .map_err(PersistentRemoteWatchError::Signal)
}

fn emit_record<Emit>(
    emit: &mut Emit,
    record: PersistentRemoteWatchRecord,
) -> Result<(), PersistentRemoteWatchError>
where
    Emit: FnMut(PersistentRemoteWatchRecord) -> io::Result<()>,
{
    emit(record).map_err(PersistentRemoteWatchError::Output)
}

fn emit_bootstrap<Emit>(
    reducer: &mut WatchReducer,
    requested_cursor: RuntimeInnerCursor,
    bootstrap: WatchBootstrap,
    emit: &mut Emit,
) -> Result<(), PersistentRemoteWatchError>
where
    Emit: FnMut(PersistentRemoteWatchRecord) -> io::Result<()>,
{
    for record in reducer.take_bootstrap_records() {
        emit_record(emit, record)?;
    }
    emit_record(
        emit,
        PersistentRemoteWatchRecord::Synchronized {
            requested_cursor,
            route_accepted: bootstrap.route_accepted,
            subscription: bootstrap.subscription,
            sync_complete: bootstrap.sync_complete,
        },
    )
}

enum ConnectedWatchExit<Revocation> {
    Interrupted,
    RevocationCommitted(Revocation),
}

async fn watch_connected<R, Runtime, Cancel, Emit>(
    runtime: &mut Runtime,
    initial_cursor: RuntimeInnerCursor,
    rng: &mut R,
    mut cancel: Pin<&mut Cancel>,
    emit: &mut Emit,
) -> Result<ConnectedWatchExit<Runtime::Revocation>, PersistentRemoteWatchError>
where
    R: CryptoRng,
    Runtime: ConnectedWatchRuntime<R>,
    Cancel: Future<Output = io::Result<()>>,
    Emit: FnMut(PersistentRemoteWatchRecord) -> io::Result<()>,
{
    let initial_cursor = runtime.subscription_restart_cursor(initial_cursor)?;
    let mut reducer = WatchReducer::from_cursor(initial_cursor)?;

    'subscription: loop {
        let requested_cursor = reducer.cursor().clone();
        let (bootstrap, mut latched_interrupt) = match runtime
            .subscribe(requested_cursor.clone(), &mut reducer, rng, cancel.as_mut())
            .await?
        {
            RemoteRuntimeInterruptible::Completed(bootstrap) => (bootstrap, None),
            RemoteRuntimeInterruptible::CompletedAndInterrupted { output, interrupt } => {
                (output, Some(interrupt))
            }
            RemoteRuntimeInterruptible::Interrupted(signal) => {
                return interruption(signal).map(|_| ConnectedWatchExit::Interrupted);
            }
            RemoteRuntimeInterruptible::FailedAndInterrupted { error, .. } => {
                return Err(error.into());
            }
        };
        let bootstrap = match bootstrap {
            WatchSubscribeOutcome::Bootstrapped(bootstrap) => bootstrap,
            WatchSubscribeOutcome::RevocationCommitted(terminal) => {
                return Ok(ConnectedWatchExit::RevocationCommitted(terminal));
            }
        };
        emit_bootstrap(&mut reducer, requested_cursor, bootstrap, emit)?;
        if let Some(signal) = latched_interrupt.take() {
            return interruption(signal).map(|_| ConnectedWatchExit::Interrupted);
        }

        loop {
            let (outcome, mut latched_interrupt) =
                match runtime.receive(&mut reducer, cancel.as_mut()).await {
                    Ok(RemoteRuntimeInterruptible::Completed(outcome)) => (Ok(outcome), None),
                    Ok(RemoteRuntimeInterruptible::CompletedAndInterrupted {
                        output,
                        interrupt,
                    }) => (Ok(output), Some(interrupt)),
                    Ok(RemoteRuntimeInterruptible::Interrupted(signal)) => {
                        return interruption(signal).map(|_| ConnectedWatchExit::Interrupted);
                    }
                    Ok(RemoteRuntimeInterruptible::FailedAndInterrupted { error, interrupt }) => {
                        (Err(error), Some(interrupt))
                    }
                    Err(error) => (Err(error), None),
                };
            let outcome = match outcome {
                Ok(outcome) => outcome,
                Err(RemoteRuntimeError::TransferBootstrapRequired(error)) => {
                    emit_record(
                        emit,
                        PersistentRemoteWatchRecord::Control {
                            control: PersistentRemoteWatchControl::TransferBootstrapRequired {
                                code: error.code(),
                            },
                        },
                    )?;
                    if let Some(signal) = latched_interrupt.take() {
                        return interruption(signal).map(|_| ConnectedWatchExit::Interrupted);
                    }
                    continue 'subscription;
                }
                Err(error) => return Err(error.into()),
            };

            let outcome = match outcome {
                WatchStreamOutcome::Runtime(outcome) => outcome,
                WatchStreamOutcome::RevocationCommitted(terminal) => {
                    return Ok(ConnectedWatchExit::RevocationCommitted(terminal));
                }
            };
            let control = match outcome {
                RemoteStreamFrameOutcome::Applied(item) => {
                    let RuntimeStreamItem::Event(event) = *item else {
                        return Err(RemoteRuntimeError::InvalidReply(
                            "remote watch received a non-conversation applied item",
                        )
                        .into());
                    };
                    emit_record(emit, PersistentRemoteWatchRecord::Event { event })?;
                    if let Some(signal) = latched_interrupt.take() {
                        return interruption(signal).map(|_| ConnectedWatchExit::Interrupted);
                    }
                    continue;
                }
                RemoteStreamFrameOutcome::AuthenticatedOverlap => {
                    PersistentRemoteWatchControl::AuthenticatedOverlap
                }
                RemoteStreamFrameOutcome::AppliedDuplicate => {
                    PersistentRemoteWatchControl::AppliedDuplicate
                }
                RemoteStreamFrameOutcome::TransferBuffered {
                    received_parts,
                    part_count,
                    ..
                } => PersistentRemoteWatchControl::TransferBuffered {
                    received_parts,
                    part_count,
                },
                RemoteStreamFrameOutcome::TransferAlreadyComplete { .. } => {
                    PersistentRemoteWatchControl::TransferAlreadyComplete
                }
                RemoteStreamFrameOutcome::Gap {
                    need_stream_seq,
                    oldest_stream_seq,
                } => {
                    emit_record(
                        emit,
                        PersistentRemoteWatchRecord::Control {
                            control: PersistentRemoteWatchControl::Gap {
                                need_stream_seq,
                                oldest_stream_seq,
                            },
                        },
                    )?;
                    if let Some(signal) = latched_interrupt.take() {
                        return interruption(signal).map(|_| ConnectedWatchExit::Interrupted);
                    }
                    continue 'subscription;
                }
                RemoteStreamFrameOutcome::ReplayComplete { current_cursor } => {
                    PersistentRemoteWatchControl::ReplayComplete { current_cursor }
                }
                RemoteStreamFrameOutcome::KeySyncPending { attempt } => {
                    PersistentRemoteWatchControl::KeySyncPending { attempt }
                }
                RemoteStreamFrameOutcome::KeySyncRouteAccepted { attempt } => {
                    PersistentRemoteWatchControl::KeySyncRouteAccepted { attempt }
                }
                RemoteStreamFrameOutcome::KeyUpdateInstalled {
                    key_directory_revision,
                    next_attempt,
                } => PersistentRemoteWatchControl::KeyUpdateInstalled {
                    key_directory_revision,
                    next_attempt,
                },
                RemoteStreamFrameOutcome::KeyUpdateAckRouteAccepted {
                    key_directory_revision,
                } => PersistentRemoteWatchControl::KeyUpdateAckRouteAccepted {
                    key_directory_revision,
                },
                RemoteStreamFrameOutcome::EpochBarrierApplied {
                    stream_seq,
                    key_directory_revision,
                    key_epoch,
                    already_applied,
                } => PersistentRemoteWatchControl::EpochBarrierApplied {
                    stream_seq,
                    key_directory_revision,
                    key_epoch,
                    already_applied,
                },
                RemoteStreamFrameOutcome::StreamAppliedAckRouteAccepted {
                    applied_stream_seq,
                    ..
                } => PersistentRemoteWatchControl::StreamAppliedAckRouteAccepted {
                    applied_stream_seq,
                },
                RemoteStreamFrameOutcome::RevocationCommitted { .. } => {
                    return Err(RemoteRuntimeError::InvalidDurableState.into());
                }
            };
            emit_record(emit, PersistentRemoteWatchRecord::Control { control })?;
            if let Some(signal) = latched_interrupt.take() {
                return interruption(signal).map(|_| ConnectedWatchExit::Interrupted);
            }
        }
    }
}

/// 测试 seam 也复用的严格 recover → exact open → durable cursor readback → connect →
/// subscribe/live → shutdown 编排。
#[allow(clippy::too_many_arguments)]
pub(super) async fn execute_with<
    R,
    Store,
    Machine,
    Runtime,
    Recover,
    Open,
    Connect,
    ConnectFuture,
    Cancel,
    Emit,
>(
    selector: PersistentMachineSelector,
    conversation_id: ConversationId,
    rng: &mut R,
    cancel: Cancel,
    emit: &mut Emit,
    recover: Recover,
    open: Open,
    connect: Connect,
) -> Result<PersistentRemoteWatchExit, PersistentRemoteWatchError>
where
    R: CryptoRng,
    Runtime: ConnectedWatchRuntime<R>,
    Recover: FnOnce() -> Result<Store, PersistentRemoteWatchError>,
    Open: FnOnce(Store, PairedMachineIdentity) -> Result<Machine, PersistentRemoteWatchError>,
    Connect: FnOnce(Machine) -> ConnectFuture,
    ConnectFuture:
        Future<Output = Result<WatchRuntimeConnectOutcome<Runtime>, PersistentRemoteWatchError>>,
    Cancel: Future<Output = io::Result<()>>,
    Emit: FnMut(PersistentRemoteWatchRecord) -> io::Result<()>,
{
    let recovered = recover()?;
    let machine = open(recovered, selector.identity())?;
    // CLI 不持久化明文 reducer/transcript：默认从 BeforeFirst 请求 fresh snapshot；若 sealed
    // state 中仍有同 target Subscribe pending，connected runtime 会选择其原 cursor exact
    // retry。普通 durable inner HWM 仍不能冒充内存 reducer 状态。
    let initial_cursor = RuntimeInnerCursor::Conversation {
        conversation_id,
        cursor: StreamCursor::BeforeFirst,
    };
    tokio::pin!(cancel);
    let mut connection_future = Box::pin(connect(machine));
    let connection = tokio::select! {
        biased;
        result = connection_future.as_mut() => result?,
        signal = cancel.as_mut() => {
            // 先销毁仍拥有 machine/connector/可能 transport task 的 future，再公开 stopped。
            drop(connection_future);
            let exit = interruption(signal)?;
            emit_record(emit, PersistentRemoteWatchRecord::Stopped)?;
            return Ok(exit);
        },
    };
    drop(connection_future);
    let mut runtime = match connection {
        WatchRuntimeConnectOutcome::Connected(runtime) => runtime,
        WatchRuntimeConnectOutcome::Revoked => {
            // Connector contract 已保证 exact root-signed terminal、transport drop 与
            // crash-safe paired cleanup 全部完成；此处只公开 canonical revoked 终态。
            emit_record(emit, PersistentRemoteWatchRecord::Revoked)?;
            return Ok(PersistentRemoteWatchExit::Revoked);
        }
    };
    if let Some(signal) = take_ready_interrupt(cancel.as_mut()).await {
        runtime.shutdown().await;
        let exit = interruption(signal)?;
        emit_record(emit, PersistentRemoteWatchRecord::Stopped)?;
        return Ok(exit);
    }
    let result = watch_connected(&mut runtime, initial_cursor, rng, cancel.as_mut(), emit).await;
    match result {
        Ok(ConnectedWatchExit::Interrupted) => {
            runtime.shutdown().await;
            emit_record(emit, PersistentRemoteWatchRecord::Stopped)?;
            Ok(PersistentRemoteWatchExit::Interrupted)
        }
        Ok(ConnectedWatchExit::RevocationCommitted(terminal)) => {
            runtime.commit_live_revocation(terminal).await?;
            // 只有 transport shutdown/drop 与 paired cleanup 均已完成，才公开 revoked 终态。
            emit_record(emit, PersistentRemoteWatchRecord::Revoked)?;
            Ok(PersistentRemoteWatchExit::Revoked)
        }
        Err(error) => {
            runtime.shutdown().await;
            Err(error)
        }
    }
}

/// Production CLI 的唯一 persistent conversation watch 入口。
pub async fn watch_persistent_remote_conversation<R, Cancel, Emit>(
    composition: &PersistentRemoteComposition,
    selector: PersistentMachineSelector,
    conversation_id: ConversationId,
    rng: &mut R,
    cancel: Cancel,
    mut emit: Emit,
) -> Result<PersistentRemoteWatchExit, PersistentRemoteWatchError>
where
    R: CryptoRng,
    Cancel: Future<Output = io::Result<()>>,
    Emit: FnMut(PersistentRemoteWatchRecord) -> io::Result<()>,
{
    execute_with(
        selector,
        conversation_id,
        rng,
        cancel,
        &mut emit,
        || {
            composition
                .recovered_paired_machine_store()
                .map_err(PersistentRemoteWatchError::Paired)
        },
        |recovered, identity| {
            recovered
                .open_exact(identity)
                .map_err(PersistentRemoteWatchError::Paired)
        },
        |machine| async move {
            match connect_paired_runtime(machine)
                .await
                .map_err(PersistentRemoteWatchError::Connect)?
            {
                PairedRuntimeConnectOutcome::Connected(runtime) => {
                    Ok(WatchRuntimeConnectOutcome::Connected(runtime))
                }
                PairedRuntimeConnectOutcome::Revoked => Ok(WatchRuntimeConnectOutcome::Revoked),
            }
        },
    )
    .await
}
