//! Runtime canonical stream 的 COMMIT high-water 通知与 subscription capture。
//!
//! watcher 只合并 durable high-water，不保存 event/catalog payload；实际 catch-up
//! 始终回到 Runtime store 的 authenticated replay index。

use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use agentdeck_protocol::runtime::StreamCursor;
use tokio::sync::{mpsc, watch};

use super::backfill::{BarrierDecision, BarrierRequest};
use super::model::RuntimeStoreError;
use super::store::{
    ReadySnapshotReference, RuntimeBackfillPin, RuntimeId, RuntimeSnapshotBuildPin,
};

/// Catalog 与 conversation 共用的 stream target。
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RuntimeStreamTarget {
    Catalog,
    Conversation(RuntimeId),
}

/// 单个 SQLite transaction 在 COMMIT 前发现的精确 stream targets。
///
/// 该值本身不能用于通知；只有 transaction COMMIT 成功或 outcome unknown 时，
/// 才能 promote 到当前 command 的 durable-possible effects。
#[must_use]
#[derive(Default)]
pub(crate) struct PendingStreamTargets {
    targets: BTreeSet<RuntimeStreamTarget>,
}

impl PendingStreamTargets {
    pub(crate) fn insert(&mut self, target: RuntimeStreamTarget) {
        self.targets.insert(target);
    }
}

/// 一个 worker command 内所有已经 COMMIT 或可能已经 COMMIT 的精确 effects。
/// 多个前置/主/安全事务的 targets 在这里做 deterministic union。
#[must_use]
#[derive(Default)]
pub(crate) struct CommandStreamEffects {
    targets: BTreeSet<RuntimeStreamTarget>,
}

impl CommandStreamEffects {
    pub(crate) fn record_commit_result(
        &mut self,
        pending: PendingStreamTargets,
        result: &Result<(), RuntimeStoreError>,
    ) {
        if result.is_ok() || matches!(result, Err(RuntimeStoreError::CommitOutcomeUnknown { .. })) {
            self.targets.extend(pending.targets);
        }
    }

    #[must_use]
    pub(crate) fn is_empty(&self) -> bool {
        self.targets.is_empty()
    }

    pub(crate) fn targets(&self) -> impl Iterator<Item = RuntimeStreamTarget> + '_ {
        self.targets.iter().copied()
    }
}

/// 单 subscription 的本地 generation；零值无效，避免默认值被误当成 active。
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct WatchGeneration(u64);

impl WatchGeneration {
    pub fn new(value: u64) -> Option<Self> {
        (value != 0).then_some(Self(value))
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// watcher 的不可伪造本地坐标。旧 generation/token 不能释放或推进新 watcher。
#[derive(Clone)]
struct StoreCommitHubIncarnation(Arc<StoreCommitHubIncarnationMarker>);

struct StoreCommitHubIncarnationMarker {
    nonce: [u8; 16],
}

impl StoreCommitHubIncarnation {
    fn new(mut nonce: [u8; 16]) -> Self {
        // Incarnation 不能是零值。production nonce 来自 OS entropy；Default 仅供
        // 算法测试使用，Arc allocation 本身提供不会被 stale token 复用的 identity。
        if nonce == [0; 16] {
            nonce[0] = 1;
        }
        Self(Arc::new(StoreCommitHubIncarnationMarker { nonce }))
    }
}

impl PartialEq for StoreCommitHubIncarnation {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for StoreCommitHubIncarnation {}

impl Hash for StoreCommitHubIncarnation {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.nonce.hash(state);
        Arc::as_ptr(&self.0).hash(state);
    }
}

impl fmt::Debug for StoreCommitHubIncarnation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StoreCommitHubIncarnation([REDACTED])")
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct StoreWatchToken {
    incarnation: StoreCommitHubIncarnation,
    watch_id: u64,
    generation: WatchGeneration,
    target: RuntimeStreamTarget,
}

/// Drop 路径只发送不可伪造的本地 cleanup capability；唯一 store worker
/// 串行应用 watch 与 TEMP snapshot pin 回收。
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum StoreCleanup {
    Watch(StoreWatchToken),
    BackfillPin([u8; 16]),
    SnapshotBuildPin(RuntimeSnapshotBuildPin),
}

/// 已注册 watcher。receiver 中只有合并后的 HWM，没有 payload。
pub struct StoreWatch {
    token: StoreWatchToken,
    registered_after: StreamCursor,
    receiver: watch::Receiver<StreamCursor>,
    cleanup_tx: Option<mpsc::UnboundedSender<StoreCleanup>>,
}

impl StoreWatch {
    #[must_use]
    pub fn token(&self) -> StoreWatchToken {
        self.token.clone()
    }

    #[must_use]
    pub const fn generation(&self) -> WatchGeneration {
        self.token.generation
    }

    #[must_use]
    pub const fn registered_after(&self) -> StreamCursor {
        self.registered_after
    }

    pub fn next_sequence(&self) -> Result<u64, agentdeck_protocol::runtime::StreamCursorError> {
        self.registered_after.checked_next()
    }

    #[must_use]
    pub fn latest(&self) -> StreamCursor {
        *self.receiver.borrow()
    }

    /// 同步取走合并后的最新 HWM；相同 HWM 不会重复返回。
    pub fn take_coalesced(&mut self) -> Option<StreamCursor> {
        match self.receiver.has_changed() {
            Ok(true) => Some(*self.receiver.borrow_and_update()),
            Ok(false) | Err(_) => None,
        }
    }

    /// 等待下一次 durable HWM 推进。channel 只携带 cursor，不携带 payload。
    pub async fn next_committed(&mut self) -> Result<StreamCursor, StoreWatchClosed> {
        self.receiver
            .changed()
            .await
            .map_err(|_| StoreWatchClosed)?;
        Ok(*self.receiver.borrow_and_update())
    }

    pub(crate) fn snapshot_build_pin_cleanup(
        &self,
        pin: RuntimeSnapshotBuildPin,
    ) -> SnapshotBuildPinCleanup {
        SnapshotBuildPinCleanup::with_optional_sender(pin, self.cleanup_tx.clone())
    }

    pub(crate) fn backfill_pin_cleanup(&self, pin_id: [u8; 16]) -> BackfillPinCleanup {
        BackfillPinCleanup {
            pin_id: Some(pin_id),
            cleanup_tx: self.cleanup_tx.clone(),
        }
    }
}

impl Drop for StoreWatch {
    fn drop(&mut self) {
        if let Some(cleanup_tx) = &self.cleanup_tx {
            let _ = cleanup_tx.send(StoreCleanup::Watch(self.token.clone()));
        }
    }
}

pub(crate) struct SnapshotBuildPinCleanup {
    pin: Option<RuntimeSnapshotBuildPin>,
    cleanup_tx: Option<mpsc::UnboundedSender<StoreCleanup>>,
}

impl SnapshotBuildPinCleanup {
    pub(crate) fn new(
        pin: RuntimeSnapshotBuildPin,
        cleanup_tx: mpsc::UnboundedSender<StoreCleanup>,
    ) -> Self {
        Self::with_optional_sender(pin, Some(cleanup_tx))
    }

    fn with_optional_sender(
        pin: RuntimeSnapshotBuildPin,
        cleanup_tx: Option<mpsc::UnboundedSender<StoreCleanup>>,
    ) -> Self {
        Self {
            pin: Some(pin),
            cleanup_tx,
        }
    }

    pub(crate) fn disarm(&mut self) {
        self.pin.take();
    }
}

impl Drop for SnapshotBuildPinCleanup {
    fn drop(&mut self) {
        if let (Some(cleanup_tx), Some(pin)) = (&self.cleanup_tx, self.pin.take()) {
            let _ = cleanup_tx.send(StoreCleanup::SnapshotBuildPin(pin));
        }
    }
}

pub(crate) struct BackfillPinCleanup {
    pin_id: Option<[u8; 16]>,
    cleanup_tx: Option<mpsc::UnboundedSender<StoreCleanup>>,
}

impl BackfillPinCleanup {
    pub(crate) fn disarm(&mut self) {
        self.pin_id.take();
    }
}

impl Drop for BackfillPinCleanup {
    fn drop(&mut self) {
        if let (Some(cleanup_tx), Some(pin_id)) = (&self.cleanup_tx, self.pin_id.take()) {
            let _ = cleanup_tx.send(StoreCleanup::BackfillPin(pin_id));
        }
    }
}

pub(crate) struct PinnedBackfillSource {
    pin: RuntimeBackfillPin,
    cleanup: BackfillPinCleanup,
}

impl PinnedBackfillSource {
    pub(crate) fn new(pin: RuntimeBackfillPin, cleanup: BackfillPinCleanup) -> Self {
        Self { pin, cleanup }
    }

    pub(crate) fn pin(&self) -> &RuntimeBackfillPin {
        &self.pin
    }

    pub(crate) fn disarm_after_release(&mut self) {
        self.cleanup.disarm();
    }

    pub(crate) fn disarm(mut self) -> RuntimeBackfillPin {
        self.cleanup.disarm();
        self.pin
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("store commit watch is closed")]
pub struct StoreWatchClosed;

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum StoreCommitHubError {
    #[error("store commit watch identity is exhausted")]
    WatchIdentityExhausted,
}

#[derive(Debug, thiserror::Error)]
pub enum RegisterCaptureError<E> {
    #[error(transparent)]
    Hub(#[from] StoreCommitHubError),
    #[error("subscription barrier capture failed")]
    Capture(E),
}

/// Relay durable COMMIT 后可见的 outer/inner cut；无 stream 时两者均 BeforeFirst。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelayCommittedCut {
    pub publication_stream_id: Option<[u8; 16]>,
    pub generation: Option<[u8; 16]>,
    pub outer: StreamCursor,
    pub inner: StreamCursor,
    /// Store 从同一 authenticated publication row/cut 与 shared-key directory
    /// 捕获的 daemon-private binding capability；不会进入 Runtime DTO。
    pub(crate) stream_binding: Option<super::store::StreamBindingPermit>,
}

impl Default for RelayCommittedCut {
    fn default() -> Self {
        Self {
            publication_stream_id: None,
            generation: None,
            outer: StreamCursor::BeforeFirst,
            inner: StreamCursor::BeforeFirst,
            stream_binding: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegisterStreamBarrier {
    pub target: RuntimeStreamTarget,
    pub generation: WatchGeneration,
    pub request: BarrierRequest,
}

/// SubscriptionBarrier 已认证并冻结的 snapshot 来源。
///
/// `Ready` 绑定 exact durable row；`Build` / `TransitionBuild` / `Dynamic` 的 TEMP pin
/// 绑定本次 barrier 捕获的 conversation H。`TransitionBuild` 只读组装 exact H，不能
/// 覆盖已推进到 D 的 durable ready row；`Dynamic` 只能用于 authenticated
/// NativeProjected origin。调用方不得在 capture 后重新按“当前 H”申请另一枚 pin。
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SnapshotBarrierSource {
    Ready(ReadySnapshotReference),
    Build(RuntimeSnapshotBuildPin),
    TransitionBuild(RuntimeSnapshotBuildPin),
    Dynamic(RuntimeSnapshotBuildPin),
}

/// Catalog barrier 冻结的 durable baseline（fresh DB 为 None）与 exact H。
/// 该 source 只供 CatalogSnapshotProvider 消费，不冒充 conversation build pin。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CatalogSnapshotMaterializationMode {
    DurableRefresh,
    TransitionEphemeral,
}

pub struct CatalogSnapshotSource {
    mode: CatalogSnapshotMaterializationMode,
    baseline: Option<ReadySnapshotReference>,
    frozen: StreamCursor,
}

impl CatalogSnapshotSource {
    pub(crate) fn new(baseline: Option<ReadySnapshotReference>, frozen: StreamCursor) -> Self {
        Self {
            mode: CatalogSnapshotMaterializationMode::DurableRefresh,
            baseline,
            frozen,
        }
    }

    pub(crate) fn transition(
        baseline: Option<ReadySnapshotReference>,
        frozen: StreamCursor,
    ) -> Self {
        Self {
            mode: CatalogSnapshotMaterializationMode::TransitionEphemeral,
            baseline,
            frozen,
        }
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        CatalogSnapshotMaterializationMode,
        Option<ReadySnapshotReference>,
        StreamCursor,
    ) {
        (self.mode, self.baseline, self.frozen)
    }
}

/// Registration 捕获后交给 materializer 的线性 source lease。
///
/// `Build` source 与 exact TEMP pin cleanup guard 必须作为同一个不可 Clone 的值移动；
/// source 在进入 materializer 前被放弃时，guard 会通过唯一 store worker 回收 pin。
pub struct SnapshotMaterializationSource {
    source: SnapshotBarrierSource,
    cleanup: Option<SnapshotBuildPinCleanup>,
}

impl fmt::Debug for SnapshotMaterializationSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SnapshotMaterializationSource")
            .field("source", &self.source)
            .field("has_cleanup", &self.cleanup.is_some())
            .finish()
    }
}

impl SnapshotMaterializationSource {
    pub(crate) fn new(
        source: SnapshotBarrierSource,
        cleanup: Option<SnapshotBuildPinCleanup>,
    ) -> Self {
        Self { source, cleanup }
    }

    #[must_use]
    pub const fn source(&self) -> &SnapshotBarrierSource {
        &self.source
    }

    #[must_use]
    pub const fn build_pin(&self) -> Option<&RuntimeSnapshotBuildPin> {
        match &self.source {
            SnapshotBarrierSource::Build(pin)
            | SnapshotBarrierSource::TransitionBuild(pin)
            | SnapshotBarrierSource::Dynamic(pin) => Some(pin),
            SnapshotBarrierSource::Ready(_) => None,
        }
    }

    pub(crate) fn into_parts(self) -> (SnapshotBarrierSource, Option<SnapshotBuildPinCleanup>) {
        (self.source, self.cleanup)
    }

    pub(crate) fn into_build_pin_for_immediate_cleanup(
        mut self,
    ) -> Option<RuntimeSnapshotBuildPin> {
        let pin = match &self.source {
            SnapshotBarrierSource::Build(pin)
            | SnapshotBarrierSource::TransitionBuild(pin)
            | SnapshotBarrierSource::Dynamic(pin) => pin,
            SnapshotBarrierSource::Ready(_) => return None,
        };
        if let Some(cleanup) = &mut self.cleanup {
            cleanup.disarm();
        }
        Some(pin.clone())
    }
}

pub struct StreamBarrierRegistration {
    pub target: RuntimeStreamTarget,
    pub high_water: StreamCursor,
    pub retained_floor: Option<u64>,
    pub ready_snapshot_base: Option<StreamCursor>,
    /// 仅 `BarrierDecision::Snapshot` 可携带来源；Backfill/SyncComplete/
    /// NeedSnapshot/CursorAhead 均为 `None`。Catalog fresh DB 的 build source 留给后续 slice。
    pub(crate) snapshot_source: Option<SnapshotBarrierSource>,
    pub(crate) snapshot_cleanup: Option<SnapshotBuildPinCleanup>,
    pub(crate) catalog_snapshot_source: Option<CatalogSnapshotSource>,
    pub(crate) backfill_pin: Option<RuntimeBackfillPin>,
    pub(crate) backfill_cleanup: Option<BackfillPinCleanup>,
    pub relay_committed: RelayCommittedCut,
    pub decision: BarrierDecision,
    pub watch: StoreWatch,
}

impl StreamBarrierRegistration {
    #[must_use]
    pub fn snapshot_source(&self) -> Option<&SnapshotBarrierSource> {
        self.snapshot_source.as_ref()
    }

    /// 原子移动 source 与同一枚 build pin cleanup guard。返回值不可 Clone；在
    /// materializer 接管前 drop 也会回收 exact TEMP pin，不存在裸 pin handoff gap。
    pub fn take_snapshot_source(&mut self) -> Option<SnapshotMaterializationSource> {
        let source = self.snapshot_source.take()?;
        Some(SnapshotMaterializationSource::new(
            source,
            self.snapshot_cleanup.take(),
        ))
    }

    pub(crate) fn take_catalog_snapshot_source(&mut self) -> Option<CatalogSnapshotSource> {
        self.catalog_snapshot_source.take()
    }

    /// Barrier capture 同一 worker command 内建立的 exact retained-range pin。
    pub(crate) fn take_backfill_source(&mut self) -> Option<PinnedBackfillSource> {
        Some(PinnedBackfillSource::new(
            self.backfill_pin.take()?,
            self.backfill_cleanup.take()?,
        ))
    }
}

struct WatchEntry {
    token: StoreWatchToken,
    sender: watch::Sender<StreamCursor>,
}

/// 唯一 store worker 所拥有的 commit hub。
pub struct StoreCommitHub {
    incarnation: StoreCommitHubIncarnation,
    next_watch_id: u64,
    high_waters: HashMap<RuntimeStreamTarget, StreamCursor>,
    watchers: HashMap<RuntimeStreamTarget, HashMap<u64, WatchEntry>>,
    cleanup_tx: Option<mpsc::UnboundedSender<StoreCleanup>>,
}

impl Default for StoreCommitHub {
    fn default() -> Self {
        Self {
            // Default 只服务独立 Hub 算法测试。每次 allocation 都是不同 incarnation；
            // stale token 持有 Arc，因此 allocator 也不能在 token 存活时复用 identity。
            incarnation: StoreCommitHubIncarnation::new([0xAD; 16]),
            next_watch_id: 1,
            high_waters: HashMap::new(),
            watchers: HashMap::new(),
            cleanup_tx: None,
        }
    }
}

impl StoreCommitHub {
    #[cfg(test)]
    pub(crate) fn with_cleanup_sender(cleanup_tx: mpsc::UnboundedSender<StoreCleanup>) -> Self {
        Self {
            cleanup_tx: Some(cleanup_tx),
            ..Self::default()
        }
    }

    pub(crate) fn with_cleanup_sender_and_incarnation(
        cleanup_tx: mpsc::UnboundedSender<StoreCleanup>,
        incarnation: [u8; 16],
    ) -> Self {
        Self {
            incarnation: StoreCommitHubIncarnation::new(incarnation),
            next_watch_id: 1,
            high_waters: HashMap::new(),
            watchers: HashMap::new(),
            cleanup_tx: Some(cleanup_tx),
        }
    }

    #[must_use]
    pub fn high_water(&self, target: RuntimeStreamTarget) -> StreamCursor {
        self.high_waters
            .get(&target)
            .copied()
            .unwrap_or(StreamCursor::BeforeFirst)
    }

    /// register 与 capture 严格在一次调用内线性化。确定性测试可在 closure 中
    /// 注入“注册后、capture 前”COMMIT 通知；生产 closure 只做短 authenticated readback。
    pub fn register_then_capture<T, E>(
        &mut self,
        target: RuntimeStreamTarget,
        generation: WatchGeneration,
        capture: impl FnOnce(&mut Self) -> Result<(StreamCursor, T), E>,
    ) -> Result<(StoreWatch, T), RegisterCaptureError<E>> {
        let watch_id = self.next_watch_id;
        self.next_watch_id = self
            .next_watch_id
            .checked_add(1)
            .ok_or(StoreCommitHubError::WatchIdentityExhausted)?;
        let token = StoreWatchToken {
            incarnation: self.incarnation.clone(),
            watch_id,
            generation,
            target,
        };
        let (sender, receiver) = watch::channel(self.high_water(target));
        self.watchers.entry(target).or_default().insert(
            watch_id,
            WatchEntry {
                token: token.clone(),
                sender,
            },
        );
        let (captured_high_water, captured) = match capture(self) {
            Ok(value) => value,
            Err(error) => {
                let _ = self.release(&token);
                return Err(RegisterCaptureError::Capture(error));
            }
        };
        self.notify_committed(target, captured_high_water);
        let mut watch = StoreWatch {
            token,
            registered_after: captured_high_water,
            receiver,
            cleanup_tx: self.cleanup_tx.clone(),
        };
        if !cursor_is_newer(watch.latest(), captured_high_water) {
            let _ = watch.receiver.borrow_and_update();
        }
        Ok((watch, captured))
    }

    /// 兼容小型算法测试；生产 subscription 使用 `register_then_capture`。
    pub fn register(
        &mut self,
        target: RuntimeStreamTarget,
        generation: WatchGeneration,
    ) -> Result<StoreWatch, StoreCommitHubError> {
        let captured = self.high_water(target);
        self.register_then_capture(target, generation, |_| {
            Ok::<_, std::convert::Infallible>((captured, ()))
        })
        .map(|(watch, ())| watch)
        .map_err(|error| match error {
            RegisterCaptureError::Hub(error) => error,
            RegisterCaptureError::Capture(never) => match never {},
        })
    }

    /// stale token 只得到 false，不能影响新 generation。
    pub fn release(&mut self, token: &StoreWatchToken) -> bool {
        let Some(bucket) = self.watchers.get_mut(&token.target) else {
            return false;
        };
        let released = bucket
            .get(&token.watch_id)
            .is_some_and(|entry| &entry.token == token);
        if released {
            bucket.remove(&token.watch_id);
        }
        if bucket.is_empty() {
            self.watchers.remove(&token.target);
        }
        released
    }

    #[must_use]
    pub fn is_current(&self, token: &StoreWatchToken) -> bool {
        self.watchers
            .get(&token.target)
            .and_then(|bucket| bucket.get(&token.watch_id))
            .is_some_and(|entry| &entry.token == token)
    }

    #[must_use]
    pub fn watched_targets(&self) -> Vec<RuntimeStreamTarget> {
        self.watchers.keys().copied().collect()
    }

    #[must_use]
    pub fn has_watchers(&self, target: RuntimeStreamTarget) -> bool {
        self.watchers
            .get(&target)
            .is_some_and(|bucket| !bucket.is_empty())
    }

    /// authenticated readback 失败时关闭该 target 的全部 watcher，并丢弃本地
    /// cached HWM。其他 target 不受影响；后续重新注册必须重新完成 authenticated
    /// capture，不能沿用失败前的内存事实。
    pub fn fail_closed(&mut self, target: RuntimeStreamTarget) -> usize {
        self.high_waters.remove(&target);
        self.watchers
            .remove(&target)
            .map_or(0, |bucket| bucket.len())
    }

    /// 只在 durable COMMIT 或 COMMIT-unknown 的 authenticated readback 后调用。
    pub fn notify_committed(
        &mut self,
        target: RuntimeStreamTarget,
        high_water: StreamCursor,
    ) -> usize {
        if !cursor_is_newer(high_water, self.high_water(target)) {
            return 0;
        }
        self.high_waters.insert(target, high_water);
        let Some(bucket) = self.watchers.get_mut(&target) else {
            return 0;
        };
        let visited = bucket.len();
        bucket.retain(|_, entry| entry.sender.send(high_water).is_ok());
        if bucket.is_empty() {
            self.watchers.remove(&target);
        }
        visited
    }
}

fn cursor_is_newer(candidate: StreamCursor, current: StreamCursor) -> bool {
    match (candidate.high_water(), current.high_water()) {
        (Some(_), None) => true,
        (Some(candidate), Some(current)) => candidate > current,
        _ => false,
    }
}

#[cfg(test)]
mod command_effect_tests {
    use super::{CommandStreamEffects, PendingStreamTargets, RuntimeStreamTarget};
    use crate::runtime::model::{RuntimeCommitOperation, RuntimeStoreError};
    use crate::runtime::store::{RuntimeId, RuntimeIdKind};

    fn conversation(seed: u8) -> RuntimeStreamTarget {
        RuntimeStreamTarget::Conversation(
            RuntimeId::from_bytes(RuntimeIdKind::Conversation, [seed; 16])
                .expect("nonzero conversation id"),
        )
    }

    #[test]
    fn command_effects_promote_only_durable_possible_targets_and_deduplicate_union() {
        let first = conversation(1);
        let second = conversation(2);
        let mut effects = CommandStreamEffects::default();

        let mut rolled_back = PendingStreamTargets::default();
        rolled_back.insert(first);
        effects.record_commit_result(
            rolled_back,
            &Err(RuntimeStoreError::InvalidConfig("definite rollback")),
        );
        assert!(
            effects.is_empty(),
            "definite rollback cannot promote effects"
        );

        let mut unknown = PendingStreamTargets::default();
        unknown.insert(first);
        unknown.insert(second);
        unknown.insert(first);
        effects.record_commit_result(
            unknown,
            &Err(RuntimeStoreError::CommitOutcomeUnknown {
                operation: RuntimeCommitOperation::ExpireCommands,
            }),
        );

        let mut committed = PendingStreamTargets::default();
        committed.insert(second);
        committed.insert(RuntimeStreamTarget::Catalog);
        effects.record_commit_result(committed, &Ok(()));

        assert_eq!(
            effects.targets().collect::<Vec<_>>(),
            vec![RuntimeStreamTarget::Catalog, first, second],
            "durable effects form one deterministic cross-target set"
        );
    }
}
