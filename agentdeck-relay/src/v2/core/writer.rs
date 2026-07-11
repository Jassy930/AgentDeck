//! Relay v2 连接出站 writer 的有界入队面。
//!
//! Core 只调用 [`OutboundWriter::try_enqueue`]，不等待 socket。数据与控制
//! frame 各自使用独立的 frame/byte 预算，但共用一条 FIFO：因此预留的
//! control 容量不会被普通数据耗尽，`ReplayComplete` 也不会超过先入队
//! 的 replay frame。预算在 [`OutboundDelivery::mark_flushed`] 之前一直占用，
//! 包括已从队列取出、正在写 socket 的 in-flight frame。

use std::collections::VecDeque;
use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use agentdeck_protocol::relay_v2::{OpaqueRouteFrame, encode};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

/// 普通 data/replay 的默认 frame 上限。
pub const DEFAULT_NORMAL_MAX_FRAMES: usize = 512;
/// 普通 data/replay 的默认 byte 上限（16 MiB）。
pub const DEFAULT_NORMAL_MAX_BYTES: usize = 16 * 1024 * 1024;
/// 关键 control 的默认预留 frame 上限。
pub const DEFAULT_CONTROL_MAX_FRAMES: usize = 16;
/// 关键 control 的默认预留 byte 上限（1 MiB）。
pub const DEFAULT_CONTROL_MAX_BYTES: usize = 1024 * 1024;
/// 单个 revoke/retirement terminal frame 的硬上限（4 KiB）。
pub const TERMINAL_MAX_BYTES: usize = 4 * 1024;
/// 全 Core 同时 queued/in-flight terminal 的硬 frame 上限。
pub const GLOBAL_TERMINAL_MAX_FRAMES: usize = 4_096;
/// 全 Core 同时 queued/in-flight terminal 的硬 byte 上限（16 MiB）。
pub const GLOBAL_TERMINAL_MAX_BYTES: usize = 16 * 1024 * 1024;

/// 一类 frame 的 frame/byte 双重预算。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriterBudget {
    pub max_frames: usize,
    pub max_bytes: usize,
}

impl WriterBudget {
    pub const fn new(max_frames: usize, max_bytes: usize) -> Self {
        Self {
            max_frames,
            max_bytes,
        }
    }
}

/// 单连接 outbound writer 预算。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutboundWriterConfig {
    pub normal: WriterBudget,
    pub control: WriterBudget,
}

impl Default for OutboundWriterConfig {
    fn default() -> Self {
        Self {
            normal: WriterBudget::new(DEFAULT_NORMAL_MAX_FRAMES, DEFAULT_NORMAL_MAX_BYTES),
            control: WriterBudget::new(DEFAULT_CONTROL_MAX_FRAMES, DEFAULT_CONTROL_MAX_BYTES),
        }
    }
}

/// frame 在 writer 中使用的预算类别。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboundClass {
    /// Publish/Reply/PairData 以及 replay 数据。
    Data,
    /// Gap/ReplayComplete/Error/ServerRestarting 等必须保留容量的控制帧。
    Control,
}

/// writer 首个 close 原因（first-writer-wins）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriterCloseReason {
    Explicit,
    Disconnected,
    Replaced,
    AuthorizationInvalidated,
    HeartbeatTimeout,
    Shutdown,
    Lagged,
    CriticalBackpressure,
    ReceiverDropped,
    DeliveryDropped,
    AllWritersDropped,
    /// root-signed device revocation terminal 已 flush 或达到 deadline。
    Revoked,
    /// root-signed machine retirement terminal 已 flush 或达到 deadline。
    Retired,
}

/// 独立 terminal slot 的幂等 admission 结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminalAdmission {
    Staged,
    Existing,
}

/// 独立 terminal slot admission 失败。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BeginTerminalError {
    Closed(WriterCloseReason),
    Conflict,
    FrameTooLarge,
    Capacity,
    InvalidCloseReason,
}

impl std::error::Error for BeginTerminalError {}

impl fmt::Display for BeginTerminalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed(reason) => write!(formatter, "outbound writer is closed: {reason:?}"),
            Self::Conflict => formatter.write_str("a different terminal is already staged"),
            Self::FrameTooLarge => formatter.write_str("terminal frame exceeds hard limit"),
            Self::Capacity => formatter.write_str("global terminal reserve is exhausted"),
            Self::InvalidCloseReason => {
                formatter.write_str("terminal requires revoked or retired close reason")
            }
        }
    }
}

/// 非等待入队失败。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TryEnqueueError {
    /// normal frame/byte 预算不足；该 writer 已 fail-closed。
    Lagged,
    /// control 预留也已耗尽；该 writer 已 fail-closed。
    CriticalBackpressure,
    /// writer 早已关闭。
    Closed(WriterCloseReason),
}

impl std::error::Error for TryEnqueueError {}

impl fmt::Display for TryEnqueueError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Lagged => formatter.write_str("outbound normal budget exhausted"),
            Self::CriticalBackpressure => formatter.write_str("outbound control reserve exhausted"),
            Self::Closed(reason) => write!(formatter, "outbound writer is closed: {reason:?}"),
        }
    }
}

/// 等待 replay 入队预算的结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitForBudgetError {
    Cancelled,
    Closed(WriterCloseReason),
    RequestExceedsLimit,
}

impl std::error::Error for WaitForBudgetError {}

impl fmt::Display for WaitForBudgetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => formatter.write_str("writer budget wait cancelled"),
            Self::Closed(reason) => write!(formatter, "outbound writer is closed: {reason:?}"),
            Self::RequestExceedsLimit => {
                formatter.write_str("requested budget exceeds writer limit")
            }
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Usage {
    frames: usize,
    bytes: usize,
}

impl Usage {
    fn can_reserve(self, budget: WriterBudget, bytes: usize) -> bool {
        self.frames < budget.max_frames && bytes <= budget.max_bytes.saturating_sub(self.bytes)
    }

    fn reserve(&mut self, bytes: usize) {
        self.frames += 1;
        self.bytes += bytes;
    }

    fn can_reserve_many(self, budget: WriterBudget, frames: usize, bytes: usize) -> bool {
        frames <= budget.max_frames.saturating_sub(self.frames)
            && bytes <= budget.max_bytes.saturating_sub(self.bytes)
    }

    fn reserve_many(&mut self, frames: usize, bytes: usize) {
        self.frames += frames;
        self.bytes += bytes;
    }

    fn release(&mut self, bytes: usize) {
        self.frames = self.frames.saturating_sub(1);
        self.bytes = self.bytes.saturating_sub(bytes);
    }

    fn release_many(&mut self, frames: usize, bytes: usize) {
        self.frames = self.frames.saturating_sub(frames);
        self.bytes = self.bytes.saturating_sub(bytes);
    }
}

struct QueuedFrame {
    encoded: Arc<[u8]>,
    class: OutboundClass,
    terminal_reason: Option<WriterCloseReason>,
    _global: Option<GlobalWriterReservation>,
}

impl fmt::Debug for QueuedFrame {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QueuedFrame")
            .field("class", &self.class)
            .field("terminal", &self.terminal_reason.is_some())
            .field(
                "encoded",
                &format_args!("<redacted:{} bytes>", self.encoded.len()),
            )
            .finish()
    }
}

struct Inner {
    queue: VecDeque<QueuedFrame>,
    normal_usage: Usage,
    control_usage: Usage,
    terminal_usage: Usage,
    terminal_state: Option<TerminalState>,
    close_reason: Option<WriterCloseReason>,
    global_budget: Option<Arc<GlobalWriterBudget>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TerminalState {
    encoded: Arc<[u8]>,
    close_reason: WriterCloseReason,
}

impl Inner {
    fn usage_mut(&mut self, class: OutboundClass) -> &mut Usage {
        match class {
            OutboundClass::Data => &mut self.normal_usage,
            OutboundClass::Control => &mut self.control_usage,
        }
    }

    fn usage(&self, class: OutboundClass) -> Usage {
        match class {
            OutboundClass::Data => self.normal_usage,
            OutboundClass::Control => self.control_usage,
        }
    }

    fn unavailable_reason(&self) -> Option<WriterCloseReason> {
        self.close_reason.or_else(|| {
            self.terminal_state
                .as_ref()
                .map(|terminal| terminal.close_reason)
        })
    }

    fn release_queued(&mut self, frame: &QueuedFrame) {
        if frame.terminal_reason.is_some() {
            self.terminal_usage.release(frame.encoded.len());
        } else {
            self.usage_mut(frame.class).release(frame.encoded.len());
        }
    }

    /// 设置 first close reason，清理尚未取出的 frame。
    fn close(&mut self, reason: WriterCloseReason) -> bool {
        if self.close_reason.is_some() {
            return false;
        }
        self.close_reason = Some(reason);
        self.terminal_state = None;
        while let Some(frame) = self.queue.pop_front() {
            self.release_queued(&frame);
        }
        true
    }
}

fn reserve_global(
    inner: &Inner,
    class: OutboundClass,
    bytes: usize,
) -> Result<Option<GlobalWriterReservation>, ()> {
    match &inner.global_budget {
        Some(budget) => budget.try_reserve(class, bytes).map(Some).ok_or(()),
        None => Ok(None),
    }
}

fn reserve_global_terminal(
    inner: &Inner,
    bytes: usize,
) -> Result<Option<GlobalWriterReservation>, ()> {
    match &inner.global_budget {
        Some(budget) => budget.try_reserve_terminal(bytes).map(Some).ok_or(()),
        None => Ok(None),
    }
}

struct Shared {
    config: OutboundWriterConfig,
    inner: Mutex<Inner>,
    item_ready: Notify,
    normal_budget_changed: Notify,
    control_budget_changed: Notify,
    closed: Notify,
    writer_count: AtomicUsize,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn close(&self, reason: WriterCloseReason) -> bool {
        let changed = self.lock().close(reason);
        if changed {
            self.item_ready.notify_waiters();
            self.normal_budget_changed.notify_waiters();
            self.control_budget_changed.notify_waiters();
            self.closed.notify_waiters();
        }
        changed
    }

    fn release(&self, class: OutboundClass, bytes: usize) {
        {
            let mut inner = self.lock();
            inner.usage_mut(class).release(bytes);
        }
        match class {
            OutboundClass::Data => self.normal_budget_changed.notify_waiters(),
            OutboundClass::Control => self.control_budget_changed.notify_waiters(),
        }
    }

    fn release_terminal(&self, bytes: usize) {
        {
            let mut inner = self.lock();
            inner.terminal_usage.release(bytes);
        }
    }

    fn terminal_flushed(&self, bytes: usize, reason: WriterCloseReason) {
        let changed = {
            let mut inner = self.lock();
            inner.terminal_usage.release(bytes);
            inner.close(reason)
        };
        if changed {
            self.item_ready.notify_waiters();
            self.normal_budget_changed.notify_waiters();
            self.control_budget_changed.notify_waiters();
            self.closed.notify_waiters();
        }
    }

    fn release_normal_reservation(&self, frames: usize, bytes: usize) {
        {
            let mut inner = self.lock();
            inner.normal_usage.release_many(frames, bytes);
        }
        self.normal_budget_changed.notify_waiters();
    }

    fn release_control_reservation(&self, frames: usize, bytes: usize) {
        {
            let mut inner = self.lock();
            inner.control_usage.release_many(frames, bytes);
        }
        self.control_budget_changed.notify_waiters();
    }

    async fn wait_closed(&self) -> WriterCloseReason {
        loop {
            // 先注册 waiter 再读取状态，避免 close 落在 check/wait 之间时丢失唤醒。
            let closed = self.closed.notified();
            if let Some(reason) = self.lock().close_reason {
                return reason;
            }
            closed.await;
        }
    }
}

/// Core 持有的可克隆非等待入队端。
pub struct OutboundWriter {
    shared: Arc<Shared>,
}

/// Core/router 使用的短名别名。
pub type WriterHandle = OutboundWriter;
pub type WriterReceiver = OutboundReceiver;
pub type WriterConfig = OutboundWriterConfig;
pub type WriterFrameClass = OutboundClass;
pub type WriterEnqueueError = TryEnqueueError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TryReserveWriterError {
    Unavailable,
    RequestExceedsLimit,
    Closed(WriterCloseReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BindGlobalBudgetError {
    AlreadyBound,
    WriterAlreadyUsed,
}

/// 所有已 attach writer 共享的实际 queued/in-flight frame/byte hard bound。
///
/// 单连接上限只能隔离慢端，不能阻止一个 Publish 同时 fan-out 到数千 reader；这个预算
/// 把聚合内存固定在 CoreConfig 明确值内。reservation 随 queued/in-flight delivery 存活，
/// flush、close 或 drop 时释放。
pub(crate) struct GlobalWriterBudget {
    limits: OutboundWriterConfig,
    terminal_limit: WriterBudget,
    usage: Mutex<GlobalUsage>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct GlobalUsage {
    normal: Usage,
    control: Usage,
    terminal: Usage,
}

impl GlobalWriterBudget {
    pub(crate) fn new(normal: WriterBudget, control: WriterBudget) -> Self {
        Self {
            limits: OutboundWriterConfig { normal, control },
            terminal_limit: WriterBudget::new(
                GLOBAL_TERMINAL_MAX_FRAMES,
                GLOBAL_TERMINAL_MAX_BYTES,
            ),
            usage: Mutex::new(GlobalUsage::default()),
        }
    }

    fn try_reserve(
        self: &Arc<Self>,
        class: OutboundClass,
        bytes: usize,
    ) -> Option<GlobalWriterReservation> {
        let mut usage = self
            .usage
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (class_usage, limit) = match class {
            OutboundClass::Data => (&mut usage.normal, self.limits.normal),
            OutboundClass::Control => (&mut usage.control, self.limits.control),
        };
        if !class_usage.can_reserve(limit, bytes) {
            return None;
        }
        class_usage.reserve(bytes);
        drop(usage);
        Some(GlobalWriterReservation {
            budget: Arc::clone(self),
            class: GlobalReservationClass::Ordinary(class),
            bytes,
        })
    }

    fn try_reserve_terminal(self: &Arc<Self>, bytes: usize) -> Option<GlobalWriterReservation> {
        let mut usage = self
            .usage
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !usage.terminal.can_reserve(self.terminal_limit, bytes) {
            return None;
        }
        usage.terminal.reserve(bytes);
        drop(usage);
        Some(GlobalWriterReservation {
            budget: Arc::clone(self),
            class: GlobalReservationClass::Terminal,
            bytes,
        })
    }

    fn release(&self, class: GlobalReservationClass, bytes: usize) {
        let mut usage = self
            .usage
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match class {
            GlobalReservationClass::Ordinary(OutboundClass::Data) => usage.normal.release(bytes),
            GlobalReservationClass::Ordinary(OutboundClass::Control) => {
                usage.control.release(bytes)
            }
            GlobalReservationClass::Terminal => usage.terminal.release(bytes),
        }
    }

    #[cfg(test)]
    fn current_usage(&self) -> GlobalUsage {
        *self
            .usage
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl fmt::Debug for GlobalWriterBudget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GlobalWriterBudget")
            .field("limits", &self.limits)
            .field("terminal_limit", &self.terminal_limit)
            .finish_non_exhaustive()
    }
}

struct GlobalWriterReservation {
    budget: Arc<GlobalWriterBudget>,
    class: GlobalReservationClass,
    bytes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GlobalReservationClass {
    Ordinary(OutboundClass),
    Terminal,
}

impl Drop for GlobalWriterReservation {
    fn drop(&mut self) {
        self.budget.release(self.class, self.bytes);
    }
}

impl fmt::Debug for GlobalWriterReservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GlobalWriterReservation")
            .field("class", &self.class)
            .field("bytes", &self.bytes)
            .finish_non_exhaustive()
    }
}

/// replay task 在访问 Store 前原子占有的 normal writer page 预算。
///
/// reservation 把最坏页预算计入 writer usage，普通 live fanout 无法在 Store fetch 与
/// Core enqueue 之间抢走它。每个实际 frame 入 FIFO 时只把相应部分从“未使用预留”转换成
/// queued/in-flight usage；Drop 释放剩余部分。
pub(crate) struct NormalWriterReservation {
    shared: Arc<Shared>,
    remaining_frames: usize,
    remaining_bytes: usize,
}

impl NormalWriterReservation {
    pub(crate) fn try_enqueue_data(
        &mut self,
        frame: OpaqueRouteFrame,
    ) -> Result<(), TryEnqueueError> {
        if let Some(reason) = self.shared.lock().unavailable_reason() {
            return Err(TryEnqueueError::Closed(reason));
        }
        let encoded: Arc<[u8]> = encode(&frame).into();
        let encoded_len = encoded.len();
        let mut inner = self.shared.lock();
        if let Some(reason) = inner.unavailable_reason() {
            return Err(TryEnqueueError::Closed(reason));
        }
        if self.remaining_frames == 0 || encoded_len > self.remaining_bytes {
            inner.close(WriterCloseReason::Lagged);
            drop(inner);
            self.shared.item_ready.notify_waiters();
            self.shared.normal_budget_changed.notify_waiters();
            self.shared.closed.notify_waiters();
            return Err(TryEnqueueError::Lagged);
        }
        let global = match reserve_global(&inner, OutboundClass::Data, encoded_len) {
            Ok(reservation) => reservation,
            Err(()) => {
                inner.close(WriterCloseReason::Lagged);
                drop(inner);
                self.shared.item_ready.notify_waiters();
                self.shared.normal_budget_changed.notify_waiters();
                self.shared.control_budget_changed.notify_waiters();
                self.shared.closed.notify_waiters();
                return Err(TryEnqueueError::Lagged);
            }
        };
        self.remaining_frames -= 1;
        self.remaining_bytes -= encoded_len;
        inner.queue.push_back(QueuedFrame {
            encoded,
            class: OutboundClass::Data,
            terminal_reason: None,
            _global: global,
        });
        drop(inner);
        self.shared.item_ready.notify_one();
        Ok(())
    }
}

impl Drop for NormalWriterReservation {
    fn drop(&mut self) {
        self.shared
            .release_normal_reservation(self.remaining_frames, self.remaining_bytes);
        self.remaining_frames = 0;
        self.remaining_bytes = 0;
    }
}

impl fmt::Debug for NormalWriterReservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NormalWriterReservation")
            .field("remaining_frames", &self.remaining_frames)
            .field("remaining_bytes", &self.remaining_bytes)
            .finish()
    }
}

/// replay terminal 在推进 connection state 前原子占有的 control writer 预算。
///
/// 与 normal page reservation 相同，预算在 frame 真正进入 FIFO 前已经计入 usage；
/// 因此多个空 replay terminal 会等待 socket flush，而不是瞬时耗尽 control reserve。
pub(crate) struct ControlWriterReservation {
    shared: Arc<Shared>,
    remaining_frames: usize,
    remaining_bytes: usize,
}

impl ControlWriterReservation {
    pub(crate) fn try_enqueue_control(
        &mut self,
        frame: OpaqueRouteFrame,
    ) -> Result<(), TryEnqueueError> {
        if let Some(reason) = self.shared.lock().unavailable_reason() {
            return Err(TryEnqueueError::Closed(reason));
        }
        let encoded: Arc<[u8]> = encode(&frame).into();
        let encoded_len = encoded.len();
        let mut inner = self.shared.lock();
        if let Some(reason) = inner.unavailable_reason() {
            return Err(TryEnqueueError::Closed(reason));
        }
        if self.remaining_frames == 0 || encoded_len > self.remaining_bytes {
            inner.close(WriterCloseReason::CriticalBackpressure);
            drop(inner);
            self.shared.item_ready.notify_waiters();
            self.shared.normal_budget_changed.notify_waiters();
            self.shared.control_budget_changed.notify_waiters();
            self.shared.closed.notify_waiters();
            return Err(TryEnqueueError::CriticalBackpressure);
        }
        let global = match reserve_global(&inner, OutboundClass::Control, encoded_len) {
            Ok(reservation) => reservation,
            Err(()) => {
                inner.close(WriterCloseReason::CriticalBackpressure);
                drop(inner);
                self.shared.item_ready.notify_waiters();
                self.shared.normal_budget_changed.notify_waiters();
                self.shared.control_budget_changed.notify_waiters();
                self.shared.closed.notify_waiters();
                return Err(TryEnqueueError::CriticalBackpressure);
            }
        };
        self.remaining_frames -= 1;
        self.remaining_bytes -= encoded_len;
        inner.queue.push_back(QueuedFrame {
            encoded,
            class: OutboundClass::Control,
            terminal_reason: None,
            _global: global,
        });
        drop(inner);
        self.shared.item_ready.notify_one();
        Ok(())
    }
}

impl Drop for ControlWriterReservation {
    fn drop(&mut self) {
        self.shared
            .release_control_reservation(self.remaining_frames, self.remaining_bytes);
        self.remaining_frames = 0;
        self.remaining_bytes = 0;
    }
}

impl fmt::Debug for ControlWriterReservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ControlWriterReservation")
            .field("remaining_frames", &self.remaining_frames)
            .field("remaining_bytes", &self.remaining_bytes)
            .finish()
    }
}

impl OutboundWriter {
    /// 创建一条单 consumer FIFO writer。
    pub fn new(config: OutboundWriterConfig) -> (Self, OutboundReceiver) {
        let shared = Arc::new(Shared {
            config,
            inner: Mutex::new(Inner {
                queue: VecDeque::with_capacity(
                    config
                        .normal
                        .max_frames
                        .saturating_add(config.control.max_frames),
                ),
                normal_usage: Usage::default(),
                control_usage: Usage::default(),
                terminal_usage: Usage::default(),
                terminal_state: None,
                close_reason: None,
                global_budget: None,
            }),
            item_ready: Notify::new(),
            normal_budget_changed: Notify::new(),
            control_budget_changed: Notify::new(),
            closed: Notify::new(),
            writer_count: AtomicUsize::new(1),
        });
        (
            Self {
                shared: Arc::clone(&shared),
            },
            OutboundReceiver { shared },
        )
    }

    /// 创建默认 512 frame/16 MiB normal + 16 frame/1 MiB control writer。
    pub fn channel() -> (Self, OutboundReceiver) {
        Self::new(OutboundWriterConfig::default())
    }

    /// Core attach 前绑定唯一聚合预算。已经入队/预留过 frame 的 writer 不能补绑，避免
    /// 未计数 bytes 混入生产连接。
    pub(crate) fn bind_global_budget(
        &self,
        budget: Arc<GlobalWriterBudget>,
    ) -> Result<(), BindGlobalBudgetError> {
        let mut inner = self.shared.lock();
        if inner.global_budget.is_some() {
            return Err(BindGlobalBudgetError::AlreadyBound);
        }
        if !inner.queue.is_empty()
            || inner.normal_usage != Usage::default()
            || inner.control_usage != Usage::default()
            || inner.terminal_usage != Usage::default()
            || inner.terminal_state.is_some()
        {
            return Err(BindGlobalBudgetError::WriterAlreadyUsed);
        }
        inner.global_budget = Some(budget);
        Ok(())
    }

    /// canonical 编码后立即尝试入队；绝不等待 receiver/socket。
    ///
    /// 预算耗尽会立即 fail-close 本 writer，并清理尚未写出的队列。
    pub fn try_enqueue(
        &self,
        frame: OpaqueRouteFrame,
        class: OutboundClass,
    ) -> Result<(), TryEnqueueError> {
        // 已关闭连接不应继续为攻击者反复 canonical encode 大 frame。编码后仍会在
        // 同一把锁内复核 close_reason，以覆盖 fast-path check 后发生的并发 close。
        if let Some(reason) = self.shared.lock().unavailable_reason() {
            return Err(TryEnqueueError::Closed(reason));
        }
        let encoded: Arc<[u8]> = encode(&frame).into();
        let encoded_len = encoded.len();
        let budget = match class {
            OutboundClass::Data => self.shared.config.normal,
            OutboundClass::Control => self.shared.config.control,
        };

        let mut inner = self.shared.lock();
        if let Some(reason) = inner.unavailable_reason() {
            return Err(TryEnqueueError::Closed(reason));
        }
        if !inner.usage(class).can_reserve(budget, encoded_len) {
            let (reason, error) = match class {
                OutboundClass::Data => (WriterCloseReason::Lagged, TryEnqueueError::Lagged),
                OutboundClass::Control => (
                    WriterCloseReason::CriticalBackpressure,
                    TryEnqueueError::CriticalBackpressure,
                ),
            };
            inner.close(reason);
            drop(inner);
            self.shared.item_ready.notify_waiters();
            self.shared.normal_budget_changed.notify_waiters();
            self.shared.closed.notify_waiters();
            return Err(error);
        }

        let global = match reserve_global(&inner, class, encoded_len) {
            Ok(reservation) => reservation,
            Err(()) => {
                let (reason, error) = match class {
                    OutboundClass::Data => (WriterCloseReason::Lagged, TryEnqueueError::Lagged),
                    OutboundClass::Control => (
                        WriterCloseReason::CriticalBackpressure,
                        TryEnqueueError::CriticalBackpressure,
                    ),
                };
                inner.close(reason);
                drop(inner);
                self.shared.item_ready.notify_waiters();
                self.shared.normal_budget_changed.notify_waiters();
                self.shared.control_budget_changed.notify_waiters();
                self.shared.closed.notify_waiters();
                return Err(error);
            }
        };

        inner.usage_mut(class).reserve(encoded_len);
        inner.queue.push_back(QueuedFrame {
            encoded,
            class,
            terminal_reason: None,
            _global: global,
        });
        drop(inner);
        self.shared.item_ready.notify_one();
        Ok(())
    }

    pub fn try_enqueue_data(&self, frame: OpaqueRouteFrame) -> Result<(), TryEnqueueError> {
        self.try_enqueue(frame, OutboundClass::Data)
    }

    pub fn try_enqueue_control(&self, frame: OpaqueRouteFrame) -> Result<(), TryEnqueueError> {
        self.try_enqueue(frame, OutboundClass::Control)
    }

    /// 在 revoke/retirement COMMIT 后接管 writer。
    ///
    /// 本操作在一把锁内丢弃所有尚未出队的普通 data/control、拒绝后续普通入队，并把
    /// 唯一 terminal 放入不受普通预算影响的专用槽。已经被 socket receiver 取出的一个
    /// pre-COMMIT frame 允许自然完成；terminal 会成为下一次 `recv` 的唯一 frame。
    pub fn try_begin_terminal(
        &self,
        frame: OpaqueRouteFrame,
        close_reason: WriterCloseReason,
    ) -> Result<TerminalAdmission, BeginTerminalError> {
        if !matches!(
            close_reason,
            WriterCloseReason::Revoked | WriterCloseReason::Retired
        ) {
            return Err(BeginTerminalError::InvalidCloseReason);
        }
        if let Some(reason) = self.shared.lock().close_reason {
            return Err(BeginTerminalError::Closed(reason));
        }

        let encoded: Arc<[u8]> = encode(&frame).into();
        if encoded.len() > TERMINAL_MAX_BYTES {
            return Err(BeginTerminalError::FrameTooLarge);
        }

        let mut inner = self.shared.lock();
        if let Some(reason) = inner.close_reason {
            return Err(BeginTerminalError::Closed(reason));
        }
        if let Some(existing) = &inner.terminal_state {
            return if existing.close_reason == close_reason && existing.encoded == encoded {
                Ok(TerminalAdmission::Existing)
            } else {
                Err(BeginTerminalError::Conflict)
            };
        }

        let global = match reserve_global_terminal(&inner, encoded.len()) {
            Ok(reservation) => reservation,
            Err(()) => {
                inner.close(WriterCloseReason::CriticalBackpressure);
                drop(inner);
                self.shared.item_ready.notify_waiters();
                self.shared.normal_budget_changed.notify_waiters();
                self.shared.control_budget_changed.notify_waiters();
                self.shared.closed.notify_waiters();
                return Err(BeginTerminalError::Capacity);
            }
        };

        while let Some(queued) = inner.queue.pop_front() {
            inner.release_queued(&queued);
        }
        inner.terminal_usage.reserve(encoded.len());
        inner.terminal_state = Some(TerminalState {
            encoded: encoded.clone(),
            close_reason,
        });
        inner.queue.push_back(QueuedFrame {
            encoded,
            class: OutboundClass::Control,
            terminal_reason: Some(close_reason),
            _global: global,
        });
        drop(inner);

        self.shared.normal_budget_changed.notify_waiters();
        self.shared.control_budget_changed.notify_waiters();
        self.shared.item_ready.notify_one();
        Ok(TerminalAdmission::Staged)
    }

    /// 在读取 replay page 前原子预留整页 normal 预算；不足时不关闭 writer，调用方可等待
    /// `wait_for_normal_budget` 后重试。请求超过本 writer 固定上限则立即返回配置错误。
    pub(crate) fn try_reserve_normal(
        &self,
        frames: usize,
        bytes: usize,
    ) -> Result<NormalWriterReservation, TryReserveWriterError> {
        let limit = self.shared.config.normal;
        if frames == 0 || bytes == 0 || frames > limit.max_frames || bytes > limit.max_bytes {
            return Err(TryReserveWriterError::RequestExceedsLimit);
        }
        let mut inner = self.shared.lock();
        if let Some(reason) = inner.unavailable_reason() {
            return Err(TryReserveWriterError::Closed(reason));
        }
        if !inner.normal_usage.can_reserve_many(limit, frames, bytes) {
            return Err(TryReserveWriterError::Unavailable);
        }
        inner.normal_usage.reserve_many(frames, bytes);
        drop(inner);
        Ok(NormalWriterReservation {
            shared: Arc::clone(&self.shared),
            remaining_frames: frames,
            remaining_bytes: bytes,
        })
    }

    /// 在推进 replay terminal 状态前原子预留 control 预算；预算不足不会关闭 writer，
    /// 调用方必须等待 flush 后重试。
    pub(crate) fn try_reserve_control(
        &self,
        frames: usize,
        bytes: usize,
    ) -> Result<ControlWriterReservation, TryReserveWriterError> {
        let limit = self.shared.config.control;
        if frames == 0 || bytes == 0 || frames > limit.max_frames || bytes > limit.max_bytes {
            return Err(TryReserveWriterError::RequestExceedsLimit);
        }
        let mut inner = self.shared.lock();
        if let Some(reason) = inner.unavailable_reason() {
            return Err(TryReserveWriterError::Closed(reason));
        }
        if !inner.control_usage.can_reserve_many(limit, frames, bytes) {
            return Err(TryReserveWriterError::Unavailable);
        }
        inner.control_usage.reserve_many(frames, bytes);
        drop(inner);
        Ok(ControlWriterReservation {
            shared: Arc::clone(&self.shared),
            remaining_frames: frames,
            remaining_bytes: bytes,
        })
    }

    /// 等到 normal 预算同时满足 frame 和 byte 需求。
    ///
    /// in-flight frame 仍计入已用预算；只有 `mark_flushed` 后才可唤醒等待者。
    pub async fn wait_for_normal_budget(
        &self,
        min_frames: usize,
        min_bytes: usize,
        cancel: &CancellationToken,
    ) -> Result<(), WaitForBudgetError> {
        if cancel.is_cancelled() {
            return Err(WaitForBudgetError::Cancelled);
        }
        let limit = self.shared.config.normal;
        if min_frames > limit.max_frames || min_bytes > limit.max_bytes {
            return Err(WaitForBudgetError::RequestExceedsLimit);
        }

        loop {
            // 先注册 notified future 再读状态，避免 check/wait 之间丢 wakeup。
            let budget_changed = self.shared.normal_budget_changed.notified();
            let closed = self.shared.closed.notified();
            let cancelled = cancel.cancelled();
            tokio::pin!(budget_changed, closed, cancelled);

            if cancel.is_cancelled() {
                return Err(WaitForBudgetError::Cancelled);
            }
            {
                let inner = self.shared.lock();
                if let Some(reason) = inner.unavailable_reason() {
                    return Err(WaitForBudgetError::Closed(reason));
                }
                let usage = inner.normal_usage;
                let available_frames = limit.max_frames.saturating_sub(usage.frames);
                let available_bytes = limit.max_bytes.saturating_sub(usage.bytes);
                if available_frames >= min_frames && available_bytes >= min_bytes {
                    // 这只能关闭“进入 wait 前已经 cancel”的漏洞，不能把 budget 与
                    // replay epoch 原子绑定。Core 在真正 enqueue 前仍必须复核
                    // cancellation + replay_id/current authorization，解决 TOCTOU。
                    if cancel.is_cancelled() {
                        return Err(WaitForBudgetError::Cancelled);
                    }
                    return Ok(());
                }
            }
            if cancel.is_cancelled() {
                return Err(WaitForBudgetError::Cancelled);
            }

            tokio::select! {
                biased;
                _ = &mut cancelled => return Err(WaitForBudgetError::Cancelled),
                _ = &mut budget_changed => {}
                _ = &mut closed => {}
            }
        }
    }

    /// 等到 control 预算同时满足 frame 和 byte 需求；只供 replay terminal 等可等待的
    /// actor 内部推进使用。即时 Gap/heartbeat 仍走 fail-closed `try_enqueue_control`。
    pub(crate) async fn wait_for_control_budget(
        &self,
        min_frames: usize,
        min_bytes: usize,
        cancel: &CancellationToken,
    ) -> Result<(), WaitForBudgetError> {
        if cancel.is_cancelled() {
            return Err(WaitForBudgetError::Cancelled);
        }
        let limit = self.shared.config.control;
        if min_frames > limit.max_frames || min_bytes > limit.max_bytes {
            return Err(WaitForBudgetError::RequestExceedsLimit);
        }

        loop {
            let budget_changed = self.shared.control_budget_changed.notified();
            let closed = self.shared.closed.notified();
            let cancelled = cancel.cancelled();
            tokio::pin!(budget_changed, closed, cancelled);

            if cancel.is_cancelled() {
                return Err(WaitForBudgetError::Cancelled);
            }
            {
                let inner = self.shared.lock();
                if let Some(reason) = inner.unavailable_reason() {
                    return Err(WaitForBudgetError::Closed(reason));
                }
                let usage = inner.control_usage;
                let available_frames = limit.max_frames.saturating_sub(usage.frames);
                let available_bytes = limit.max_bytes.saturating_sub(usage.bytes);
                if available_frames >= min_frames && available_bytes >= min_bytes {
                    if cancel.is_cancelled() {
                        return Err(WaitForBudgetError::Cancelled);
                    }
                    return Ok(());
                }
            }

            tokio::select! {
                biased;
                _ = &mut cancelled => return Err(WaitForBudgetError::Cancelled),
                _ = &mut budget_changed => {}
                _ = &mut closed => {}
            }
        }
    }

    /// 幂等关闭；首个 reason 保留。
    pub fn close(&self, reason: WriterCloseReason) -> bool {
        self.shared.close(reason)
    }

    pub fn is_closed(&self) -> bool {
        self.shared.lock().close_reason.is_some()
    }

    pub fn is_terminalizing(&self) -> bool {
        let inner = self.shared.lock();
        inner.close_reason.is_none() && inner.terminal_state.is_some()
    }

    pub fn close_reason(&self) -> Option<WriterCloseReason> {
        self.shared.lock().close_reason
    }

    pub(crate) fn normal_budget(&self) -> WriterBudget {
        self.shared.config.normal
    }

    /// 等待本 writer fail-close，并返回 first-writer-wins 的关闭原因。
    ///
    /// socket task 必须把该 future 与 in-flight socket write 放入同一个 `select!`；
    /// 只在一次 write 返回后再调用 `recv`，无法满足 Lagged/revoke/heartbeat 的及时断连。
    pub async fn closed(&self) -> WriterCloseReason {
        self.shared.wait_closed().await
    }

    #[cfg(test)]
    fn usage(&self, class: OutboundClass) -> Usage {
        self.shared.lock().usage(class)
    }

    #[cfg(test)]
    fn queued_len(&self) -> usize {
        self.shared.lock().queue.len()
    }

    #[cfg(test)]
    fn terminal_usage(&self) -> Usage {
        self.shared.lock().terminal_usage
    }
}

impl Clone for OutboundWriter {
    fn clone(&self) -> Self {
        self.shared.writer_count.fetch_add(1, Ordering::Relaxed);
        Self {
            shared: Arc::clone(&self.shared),
        }
    }
}

impl Drop for OutboundWriter {
    fn drop(&mut self) {
        if self.shared.writer_count.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.shared.close(WriterCloseReason::AllWritersDropped);
        }
    }
}

impl fmt::Debug for OutboundWriter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let inner = self.shared.lock();
        formatter
            .debug_struct("OutboundWriter")
            .field("normal_usage", &inner.normal_usage)
            .field("control_usage", &inner.control_usage)
            .field("terminal_usage", &inner.terminal_usage)
            .field("terminalizing", &inner.terminal_state.is_some())
            .field("queued_frames", &inner.queue.len())
            .field("close_reason", &inner.close_reason)
            .finish()
    }
}

/// socket writer task 独占的 FIFO consumer。
pub struct OutboundReceiver {
    shared: Arc<Shared>,
}

impl OutboundReceiver {
    /// 取出下一帧。取出不释放预算；调用者必须在 socket write
    /// 真正完成后调用 [`OutboundDelivery::mark_flushed`]。
    pub async fn recv(&mut self) -> Option<OutboundDelivery> {
        loop {
            let item_ready = self.shared.item_ready.notified();
            {
                let mut inner = self.shared.lock();
                if let Some(frame) = inner.queue.pop_front() {
                    return Some(OutboundDelivery {
                        shared: Arc::clone(&self.shared),
                        encoded: Some(frame.encoded),
                        class: frame.class,
                        terminal_reason: frame.terminal_reason,
                        _global: frame._global,
                        flushed: false,
                    });
                }
                if inner.close_reason.is_some() {
                    return None;
                }
            }
            item_ready.await;
        }
    }

    pub fn is_closed(&self) -> bool {
        self.shared.lock().close_reason.is_some()
    }

    pub fn close_reason(&self) -> Option<WriterCloseReason> {
        self.shared.lock().close_reason
    }

    /// 等待共享 writer 关闭，供独占 receiver 的 socket task 中断 in-flight write。
    pub async fn closed(&self) -> WriterCloseReason {
        self.shared.wait_closed().await
    }
}

impl Drop for OutboundReceiver {
    fn drop(&mut self) {
        self.shared.close(WriterCloseReason::ReceiverDropped);
    }
}

impl fmt::Debug for OutboundReceiver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OutboundReceiver")
            .field("close_reason", &self.close_reason())
            .finish_non_exhaustive()
    }
}

/// 一帧已出队、正在写 socket 的 canonical bytes。
///
/// 未 `mark_flushed` 直接 Drop 表示 writer task/socket 失去了该帧，必须
/// fail-close 连接，不允许静默释放 permit 后继续路由。
pub struct OutboundDelivery {
    shared: Arc<Shared>,
    encoded: Option<Arc<[u8]>>,
    class: OutboundClass,
    terminal_reason: Option<WriterCloseReason>,
    _global: Option<GlobalWriterReservation>,
    flushed: bool,
}

impl OutboundDelivery {
    pub fn encoded(&self) -> &[u8] {
        self.encoded.as_deref().unwrap_or_default()
    }

    pub fn encoded_len(&self) -> usize {
        self.encoded.as_ref().map_or(0, |encoded| encoded.len())
    }

    pub fn class(&self) -> OutboundClass {
        self.class
    }

    pub fn is_terminal(&self) -> bool {
        self.terminal_reason.is_some()
    }

    /// socket write/flush 已成功，释放该帧的 frame + byte 预算。
    pub fn mark_flushed(mut self) {
        let bytes = self.encoded.take().map_or(0, |encoded| encoded.len());
        if let Some(reason) = self.terminal_reason {
            self.shared.terminal_flushed(bytes, reason);
        } else {
            self.shared.release(self.class, bytes);
        }
        self.flushed = true;
    }
}

impl Drop for OutboundDelivery {
    fn drop(&mut self) {
        if self.flushed {
            return;
        }
        let bytes = self.encoded.take().map_or(0, |encoded| encoded.len());
        self.shared.close(WriterCloseReason::DeliveryDropped);
        if self.terminal_reason.is_some() {
            self.shared.release_terminal(bytes);
        } else {
            self.shared.release(self.class, bytes);
        }
    }
}

impl fmt::Debug for OutboundDelivery {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OutboundDelivery")
            .field("class", &self.class)
            .field("terminal", &self.terminal_reason.is_some())
            .field(
                "encoded",
                &format_args!("<redacted:{} bytes>", self.encoded_len()),
            )
            .field("flushed", &self.flushed)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use agentdeck_protocol::relay_v2::frame::{Ping, Publish, ReplayComplete, SealedBlob};
    use agentdeck_protocol::relay_v2::{
        MAX_FRAME_BYTES, RELAY_PROTOCOL_VERSION, RelayFrameBody, StreamCursor, StreamGenerationId,
        StreamRouteId, decode,
    };

    use super::*;

    fn ping(nonce: u64) -> OpaqueRouteFrame {
        OpaqueRouteFrame {
            version: RELAY_PROTOCOL_VERSION,
            body: RelayFrameBody::Ping(Ping { nonce }),
        }
    }

    fn replay_complete() -> OpaqueRouteFrame {
        OpaqueRouteFrame {
            version: RELAY_PROTOCOL_VERSION,
            body: RelayFrameBody::ReplayComplete(ReplayComplete {
                stream_route: StreamRouteId::from_bytes([1; 16]),
                generation: StreamGenerationId::from_bytes([2; 16]),
                current_cursor: StreamCursor::At(7),
            }),
        }
    }

    fn exactly_max_wire_publish(seq: u64) -> OpaqueRouteFrame {
        let empty = OpaqueRouteFrame {
            version: RELAY_PROTOCOL_VERSION,
            body: RelayFrameBody::Publish(Publish {
                stream_route: StreamRouteId::from_bytes([3; 16]),
                generation: StreamGenerationId::from_bytes([4; 16]),
                stream_seq: seq,
                sealed_blob: SealedBlob(Vec::new()),
            }),
        };
        let overhead = encode(&empty).len();
        let mut frame = empty;
        let RelayFrameBody::Publish(publish) = &mut frame.body else {
            unreachable!();
        };
        publish.sealed_blob = SealedBlob(vec![0xA5; MAX_FRAME_BYTES - overhead]);
        assert_eq!(encode(&frame).len(), MAX_FRAME_BYTES);
        frame
    }

    #[tokio::test]
    async fn default_normal_accepts_exactly_512_frames_then_fails_closed_as_lagged() {
        let (writer, mut receiver) = OutboundWriter::channel();
        for nonce in 0..DEFAULT_NORMAL_MAX_FRAMES as u64 {
            writer.try_enqueue_data(ping(nonce)).expect("within cap");
        }
        assert_eq!(writer.usage(OutboundClass::Data).frames, 512);
        assert_eq!(writer.queued_len(), 512);

        assert_eq!(
            writer.try_enqueue_data(ping(513)),
            Err(TryEnqueueError::Lagged)
        );
        assert_eq!(writer.close_reason(), Some(WriterCloseReason::Lagged));
        assert_eq!(writer.queued_len(), 0, "close must clear queued frames");
        assert!(receiver.recv().await.is_none());
    }

    #[tokio::test]
    async fn default_normal_uses_exact_canonical_bytes_at_16_mib_boundary() {
        let (writer, mut receiver) = OutboundWriter::channel();
        for seq in 0..4 {
            writer
                .try_enqueue_data(exactly_max_wire_publish(seq))
                .expect("four 4 MiB canonical frames equal 16 MiB");
        }
        assert_eq!(
            writer.usage(OutboundClass::Data).bytes,
            DEFAULT_NORMAL_MAX_BYTES
        );

        assert_eq!(
            writer.try_enqueue_data(ping(5)),
            Err(TryEnqueueError::Lagged)
        );
        assert_eq!(writer.close_reason(), Some(WriterCloseReason::Lagged));
        assert!(receiver.recv().await.is_none());
    }

    #[tokio::test]
    async fn data_and_control_share_one_fifo() {
        let (writer, mut receiver) = OutboundWriter::channel();
        writer.try_enqueue_data(ping(11)).expect("data");
        writer
            .try_enqueue_control(replay_complete())
            .expect("control");

        let data = receiver.recv().await.expect("first");
        assert!(matches!(
            decode(data.encoded()).expect("canonical data").body,
            RelayFrameBody::Ping(Ping { nonce: 11 })
        ));
        data.mark_flushed();

        let control = receiver.recv().await.expect("second");
        assert!(matches!(
            decode(control.encoded()).expect("canonical control").body,
            RelayFrameBody::ReplayComplete(_)
        ));
        control.mark_flushed();
    }

    #[tokio::test]
    async fn in_flight_permit_is_released_only_after_mark_flushed() {
        let encoded_len = encode(&ping(1)).len();
        let config = OutboundWriterConfig {
            normal: WriterBudget::new(1, encoded_len),
            control: WriterBudget::new(1, 1024),
        };
        let (writer, mut receiver) = OutboundWriter::new(config);
        writer.try_enqueue_data(ping(1)).expect("first");
        let delivery = receiver.recv().await.expect("delivery");
        assert_eq!(writer.usage(OutboundClass::Data).frames, 1);
        assert_eq!(writer.usage(OutboundClass::Data).bytes, encoded_len);

        let cancel = CancellationToken::new();
        let blocked = tokio::time::timeout(
            Duration::from_millis(20),
            writer.wait_for_normal_budget(1, encoded_len, &cancel),
        )
        .await;
        assert!(blocked.is_err(), "recv alone must not release permit");

        delivery.mark_flushed();
        writer
            .wait_for_normal_budget(1, encoded_len, &cancel)
            .await
            .expect("flush releases permit");
        assert_eq!(writer.usage(OutboundClass::Data), Usage::default());
    }

    #[tokio::test]
    async fn global_budget_bounds_aggregate_writers_until_socket_flush() {
        let frame_len = encode(&ping(1)).len();
        let control_len = encode(&replay_complete()).len();
        let global = Arc::new(GlobalWriterBudget::new(
            WriterBudget::new(2, frame_len * 2),
            WriterBudget::new(1, control_len),
        ));
        let (first, mut first_receiver) = OutboundWriter::channel();
        let (second, mut second_receiver) = OutboundWriter::channel();
        let (excess, mut excess_receiver) = OutboundWriter::channel();
        for writer in [&first, &second, &excess] {
            writer
                .bind_global_budget(Arc::clone(&global))
                .expect("bind unused writer");
        }
        first.try_enqueue_data(ping(1)).expect("first global slot");
        second
            .try_enqueue_data(ping(2))
            .expect("second global slot");
        assert_eq!(global.current_usage().normal.frames, 2);
        first
            .try_enqueue_control(replay_complete())
            .expect("global control reserve survives normal exhaustion");
        assert_eq!(global.current_usage().control.frames, 1);
        assert_eq!(
            excess.try_enqueue_data(ping(3)),
            Err(TryEnqueueError::Lagged)
        );
        assert_eq!(excess.close_reason(), Some(WriterCloseReason::Lagged));
        assert!(excess_receiver.recv().await.is_none());

        let in_flight = first_receiver.recv().await.expect("first in flight");
        assert_eq!(global.current_usage().normal.frames, 2);
        in_flight.mark_flushed();
        assert_eq!(global.current_usage().normal.frames, 1);

        let (replacement, mut replacement_receiver) = OutboundWriter::channel();
        replacement
            .bind_global_budget(Arc::clone(&global))
            .expect("bind replacement writer");
        replacement
            .try_enqueue_data(ping(4))
            .expect("flush releases aggregate slot");
        assert_eq!(global.current_usage().normal.frames, 2);
        first_receiver
            .recv()
            .await
            .expect("reserved control")
            .mark_flushed();
        second_receiver.recv().await.expect("second").mark_flushed();
        replacement_receiver
            .recv()
            .await
            .expect("replacement")
            .mark_flushed();
        assert_eq!(global.current_usage(), GlobalUsage::default());
    }

    #[tokio::test]
    async fn control_reserve_cannot_be_consumed_by_data() {
        let data_len = encode(&ping(1)).len();
        let control_len = encode(&replay_complete()).len();
        let config = OutboundWriterConfig {
            normal: WriterBudget::new(1, data_len),
            control: WriterBudget::new(1, control_len),
        };
        let (writer, mut receiver) = OutboundWriter::new(config);
        writer.try_enqueue_data(ping(1)).expect("normal full");
        writer
            .try_enqueue_control(replay_complete())
            .expect("reserved control remains available");
        assert_eq!(writer.usage(OutboundClass::Data).frames, 1);
        assert_eq!(writer.usage(OutboundClass::Control).frames, 1);

        receiver.recv().await.expect("data").mark_flushed();
        receiver.recv().await.expect("control").mark_flushed();
    }

    #[tokio::test]
    async fn exhausting_control_reserve_is_critical_and_clears_fifo() {
        let control_len = encode(&replay_complete()).len();
        let config = OutboundWriterConfig {
            normal: WriterBudget::new(1, 1024),
            control: WriterBudget::new(1, control_len),
        };
        let (writer, mut receiver) = OutboundWriter::new(config);
        writer
            .try_enqueue_control(replay_complete())
            .expect("first");
        assert_eq!(
            writer.try_enqueue_control(replay_complete()),
            Err(TryEnqueueError::CriticalBackpressure)
        );
        assert_eq!(
            writer.close_reason(),
            Some(WriterCloseReason::CriticalBackpressure)
        );
        assert!(receiver.recv().await.is_none());
    }

    #[tokio::test]
    async fn explicit_close_clears_queue_and_wakes_receiver() {
        let (writer, mut receiver) = OutboundWriter::channel();
        writer.try_enqueue_data(ping(1)).expect("queued");
        assert!(writer.close(WriterCloseReason::Shutdown));
        assert!(!writer.close(WriterCloseReason::Explicit));
        assert_eq!(writer.close_reason(), Some(WriterCloseReason::Shutdown));
        assert_eq!(writer.queued_len(), 0);
        assert!(receiver.recv().await.is_none());
    }

    #[tokio::test]
    async fn receiver_drop_fails_closed_and_rejects_future_enqueue() {
        let (writer, receiver) = OutboundWriter::channel();
        drop(receiver);
        assert_eq!(
            writer.close_reason(),
            Some(WriterCloseReason::ReceiverDropped)
        );
        assert_eq!(
            writer.try_enqueue_data(ping(1)),
            Err(TryEnqueueError::Closed(WriterCloseReason::ReceiverDropped))
        );
    }

    #[tokio::test]
    async fn delivery_drop_without_flush_fails_closed() {
        let (writer, mut receiver) = OutboundWriter::channel();
        writer.try_enqueue_data(ping(1)).expect("queued");
        let delivery = receiver.recv().await.expect("delivery");
        drop(delivery);
        assert_eq!(
            writer.close_reason(),
            Some(WriterCloseReason::DeliveryDropped)
        );
        assert_eq!(writer.usage(OutboundClass::Data), Usage::default());
    }

    #[tokio::test]
    async fn wait_for_normal_budget_is_cancellable_without_lost_wakeup() {
        let frame_len = encode(&ping(1)).len();
        let config = OutboundWriterConfig {
            normal: WriterBudget::new(1, frame_len),
            control: WriterBudget::new(1, 1024),
        };
        let (writer, _receiver) = OutboundWriter::new(config);
        writer.try_enqueue_data(ping(1)).expect("fill budget");
        let cancel = CancellationToken::new();
        let task_writer = writer.clone();
        let task_cancel = cancel.clone();
        let waiter = tokio::spawn(async move {
            task_writer
                .wait_for_normal_budget(1, frame_len, &task_cancel)
                .await
        });
        tokio::task::yield_now().await;
        cancel.cancel();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), waiter)
                .await
                .expect("waiter wakes")
                .expect("join"),
            Err(WaitForBudgetError::Cancelled)
        );
    }

    #[tokio::test]
    async fn wait_with_available_budget_observes_a_pre_cancelled_epoch() {
        let (writer, _receiver) = OutboundWriter::channel();
        let cancel = CancellationToken::new();
        cancel.cancel();

        assert_eq!(
            writer.wait_for_normal_budget(1, 1, &cancel).await,
            Err(WaitForBudgetError::Cancelled),
            "available budget must not resurrect a cancelled replay epoch"
        );
    }

    #[tokio::test]
    async fn page_reservation_is_atomic_and_releases_only_unused_budget() {
        let frame = ping(41);
        let frame_len = encode(&frame).len();
        let config = OutboundWriterConfig {
            normal: WriterBudget::new(2, frame_len * 2),
            control: WriterBudget::new(1, 1024),
        };
        let (writer, mut receiver) = OutboundWriter::new(config);
        let mut reservation = writer
            .try_reserve_normal(2, frame_len * 2)
            .expect("reserve the entire normal page atomically");
        assert_eq!(writer.usage(OutboundClass::Data).frames, 2);
        assert_eq!(writer.usage(OutboundClass::Data).bytes, frame_len * 2);

        let cancel = CancellationToken::new();
        assert!(
            tokio::time::timeout(
                Duration::from_millis(20),
                writer.wait_for_normal_budget(1, frame_len, &cancel),
            )
            .await
            .is_err(),
            "live producers cannot steal an outstanding replay reservation"
        );

        reservation
            .try_enqueue_data(frame)
            .expect("convert reserved capacity into one queued frame");
        drop(reservation);
        assert_eq!(writer.usage(OutboundClass::Data).frames, 1);
        assert_eq!(writer.usage(OutboundClass::Data).bytes, frame_len);
        receiver
            .recv()
            .await
            .expect("reserved delivery")
            .mark_flushed();
        assert_eq!(writer.usage(OutboundClass::Data), Usage::default());
    }

    #[test]
    fn page_reservation_rejects_impossible_request_without_closing_writer() {
        let (writer, _receiver) = OutboundWriter::channel();
        assert!(matches!(
            writer.try_reserve_normal(DEFAULT_NORMAL_MAX_FRAMES + 1, 1),
            Err(TryReserveWriterError::RequestExceedsLimit)
        ));
        assert!(!writer.is_closed());
        let reservation = writer
            .try_reserve_normal(1, 1)
            .expect("valid reservation after rejected config");
        drop(reservation);
        assert_eq!(writer.usage(OutboundClass::Data), Usage::default());
    }

    #[tokio::test]
    async fn close_future_wakes_writer_and_receiver_with_first_reason() {
        let (writer, receiver) = OutboundWriter::channel();
        let writer_wait = writer.clone();
        let writer_closed = tokio::spawn(async move { writer_wait.closed().await });
        let receiver_closed = tokio::spawn(async move { receiver.closed().await });
        tokio::task::yield_now().await;

        assert!(writer.close(WriterCloseReason::Lagged));
        assert!(!writer.close(WriterCloseReason::Shutdown));
        assert_eq!(
            writer_closed.await.expect("join writer waiter"),
            WriterCloseReason::Lagged
        );
        assert_eq!(
            receiver_closed.await.expect("join receiver waiter"),
            WriterCloseReason::Lagged
        );
    }

    #[tokio::test]
    async fn flushing_an_in_flight_delivery_after_close_releases_budget_but_stays_closed() {
        let (writer, mut receiver) = OutboundWriter::channel();
        writer.try_enqueue_data(ping(1)).expect("queued");
        let delivery = receiver.recv().await.expect("in-flight delivery");
        assert!(writer.close(WriterCloseReason::Lagged));

        delivery.mark_flushed();

        assert_eq!(writer.usage(OutboundClass::Data), Usage::default());
        assert_eq!(writer.close_reason(), Some(WriterCloseReason::Lagged));
        assert!(receiver.recv().await.is_none());
        assert_eq!(
            writer.try_enqueue_data(ping(2)),
            Err(TryEnqueueError::Closed(WriterCloseReason::Lagged))
        );
    }

    #[tokio::test]
    async fn terminal_admission_discards_queued_ordinary_frames_and_closes_after_flush() {
        let (writer, mut receiver) = OutboundWriter::channel();
        writer.try_enqueue_data(ping(1)).expect("queued data");
        writer
            .try_enqueue_control(replay_complete())
            .expect("queued control");

        assert_eq!(
            writer
                .try_begin_terminal(replay_complete(), WriterCloseReason::Revoked)
                .expect("dedicated terminal slot"),
            TerminalAdmission::Staged
        );
        assert!(writer.is_terminalizing());
        assert_eq!(writer.usage(OutboundClass::Data), Usage::default());
        assert_eq!(writer.usage(OutboundClass::Control), Usage::default());
        assert_eq!(
            writer.terminal_usage(),
            Usage {
                frames: 1,
                bytes: encode(&replay_complete()).len()
            }
        );
        assert_eq!(
            writer.try_enqueue_data(ping(2)),
            Err(TryEnqueueError::Closed(WriterCloseReason::Revoked))
        );

        let terminal = receiver.recv().await.expect("terminal delivery");
        assert!(terminal.is_terminal());
        assert!(matches!(
            decode(terminal.encoded()).expect("canonical terminal").body,
            RelayFrameBody::ReplayComplete(_)
        ));
        assert_eq!(writer.close_reason(), None, "close waits for flush");
        terminal.mark_flushed();

        assert_eq!(writer.close_reason(), Some(WriterCloseReason::Revoked));
        assert_eq!(writer.terminal_usage(), Usage::default());
        assert!(receiver.recv().await.is_none());
    }

    #[tokio::test]
    async fn terminal_state_and_delivery_share_one_payload_allocation_and_clear_on_flush() {
        let (writer, mut receiver) = OutboundWriter::channel();
        writer
            .try_begin_terminal(replay_complete(), WriterCloseReason::Revoked)
            .expect("stage terminal");
        {
            let inner = writer.shared.lock();
            let state = inner.terminal_state.as_ref().expect("terminal state");
            let queued = inner.queue.front().expect("queued terminal");
            assert!(Arc::ptr_eq(&state.encoded, &queued.encoded));
        }
        let terminal = receiver.recv().await.expect("terminal delivery");
        {
            let inner = writer.shared.lock();
            let state = inner
                .terminal_state
                .as_ref()
                .expect("state while in flight");
            assert!(Arc::ptr_eq(
                &state.encoded,
                terminal.encoded.as_ref().expect("delivery payload"),
            ));
        }
        terminal.mark_flushed();
        assert!(writer.shared.lock().terminal_state.is_none());
    }

    #[tokio::test]
    async fn terminal_slot_survives_full_local_and_global_control_budget() {
        let control_len = encode(&replay_complete()).len();
        let global = Arc::new(GlobalWriterBudget::new(
            WriterBudget::new(1, 1024),
            WriterBudget::new(1, control_len),
        ));
        let config = OutboundWriterConfig {
            normal: WriterBudget::new(1, 1024),
            control: WriterBudget::new(1, control_len),
        };
        let (writer, mut receiver) = OutboundWriter::new(config);
        writer
            .bind_global_budget(Arc::clone(&global))
            .expect("bind unused writer");
        writer
            .try_enqueue_control(replay_complete())
            .expect("fill local and global control");

        writer
            .try_begin_terminal(replay_complete(), WriterCloseReason::Revoked)
            .expect("terminal has an independent reserve");
        assert_eq!(global.current_usage().control, Usage::default());
        assert_eq!(global.current_usage().terminal.frames, 1);

        let terminal = receiver.recv().await.expect("terminal delivery");
        assert!(terminal.is_terminal());
        terminal.mark_flushed();
        assert_eq!(global.current_usage(), GlobalUsage::default());
    }

    #[tokio::test]
    async fn terminal_waits_behind_one_in_flight_frame_but_not_queued_frames() {
        let (writer, mut receiver) = OutboundWriter::channel();
        writer
            .try_enqueue_data(ping(1))
            .expect("in flight candidate");
        writer.try_enqueue_data(ping(2)).expect("queued candidate");
        let in_flight = receiver.recv().await.expect("ordinary in flight");

        writer
            .try_begin_terminal(replay_complete(), WriterCloseReason::Retired)
            .expect("stage terminal");
        assert_eq!(writer.usage(OutboundClass::Data).frames, 1);
        in_flight.mark_flushed();

        let terminal = receiver.recv().await.expect("terminal follows in-flight");
        assert!(terminal.is_terminal());
        terminal.mark_flushed();
        assert_eq!(writer.close_reason(), Some(WriterCloseReason::Retired));
    }

    #[tokio::test]
    async fn identical_terminal_retry_is_idempotent_and_conflict_is_rejected() {
        let (writer, mut receiver) = OutboundWriter::channel();
        assert_eq!(
            writer
                .try_begin_terminal(replay_complete(), WriterCloseReason::Revoked)
                .expect("first terminal"),
            TerminalAdmission::Staged
        );
        assert_eq!(
            writer
                .try_begin_terminal(replay_complete(), WriterCloseReason::Revoked)
                .expect("same terminal retry"),
            TerminalAdmission::Existing
        );
        assert_eq!(
            writer.try_begin_terminal(ping(9), WriterCloseReason::Revoked),
            Err(BeginTerminalError::Conflict)
        );
        assert_eq!(writer.terminal_usage().frames, 1);

        receiver
            .recv()
            .await
            .expect("one terminal only")
            .mark_flushed();
        assert_eq!(writer.close_reason(), Some(WriterCloseReason::Revoked));
    }

    #[tokio::test]
    async fn dropped_terminal_delivery_fails_closed_and_releases_global_reserve() {
        let global = Arc::new(GlobalWriterBudget::new(
            WriterBudget::new(1, 1024),
            WriterBudget::new(1, 1024),
        ));
        let (writer, mut receiver) = OutboundWriter::channel();
        writer
            .bind_global_budget(Arc::clone(&global))
            .expect("bind unused writer");
        writer
            .try_begin_terminal(replay_complete(), WriterCloseReason::Revoked)
            .expect("stage terminal");
        let terminal = receiver.recv().await.expect("terminal delivery");
        drop(terminal);

        assert_eq!(
            writer.close_reason(),
            Some(WriterCloseReason::DeliveryDropped)
        );
        assert_eq!(writer.terminal_usage(), Usage::default());
        assert_eq!(global.current_usage(), GlobalUsage::default());
    }

    #[test]
    fn explicit_close_of_queued_terminal_releases_local_and_global_reserve() {
        let global = Arc::new(GlobalWriterBudget::new(
            WriterBudget::new(1, 1024),
            WriterBudget::new(1, 1024),
        ));
        let (writer, _receiver) = OutboundWriter::channel();
        writer
            .bind_global_budget(Arc::clone(&global))
            .expect("bind unused writer");
        writer
            .try_begin_terminal(replay_complete(), WriterCloseReason::Retired)
            .expect("stage terminal");
        assert!(writer.close(WriterCloseReason::Shutdown));

        assert_eq!(writer.terminal_usage(), Usage::default());
        assert_eq!(global.current_usage(), GlobalUsage::default());
    }

    #[test]
    fn aggregate_terminal_reserve_is_exactly_bounded_by_core_connection_hard_max() {
        let global = Arc::new(GlobalWriterBudget::new(
            WriterBudget::new(1, 1024),
            WriterBudget::new(1, 1024),
        ));
        let mut channels = Vec::with_capacity(GLOBAL_TERMINAL_MAX_FRAMES);
        for _ in 0..GLOBAL_TERMINAL_MAX_FRAMES {
            let (writer, receiver) = OutboundWriter::channel();
            writer
                .bind_global_budget(Arc::clone(&global))
                .expect("bind unused writer");
            writer
                .try_begin_terminal(replay_complete(), WriterCloseReason::Revoked)
                .expect("within aggregate terminal cap");
            channels.push((writer, receiver));
        }
        assert_eq!(
            global.current_usage().terminal.frames,
            GLOBAL_TERMINAL_MAX_FRAMES
        );

        let (excess, _receiver) = OutboundWriter::channel();
        excess
            .bind_global_budget(Arc::clone(&global))
            .expect("bind excess writer");
        assert_eq!(
            excess.try_begin_terminal(replay_complete(), WriterCloseReason::Revoked),
            Err(BeginTerminalError::Capacity)
        );
        assert_eq!(
            excess.close_reason(),
            Some(WriterCloseReason::CriticalBackpressure)
        );

        drop(channels);
        assert_eq!(global.current_usage(), GlobalUsage::default());
    }

    #[tokio::test]
    async fn wait_rejects_impossible_request_and_observes_close() {
        let (writer, _receiver) = OutboundWriter::channel();
        let cancel = CancellationToken::new();
        assert_eq!(
            writer
                .wait_for_normal_budget(DEFAULT_NORMAL_MAX_FRAMES + 1, 0, &cancel)
                .await,
            Err(WaitForBudgetError::RequestExceedsLimit)
        );
        writer.close(WriterCloseReason::Shutdown);
        assert_eq!(
            writer.wait_for_normal_budget(1, 1, &cancel).await,
            Err(WaitForBudgetError::Closed(WriterCloseReason::Shutdown))
        );
    }

    #[test]
    fn debug_output_redacts_payload_bytes() {
        let secret = b"writer-super-secret-marker";
        let frame = OpaqueRouteFrame {
            version: RELAY_PROTOCOL_VERSION,
            body: RelayFrameBody::Publish(Publish {
                stream_route: StreamRouteId::from_bytes([3; 16]),
                generation: StreamGenerationId::from_bytes([4; 16]),
                stream_seq: 1,
                sealed_blob: SealedBlob(secret.to_vec()),
            }),
        };
        let (writer, _receiver) = OutboundWriter::channel();
        writer.try_enqueue_data(frame).expect("queued");
        let debug = format!("{writer:?}");
        assert!(!debug.contains("writer-super-secret-marker"));
        assert!(!debug.contains(&hex(secret)));
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
