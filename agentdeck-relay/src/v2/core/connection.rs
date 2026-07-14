//! Core actor 独占的连接与 runtime subscription 状态。
//!
//! 本模块故意不加锁：所有 mutation 都只能由单一 RelayCore actor 调用。Store 中的
//! subscription/ACK 是 durable truth；这里仅保存当前 connection generation 的 writer、
//! replay barrier 与 heartbeat 状态，disconnect 时必须整体清除。

use std::collections::{HashMap, VecDeque};

use agentdeck_protocol::relay_v2::{
    ConnectionInstanceId, MachineRouteId, OpaqueRouteFrame, StreamCursor, StreamGenerationId,
    StreamRouteId, encode,
};
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;

use crate::v2::auth::{AccessContext, PrincipalRoute};

use super::writer::{TerminalAdmission, WriterCloseReason, WriterHandle};

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct StreamKey {
    pub stream_route: StreamRouteId,
    pub generation: StreamGenerationId,
}

impl std::fmt::Debug for StreamKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StreamKey")
            .field("stream", &self.stream_route.redacted())
            .field("generation", &self.generation.redacted())
            .finish()
    }
}

impl StreamKey {
    pub(crate) const fn new(stream_route: StreamRouteId, generation: StreamGenerationId) -> Self {
        Self {
            stream_route,
            generation,
        }
    }
}

/// 连接内单个订阅的交付阶段。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SubscriptionPhase {
    /// 首轮重放严格冻结在 Subscribe transaction 读出的 terminal；其后的 Publish 只推进
    /// `missed_hwm`，不能抢跑到 ReplayComplete 前。
    Replaying {
        replay_epoch: u64,
        cursor: StreamCursor,
        terminal: StreamCursor,
        missed_hwm: Option<u64>,
    },
    /// 同一 connection 只允许一个 task 物化 replay page；其余 subscription 进入有界
    /// actor-owned FIFO，避免并发 page reservation 互相挤爆 writer。
    ReplayQueued {
        mode: ReplayStartMode,
        cursor: StreamCursor,
        terminal: StreamCursor,
        missed_hwm: Option<u64>,
    },
    /// 首轮 ReplayComplete 已进入同一 FIFO，正在补投 terminal 之后的并发 Publish。
    /// 此阶段不再发送第二个 ReplayComplete。
    PostTerminalCatchup {
        replay_epoch: u64,
        cursor: StreamCursor,
        terminal: StreamCursor,
        missed_hwm: Option<u64>,
    },
    Live {
        cursor: StreamCursor,
    },
    /// 缺口后禁止任何更高 live frame，直到显式、合法的同 generation Subscribe 替换它。
    GapPaused {
        needed: u64,
        oldest: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RuntimeSubscription {
    pub phase: SubscriptionPhase,
}

#[derive(Clone)]
pub(crate) struct ReplayStart {
    pub connection: ConnectionInstanceId,
    pub key: StreamKey,
    pub replay_epoch: u64,
    pub mode: ReplayStartMode,
    pub cursor: StreamCursor,
    pub terminal: StreamCursor,
    pub cancel: CancellationToken,
}

impl std::fmt::Debug for ReplayStart {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ReplayStart")
            .field("connection", &self.connection.redacted())
            .field("key", &self.key)
            .field("replay_epoch", &self.replay_epoch)
            .field("mode", &self.mode)
            .field("cursor", &self.cursor)
            .field("terminal", &self.terminal)
            .field("cancelled", &self.cancel.is_cancelled())
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReplayStartMode {
    Initial,
    PostTerminal,
}

#[derive(Debug, Clone)]
pub(crate) struct InitialReplayCompleted {
    pub catchup: Option<ReplayStart>,
    pub next_queued: Option<ReplayStart>,
}

#[derive(Debug, Clone)]
pub(crate) struct CatchupCompleted {
    pub next: Option<ReplayStart>,
    pub live_cursor: Option<StreamCursor>,
    pub next_queued: Option<ReplayStart>,
}

#[derive(Debug, Clone)]
pub(crate) enum ReplayAdmission {
    Started(ReplayStart),
    Queued,
}

#[derive(Debug, Clone, Copy)]
struct QueuedReplay {
    key: StreamKey,
    mode: ReplayStartMode,
    cursor: StreamCursor,
    terminal: StreamCursor,
    missed_hwm: Option<u64>,
}

#[derive(Clone)]
pub(crate) struct LiveDelivery {
    pub connection: ConnectionInstanceId,
    pub access: AccessContext,
    pub writer: WriterHandle,
    pub kind: LiveDeliveryKind,
}

impl std::fmt::Debug for LiveDelivery {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LiveDelivery")
            .field("connection", &self.connection.redacted())
            .field("access", &self.access)
            .field("writer", &self.writer)
            .field("kind", &self.kind)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LiveDeliveryKind {
    Frame,
    Gap { needed: u64, oldest: u64 },
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ConnectionCleanup {
    pub connection: ConnectionInstanceId,
    pub access: Option<AccessContext>,
    pub principal: Option<PrincipalRoute>,
}

impl std::fmt::Debug for ConnectionCleanup {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConnectionCleanup")
            .field("connection", &self.connection.redacted())
            .field("has_access", &self.access.is_some())
            .field("principal", &self.principal)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConnectionStateError {
    DuplicateConnection,
    ConnectionNotFound,
    ConnectionNotActive,
    AccessMismatch,
    SubscriptionLimit,
    ReplayEpochExhausted,
    ReplayMismatch,
    HeartbeatAlreadyPending,
    TerminalRejected,
}

impl std::fmt::Display for ConnectionStateError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "Relay connection state rejected operation: {self:?}"
        )
    }
}

impl std::error::Error for ConnectionStateError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PendingPing {
    pub nonce: u64,
    pub sent_at_ms: u64,
}

pub(crate) struct ConnectionEntry {
    pub writer: WriterHandle,
    pub access: Option<AccessContext>,
    /// Activated lifecycle 可能先于 transport 的 `activate(access)` 到达；保留 principal
    /// 使 pending writer 死亡时仍能精确清掉 AuthorizationCoordinator 中的 orphan active。
    pub pending_principal: Option<PrincipalRoute>,
    pub subscriptions: HashMap<StreamKey, RuntimeSubscription>,
    pub replay_key: Option<StreamKey>,
    pub replay_cancel: Option<CancellationToken>,
    pending_replays: VecDeque<QueuedReplay>,
    pub next_replay_epoch: u64,
    pub last_pong_ms: u64,
    pub last_ping_ms: u64,
    pub pending_ping: Option<PendingPing>,
    pub terminal: Option<TerminalDrain>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TerminalDrain {
    pub token: TerminalToken,
    pub close_reason: WriterCloseReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TerminalToken {
    epoch: u64,
    digest: [u8; 32],
}

pub(crate) struct TerminalStage {
    pub token: TerminalToken,
    pub writer: WriterHandle,
    pub admission: TerminalAdmission,
}

/// Actor future 被 runtime 取消或 panic 时，`ConnectionRegistry` 可能来不及走显式
/// `close_all`。entry 自身因此承担最后一道 fail-closed：transport 即使还持 writer clone，
/// 也会立即看到关闭；活跃 replay token 同时被取消。显式关闭路径仍由 first reason wins。
impl Drop for ConnectionEntry {
    fn drop(&mut self) {
        if let Some(cancel) = self.replay_cancel.take() {
            cancel.cancel();
        }
        self.writer.close(WriterCloseReason::Shutdown);
    }
}

/// 只由 RelayCore actor 修改；不在内部加锁。
pub struct ConnectionRegistry {
    pub(crate) entries: HashMap<ConnectionInstanceId, ConnectionEntry>,
    pub(crate) max_subscriptions_per_connection: usize,
    next_terminal_epoch: u64,
}

impl ConnectionRegistry {
    pub(crate) fn new(max_subscriptions_per_connection: usize) -> Self {
        Self {
            entries: HashMap::new(),
            max_subscriptions_per_connection,
            next_terminal_epoch: 1,
        }
    }

    pub(crate) fn contains(&self, connection: ConnectionInstanceId) -> bool {
        self.entries.contains_key(&connection)
    }

    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    /// pending writer 必须在鉴权前注册；重复 connection instance 不得替换既有 writer。
    pub(crate) fn attach_pending(
        &mut self,
        connection: ConnectionInstanceId,
        writer: WriterHandle,
        now_ms: u64,
    ) -> Result<(), (ConnectionStateError, WriterHandle)> {
        if self.entries.contains_key(&connection) {
            return Err((ConnectionStateError::DuplicateConnection, writer));
        }
        self.entries.insert(
            connection,
            ConnectionEntry {
                writer,
                access: None,
                pending_principal: None,
                subscriptions: HashMap::new(),
                replay_key: None,
                replay_cancel: None,
                pending_replays: VecDeque::new(),
                next_replay_epoch: 1,
                last_pong_ms: now_ms,
                last_ping_ms: now_ms,
                pending_ping: None,
                terminal: None,
            },
        );
        Ok(())
    }

    /// 绑定真实 auth 结果；同 principal 的旧 generation 在本调用返回前确定性关闭。
    /// lifecycle channel 仍是 fail-closed 兜底，但不承担 activate 的线性化屏障。
    pub(crate) fn activate(
        &mut self,
        access: AccessContext,
        now_ms: u64,
        replacement_reason: WriterCloseReason,
    ) -> Result<Option<ConnectionCleanup>, ConnectionStateError> {
        let connection = access.connection_instance();
        let principal = access.principal_route();
        let target = self
            .entries
            .get(&connection)
            .ok_or(ConnectionStateError::ConnectionNotFound)?;
        if matches!((target.pending_principal, principal), (Some(_), None))
            || matches!(
                (target.pending_principal, principal),
                (Some(pending), Some(active)) if pending != active
            )
        {
            return Err(ConnectionStateError::AccessMismatch);
        }
        if target.terminal.is_some() {
            return Err(ConnectionStateError::ConnectionNotActive);
        }
        if let Some(existing) = &target.access {
            if existing == &access {
                return Ok(None);
            }
            return Err(ConnectionStateError::AccessMismatch);
        }

        let replaced = principal.and_then(|principal| {
            self.entries.iter().find_map(|(candidate, entry)| {
                (*candidate != connection
                    && entry
                        .access
                        .as_ref()
                        .and_then(AccessContext::principal_route)
                        == Some(principal))
                .then_some(*candidate)
            })
        });
        let cleanup = replaced.and_then(|old| self.remove_and_close(old, replacement_reason));

        let target = self
            .entries
            .get_mut(&connection)
            .ok_or(ConnectionStateError::ConnectionNotFound)?;
        target.access = Some(access);
        target.pending_principal = principal;
        target.last_pong_ms = now_ms;
        target.last_ping_ms = now_ms;
        target.pending_ping = None;
        Ok(cleanup)
    }

    /// 记录 coordinator 已提交的 activation；pending connection 尚无完整 AccessContext，
    /// 但 cleanup 必须从此刻起拥有精确 principal route。
    pub(crate) fn note_activation(
        &mut self,
        connection: ConnectionInstanceId,
        principal: PrincipalRoute,
    ) -> Result<(), ConnectionStateError> {
        let entry = self
            .entries
            .get_mut(&connection)
            .ok_or(ConnectionStateError::ConnectionNotFound)?;
        if entry
            .access
            .as_ref()
            .and_then(AccessContext::principal_route)
            .is_some_and(|active| active != principal)
            || entry
                .pending_principal
                .is_some_and(|pending| pending != principal)
        {
            return Err(ConnectionStateError::AccessMismatch);
        }
        entry.pending_principal = Some(principal);
        Ok(())
    }

    pub(crate) fn validates(&self, access: &AccessContext) -> bool {
        self.entries
            .get(&access.connection_instance())
            .filter(|entry| entry.terminal.is_none())
            .and_then(|entry| entry.access.as_ref())
            == Some(access)
    }

    pub(crate) fn writer_for(&self, access: &AccessContext) -> Option<WriterHandle> {
        self.entries
            .get(&access.connection_instance())
            .filter(|entry| entry.terminal.is_none() && entry.access.as_ref() == Some(access))
            .map(|entry| entry.writer.clone())
    }

    /// COMMIT 后把连接切到 terminal drain。普通 runtime/replay 状态立即清空，但 entry 与
    /// writer 保留到 terminal flush、2 秒 deadline 或 transport failure。
    pub(crate) fn begin_terminal(
        &mut self,
        connection: ConnectionInstanceId,
        frame: OpaqueRouteFrame,
        close_reason: WriterCloseReason,
    ) -> Result<TerminalStage, ConnectionStateError> {
        let encoded = encode(&frame);
        let digest: [u8; 32] = Sha256::digest(&encoded).into();
        let entry = self
            .entries
            .get(&connection)
            .ok_or(ConnectionStateError::ConnectionNotFound)?;
        if let Some(existing) = entry.terminal {
            return if existing.token.digest == digest && existing.close_reason == close_reason {
                Ok(TerminalStage {
                    token: existing.token,
                    writer: entry.writer.clone(),
                    admission: TerminalAdmission::Existing,
                })
            } else {
                Err(ConnectionStateError::TerminalRejected)
            };
        }
        let epoch = self.next_terminal_epoch;
        self.next_terminal_epoch = self
            .next_terminal_epoch
            .checked_add(1)
            .ok_or(ConnectionStateError::TerminalRejected)?;
        let token = TerminalToken { epoch, digest };
        let entry = self
            .entries
            .get_mut(&connection)
            .ok_or(ConnectionStateError::ConnectionNotFound)?;
        let admission = entry
            .writer
            .try_begin_terminal(frame, close_reason)
            .map_err(|_| ConnectionStateError::TerminalRejected)?;
        if let Some(cancel) = entry.replay_cancel.take() {
            cancel.cancel();
        }
        entry.replay_key = None;
        entry.pending_replays.clear();
        entry.subscriptions.clear();
        entry.pending_ping = None;
        entry.terminal = Some(TerminalDrain {
            token,
            close_reason,
        });
        Ok(TerminalStage {
            token,
            writer: entry.writer.clone(),
            admission,
        })
    }

    pub(crate) fn begin_terminal_reauth(
        &mut self,
        access: &AccessContext,
        frame: OpaqueRouteFrame,
        close_reason: WriterCloseReason,
    ) -> Result<TerminalStage, ConnectionStateError> {
        let connection = access.connection_instance();
        let principal = access
            .principal_route()
            .ok_or(ConnectionStateError::AccessMismatch)?;
        let entry = self
            .entries
            .get(&connection)
            .ok_or(ConnectionStateError::ConnectionNotFound)?;
        if entry.access.is_some()
            || entry
                .pending_principal
                .is_some_and(|pending| pending != principal)
        {
            return Err(ConnectionStateError::AccessMismatch);
        }
        let staged = self.begin_terminal(connection, frame, close_reason)?;
        let entry = self
            .entries
            .get_mut(&connection)
            .ok_or(ConnectionStateError::ConnectionNotFound)?;
        entry.pending_principal = Some(principal);
        Ok(staged)
    }

    pub(crate) fn is_terminal(&self, connection: ConnectionInstanceId) -> bool {
        self.entries
            .get(&connection)
            .is_some_and(|entry| entry.terminal.is_some())
    }

    pub(crate) fn finish_terminal(
        &mut self,
        connection: ConnectionInstanceId,
        token: TerminalToken,
    ) -> Option<ConnectionCleanup> {
        let matches = self
            .entries
            .get(&connection)
            .and_then(|entry| entry.terminal)
            .is_some_and(|terminal| terminal.token == token);
        if !matches {
            return None;
        }
        let reason = self
            .entries
            .get(&connection)
            .and_then(|entry| entry.terminal)
            .map(|terminal| terminal.close_reason)?;
        self.remove_and_close(connection, reason)
    }

    pub(crate) fn begin_initial_replay(
        &mut self,
        connection: ConnectionInstanceId,
        key: StreamKey,
        cursor: StreamCursor,
        terminal: StreamCursor,
    ) -> Result<ReplayAdmission, ConnectionStateError> {
        let max_subscriptions = self.max_subscriptions_per_connection;
        let entry = self.active_entry_mut(connection)?;
        if !entry.subscriptions.contains_key(&key) && entry.subscriptions.len() >= max_subscriptions
        {
            return Err(ConnectionStateError::SubscriptionLimit);
        }
        if entry.replay_key == Some(key) {
            return Err(ConnectionStateError::ReplayMismatch);
        }
        entry.pending_replays.retain(|queued| queued.key != key);
        if entry.replay_key.is_some() {
            entry.subscriptions.insert(
                key,
                RuntimeSubscription {
                    phase: SubscriptionPhase::ReplayQueued {
                        mode: ReplayStartMode::Initial,
                        cursor,
                        terminal,
                        missed_hwm: None,
                    },
                },
            );
            entry.pending_replays.push_back(QueuedReplay {
                key,
                mode: ReplayStartMode::Initial,
                cursor,
                terminal,
                missed_hwm: None,
            });
            return Ok(ReplayAdmission::Queued);
        }
        let start = start_replay(
            entry,
            connection,
            key,
            ReplayStartMode::Initial,
            cursor,
            terminal,
            None,
        )?;
        Ok(ReplayAdmission::Started(start))
    }

    fn start_next_queued(
        entry: &mut ConnectionEntry,
        connection: ConnectionInstanceId,
    ) -> Result<Option<ReplayStart>, ConnectionStateError> {
        if entry.replay_key.is_some() {
            return Ok(None);
        }
        let Some(queued) = entry.pending_replays.pop_front() else {
            return Ok(None);
        };
        start_replay(
            entry,
            connection,
            queued.key,
            queued.mode,
            queued.cursor,
            queued.terminal,
            queued.missed_hwm,
        )
        .map(Some)
    }

    fn install_replaying_phase(
        entry: &mut ConnectionEntry,
        key: StreamKey,
        replay_epoch: u64,
        mode: ReplayStartMode,
        cursor: StreamCursor,
        terminal: StreamCursor,
        missed_hwm: Option<u64>,
    ) {
        let phase = match mode {
            ReplayStartMode::Initial => SubscriptionPhase::Replaying {
                replay_epoch,
                cursor,
                terminal,
                missed_hwm,
            },
            ReplayStartMode::PostTerminal => SubscriptionPhase::PostTerminalCatchup {
                replay_epoch,
                cursor,
                terminal,
                missed_hwm,
            },
        };
        entry
            .subscriptions
            .insert(key, RuntimeSubscription { phase });
    }

    /// Publish COMMIT 后调用。Live 目标只返回尚未推进的 seq；replay/catch-up 只记录
    /// high-water，不缓存 ciphertext，也不让 live 抢跑。
    pub(crate) fn note_committed_publish(
        &mut self,
        machine_route: MachineRouteId,
        key: StreamKey,
        stream_seq: u64,
    ) -> Vec<LiveDelivery> {
        let mut deliveries = Vec::new();
        for (connection, entry) in &mut self.entries {
            let Some(access) = entry.access.as_ref() else {
                continue;
            };
            if !is_device_for_machine(Some(access), machine_route) {
                continue;
            }
            let Some(subscription) = entry.subscriptions.get_mut(&key) else {
                continue;
            };
            let mut queued_missed = None;
            match &mut subscription.phase {
                SubscriptionPhase::Replaying {
                    terminal,
                    missed_hwm,
                    ..
                }
                | SubscriptionPhase::PostTerminalCatchup {
                    terminal,
                    missed_hwm,
                    ..
                } => {
                    if cursor_is_before(*terminal, stream_seq) {
                        *missed_hwm =
                            Some(missed_hwm.map_or(stream_seq, |old| old.max(stream_seq)));
                    }
                }
                SubscriptionPhase::ReplayQueued {
                    terminal,
                    missed_hwm,
                    ..
                } => {
                    if cursor_is_before(*terminal, stream_seq) {
                        let updated = missed_hwm.map_or(stream_seq, |old| old.max(stream_seq));
                        *missed_hwm = Some(updated);
                        queued_missed = Some(updated);
                    }
                }
                SubscriptionPhase::Live { cursor } => {
                    match next_after_cursor(*cursor) {
                        Some(expected) if stream_seq == expected => {
                            *cursor = StreamCursor::At(stream_seq);
                            deliveries.push(LiveDelivery {
                                connection: *connection,
                                access: access.clone(),
                                writer: entry.writer.clone(),
                                kind: LiveDeliveryKind::Frame,
                            });
                        }
                        Some(expected) if stream_seq > expected => {
                            subscription.phase = SubscriptionPhase::GapPaused {
                                needed: expected,
                                oldest: stream_seq,
                            };
                            deliveries.push(LiveDelivery {
                                connection: *connection,
                                access: access.clone(),
                                writer: entry.writer.clone(),
                                kind: LiveDeliveryKind::Gap {
                                    needed: expected,
                                    oldest: stream_seq,
                                },
                            });
                        }
                        Some(_) | None => {
                            // canonical duplicate 或耗尽 generation；均不得重复投递。
                        }
                    }
                }
                SubscriptionPhase::GapPaused { .. } => {}
            }
            if let Some(updated) = queued_missed
                && let Some(queued) = entry
                    .pending_replays
                    .iter_mut()
                    .find(|queued| queued.key == key)
            {
                queued.missed_hwm = Some(updated);
            }
        }
        deliveries
    }

    /// 首轮 replay task 已把冻结 terminal 的全部 frame 入 FIFO。调用方随后应把唯一的
    /// ReplayComplete 入同一 FIFO；若有 missed HWM，再启动返回的 post-terminal catchup。
    pub(crate) fn complete_initial_replay(
        &mut self,
        connection: ConnectionInstanceId,
        key: StreamKey,
        replay_epoch: u64,
    ) -> Result<InitialReplayCompleted, ConnectionStateError> {
        let entry = self.active_entry_mut(connection)?;
        ensure_active_replay(entry, key)?;
        let subscription = entry
            .subscriptions
            .get(&key)
            .ok_or(ConnectionStateError::ReplayMismatch)?;
        let (terminal, missed_hwm) = match subscription.phase {
            SubscriptionPhase::Replaying {
                replay_epoch: actual,
                terminal,
                missed_hwm,
                ..
            } if actual == replay_epoch => (terminal, missed_hwm),
            _ => return Err(ConnectionStateError::ReplayMismatch),
        };
        clear_active_replay(entry);

        let (catchup, next_queued) = match missed_after(terminal, missed_hwm) {
            Some(through) if entry.pending_replays.is_empty() => (
                Some(begin_catchup(entry, connection, key, terminal, through)?),
                None,
            ),
            Some(through) => {
                enqueue_catchup(entry, key, terminal, through)?;
                (None, Self::start_next_queued(entry, connection)?)
            }
            None => {
                entry
                    .subscriptions
                    .get_mut(&key)
                    .ok_or(ConnectionStateError::ReplayMismatch)?
                    .phase = SubscriptionPhase::Live { cursor: terminal };
                (None, Self::start_next_queued(entry, connection)?)
            }
        };
        Ok(InitialReplayCompleted {
            catchup,
            next_queued,
        })
    }

    /// post-terminal catchup 完成；期间又出现的 Publish 会形成下一段固定 catchup，直到
    /// actor 观察到没有 missed HWM 才进入 Live。
    pub(crate) fn complete_catchup(
        &mut self,
        connection: ConnectionInstanceId,
        key: StreamKey,
        replay_epoch: u64,
        actual_replay_through: StreamCursor,
    ) -> Result<CatchupCompleted, ConnectionStateError> {
        let entry = self.active_entry_mut(connection)?;
        ensure_active_replay(entry, key)?;
        let subscription = entry
            .subscriptions
            .get(&key)
            .ok_or(ConnectionStateError::ReplayMismatch)?;
        let (predicted_terminal, missed_hwm) = match subscription.phase {
            SubscriptionPhase::PostTerminalCatchup {
                replay_epoch: actual,
                terminal,
                missed_hwm,
                ..
            } if actual == replay_epoch => (terminal, missed_hwm),
            _ => return Err(ConnectionStateError::ReplayMismatch),
        };
        if !cursor_at_or_after(actual_replay_through, predicted_terminal) {
            return Err(ConnectionStateError::ReplayMismatch);
        }
        clear_active_replay(entry);
        match missed_after(actual_replay_through, missed_hwm) {
            Some(through) if entry.pending_replays.is_empty() => Ok(CatchupCompleted {
                next: Some(begin_catchup(
                    entry,
                    connection,
                    key,
                    actual_replay_through,
                    through,
                )?),
                live_cursor: None,
                next_queued: None,
            }),
            Some(through) => {
                enqueue_catchup(entry, key, actual_replay_through, through)?;
                let next_queued = Self::start_next_queued(entry, connection)?;
                Ok(CatchupCompleted {
                    next: None,
                    live_cursor: None,
                    next_queued,
                })
            }
            None => {
                entry
                    .subscriptions
                    .get_mut(&key)
                    .ok_or(ConnectionStateError::ReplayMismatch)?
                    .phase = SubscriptionPhase::Live {
                    cursor: actual_replay_through,
                };
                let next_queued = Self::start_next_queued(entry, connection)?;
                Ok(CatchupCompleted {
                    next: None,
                    live_cursor: Some(actual_replay_through),
                    next_queued,
                })
            }
        }
    }

    pub(crate) fn pause_gap(
        &mut self,
        connection: ConnectionInstanceId,
        key: StreamKey,
        needed: u64,
        oldest: u64,
    ) -> Result<Option<ReplayStart>, ConnectionStateError> {
        let max_subscriptions = self.max_subscriptions_per_connection;
        let entry = self.active_entry_mut(connection)?;
        if !entry.subscriptions.contains_key(&key) && entry.subscriptions.len() >= max_subscriptions
        {
            return Err(ConnectionStateError::SubscriptionLimit);
        }
        if entry.replay_key == Some(key) {
            clear_active_replay(entry);
        }
        entry.pending_replays.retain(|queued| queued.key != key);
        entry.subscriptions.insert(
            key,
            RuntimeSubscription {
                phase: SubscriptionPhase::GapPaused { needed, oldest },
            },
        );
        Self::start_next_queued(entry, connection)
    }

    /// 显式 Unsubscribe 只清 runtime；调用方必须先完成 Store delete COMMIT。
    pub(crate) fn unsubscribe_runtime(
        &mut self,
        connection: ConnectionInstanceId,
        key: StreamKey,
    ) -> Result<(bool, Option<ReplayStart>), ConnectionStateError> {
        let entry = self.active_entry_mut(connection)?;
        let was_active = entry.replay_key == Some(key);
        if entry.replay_key == Some(key) {
            clear_active_replay(entry);
        }
        entry.pending_replays.retain(|queued| queued.key != key);
        let removed = entry.subscriptions.remove(&key).is_some();
        let next = if was_active {
            Self::start_next_queued(entry, connection)?
        } else {
            None
        };
        Ok((removed, next))
    }

    pub(crate) fn subscription_phase(
        &self,
        connection: ConnectionInstanceId,
        key: StreamKey,
    ) -> Option<&SubscriptionPhase> {
        Some(
            &self
                .entries
                .get(&connection)?
                .subscriptions
                .get(&key)?
                .phase,
        )
    }

    pub(crate) fn heartbeat_candidates(
        &self,
        now_ms: u64,
        interval_ms: u64,
    ) -> Vec<ConnectionInstanceId> {
        self.entries
            .iter()
            .filter_map(|(connection, entry)| {
                (entry.access.is_some()
                    && entry.terminal.is_none()
                    && entry.pending_ping.is_none()
                    && now_ms.saturating_sub(entry.last_ping_ms) >= interval_ms)
                    .then_some(*connection)
            })
            .collect()
    }

    /// 返回已越过 root-signed MachineLink absolute expiry 的 active connections。
    /// `None` 代表证书没有 absolute expiry，不参与此清理。
    pub(crate) fn expired_machine_links(&self, now_ms: u64) -> Vec<ConnectionInstanceId> {
        self.entries
            .iter()
            .filter_map(|(connection, entry)| {
                (entry.terminal.is_none()
                    && entry
                        .access
                        .as_ref()
                        .is_some_and(|access| access.machine_link_is_expired_at(now_ms)))
                .then_some(*connection)
            })
            .collect()
    }

    pub(crate) fn record_ping(
        &mut self,
        connection: ConnectionInstanceId,
        nonce: u64,
        now_ms: u64,
    ) -> Result<WriterHandle, ConnectionStateError> {
        let entry = self.active_entry_mut(connection)?;
        if entry.pending_ping.is_some() {
            return Err(ConnectionStateError::HeartbeatAlreadyPending);
        }
        entry.pending_ping = Some(PendingPing {
            nonce,
            sent_at_ms: now_ms,
        });
        entry.last_ping_ms = now_ms;
        Ok(entry.writer.clone())
    }

    /// 只有 exact pending nonce 才刷新 lease；错误/迟到 Pong 完全不改变 heartbeat 状态。
    pub(crate) fn accept_pong(
        &mut self,
        connection: ConnectionInstanceId,
        nonce: u64,
        now_ms: u64,
    ) -> Result<bool, ConnectionStateError> {
        let entry = self.active_entry_mut(connection)?;
        if entry
            .pending_ping
            .is_some_and(|pending| pending.nonce == nonce)
        {
            entry.pending_ping = None;
            entry.last_pong_ms = now_ms;
            return Ok(true);
        }
        Ok(false)
    }

    pub(crate) fn timed_out(&self, now_ms: u64, timeout_ms: u64) -> Vec<ConnectionInstanceId> {
        self.entries
            .iter()
            .filter_map(|(connection, entry)| {
                (entry.terminal.is_none()
                    && now_ms.saturating_sub(entry.last_pong_ms) >= timeout_ms)
                    .then_some(*connection)
            })
            .collect()
    }

    pub(crate) fn remove_and_close(
        &mut self,
        connection: ConnectionInstanceId,
        reason: WriterCloseReason,
    ) -> Option<ConnectionCleanup> {
        let mut entry = self.entries.remove(&connection)?;
        if let Some(cancel) = entry.replay_cancel.take() {
            cancel.cancel();
        }
        entry.replay_key = None;
        entry.writer.close(reason);
        let access = entry.access.take();
        let principal = access
            .as_ref()
            .and_then(AccessContext::principal_route)
            .or(entry.pending_principal);
        Some(ConnectionCleanup {
            connection,
            access,
            principal,
        })
    }

    pub(crate) fn remove_if_access_and_close(
        &mut self,
        access: &AccessContext,
        reason: WriterCloseReason,
    ) -> Option<ConnectionCleanup> {
        self.validates(access)
            .then(|| self.remove_and_close(access.connection_instance(), reason))
            .flatten()
    }

    pub(crate) fn close_all(&mut self, reason: WriterCloseReason) -> Vec<ConnectionCleanup> {
        let connections: Vec<_> = self.entries.keys().copied().collect();
        connections
            .into_iter()
            .filter_map(|connection| self.remove_and_close(connection, reason))
            .collect()
    }

    fn active_entry_mut(
        &mut self,
        connection: ConnectionInstanceId,
    ) -> Result<&mut ConnectionEntry, ConnectionStateError> {
        let entry = self
            .entries
            .get_mut(&connection)
            .ok_or(ConnectionStateError::ConnectionNotFound)?;
        if entry.access.is_none() {
            return Err(ConnectionStateError::ConnectionNotActive);
        }
        if entry.terminal.is_some() {
            return Err(ConnectionStateError::ConnectionNotActive);
        }
        Ok(entry)
    }
}

fn take_replay_epoch(entry: &mut ConnectionEntry) -> Result<u64, ConnectionStateError> {
    let epoch = entry.next_replay_epoch;
    entry.next_replay_epoch = epoch
        .checked_add(1)
        .ok_or(ConnectionStateError::ReplayEpochExhausted)?;
    Ok(epoch)
}

fn start_replay(
    entry: &mut ConnectionEntry,
    connection: ConnectionInstanceId,
    key: StreamKey,
    mode: ReplayStartMode,
    cursor: StreamCursor,
    terminal: StreamCursor,
    missed_hwm: Option<u64>,
) -> Result<ReplayStart, ConnectionStateError> {
    let replay_epoch = take_replay_epoch(entry)?;
    let cancel = CancellationToken::new();
    entry.replay_key = Some(key);
    entry.replay_cancel = Some(cancel.clone());
    ConnectionRegistry::install_replaying_phase(
        entry,
        key,
        replay_epoch,
        mode,
        cursor,
        terminal,
        missed_hwm,
    );
    Ok(ReplayStart {
        connection,
        key,
        replay_epoch,
        mode,
        cursor,
        terminal,
        cancel,
    })
}

fn begin_catchup(
    entry: &mut ConnectionEntry,
    connection: ConnectionInstanceId,
    key: StreamKey,
    cursor: StreamCursor,
    through: u64,
) -> Result<ReplayStart, ConnectionStateError> {
    let terminal = StreamCursor::At(through);
    if !entry.subscriptions.contains_key(&key) {
        return Err(ConnectionStateError::ReplayMismatch);
    }
    start_replay(
        entry,
        connection,
        key,
        ReplayStartMode::PostTerminal,
        cursor,
        terminal,
        None,
    )
}

fn enqueue_catchup(
    entry: &mut ConnectionEntry,
    key: StreamKey,
    cursor: StreamCursor,
    through: u64,
) -> Result<(), ConnectionStateError> {
    let terminal = StreamCursor::At(through);
    let subscription = entry
        .subscriptions
        .get_mut(&key)
        .ok_or(ConnectionStateError::ReplayMismatch)?;
    subscription.phase = SubscriptionPhase::ReplayQueued {
        mode: ReplayStartMode::PostTerminal,
        cursor,
        terminal,
        missed_hwm: None,
    };
    entry.pending_replays.retain(|queued| queued.key != key);
    entry.pending_replays.push_back(QueuedReplay {
        key,
        mode: ReplayStartMode::PostTerminal,
        cursor,
        terminal,
        missed_hwm: None,
    });
    Ok(())
}

fn ensure_active_replay(
    entry: &ConnectionEntry,
    key: StreamKey,
) -> Result<(), ConnectionStateError> {
    if entry.replay_key == Some(key) && entry.replay_cancel.is_some() {
        Ok(())
    } else {
        Err(ConnectionStateError::ReplayMismatch)
    }
}

fn clear_active_replay(entry: &mut ConnectionEntry) {
    if let Some(cancel) = entry.replay_cancel.take() {
        cancel.cancel();
    }
    entry.replay_key = None;
}

fn missed_after(terminal: StreamCursor, missed_hwm: Option<u64>) -> Option<u64> {
    missed_hwm.filter(|seq| cursor_is_before(terminal, *seq))
}

fn cursor_is_before(cursor: StreamCursor, sequence: u64) -> bool {
    match cursor {
        StreamCursor::BeforeFirst => true,
        StreamCursor::At(current) => current < sequence,
    }
}

fn cursor_at_or_after(candidate: StreamCursor, baseline: StreamCursor) -> bool {
    match (candidate, baseline) {
        (_, StreamCursor::BeforeFirst) => true,
        (StreamCursor::BeforeFirst, StreamCursor::At(_)) => false,
        (StreamCursor::At(candidate), StreamCursor::At(baseline)) => candidate >= baseline,
    }
}

fn next_after_cursor(cursor: StreamCursor) -> Option<u64> {
    match cursor {
        StreamCursor::BeforeFirst => Some(0),
        StreamCursor::At(current) => current.checked_add(1),
    }
}

fn is_device_for_machine(access: Option<&AccessContext>, machine: MachineRouteId) -> bool {
    matches!(
        access.and_then(AccessContext::principal_route),
        Some(PrincipalRoute::Device { machine_route, .. }) if machine_route == machine
    )
}

impl std::fmt::Debug for ConnectionRegistry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConnectionRegistry")
            .field("connection_count", &self.entries.len())
            .field(
                "max_subscriptions_per_connection",
                &self.max_subscriptions_per_connection,
            )
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use agentdeck_protocol::relay_v2::frame::Ping;
    use agentdeck_protocol::relay_v2::{
        DeviceRouteId, GrantSerial, LinkGeneration, PairRouteId, RELAY_PROTOCOL_VERSION,
        RelayFrameBody, RelayServerId, TrustEpoch,
    };

    use crate::v2::auth::{DeviceAccess, MachineAccess, PairingAccess};
    use crate::v2::core::writer::WriterHandle;

    use super::*;

    fn connection(seed: u8) -> ConnectionInstanceId {
        ConnectionInstanceId::from_bytes([seed; 16])
    }

    fn machine(seed: u8) -> MachineRouteId {
        MachineRouteId::from_bytes([seed; 16])
    }

    fn device(seed: u8) -> DeviceRouteId {
        DeviceRouteId::from_bytes([seed; 16])
    }

    fn started(admission: ReplayAdmission) -> ReplayStart {
        match admission {
            ReplayAdmission::Started(start) => start,
            ReplayAdmission::Queued => panic!("expected replay to start immediately"),
        }
    }

    fn machine_access(connection_seed: u8, machine_seed: u8) -> AccessContext {
        AccessContext::Machine(MachineAccess {
            machine_route: machine(machine_seed),
            connection_instance: connection(connection_seed),
            trust_epoch: TrustEpoch::new(1),
            link_generation: LinkGeneration::new(1),
            cert_hash: [0x11; 32],
            absolute_expiry_ms: None,
        })
    }

    fn device_access(connection_seed: u8, machine_seed: u8) -> AccessContext {
        AccessContext::Device(DeviceAccess {
            machine_route: machine(machine_seed),
            device_route: DeviceRouteId::from_bytes([0xd0; 16]),
            connection_instance: connection(connection_seed),
            grant_serial: GrantSerial::new(1),
            grant_hash: [0x22; 32],
            device_sign_fingerprint: [0x33; 32],
        })
    }

    fn pairing_access(connection_seed: u8, machine_seed: u8, pair_seed: u8) -> AccessContext {
        AccessContext::Pairing(PairingAccess {
            relay_server_id: RelayServerId::from_bytes([0xa1; 16]),
            machine_route: machine(machine_seed),
            pair_route: PairRouteId::from_bytes([pair_seed; 16]),
            connection_instance: connection(connection_seed),
            absolute_expiry_ms: 300_000,
        })
    }

    fn stream_key(seed: u8) -> StreamKey {
        StreamKey::new(
            StreamRouteId::from_bytes([seed; 16]),
            StreamGenerationId::from_bytes([seed.wrapping_add(1); 16]),
        )
    }

    fn terminal_frame(nonce: u64) -> OpaqueRouteFrame {
        OpaqueRouteFrame {
            version: RELAY_PROTOCOL_VERSION,
            body: RelayFrameBody::Ping(Ping { nonce }),
        }
    }

    #[test]
    fn terminal_reauth_requires_pending_principal_and_reuses_no_deadline_token() {
        let mut registry = ConnectionRegistry::new(8);
        let access = device_access(1, 2);
        let (writer, _receiver) = WriterHandle::channel();
        registry
            .attach_pending(connection(1), writer, 0)
            .expect("attach pending");
        let staged = registry
            .begin_terminal_reauth(&access, terminal_frame(1), WriterCloseReason::Revoked)
            .expect("first terminal");
        assert_eq!(staged.admission, TerminalAdmission::Staged);
        let existing = registry
            .begin_terminal_reauth(&access, terminal_frame(1), WriterCloseReason::Revoked)
            .expect("exact retry");
        assert_eq!(existing.admission, TerminalAdmission::Existing);
        assert_eq!(existing.token, staged.token);

        registry
            .finish_terminal(connection(1), staged.token)
            .expect("finish old terminal");
        let (replacement, _receiver) = WriterHandle::channel();
        registry
            .attach_pending(connection(1), replacement, 0)
            .expect("reuse connection id");
        let replacement = registry
            .begin_terminal_reauth(&access, terminal_frame(1), WriterCloseReason::Revoked)
            .expect("new terminal generation");
        assert_ne!(replacement.token, staged.token, "ABA token must be unique");
    }

    #[test]
    fn terminal_reauth_cannot_be_applied_to_an_active_entry() {
        let mut registry = ConnectionRegistry::new(8);
        let access = device_access(2, 3);
        let (writer, _receiver) = WriterHandle::channel();
        registry
            .attach_pending(connection(2), writer, 0)
            .expect("attach pending");
        registry
            .activate(access.clone(), 0, WriterCloseReason::Replaced)
            .expect("activate");
        assert!(matches!(
            registry.begin_terminal_reauth(&access, terminal_frame(2), WriterCloseReason::Revoked,),
            Err(ConnectionStateError::AccessMismatch)
        ));
    }

    #[test]
    fn terminal_reauth_rejects_a_mismatched_pending_principal() {
        let mut registry = ConnectionRegistry::new(8);
        let access = device_access(3, 4);
        let (writer, _receiver) = WriterHandle::channel();
        registry
            .attach_pending(connection(3), writer, 0)
            .expect("attach pending");
        registry
            .note_activation(connection(3), PrincipalRoute::Machine(machine(9)))
            .expect("bind another pending principal");
        assert!(matches!(
            registry.begin_terminal_reauth(&access, terminal_frame(3), WriterCloseReason::Revoked),
            Err(ConnectionStateError::AccessMismatch)
        ));
        assert!(!registry.is_terminal(connection(3)));
    }

    #[test]
    fn core_debug_output_redacts_stream_generation_and_connection_routes() {
        let key = stream_key(42);
        let start = ReplayStart {
            connection: connection(43),
            key,
            replay_epoch: 1,
            mode: ReplayStartMode::Initial,
            cursor: StreamCursor::BeforeFirst,
            terminal: StreamCursor::At(9),
            cancel: CancellationToken::new(),
        };
        let debug = format!("{start:?}");
        assert!(debug.contains(&key.stream_route.redacted()));
        assert!(debug.contains(&key.generation.redacted()));
        assert!(debug.contains(&connection(43).redacted()));
        assert!(!debug.contains("StreamRouteId"));
        assert!(!debug.contains("StreamGenerationId"));
        assert!(!debug.contains("ConnectionInstanceId"));
    }

    #[test]
    fn activate_is_a_deterministic_same_principal_replacement_barrier() {
        let mut registry = ConnectionRegistry::new(4);
        let (old_writer, _old_receiver) = WriterHandle::channel();
        let (new_writer, _new_receiver) = WriterHandle::channel();
        registry
            .attach_pending(connection(1), old_writer.clone(), 0)
            .expect("attach old");
        registry
            .attach_pending(connection(2), new_writer, 0)
            .expect("attach new");
        let old_access = machine_access(1, 9);
        let new_access = machine_access(2, 9);
        assert!(
            registry
                .activate(old_access.clone(), 10, WriterCloseReason::Explicit)
                .expect("activate old")
                .is_none()
        );

        let cleanup = registry
            .activate(new_access.clone(), 20, WriterCloseReason::Explicit)
            .expect("activate replacement")
            .expect("old generation cleanup");
        assert_eq!(cleanup.connection, connection(1));
        assert_eq!(cleanup.access, Some(old_access));
        assert_eq!(cleanup.principal, Some(PrincipalRoute::Machine(machine(9))));
        assert_eq!(old_writer.close_reason(), Some(WriterCloseReason::Explicit));
        assert!(registry.validates(&new_access));
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn pairing_activation_needs_no_principal_and_cleanup_keeps_principal_empty() {
        let mut registry = ConnectionRegistry::new(1);
        let (writer, _receiver) = WriterHandle::channel();
        let access = pairing_access(2, 9, 7);
        registry
            .attach_pending(connection(2), writer, 10)
            .expect("attach pairing writer");

        assert!(
            registry
                .activate(access.clone(), 20, WriterCloseReason::Explicit)
                .expect("activate restricted pairing access")
                .is_none()
        );
        assert!(registry.validates(&access));
        let cleanup = registry
            .remove_and_close(connection(2), WriterCloseReason::Explicit)
            .expect("cleanup pairing writer");
        assert_eq!(cleanup.access, Some(access));
        assert_eq!(cleanup.principal, None);
    }

    #[test]
    fn initial_barrier_then_post_terminal_catchup_never_moves_replay_complete() {
        let mut registry = ConnectionRegistry::new(4);
        let (writer, _receiver) = WriterHandle::channel();
        let access = device_access(3, 9);
        registry
            .attach_pending(connection(3), writer, 0)
            .expect("attach");
        registry
            .activate(access, 0, WriterCloseReason::Explicit)
            .expect("activate");
        let key = stream_key(4);
        let initial = started(
            registry
                .begin_initial_replay(
                    connection(3),
                    key,
                    StreamCursor::BeforeFirst,
                    StreamCursor::At(5),
                )
                .expect("initial replay"),
        );
        assert!(
            registry
                .note_committed_publish(machine(9), key, 6)
                .is_empty()
        );
        assert!(
            registry
                .note_committed_publish(machine(9), key, 7)
                .is_empty()
        );

        let completed = registry
            .complete_initial_replay(connection(3), key, initial.replay_epoch)
            .expect("initial completion");
        let catchup = completed.catchup.expect("missed publish catchup");
        assert_eq!(catchup.cursor, StreamCursor::At(5));
        assert_eq!(catchup.terminal, StreamCursor::At(7));

        assert!(
            registry
                .note_committed_publish(machine(9), key, 8)
                .is_empty()
        );
        let second = registry
            .complete_catchup(
                connection(3),
                key,
                catchup.replay_epoch,
                StreamCursor::At(7),
            )
            .expect("first catchup completion")
            .next
            .expect("second fixed catchup");
        assert_eq!(second.cursor, StreamCursor::At(7));
        assert_eq!(second.terminal, StreamCursor::At(8));
        let live = registry
            .complete_catchup(connection(3), key, second.replay_epoch, StreamCursor::At(8))
            .expect("second catchup completion");
        assert_eq!(live.live_cursor, Some(StreamCursor::At(8)));
        assert!(matches!(
            registry.subscription_phase(connection(3), key),
            Some(SubscriptionPhase::Live {
                cursor: StreamCursor::At(8)
            })
        ));
        assert!(
            registry
                .note_committed_publish(machine(9), key, 8)
                .is_empty()
        );
        assert_eq!(registry.note_committed_publish(machine(9), key, 9).len(), 1);
        let gap = registry.note_committed_publish(machine(9), key, 11);
        assert!(matches!(
            gap.as_slice(),
            [LiveDelivery {
                kind: LiveDeliveryKind::Gap {
                    needed: 10,
                    oldest: 11
                },
                ..
            }]
        ));
        assert!(matches!(
            registry.subscription_phase(connection(3), key),
            Some(SubscriptionPhase::GapPaused {
                needed: 10,
                oldest: 11
            })
        ));
    }

    #[test]
    fn gap_pauses_live_and_subscription_cap_is_hard() {
        let mut registry = ConnectionRegistry::new(1);
        let (writer, _receiver) = WriterHandle::channel();
        let access = device_access(4, 8);
        registry
            .attach_pending(connection(4), writer, 0)
            .expect("attach");
        registry
            .activate(access, 0, WriterCloseReason::Explicit)
            .expect("activate");
        let first = stream_key(7);
        let second = stream_key(8);
        registry
            .pause_gap(connection(4), first, 0, 4)
            .expect("pause gap");
        assert!(
            registry
                .note_committed_publish(machine(8), first, 5)
                .is_empty()
        );
        assert_eq!(
            registry
                .begin_initial_replay(
                    connection(4),
                    second,
                    StreamCursor::BeforeFirst,
                    StreamCursor::BeforeFirst,
                )
                .expect_err("second subscription exceeds cap"),
            ConnectionStateError::SubscriptionLimit
        );
        let (removed, next) = registry
            .unsubscribe_runtime(connection(4), first)
            .expect("unsubscribe gap");
        assert!(removed);
        assert!(next.is_none());
        registry
            .begin_initial_replay(
                connection(4),
                second,
                StreamCursor::BeforeFirst,
                StreamCursor::BeforeFirst,
            )
            .expect("capacity released");
    }

    #[test]
    fn only_matching_pong_refreshes_and_timeout_boundary_is_exact() {
        let mut registry = ConnectionRegistry::new(1);
        let (writer, _receiver) = WriterHandle::channel();
        let access = machine_access(5, 5);
        registry
            .attach_pending(connection(5), writer, 0)
            .expect("attach");
        registry
            .activate(access, 0, WriterCloseReason::Explicit)
            .expect("activate");
        assert!(registry.heartbeat_candidates(19_999, 20_000).is_empty());
        assert_eq!(
            registry.heartbeat_candidates(20_000, 20_000),
            vec![connection(5)]
        );
        registry
            .record_ping(connection(5), 0x1234, 20_000)
            .expect("record ping");
        assert!(
            !registry
                .accept_pong(connection(5), 0x9999, 30_000)
                .expect("wrong pong")
        );
        assert_eq!(registry.timed_out(59_999, 60_000), Vec::new());
        assert_eq!(registry.timed_out(60_000, 60_000), vec![connection(5)]);
        assert!(
            registry
                .accept_pong(connection(5), 0x1234, 30_000)
                .expect("matching pong")
        );
        assert!(registry.timed_out(89_999, 60_000).is_empty());
        assert_eq!(registry.timed_out(90_000, 60_000), vec![connection(5)]);
    }

    #[test]
    fn machine_link_expiry_boundary_is_exact_and_none_remains_unbounded() {
        let mut registry = ConnectionRegistry::new(1);
        let expiring = AccessContext::Machine(MachineAccess {
            machine_route: machine(6),
            connection_instance: connection(6),
            trust_epoch: TrustEpoch::new(1),
            link_generation: LinkGeneration::new(1),
            cert_hash: [0x61; 32],
            absolute_expiry_ms: Some(100),
        });
        let permanent = machine_access(7, 7);
        for access in [&expiring, &permanent] {
            let (writer, _receiver) = WriterHandle::channel();
            registry
                .attach_pending(access.connection_instance(), writer, 0)
                .expect("attach");
            registry
                .activate(access.clone(), 0, WriterCloseReason::Explicit)
                .expect("activate");
        }

        assert!(registry.expired_machine_links(99).is_empty());
        assert_eq!(registry.expired_machine_links(100), vec![connection(6)]);
        assert_eq!(
            registry.expired_machine_links(u64::MAX),
            vec![connection(6)]
        );
    }

    #[test]
    fn cleanup_cancels_replay_closes_writer_and_returns_principal() {
        let mut registry = ConnectionRegistry::new(1);
        let (writer, _receiver) = WriterHandle::channel();
        let access = device_access(6, 6);
        registry
            .attach_pending(connection(6), writer.clone(), 0)
            .expect("attach");
        registry
            .activate(access.clone(), 0, WriterCloseReason::Explicit)
            .expect("activate");
        let replay = started(
            registry
                .begin_initial_replay(
                    connection(6),
                    stream_key(9),
                    StreamCursor::BeforeFirst,
                    StreamCursor::At(1),
                )
                .expect("replay"),
        );
        assert!(!replay.cancel.is_cancelled());
        let cleanup = registry
            .remove_if_access_and_close(&access, WriterCloseReason::Shutdown)
            .expect("cleanup");
        assert_eq!(cleanup.connection, connection(6));
        assert!(cleanup.principal.is_some());
        assert!(replay.cancel.is_cancelled());
        assert_eq!(writer.close_reason(), Some(WriterCloseReason::Shutdown));
        assert!(!registry.contains(connection(6)));
    }

    #[test]
    fn concurrent_subscriptions_are_fifo_serialized_and_preserve_missed_hwm() {
        let mut registry = ConnectionRegistry::new(4);
        let (writer, _receiver) = WriterHandle::channel();
        let access = device_access(8, 8);
        registry
            .attach_pending(connection(8), writer, 0)
            .expect("attach");
        registry
            .activate(access, 0, WriterCloseReason::Explicit)
            .expect("activate");
        let first_key = stream_key(20);
        let second_key = stream_key(21);
        let first = started(
            registry
                .begin_initial_replay(
                    connection(8),
                    first_key,
                    StreamCursor::BeforeFirst,
                    StreamCursor::At(2),
                )
                .expect("first replay"),
        );
        assert!(matches!(
            registry
                .begin_initial_replay(
                    connection(8),
                    second_key,
                    StreamCursor::BeforeFirst,
                    StreamCursor::At(4),
                )
                .expect("second replay is queued"),
            ReplayAdmission::Queued
        ));
        assert!(
            registry
                .note_committed_publish(machine(8), second_key, 5)
                .is_empty()
        );

        let first_done = registry
            .complete_initial_replay(connection(8), first_key, first.replay_epoch)
            .expect("first replay complete");
        assert!(first_done.catchup.is_none());
        let second = first_done.next_queued.expect("second replay starts next");
        assert_eq!(second.key, second_key);
        assert_eq!(second.cursor, StreamCursor::BeforeFirst);
        assert_eq!(second.terminal, StreamCursor::At(4));

        let second_done = registry
            .complete_initial_replay(connection(8), second_key, second.replay_epoch)
            .expect("second initial replay complete");
        let catchup = second_done.catchup.expect("queued missed publish catchup");
        assert_eq!(catchup.cursor, StreamCursor::At(4));
        assert_eq!(catchup.terminal, StreamCursor::At(5));
    }

    #[test]
    fn hot_stream_catchup_yields_to_queued_subscriptions_then_rotates_to_tail() {
        let mut registry = ConnectionRegistry::new(5);
        let (writer, _receiver) = WriterHandle::channel();
        let access = device_access(10, 10);
        registry
            .attach_pending(connection(10), writer, 0)
            .expect("attach");
        registry
            .activate(access, 0, WriterCloseReason::Explicit)
            .expect("activate");
        let hot = stream_key(40);
        let second = stream_key(41);
        let third = stream_key(42);
        let hot_initial = started(
            registry
                .begin_initial_replay(
                    connection(10),
                    hot,
                    StreamCursor::BeforeFirst,
                    StreamCursor::At(5),
                )
                .expect("hot initial"),
        );
        assert!(matches!(
            registry
                .begin_initial_replay(
                    connection(10),
                    second,
                    StreamCursor::BeforeFirst,
                    StreamCursor::BeforeFirst,
                )
                .expect("queue second"),
            ReplayAdmission::Queued
        ));
        registry.note_committed_publish(machine(10), hot, 6);
        let hot_done = registry
            .complete_initial_replay(connection(10), hot, hot_initial.replay_epoch)
            .expect("hot initial done");
        assert!(hot_done.catchup.is_none());
        let second_start = hot_done.next_queued.expect("second gets first quantum");
        assert_eq!(second_start.key, second);
        assert_eq!(second_start.mode, ReplayStartMode::Initial);

        let second_done = registry
            .complete_initial_replay(connection(10), second, second_start.replay_epoch)
            .expect("second done");
        let hot_catchup = second_done
            .next_queued
            .expect("hot catchup rotates behind second");
        assert_eq!(hot_catchup.key, hot);
        assert_eq!(hot_catchup.mode, ReplayStartMode::PostTerminal);
        assert_eq!(hot_catchup.cursor, StreamCursor::At(5));

        assert!(matches!(
            registry
                .begin_initial_replay(
                    connection(10),
                    third,
                    StreamCursor::BeforeFirst,
                    StreamCursor::BeforeFirst,
                )
                .expect("queue third during hot catchup"),
            ReplayAdmission::Queued
        ));
        registry.note_committed_publish(machine(10), hot, 7);
        let catchup_done = registry
            .complete_catchup(
                connection(10),
                hot,
                hot_catchup.replay_epoch,
                StreamCursor::At(6),
            )
            .expect("hot catchup quantum done");
        assert!(catchup_done.next.is_none());
        assert!(catchup_done.live_cursor.is_none());
        let third_start = catchup_done
            .next_queued
            .expect("third cannot starve behind hot stream");
        assert_eq!(third_start.key, third);
        assert_eq!(third_start.mode, ReplayStartMode::Initial);
    }

    #[test]
    fn gap_replaces_a_queued_replay_instead_of_restarting_it_later() {
        let mut registry = ConnectionRegistry::new(4);
        let (writer, _receiver) = WriterHandle::channel();
        let access = device_access(9, 9);
        registry
            .attach_pending(connection(9), writer, 0)
            .expect("attach");
        registry
            .activate(access, 0, WriterCloseReason::Explicit)
            .expect("activate");
        let active_key = stream_key(30);
        let gap_key = stream_key(31);
        let active = started(
            registry
                .begin_initial_replay(
                    connection(9),
                    active_key,
                    StreamCursor::BeforeFirst,
                    StreamCursor::At(1),
                )
                .expect("active replay"),
        );
        assert!(matches!(
            registry
                .begin_initial_replay(
                    connection(9),
                    gap_key,
                    StreamCursor::BeforeFirst,
                    StreamCursor::At(1),
                )
                .expect("queued replay"),
            ReplayAdmission::Queued
        ));
        assert!(
            registry
                .pause_gap(connection(9), gap_key, 0, 4)
                .expect("replace queued replay with gap")
                .is_none()
        );
        let completed = registry
            .complete_initial_replay(connection(9), active_key, active.replay_epoch)
            .expect("active replay complete");
        assert!(completed.next_queued.is_none());
        assert!(matches!(
            registry.subscription_phase(connection(9), gap_key),
            Some(SubscriptionPhase::GapPaused {
                needed: 0,
                oldest: 4
            })
        ));
    }

    #[test]
    fn pending_writer_keeps_activated_principal_for_orphan_cleanup() {
        let mut registry = ConnectionRegistry::new(1);
        let (writer, _receiver) = WriterHandle::channel();
        let principal = PrincipalRoute::Device {
            machine_route: machine(7),
            device_route: device(7),
        };
        registry
            .attach_pending(connection(7), writer, 0)
            .expect("attach pending writer");
        registry
            .note_activation(connection(7), principal)
            .expect("record coordinator activation before transport binds access");

        let cleanup = registry
            .remove_and_close(connection(7), WriterCloseReason::ReceiverDropped)
            .expect("remove orphan pending writer");
        assert_eq!(cleanup.access, None);
        assert_eq!(cleanup.principal, Some(principal));
    }

    #[test]
    fn dropping_registry_cancels_replay_and_closes_transport_writer_clone() {
        let mut registry = ConnectionRegistry::new(1);
        let (writer, _receiver) = WriterHandle::channel();
        let transport_writer = writer.clone();
        registry
            .attach_pending(connection(11), writer, 0)
            .expect("attach pending writer");
        registry
            .activate(device_access(11, 11), 0, WriterCloseReason::Explicit)
            .expect("activate connection");
        let replay = started(
            registry
                .begin_initial_replay(
                    connection(11),
                    stream_key(41),
                    StreamCursor::BeforeFirst,
                    StreamCursor::At(1),
                )
                .expect("start replay"),
        );

        drop(registry);

        assert!(replay.cancel.is_cancelled());
        assert_eq!(
            transport_writer.close_reason(),
            Some(WriterCloseReason::Shutdown)
        );
    }
}
