//! Runtime subscription 的本地 lifecycle 与固定资源预算。
//!
//! 具体威胁场景：恶意连接可用 subscribe/resubscribe 或慢 snapshot 长期占住 task/
//! memory 配额，旧 generation 的迟到完成还可能污染新订阅。这里用单锁原子 reserve、
//! absolute barrier TTL、不可 Clone lease 与 exact-generation cleanup 封住这些边界；
//! registry 不持有 actor/store/SQLite，也不 spawn task。

use super::connection::ConnectionId;
use super::events::RuntimeStreamTarget;
use agentdeck_protocol::runtime::identity::StreamGeneration;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

mod budget;
pub(crate) mod coordinator;
pub(crate) mod egress;
mod pump;
mod reducer;
use budget::{Limits, Usage, check_limits};
#[cfg(test)]
use budget::{
    MAX_ACTIVE_BARRIERS_GLOBAL, MAX_ACTIVE_BARRIERS_PER_CONNECTION, MAX_LIVE_SUBSCRIPTIONS_GLOBAL,
    MAX_LIVE_SUBSCRIPTIONS_PER_CONNECTION, MAX_SNAPSHOT_SENDERS_GLOBAL,
    MAX_SNAPSHOT_SENDERS_PER_CONNECTION, SUBSCRIPTION_BARRIER_TTL_MS,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SubscriptionGeneration {
    serial: u64,
    wire: [u8; 16],
}

impl SubscriptionGeneration {
    pub(crate) fn watch_generation(self) -> u64 {
        self.serial
    }

    pub(crate) fn wire_generation(self) -> StreamGeneration {
        StreamGeneration::new(uuid::Uuid::from_bytes(self.wire).hyphenated().to_string())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum SubscriptionRegistryError {
    #[error("subscription registry lock is poisoned")]
    Poisoned,
    #[error("subscription resource is exhausted: {0}")]
    Overloaded(&'static str),
    #[error("subscription generation space is exhausted")]
    GenerationExhausted,
    #[error("subscription generation entropy is unavailable")]
    EntropyUnavailable,
    #[error("subscription lease belongs to a stale generation")]
    StaleGeneration,
    #[error("live enqueue is blocked until the subscription barrier completes")]
    BarrierActive,
    #[error("subscription clock regressed from {previous_ms} ms to {observed_ms} ms")]
    ClockRegressed { previous_ms: u64, observed_ms: u64 },
    #[error("subscription barrier expiry is outside the representable clock range")]
    TimeOutOfRange,
    #[error("subscription resource accounting invariant failed")]
    AccountingOverflow,
}

struct Entry {
    generation: SubscriptionGeneration,
    barrier_expires_at_ms: Option<u64>,
    snapshot_sender: bool,
    cancelled: Arc<AtomicBool>,
}

impl Entry {
    fn usage(&self) -> Usage {
        Usage {
            live: 1,
            barriers: self.barrier_expires_at_ms.is_some() as usize,
            snapshot_senders: self.snapshot_sender as usize,
        }
    }
}

#[derive(Default)]
struct ConnectionState {
    entries: HashMap<RuntimeStreamTarget, Entry>,
}

impl ConnectionState {
    fn usage(&self) -> Result<Usage, SubscriptionRegistryError> {
        self.entries
            .values()
            .try_fold(Usage::default(), |usage, entry| {
                usage.checked_replace(Usage::default(), entry.usage())
            })
    }
}

struct State {
    next_generation: u64,
    next_transient_id: u64,
    last_now_ms: Option<u64>,
    connections: HashMap<ConnectionId, ConnectionState>,
    transients: HashMap<u64, TransientEntry>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            next_generation: 1,
            next_transient_id: 1,
            last_now_ms: None,
            connections: HashMap::new(),
            transients: HashMap::new(),
        }
    }
}

struct TransientEntry {
    connection_id: ConnectionId,
    usage: Usage,
}

struct RegistryInner {
    limits: Limits,
    state: Mutex<State>,
}

#[derive(Clone)]
pub(crate) struct SubscriptionRegistry {
    inner: Arc<RegistryInner>,
}

impl SubscriptionRegistry {
    pub(crate) fn new() -> Self {
        Self::with_limits(Limits::default())
    }

    fn with_limits(limits: Limits) -> Self {
        Self {
            inner: Arc::new(RegistryInner {
                limits,
                state: Mutex::new(State::default()),
            }),
        }
    }

    #[cfg(test)]
    pub(crate) fn reserve(
        &self,
        connection_id: ConnectionId,
        target: RuntimeStreamTarget,
        needs_snapshot_sender: bool,
        now_ms: u64,
    ) -> Result<SubscriptionLease, SubscriptionRegistryError> {
        let generation = self.allocate_generation()?;
        self.install(
            connection_id,
            target,
            generation,
            needs_snapshot_sender,
            now_ms,
        )
    }

    /// 先分配 generation，再由 StoreCommitHub 注册 watcher 并冻结 cut。只有后续
    /// `install` 成功才替换旧订阅；capture/quota 失败不会误杀仍可用的旧 generation。
    pub(crate) fn allocate_generation(
        &self,
    ) -> Result<SubscriptionGeneration, SubscriptionRegistryError> {
        let mut wire = [0_u8; 16];
        getrandom::fill(&mut wire).map_err(|_| SubscriptionRegistryError::EntropyUnavailable)?;
        if wire == [0; 16] {
            return Err(SubscriptionRegistryError::EntropyUnavailable);
        }
        let mut state = self.lock()?;
        let serial = state.next_generation;
        state.next_generation = state
            .next_generation
            .checked_add(1)
            .ok_or(SubscriptionRegistryError::GenerationExhausted)?;
        Ok(SubscriptionGeneration { serial, wire })
    }

    pub(crate) fn install(
        &self,
        connection_id: ConnectionId,
        target: RuntimeStreamTarget,
        generation: SubscriptionGeneration,
        needs_snapshot_sender: bool,
        now_ms: u64,
    ) -> Result<SubscriptionLease, SubscriptionRegistryError> {
        let expires_at_ms = now_ms
            .checked_add(self.inner.limits.barrier_ttl_ms)
            .ok_or(SubscriptionRegistryError::TimeOutOfRange)?;
        let mut state = self.lock()?;
        observe_now(&mut state, now_ms)?;
        expire_locked(&mut state, now_ms)?;

        let old_usage = state
            .connections
            .get(&connection_id)
            .and_then(|connection| connection.entries.get(&target))
            .map_or(Usage::default(), Entry::usage);
        let connection_usage = connection_usage(&state, connection_id)?;
        let added = Usage::subscription(needs_snapshot_sender);
        let projected_connection = connection_usage.checked_replace(old_usage, added)?;
        let projected_global = all_usage(&state)?.checked_replace(old_usage, added)?;
        check_limits(projected_connection, projected_global, self.inner.limits)?;

        let cancelled = Arc::new(AtomicBool::new(false));
        let previous = state
            .connections
            .entry(connection_id)
            .or_default()
            .entries
            .insert(
                target,
                Entry {
                    generation,
                    barrier_expires_at_ms: Some(expires_at_ms),
                    snapshot_sender: needs_snapshot_sender,
                    cancelled: cancelled.clone(),
                },
            );
        if let Some(previous) = previous {
            previous.cancelled.store(true, Ordering::Release);
        }
        Ok(SubscriptionLease {
            inner: self.inner.clone(),
            connection_id,
            target,
            generation,
            cancelled,
            cleanup_armed: true,
        })
    }

    /// CatalogRequest 等非 live one-shot 也必须和 subscription 共用 barrier/
    /// snapshot-sender 硬上限。lease 不计 live subscription，并由 caller 的同一个
    /// absolute deadline 管理；Drop/disconnect 都 exact 回收。
    pub(crate) fn reserve_transient(
        &self,
        connection_id: ConnectionId,
        barrier: bool,
        snapshot_sender: bool,
        now_ms: u64,
    ) -> Result<TransientSubscriptionLease, SubscriptionRegistryError> {
        let added = Usage::transient(barrier, snapshot_sender);
        if added == Usage::default() {
            return Err(SubscriptionRegistryError::AccountingOverflow);
        }
        let mut state = self.lock()?;
        observe_now(&mut state, now_ms)?;
        expire_locked(&mut state, now_ms)?;
        let connection_usage = connection_usage(&state, connection_id)?;
        let projected_connection = connection_usage.checked_replace(Usage::default(), added)?;
        let projected_global = all_usage(&state)?.checked_replace(Usage::default(), added)?;
        check_limits(projected_connection, projected_global, self.inner.limits)?;
        let transient_id = state.next_transient_id;
        state.next_transient_id = state
            .next_transient_id
            .checked_add(1)
            .ok_or(SubscriptionRegistryError::GenerationExhausted)?;
        let replaced = state.transients.insert(
            transient_id,
            TransientEntry {
                connection_id,
                usage: added,
            },
        );
        debug_assert!(replaced.is_none());
        Ok(TransientSubscriptionLease {
            inner: self.inner.clone(),
            transient_id,
            connection_id,
            cleanup_armed: true,
        })
    }

    pub(crate) fn complete_barrier(
        &self,
        lease: &SubscriptionLease,
        now_ms: u64,
    ) -> Result<bool, SubscriptionRegistryError> {
        self.require_same_registry(lease)?;
        let mut state = self.lock()?;
        observe_now(&mut state, now_ms)?;
        expire_locked(&mut state, now_ms)?;
        if current_entry(&state, lease)?
            .barrier_expires_at_ms
            .is_none()
        {
            return Ok(false);
        }
        let entry = current_entry_mut(&mut state, lease)?;
        entry.barrier_expires_at_ms = None;
        entry.snapshot_sender = false;
        Ok(true)
    }

    pub(crate) fn admit_live_enqueue(
        &self,
        lease: &SubscriptionLease,
        now_ms: u64,
    ) -> Result<SubscriptionGeneration, SubscriptionRegistryError> {
        self.require_same_registry(lease)?;
        let mut state = self.lock()?;
        observe_now(&mut state, now_ms)?;
        expire_locked(&mut state, now_ms)?;
        let entry = current_entry(&state, lease)?;
        if entry.barrier_expires_at_ms.is_some() {
            return Err(SubscriptionRegistryError::BarrierActive);
        }
        Ok(entry.generation)
    }

    /// Coordinator 在发布 receipt 或替换 job 前使用的 exact-generation gate。
    /// 它不推进 clock/TTL，只确认 prepare 得到的 lease 仍是当前 target owner。
    pub(crate) fn require_current(
        &self,
        lease: &SubscriptionLease,
    ) -> Result<SubscriptionGeneration, SubscriptionRegistryError> {
        self.require_same_registry(lease)?;
        let state = self.lock()?;
        Ok(current_entry(&state, lease)?.generation)
    }

    pub(crate) fn unsubscribe(
        &self,
        connection_id: ConnectionId,
        target: RuntimeStreamTarget,
    ) -> Result<bool, SubscriptionRegistryError> {
        remove_target(&mut *self.lock()?, connection_id, target)
    }

    pub(crate) fn disconnect(
        &self,
        connection_id: ConnectionId,
    ) -> Result<bool, SubscriptionRegistryError> {
        disconnect_locked(&mut *self.lock()?, connection_id)
    }

    #[cfg(test)]
    pub(crate) fn expire(&self, now_ms: u64) -> Result<usize, SubscriptionRegistryError> {
        let mut state = self.lock()?;
        observe_now(&mut state, now_ms)?;
        expire_locked(&mut state, now_ms)
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, State>, SubscriptionRegistryError> {
        self.inner
            .state
            .lock()
            .map_err(|_| SubscriptionRegistryError::Poisoned)
    }

    fn require_same_registry(
        &self,
        lease: &SubscriptionLease,
    ) -> Result<(), SubscriptionRegistryError> {
        if Arc::ptr_eq(&self.inner, &lease.inner) {
            Ok(())
        } else {
            Err(SubscriptionRegistryError::StaleGeneration)
        }
    }

    #[cfg(test)]
    fn metrics(&self) -> Result<(Usage, usize), SubscriptionRegistryError> {
        let state = self.lock()?;
        Ok((all_usage(&state)?, state.connections.len()))
    }

    #[cfg(test)]
    fn transient_count_for_test(&self) -> Result<usize, SubscriptionRegistryError> {
        Ok(self.lock()?.transients.len())
    }
}

pub(crate) struct SubscriptionLease {
    inner: Arc<RegistryInner>,
    connection_id: ConnectionId,
    target: RuntimeStreamTarget,
    generation: SubscriptionGeneration,
    cancelled: Arc<AtomicBool>,
    cleanup_armed: bool,
}

pub(crate) struct TransientSubscriptionLease {
    inner: Arc<RegistryInner>,
    transient_id: u64,
    connection_id: ConnectionId,
    cleanup_armed: bool,
}

impl Drop for TransientSubscriptionLease {
    fn drop(&mut self) {
        if !self.cleanup_armed {
            return;
        }
        if let Ok(mut state) = self.inner.state.lock() {
            let _ = remove_transient_exact(&mut state, self.transient_id, self.connection_id);
            self.cleanup_armed = false;
        }
    }
}

impl SubscriptionLease {
    pub(crate) fn generation(&self) -> SubscriptionGeneration {
        self.generation
    }

    pub(crate) fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    pub(crate) fn release(&mut self) -> Result<bool, SubscriptionRegistryError> {
        if !self.cleanup_armed {
            return Ok(false);
        }
        let mut state = self
            .inner
            .state
            .lock()
            .map_err(|_| SubscriptionRegistryError::Poisoned)?;
        let released = remove_generation(&mut state, self)?;
        self.cleanup_armed = false;
        Ok(released)
    }
}

impl Drop for SubscriptionLease {
    fn drop(&mut self) {
        if !self.cleanup_armed {
            return;
        }
        if let Ok(mut state) = self.inner.state.lock() {
            let _ = remove_generation(&mut state, self);
        }
    }
}

fn observe_now(state: &mut State, now_ms: u64) -> Result<(), SubscriptionRegistryError> {
    if let Some(previous_ms) = state.last_now_ms
        && now_ms < previous_ms
    {
        return Err(SubscriptionRegistryError::ClockRegressed {
            previous_ms,
            observed_ms: now_ms,
        });
    }
    state.last_now_ms = Some(now_ms);
    Ok(())
}

fn current_entry<'a>(
    state: &'a State,
    lease: &SubscriptionLease,
) -> Result<&'a Entry, SubscriptionRegistryError> {
    state
        .connections
        .get(&lease.connection_id)
        .and_then(|connection| connection.entries.get(&lease.target))
        .filter(|entry| entry.generation == lease.generation)
        .ok_or(SubscriptionRegistryError::StaleGeneration)
}

fn current_entry_mut<'a>(
    state: &'a mut State,
    lease: &SubscriptionLease,
) -> Result<&'a mut Entry, SubscriptionRegistryError> {
    state
        .connections
        .get_mut(&lease.connection_id)
        .and_then(|connection| connection.entries.get_mut(&lease.target))
        .filter(|entry| entry.generation == lease.generation)
        .ok_or(SubscriptionRegistryError::StaleGeneration)
}

fn expire_locked(state: &mut State, now_ms: u64) -> Result<usize, SubscriptionRegistryError> {
    let expired = state
        .connections
        .iter()
        .flat_map(|(connection_id, connection)| {
            connection.entries.iter().filter_map(|(target, entry)| {
                entry
                    .barrier_expires_at_ms
                    .filter(|expires_at| now_ms >= *expires_at)
                    .map(|_| (*connection_id, *target, entry.generation))
            })
        })
        .collect::<Vec<_>>();
    let mut released = 0_usize;
    for (connection_id, target, generation) in expired {
        released = released
            .checked_add(remove_exact(state, connection_id, target, generation)? as usize)
            .ok_or(SubscriptionRegistryError::AccountingOverflow)?;
    }
    Ok(released)
}

fn remove_generation(
    state: &mut State,
    lease: &SubscriptionLease,
) -> Result<bool, SubscriptionRegistryError> {
    remove_exact(state, lease.connection_id, lease.target, lease.generation)
}

fn remove_exact(
    state: &mut State,
    connection_id: ConnectionId,
    target: RuntimeStreamTarget,
    generation: SubscriptionGeneration,
) -> Result<bool, SubscriptionRegistryError> {
    let Some(entry) = state
        .connections
        .get(&connection_id)
        .and_then(|connection| connection.entries.get(&target))
    else {
        return Ok(false);
    };
    if entry.generation != generation {
        return Ok(false);
    }
    remove_target(state, connection_id, target)
}

fn remove_target(
    state: &mut State,
    connection_id: ConnectionId,
    target: RuntimeStreamTarget,
) -> Result<bool, SubscriptionRegistryError> {
    let exists = state
        .connections
        .get(&connection_id)
        .is_some_and(|connection| connection.entries.contains_key(&target));
    if !exists {
        return Ok(false);
    }
    let connection = state
        .connections
        .get_mut(&connection_id)
        .ok_or(SubscriptionRegistryError::AccountingOverflow)?;
    let entry = connection
        .entries
        .remove(&target)
        .ok_or(SubscriptionRegistryError::AccountingOverflow)?;
    let remove_connection = connection.entries.is_empty();
    entry.cancelled.store(true, Ordering::Release);
    if remove_connection {
        state.connections.remove(&connection_id);
    }
    Ok(true)
}

fn disconnect_locked(
    state: &mut State,
    connection_id: ConnectionId,
) -> Result<bool, SubscriptionRegistryError> {
    let mut released = false;
    if let Some(connection) = state.connections.remove(&connection_id) {
        for entry in connection.entries.into_values() {
            entry.cancelled.store(true, Ordering::Release);
        }
        released = true;
    }
    let transient_ids = state
        .transients
        .iter()
        .filter_map(|(id, entry)| (entry.connection_id == connection_id).then_some(*id))
        .collect::<Vec<_>>();
    for transient_id in transient_ids {
        released |= state.transients.remove(&transient_id).is_some();
    }
    Ok(released)
}

fn all_usage(state: &State) -> Result<Usage, SubscriptionRegistryError> {
    let subscriptions = state
        .connections
        .values()
        .try_fold(Usage::default(), |usage, connection| {
            usage.checked_replace(Usage::default(), connection.usage()?)
        })?;
    state
        .transients
        .values()
        .try_fold(subscriptions, |usage, transient| {
            usage.checked_replace(Usage::default(), transient.usage)
        })
}

fn connection_usage(
    state: &State,
    connection_id: ConnectionId,
) -> Result<Usage, SubscriptionRegistryError> {
    let subscriptions = state
        .connections
        .get(&connection_id)
        .map(ConnectionState::usage)
        .transpose()?
        .unwrap_or_default();
    state
        .transients
        .values()
        .filter(|entry| entry.connection_id == connection_id)
        .try_fold(subscriptions, |usage, transient| {
            usage.checked_replace(Usage::default(), transient.usage)
        })
}

fn remove_transient_exact(
    state: &mut State,
    transient_id: u64,
    connection_id: ConnectionId,
) -> Result<bool, SubscriptionRegistryError> {
    let Some(entry) = state.transients.get(&transient_id) else {
        return Ok(false);
    };
    if entry.connection_id != connection_id {
        return Err(SubscriptionRegistryError::StaleGeneration);
    }
    Ok(state.transients.remove(&transient_id).is_some())
}

#[cfg(test)]
#[path = "subscription/tests.rs"]
mod tests;
