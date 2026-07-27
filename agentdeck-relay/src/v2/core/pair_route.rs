//! Relay v2 PairRoute 的 actor-owned 有界内存状态机。

use std::collections::HashMap;
use std::fmt;

use agentdeck_protocol::relay_v2::failure::{
    RELAY_QUOTA_EXCEEDED, RELAY_ROUTE_CONFLICT, RELAY_ROUTE_FORBIDDEN, RELAY_ROUTE_NOT_FOUND,
    RELAY_STORE_UNAVAILABLE, RELAY_TRANSPORT_CONFIG_INVALID,
};
use agentdeck_protocol::relay_v2::frame::{
    ClosePairRoute, OpenPairRoute, PairRouteCloseOutcome, PairRouteClosed, PairRouteOpened,
};
use agentdeck_protocol::relay_v2::{
    ConnectionInstanceId, MachineRouteId, PairRouteId, RelayFailure, RelayServerId,
};

use crate::v2::auth::{ActivePairRoute, PairRouteView, PairingAccess};

pub const HARD_MAX_ROUTES_PER_MACHINE: usize = 8;
pub const HARD_MAX_ROUTES_GLOBAL: usize = 1_024;
pub const HARD_MAX_FRAMES_PER_ROUTE: usize = 32;
pub const HARD_MAX_BYTES_PER_ROUTE: usize = 1024 * 1024;
pub const HARD_MAX_TTL_MS: u64 = 300_000;
pub const HARD_MAX_BUCKET_CAPACITY: u64 = 8;
pub const HARD_MAX_BUCKET_REFILL_PER_SECOND: u64 = 2;

const TOKEN_MILLIS: u64 = 1_000;

/// PairRoute 的生产默认值也是不可越过的 hard max；测试只能下调。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PairRouteLimits {
    pub max_routes_per_machine: usize,
    pub max_routes_global: usize,
    pub max_frames_per_route: usize,
    pub max_bytes_per_route: usize,
    pub ttl_ms: u64,
    pub bucket_capacity: u64,
    pub bucket_refill_per_second: u64,
}

impl Default for PairRouteLimits {
    fn default() -> Self {
        Self {
            max_routes_per_machine: HARD_MAX_ROUTES_PER_MACHINE,
            max_routes_global: HARD_MAX_ROUTES_GLOBAL,
            max_frames_per_route: HARD_MAX_FRAMES_PER_ROUTE,
            max_bytes_per_route: HARD_MAX_BYTES_PER_ROUTE,
            ttl_ms: HARD_MAX_TTL_MS,
            bucket_capacity: HARD_MAX_BUCKET_CAPACITY,
            bucket_refill_per_second: HARD_MAX_BUCKET_REFILL_PER_SECOND,
        }
    }
}

impl PairRouteLimits {
    pub fn validate(self) -> Result<Self, RelayFailure> {
        let invalid = self.max_routes_per_machine == 0
            || self.max_routes_per_machine > HARD_MAX_ROUTES_PER_MACHINE
            || self.max_routes_global == 0
            || self.max_routes_global > HARD_MAX_ROUTES_GLOBAL
            || self.max_routes_per_machine > self.max_routes_global
            || self.max_frames_per_route == 0
            || self.max_frames_per_route > HARD_MAX_FRAMES_PER_ROUTE
            || self.max_bytes_per_route == 0
            || self.max_bytes_per_route > HARD_MAX_BYTES_PER_ROUTE
            || self.ttl_ms == 0
            || self.ttl_ms > HARD_MAX_TTL_MS
            || self.bucket_capacity == 0
            || self.bucket_capacity > HARD_MAX_BUCKET_CAPACITY
            || usize::try_from(self.bucket_capacity)
                .map_or(true, |capacity| capacity > self.max_frames_per_route)
            || self.bucket_refill_per_second == 0
            || self.bucket_refill_per_second > HARD_MAX_BUCKET_REFILL_PER_SECOND
            || self.bucket_capacity.checked_mul(TOKEN_MILLIS).is_none();
        if invalid {
            return Err(failure(
                RELAY_TRANSPORT_CONFIG_INVALID,
                "PairRoute limits are invalid",
            ));
        }
        Ok(self)
    }
}

#[derive(Clone, Copy)]
struct TokenBucket {
    available_milli_tokens: u64,
    last_refill_ms: u64,
}

impl TokenBucket {
    fn full(limits: PairRouteLimits, now_ms: u64) -> Self {
        Self {
            available_milli_tokens: limits.bucket_capacity.saturating_mul(TOKEN_MILLIS),
            last_refill_ms: now_ms,
        }
    }

    fn take(&mut self, limits: PairRouteLimits, now_ms: u64) -> bool {
        if now_ms >= self.last_refill_ms {
            let elapsed_ms = now_ms - self.last_refill_ms;
            let refill = elapsed_ms.saturating_mul(limits.bucket_refill_per_second);
            self.available_milli_tokens = self
                .available_milli_tokens
                .saturating_add(refill)
                .min(limits.bucket_capacity.saturating_mul(TOKEN_MILLIS));
            self.last_refill_ms = now_ms;
        }
        if self.available_milli_tokens < TOKEN_MILLIS {
            false
        } else {
            self.available_milli_tokens -= TOKEN_MILLIS;
            true
        }
    }
}

struct ActiveRoute {
    machine_route: MachineRouteId,
    absolute_expiry_ms: u64,
    pairing_connection: Option<ConnectionInstanceId>,
    committed_frames: usize,
    committed_bytes: usize,
    reserved_frames: usize,
    reserved_bytes: usize,
    reservations: HashMap<u64, usize>,
    bucket: TokenBucket,
}

struct Tombstone {
    machine_route: MachineRouteId,
    absolute_expiry_ms: u64,
}

enum RouteState {
    Active(ActiveRoute),
    Tombstone(Tombstone),
}

impl RouteState {
    fn machine_route(&self) -> MachineRouteId {
        match self {
            Self::Active(route) => route.machine_route,
            Self::Tombstone(route) => route.machine_route,
        }
    }

    fn absolute_expiry_ms(&self) -> u64 {
        match self {
            Self::Active(route) => route.absolute_expiry_ms,
            Self::Tombstone(route) => route.absolute_expiry_ms,
        }
    }
}

/// PairData 进入目标 writer 前占用 lifetime frame/byte 预算。
///
/// target enqueue 失败必须 rollback；成功后 commit。rate token 在 reserve 时已经消费，
/// rollback 不退还，防离线目标被无限打。
pub(crate) struct PairFrameReservation {
    machine_route: MachineRouteId,
    pair_route: PairRouteId,
    reservation_id: u64,
    canonical_bytes: usize,
}

impl fmt::Debug for PairFrameReservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PairFrameReservation")
            .field("machine", &self.machine_route.redacted())
            .field("pair", &self.pair_route.redacted())
            .field("reservation_id", &self.reservation_id)
            .field("canonical_bytes", &self.canonical_bytes)
            .finish()
    }
}

pub(crate) struct PairRouteCloseResult {
    pub frame: PairRouteClosed,
    pub detached_pairing: Option<ConnectionInstanceId>,
}

impl fmt::Debug for PairRouteCloseResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PairRouteCloseResult")
            .field("pair", &self.frame.pair_route.redacted())
            .field("outcome", &self.frame.outcome)
            .field("detached_pairing", &self.detached_pairing.is_some())
            .finish()
    }
}

#[derive(Default, PartialEq, Eq)]
pub(crate) struct PairRouteRemovalEffects {
    pub removed_active: usize,
    pub removed_tombstones: usize,
    pub detached_pairings: Vec<ConnectionInstanceId>,
}

impl PairRouteRemovalEffects {
    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.removed_active == 0
            && self.removed_tombstones == 0
            && self.detached_pairings.is_empty()
    }
}

impl fmt::Debug for PairRouteRemovalEffects {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PairRouteRemovalEffects")
            .field("removed_active", &self.removed_active)
            .field("removed_tombstones", &self.removed_tombstones)
            .field("detached_pairing_count", &self.detached_pairings.len())
            .finish()
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct PairRouteStats {
    pub active_routes: usize,
    pub tombstones: usize,
    pub pairing_bindings: usize,
    pub pending_reservations: usize,
}

impl PairRouteStats {
    #[cfg(test)]
    pub(crate) fn total_routes(self) -> usize {
        self.active_routes.saturating_add(self.tombstones)
    }

    #[cfg(test)]
    pub(crate) fn is_empty(self) -> bool {
        self.total_routes() == 0 && self.pairing_bindings == 0 && self.pending_reservations == 0
    }
}

/// 只由 RelayCore actor 修改。PairRoute/密文/connection 原值都不会出现在 Debug。
pub(crate) struct PairRouteRegistry {
    relay_server_id: RelayServerId,
    limits: PairRouteLimits,
    routes: HashMap<PairRouteId, RouteState>,
    per_machine: HashMap<MachineRouteId, usize>,
    pairing_routes: HashMap<ConnectionInstanceId, PairRouteId>,
    next_reservation_id: u64,
}

impl PairRouteRegistry {
    pub(crate) fn new(
        relay_server_id: RelayServerId,
        limits: PairRouteLimits,
    ) -> Result<Self, RelayFailure> {
        Ok(Self {
            relay_server_id,
            limits: limits.validate()?,
            routes: HashMap::new(),
            per_machine: HashMap::new(),
            pairing_routes: HashMap::new(),
            next_reservation_id: 1,
        })
    }

    pub(crate) fn open(
        &mut self,
        owner: MachineRouteId,
        frame: OpenPairRoute,
        now_ms: u64,
    ) -> Result<PairRouteOpened, RelayFailure> {
        if frame.machine_route != owner {
            return Err(forbidden("PairRoute owner does not match access"));
        }
        if frame.absolute_expiry_ms <= now_ms
            || frame.absolute_expiry_ms > now_ms.saturating_add(self.limits.ttl_ms)
        {
            return Err(conflict("PairRoute absolute expiry is invalid"));
        }

        if let Some(existing) = self.routes.get(&frame.pair_route) {
            return match existing {
                RouteState::Active(route)
                    if route.machine_route == owner
                        && route.absolute_expiry_ms == frame.absolute_expiry_ms =>
                {
                    Ok(PairRouteOpened {
                        machine_route: owner,
                        pair_route: frame.pair_route,
                        absolute_expiry_ms: frame.absolute_expiry_ms,
                    })
                }
                RouteState::Active(_) | RouteState::Tombstone(_) => {
                    Err(conflict("PairRoute is already bound"))
                }
            };
        }

        if self.routes.len() >= self.limits.max_routes_global
            || self.per_machine.get(&owner).copied().unwrap_or(0)
                >= self.limits.max_routes_per_machine
        {
            return Err(quota("PairRoute capacity is exhausted"));
        }

        self.routes.insert(
            frame.pair_route,
            RouteState::Active(ActiveRoute {
                machine_route: owner,
                absolute_expiry_ms: frame.absolute_expiry_ms,
                pairing_connection: None,
                committed_frames: 0,
                committed_bytes: 0,
                reserved_frames: 0,
                reserved_bytes: 0,
                reservations: HashMap::new(),
                bucket: TokenBucket::full(self.limits, now_ms),
            }),
        );
        let count = self.per_machine.entry(owner).or_insert(0);
        *count = count.saturating_add(1);
        Ok(PairRouteOpened {
            machine_route: owner,
            pair_route: frame.pair_route,
            absolute_expiry_ms: frame.absolute_expiry_ms,
        })
    }

    pub(crate) fn close(
        &mut self,
        owner: MachineRouteId,
        frame: ClosePairRoute,
        now_ms: u64,
    ) -> Result<PairRouteCloseResult, RelayFailure> {
        if frame.machine_route != owner {
            return Err(forbidden("PairRoute owner does not match access"));
        }

        let state = self.routes.remove(&frame.pair_route);
        let (outcome, detached_pairing) = match state {
            None => (PairRouteCloseOutcome::AlreadyAbsent, None),
            Some(RouteState::Tombstone(tombstone)) => {
                if now_ms < tombstone.absolute_expiry_ms && tombstone.machine_route != owner {
                    self.routes
                        .insert(frame.pair_route, RouteState::Tombstone(tombstone));
                    return Err(forbidden("PairRoute is unavailable for this access"));
                }
                if now_ms < tombstone.absolute_expiry_ms {
                    self.routes
                        .insert(frame.pair_route, RouteState::Tombstone(tombstone));
                } else {
                    self.decrement_machine(tombstone.machine_route);
                }
                (PairRouteCloseOutcome::AlreadyAbsent, None)
            }
            Some(RouteState::Active(route)) if now_ms >= route.absolute_expiry_ms => {
                self.decrement_machine(route.machine_route);
                let detached = self.detach_binding(frame.pair_route, route.pairing_connection);
                (PairRouteCloseOutcome::AlreadyAbsent, detached)
            }
            Some(RouteState::Active(route)) if route.machine_route != owner => {
                self.routes
                    .insert(frame.pair_route, RouteState::Active(route));
                return Err(forbidden("PairRoute is unavailable for this access"));
            }
            Some(RouteState::Active(route)) => {
                let detached = self.detach_binding(frame.pair_route, route.pairing_connection);
                self.routes.insert(
                    frame.pair_route,
                    RouteState::Tombstone(Tombstone {
                        machine_route: route.machine_route,
                        absolute_expiry_ms: route.absolute_expiry_ms,
                    }),
                );
                (PairRouteCloseOutcome::Closed, detached)
            }
        };
        Ok(PairRouteCloseResult {
            frame: PairRouteClosed {
                pair_route: frame.pair_route,
                outcome,
            },
            detached_pairing,
        })
    }

    pub(crate) fn view(&self, pair_route: PairRouteId, now_ms: u64) -> PairRouteView {
        let active_route = match self.routes.get(&pair_route) {
            Some(RouteState::Active(route)) if now_ms < route.absolute_expiry_ms => {
                Some(ActivePairRoute {
                    relay_server_id: self.relay_server_id,
                    machine_route: route.machine_route,
                    pair_route,
                    absolute_expiry_ms: route.absolute_expiry_ms,
                })
            }
            Some(RouteState::Active(_)) | Some(RouteState::Tombstone(_)) | None => None,
        };
        let tombstoned = matches!(
            self.routes.get(&pair_route),
            Some(RouteState::Tombstone(route)) if now_ms < route.absolute_expiry_ms
        );
        PairRouteView {
            now_ms,
            active_route,
            tombstoned,
        }
    }

    /// view→activate 的 actor 内二次验证与唯一 pairing writer 绑定。
    pub(crate) fn bind_pairing(
        &mut self,
        access: &PairingAccess,
        now_ms: u64,
    ) -> Result<(), RelayFailure> {
        self.validate_pairing_identity(access, now_ms)?;
        if let Some(bound_route) = self
            .pairing_routes
            .get(&access.connection_instance)
            .copied()
            && bound_route != access.pair_route
        {
            return Err(conflict("pairing connection is already bound"));
        }

        let existing_connection = match self.routes.get(&access.pair_route) {
            Some(RouteState::Active(route)) => route.pairing_connection,
            Some(RouteState::Tombstone(_)) | None => {
                return Err(not_found("PairRoute is unavailable or expired"));
            }
        };
        if existing_connection.is_some_and(|connection| connection != access.connection_instance) {
            return Err(conflict(
                "PairRoute already has an active pairing connection",
            ));
        }

        let Some(RouteState::Active(route)) = self.routes.get_mut(&access.pair_route) else {
            return Err(not_found("PairRoute is unavailable or expired"));
        };
        route.pairing_connection = Some(access.connection_instance);
        self.pairing_routes
            .insert(access.connection_instance, access.pair_route);
        Ok(())
    }

    pub(crate) fn validate_pairing(
        &self,
        access: &PairingAccess,
        now_ms: u64,
    ) -> Result<(), RelayFailure> {
        self.validate_pairing_identity(access, now_ms)?;
        let bound = match self.routes.get(&access.pair_route) {
            Some(RouteState::Active(route)) => route.pairing_connection,
            Some(RouteState::Tombstone(_)) | None => None,
        };
        if bound != Some(access.connection_instance)
            || self.pairing_routes.get(&access.connection_instance) != Some(&access.pair_route)
        {
            return Err(forbidden("pairing connection is not bound to this route"));
        }
        Ok(())
    }

    /// Close ACK 丢失后，已经由本 Core 激活的 pairing connection 可在 tombstone 生命周期
    /// 内重试并取得 AlreadyAbsent；PairData/Pong 仍只能访问 active+bound route。
    pub(crate) fn validate_pairing_close(
        &self,
        access: &PairingAccess,
        now_ms: u64,
    ) -> Result<(), RelayFailure> {
        if access.relay_server_id != self.relay_server_id || now_ms >= access.absolute_expiry_ms {
            return Err(not_found("PairRoute is unavailable or expired"));
        }
        match self.routes.get(&access.pair_route) {
            Some(RouteState::Active(_)) => self.validate_pairing(access, now_ms),
            Some(RouteState::Tombstone(route))
                if route.machine_route == access.machine_route
                    && route.absolute_expiry_ms == access.absolute_expiry_ms =>
            {
                Ok(())
            }
            Some(RouteState::Tombstone(_)) | None => {
                Err(not_found("PairRoute is unavailable or expired"))
            }
        }
    }

    pub(crate) fn validate_machine(
        &self,
        machine_route: MachineRouteId,
        pair_route: PairRouteId,
        now_ms: u64,
    ) -> Result<(), RelayFailure> {
        match self.routes.get(&pair_route) {
            Some(RouteState::Active(route))
                if route.machine_route == machine_route && now_ms < route.absolute_expiry_ms =>
            {
                Ok(())
            }
            Some(RouteState::Active(_)) | Some(RouteState::Tombstone(_)) | None => {
                Err(not_found("PairRoute is unavailable or expired"))
            }
        }
    }

    pub(crate) fn pairing_connection(
        &self,
        machine_route: MachineRouteId,
        pair_route: PairRouteId,
        now_ms: u64,
    ) -> Result<ConnectionInstanceId, RelayFailure> {
        match self.routes.get(&pair_route) {
            Some(RouteState::Active(route))
                if route.machine_route == machine_route && now_ms < route.absolute_expiry_ms =>
            {
                route
                    .pairing_connection
                    .filter(|connection| self.pairing_routes.get(connection) == Some(&pair_route))
                    .ok_or_else(|| not_found("PairRoute target is offline"))
            }
            Some(RouteState::Active(_)) | Some(RouteState::Tombstone(_)) | None => {
                Err(not_found("PairRoute is unavailable or expired"))
            }
        }
    }

    pub(crate) fn unbind_pairing(
        &mut self,
        connection: ConnectionInstanceId,
    ) -> Option<PairRouteId> {
        let pair_route = self.pairing_routes.remove(&connection)?;
        if let Some(RouteState::Active(route)) = self.routes.get_mut(&pair_route)
            && route.pairing_connection == Some(connection)
        {
            route.pairing_connection = None;
        }
        Some(pair_route)
    }

    pub(crate) fn reserve_frame(
        &mut self,
        machine_route: MachineRouteId,
        pair_route: PairRouteId,
        canonical_bytes: usize,
        now_ms: u64,
    ) -> Result<PairFrameReservation, RelayFailure> {
        self.validate_machine(machine_route, pair_route, now_ms)?;
        let reservation_id = self.next_reservation_id;
        let next_reservation_id = reservation_id.checked_add(1).ok_or_else(|| {
            failure(
                RELAY_STORE_UNAVAILABLE,
                "PairRoute reservation state is exhausted",
            )
        })?;
        let Some(RouteState::Active(route)) = self.routes.get_mut(&pair_route) else {
            return Err(not_found("PairRoute is unavailable or expired"));
        };

        let used_frames = route
            .committed_frames
            .checked_add(route.reserved_frames)
            .ok_or_else(|| quota("PairRoute frame capacity is exhausted"))?;
        let used_bytes = route
            .committed_bytes
            .checked_add(route.reserved_bytes)
            .ok_or_else(|| quota("PairRoute byte capacity is exhausted"))?;
        if used_frames >= self.limits.max_frames_per_route
            || canonical_bytes > self.limits.max_bytes_per_route.saturating_sub(used_bytes)
        {
            return Err(quota("PairRoute lifetime capacity is exhausted"));
        }
        if !route.bucket.take(self.limits, now_ms) {
            return Err(quota("PairRoute rate capacity is exhausted"));
        }

        route.reserved_frames = route.reserved_frames.saturating_add(1);
        route.reserved_bytes = route.reserved_bytes.saturating_add(canonical_bytes);
        route.reservations.insert(reservation_id, canonical_bytes);
        self.next_reservation_id = next_reservation_id;
        Ok(PairFrameReservation {
            machine_route,
            pair_route,
            reservation_id,
            canonical_bytes,
        })
    }

    pub(crate) fn commit_frame(
        &mut self,
        reservation: PairFrameReservation,
    ) -> Result<(), RelayFailure> {
        let route = self.reservation_route_mut(&reservation)?;
        release_reservation(route, &reservation)?;
        route.committed_frames = route.committed_frames.checked_add(1).ok_or_else(|| {
            failure(
                RELAY_STORE_UNAVAILABLE,
                "PairRoute frame accounting is unavailable",
            )
        })?;
        route.committed_bytes = route
            .committed_bytes
            .checked_add(reservation.canonical_bytes)
            .ok_or_else(|| {
                failure(
                    RELAY_STORE_UNAVAILABLE,
                    "PairRoute byte accounting is unavailable",
                )
            })?;
        Ok(())
    }

    pub(crate) fn rollback_frame(
        &mut self,
        reservation: PairFrameReservation,
    ) -> Result<(), RelayFailure> {
        let route = self.reservation_route_mut(&reservation)?;
        release_reservation(route, &reservation)
    }

    pub(crate) fn tick(&mut self, now_ms: u64) -> PairRouteRemovalEffects {
        let expired: Vec<_> = self
            .routes
            .iter()
            .filter_map(|(pair_route, state)| {
                (now_ms >= state.absolute_expiry_ms()).then_some(*pair_route)
            })
            .collect();
        self.remove_routes(expired)
    }

    /// P2.5 RetireMachine/purge 的预留入口；本阶段不触碰 SQLite/tombstone 持久态。
    #[allow(dead_code)]
    pub(crate) fn remove_machine(
        &mut self,
        machine_route: MachineRouteId,
    ) -> PairRouteRemovalEffects {
        let routes: Vec<_> = self
            .routes
            .iter()
            .filter_map(|(pair_route, state)| {
                (state.machine_route() == machine_route).then_some(*pair_route)
            })
            .collect();
        self.remove_routes(routes)
    }

    pub(crate) fn stats(&self) -> PairRouteStats {
        let mut stats = PairRouteStats {
            pairing_bindings: self.pairing_routes.len(),
            ..PairRouteStats::default()
        };
        for state in self.routes.values() {
            match state {
                RouteState::Active(route) => {
                    stats.active_routes = stats.active_routes.saturating_add(1);
                    stats.pending_reservations = stats
                        .pending_reservations
                        .saturating_add(route.reservations.len());
                }
                RouteState::Tombstone(_) => {
                    stats.tombstones = stats.tombstones.saturating_add(1);
                }
            }
        }
        stats
    }

    #[cfg(test)]
    fn usage(&self, pair_route: PairRouteId) -> Option<(usize, usize, usize, usize)> {
        match self.routes.get(&pair_route)? {
            RouteState::Active(route) => Some((
                route.committed_frames,
                route.committed_bytes,
                route.reserved_frames,
                route.reserved_bytes,
            )),
            RouteState::Tombstone(_) => None,
        }
    }

    fn validate_pairing_identity(
        &self,
        access: &PairingAccess,
        now_ms: u64,
    ) -> Result<(), RelayFailure> {
        match self.routes.get(&access.pair_route) {
            Some(RouteState::Active(route))
                if access.relay_server_id == self.relay_server_id
                    && access.machine_route == route.machine_route
                    && access.absolute_expiry_ms == route.absolute_expiry_ms
                    && now_ms < route.absolute_expiry_ms =>
            {
                Ok(())
            }
            Some(RouteState::Active(_)) | Some(RouteState::Tombstone(_)) | None => {
                Err(not_found("PairRoute is unavailable or expired"))
            }
        }
    }

    fn reservation_route_mut(
        &mut self,
        reservation: &PairFrameReservation,
    ) -> Result<&mut ActiveRoute, RelayFailure> {
        match self.routes.get_mut(&reservation.pair_route) {
            Some(RouteState::Active(route))
                if route.machine_route == reservation.machine_route
                    && route.reservations.get(&reservation.reservation_id)
                        == Some(&reservation.canonical_bytes) =>
            {
                Ok(route)
            }
            Some(RouteState::Active(_)) | Some(RouteState::Tombstone(_)) | None => {
                Err(not_found("PairRoute reservation is unavailable"))
            }
        }
    }

    fn remove_routes(&mut self, pair_routes: Vec<PairRouteId>) -> PairRouteRemovalEffects {
        let mut effects = PairRouteRemovalEffects::default();
        for pair_route in pair_routes {
            let Some(state) = self.routes.remove(&pair_route) else {
                continue;
            };
            self.decrement_machine(state.machine_route());
            match state {
                RouteState::Active(route) => {
                    effects.removed_active = effects.removed_active.saturating_add(1);
                    if let Some(connection) =
                        self.detach_binding(pair_route, route.pairing_connection)
                    {
                        effects.detached_pairings.push(connection);
                    }
                }
                RouteState::Tombstone(_) => {
                    effects.removed_tombstones = effects.removed_tombstones.saturating_add(1);
                }
            }
        }
        effects
    }

    fn detach_binding(
        &mut self,
        pair_route: PairRouteId,
        connection: Option<ConnectionInstanceId>,
    ) -> Option<ConnectionInstanceId> {
        let connection = connection?;
        if self.pairing_routes.get(&connection) == Some(&pair_route) {
            self.pairing_routes.remove(&connection);
        }
        Some(connection)
    }

    fn decrement_machine(&mut self, machine_route: MachineRouteId) {
        let should_remove = if let Some(count) = self.per_machine.get_mut(&machine_route) {
            *count = count.saturating_sub(1);
            *count == 0
        } else {
            false
        };
        if should_remove {
            self.per_machine.remove(&machine_route);
        }
    }
}

impl fmt::Debug for PairRouteRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PairRouteRegistry")
            .field("relay_server", &"<redacted>")
            .field("limits", &self.limits)
            .field("stats", &self.stats())
            .finish()
    }
}

fn release_reservation(
    route: &mut ActiveRoute,
    reservation: &PairFrameReservation,
) -> Result<(), RelayFailure> {
    let Some(bytes) = route.reservations.remove(&reservation.reservation_id) else {
        return Err(not_found("PairRoute reservation is unavailable"));
    };
    if bytes != reservation.canonical_bytes
        || route.reserved_frames == 0
        || route.reserved_bytes < reservation.canonical_bytes
    {
        return Err(failure(
            RELAY_STORE_UNAVAILABLE,
            "PairRoute reservation accounting is unavailable",
        ));
    }
    route.reserved_frames -= 1;
    route.reserved_bytes -= reservation.canonical_bytes;
    Ok(())
}

fn failure(code: &'static str, message: &'static str) -> RelayFailure {
    RelayFailure::new(code, message)
}

fn conflict(message: &'static str) -> RelayFailure {
    failure(RELAY_ROUTE_CONFLICT, message)
}

fn forbidden(message: &'static str) -> RelayFailure {
    failure(RELAY_ROUTE_FORBIDDEN, message)
}

fn not_found(message: &'static str) -> RelayFailure {
    failure(RELAY_ROUTE_NOT_FOUND, message)
}

fn quota(message: &'static str) -> RelayFailure {
    failure(RELAY_QUOTA_EXCEEDED, message)
}

#[cfg(test)]
mod tests {
    use agentdeck_protocol::relay_v2::failure::{
        RELAY_QUOTA_EXCEEDED, RELAY_ROUTE_CONFLICT, RELAY_ROUTE_FORBIDDEN, RELAY_ROUTE_NOT_FOUND,
        RELAY_TRANSPORT_CONFIG_INVALID,
    };
    use agentdeck_protocol::relay_v2::frame::{
        ClosePairRoute, OpenPairRoute, PairRouteCloseOutcome,
    };
    use agentdeck_protocol::relay_v2::{
        ConnectionInstanceId, MachineRouteId, PairRouteId, RelayServerId,
    };

    use crate::v2::auth::PairingAccess;

    use super::*;

    const NOW_MS: u64 = 1_726_000_000_000;

    fn server(seed: u8) -> RelayServerId {
        RelayServerId::from_bytes([seed; 16])
    }

    fn machine(seed: u8) -> MachineRouteId {
        MachineRouteId::from_bytes([seed; 16])
    }

    fn route(seed: u8) -> PairRouteId {
        PairRouteId::from_bytes([seed; 16])
    }

    fn numbered_route(value: u128) -> PairRouteId {
        PairRouteId::from_bytes(value.to_be_bytes())
    }

    fn connection(value: u128) -> ConnectionInstanceId {
        ConnectionInstanceId::from_bytes(value.to_be_bytes())
    }

    fn open(machine_route: MachineRouteId, pair_route: PairRouteId, expiry: u64) -> OpenPairRoute {
        OpenPairRoute {
            machine_route,
            pair_route,
            absolute_expiry_ms: expiry,
        }
    }

    fn close(machine_route: MachineRouteId, pair_route: PairRouteId) -> ClosePairRoute {
        ClosePairRoute {
            machine_route,
            pair_route,
        }
    }

    fn pairing_access(
        relay_server_id: RelayServerId,
        machine_route: MachineRouteId,
        pair_route: PairRouteId,
        connection_instance: ConnectionInstanceId,
        absolute_expiry_ms: u64,
    ) -> PairingAccess {
        PairingAccess {
            relay_server_id,
            machine_route,
            pair_route,
            connection_instance,
            absolute_expiry_ms,
        }
    }

    #[test]
    fn default_limits_are_exact_and_invalid_or_raised_limits_fail_closed() {
        let defaults = PairRouteLimits::default();
        assert_eq!(defaults.max_routes_per_machine, 8);
        assert_eq!(defaults.max_routes_global, 1_024);
        assert_eq!(defaults.max_frames_per_route, 32);
        assert_eq!(defaults.max_bytes_per_route, 1024 * 1024);
        assert_eq!(defaults.ttl_ms, 300_000);
        assert_eq!(defaults.bucket_capacity, 8);
        assert_eq!(defaults.bucket_refill_per_second, 2);
        defaults.validate().expect("approved defaults");

        for invalid in [
            PairRouteLimits {
                max_routes_per_machine: 0,
                ..defaults
            },
            PairRouteLimits {
                max_routes_global: HARD_MAX_ROUTES_GLOBAL + 1,
                ..defaults
            },
            PairRouteLimits {
                max_frames_per_route: HARD_MAX_FRAMES_PER_ROUTE + 1,
                ..defaults
            },
            PairRouteLimits {
                max_bytes_per_route: HARD_MAX_BYTES_PER_ROUTE + 1,
                ..defaults
            },
            PairRouteLimits {
                ttl_ms: HARD_MAX_TTL_MS + 1,
                ..defaults
            },
            PairRouteLimits {
                bucket_capacity: HARD_MAX_BUCKET_CAPACITY + 1,
                ..defaults
            },
            PairRouteLimits {
                bucket_refill_per_second: HARD_MAX_BUCKET_REFILL_PER_SECOND + 1,
                ..defaults
            },
            PairRouteLimits {
                max_routes_per_machine: 2,
                max_routes_global: 1,
                ..defaults
            },
            PairRouteLimits {
                max_frames_per_route: 4,
                bucket_capacity: 5,
                ..defaults
            },
        ] {
            assert_eq!(
                invalid.validate().expect_err("invalid limits").code,
                RELAY_TRANSPORT_CONFIG_INVALID
            );
        }
    }

    #[test]
    fn exact_per_machine_and_global_route_caps_are_enforced() {
        let limits = PairRouteLimits::default();
        let expiry = NOW_MS + limits.ttl_ms;
        let owner = machine(1);
        let mut per_machine = PairRouteRegistry::new(server(1), limits).expect("registry");
        for index in 0..limits.max_routes_per_machine {
            let pair = numbered_route(index as u128 + 1);
            per_machine
                .open(owner, open(owner, pair, expiry), NOW_MS)
                .expect("within per-machine cap");
        }
        assert_eq!(
            per_machine
                .open(owner, open(owner, numbered_route(99), expiry), NOW_MS,)
                .expect_err("ninth route for one machine")
                .code,
            RELAY_QUOTA_EXCEEDED
        );
        per_machine
            .open(
                machine(2),
                open(machine(2), numbered_route(100), expiry),
                NOW_MS,
            )
            .expect("another machine has independent cap");

        let mut global = PairRouteRegistry::new(server(2), limits).expect("registry");
        for machine_index in 0..128_u16 {
            let owner = machine(machine_index as u8);
            for slot in 0..limits.max_routes_per_machine {
                let value = u128::from(machine_index)
                    .saturating_mul(limits.max_routes_per_machine as u128)
                    .saturating_add(slot as u128)
                    .saturating_add(1);
                let pair = numbered_route(value);
                global
                    .open(owner, open(owner, pair, expiry), NOW_MS)
                    .expect("within global cap");
            }
        }
        assert_eq!(global.stats().active_routes, limits.max_routes_global);
        assert_eq!(
            global
                .open(
                    machine(200),
                    open(machine(200), numbered_route(2_000), expiry),
                    NOW_MS,
                )
                .expect_err("global route cap")
                .code,
            RELAY_QUOTA_EXCEEDED
        );
    }

    #[test]
    fn open_is_exactly_idempotent_and_rejects_owner_expiry_and_ttl_conflicts() {
        let mut registry =
            PairRouteRegistry::new(server(1), PairRouteLimits::default()).expect("registry");
        let owner = machine(2);
        let pair = route(3);
        let expiry = NOW_MS + HARD_MAX_TTL_MS;
        let request = open(owner, pair, expiry);

        let first = registry
            .open(owner, request.clone(), NOW_MS)
            .expect("first open");
        assert_eq!(first.machine_route, owner);
        assert_eq!(first.pair_route, pair);
        assert_eq!(first.absolute_expiry_ms, expiry);
        assert_eq!(
            registry
                .open(owner, request.clone(), NOW_MS + 1)
                .expect("exact retry"),
            first
        );

        assert_eq!(
            registry
                .open(machine(4), request.clone(), NOW_MS + 1)
                .expect_err("frame owner mismatch")
                .code,
            RELAY_ROUTE_FORBIDDEN
        );
        assert_eq!(
            registry
                .open(machine(4), open(machine(4), pair, expiry), NOW_MS + 1,)
                .expect_err("active owner conflict")
                .code,
            RELAY_ROUTE_CONFLICT
        );
        assert_eq!(
            registry
                .open(owner, open(owner, pair, expiry - 1), NOW_MS + 1)
                .expect_err("expiry conflict")
                .code,
            RELAY_ROUTE_CONFLICT
        );
        assert_eq!(
            registry
                .open(owner, open(owner, route(5), NOW_MS), NOW_MS)
                .expect_err("already expired")
                .code,
            RELAY_ROUTE_CONFLICT
        );
        assert_eq!(
            registry
                .open(
                    owner,
                    open(owner, route(6), NOW_MS + HARD_MAX_TTL_MS + 1),
                    NOW_MS,
                )
                .expect_err("ttl extension")
                .code,
            RELAY_ROUTE_CONFLICT
        );
    }

    #[test]
    fn tombstones_hold_capacity_block_late_open_and_expire_on_tick() {
        let limits = PairRouteLimits {
            max_routes_per_machine: 1,
            max_routes_global: 1,
            ttl_ms: 1_000,
            ..PairRouteLimits::default()
        };
        let mut registry = PairRouteRegistry::new(server(1), limits).expect("registry");
        let owner = machine(2);
        let first_route = route(3);
        let expiry = NOW_MS + 1_000;
        registry
            .open(owner, open(owner, first_route, expiry), NOW_MS)
            .expect("open");
        let closed = registry
            .close(owner, close(owner, first_route), NOW_MS + 1)
            .expect("close");
        assert_eq!(closed.frame.outcome, PairRouteCloseOutcome::Closed);
        assert_eq!(registry.stats().active_routes, 0);
        assert_eq!(registry.stats().tombstones, 1);
        assert_eq!(
            registry
                .close(machine(9), close(machine(9), first_route), NOW_MS + 1,)
                .expect_err("tombstone remains owner-isolated")
                .code,
            RELAY_ROUTE_FORBIDDEN
        );

        assert_eq!(
            registry
                .open(owner, open(owner, first_route, expiry), NOW_MS + 2,)
                .expect_err("terminal route cannot reopen")
                .code,
            RELAY_ROUTE_CONFLICT
        );
        assert_eq!(
            registry
                .open(owner, open(owner, route(4), expiry), NOW_MS + 2)
                .expect_err("tombstone counts toward capacity")
                .code,
            RELAY_QUOTA_EXCEEDED
        );
        assert!(registry.tick(expiry - 1).is_empty());
        let swept = registry.tick(expiry);
        assert_eq!(swept.removed_tombstones, 1);
        assert_eq!(registry.stats().total_routes(), 0);
    }

    #[test]
    fn close_is_owner_checked_and_unknown_or_expired_is_already_absent() {
        let mut registry =
            PairRouteRegistry::new(server(1), PairRouteLimits::default()).expect("registry");
        let owner = machine(2);
        let pair = route(3);
        let expiry = NOW_MS + 100;
        registry
            .open(owner, open(owner, pair, expiry), NOW_MS)
            .expect("open");

        assert_eq!(
            registry
                .close(machine(4), close(machine(4), pair), NOW_MS + 1)
                .expect_err("different active owner")
                .code,
            RELAY_ROUTE_FORBIDDEN
        );
        assert_eq!(
            registry
                .close(owner, close(machine(4), pair), NOW_MS + 1)
                .expect_err("frame owner mismatch")
                .code,
            RELAY_ROUTE_FORBIDDEN
        );
        assert_eq!(
            registry
                .close(owner, close(owner, route(9)), NOW_MS + 1)
                .expect("unknown")
                .frame
                .outcome,
            PairRouteCloseOutcome::AlreadyAbsent
        );
        assert_eq!(
            registry
                .close(owner, close(owner, pair), expiry)
                .expect("expired")
                .frame
                .outcome,
            PairRouteCloseOutcome::AlreadyAbsent
        );
        assert_eq!(registry.stats().total_routes(), 0);
    }

    #[test]
    fn view_filters_tombstone_and_expiry_without_exposing_other_routes() {
        let relay = server(1);
        let mut registry =
            PairRouteRegistry::new(relay, PairRouteLimits::default()).expect("registry");
        let owner = machine(2);
        let pair = route(3);
        let expiry = NOW_MS + 10;
        registry
            .open(owner, open(owner, pair, expiry), NOW_MS)
            .expect("open");

        let view = registry.view(pair, NOW_MS + 9);
        let active = view.active_route.expect("active route");
        assert_eq!(active.relay_server_id, relay);
        assert_eq!(active.machine_route, owner);
        assert_eq!(active.pair_route, pair);
        assert_eq!(active.absolute_expiry_ms, expiry);
        assert!(!view.tombstoned);
        let unknown = registry.view(route(4), NOW_MS + 9);
        assert!(unknown.active_route.is_none());
        assert!(!unknown.tombstoned);
        let expired = registry.view(pair, expiry);
        assert!(expired.active_route.is_none());
        assert!(!expired.tombstoned);

        registry
            .close(owner, close(owner, pair), NOW_MS + 9)
            .expect("close");
        let tombstone = registry.view(pair, NOW_MS + 9);
        assert!(tombstone.active_route.is_none());
        assert!(tombstone.tombstoned);
    }

    #[test]
    fn pairing_binding_is_single_idempotent_revalidated_and_reconnectable_after_unbind() {
        let relay = server(1);
        let mut registry =
            PairRouteRegistry::new(relay, PairRouteLimits::default()).expect("registry");
        let owner = machine(2);
        let pair = route(3);
        let expiry = NOW_MS + 100;
        registry
            .open(owner, open(owner, pair, expiry), NOW_MS)
            .expect("open");
        let first = pairing_access(relay, owner, pair, connection(1), expiry);
        let second = pairing_access(relay, owner, pair, connection(2), expiry);

        registry
            .bind_pairing(&first, NOW_MS + 1)
            .expect("first bind");
        assert_eq!(
            registry
                .pairing_connection(owner, pair, NOW_MS + 1)
                .expect("bound target"),
            connection(1)
        );
        assert_eq!(
            registry
                .pairing_connection(machine(9), pair, NOW_MS + 1)
                .expect_err("cross-owner lookup is opaque")
                .code,
            RELAY_ROUTE_NOT_FOUND
        );
        registry
            .bind_pairing(&first, NOW_MS + 2)
            .expect("idempotent bind");
        registry
            .validate_pairing(&first, NOW_MS + 2)
            .expect("bound access");
        assert_eq!(
            registry
                .bind_pairing(&second, NOW_MS + 2)
                .expect_err("single writer")
                .code,
            RELAY_ROUTE_CONFLICT
        );
        assert_eq!(
            registry
                .validate_pairing(&second, NOW_MS + 2)
                .expect_err("unbound access")
                .code,
            RELAY_ROUTE_FORBIDDEN
        );
        assert_eq!(registry.unbind_pairing(connection(1)), Some(pair));
        assert_eq!(
            registry
                .pairing_connection(owner, pair, NOW_MS + 2)
                .expect_err("unbound target is offline")
                .code,
            RELAY_ROUTE_NOT_FOUND
        );
        registry
            .bind_pairing(&second, NOW_MS + 3)
            .expect("reconnect");
        assert_eq!(registry.stats().pairing_bindings, 1);
        let closed = registry
            .close(owner, close(owner, pair), NOW_MS + 4)
            .expect("close bound route");
        assert_eq!(closed.frame.outcome, PairRouteCloseOutcome::Closed);
        assert_eq!(closed.detached_pairing, Some(connection(2)));
        assert_eq!(registry.stats().pairing_bindings, 0);
        registry
            .validate_pairing_close(&second, NOW_MS + 4)
            .expect("activated connection may retry terminal close on tombstone");
        assert_eq!(
            registry
                .validate_pairing(&second, NOW_MS + 4)
                .expect_err("closed route")
                .code,
            RELAY_ROUTE_NOT_FOUND
        );
        assert_eq!(
            registry
                .validate_pairing_close(&second, expiry)
                .expect_err("expired pairing access cannot retry close")
                .code,
            RELAY_ROUTE_NOT_FOUND
        );
    }

    #[test]
    fn bucket_is_route_local_refills_and_rollback_does_not_refund_rate_token() {
        let limits = PairRouteLimits {
            max_frames_per_route: 8,
            bucket_capacity: 2,
            bucket_refill_per_second: 1,
            ..PairRouteLimits::default()
        };
        let mut registry = PairRouteRegistry::new(server(1), limits).expect("registry");
        let owner = machine(2);
        for pair in [route(3), route(4)] {
            registry
                .open(owner, open(owner, pair, NOW_MS + limits.ttl_ms), NOW_MS)
                .expect("open");
        }

        let first = registry
            .reserve_frame(owner, route(3), 10, NOW_MS)
            .expect("first token");
        registry.rollback_frame(first).expect("rollback");
        let second = registry
            .reserve_frame(owner, route(3), 10, NOW_MS)
            .expect("second token");
        registry.rollback_frame(second).expect("rollback");
        assert_eq!(
            registry
                .reserve_frame(owner, route(3), 10, NOW_MS + 999)
                .expect_err("no early refill")
                .code,
            RELAY_QUOTA_EXCEEDED
        );
        let refilled = registry
            .reserve_frame(owner, route(3), 10, NOW_MS + 1_000)
            .expect("one token refilled");
        registry.commit_frame(refilled).expect("commit");

        let independent = registry
            .reserve_frame(owner, route(4), 10, NOW_MS)
            .expect("other route has own bucket");
        registry.commit_frame(independent).expect("commit");
    }

    #[test]
    fn lifetime_count_and_canonical_bytes_are_two_phase_and_bounded() {
        let limits = PairRouteLimits {
            max_frames_per_route: 2,
            max_bytes_per_route: 10,
            bucket_capacity: 2,
            bucket_refill_per_second: 2,
            ..PairRouteLimits::default()
        };
        let mut registry = PairRouteRegistry::new(server(1), limits).expect("registry");
        let owner = machine(2);
        let pair = route(3);
        registry
            .open(owner, open(owner, pair, NOW_MS + limits.ttl_ms), NOW_MS)
            .expect("open");

        let rolled_back = registry
            .reserve_frame(owner, pair, 6, NOW_MS)
            .expect("reserve");
        assert_eq!(registry.stats().pending_reservations, 1);
        registry.rollback_frame(rolled_back).expect("rollback");
        assert_eq!(registry.stats().pending_reservations, 0);

        let first = registry
            .reserve_frame(owner, pair, 6, NOW_MS + 500)
            .expect("refilled after rollback");
        registry.commit_frame(first).expect("commit");
        assert_eq!(registry.usage(pair), Some((1, 6, 0, 0)));
        assert_eq!(
            registry
                .reserve_frame(owner, pair, 5, NOW_MS + 1_000)
                .expect_err("cumulative byte quota")
                .code,
            RELAY_QUOTA_EXCEEDED
        );
        let second = registry
            .reserve_frame(owner, pair, 4, NOW_MS + 1_000)
            .expect("exact byte boundary");
        registry.commit_frame(second).expect("commit");
        assert_eq!(registry.usage(pair), Some((2, 10, 0, 0)));
        assert_eq!(
            registry
                .reserve_frame(owner, pair, 0, NOW_MS + 1_500)
                .expect_err("frame count quota")
                .code,
            RELAY_QUOTA_EXCEEDED
        );
    }

    #[test]
    fn tick_and_remove_machine_detach_pairing_and_bound_all_memory() {
        let relay = server(1);
        let limits = PairRouteLimits {
            ttl_ms: 100,
            ..PairRouteLimits::default()
        };
        let mut registry = PairRouteRegistry::new(relay, limits).expect("registry");
        let owner_a = machine(2);
        let owner_b = machine(3);
        for (owner, pair, conn) in [
            (owner_a, route(4), connection(1)),
            (owner_a, route(5), connection(2)),
            (owner_b, route(6), connection(3)),
        ] {
            registry
                .open(owner, open(owner, pair, NOW_MS + limits.ttl_ms), NOW_MS)
                .expect("open");
            registry
                .bind_pairing(
                    &pairing_access(relay, owner, pair, conn, NOW_MS + limits.ttl_ms),
                    NOW_MS,
                )
                .expect("bind");
        }

        let removed = registry.remove_machine(owner_a);
        assert_eq!(removed.removed_active, 2);
        assert_eq!(removed.detached_pairings.len(), 2);
        assert_eq!(registry.stats().active_routes, 1);
        let expired = registry.tick(NOW_MS + limits.ttl_ms);
        assert_eq!(expired.removed_active, 1);
        assert_eq!(expired.detached_pairings, vec![connection(3)]);
        assert!(registry.stats().is_empty());
    }

    #[test]
    fn debug_output_contains_only_limits_counts_and_redacted_routes() {
        let mut registry =
            PairRouteRegistry::new(server(0xaa), PairRouteLimits::default()).expect("registry");
        let owner = machine(0xbb);
        let pair = route(0xcc);
        registry
            .open(owner, open(owner, pair, NOW_MS + HARD_MAX_TTL_MS), NOW_MS)
            .expect("open");
        let ticket = registry
            .reserve_frame(owner, pair, 17, NOW_MS)
            .expect("ticket");

        let registry_debug = format!("{registry:?}");
        let ticket_debug = format!("{ticket:?}");
        for raw in [
            format!("{:?}", [0xaa_u8; 16]),
            format!("{:?}", [0xbb_u8; 16]),
            format!("{:?}", [0xcc_u8; 16]),
            "aa".repeat(16),
            "bb".repeat(16),
            "cc".repeat(16),
        ] {
            assert!(!registry_debug.contains(&raw));
            assert!(!ticket_debug.contains(&raw));
        }
        assert!(registry_debug.contains("active_routes"));
        assert!(ticket_debug.contains(&pair.redacted()));
    }
}
