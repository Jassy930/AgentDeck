//! 有界、单次、仅内存的 Relay v2 challenge registry。

use std::collections::HashMap;
use std::fmt;
use std::sync::Mutex;
use std::time::Instant;

use agentdeck_protocol::relay_v2::failure::{
    RELAY_AUTH_CHALLENGE_EXPIRED, RELAY_AUTH_REPLAY, RELAY_QUOTA_EXCEEDED, RELAY_STORE_UNAVAILABLE,
};
use agentdeck_protocol::relay_v2::frame::Challenge;
use agentdeck_protocol::relay_v2::{
    ConnectionInstanceId, DeviceRouteId, MachineRouteId, RelayFailure, RelayServerId,
};
use rand::RngCore;

pub const CHALLENGE_TTL_MS: u64 = 30_000;
pub const MAX_PENDING_CHALLENGES: usize = 4_096;
pub const MAX_CHALLENGE_BUCKET_IDLE_TTL_MS: u64 = 5 * 60_000;
const TOKEN_MILLIS: u64 = 1_000;

pub trait MonotonicClock: Send + Sync + 'static {
    fn now_ms(&self) -> u64;
}

#[derive(Debug)]
pub struct SystemMonotonicClock {
    origin: Instant,
}

impl Default for SystemMonotonicClock {
    fn default() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl MonotonicClock for SystemMonotonicClock {
    fn now_ms(&self) -> u64 {
        u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChallengeSource([u8; 32]);

impl ChallengeSource {
    /// 调用方传入进程内 keyed hash；Registry 不保存原始 IP/transport identity。
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for ChallengeSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ChallengeSource")
            .field(&"<redacted>")
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChallengeRoute {
    Machine(MachineRouteId),
    Device {
        machine_route: MachineRouteId,
        device_route: DeviceRouteId,
    },
}

impl fmt::Debug for ChallengeRoute {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Machine(machine) => formatter
                .debug_tuple("Machine")
                .field(&machine.redacted())
                .finish(),
            Self::Device {
                machine_route,
                device_route,
            } => formatter
                .debug_struct("Device")
                .field("machine", &machine_route.redacted())
                .field("device", &device_route.redacted())
                .finish(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenBucketLimits {
    pub capacity: u64,
    pub refill_tokens_per_second: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChallengeLimits {
    pub max_pending: usize,
    pub source_bucket: TokenBucketLimits,
    pub route_bucket: TokenBucketLimits,
    pub max_source_buckets: usize,
    pub max_route_buckets: usize,
    pub bucket_idle_ttl_ms: u64,
}

impl Default for ChallengeLimits {
    fn default() -> Self {
        Self {
            max_pending: MAX_PENDING_CHALLENGES,
            source_bucket: TokenBucketLimits {
                capacity: 16,
                refill_tokens_per_second: 2,
            },
            route_bucket: TokenBucketLimits {
                capacity: 32,
                refill_tokens_per_second: 4,
            },
            max_source_buckets: MAX_PENDING_CHALLENGES,
            max_route_buckets: MAX_PENDING_CHALLENGES,
            bucket_idle_ttl_ms: 2 * CHALLENGE_TTL_MS,
        }
    }
}

impl ChallengeLimits {
    fn validate(self) -> Result<Self, RelayFailure> {
        let bucket_valid = |bucket: TokenBucketLimits| {
            bucket.capacity > 0
                && bucket.capacity <= MAX_PENDING_CHALLENGES as u64
                && bucket.refill_tokens_per_second > 0
                && bucket.refill_tokens_per_second <= MAX_PENDING_CHALLENGES as u64
                && bucket.capacity.checked_mul(TOKEN_MILLIS).is_some()
        };
        if self.max_pending == 0
            || self.max_pending > MAX_PENDING_CHALLENGES
            || self.max_source_buckets == 0
            || self.max_source_buckets > MAX_PENDING_CHALLENGES
            || self.max_route_buckets == 0
            || self.max_route_buckets > MAX_PENDING_CHALLENGES
            || self.bucket_idle_ttl_ms < CHALLENGE_TTL_MS
            || self.bucket_idle_ttl_ms > MAX_CHALLENGE_BUCKET_IDLE_TTL_MS
            || !bucket_valid(self.source_bucket)
            || !bucket_valid(self.route_bucket)
        {
            return Err(quota_failure("challenge limits are invalid"));
        }
        Ok(self)
    }
}

#[derive(Clone)]
struct PendingChallenge {
    challenge: Challenge,
    source: ChallengeSource,
    issued_at_ms: u64,
}

#[derive(Clone, Copy)]
struct ExpiredChallenge {
    expired_at_ms: u64,
    source: ChallengeSource,
}

#[derive(Debug, Clone, Copy)]
struct TokenBucket {
    available_milli_tokens: u64,
    last_refill_ms: u64,
    last_seen_ms: u64,
}

impl TokenBucket {
    fn full(limits: TokenBucketLimits, now_ms: u64) -> Self {
        Self {
            available_milli_tokens: limits.capacity.saturating_mul(TOKEN_MILLIS),
            last_refill_ms: now_ms,
            last_seen_ms: now_ms,
        }
    }

    fn take(&mut self, limits: TokenBucketLimits, now_ms: u64) -> bool {
        if now_ms >= self.last_refill_ms {
            let elapsed = now_ms - self.last_refill_ms;
            let refill = elapsed.saturating_mul(limits.refill_tokens_per_second);
            self.available_milli_tokens = self
                .available_milli_tokens
                .saturating_add(refill)
                .min(limits.capacity.saturating_mul(TOKEN_MILLIS));
            self.last_refill_ms = now_ms;
        }
        self.last_seen_ms = now_ms;
        if self.available_milli_tokens < TOKEN_MILLIS {
            false
        } else {
            self.available_milli_tokens -= TOKEN_MILLIS;
            true
        }
    }
}

#[derive(Default)]
struct ChallengeState {
    pending: HashMap<ConnectionInstanceId, PendingChallenge>,
    expired: HashMap<ConnectionInstanceId, ExpiredChallenge>,
    source_buckets: HashMap<ChallengeSource, TokenBucket>,
    route_buckets: HashMap<ChallengeRoute, TokenBucket>,
}

pub struct ChallengeRegistry {
    relay_server_id: RelayServerId,
    clock: std::sync::Arc<dyn MonotonicClock>,
    limits: ChallengeLimits,
    state: Mutex<ChallengeState>,
}

impl fmt::Debug for ChallengeRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ChallengeRegistry")
            .field("limits", &self.limits)
            .field("relay_server", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl ChallengeRegistry {
    pub fn new(
        relay_server_id: RelayServerId,
        clock: std::sync::Arc<dyn MonotonicClock>,
        limits: ChallengeLimits,
    ) -> Result<Self, RelayFailure> {
        Ok(Self {
            relay_server_id,
            clock,
            limits: limits.validate()?,
            state: Mutex::new(ChallengeState::default()),
        })
    }

    pub fn issue(
        &self,
        connection_instance: ConnectionInstanceId,
        source: ChallengeSource,
    ) -> Result<Challenge, RelayFailure> {
        let now_ms = self.clock.now_ms();
        let mut state = self.lock()?;
        self.cleanup(&mut state, now_ms);
        if state.pending.contains_key(&connection_instance)
            || state.expired.contains_key(&connection_instance)
        {
            return Err(replay_failure());
        }
        if state.pending.len() >= self.limits.max_pending {
            return Err(quota_failure("challenge capacity is exhausted"));
        }
        take_bucket(
            &mut state.source_buckets,
            source,
            self.limits.source_bucket,
            self.limits.max_source_buckets,
            now_ms,
        )?;
        let mut nonce = [0_u8; 32];
        rand::rngs::OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| unavailable_failure())?;
        let challenge = Challenge {
            relay_server_id: self.relay_server_id,
            connection_instance,
            challenge_nonce: nonce,
        };
        state.pending.insert(
            connection_instance,
            PendingChallenge {
                challenge: challenge.clone(),
                source,
                issued_at_ms: now_ms,
            },
        );
        Ok(challenge)
    }

    /// `remove` 发生在 source/TTL/route rate 检查之前；任何消费尝试都烧毁 nonce。
    pub fn consume(
        &self,
        connection_instance: ConnectionInstanceId,
        source: ChallengeSource,
        route: ChallengeRoute,
    ) -> Result<ConsumedChallenge, RelayFailure> {
        let now_ms = self.clock.now_ms();
        let mut state = self.lock()?;
        self.cleanup(&mut state, now_ms);
        let Some(pending) = state.pending.remove(&connection_instance) else {
            if let Some(expired) = state.expired.remove(&connection_instance) {
                return if expired.source == source {
                    Err(expired_failure())
                } else {
                    Err(replay_failure())
                };
            }
            return Err(replay_failure());
        };
        if pending.source != source {
            return Err(replay_failure());
        }
        if now_ms.saturating_sub(pending.issued_at_ms) >= CHALLENGE_TTL_MS {
            return Err(expired_failure());
        }
        take_bucket(
            &mut state.route_buckets,
            route,
            self.limits.route_bucket,
            self.limits.max_route_buckets,
            now_ms,
        )?;
        Ok(ConsumedChallenge {
            challenge: pending.challenge,
            route,
            consumed_at_ms: now_ms,
        })
    }

    pub fn stats(&self) -> Result<ChallengeStats, RelayFailure> {
        let now_ms = self.clock.now_ms();
        let mut state = self.lock()?;
        self.cleanup(&mut state, now_ms);
        Ok(ChallengeStats {
            pending: state.pending.len(),
            expired_tombstones: state.expired.len(),
            source_buckets: state.source_buckets.len(),
            route_buckets: state.route_buckets.len(),
        })
    }

    fn cleanup(&self, state: &mut ChallengeState, now_ms: u64) {
        state
            .expired
            .retain(|_, expired| now_ms.saturating_sub(expired.expired_at_ms) < CHALLENGE_TTL_MS);
        let expired_connections: Vec<_> = state
            .pending
            .iter()
            .filter_map(|(connection, pending)| {
                (now_ms.saturating_sub(pending.issued_at_ms) >= CHALLENGE_TTL_MS).then_some((
                    *connection,
                    ExpiredChallenge {
                        expired_at_ms: pending.issued_at_ms.saturating_add(CHALLENGE_TTL_MS),
                        source: pending.source,
                    },
                ))
            })
            .collect();
        for (connection, expired) in expired_connections {
            state.pending.remove(&connection);
            if state.expired.len() >= self.limits.max_pending
                && let Some(oldest) = state
                    .expired
                    .iter()
                    .min_by_key(|(_, expired)| expired.expired_at_ms)
                    .map(|(connection, _)| *connection)
            {
                state.expired.remove(&oldest);
            }
            state.expired.insert(connection, expired);
        }
        let idle_ttl = self.limits.bucket_idle_ttl_ms;
        state
            .source_buckets
            .retain(|_, bucket| now_ms.saturating_sub(bucket.last_seen_ms) < idle_ttl);
        state
            .route_buckets
            .retain(|_, bucket| now_ms.saturating_sub(bucket.last_seen_ms) < idle_ttl);
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, ChallengeState>, RelayFailure> {
        self.state.lock().map_err(|_| unavailable_failure())
    }
}

pub struct ConsumedChallenge {
    challenge: Challenge,
    route: ChallengeRoute,
    consumed_at_ms: u64,
}

impl fmt::Debug for ConsumedChallenge {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConsumedChallenge")
            .field("route", &self.route)
            .field("consumed_at_ms", &self.consumed_at_ms)
            .field("challenge", &"<redacted>")
            .finish()
    }
}

impl ConsumedChallenge {
    pub fn challenge(&self) -> &Challenge {
        &self.challenge
    }

    pub fn route(&self) -> ChallengeRoute {
        self.route
    }

    pub fn consumed_at_ms(&self) -> u64 {
        self.consumed_at_ms
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChallengeStats {
    pub pending: usize,
    pub expired_tombstones: usize,
    pub source_buckets: usize,
    pub route_buckets: usize,
}

fn take_bucket<K: Copy + Eq + std::hash::Hash>(
    buckets: &mut HashMap<K, TokenBucket>,
    key: K,
    limits: TokenBucketLimits,
    max_buckets: usize,
    now_ms: u64,
) -> Result<(), RelayFailure> {
    if !buckets.contains_key(&key) && buckets.len() >= max_buckets {
        return Err(quota_failure("challenge rate-limit capacity is exhausted"));
    }
    let bucket = buckets
        .entry(key)
        .or_insert_with(|| TokenBucket::full(limits, now_ms));
    if bucket.take(limits, now_ms) {
        Ok(())
    } else {
        Err(quota_failure("challenge rate limit exceeded"))
    }
}

fn replay_failure() -> RelayFailure {
    RelayFailure::new(
        RELAY_AUTH_REPLAY,
        "authentication challenge was already used",
    )
}

fn expired_failure() -> RelayFailure {
    RelayFailure::new(
        RELAY_AUTH_CHALLENGE_EXPIRED,
        "authentication challenge expired",
    )
}

fn quota_failure(message: &'static str) -> RelayFailure {
    RelayFailure::new(RELAY_QUOTA_EXCEEDED, message)
}

fn unavailable_failure() -> RelayFailure {
    RelayFailure::new(
        RELAY_STORE_UNAVAILABLE,
        "authentication challenge state is unavailable",
    )
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Barrier};

    use super::*;

    #[derive(Default)]
    struct ManualClock(AtomicU64);

    impl ManualClock {
        fn set(&self, value: u64) {
            self.0.store(value, Ordering::SeqCst);
        }
    }

    impl MonotonicClock for ManualClock {
        fn now_ms(&self) -> u64 {
            self.0.load(Ordering::SeqCst)
        }
    }

    fn id(value: u8) -> ConnectionInstanceId {
        ConnectionInstanceId::from_bytes([value; 16])
    }

    fn source(value: u8) -> ChallengeSource {
        ChallengeSource::from_bytes([value; 32])
    }

    fn route(value: u8) -> ChallengeRoute {
        ChallengeRoute::Machine(MachineRouteId::from_bytes([value; 16]))
    }

    fn limits() -> ChallengeLimits {
        ChallengeLimits {
            max_pending: 4,
            source_bucket: TokenBucketLimits {
                capacity: 4,
                refill_tokens_per_second: 1,
            },
            route_bucket: TokenBucketLimits {
                capacity: 4,
                refill_tokens_per_second: 1,
            },
            max_source_buckets: 4,
            max_route_buckets: 4,
            bucket_idle_ttl_ms: CHALLENGE_TTL_MS,
        }
    }

    fn registry(clock: Arc<ManualClock>, limits: ChallengeLimits) -> ChallengeRegistry {
        ChallengeRegistry::new(RelayServerId::from_bytes([9; 16]), clock, limits)
            .unwrap_or_else(|error| panic!("test limits must be valid: {}", error.code))
    }

    #[test]
    fn expiry_boundary_and_replay_are_one_shot() {
        let clock = Arc::new(ManualClock::default());
        let registry = registry(clock.clone(), limits());
        registry.issue(id(1), source(1)).expect("issue");
        clock.set(CHALLENGE_TTL_MS - 1);
        registry
            .consume(id(1), source(1), route(1))
            .expect("29,999 ms remains valid");
        assert_eq!(
            registry
                .consume(id(1), source(1), route(1))
                .expect_err("second consume is replay")
                .code,
            RELAY_AUTH_REPLAY
        );

        clock.set(50_000);
        registry.issue(id(2), source(1)).expect("issue");
        clock.set(50_000 + CHALLENGE_TTL_MS);
        let stats = registry.stats().expect("cleanup stats");
        assert_eq!(stats.pending, 0);
        assert_eq!(stats.expired_tombstones, 1);
        assert_eq!(
            registry
                .consume(id(2), source(1), route(1))
                .expect_err("30 seconds is expired")
                .code,
            RELAY_AUTH_CHALLENGE_EXPIRED
        );

        clock.set(100_000);
        registry.issue(id(3), source(1)).expect("issue");
        clock.set(100_000 + CHALLENGE_TTL_MS);
        registry.stats().expect("move to expired tombstone");
        assert_eq!(
            registry
                .consume(id(3), source(2), route(1))
                .expect_err("expired tombstone remains source-bound")
                .code,
            RELAY_AUTH_REPLAY
        );
        assert_eq!(
            registry
                .consume(id(3), source(1), route(1))
                .expect_err("wrong-source attempt burns tombstone")
                .code,
            RELAY_AUTH_REPLAY
        );
    }

    #[test]
    fn concurrent_double_consume_has_exactly_one_winner() {
        let clock = Arc::new(ManualClock::default());
        let registry = Arc::new(registry(clock, limits()));
        registry.issue(id(1), source(1)).expect("issue");
        let barrier = Arc::new(Barrier::new(3));
        let mut threads = Vec::new();
        for _ in 0..2 {
            let registry = registry.clone();
            let barrier = barrier.clone();
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                registry.consume(id(1), source(1), route(1))
            }));
        }
        barrier.wait();
        let outcomes: Vec<_> = threads
            .into_iter()
            .map(|thread| thread.join().expect("consumer thread"))
            .collect();
        assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
        assert_eq!(
            outcomes
                .iter()
                .filter_map(|outcome| outcome.as_ref().err())
                .filter(|error| error.code == RELAY_AUTH_REPLAY)
                .count(),
            1
        );
    }

    #[test]
    fn capacity_collision_and_source_route_buckets_are_bounded() {
        let clock = Arc::new(ManualClock::default());
        let mut custom = limits();
        custom.max_pending = 2;
        custom.source_bucket.capacity = 1;
        custom.route_bucket.capacity = 1;
        let registry = registry(clock.clone(), custom);
        registry
            .issue(id(1), source(1))
            .expect("first source token");
        assert_eq!(
            registry
                .issue(id(2), source(1))
                .expect_err("source burst exhausted")
                .code,
            RELAY_QUOTA_EXCEEDED
        );
        assert_eq!(
            registry
                .issue(id(1), source(2))
                .expect_err("connection collision")
                .code,
            RELAY_AUTH_REPLAY
        );
        clock.set(1_000);
        registry.issue(id(2), source(1)).expect("source refilled");
        registry
            .consume(id(1), source(1), route(1))
            .expect("first route token");
        assert_eq!(
            registry
                .consume(id(2), source(1), route(1))
                .expect_err("route burst exhausted")
                .code,
            RELAY_QUOTA_EXCEEDED
        );
        let stats = registry.stats().expect("stats");
        assert!(stats.source_buckets <= custom.max_source_buckets);
        assert!(stats.route_buckets <= custom.max_route_buckets);
    }

    #[test]
    fn expiry_and_idle_cleanup_release_all_hard_bounds() {
        let clock = Arc::new(ManualClock::default());
        let mut custom = limits();
        custom.max_pending = 1;
        custom.max_source_buckets = 1;
        let registry = registry(clock.clone(), custom);
        registry.issue(id(1), source(1)).expect("fills bounds");
        assert_eq!(
            registry
                .issue(id(2), source(2))
                .expect_err("pending full")
                .code,
            RELAY_QUOTA_EXCEEDED
        );
        clock.set(CHALLENGE_TTL_MS);
        registry
            .issue(id(2), source(2))
            .expect("expired pending and idle bucket release bounds");
        let stats = registry.stats().expect("stats");
        assert_eq!(stats.pending, 1);
        assert_eq!(stats.source_buckets, 1);
    }

    #[test]
    fn idle_route_bucket_is_cleaned_before_new_route_capacity_check() {
        let clock = Arc::new(ManualClock::default());
        let mut custom = limits();
        custom.route_bucket.capacity = 1;
        custom.max_route_buckets = 1;
        custom.bucket_idle_ttl_ms = CHALLENGE_TTL_MS;
        let registry = registry(clock.clone(), custom);
        registry.issue(id(1), source(1)).expect("issue first");
        registry
            .consume(id(1), source(1), route(1))
            .expect("create route A bucket");
        clock.set(1);
        registry.issue(id(2), source(1)).expect("issue second");
        clock.set(CHALLENGE_TTL_MS);
        registry
            .consume(id(2), source(1), route(2))
            .expect("idle route A bucket is removed before route B admission");
        let stats = registry.stats().expect("stats");
        assert_eq!(stats.route_buckets, 1);
    }

    #[test]
    fn idle_bucket_ttl_cannot_be_configured_unbounded() {
        let clock = Arc::new(ManualClock::default());
        let mut custom = limits();
        custom.bucket_idle_ttl_ms = MAX_CHALLENGE_BUCKET_IDLE_TTL_MS + 1;
        assert_eq!(
            ChallengeRegistry::new(RelayServerId::from_bytes([9; 16]), clock, custom)
                .expect_err("oversize idle TTL")
                .code,
            RELAY_QUOTA_EXCEEDED
        );
    }

    #[test]
    fn debug_output_redacts_source_route_and_nonce() {
        let clock = Arc::new(ManualClock::default());
        let registry = registry(clock, limits());
        registry.issue(id(1), source(0xaa)).expect("issue");
        let consumed = registry
            .consume(id(1), source(0xaa), route(0xbb))
            .expect("consume");
        let rendered = format!("{registry:?} {consumed:?} {:?}", source(0xaa));
        assert!(!rendered.contains(&"aa".repeat(32)));
        assert!(!rendered.contains(&"bb".repeat(16)));
        assert!(!rendered.contains(&format!("{:?}", consumed.challenge().challenge_nonce)));
    }
}
