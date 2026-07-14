use super::SubscriptionRegistryError;

pub(crate) const MAX_LIVE_SUBSCRIPTIONS_PER_CONNECTION: usize = 64;
pub(crate) const MAX_LIVE_SUBSCRIPTIONS_GLOBAL: usize = 4_096;
pub(crate) const MAX_ACTIVE_BARRIERS_PER_CONNECTION: usize = 4;
pub(crate) const MAX_ACTIVE_BARRIERS_GLOBAL: usize = 128;
// replacement job 在成为 registry-current pump 前会短暂持有旧 handle/registration；
// 复用 barrier 上限封住这段隐藏 task/source 链，而不压低 64/4,096 live 上限。
pub(crate) const MAX_PENDING_SUBSCRIPTION_JOBS_PER_CONNECTION: usize =
    MAX_ACTIVE_BARRIERS_PER_CONNECTION;
pub(crate) const MAX_PENDING_SUBSCRIPTION_JOBS_GLOBAL: usize = MAX_ACTIVE_BARRIERS_GLOBAL;
pub(crate) const MAX_SNAPSHOT_SENDERS_PER_CONNECTION: usize = 1;
pub(crate) const MAX_SNAPSHOT_SENDERS_GLOBAL: usize = 2;
pub(crate) const SUBSCRIPTION_BARRIER_TTL_MS: u64 = 5 * 60 * 1_000;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct Usage {
    pub(super) live: usize,
    pub(super) barriers: usize,
    pub(super) snapshot_senders: usize,
}

impl Usage {
    pub(super) const fn subscription(snapshot_sender: bool) -> Self {
        Self {
            live: 1,
            barriers: 1,
            snapshot_senders: snapshot_sender as usize,
        }
    }

    pub(super) const fn transient(barrier: bool, snapshot_sender: bool) -> Self {
        Self {
            live: 0,
            barriers: barrier as usize,
            snapshot_senders: snapshot_sender as usize,
        }
    }

    pub(super) fn checked_replace(
        self,
        removed: Self,
        added: Self,
    ) -> Result<Self, SubscriptionRegistryError> {
        Ok(Self {
            live: checked_replace(self.live, removed.live, added.live)?,
            barriers: checked_replace(self.barriers, removed.barriers, added.barriers)?,
            snapshot_senders: checked_replace(
                self.snapshot_senders,
                removed.snapshot_senders,
                added.snapshot_senders,
            )?,
        })
    }
}

#[derive(Clone, Copy)]
pub(super) struct Limits {
    pub(super) live_per_connection: usize,
    pub(super) live_global: usize,
    pub(super) barriers_per_connection: usize,
    pub(super) barriers_global: usize,
    pub(super) snapshot_senders_per_connection: usize,
    pub(super) snapshot_senders_global: usize,
    pub(super) barrier_ttl_ms: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            live_per_connection: MAX_LIVE_SUBSCRIPTIONS_PER_CONNECTION,
            live_global: MAX_LIVE_SUBSCRIPTIONS_GLOBAL,
            barriers_per_connection: MAX_ACTIVE_BARRIERS_PER_CONNECTION,
            barriers_global: MAX_ACTIVE_BARRIERS_GLOBAL,
            snapshot_senders_per_connection: MAX_SNAPSHOT_SENDERS_PER_CONNECTION,
            snapshot_senders_global: MAX_SNAPSHOT_SENDERS_GLOBAL,
            barrier_ttl_ms: SUBSCRIPTION_BARRIER_TTL_MS,
        }
    }
}

pub(super) fn check_limits(
    connection: Usage,
    global: Usage,
    limits: Limits,
) -> Result<(), SubscriptionRegistryError> {
    let checks = [
        (
            connection.live > limits.live_per_connection,
            "connection live",
        ),
        (global.live > limits.live_global, "global live"),
        (
            connection.barriers > limits.barriers_per_connection,
            "connection barrier",
        ),
        (global.barriers > limits.barriers_global, "global barrier"),
        (
            connection.snapshot_senders > limits.snapshot_senders_per_connection,
            "connection snapshot sender",
        ),
        (
            global.snapshot_senders > limits.snapshot_senders_global,
            "global snapshot sender",
        ),
    ];
    checks
        .into_iter()
        .find(|(over, _)| *over)
        .map_or(Ok(()), |(_, resource)| {
            Err(SubscriptionRegistryError::Overloaded(resource))
        })
}

fn checked_replace(
    value: usize,
    removed: usize,
    added: usize,
) -> Result<usize, SubscriptionRegistryError> {
    value
        .checked_sub(removed)
        .and_then(|value| value.checked_add(added))
        .ok_or(SubscriptionRegistryError::AccountingOverflow)
}
