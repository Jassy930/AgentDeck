//! Crash-safe sender counter block reconciliation（发送 counter block 对账）纯状态机。

/// 每次全有或全无预留的 sender counter 数量。
pub const COUNTER_BLOCK_SIZE: u64 = 1_024;

/// 连续 sender counter 区间，表示为 `[start, end_exclusive)`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CounterReservation {
    pub start: u64,
    pub end_exclusive: u64,
}

/// 对账 Keychain guard 与 DB high-water 后的 fail-closed 结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CounterReconcile {
    Usable(CounterReservation),
    DbRollback,
    EpochRetirementRequired,
}

/// 对账两个 exclusive counter high-water，并提议下一个完整 block。
///
/// 本函数不执行 IO。只有调用方先把 `end_exclusive` 持久化到 guard、再持久化到 DB 后，
/// 返回的 reservation 才可消费。
pub fn reconcile_counter_block(guard_high_water: u64, db_high_water: u64) -> CounterReconcile {
    match db_high_water.cmp(&guard_high_water) {
        std::cmp::Ordering::Less => CounterReconcile::DbRollback,
        std::cmp::Ordering::Greater => CounterReconcile::EpochRetirementRequired,
        std::cmp::Ordering::Equal => match guard_high_water.checked_add(COUNTER_BLOCK_SIZE) {
            Some(end_exclusive) => CounterReconcile::Usable(CounterReservation {
                start: guard_high_water,
                end_exclusive,
            }),
            None => CounterReconcile::EpochRetirementRequired,
        },
    }
}
