use agentdeck_crypto::counter::{
    COUNTER_BLOCK_SIZE, CounterReconcile, CounterReservation, reconcile_counter_block,
};

#[test]
fn equal_high_waters_reserve_one_complete_block() {
    assert_eq!(
        reconcile_counter_block(0, 0),
        CounterReconcile::Usable(CounterReservation {
            start: 0,
            end_exclusive: COUNTER_BLOCK_SIZE,
        })
    );

    let high_water = 17_000;
    assert_eq!(
        reconcile_counter_block(high_water, high_water),
        CounterReconcile::Usable(CounterReservation {
            start: high_water,
            end_exclusive: high_water + COUNTER_BLOCK_SIZE,
        })
    );
}

#[test]
fn db_behind_guard_is_fail_closed_as_rollback() {
    assert_eq!(
        reconcile_counter_block(COUNTER_BLOCK_SIZE, 0),
        CounterReconcile::DbRollback
    );
}

#[test]
fn db_ahead_of_guard_requires_epoch_retirement() {
    assert_eq!(
        reconcile_counter_block(0, COUNTER_BLOCK_SIZE),
        CounterReconcile::EpochRetirementRequired
    );
}

#[test]
fn last_complete_block_before_u64_limit_is_usable() {
    let start = u64::MAX - COUNTER_BLOCK_SIZE;
    assert_eq!(
        reconcile_counter_block(start, start),
        CounterReconcile::Usable(CounterReservation {
            start,
            end_exclusive: u64::MAX,
        })
    );
}

#[test]
fn incomplete_block_near_u64_limit_requires_retirement_without_wrap() {
    for high_water in [u64::MAX - COUNTER_BLOCK_SIZE + 1, u64::MAX - 1, u64::MAX] {
        assert_eq!(
            reconcile_counter_block(high_water, high_water),
            CounterReconcile::EpochRetirementRequired,
            "high_water={high_water}"
        );
    }
}

#[test]
fn boundary_matrix_is_deterministic_and_never_panics() {
    let boundary_values = [
        0,
        1,
        COUNTER_BLOCK_SIZE - 1,
        COUNTER_BLOCK_SIZE,
        u64::MAX - COUNTER_BLOCK_SIZE,
        u64::MAX - COUNTER_BLOCK_SIZE + 1,
        u64::MAX - 1,
        u64::MAX,
    ];

    for guard in boundary_values {
        for db in boundary_values {
            let outcome = reconcile_counter_block(guard, db);
            match db.cmp(&guard) {
                std::cmp::Ordering::Less => assert_eq!(outcome, CounterReconcile::DbRollback),
                std::cmp::Ordering::Greater => {
                    assert_eq!(outcome, CounterReconcile::EpochRetirementRequired)
                }
                std::cmp::Ordering::Equal => match guard.checked_add(COUNTER_BLOCK_SIZE) {
                    Some(end_exclusive) => assert_eq!(
                        outcome,
                        CounterReconcile::Usable(CounterReservation {
                            start: guard,
                            end_exclusive,
                        })
                    ),
                    None => {
                        assert_eq!(outcome, CounterReconcile::EpochRetirementRequired)
                    }
                },
            }
        }
    }
}
