use super::*;
use crate::runtime::store::{RuntimeId, RuntimeIdKind};
fn connection(seed: u8) -> ConnectionId {
    ConnectionId::from_test_bytes([seed; 16])
}
fn target(seed: u8) -> RuntimeStreamTarget {
    RuntimeStreamTarget::Conversation(
        RuntimeId::from_bytes(RuntimeIdKind::Conversation, [seed; 16])
            .expect("nonzero conversation id"),
    )
}
fn small_limits() -> Limits {
    Limits {
        live_per_connection: 2,
        live_global: 3,
        barriers_per_connection: 1,
        barriers_global: 2,
        snapshot_senders_per_connection: 1,
        snapshot_senders_global: 1,
        barrier_ttl_ms: 10,
    }
}
fn assert_usage(registry: &SubscriptionRegistry, expected: Usage, connections: usize) {
    assert_eq!(
        registry.metrics().expect("read registry metrics"),
        (expected, connections)
    );
}
#[test]
fn production_limits_match_the_frozen_resource_contract() {
    let _production_registry = SubscriptionRegistry::new();
    assert_eq!(MAX_LIVE_SUBSCRIPTIONS_PER_CONNECTION, 64);
    assert_eq!(MAX_LIVE_SUBSCRIPTIONS_GLOBAL, 4_096);
    assert_eq!(MAX_ACTIVE_BARRIERS_PER_CONNECTION, 4);
    assert_eq!(MAX_ACTIVE_BARRIERS_GLOBAL, 128);
    assert_eq!(MAX_SNAPSHOT_SENDERS_PER_CONNECTION, 1);
    assert_eq!(MAX_SNAPSHOT_SENDERS_GLOBAL, 2);
    assert_eq!(SUBSCRIPTION_BARRIER_TTL_MS, 5 * 60 * 1_000);
    assert_eq!(
        check_limits(
            Usage {
                live: 3,
                ..Usage::default()
            },
            Usage::default(),
            small_limits(),
        ),
        Err(SubscriptionRegistryError::Overloaded("connection live"))
    );
    assert_eq!(
        check_limits(
            Usage::default(),
            Usage {
                barriers: 3,
                ..Usage::default()
            },
            small_limits(),
        ),
        Err(SubscriptionRegistryError::Overloaded("global barrier"))
    );
    assert_eq!(
        Usage {
            live: usize::MAX,
            ..Usage::default()
        }
        .checked_replace(Usage::default(), Usage::subscription(false)),
        Err(SubscriptionRegistryError::AccountingOverflow)
    );
}

#[test]
fn subscription_and_barrier_quotas_fail_before_spawning_tasks() {
    let registry = SubscriptionRegistry::with_limits(small_limits());
    let first = registry
        .reserve(connection(1), target(1), false, 0)
        .expect("first barrier");
    assert_usage(
        &registry,
        Usage {
            live: 1,
            barriers: 1,
            snapshot_senders: 0,
        },
        1,
    );
    assert!(matches!(
        registry.reserve(connection(1), target(2), false, 0),
        Err(SubscriptionRegistryError::Overloaded("connection barrier"))
    ));
    assert!(!first.is_cancelled());
    assert_usage(
        &registry,
        Usage {
            live: 1,
            barriers: 1,
            snapshot_senders: 0,
        },
        1,
    );

    registry
        .complete_barrier(&first, 1)
        .expect("release first barrier");
    let second = registry
        .reserve(connection(1), target(2), true, 1)
        .expect("one snapshot sender");
    assert!(matches!(
        registry.reserve(connection(2), target(3), true, 1),
        Err(SubscriptionRegistryError::Overloaded(
            "global snapshot sender"
        ))
    ));
    assert_usage(
        &registry,
        Usage {
            live: 2,
            barriers: 1,
            snapshot_senders: 1,
        },
        1,
    );

    assert!(
        registry
            .release_snapshot_sender(&second, 2)
            .expect("release snapshot sender before barrier")
    );
    assert_eq!(
        registry.admit_live_enqueue(&second, 2),
        Err(SubscriptionRegistryError::BarrierActive),
        "释放 snapshot sender 不得提前放行 live enqueue"
    );
    assert_usage(
        &registry,
        Usage {
            live: 2,
            barriers: 1,
            snapshot_senders: 0,
        },
        1,
    );
    registry
        .complete_barrier(&second, 2)
        .expect("release second barrier");
    let third = registry
        .reserve(connection(2), target(3), false, 2)
        .expect("reach global live cap");
    assert!(matches!(
        registry.reserve(connection(3), target(4), false, 2),
        Err(SubscriptionRegistryError::Overloaded("global live"))
    ));
    assert!(!third.is_cancelled());
    assert_usage(
        &registry,
        Usage {
            live: 3,
            barriers: 1,
            snapshot_senders: 0,
        },
        2,
    );
}

#[test]
fn transient_catalog_and_live_subscriptions_share_barrier_and_sender_limits() {
    let registry = SubscriptionRegistry::with_limits(small_limits());
    let transient = registry
        .reserve_transient(connection(1), true, true, 0)
        .expect("reserve catalog barrier and sender");
    assert_usage(
        &registry,
        Usage {
            live: 0,
            barriers: 1,
            snapshot_senders: 1,
        },
        0,
    );
    assert!(matches!(
        registry.reserve(connection(1), target(1), false, 0),
        Err(SubscriptionRegistryError::Overloaded("connection barrier"))
    ));
    assert!(matches!(
        registry.reserve_transient(connection(2), false, true, 0),
        Err(SubscriptionRegistryError::Overloaded(
            "global snapshot sender"
        ))
    ));
    drop(transient);
    let live = registry
        .reserve(connection(1), target(1), true, 1)
        .expect("live sender after transient drop");
    assert!(matches!(
        registry.reserve_transient(connection(2), true, true, 1),
        Err(SubscriptionRegistryError::Overloaded(
            "global snapshot sender"
        ))
    ));
    assert!(registry.disconnect(connection(1)).expect("disconnect live"));
    drop(live);
    assert_usage(&registry, Usage::default(), 0);
}

#[test]
fn registry_stale_generation_cannot_mutate_resubscribe_replacement() {
    let registry = SubscriptionRegistry::with_limits(Limits {
        barriers_per_connection: 2,
        ..small_limits()
    });
    let mut old = registry
        .reserve(connection(1), target(1), false, 0)
        .expect("old generation");
    let current = registry
        .reserve(connection(1), target(1), true, 1)
        .expect("atomic replacement");
    assert_ne!(old.generation(), current.generation());
    assert!(old.is_cancelled());
    assert!(!current.is_cancelled());
    assert_eq!(
        registry.admit_live_enqueue(&old, 1),
        Err(SubscriptionRegistryError::StaleGeneration)
    );
    assert_eq!(
        registry.complete_barrier(&old, 1),
        Err(SubscriptionRegistryError::StaleGeneration)
    );
    assert!(!old.release().expect("stale cleanup is idempotent"));
    assert_eq!(
        registry.admit_live_enqueue(&current, 1),
        Err(SubscriptionRegistryError::BarrierActive)
    );
    assert!(
        registry
            .complete_barrier(&current, 2)
            .expect("sync complete")
    );
    assert!(
        !registry
            .complete_barrier(&current, 2)
            .expect("idempotent completion")
    );
    assert_eq!(
        registry
            .admit_live_enqueue(&current, 2)
            .expect("current live enqueue"),
        current.generation()
    );
    assert_usage(
        &registry,
        Usage {
            live: 1,
            barriers: 0,
            snapshot_senders: 0,
        },
        1,
    );
}

#[test]
fn failed_resubscribe_preserves_the_old_generation_and_its_budgets() {
    let registry = SubscriptionRegistry::with_limits(Limits {
        barriers_per_connection: 3,
        ..small_limits()
    });
    let old = registry
        .reserve(connection(1), target(1), false, 0)
        .expect("old generation");
    let snapshot = registry
        .reserve(connection(1), target(2), true, 0)
        .expect("occupy connection snapshot sender");
    assert!(matches!(
        registry.reserve(connection(1), target(1), true, 1),
        Err(SubscriptionRegistryError::Overloaded(
            "connection snapshot sender"
        ))
    ));
    assert!(!old.is_cancelled());
    assert!(!snapshot.is_cancelled());
    assert!(
        registry
            .complete_barrier(&old, 1)
            .expect("old remains current")
    );
}

#[test]
fn barrier_ttl_cancels_snapshot_and_releases_every_budget() {
    let registry = SubscriptionRegistry::with_limits(small_limits());
    let expired = registry
        .reserve(connection(1), target(1), true, 100)
        .expect("expiring barrier");
    assert_eq!(registry.expire(109).expect("before boundary"), 0);
    assert!(!expired.is_cancelled());
    assert_eq!(registry.expire(110).expect("exact boundary"), 1);
    assert!(expired.is_cancelled());
    assert_eq!(registry.expire(110).expect("idempotent expiry"), 0);
    assert_usage(&registry, Usage::default(), 0);

    let live = registry
        .reserve(connection(1), target(2), false, 200)
        .expect("live subscription");
    registry
        .complete_barrier(&live, 201)
        .expect("complete live barrier");
    assert_eq!(registry.expire(10_000).expect("no live TTL"), 0);
    assert_eq!(
        registry
            .admit_live_enqueue(&live, 10_000)
            .expect("live remains current"),
        live.generation()
    );
}

#[test]
fn clock_regression_and_deadline_overflow_are_typed_without_partial_reserve() {
    let registry = SubscriptionRegistry::with_limits(small_limits());
    let lease = registry
        .reserve(connection(1), target(1), false, 50)
        .expect("establish clock");
    let retained = registry.metrics().expect("retained metrics");
    assert_eq!(
        registry.expire(49),
        Err(SubscriptionRegistryError::ClockRegressed {
            previous_ms: 50,
            observed_ms: 49,
        })
    );
    assert_eq!(registry.metrics().expect("unchanged metrics"), retained);
    assert!(!lease.is_cancelled());
    assert!(matches!(
        registry.reserve(
            connection(2),
            target(2),
            false,
            u64::MAX - small_limits().barrier_ttl_ms + 1,
        ),
        Err(SubscriptionRegistryError::TimeOutOfRange)
    ));
    assert_eq!(registry.metrics().expect("no partial reserve"), retained);
}

#[test]
fn unsubscribe_disconnect_drop_and_generation_exhaustion_cleanup_are_idempotent() {
    let registry = SubscriptionRegistry::with_limits(Limits {
        barriers_per_connection: 4,
        ..small_limits()
    });
    let first = registry
        .reserve(connection(1), target(1), false, 0)
        .expect("first target");
    assert!(
        registry
            .unsubscribe(connection(1), target(1))
            .expect("unsubscribe")
    );
    assert!(
        !registry
            .unsubscribe(connection(1), target(1))
            .expect("repeat unsubscribe")
    );
    assert!(first.is_cancelled());
    assert_usage(&registry, Usage::default(), 0);

    {
        let _dropped = registry
            .reserve(connection(1), target(1), false, 1)
            .expect("drop cleanup");
    }
    assert_usage(&registry, Usage::default(), 0);

    let second = registry
        .reserve(connection(1), target(1), false, 2)
        .expect("disconnect first");
    let third = registry
        .reserve(connection(1), target(2), false, 2)
        .expect("disconnect second");
    assert!(registry.disconnect(connection(1)).expect("disconnect"));
    assert!(
        !registry
            .disconnect(connection(1))
            .expect("repeat disconnect")
    );
    assert!(second.is_cancelled());
    assert!(third.is_cancelled());
    assert_usage(&registry, Usage::default(), 0);

    registry
        .inner
        .state
        .lock()
        .expect("generation state")
        .next_generation = u64::MAX;
    assert!(matches!(
        registry.reserve(connection(2), target(3), false, 3),
        Err(SubscriptionRegistryError::GenerationExhausted)
    ));
    assert_usage(&registry, Usage::default(), 0);
}
