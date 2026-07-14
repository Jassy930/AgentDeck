use super::*;

use std::sync::{Condvar, Mutex as StdMutex};

use crate::runtime::store::{RuntimeStoreFaultInjector, RuntimeStoreOperation};

#[derive(Default)]
struct BlockingSubscriptionSnapshotFault {
    state: StdMutex<BlockingSubscriptionSnapshotState>,
    changed: Condvar,
}

#[derive(Default)]
struct BlockingSubscriptionSnapshotState {
    reached: bool,
    released: bool,
}

impl BlockingSubscriptionSnapshotFault {
    fn wait_until_reached(&self) {
        let mut state = self.state.lock().expect("lock subscription snapshot fault");
        while !state.reached {
            state = self
                .changed
                .wait(state)
                .expect("wait for subscription snapshot fault");
        }
    }

    fn release(&self) {
        let mut state = self
            .state
            .lock()
            .expect("lock subscription snapshot release");
        state.released = true;
        self.changed.notify_all();
    }
}

impl RuntimeStoreFaultInjector for BlockingSubscriptionSnapshotFault {
    fn before_operation(&self, operation: RuntimeStoreOperation) -> Result<(), RuntimeStoreError> {
        if operation != RuntimeStoreOperation::StoreSnapshotBeforeCommit {
            return Ok(());
        }
        let mut state = self.state.lock().map_err(|_| {
            RuntimeStoreError::InvalidConfig("subscription snapshot fault poisoned")
        })?;
        state.reached = true;
        self.changed.notify_all();
        while !state.released {
            state = self.changed.wait(state).map_err(|_| {
                RuntimeStoreError::InvalidConfig("subscription snapshot wait poisoned")
            })?;
        }
        Err(RuntimeStoreError::InvalidConfig(
            "injected subscription snapshot retry",
        ))
    }
}

#[tokio::test]
async fn disconnecting_snapshot_build_keeps_shared_budget_until_store_command_finishes() {
    let root = TestRoot::new("subscription-cancelled-snapshot-store-budget");
    let command_id = RuntimeId::from_bytes(RuntimeIdKind::Command, [0x96; 16]).expect("command id");
    let turn_id = RuntimeId::from_bytes(RuntimeIdKind::Turn, [0x97; 16]).expect("turn id");
    let event_id = RuntimeId::from_bytes(RuntimeIdKind::Event, [0x98; 16]).expect("event id");
    let fault = Arc::new(BlockingSubscriptionSnapshotFault::default());
    let store = RuntimeStoreHandle::open(
        crate::runtime::store::RuntimeStoreConfig::new(root.path.join("runtime.db"))
            .with_command_capacity(1_024)
            .with_id_source(SequenceIdSource::new([command_id, turn_id, event_id]))
            .with_fault_injector(fault.clone()),
        root.kek(),
    )
    .await
    .expect("open cancelled snapshot store budget store");
    let router = Arc::new(AgentRouter::with_runtime_store(store.clone()));
    let core = Arc::new(
        RuntimeCore::new(store, router, [0xA1; 32])
            .expect("construct cancelled snapshot store budget core"),
    );
    core.recover()
        .await
        .expect("recover cancelled snapshot store budget core");
    let full_snapshot_budget = core.subscriptions.snapshot_budget_available_for_test();

    let input = catalog_conversation(0x99);
    let conversation_id = input.conversation_id;
    core.store
        .create_conversation(input)
        .await
        .expect("create cancelled snapshot store conversation");
    append_large_snapshot_event(
        &core,
        conversation_id,
        command_id,
        turn_id,
        event_id,
        0x9A,
        2 * MAX_JSON_PART_BYTES,
    )
    .await;

    let (connection, mut receiver) = connect_recording(&core, 0x9B).await;
    core.handle_envelope(
        connection,
        subscribe_conversation_envelope("cancelled-snapshot-store-budget", conversation_id),
    )
    .await
    .expect("install cancelled snapshot store subscription");
    let subscribed = timeout(Duration::from_secs(2), receiver.recv())
        .await
        .expect("cancelled snapshot store subscribed timeout")
        .expect("cancelled snapshot store subscribed receipt");
    assert!(matches!(
        decode(&subscribed).body,
        RuntimeMessage::Reply(RuntimeReply::Subscription(
            SubscriptionReceipt::Subscribed { .. }
        ))
    ));
    subscribed
        .acknowledge()
        .expect("flush cancelled snapshot store subscription receipt");

    let wait_fault = fault.clone();
    timeout(
        Duration::from_secs(30),
        tokio::task::spawn_blocking(move || wait_fault.wait_until_reached()),
    )
    .await
    .expect("snapshot store command must reach blocked pre-COMMIT fault")
    .expect("join cancelled snapshot store fault waiter");
    let available_while_blocked = core.subscriptions.snapshot_budget_available_for_test();
    assert!(
        available_while_blocked < full_snapshot_budget,
        "blocked Store command must correspond to an occupied shared build budget"
    );

    core.disconnect(connection).await;
    timeout(Duration::from_secs(2), async {
        loop {
            if core
                .subscriptions
                .metrics_for_test()
                .expect("cancelled snapshot store subscription metrics")
                == (0, 0, 0, 0)
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("disconnect must cancel the caller-side snapshot job");

    // 威胁场景：connection 断开会 drop 等待 Store reply 的 future，但 blocking
    // worker 已拥有同一大 payload；若共享 permit 跟随 caller 提前释放，第二次 build
    // 可在第一条命令仍执行时重复占用同一 128 MiB 额度并导致进程内存越界。
    assert_eq!(
        core.subscriptions.snapshot_budget_available_for_test(),
        available_while_blocked,
        "caller cancellation must not release the permit owned by the queued Store command"
    );

    fault.release();
    timeout(Duration::from_secs(2), async {
        loop {
            let pin_count = core
                .store
                .active_snapshot_build_pin_count_for_test()
                .await
                .expect("count snapshot build pins after cancelled Store completion");
            if pin_count == 0
                && core.subscriptions.snapshot_budget_available_for_test() == full_snapshot_budget
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("worker completion must release the shared build budget and TEMP pin");

    core.shutdown()
        .await
        .expect("shutdown cancelled snapshot store budget core");
}

#[tokio::test]
async fn unacked_snapshot_store_failure_drops_retry_payload_and_build_pin_before_terminal_flush() {
    let root = TestRoot::new("subscription-snapshot-store-error-compaction");
    let command_id = RuntimeId::from_bytes(RuntimeIdKind::Command, [0x91; 16]).expect("command id");
    let turn_id = RuntimeId::from_bytes(RuntimeIdKind::Turn, [0x92; 16]).expect("turn id");
    let event_id = RuntimeId::from_bytes(RuntimeIdKind::Event, [0x93; 16]).expect("event id");
    let fault = Arc::new(BlockingSubscriptionSnapshotFault::default());
    let store = RuntimeStoreHandle::open(
        crate::runtime::store::RuntimeStoreConfig::new(root.path.join("runtime.db"))
            .with_command_capacity(1_024)
            .with_id_source(SequenceIdSource::new([command_id, turn_id, event_id]))
            .with_fault_injector(fault.clone()),
        root.kek(),
    )
    .await
    .expect("open snapshot store-error compaction store");
    let router = Arc::new(AgentRouter::with_runtime_store(store.clone()));
    let core = Arc::new(
        RuntimeCore::new(store, router, [0xA1; 32])
            .expect("construct snapshot store-error compaction core"),
    );
    core.recover()
        .await
        .expect("recover snapshot store-error compaction core");
    let full_snapshot_budget = core.subscriptions.snapshot_budget_available_for_test();

    let input = catalog_conversation(0x90);
    let conversation_id = input.conversation_id;
    core.store
        .create_conversation(input)
        .await
        .expect("create snapshot store-error conversation");
    append_large_snapshot_event(
        &core,
        conversation_id,
        command_id,
        turn_id,
        event_id,
        0x94,
        2 * MAX_JSON_PART_BYTES,
    )
    .await;

    let (connection, mut receiver) = connect_recording(&core, 0x95).await;
    core.handle_envelope(
        connection,
        subscribe_conversation_envelope("snapshot-store-error-compaction", conversation_id),
    )
    .await
    .expect("install snapshot store-error subscription");
    let subscribed = timeout(Duration::from_secs(2), receiver.recv())
        .await
        .expect("snapshot store-error subscribed timeout")
        .expect("snapshot store-error subscribed receipt");
    assert!(matches!(
        decode(&subscribed).body,
        RuntimeMessage::Reply(RuntimeReply::Subscription(
            SubscriptionReceipt::Subscribed { .. }
        ))
    ));
    subscribed
        .acknowledge()
        .expect("flush snapshot store-error subscription receipt");

    let wait_fault = fault.clone();
    timeout(
        Duration::from_secs(30),
        tokio::task::spawn_blocking(move || wait_fault.wait_until_reached()),
    )
    .await
    .expect("snapshot store command must reach injected pre-COMMIT fault")
    .expect("join snapshot store fault waiter");
    fault.release();

    let failure = timeout(Duration::from_secs(2), receiver.recv())
        .await
        .expect("snapshot store-error terminal timeout")
        .expect("snapshot store-error terminal failure");
    assert!(matches!(
        decode(&failure).body,
        RuntimeMessage::Reply(RuntimeReply::Failure(_))
    ));

    // 威胁场景：Store error 若把 exact retry write 留在 PumpError 中，慢 writer
    // 不 ACK terminal frame 时会无限期保留数 MiB payload、TEMP pin 与构建预算。
    // terminal frame 可继续等待，但重试 payload/pin/permit 必须在进入该等待前释放。
    timeout(Duration::from_secs(2), async {
        loop {
            let pin_count = core
                .store
                .active_snapshot_build_pin_count_for_test()
                .await
                .expect("count active snapshot build pins after store failure");
            if pin_count == 0
                && core.subscriptions.snapshot_budget_available_for_test() == full_snapshot_budget
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("retry payload, TEMP pin, and build budget must release before terminal ACK");

    assert_ne!(
        core.subscriptions
            .metrics_for_test()
            .expect("subscription metrics while terminal frame is unacked"),
        (0, 0, 0, 0),
        "terminal writer wait must still own the subscription job"
    );
    failure
        .acknowledge()
        .expect("flush snapshot store-error terminal failure");
    timeout(Duration::from_secs(2), async {
        loop {
            if core
                .subscriptions
                .metrics_for_test()
                .expect("snapshot store-error subscription metrics")
                == (0, 0, 0, 0)
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("snapshot store-error job must self-clean after terminal ACK");

    core.disconnect(connection).await;
    core.shutdown()
        .await
        .expect("shutdown snapshot store-error compaction core");
}

#[tokio::test]
async fn resubscribe_cancels_unacked_terminal_failure_without_fail_closing_connection() {
    let root = TestRoot::new("subscription-terminal-resubscribe-cancel");
    let core = core(&root).await;
    core.recover()
        .await
        .expect("recover terminal-resubscribe core");
    core.subscriptions
        .set_barrier_ttl_for_test(Duration::from_millis(20));
    let held_budget = core.subscriptions.exhaust_snapshot_budget_for_test().await;

    let input = catalog_conversation(0xA2);
    let conversation_id = input.conversation_id;
    core.store
        .create_conversation(input)
        .await
        .expect("create terminal-resubscribe conversation");
    let (connection, mut receiver) = connect_recording(&core, 0xA3).await;
    core.handle_envelope(
        connection,
        subscribe_conversation_envelope("terminal-before-resubscribe", conversation_id),
    )
    .await
    .expect("install expiring subscription");
    let subscribed = timeout(Duration::from_secs(2), receiver.recv())
        .await
        .expect("expiring subscription receipt timeout")
        .expect("expiring subscription receipt");
    subscribed
        .acknowledge()
        .expect("flush expiring subscription receipt");

    let terminal = timeout(Duration::from_secs(2), receiver.recv())
        .await
        .expect("terminal failure timeout")
        .expect("terminal failure");
    assert!(matches!(
        decode(&terminal).body,
        RuntimeMessage::Reply(RuntimeReply::Failure(_))
    ));
    timeout(Duration::from_secs(2), async {
        loop {
            if core
                .subscriptions
                .metrics_for_test()
                .expect("terminal-resubscribe metrics")
                == (0, 0, 0, 1)
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("terminal wait releases registry quotas");
    drop(held_budget);
    core.subscriptions
        .set_barrier_ttl_for_test(Duration::from_secs(5 * 60));

    timeout(
        Duration::from_secs(2),
        core.handle_envelope(
            connection,
            subscribe_conversation_envelope("replacement-after-terminal", conversation_id),
        ),
    )
    .await
    .expect("resubscribe cancels the old terminal wait")
    .expect("replacement generation remains connected");
    assert!(
        core.connections.principal(connection).is_ok(),
        "canceling the old terminal writer wait must not fail-close the connection"
    );
    assert!(
        receiver.try_recv().is_err(),
        "replacement receipt cannot overtake the already committed terminal frame"
    );

    terminal
        .acknowledge()
        .expect("drain canceled old terminal frame");
    let replacement = timeout(Duration::from_secs(2), receiver.recv())
        .await
        .expect("replacement receipt timeout")
        .expect("replacement receipt");
    assert!(matches!(
        decode(&replacement).body,
        RuntimeMessage::Reply(RuntimeReply::Subscription(
            SubscriptionReceipt::Subscribed { .. }
        ))
    ));
    replacement
        .acknowledge()
        .expect("flush replacement receipt");

    let snapshot = timeout(Duration::from_secs(2), receiver.recv())
        .await
        .expect("replacement snapshot timeout")
        .expect("replacement snapshot");
    assert!(matches!(
        decode(&snapshot).body,
        RuntimeMessage::Reply(RuntimeReply::Snapshot(_))
    ));
    snapshot.acknowledge().expect("flush replacement snapshot");
    let sync = timeout(Duration::from_secs(2), receiver.recv())
        .await
        .expect("replacement sync timeout")
        .expect("replacement sync");
    assert!(matches!(
        decode(&sync).body,
        RuntimeMessage::Reply(RuntimeReply::SyncComplete(_))
    ));
    sync.acknowledge().expect("flush replacement sync");

    core.disconnect(connection).await;
    core.shutdown()
        .await
        .expect("shutdown terminal-resubscribe core");
}
