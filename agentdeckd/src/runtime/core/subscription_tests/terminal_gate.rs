use super::*;

struct TerminalGateFixture {
    _root: TestRoot,
    core: Arc<RuntimeCore>,
    held_budget: tokio::sync::OwnedSemaphorePermit,
    connection: ConnectionId,
    receiver: mpsc::Receiver<crate::runtime::ConnectionWrite>,
    failure: crate::runtime::ConnectionWrite,
}

async fn terminal_gate_fixture(label: &str, seed: u8) -> TerminalGateFixture {
    let root = TestRoot::new(label);
    let core = core(&root).await;
    core.recover().await.expect("recover core");
    core.subscriptions
        .set_barrier_ttl_for_test(Duration::from_millis(200));
    let held_budget = core.subscriptions.exhaust_snapshot_budget_for_test().await;
    let (connection, mut receiver) = connect_recording(&core, seed).await;
    let input = catalog_conversation(seed.wrapping_add(1));
    let conversation_id = input.conversation_id;
    core.store
        .create_conversation(input)
        .await
        .expect("create terminal gate conversation");

    let expiring = core
        .subscriptions
        .prepare(
            connection,
            MessageId::new(format!("{label}-failure")),
            crate::runtime::events::RuntimeStreamTarget::Conversation(conversation_id),
            crate::runtime::backfill::BarrierRequest::Subscribe {
                cursor: StreamCursor::BeforeFirst,
            },
            false,
        )
        .await
        .expect("prepare expiring snapshot target");
    expiring.commit().await.expect("publish expiring target");
    // 让第一个 job 取得 egress gate 并真实阻塞在 snapshot budget；commit 本身
    // 已经返回，不能把 Core operation 绑在这个 gate 上。
    for _ in 0..4 {
        tokio::task::yield_now().await;
    }

    core.subscriptions
        .set_barrier_ttl_for_test(Duration::from_secs(5));
    let sibling = core
        .subscriptions
        .prepare(
            connection,
            MessageId::new(format!("{label}-sibling")),
            crate::runtime::events::RuntimeStreamTarget::Catalog,
            crate::runtime::backfill::BarrierRequest::Backfill {
                after: StreamCursor::At(0),
            },
            false,
        )
        .await
        .expect("prepare immediate sibling target");
    timeout(Duration::from_secs(2), sibling.commit())
        .await
        .expect("sibling commit waited on socket gate")
        .expect("publish sibling target");

    let failure = timeout(Duration::from_secs(2), receiver.recv())
        .await
        .expect("terminal gate failure timeout")
        .expect("terminal gate failure");
    let failure_envelope = decode(&failure);
    assert_eq!(
        failure_envelope.message_id.as_str(),
        format!("{label}-failure")
    );
    assert!(matches!(
        failure_envelope.body,
        RuntimeMessage::Reply(RuntimeReply::Failure(_))
    ));
    assert!(
        receiver.try_recv().is_err(),
        "sibling dequeued a frame before terminal Failure flush ACK"
    );
    assert!(
        core.connections.principal(connection).is_ok(),
        "paced reservation contention incorrectly fail-closed the connection"
    );

    TerminalGateFixture {
        _root: root,
        core,
        held_budget,
        connection,
        receiver,
        failure,
    }
}

#[tokio::test]
async fn terminal_failure_gate_disconnects_without_lock_cycle() {
    // 威胁场景：恶意客户端不 ACK terminal Failure，同时提交另一 target；
    // disconnect 必须找到并取消两个已登记 job，不能形成 coordination/egress 锁环。
    let TerminalGateFixture {
        _root,
        core,
        held_budget,
        connection,
        receiver: _,
        failure,
    } = terminal_gate_fixture("terminal-gate-disconnect", 0x7A).await;

    timeout(Duration::from_secs(2), core.disconnect(connection))
        .await
        .expect("disconnect deadlocked behind terminal and sibling gates");
    assert_eq!(
        core.subscriptions
            .metrics_for_test()
            .expect("subscription metrics after disconnect"),
        (0, 0, 0, 0),
        "disconnect must reap terminal and sibling subscription state"
    );
    drop(failure);
    drop(held_budget);
    core.shutdown().await.expect("shutdown core");
}

#[tokio::test]
async fn pending_sibling_unsubscribe_and_shutdown_do_not_wait_for_terminal_ack() {
    // 威胁场景：terminal target A 持有 egress gate且拒绝 ACK，target B 已提交但
    // 尚未取得 gate；Unsubscribe(B) 与 Core shutdown 都必须通过 jobs map 精确取消，
    // 不能依赖 A 的 ACK，也不能让 handle_envelope operation 卡住 shutdown。
    let TerminalGateFixture {
        _root,
        core,
        held_budget,
        connection,
        mut receiver,
        failure,
    } = terminal_gate_fixture("terminal-gate-unsubscribe", 0x7B).await;

    assert!(
        timeout(
            Duration::from_secs(2),
            core.subscriptions.unsubscribe(
                connection,
                crate::runtime::events::RuntimeStreamTarget::Catalog,
            ),
        )
        .await
        .expect("unsubscribe waited for sibling terminal gate")
        .expect("unsubscribe pending sibling"),
        "pending sibling lease must still be current before unsubscribe"
    );
    assert_eq!(
        core.subscriptions
            .metrics_for_test()
            .expect("subscription metrics after unsubscribe"),
        (0, 0, 0, 1),
        "only the unacknowledged terminal writer job may remain"
    );
    assert!(
        receiver.try_recv().is_err(),
        "unsubscribed sibling emitted a late frame"
    );

    timeout(Duration::from_secs(2), core.shutdown())
        .await
        .expect("shutdown waited for terminal ACK")
        .expect("shutdown core");
    assert_eq!(
        core.subscriptions
            .metrics_for_test()
            .expect("subscription metrics after shutdown"),
        (0, 0, 0, 0)
    );
    drop(failure);
    drop(held_budget);
}

#[tokio::test]
async fn terminal_gate_same_target_replacements_publish_only_latest_generation() {
    // 威胁场景：terminal target 持 gate 时同一 sibling target 连续 resubscribe；
    // 被替换的后台 job 必须保持可取消、可 join，不能在 gate 释放后发布迟到 receipt。
    let TerminalGateFixture {
        _root,
        core,
        held_budget,
        connection,
        mut receiver,
        failure,
    } = terminal_gate_fixture("terminal-gate-replacement", 0x7C).await;

    for message in ["replacement-stale", "replacement-current"] {
        let replacement = core
            .subscriptions
            .prepare(
                connection,
                MessageId::new(message),
                crate::runtime::events::RuntimeStreamTarget::Catalog,
                crate::runtime::backfill::BarrierRequest::Backfill {
                    after: StreamCursor::At(0),
                },
                true,
            )
            .await
            .expect("prepare replacement generation");
        timeout(Duration::from_secs(2), replacement.commit())
            .await
            .expect("replacement commit waited on terminal gate")
            .expect("publish replacement generation");
    }
    assert!(
        receiver.try_recv().is_err(),
        "replacement overtook unacknowledged terminal Failure"
    );

    failure
        .acknowledge()
        .expect("flush terminal replacement gate");
    let receipt = timeout(Duration::from_secs(2), receiver.recv())
        .await
        .expect("latest replacement receipt timeout")
        .expect("latest replacement receipt");
    let receipt_envelope = decode(&receipt);
    assert_eq!(receipt_envelope.message_id.as_str(), "replacement-current");
    assert!(matches!(
        receipt_envelope.body,
        RuntimeMessage::Reply(RuntimeReply::Subscription(
            SubscriptionReceipt::Subscribed { .. }
        ))
    ));
    receipt
        .acknowledge()
        .expect("flush latest replacement receipt");

    let sync = timeout(Duration::from_secs(2), receiver.recv())
        .await
        .expect("latest replacement SyncComplete timeout")
        .expect("latest replacement SyncComplete");
    let sync_envelope = decode(&sync);
    assert_eq!(sync_envelope.message_id.as_str(), "replacement-current");
    assert!(matches!(
        sync_envelope.body,
        RuntimeMessage::Reply(RuntimeReply::SyncComplete(_))
    ));
    sync.acknowledge()
        .expect("flush latest replacement SyncComplete");
    assert!(
        timeout(Duration::from_millis(100), receiver.recv())
            .await
            .is_err(),
        "stale replacement published a delayed frame"
    );

    drop(held_budget);
    core.disconnect(connection).await;
    core.shutdown().await.expect("shutdown core");
}

#[tokio::test]
async fn gate_wait_expiry_drops_snapshot_pin_before_terminal_writer_wait() {
    // 威胁场景：target A 的 terminal Failure 永不 ACK，target C 带 snapshot TEMP pin
    // 排队等同一 gate并先到 TTL；C 进入无 deadline terminal wait 前必须先丢弃整份
    // registration，否则一个慢连接可长期 pin 住 snapshot/watch 资源。
    let TerminalGateFixture {
        _root,
        core,
        held_budget,
        connection,
        mut receiver,
        failure,
    } = terminal_gate_fixture("terminal-gate-expired-pin", 0x7D).await;

    core.subscriptions
        .set_barrier_ttl_for_test(Duration::from_millis(100));
    let input = catalog_conversation(0x7E);
    let conversation_id = input.conversation_id;
    core.store
        .create_conversation(input)
        .await
        .expect("create gate-wait snapshot conversation");
    let expiring = core
        .subscriptions
        .prepare(
            connection,
            MessageId::new("gate-wait-expired-pin"),
            crate::runtime::events::RuntimeStreamTarget::Conversation(conversation_id),
            crate::runtime::backfill::BarrierRequest::Subscribe {
                cursor: StreamCursor::BeforeFirst,
            },
            false,
        )
        .await
        .expect("prepare gate-wait snapshot target");
    assert_eq!(
        core.store
            .active_snapshot_build_pin_count_for_test()
            .await
            .expect("count snapshot pin before gate wait"),
        1,
        "real barrier capture must create the TEMP pin exercised by this test"
    );
    expiring.commit().await.expect("publish gate-wait target");

    timeout(Duration::from_secs(2), async {
        loop {
            let pins = core
                .store
                .active_snapshot_build_pin_count_for_test()
                .await
                .expect("count snapshot pins after gate-wait expiry");
            let (_, _, snapshot_senders, _) = core
                .subscriptions
                .metrics_for_test()
                .expect("metrics after gate-wait expiry");
            if pins == 0 && snapshot_senders == 0 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("gate-wait expiry retained snapshot pin or sender quota");
    assert!(
        receiver.try_recv().is_err(),
        "expired sibling emitted terminal reply before owning the gate"
    );

    core.disconnect(connection).await;
    drop(failure);
    drop(held_budget);
    core.shutdown().await.expect("shutdown core");
}

#[tokio::test]
async fn pending_replacement_capture_chain_has_a_hard_pre_spawn_bound() {
    // 威胁场景：客户端在 terminal sibling 持 gate 时并发 prepare 同一 target，
    // 每份 PreparedSubscription 都会冻结 watch/source；第五份必须在 Store capture
    // 与 spawn 前失败，不能让 registry 的“只看最新 generation”隐藏无界资源链。
    let TerminalGateFixture {
        _root,
        core,
        held_budget,
        connection,
        receiver: _,
        failure,
    } = terminal_gate_fixture("terminal-gate-pending-bound", 0x7F).await;

    let mut prepared = Vec::new();
    for index in 0..3 {
        prepared.push(
            core.subscriptions
                .prepare(
                    connection,
                    MessageId::new(format!("pending-bound-{index}")),
                    crate::runtime::events::RuntimeStreamTarget::Catalog,
                    crate::runtime::backfill::BarrierRequest::Backfill {
                        after: StreamCursor::At(0),
                    },
                    false,
                )
                .await
                .expect("reserve bounded pending replacement"),
        );
    }
    assert_eq!(
        core.subscriptions
            .pending_job_usage_for_test(connection)
            .expect("pending job usage at bound"),
        (4, 4),
        "one published sibling plus three prepared replacements must fill the hard bound"
    );
    let overflow = match core
        .subscriptions
        .prepare(
            connection,
            MessageId::new("pending-bound-overflow"),
            crate::runtime::events::RuntimeStreamTarget::Catalog,
            crate::runtime::backfill::BarrierRequest::Backfill {
                after: StreamCursor::At(0),
            },
            false,
        )
        .await
    {
        Ok(_) => panic!("fifth pending capture must fail before Store registration"),
        Err(error) => error,
    };
    assert!(
        overflow.to_string().contains("connection pending job"),
        "overflow must identify the bounded pending-job resource"
    );
    assert_eq!(
        core.subscriptions
            .pending_job_usage_for_test(connection)
            .expect("pending job usage after rejection"),
        (4, 4),
        "rejected capture must not consume another permit"
    );

    drop(prepared);
    assert_eq!(
        core.subscriptions
            .pending_job_usage_for_test(connection)
            .expect("pending job usage after prepared drop"),
        (1, 1),
        "dropping uncommitted replacements must return their exact permits"
    );
    core.disconnect(connection).await;
    assert_eq!(
        core.subscriptions
            .pending_job_usage_for_test(connection)
            .expect("pending job usage after disconnect"),
        (0, 0)
    );
    drop(failure);
    drop(held_budget);
    core.shutdown().await.expect("shutdown core");
}

#[tokio::test]
async fn disconnect_wins_before_pending_slot_capture_and_stale_prepare_cannot_recreate_it() {
    // 威胁场景：prepare 已通过第一次 principal 快检，但在取得 per-connection
    // pending slot 前被 disconnect 超车；stale prepare 不能在 map removal 后新建 S2
    // 并做真实 Store capture，否则重复 disconnect 可绕过每连接 4 项硬上界。
    let root = TestRoot::new("subscription-pending-slot-disconnect-race");
    let core = core(&root).await;
    core.recover().await.expect("recover core");
    let (connection, _receiver) = connect_recording(&core, 0x80).await;
    let coordination_guard = core
        .subscriptions
        .hold_coordination_gate_for_test(connection)
        .await;

    let disconnect_core = core.clone();
    let mut disconnect = tokio::spawn(async move {
        disconnect_core.disconnect(connection).await;
    });
    for _ in 0..4 {
        tokio::task::yield_now().await;
    }
    assert!(
        timeout(Duration::from_millis(20), &mut disconnect)
            .await
            .is_err(),
        "disconnect setup did not queue on coordination gate"
    );

    let prepare_core = core.clone();
    let mut stale_prepare = tokio::spawn(async move {
        prepare_core
            .subscriptions
            .prepare(
                connection,
                MessageId::new("stale-pending-slot-prepare"),
                crate::runtime::events::RuntimeStreamTarget::Catalog,
                crate::runtime::backfill::BarrierRequest::Backfill {
                    after: StreamCursor::BeforeFirst,
                },
                false,
            )
            .await
    });
    for _ in 0..4 {
        tokio::task::yield_now().await;
    }
    drop(coordination_guard);

    timeout(Duration::from_secs(2), &mut disconnect)
        .await
        .expect("disconnect did not win coordination race")
        .expect("disconnect task");
    let stale_result = timeout(Duration::from_secs(2), &mut stale_prepare)
        .await
        .expect("stale prepare remained blocked")
        .expect("stale prepare task");
    assert!(
        stale_result.is_err(),
        "prepare after disconnect must fail principal revalidation"
    );
    assert_eq!(
        core.subscriptions
            .pending_job_usage_for_test(connection)
            .expect("pending usage after disconnect race"),
        (0, 0)
    );
    assert_eq!(
        core.subscriptions
            .pending_job_connection_slot_count_for_test()
            .expect("pending slot map after disconnect race"),
        0,
        "stale prepare must not recreate an empty per-connection semaphore entry"
    );
    core.shutdown().await.expect("shutdown core");
}
