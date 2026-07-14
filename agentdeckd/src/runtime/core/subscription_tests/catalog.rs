use super::*;

#[tokio::test]
async fn catalog_null_request_freezes_fresh_source_and_releases_one_shot_resources() {
    let root = TestRoot::new("catalog-null-one-shot");
    let core = core(&root).await;
    core.recover().await.expect("recover core");
    let (connection, mut receiver) = connect_recording(&core, 0x78).await;

    for index in 0..32 {
        let snapshot = request_catalog_page(
            &core,
            connection,
            &mut receiver,
            &format!("catalog-null-{index}"),
            None,
        )
        .await;
        assert_eq!(snapshot.base_catalog_cursor, StreamCursor::BeforeFirst);
        assert!(snapshot.entries().is_empty());
        assert!(snapshot.next_page_cursor().is_none());
        assert_eq!(
            core.subscriptions.catalog_resource_usage_for_test(),
            (
                0,
                crate::runtime::catalog_snapshot::ONE_SHOT_CATALOG_BARRIERS,
            ),
            "one-shot request leaked decoded memory or barrier quota"
        );
    }

    core.disconnect(connection).await;
    let (shutdown_connection, mut shutdown_receiver) = connect_recording(&core, 0x81).await;
    core.handle_envelope(
        shutdown_connection,
        catalog_request_envelope("catalog-shutdown-unflushed", None),
    )
    .await
    .expect("start shutdown catalog job");
    let shutdown_held = timeout(Duration::from_secs(5), shutdown_receiver.recv())
        .await
        .expect("shutdown catalog write timeout")
        .expect("shutdown catalog write");
    assert!(matches!(
        decode(&shutdown_held).body,
        RuntimeMessage::Reply(RuntimeReply::Catalog(_))
    ));
    timeout(Duration::from_secs(2), core.shutdown())
        .await
        .expect("shutdown must cancel unflushed catalog job")
        .expect("shutdown core");
    drop(shutdown_held);
    assert_eq!(
        core.subscriptions
            .catalog_metrics_for_test()
            .expect("post-shutdown catalog metrics"),
        (0, 0)
    );
    assert_eq!(
        core.subscriptions.catalog_resource_usage_for_test(),
        (
            0,
            crate::runtime::catalog_snapshot::ONE_SHOT_CATALOG_BARRIERS,
        ),
        "shutdown must release every catalog job resource"
    );
}

#[tokio::test]
async fn direct_catalog_handle_is_rejected_before_large_dto_can_escape() {
    let root = TestRoot::new("catalog-direct-handle-invalid");
    let core = core(&root).await;
    core.recover().await.expect("recover core");
    let (connection, _receiver) = connect_recording(&core, 0x7B).await;

    let reply = core
        .handle(
            connection,
            RuntimeRequest::Catalog(CatalogRequest { page_cursor: None }),
        )
        .await;
    assert!(matches!(
        reply,
        RuntimeReply::Failure(failure)
            if failure.code == agentdeck_protocol::runtime::failure::DAEMON_RUNTIME_INVALID_REQUEST
    ));
    assert_eq!(
        core.subscriptions
            .catalog_metrics_for_test()
            .expect("catalog metrics"),
        (0, 0)
    );

    core.disconnect(connection).await;
    core.shutdown().await.expect("shutdown core");
}

#[tokio::test]
async fn catalog_one_shot_quotas_reject_before_spawning_or_building() {
    let root = TestRoot::new("catalog-one-shot-quotas");
    let core = core(&root).await;
    core.recover().await.expect("recover core");

    let (global_connection, mut global_receiver) = connect_recording(&core, 0x7C).await;
    let held_global = core.subscriptions.exhaust_catalog_global_quota_for_test();
    core.handle_envelope(
        global_connection,
        catalog_request_envelope("catalog-global-full", None),
    )
    .await
    .expect("global quota rejection is a directed failure");
    let failure = timeout(Duration::from_secs(2), global_receiver.recv())
        .await
        .expect("global quota failure timeout")
        .expect("global quota failure");
    assert!(matches!(
        decode(&failure).body,
        RuntimeMessage::Reply(RuntimeReply::Failure(_))
    ));
    failure.acknowledge().expect("flush global quota failure");
    assert_eq!(
        core.subscriptions
            .catalog_metrics_for_test()
            .expect("global quota metrics"),
        (0, 0),
        "global rejection must not spawn a job or retain per-connection admission"
    );
    assert_eq!(
        core.subscriptions.catalog_resource_usage_for_test(),
        (0, 0),
        "global rejection must not build a barrier/page"
    );
    drop(held_global);
    assert_eq!(
        core.subscriptions.catalog_resource_usage_for_test(),
        (
            0,
            crate::runtime::catalog_snapshot::ONE_SHOT_CATALOG_BARRIERS,
        )
    );

    let (connection, mut receiver) = connect_recording(&core, 0x7D).await;
    core.handle_envelope(connection, catalog_request_envelope("catalog-held", None))
        .await
        .expect("reserve shared catalog sender");
    assert_eq!(
        core.subscriptions
            .catalog_metrics_for_test()
            .expect("held catalog metrics"),
        (1, 1)
    );
    let permits_before_rejection = core.subscriptions.catalog_resource_usage_for_test().1;
    core.handle_envelope(
        connection,
        catalog_request_envelope("catalog-per-connection-full", None),
    )
    .await
    .expect("per-connection quota rejection is a directed failure");
    assert_eq!(
        core.subscriptions
            .catalog_metrics_for_test()
            .expect("post-rejection catalog metrics"),
        (1, 1),
        "second request must hit the shared one-sender/connection cap before spawning"
    );
    assert_eq!(
        core.subscriptions.catalog_resource_usage_for_test().1,
        permits_before_rejection,
        "shared sender rejection must happen before provider quota reservation"
    );
    let held_write = timeout(Duration::from_secs(2), receiver.recv())
        .await
        .expect("held catalog write timeout")
        .expect("held catalog write");
    timeout(Duration::from_secs(2), core.disconnect(connection))
        .await
        .expect("disconnect must cancel all held one-shot jobs");
    drop(held_write);
    wait_catalog_jobs_idle(&core).await;
    assert_eq!(
        core.subscriptions.catalog_resource_usage_for_test(),
        (
            0,
            crate::runtime::catalog_snapshot::ONE_SHOT_CATALOG_BARRIERS,
        ),
        "disconnect must release page memory and every global permit"
    );

    core.disconnect(global_connection).await;
    core.shutdown().await.expect("shutdown core");
}

#[tokio::test]
async fn disconnect_admission_fence_prevents_post_disconnect_catalog_spawn() {
    let root = TestRoot::new("catalog-disconnect-admission-race");
    let core = core(&root).await;
    core.recover().await.expect("recover core");
    let (connection, _receiver) = connect_recording(&core, 0x82).await;
    let held = core
        .subscriptions
        .hold_coordination_gate_for_test(connection)
        .await;

    let disconnect_core = core.clone();
    let disconnect = tokio::spawn(async move {
        disconnect_core.disconnect(connection).await;
    });
    tokio::task::yield_now().await;
    let request_core = core.clone();
    let request = tokio::spawn(async move {
        request_core
            .handle_envelope(
                connection,
                catalog_request_envelope("catalog-after-disconnect-fence", None),
            )
            .await
    });
    tokio::task::yield_now().await;
    assert_eq!(
        core.subscriptions
            .catalog_metrics_for_test()
            .expect("pending admission metrics"),
        (0, 0),
        "waiting coordination admission must not reserve quota or spawn"
    );
    drop(held);
    timeout(Duration::from_secs(2), disconnect)
        .await
        .expect("disconnect race timeout")
        .expect("disconnect task");
    let request_result = timeout(Duration::from_secs(2), request)
        .await
        .expect("post-disconnect request timeout")
        .expect("request task");
    assert!(request_result.is_err());
    assert_eq!(
        core.subscriptions
            .catalog_metrics_for_test()
            .expect("post-disconnect catalog metrics"),
        (0, 0)
    );
    assert_eq!(
        core.subscriptions.catalog_resource_usage_for_test(),
        (
            0,
            crate::runtime::catalog_snapshot::ONE_SHOT_CATALOG_BARRIERS,
        )
    );
    core.shutdown().await.expect("shutdown core");
}

#[tokio::test]
async fn unacked_catalog_frame_deadline_fail_closes_without_terminal_reply() {
    let root = TestRoot::new("catalog-unacked-deadline-close");
    let core = core(&root).await;
    core.recover().await.expect("recover core");
    core.subscriptions
        .set_barrier_ttl_for_test(Duration::from_millis(20));
    let (connection, mut receiver) = connect_recording(&core, 0x83).await;
    core.handle_envelope(
        connection,
        catalog_request_envelope("catalog-unacked-deadline", None),
    )
    .await
    .expect("start deadline catalog job");
    let held = timeout(Duration::from_secs(2), receiver.recv())
        .await
        .expect("catalog frame timeout")
        .expect("catalog frame");
    assert!(matches!(
        decode(&held).body,
        RuntimeMessage::Reply(RuntimeReply::Catalog(_))
    ));
    timeout(Duration::from_secs(2), async {
        loop {
            if core.connections.principal(connection).is_err() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("unacked committed frame must fail-close at deadline");
    assert!(
        receiver.try_recv().is_err(),
        "deadline after a committed frame must not enqueue a second Failure"
    );
    drop(held);
    wait_catalog_jobs_idle(&core).await;
    core.shutdown().await.expect("shutdown core");
}

#[tokio::test]
async fn unacked_sync_complete_deadline_fail_closes_without_terminal_reply() {
    let root = TestRoot::new("sync-unacked-deadline-close");
    let core = core(&root).await;
    core.recover().await.expect("recover core");
    core.subscriptions
        .set_barrier_ttl_for_test(Duration::from_millis(20));
    let (connection, mut receiver) = connect_recording(&core, 0x84).await;
    core.handle_envelope(connection, backfill_envelope("sync-unacked-deadline"))
        .await
        .expect("start deadline backfill job");
    let held = timeout(Duration::from_secs(2), receiver.recv())
        .await
        .expect("SyncComplete frame timeout")
        .expect("SyncComplete frame");
    assert!(matches!(
        decode(&held).body,
        RuntimeMessage::Reply(RuntimeReply::SyncComplete(_))
    ));
    timeout(Duration::from_secs(2), async {
        loop {
            if core.connections.principal(connection).is_err() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("unacked SyncComplete must fail-close at deadline");
    assert!(
        receiver.try_recv().is_err(),
        "pump must not append Failure after a committed SyncComplete"
    );
    drop(held);
    timeout(Duration::from_secs(2), async {
        loop {
            if core
                .subscriptions
                .metrics_for_test()
                .expect("subscription metrics")
                == (0, 0, 0, 0)
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("fail-close cascade must remove the subscription job");
    core.shutdown().await.expect("shutdown core");
}

#[tokio::test]
async fn large_catalog_request_uses_tracked_paced_transfer_until_flush_or_disconnect() {
    let root = TestRoot::new("catalog-large-paced-egress");
    let core = core(&root).await;
    core.recover().await.expect("recover core");
    for index in 0..2 {
        core.store
            .create_conversation(large_catalog_conversation(index))
            .await
            .expect("create large catalog row");
    }
    let (connection, mut receiver) = connect_recording(&core, 0x7E).await;

    timeout(
        Duration::from_secs(2),
        core.handle_envelope(
            connection,
            catalog_request_envelope("catalog-large-transfer", None),
        ),
    )
    .await
    .expect("handle_envelope must return without waiting for socket ACK")
    .expect("start large catalog job");

    let mut payload = Vec::new();
    let mut next_index = 0_u32;
    let mut part_count = None;
    loop {
        let write = timeout(Duration::from_secs(5), receiver.recv())
            .await
            .expect("catalog TransferPart timeout")
            .expect("catalog TransferPart");
        let envelope = decode(&write);
        assert_eq!(envelope.message_id.as_str(), "catalog-large-transfer");
        let RuntimeMessage::Reply(RuntimeReply::TransferPart(part)) = envelope.body else {
            panic!("large catalog must use production TransferPart egress");
        };
        assert_eq!(part.part_index, next_index);
        assert_eq!(*part_count.get_or_insert(part.part_count), part.part_count);
        assert!(part.part_count > 1);
        if next_index == 0 {
            assert_eq!(
                core.subscriptions
                    .catalog_metrics_for_test()
                    .expect("active large catalog metrics"),
                (1, 1)
            );
            let (memory, permits) = core.subscriptions.catalog_resource_usage_for_test();
            assert!(memory > 0, "page memory must remain charged until flush");
            assert_eq!(
                permits,
                crate::runtime::catalog_snapshot::ONE_SHOT_CATALOG_BARRIERS - 1
            );
        }
        payload.extend_from_slice(&part.part);
        assert!(
            receiver.try_recv().is_err(),
            "next TransferPart must not overtake the current FlushReceipt"
        );
        write.acknowledge().expect("flush catalog TransferPart");
        next_index += 1;
        if next_index == part.part_count {
            break;
        }
    }
    assert!(payload.len() > MAX_RUNTIME_JSON_FRAME_BYTES);
    let snapshot: agentdeck_protocol::runtime::CatalogSnapshot =
        serde_json::from_slice(&payload).expect("decode reassembled catalog snapshot");
    assert_eq!(snapshot.entries().len(), 2);
    wait_catalog_jobs_idle(&core).await;
    assert_eq!(
        core.subscriptions.catalog_resource_usage_for_test(),
        (
            0,
            crate::runtime::catalog_snapshot::ONE_SHOT_CATALOG_BARRIERS,
        )
    );

    let (cancelled_connection, mut cancelled_receiver) = connect_recording(&core, 0x7F).await;
    core.handle_envelope(
        cancelled_connection,
        catalog_request_envelope("catalog-large-disconnect", None),
    )
    .await
    .expect("start disconnect catalog job");
    let held = timeout(Duration::from_secs(5), cancelled_receiver.recv())
        .await
        .expect("disconnect TransferPart timeout")
        .expect("disconnect TransferPart");
    assert!(matches!(
        decode(&held).body,
        RuntimeMessage::Reply(RuntimeReply::TransferPart(_))
    ));
    let (memory, permits) = core.subscriptions.catalog_resource_usage_for_test();
    assert!(memory > 0);
    assert_eq!(
        permits,
        crate::runtime::catalog_snapshot::ONE_SHOT_CATALOG_BARRIERS - 1
    );
    timeout(
        Duration::from_secs(2),
        core.disconnect(cancelled_connection),
    )
    .await
    .expect("disconnect must cancel an unflushed TransferPart without waiting for ACK");
    drop(held);
    wait_catalog_jobs_idle(&core).await;
    assert_eq!(
        core.subscriptions.catalog_resource_usage_for_test(),
        (
            0,
            crate::runtime::catalog_snapshot::ONE_SHOT_CATALOG_BARRIERS,
        ),
        "disconnect must release memory, permit, and tracked job"
    );

    let (failed_connection, mut failed_receiver) = connect_recording(&core, 0x80).await;
    core.handle_envelope(
        failed_connection,
        RuntimeEnvelope {
            version: RUNTIME_PROTOCOL_VERSION,
            message_id: MessageId::new("catalog-live-sibling"),
            body: RuntimeMessage::Request(RuntimeRequest::Backfill(BackfillRequest::Catalog {
                after: StreamCursor::At(1),
            })),
        },
    )
    .await
    .expect("start live sibling subscription");
    let sibling_sync = timeout(Duration::from_secs(2), failed_receiver.recv())
        .await
        .expect("sibling SyncComplete timeout")
        .expect("sibling SyncComplete");
    assert!(matches!(
        decode(&sibling_sync).body,
        RuntimeMessage::Reply(RuntimeReply::SyncComplete(_))
    ));
    sibling_sync.acknowledge().expect("flush sibling sync");
    core.handle_envelope(
        failed_connection,
        catalog_request_envelope("catalog-large-partial-failure", None),
    )
    .await
    .expect("start partial-failure catalog job");
    let first = timeout(Duration::from_secs(5), failed_receiver.recv())
        .await
        .expect("partial-failure first part timeout")
        .expect("partial-failure first part");
    assert!(matches!(
        decode(&first).body,
        RuntimeMessage::Reply(RuntimeReply::TransferPart(ref part)) if part.part_index == 0
    ));
    first.acknowledge().expect("flush first visible part");
    let second = timeout(Duration::from_secs(5), failed_receiver.recv())
        .await
        .expect("partial-failure second part timeout")
        .expect("partial-failure second part");
    assert!(matches!(
        decode(&second).body,
        RuntimeMessage::Reply(RuntimeReply::TransferPart(ref part)) if part.part_index == 1
    ));
    drop(second);
    wait_catalog_jobs_idle(&core).await;
    timeout(Duration::from_secs(2), async {
        loop {
            if core
                .subscriptions
                .metrics_for_test()
                .expect("sibling subscription metrics")
                == (0, 0, 0, 0)
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("fail-close must cancel sibling live subscription/watch");
    assert!(
        core.connections.principal(failed_connection).is_err(),
        "failure after one flushed part must fail-close the connection"
    );
    assert_eq!(
        core.subscriptions.catalog_resource_usage_for_test(),
        (
            0,
            crate::runtime::catalog_snapshot::ONE_SHOT_CATALOG_BARRIERS,
        ),
        "partial transfer failure must release page memory and quota"
    );

    core.disconnect(connection).await;
    core.shutdown().await.expect("shutdown core");
}

#[tokio::test]
async fn small_catalog_refresh_succeeds_beside_exact_old_cursor_cache() {
    let root = TestRoot::new("catalog-cursor-concurrent-refresh");
    let core = core(&root).await;
    core.recover().await.expect("recover core");
    let (connection, mut receiver) = connect_recording(&core, 0x79).await;
    create_indexed_catalog_rows(&core, 0, 501).await;

    let first =
        request_catalog_page(&core, connection, &mut receiver, "catalog-old-first", None).await;
    assert_eq!(first.base_catalog_cursor, StreamCursor::At(500));
    let old_cursor = first
        .next_page_cursor()
        .cloned()
        .expect("501 rows require old second-page cursor");

    create_indexed_catalog_rows(&core, 501, 1).await;
    let refreshed = request_catalog_page(
        &core,
        connection,
        &mut receiver,
        "catalog-refresh-small",
        None,
    )
    .await;
    assert_eq!(refreshed.base_catalog_cursor, StreamCursor::At(501));
    assert_eq!(refreshed.entries().len(), 500);
    assert!(refreshed.next_page_cursor().is_some());
    let (retained_cache, permits) = core.subscriptions.catalog_resource_usage_for_test();
    assert!(
        retained_cache > 0,
        "old exact cursor cache must remain readable"
    );
    assert_eq!(
        permits,
        crate::runtime::catalog_snapshot::ONE_SHOT_CATALOG_BARRIERS
    );

    let old_second = request_catalog_page(
        &core,
        connection,
        &mut receiver,
        "catalog-old-second",
        Some(old_cursor),
    )
    .await;
    assert_eq!(old_second.base_catalog_cursor, StreamCursor::At(500));
    assert_eq!(old_second.entries().len(), 1);
    assert!(old_second.next_page_cursor().is_none());

    core.disconnect(connection).await;
    core.shutdown().await.expect("shutdown core");
}

#[tokio::test]
async fn catalog_and_conversation_share_one_global_snapshot_build_budget() {
    let root = TestRoot::new("catalog-conversation-shared-build-budget");
    let core = core(&root).await;
    core.recover().await.expect("recover core");
    let held = core.subscriptions.exhaust_snapshot_budget_for_test().await;
    let (connection, mut receiver) = connect_recording(&core, 0x87).await;

    core.handle_envelope(
        connection,
        catalog_request_envelope("catalog-shared-budget-overload", None),
    )
    .await
    .expect("start catalog request against held conversation budget");
    let failure = timeout(Duration::from_secs(2), receiver.recv())
        .await
        .expect("shared budget failure timeout")
        .expect("shared budget failure");
    assert!(matches!(
        decode(&failure).body,
        RuntimeMessage::Reply(RuntimeReply::Failure(_))
    ));
    failure.acknowledge().expect("flush shared budget failure");
    wait_catalog_jobs_idle(&core).await;

    drop(held);
    let recovered = request_catalog_page(
        &core,
        connection,
        &mut receiver,
        "catalog-shared-budget-released",
        None,
    )
    .await;
    assert_eq!(recovered.base_catalog_cursor, StreamCursor::BeforeFirst);
    assert!(recovered.entries().is_empty());

    core.disconnect(connection).await;
    core.shutdown().await.expect("shutdown core");
}

#[tokio::test]
async fn small_catalog_cache_does_not_starve_small_conversation_snapshot() {
    let root = TestRoot::new("small-catalog-cache-small-conversation");
    let core = core(&root).await;
    core.recover().await.expect("recover core");
    let conversation_id = indexed_catalog_conversation(0).conversation_id;
    create_indexed_catalog_rows(&core, 0, 501).await;
    let (catalog_connection, mut catalog_receiver) = connect_recording(&core, 0x88).await;
    let first = request_catalog_page(
        &core,
        catalog_connection,
        &mut catalog_receiver,
        "small-cache-first-page",
        None,
    )
    .await;
    assert!(first.next_page_cursor().is_some());
    let (cached_bytes, _) = core.subscriptions.catalog_resource_usage_for_test();
    assert!(
        cached_bytes > 0,
        "fixture must retain an exact cursor cache"
    );

    let (snapshot_connection, mut snapshot_receiver) = connect_recording(&core, 0x89).await;
    core.handle_envelope(
        snapshot_connection,
        subscribe_conversation_envelope("small-conversation-snapshot", conversation_id),
    )
    .await
    .expect("start small conversation snapshot beside catalog cache");
    let receipt = timeout(Duration::from_secs(2), snapshot_receiver.recv())
        .await
        .expect("small snapshot receipt timeout")
        .expect("small snapshot receipt");
    assert!(matches!(
        decode(&receipt).body,
        RuntimeMessage::Reply(RuntimeReply::Subscription(
            SubscriptionReceipt::Subscribed { .. }
        ))
    ));
    receipt.acknowledge().expect("flush small snapshot receipt");

    let snapshot = timeout(Duration::from_secs(2), snapshot_receiver.recv())
        .await
        .expect("small snapshot must not wait for cursor TTL")
        .expect("small snapshot reply");
    assert!(matches!(
        decode(&snapshot).body,
        RuntimeMessage::Reply(RuntimeReply::Snapshot(ref snapshot)) if snapshot.items().len() == 1
    ));
    snapshot.acknowledge().expect("flush small snapshot");
    let sync = timeout(Duration::from_secs(2), snapshot_receiver.recv())
        .await
        .expect("small snapshot SyncComplete timeout")
        .expect("small snapshot SyncComplete");
    assert!(matches!(
        decode(&sync).body,
        RuntimeMessage::Reply(RuntimeReply::SyncComplete(_))
    ));
    sync.acknowledge()
        .expect("flush small snapshot SyncComplete");
    assert_eq!(
        core.subscriptions.snapshot_budget_available_for_test(),
        crate::runtime::snapshot::SNAPSHOT_BUILD_MEMORY_BYTES - cached_bytes,
        "conversation egress must return only its own variable reservation"
    );

    core.disconnect(catalog_connection).await;
    core.disconnect(snapshot_connection).await;
    core.shutdown().await.expect("shutdown core");
}

#[tokio::test]
async fn catalog_cache_plus_full_conversation_bound_expires_without_budget_leak() {
    let root = TestRoot::new("catalog-cache-full-conversation-bound");
    let core = core(&root).await;
    core.recover().await.expect("recover core");
    let conversation_id = indexed_catalog_conversation(0).conversation_id;
    create_indexed_catalog_rows(&core, 0, 501).await;
    for index in 501..591 {
        core.store
            .create_conversation(large_catalog_conversation(index))
            .await
            .expect("create large catalog cache row");
    }
    store_ready_snapshot_with_text_bytes(&core, conversation_id, 39 * 1024 * 1024).await;
    let (catalog_connection, mut catalog_receiver) = connect_recording(&core, 0x8A).await;
    // 该 fixture 会真实构造并认证约 54 MiB cursor cache；不能沿用小页 2 秒
    // 交互 timeout，也不能缩小数据后把组合峰值冒充成已覆盖。
    let first = request_catalog_page_with_timeout(
        &core,
        catalog_connection,
        &mut catalog_receiver,
        "combined-bound-catalog-page",
        None,
        Duration::from_secs(120),
    )
    .await;
    assert!(first.next_page_cursor().is_some());
    let (cached_bytes, _) = core.subscriptions.catalog_resource_usage_for_test();
    assert!(
        cached_bytes > 48 * 1024 * 1024,
        "fixture must retain a genuinely large catalog cache, got {cached_bytes} bytes"
    );
    assert!(
        cached_bytes + 2 * 39 * 1024 * 1024 > crate::runtime::snapshot::SNAPSHOT_BUILD_MEMORY_BYTES,
        "catalog cache plus typed+payload lower bound must exceed the shared cap"
    );
    let available_before = core.subscriptions.snapshot_budget_available_for_test();
    assert_eq!(
        available_before,
        crate::runtime::snapshot::SNAPSHOT_BUILD_MEMORY_BYTES - cached_bytes
    );

    core.subscriptions
        .set_barrier_ttl_for_test(Duration::from_millis(20));
    let (snapshot_connection, mut snapshot_receiver) = connect_recording(&core, 0x8B).await;
    core.handle_envelope(
        snapshot_connection,
        subscribe_conversation_envelope("combined-bound-large-snapshot", conversation_id),
    )
    .await
    .expect("start full-bound conversation snapshot");
    let receipt = timeout(Duration::from_secs(2), snapshot_receiver.recv())
        .await
        .expect("combined-bound receipt timeout")
        .expect("combined-bound receipt");
    receipt.acknowledge().expect("flush combined-bound receipt");
    let failure = timeout(Duration::from_secs(2), snapshot_receiver.recv())
        .await
        .expect("combined-bound typed expiry timeout")
        .expect("combined-bound typed expiry");
    assert!(matches!(
        decode(&failure).body,
        RuntimeMessage::Reply(RuntimeReply::Failure(_))
    ));
    failure.acknowledge().expect("flush combined-bound failure");
    assert_eq!(
        core.subscriptions.snapshot_budget_available_for_test(),
        available_before,
        "expired variable reservation leaked shared permits"
    );
    assert!(
        core.store
            .load_conversation_snapshot(conversation_id)
            .await
            .expect("ready snapshot remains readable after typed expiry")
            .is_some()
    );

    core.disconnect(catalog_connection).await;
    core.disconnect(snapshot_connection).await;
    core.shutdown().await.expect("shutdown core");
}
