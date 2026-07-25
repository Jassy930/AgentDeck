use super::*;

use agentdeck_protocol::runtime::command::HelloParams;
use agentdeck_protocol::runtime::identity::{ConversationId, EventId, MessageId, TransferId};
use agentdeck_protocol::runtime::{
    MAX_RUNTIME_JSON_FRAME_BYTES, RUNTIME_PROTOCOL_VERSION, RuntimeEnvelope, RuntimeEvent,
    RuntimeEventBody, RuntimeFailure, RuntimeMessage, RuntimeReply, RuntimeStreamItem,
    RuntimeTransferCarrierV1, RuntimeTransferChannel, TransferEnvelope,
};

fn principal(seed: u8) -> AuthenticatedPrincipal {
    PrincipalIssuer::local_only([0xA1; 32])
        .issue_verified_local(501, [seed; 16])
        .expect("issue test local principal")
}

async fn enqueue_paced(
    registry: &ConnectionRegistry,
    id: ConnectionId,
    frame: EncodedRuntimeFrame,
) -> Result<FlushReceipt, ConnectionError> {
    let reservation = registry.reserve_paced(id, frame).await?;
    registry.commit_paced(reservation)
}

fn take_disconnect_owner(
    registry: &ConnectionRegistry,
    id: ConnectionId,
) -> tokio::task::JoinHandle<()> {
    match registry.begin_disconnect(id).expect("begin disconnect") {
        DisconnectWriter::Owner(handle) => handle,
        DisconnectWriter::Wait(_) => panic!("disconnect owner already exists"),
        DisconnectWriter::Absent => panic!("disconnect writer is absent"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn panicking_writer_reports_same_failure_to_owner_and_waiter() {
    let registry = ConnectionRegistry::new(1, 8);
    let id = ConnectionId::from_test_bytes([0x51; 16]);
    let incarnation = Arc::new(ConnectionIncarnation);
    let exit = Arc::new(WriterTaskExit::new());
    let connection_slot = registry
        .connection_slots
        .clone()
        .try_acquire_owned()
        .expect("reserve panic fixture writer slot");
    let (writer, _receiver) = mpsc::channel(1);
    let lifetime = WriterTaskLifetime {
        id,
        incarnation: incarnation.clone(),
        entries: Arc::downgrade(&registry.entries),
        tasks: Arc::downgrade(&registry.tasks),
        connection_slot: Some(connection_slot),
        exit: exit.clone(),
    };
    let (published, published_rx) = oneshot::channel();
    let (panic_now, panic_now_rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        let _lifetime = lifetime;
        published_rx.await.expect("panic fixture published");
        panic_now_rx.await.expect("panic fixture released");
        panic!("injected writer panic");
    });
    {
        let mut entries = registry.entries.lock().expect("lock connection entries");
        let mut tasks = registry.tasks.lock().expect("lock writer tasks");
        entries.insert(
            id,
            ConnectionEntry {
                incarnation: incarnation.clone(),
                principal: principal(24),
                writer,
                byte_budget: Arc::new(Semaphore::new(8)),
                frame_budget: Arc::new(Semaphore::new(1)),
                paced_reservation_slot: Arc::new(Semaphore::new(1)),
                framing_profile: ConnectionFramingProfile::JsonRuntime,
            },
        );
        tasks.insert(
            id,
            TrackedWriterTask {
                incarnation,
                handle: Some(task),
                exit,
            },
        );
    }
    published.send(()).expect("publish panic fixture");
    let owner = take_disconnect_owner(&registry, id);
    let waiter = match registry.begin_disconnect(id).expect("begin waiter") {
        DisconnectWriter::Wait(exit) => exit,
        DisconnectWriter::Owner(_) => panic!("waiter unexpectedly owns writer"),
        DisconnectWriter::Absent => panic!("panic fixture writer is absent"),
    };
    let mut disconnect_waiter = Box::pin(registry.disconnect(id));
    assert!(
        (tokio::select! {
            biased;
            result = &mut disconnect_waiter => Some(result),
            () = async {} => None,
        })
        .is_none(),
        "disconnect waiter returned before panic terminal"
    );
    let mut shutdown_waiter = Box::pin(registry.shutdown());
    assert!(
        (tokio::select! {
            biased;
            result = &mut shutdown_waiter => Some(result),
            () = async {} => None,
        })
        .is_none(),
        "shutdown waiter returned before panic terminal"
    );

    panic_now.send(()).expect("release panic fixture");
    let (owner_result, waiter_result, disconnect_result, shutdown_result) = tokio::join!(
        join_writer(owner),
        waiter.wait(),
        &mut disconnect_waiter,
        &mut shutdown_waiter
    );
    let final_entries = registry.len();
    let final_active = registry.active_writer_count();
    let final_tracked = registry.tracked_task_count();

    assert_eq!(owner_result, Err(ConnectionError::WriterTaskFailed));
    assert_eq!(waiter_result, Err(ConnectionError::WriterTaskFailed));
    assert_eq!(disconnect_result, Err(ConnectionError::WriterTaskFailed));
    assert_eq!(shutdown_result, Err(ConnectionError::WriterTaskFailed));
    assert_eq!(final_entries, 0);
    assert_eq!(final_active, 0);
    assert_eq!(final_tracked, 0);
}

#[tokio::test]
async fn connection_id_collision_check_includes_tracked_task_after_entry_removal() {
    let id = ConnectionId::from_test_bytes([0x42; 16]);
    let entries = HashMap::new();
    let incarnation = Arc::new(ConnectionIncarnation);
    let mut tasks = HashMap::new();
    tasks.insert(
        id,
        TrackedWriterTask {
            incarnation,
            handle: Some(tokio::spawn(std::future::pending())),
            exit: Arc::new(WriterTaskExit::new()),
        },
    );

    let available = connection_id_is_available(&entries, &tasks, id);
    let task = tasks.remove(&id).expect("take collision fixture task");
    let handle = task.handle.expect("collision fixture handle");
    handle.abort();
    join_writer(handle)
        .await
        .expect("join collision fixture task");

    assert!(
        !available,
        "an id with a live tracked task must remain unavailable after entry removal"
    );
}

#[tokio::test]
async fn disconnect_retains_id_tombstone_until_writer_future_exits() {
    let registry = ConnectionRegistry::new(1, 8);
    let (tx, mut rx) = mpsc::channel(1);
    let id = registry
        .connect(principal(19), ConnectionSink::new(tx))
        .expect("connect retiring writer");
    let receipt = enqueue_paced(
        &registry,
        id,
        EncodedRuntimeFrame::from_bytes(&b"retiring"[..]),
    )
    .await
    .expect("enqueue retiring write");
    let write = rx.recv().await.expect("retiring transport write");

    let task = take_disconnect_owner(&registry, id);
    let (id_available, tracked_during_retirement) = {
        let entries = registry.entries.lock().expect("lock connection entries");
        let tasks = registry.tasks.lock().expect("lock writer tasks");
        (
            connection_id_is_available(&entries, &tasks, id),
            tasks.contains_key(&id),
        )
    };

    task.abort();
    drop(write);
    drop(receipt);
    join_writer(task).await.expect("join retiring writer");
    let final_active = registry.active_writer_count();
    let final_tracked = registry.tracked_task_count();

    assert!(
        !id_available,
        "retiring writer id became reusable before its future exited"
    );
    assert!(
        tracked_during_retirement,
        "disconnect removed the tracked tombstone before writer exit"
    );
    assert_eq!(final_active, 0);
    assert_eq!(final_tracked, 0);
}

#[tokio::test]
async fn concurrent_disconnect_waits_for_retiring_writer_exit() {
    let registry = ConnectionRegistry::new(1, 8);
    let (tx, mut rx) = mpsc::channel(1);
    let id = registry
        .connect(principal(21), ConnectionSink::new(tx))
        .expect("connect concurrent-disconnect writer");
    let receipt = enqueue_paced(
        &registry,
        id,
        EncodedRuntimeFrame::from_bytes(&b"retiring"[..]),
    )
    .await
    .expect("enqueue concurrent-disconnect write");
    let write = rx
        .recv()
        .await
        .expect("concurrent-disconnect transport write");
    let owner = take_disconnect_owner(&registry, id);

    let mut follower = Box::pin(registry.disconnect(id));
    let early_follower = tokio::select! {
        biased;
        result = &mut follower => Some(result),
        () = async {} => None,
    };
    let follower_waited = early_follower.is_none();
    owner.abort();
    drop(write);
    drop(receipt);
    join_writer(owner).await.expect("join owner writer");
    match early_follower {
        Some(result) => result.expect("early follower disconnect"),
        None => follower.await.expect("follower after writer exit"),
    }
    let final_entry_count = registry.len();
    let final_active = registry.active_writer_count();
    let final_tracked = registry.tracked_task_count();

    assert!(
        follower_waited,
        "second disconnect returned before the retiring writer exited"
    );
    assert_eq!(final_entry_count, 0);
    assert_eq!(final_active, 0);
    assert_eq!(final_tracked, 0);
}

#[tokio::test]
async fn disconnect_waits_while_shutdown_owns_writer_handle() {
    let registry = ConnectionRegistry::new(1, 8);
    let (tx, mut rx) = mpsc::channel(1);
    let id = registry
        .connect(principal(22), ConnectionSink::new(tx))
        .expect("connect shutdown-owned writer");
    let receipt = enqueue_paced(
        &registry,
        id,
        EncodedRuntimeFrame::from_bytes(&b"owned"[..]),
    )
    .await
    .expect("enqueue shutdown-owned write");
    let write = rx.recv().await.expect("shutdown-owned transport write");
    registry
        .entries
        .lock()
        .expect("lock connection entries")
        .remove(&id);
    let mut claimed = registry
        .claim_writers_for_shutdown()
        .expect("claim writer for shutdown");
    assert_eq!(claimed.len(), 1);
    let owner = claimed[0]
        .handle
        .take()
        .expect("shutdown owns writer handle");

    let mut disconnect = Box::pin(registry.disconnect(id));
    let early_disconnect = tokio::select! {
        biased;
        result = &mut disconnect => Some(result),
        () = async {} => None,
    };
    let disconnect_waited = early_disconnect.is_none();
    owner.abort();
    drop(write);
    drop(receipt);
    join_writer(owner)
        .await
        .expect("join shutdown-owned writer");
    match early_disconnect {
        Some(result) => result.expect("early shutdown-owned disconnect"),
        None => disconnect
            .await
            .expect("disconnect after shutdown-owned writer exit"),
    }
    drop(claimed);
    let final_active = registry.active_writer_count();
    let final_tracked = registry.tracked_task_count();

    assert!(
        disconnect_waited,
        "disconnect returned while shutdown still owned the live writer"
    );
    assert_eq!(final_active, 0);
    assert_eq!(final_tracked, 0);
}

#[tokio::test]
async fn second_shutdown_waits_while_first_shutdown_owns_writer_handle() {
    let registry = ConnectionRegistry::new(1, 8);
    let (tx, mut rx) = mpsc::channel(1);
    let id = registry
        .connect(principal(23), ConnectionSink::new(tx))
        .expect("connect double-shutdown writer");
    let receipt = enqueue_paced(
        &registry,
        id,
        EncodedRuntimeFrame::from_bytes(&b"owned"[..]),
    )
    .await
    .expect("enqueue double-shutdown write");
    let write = rx.recv().await.expect("double-shutdown transport write");
    registry
        .entries
        .lock()
        .expect("lock connection entries")
        .remove(&id);
    let mut claimed = registry
        .claim_writers_for_shutdown()
        .expect("first shutdown claims writer");
    let owner = claimed[0]
        .handle
        .take()
        .expect("first shutdown owns writer handle");

    let mut second_shutdown = Box::pin(registry.shutdown());
    let early_shutdown = tokio::select! {
        biased;
        result = &mut second_shutdown => Some(result),
        () = async {} => None,
    };
    let second_waited = early_shutdown.is_none();
    owner.abort();
    drop(write);
    drop(receipt);
    join_writer(owner)
        .await
        .expect("join double-shutdown writer");
    match early_shutdown {
        Some(result) => result.expect("early second shutdown"),
        None => second_shutdown.await.expect("second shutdown after exit"),
    }
    drop(claimed);

    assert!(
        second_waited,
        "second shutdown returned while the first still owned the live writer"
    );
    assert_eq!(registry.active_writer_count(), 0);
    assert_eq!(registry.tracked_task_count(), 0);
}

#[tokio::test]
async fn shutdown_waits_for_disconnect_owned_writer_exit_latch() {
    let registry = ConnectionRegistry::new(1, 8);
    let (tx, mut rx) = mpsc::channel(1);
    let id = registry
        .connect(principal(20), ConnectionSink::new(tx))
        .expect("connect shutdown-retiring writer");
    let receipt = enqueue_paced(
        &registry,
        id,
        EncodedRuntimeFrame::from_bytes(&b"retiring"[..]),
    )
    .await
    .expect("enqueue shutdown-retiring write");
    let write = rx.recv().await.expect("shutdown-retiring transport write");
    let task = take_disconnect_owner(&registry, id);

    let mut shutdown = Box::pin(registry.shutdown());
    let early_shutdown = tokio::select! {
        biased;
        result = &mut shutdown => Some(result),
        () = async {} => None,
    };
    let waited_for_exit = early_shutdown.is_none();
    task.abort();
    drop(write);
    drop(receipt);
    join_writer(task)
        .await
        .expect("join shutdown-retiring writer");
    match early_shutdown {
        Some(result) => result.expect("early shutdown result"),
        None => shutdown.await.expect("shutdown after writer exit"),
    }

    assert!(
        waited_for_exit,
        "shutdown returned before the disconnect-owned writer exited"
    );
}

#[tokio::test]
async fn paced_reservation_allows_only_one_waiter_per_connection() {
    let registry = ConnectionRegistry::new(1, 8);
    let (tx, mut rx) = mpsc::channel(1);
    let id = registry
        .connect(principal(16), ConnectionSink::new(tx))
        .expect("connect paced writer");
    let first_receipt = enqueue_paced(&registry, id, EncodedRuntimeFrame::from_bytes(&b"one"[..]))
        .await
        .expect("enqueue first paced frame");
    let first_write = rx.recv().await.expect("first transport write");

    let mut waiting =
        Box::pin(registry.reserve_paced(id, EncodedRuntimeFrame::from_bytes(&b"two"[..])));
    assert!(
        (tokio::select! {
            biased;
            result = &mut waiting => Some(result),
            () = async {} => None,
        })
        .is_none(),
        "first paced waiter must wait for the held frame budget"
    );
    let mut overflow =
        Box::pin(registry.reserve_paced(id, EncodedRuntimeFrame::from_bytes(&b"three"[..])));
    let overflow_result = tokio::select! {
        biased;
        result = &mut overflow => Some(result),
        () = async {} => None,
    };
    drop(overflow);

    first_write
        .acknowledge()
        .expect("ACK first transport flush");
    first_receipt.wait().await.expect("observe first flush ACK");
    drop(waiting.await.expect("first paced waiter obtains budget"));
    registry.shutdown().await.expect("shutdown paced writer");

    assert!(
        matches!(overflow_result, Some(Err(ConnectionError::Lagged))),
        "a second concurrent paced waiter must be rejected immediately"
    );
}

#[tokio::test]
async fn stale_paced_reservation_cannot_remove_replacement_connection_entry() {
    let registry = ConnectionRegistry::new(1, 8);
    let (tx, _rx) = mpsc::channel(1);
    let id = registry
        .connect(principal(17), ConnectionSink::new(tx))
        .expect("connect original writer");
    let reservation = registry
        .reserve_paced(id, EncodedRuntimeFrame::from_bytes(&b"stale"[..]))
        .await
        .expect("reserve against original writer");

    let task = registry
        .tasks
        .lock()
        .expect("lock writer tasks")
        .remove(&id)
        .expect("take original writer task");
    let handle = task.handle.expect("original writer handle");
    handle.abort();
    join_writer(handle).await.expect("join original writer");
    let (replacement_writer, _replacement_receiver) = mpsc::channel(1);
    registry
        .entries
        .lock()
        .expect("lock connection entries")
        .insert(
            id,
            ConnectionEntry {
                incarnation: Arc::new(ConnectionIncarnation),
                principal: principal(18),
                writer: replacement_writer,
                byte_budget: Arc::new(Semaphore::new(8)),
                frame_budget: Arc::new(Semaphore::new(1)),
                paced_reservation_slot: Arc::new(Semaphore::new(1)),
                framing_profile: ConnectionFramingProfile::JsonRuntime,
            },
        );

    assert!(registry.commit_paced(reservation).is_err());
    assert!(
        registry.principal(id).is_ok(),
        "stale reservation cleanup removed the replacement entry"
    );
    registry
        .shutdown()
        .await
        .expect("shutdown replacement registry");
}

#[test]
fn encoded_frame_contains_the_complete_runtime_envelope() {
    let envelope = RuntimeEnvelope {
        version: RUNTIME_PROTOCOL_VERSION,
        message_id: MessageId::new("message-connection-test"),
        body: RuntimeMessage::Reply(RuntimeReply::Hello(HelloParams {
            runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
        })),
    };
    let frame = EncodedRuntimeFrame::from_envelope(&envelope).expect("encode envelope");
    let decoded: RuntimeEnvelope =
        serde_json::from_slice(&frame.bytes).expect("decode complete envelope");
    assert_eq!(decoded.version, RUNTIME_PROTOCOL_VERSION);
    assert_eq!(decoded.message_id.as_str(), "message-connection-test");
    assert!(matches!(
        decoded.body,
        RuntimeMessage::Reply(RuntimeReply::Hello(HelloParams {
            runtime_protocol_version: RUNTIME_PROTOCOL_VERSION
        }))
    ));
}

#[test]
fn encoded_frame_rejects_oversized_reply_and_stream_before_writer_admission() {
    let failure = || {
        RuntimeFailure::new(
            "daemon.test.oversized",
            "x".repeat(MAX_RUNTIME_JSON_FRAME_BYTES),
        )
    };
    let reply = RuntimeEnvelope {
        version: RUNTIME_PROTOCOL_VERSION,
        message_id: MessageId::new("message-oversized-reply"),
        body: RuntimeMessage::Reply(RuntimeReply::Failure(failure())),
    };
    assert!(matches!(
        EncodedRuntimeFrame::from_envelope(&reply),
        Err(ConnectionError::FrameTooLarge)
    ));

    let event = RuntimeEvent::new(
        ConversationId::new("conversation-oversized-stream"),
        EventId::new("event-oversized-stream"),
        0,
        None,
        None,
        None,
        RuntimeEventBody::Error { failure: failure() },
    )
    .unwrap();
    let stream = RuntimeEnvelope {
        version: RUNTIME_PROTOCOL_VERSION,
        message_id: MessageId::new("message-oversized-stream"),
        body: RuntimeMessage::Stream(RuntimeStreamItem::Event(event)),
    };
    assert!(matches!(
        EncodedRuntimeFrame::from_envelope(&stream),
        Err(ConnectionError::FrameTooLarge)
    ));
}

#[tokio::test]
async fn compact_transfer_frame_is_typed_and_rejected_by_a_json_only_connection() {
    let transfer = TransferEnvelope::new(
        TransferId::new("typed-compact-transfer"),
        0,
        1,
        [0x22; 32],
        7,
        b"compact".to_vec(),
    )
    .expect("valid compact transfer");
    let carrier = RuntimeTransferCarrierV1::new(
        MessageId::new("typed-compact-message"),
        RuntimeTransferChannel::Stream,
        transfer,
    );
    let frame = EncodedRuntimeFrame::from_transfer_carrier(&carrier)
        .expect("typed carrier constructor must encode ADRT1");
    assert_eq!(frame.kind(), EncodedRuntimeFrameKind::CompactTransfer);

    let registry = ConnectionRegistry::new(1, 4 * 1024 * 1024);
    let (tx, mut rx) = mpsc::channel(1);
    let id = registry
        .connect(principal(29), ConnectionSink::new(tx))
        .expect("connect default JSON-only writer");
    assert!(matches!(
        registry.reserve_paced(id, frame).await,
        Err(ConnectionError::FramingProfileMismatch)
    ));
    assert!(rx.try_recv().is_err());
    registry.shutdown().await.expect("shutdown JSON writer");
}

#[tokio::test]
async fn paced_frames_reach_transport_only_after_the_previous_flush_ack() {
    let registry = ConnectionRegistry::new(1, 8);
    let (tx, mut rx) = mpsc::channel(2);
    let id = registry
        .connect(principal(13), ConnectionSink::new(tx))
        .expect("connect paced writer");

    let first_receipt = enqueue_paced(&registry, id, EncodedRuntimeFrame::from_bytes(&b"one"[..]))
        .await
        .expect("enqueue first paced frame");
    let first_write = rx.recv().await.expect("first transport write");
    assert_eq!(first_write.bytes(), b"one");

    let second = enqueue_paced(&registry, id, EncodedRuntimeFrame::from_bytes(&b"two"[..]));
    tokio::pin!(second);
    tokio::select! {
        biased;
        result = &mut second => panic!("second paced enqueue completed before permit release: {result:?}"),
        () = async {} => {}
    }
    assert!(matches!(
        rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));

    first_write
        .acknowledge()
        .expect("ACK first transport flush");
    first_receipt.wait().await.expect("observe first flush ACK");
    let second_receipt = second.await.expect("enqueue after first flush ACK");
    let second_write = rx.recv().await.expect("second transport write");
    assert_eq!(second_write.bytes(), b"two");
    second_write
        .acknowledge()
        .expect("ACK second transport flush");
    second_receipt
        .wait()
        .await
        .expect("observe second flush ACK");
    registry.shutdown().await.expect("shutdown paced writer");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn writer_slot_and_join_handle_survive_fail_close_until_task_return() {
    let registry = ConnectionRegistry::new(1, 8);
    let (tx, mut rx) = mpsc::channel(1);
    let id = registry
        .connect(principal(15), ConnectionSink::new(tx))
        .expect("connect paced writer");
    let receipt = enqueue_paced(&registry, id, EncodedRuntimeFrame::from_bytes(&b"lost"[..]))
        .await
        .expect("enqueue paced frame");
    let write = rx.recv().await.expect("transport write");

    // 专用 lock-holder thread 把 writer 精确卡在 future-return cleanup，避免测试
    // future 跨 await 持 std::sync::MutexGuard。writer 仍应先完成 fail-close/error phase。
    let tasks = registry.tasks.clone();
    let (locked_tx, locked_rx) = oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel(0);
    let lock_holder = std::thread::spawn(move || {
        let tasks = tasks.lock().expect("lock writer task map");
        let exit = tasks.get(&id).expect("tracked writer").exit.clone();
        assert!(
            locked_tx.send((exit, tasks.contains_key(&id))).is_ok(),
            "publish locked writer phase"
        );
        release_rx.recv().expect("release writer task map lock");
    });
    let (exit, tracked_during_fail_close) = locked_rx.await.expect("writer task map lock acquired");
    drop(write);
    let flush_result = receipt.wait().await;
    let entry_missing = matches!(registry.principal(id), Err(ConnectionError::NotFound));
    let active_during_fail_close = registry.active_writer_count();
    release_tx.send(()).expect("release writer task map lock");
    lock_holder.join().expect("join writer lock holder");

    exit.wait().await.expect("writer exits cleanly");
    let final_active = registry.active_writer_count();
    let final_tracked = registry.tracked_task_count();

    assert_eq!(flush_result, Err(ConnectionError::Lagged));
    assert!(entry_missing);
    assert_eq!(
        active_during_fail_close, 1,
        "the live writer must retain its connection slot"
    );
    assert!(
        tracked_during_fail_close,
        "shutdown must still be able to find and join the live writer"
    );
    assert_eq!(final_active, 0);
    assert_eq!(final_tracked, 0);
}

#[tokio::test]
async fn dropped_unacknowledged_paced_write_fail_closes_and_releases_connection() {
    let registry = ConnectionRegistry::new(1, 8);
    let (tx, mut rx) = mpsc::channel(1);
    let id = registry
        .connect(principal(14), ConnectionSink::new(tx))
        .expect("connect paced writer");
    let receipt = enqueue_paced(&registry, id, EncodedRuntimeFrame::from_bytes(&b"lost"[..]))
        .await
        .expect("enqueue paced frame");

    drop(rx.recv().await.expect("unacknowledged transport write"));
    assert_eq!(receipt.wait().await, Err(ConnectionError::Lagged));
    assert!(matches!(
        registry.principal(id),
        Err(ConnectionError::NotFound)
    ));
    assert_eq!(registry.active_writer_count(), 0);
    assert_eq!(registry.tracked_task_count(), 0);
}

#[tokio::test]
async fn slow_writer_is_disconnected_without_affecting_fast_writer() {
    let registry = ConnectionRegistry::new(2, 8);
    let (slow_tx, mut slow_rx) = mpsc::channel(1);
    let (fast_tx, mut fast_rx) = mpsc::channel(8);
    let slow = registry
        .connect(principal(1), ConnectionSink::new(slow_tx))
        .expect("connect slow");
    let fast = registry
        .connect(principal(2), ConnectionSink::new(fast_tx))
        .expect("connect fast");

    let mut accepted = 0_usize;
    let mut lagged = false;
    for _ in 0..16 {
        match registry.try_enqueue(slow, EncodedRuntimeFrame::from_bytes(&b"aa"[..])) {
            Ok(()) => accepted += 1,
            Err(ConnectionError::Lagged) => {
                lagged = true;
                break;
            }
            Err(other) => panic!("unexpected slow writer error: {other:?}"),
        }
        tokio::task::yield_now().await;
    }
    assert!(accepted > 0);
    assert!(lagged, "bounded slow writer must eventually lag");
    assert!(matches!(
        registry.principal(slow),
        Err(ConnectionError::NotFound)
    ));

    registry
        .try_enqueue(fast, EncodedRuntimeFrame::from_bytes(&b"ok"[..]))
        .expect("fast writer remains connected");
    let write = fast_rx.recv().await.expect("fast transport write");
    assert_eq!(write.bytes(), b"ok");
    write.acknowledge().expect("ack fast socket flush");
    drop(slow_rx.recv().await);
    registry.shutdown().await.expect("shutdown registry");
}

#[tokio::test]
async fn byte_budget_is_reserved_atomically_and_disconnect_is_idempotent() {
    let registry = Arc::new(ConnectionRegistry::new(32, 4));
    let (tx, _rx) = mpsc::channel(1);
    let id = registry
        .connect(principal(3), ConnectionSink::new(tx))
        .expect("connect");
    let first = registry.clone();
    let second = registry.clone();
    let (left, right) = tokio::join!(
        async move { first.try_enqueue(id, EncodedRuntimeFrame::from_bytes(&b"aaa"[..])) },
        async move { second.try_enqueue(id, EncodedRuntimeFrame::from_bytes(&b"bbb"[..])) }
    );
    assert!(
        (left.is_ok() && right == Err(ConnectionError::Lagged))
            || (right.is_ok() && left == Err(ConnectionError::Lagged))
    );
    registry.disconnect(id).await.expect("first disconnect");
    registry
        .disconnect(id)
        .await
        .expect("idempotent disconnect");
    assert_eq!(registry.len(), 0);
}

#[tokio::test]
async fn revocation_waits_for_inflight_guard_and_new_work_fails_closed() {
    let principal = principal(4);
    let guard = principal.try_enter().expect("active guard");
    let revoking = principal.clone();
    let task = tokio::spawn(async move { revoking.begin_revoke().await });
    tokio::task::yield_now().await;
    assert_eq!(
        principal.try_enter().err(),
        Some(PrincipalAccessError::Revoked)
    );
    assert!(!task.is_finished());
    drop(guard);
    task.await.expect("join revoke").expect("begin revoke");
    principal.finish_revoke();
    assert!(!principal.is_active());
}

#[tokio::test]
async fn remote_self_revocation_admission_is_exact_remote_only() {
    let issuer = PrincipalIssuer::local_only([0xC2; 32]);
    let local = issuer
        .issue_verified_local_control(501, [0x21; 16])
        .expect("issue local control principal");
    assert!(matches!(
        local.try_enter_remote_self_revocation(),
        Err(PrincipalAccessError::PermissionDenied)
    ));

    let zero_route = issuer
        .issue_test_remote([0x22; 16], [0; 16], 1, [0x23; 32])
        .expect("issue synthetic zero-route principal");
    assert!(matches!(
        zero_route.try_enter_remote_self_revocation(),
        Err(PrincipalAccessError::PermissionDenied)
    ));
    let zero_serial = issuer
        .issue_test_remote([0x24; 16], [0x25; 16], 0, [0x26; 32])
        .expect("issue synthetic zero-serial principal");
    assert!(matches!(
        zero_serial.try_enter_remote_self_revocation(),
        Err(PrincipalAccessError::PermissionDenied)
    ));

    let exact = issuer
        .issue_test_remote([0x27; 16], [0x28; 16], 9, [0x29; 32])
        .expect("issue exact remote self-revocation principal");
    let first = exact
        .try_enter_remote_self_revocation()
        .expect("Active exact principal may start self-revocation");
    assert!(!first.is_revoking_retry());
    let (projected, device, grant_serial) = first.into_parts();
    assert_eq!(
        device,
        DeviceHandle::new(format!("device-{}", "28".repeat(16)))
    );
    assert_eq!(grant_serial, GrantSerial::new(9));

    projected.begin_revoke().await.expect("enter Revoking");
    let retry = exact
        .try_enter_remote_self_revocation()
        .expect("Revoking exact principal may retry self-revocation");
    assert!(retry.is_revoking_retry());
    let (_, retry_device, retry_serial) = retry.into_parts();
    assert_eq!(retry_device, device);
    assert_eq!(retry_serial, grant_serial);
    let retry_principal = exact
        .try_enter_remote_self_revocation()
        .expect("issue purpose-scoped retry connection capability")
        .into_revoking_retry_principal()
        .expect("consume Revoking retry capability");
    assert_eq!(
        retry_principal.authorization_key(),
        projected.authorization_key()
    );
    projected.finish_revoke();
    assert!(matches!(
        exact.try_enter_remote_self_revocation(),
        Err(PrincipalAccessError::Revoked)
    ));
}

#[tokio::test]
async fn fresh_self_revocation_has_one_atomic_winner_and_exact_retry_can_resume() {
    let issuer = PrincipalIssuer::local_only([0xC4; 32]);
    let principal = issuer
        .issue_test_remote([0x31; 16], [0x32; 16], 10, [0x33; 32])
        .expect("issue replay-aware self-revocation principal");

    principal
        .ensure_remote_self_revocation(false)
        .expect("first Fresh precheck sees Active");
    principal
        .ensure_remote_self_revocation(false)
        .expect("second Fresh precheck can also race while Active");
    let expected = (
        DeviceHandle::new(format!("device-{}", "32".repeat(16))),
        GrantSerial::new(10),
    );
    assert_eq!(
        principal
            .admit_remote_self_revocation(false)
            .await
            .expect("first Fresh wins Active to Revoking CAS"),
        expected
    );
    assert!(matches!(
        principal.admit_remote_self_revocation(false).await,
        Err(PrincipalAccessError::Revoked)
    ));
    principal
        .ensure_remote_self_revocation(true)
        .expect("ExactDuplicate precheck may resume Revoking");
    assert_eq!(
        principal
            .admit_remote_self_revocation(true)
            .await
            .expect("ExactDuplicate may reuse the existing Revoking lease"),
        expected
    );
    principal.finish_revoke();
    assert!(matches!(
        principal.ensure_remote_self_revocation(true),
        Err(PrincipalAccessError::Revoked)
    ));
}

#[tokio::test]
async fn same_authorization_identity_shares_one_revocation_lease() {
    let issuer = PrincipalIssuer::local_only([0xC3; 32]);
    let first = issuer
        .issue_verified_local(501, [9; 16])
        .expect("first capability");
    let second = issuer
        .issue_verified_local(501, [9; 16])
        .expect("second capability");
    let guard = second.try_enter().expect("shared lease guard");
    let revoking = first.clone();
    let revoke = tokio::spawn(async move { revoking.begin_revoke().await });
    tokio::task::yield_now().await;
    assert_eq!(
        second.try_enter().err(),
        Some(PrincipalAccessError::Revoked)
    );
    drop(guard);
    revoke.await.expect("join revoke").expect("begin revoke");
    first.finish_revoke();
    assert_eq!(
        second.try_enter().err(),
        Some(PrincipalAccessError::Revoked)
    );
    drop(second);
    drop(first);
    let reissued = issuer
        .issue_verified_local(501, [9; 16])
        .expect("reissue identical capability");
    assert_eq!(
        reissued.try_enter().err(),
        Some(PrincipalAccessError::Revoked),
        "issuer lifetime must retain the revoked lease"
    );
}

#[test]
fn approval_permissions_are_explicit_and_fail_closed_per_operation() {
    let issuer = PrincipalIssuer::local_only([0xC4; 32]);
    let none = issuer
        .issue_verified_local(501, [1; 16])
        .expect("principal without approval permission");
    assert!(matches!(
        none.try_enter_approval(),
        Err(PrincipalAccessError::PermissionDenied)
    ));

    let resolve_only = issuer
        .issue_verified_local_with_approval_permissions(
            501,
            [2; 16],
            ApprovalPermissionGrant::ResolveOnly,
        )
        .expect("resolve-only principal");
    let resolve = resolve_only
        .try_enter_approval()
        .expect("enter resolve capability");
    resolve.require_resolve().expect("resolve permission");
    assert_eq!(
        resolve.require_retry(),
        Err(PrincipalAccessError::PermissionDenied)
    );

    let retry_only = issuer
        .issue_verified_local_with_approval_permissions(
            501,
            [3; 16],
            ApprovalPermissionGrant::RetryOnly,
        )
        .expect("retry-only principal");
    let retry = retry_only
        .try_enter_approval()
        .expect("enter retry capability");
    retry.require_retry().expect("retry permission");
    assert_eq!(
        retry.require_resolve(),
        Err(PrincipalAccessError::PermissionDenied)
    );
}

#[test]
fn verified_local_control_has_fixed_approval_permissions_and_cannot_upgrade_a_lease() {
    let issuer = PrincipalIssuer::local_only([0xC9; 32]);
    let control = issuer
        .issue_verified_local_control(501, [4; 16])
        .expect("issue verified local-control principal");
    let approval = control
        .try_enter_approval()
        .expect("local-control approval capability");
    approval
        .require_resolve()
        .expect("local-control resolve permission");
    approval
        .require_retry()
        .expect("local-control retry permission");
    drop(approval);

    let reconnect = issuer
        .issue_verified_local_control(501, [4; 16])
        .expect("reconnect reuses local-control identity");
    assert_eq!(
        reconnect.idempotency_owner(),
        control.idempotency_owner(),
        "stable installation identity must preserve the idempotency owner across reconnects"
    );

    assert!(matches!(
        issuer.issue_verified_local(501, [4; 16]),
        Err(PrincipalAccessError::PermissionConflict)
    ));

    let read_only = issuer
        .issue_verified_local(501, [5; 16])
        .expect("issue verified read-only local principal");
    assert!(matches!(
        read_only.try_enter_approval(),
        Err(PrincipalAccessError::PermissionDenied)
    ));
    assert!(matches!(
        issuer.issue_verified_local_control(501, [5; 16]),
        Err(PrincipalAccessError::PermissionConflict)
    ));
}

#[test]
fn verified_remote_can_resolve_without_an_is_local_shortcut() {
    let issuer = PrincipalIssuer::local_only([0xC5; 32]);
    let remote = issuer
        .issue_test_remote_with_approval_permissions(
            [4; 16],
            [5; 16],
            7,
            [6; 32],
            ApprovalPermissionGrant::ResolveOnly,
        )
        .expect("verified remote approval principal");
    assert!(!remote.is_local());
    remote
        .try_enter_approval()
        .expect("remote approval guard")
        .require_resolve()
        .expect("issuer-granted remote resolve");
}

fn rotating_remote_binding(
    revision: u64,
    command_key_epoch: u64,
    authorization_hash_seed: u8,
) -> RemoteCommandAuthorizationBinding {
    RemoteCommandAuthorizationBinding::new(
        [0xD1; 32],
        agentdeck_protocol::relay_v2::MachineRouteId::from_bytes([0x11; 16]),
        agentdeck_protocol::relay_v2::DeviceRouteId::from_bytes([0x22; 16]),
        agentdeck_protocol::relay_v2::GrantSerial::new(7),
        [0x33; 32],
        [authorization_hash_seed; 32],
        agentdeck_protocol::relay_v2::KeyDirectoryRevision::new(revision),
        command_key_epoch,
        vec![
            AuthorizationPermissionV1::CatalogRead,
            AuthorizationPermissionV1::RevokeSelf,
        ],
    )
    .expect("canonical rotating remote binding")
}

#[test]
fn remote_rotation_reuses_shared_lease_but_freezes_each_current_binding_snapshot() {
    let issuer = PrincipalIssuer::local_only([0xD1; 32]);
    let revision_one = rotating_remote_binding(1, 4, 0x41);
    let first = issuer
        .issue_verified_remote(revision_one.clone())
        .expect("issue revision-one remote principal");
    let revision_three = rotating_remote_binding(3, 5, 0x41);
    let current = issuer
        .issue_verified_remote(revision_three.clone())
        .expect("a Store-current higher revision refreshes the principal snapshot");

    assert_eq!(first.authorization_key(), current.authorization_key());
    assert_eq!(
        first.remote_command_authorization_binding(),
        Some(revision_one),
        "an in-flight old command keeps its exact ADC2 authorization snapshot"
    );
    assert_eq!(
        current.remote_command_authorization_binding(),
        Some(revision_three.clone())
    );
    let exact_replay = issuer
        .issue_verified_remote(revision_three.clone())
        .expect("the same Store-current proof reuses the shared lease");
    assert_eq!(
        exact_replay.remote_command_authorization_binding(),
        Some(revision_three.clone())
    );

    let device = canonical_device_handle([0x22; 16]).expect("canonical device handle");
    let revoke = issuer
        .remote_principal_for_revoke(&device, GrantSerial::new(7))
        .expect("lookup current remote principal")
        .expect("current remote principal exists");
    assert_eq!(
        revoke.remote_command_authorization_binding(),
        Some(revision_three.clone()),
        "offline revoke sees the latest monotonic binding"
    );

    assert!(matches!(
        issuer.issue_verified_remote(rotating_remote_binding(2, 5, 0x41)),
        Err(PrincipalAccessError::PermissionConflict)
    ));
    assert!(matches!(
        issuer.issue_verified_remote(rotating_remote_binding(3, 5, 0x44)),
        Err(PrincipalAccessError::PermissionConflict)
    ));
    assert!(matches!(
        issuer.issue_verified_remote(rotating_remote_binding(4, 6, 0x44)),
        Err(PrincipalAccessError::PermissionConflict)
    ));

    current.finish_revoke();
    assert!(matches!(
        first.try_enter(),
        Err(PrincipalAccessError::Revoked)
    ));
    assert!(
        matches!(exact_replay.try_enter(), Err(PrincipalAccessError::Revoked)),
        "all revision snapshots share one revoke lease"
    );
}

#[tokio::test]
async fn approval_guard_holds_the_shared_lease_through_revoking() {
    let issuer = PrincipalIssuer::local_only([0xC6; 32]);
    let first = issuer
        .issue_verified_local_with_approval_permissions(
            501,
            [7; 16],
            ApprovalPermissionGrant::ResolveAndRetry,
        )
        .expect("first approval principal");
    let second = issuer
        .issue_verified_local_with_approval_permissions(
            501,
            [7; 16],
            ApprovalPermissionGrant::ResolveAndRetry,
        )
        .expect("same identity reuses approval grant");
    let guard = second.try_enter_approval().expect("shared approval guard");
    guard.require_resolve().expect("resolve permission");
    let revoking = first.clone();
    let revoke = tokio::spawn(async move { revoking.begin_revoke().await });
    tokio::task::yield_now().await;
    assert!(matches!(
        second.try_enter_approval(),
        Err(PrincipalAccessError::Revoked)
    ));
    assert!(!revoke.is_finished(), "approval guard must cover the CAS");
    drop(guard);
    revoke.await.expect("join revoke").expect("begin revoke");
    first.finish_revoke();
}

#[test]
fn same_full_identity_cannot_be_reissued_with_different_approval_bits() {
    let issuer = PrincipalIssuer::local_only([0xC7; 32]);
    issuer
        .issue_verified_local_with_approval_permissions(
            501,
            [8; 16],
            ApprovalPermissionGrant::ResolveOnly,
        )
        .expect("first signed permission set");
    assert!(matches!(
        issuer.issue_verified_local_with_approval_permissions(
            501,
            [8; 16],
            ApprovalPermissionGrant::RetryOnly,
        ),
        Err(PrincipalAccessError::PermissionConflict)
    ));
    assert!(matches!(
        issuer.issue_verified_local(501, [8; 16]),
        Err(PrincipalAccessError::PermissionConflict)
    ));
}

#[test]
fn claimant_binding_is_canonical_full_identity_and_debug_redacted() {
    let issuer = PrincipalIssuer::local_only([0xC8; 32]);
    let first = issuer
        .issue_test_remote_with_approval_permissions(
            [9; 16],
            [10; 16],
            11,
            [12; 32],
            ApprovalPermissionGrant::ResolveAndRetry,
        )
        .expect("first remote claimant");
    let replay = issuer
        .issue_test_remote_with_approval_permissions(
            [9; 16],
            [10; 16],
            11,
            [12; 32],
            ApprovalPermissionGrant::ResolveAndRetry,
        )
        .expect("same full identity");
    let renewed = issuer
        .issue_test_remote_with_approval_permissions(
            [9; 16],
            [10; 16],
            12,
            [12; 32],
            ApprovalPermissionGrant::ResolveAndRetry,
        )
        .expect("new grant serial is a new full identity");
    let first_binding = first
        .try_enter_approval()
        .expect("first approval guard")
        .claimant_binding();
    let replay_binding = replay
        .try_enter_approval()
        .expect("replay approval guard")
        .claimant_binding();
    let renewed_binding = renewed
        .try_enter_approval()
        .expect("renewed approval guard")
        .claimant_binding();
    assert_eq!(first_binding.as_bytes(), replay_binding.as_bytes());
    assert_ne!(first_binding.as_bytes(), renewed_binding.as_bytes());
    assert_eq!(
        format!("{first_binding:?}"),
        "ApprovalClaimantBinding([REDACTED])"
    );
    assert!(!format!("{first_binding:?}").contains("090909"));
}

#[tokio::test]
async fn dropped_unacknowledged_transport_write_removes_registry_entry() {
    let registry = ConnectionRegistry::new(2, 8);
    let (tx, mut rx) = mpsc::channel(1);
    let id = registry
        .connect(principal(7), ConnectionSink::new(tx))
        .expect("connect");
    registry
        .try_enqueue(id, EncodedRuntimeFrame::from_bytes(&b"lost"[..]))
        .expect("enqueue");
    drop(rx.recv().await.expect("transport work without ACK"));
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while registry.len() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("writer cleanup");
    assert!(matches!(
        registry.principal(id),
        Err(ConnectionError::NotFound)
    ));
    assert_eq!(registry.active_writer_count(), 0);
}

#[tokio::test]
async fn connection_write_exposes_shared_bytes_and_observes_core_side_cancellation() {
    let registry = Arc::new(ConnectionRegistry::new(1, 8));
    let (tx, mut rx) = mpsc::channel(1);
    let id = registry
        .connect(principal(27), ConnectionSink::new(tx))
        .expect("connect cancellable writer");
    registry
        .try_enqueue(id, EncodedRuntimeFrame::from_bytes(&b"shared"[..]))
        .expect("enqueue cancellable write");
    let mut write = rx.recv().await.expect("transport write");
    let shared = write.shared_bytes();
    assert_eq!(shared.as_ref(), b"shared");

    let disconnect = tokio::spawn({
        let registry = registry.clone();
        async move { registry.disconnect(id).await }
    });
    tokio::time::timeout(std::time::Duration::from_secs(1), write.cancelled())
        .await
        .expect("writer must observe ACK receiver cancellation");
    disconnect
        .await
        .expect("join disconnect")
        .expect("disconnect writer");
    assert_eq!(write.acknowledge(), Err(ConnectionError::Lagged));
    assert_eq!(shared.as_ref(), b"shared", "shared bytes outlive the write");
}

#[tokio::test]
async fn total_connection_count_saturates_at_the_hard_limit() {
    let registry = ConnectionRegistry::new(1, 8);
    for seed in 0_u16..128 {
        let (tx, _rx) = mpsc::channel(1);
        registry
            .connect(
                principal(u8::try_from(seed).expect("test seed")),
                ConnectionSink::new(tx),
            )
            .expect("connection below hard limit");
    }
    let (overflow_tx, _overflow_rx) = mpsc::channel(1);
    assert!(
        registry
            .connect(principal(255), ConnectionSink::new(overflow_tx))
            .is_err(),
        "the 129th writer must fail before allocating an untracked task"
    );
    registry.shutdown().await.expect("join saturated writers");
    assert_eq!(registry.active_writer_count(), 0);
    assert_eq!(registry.tracked_task_count(), 0);
}

#[tokio::test]
async fn principal_lease_count_saturates_without_evicting_reuse_or_revoked_tombstone() {
    let issuer = PrincipalIssuer::local_only([0xD4; 32]);
    let first_id = 0_u128.to_be_bytes();
    let first = issuer
        .issue_verified_local(501, first_id)
        .expect("first principal");
    for index in 1_u128..1_024 {
        issuer
            .issue_verified_local(501, index.to_be_bytes())
            .expect("principal below hard limit");
    }

    issuer
        .issue_verified_local(501, first_id)
        .expect("same identity reuses a lease at capacity");
    first.begin_revoke().await.expect("begin revoke");
    first.finish_revoke();
    assert!(
        issuer
            .issue_verified_local(501, 1_024_u128.to_be_bytes())
            .is_err(),
        "a new identity must fail closed at capacity"
    );
    let tombstone = issuer
        .issue_verified_local(501, first_id)
        .expect("revoked tombstone remains addressable");
    assert_eq!(
        tombstone.try_enter().err(),
        Some(PrincipalAccessError::Revoked),
        "capacity pressure must not evict a revoked tombstone"
    );
}

#[tokio::test]
async fn dropping_registry_breaks_writer_registry_ownership() {
    let registry = ConnectionRegistry::new(1, 8);
    let entries = Arc::downgrade(&registry.entries);
    let tasks = Arc::downgrade(&registry.tasks);
    let slots = registry.connection_slots.clone();
    let (tx, mut rx) = mpsc::channel(1);
    registry
        .connect(principal(8), ConnectionSink::new(tx))
        .expect("connect");
    drop(registry);
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while entries.upgrade().is_some() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("writer task must not retain the registry after Drop");
    assert!(tasks.upgrade().is_none());
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while slots.available_permits() != DEFAULT_RUNTIME_CONNECTION_CAPACITY {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("Drop must abort every writer task");
    assert!(rx.recv().await.is_none());
}

#[tokio::test]
async fn disconnect_and_shutdown_join_writers_before_returning() {
    let registry = ConnectionRegistry::new(2, 16);
    let (first_tx, mut first_rx) = mpsc::channel(1);
    let first = registry
        .connect(principal(9), ConnectionSink::new(first_tx))
        .expect("first connection");
    assert_eq!(registry.active_writer_count(), 1);
    registry.disconnect(first).await.expect("disconnect first");
    assert_eq!(registry.active_writer_count(), 0);
    assert_eq!(registry.tracked_task_count(), 0);
    assert!(first_rx.recv().await.is_none());

    let (second_tx, mut second_rx) = mpsc::channel(1);
    let (third_tx, mut third_rx) = mpsc::channel(1);
    registry
        .connect(principal(10), ConnectionSink::new(second_tx))
        .expect("second connection");
    registry
        .connect(principal(11), ConnectionSink::new(third_tx))
        .expect("third connection");
    assert_eq!(registry.active_writer_count(), 2);
    registry.shutdown().await.expect("shutdown writers");
    assert_eq!(registry.active_writer_count(), 0);
    assert_eq!(registry.len(), 0);
    assert_eq!(registry.tracked_task_count(), 0);
    assert!(second_rx.recv().await.is_none());
    assert!(third_rx.recv().await.is_none());
    registry.shutdown().await.expect("idempotent shutdown");
}

#[tokio::test]
async fn repeated_lag_abort_reclaims_task_map_and_slots_without_churn_growth() {
    let registry = ConnectionRegistry::new(1, 1);
    for index in 0_u16..512 {
        let (tx, _rx) = mpsc::channel(1);
        let id = registry
            .connect(
                principal(u8::try_from(index % 251).expect("principal seed")),
                ConnectionSink::new(tx),
            )
            .expect("connect churn writer");
        assert_eq!(
            registry.try_enqueue(id, EncodedRuntimeFrame::from_bytes(&b"xx"[..])),
            Err(ConnectionError::Lagged)
        );
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while registry.active_writer_count() != 0 || registry.tracked_task_count() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("lagged writer cleanup");
        assert_eq!(registry.len(), 0);
    }
    registry.shutdown().await.expect("shutdown after churn");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_connect_and_shutdown_leave_no_writer_outside_the_join_fence() {
    let registry = Arc::new(ConnectionRegistry::new(1, 8));
    let barrier = Arc::new(tokio::sync::Barrier::new(33));
    let mut connects = Vec::new();
    for seed in 0_u8..32 {
        let registry = registry.clone();
        let barrier = barrier.clone();
        connects.push(tokio::spawn(async move {
            let (tx, _rx) = mpsc::channel(1);
            barrier.wait().await;
            registry.connect(principal(seed), ConnectionSink::new(tx))
        }));
    }
    let shutting_down = {
        let registry = registry.clone();
        let barrier = barrier.clone();
        tokio::spawn(async move {
            barrier.wait().await;
            registry.shutdown().await
        })
    };

    for connect in connects {
        match connect.await.expect("join connect racer") {
            Ok(_) | Err(ConnectionError::ShuttingDown) => {}
            Err(other) => panic!("unexpected connect race result: {other:?}"),
        }
    }
    shutting_down
        .await
        .expect("join shutdown racer")
        .expect("shutdown race");
    assert_eq!(registry.len(), 0);
    assert_eq!(registry.tracked_task_count(), 0);
    assert_eq!(registry.active_writer_count(), 0);

    let (tx, _rx) = mpsc::channel(1);
    assert_eq!(
        registry.connect(principal(250), ConnectionSink::new(tx)),
        Err(ConnectionError::ShuttingDown)
    );
}

#[test]
fn grant_renewal_changes_authorization_key_but_not_idempotency_owner() {
    let issuer = PrincipalIssuer::local_only([0xB2; 32]);
    let first = issuer
        .issue_test_remote([1; 16], [2; 16], 7, [3; 32])
        .expect("issue old grant");
    let renewed = issuer
        .issue_test_remote([1; 16], [2; 16], 8, [3; 32])
        .expect("issue renewed grant");
    assert_eq!(first.idempotency_owner(), renewed.idempotency_owner());
    assert_ne!(first.authorization_key(), renewed.authorization_key());
}
