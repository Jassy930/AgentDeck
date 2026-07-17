use super::*;

#[tokio::test]
async fn stable_event_item_entity_and_command_ids_survive_replay() {
    let root = TestRoot::new("stable-event-ids");
    let keys = MemoryKeyStore::new();
    let configuration_event_id = runtime_id(RuntimeIdKind::Event, 0x30);
    let command_id = runtime_id(RuntimeIdKind::Command, 0x31);
    let turn_id = runtime_id(RuntimeIdKind::Turn, 0x32);
    let event_id = runtime_id(RuntimeIdKind::Event, 0x33);
    let started_event_id = runtime_id(RuntimeIdKind::Event, 0x34);
    let item_id = ItemId::new("stable-item-id");
    let entity_id = EntityId::new("stable-entity-id");
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()).with_id_source(SequenceIdSource::new([
            configuration_event_id,
            command_id,
            turn_id,
            started_event_id,
        ])),
        root.storage_kek(&keys),
    )
    .await
    .expect("open store");
    let input = conversation(0x1b);
    let conversation_id = input.conversation_id;
    store
        .create_conversation(input)
        .await
        .expect("create conversation");
    assert_eq!(accept_one(&store, conversation_id).await, command_id);
    store
        .mark_started_with_event(StartCommand {
            conversation_id,
            command_id,
            daemon_boot_id: runtime_id(RuntimeIdKind::DaemonBoot, 0x73),
            execution_nonce: b"stable-id-nonce".to_vec(),
        })
        .await
        .expect("commit canonical TurnStarted");
    authorize_test_execution_release(
        &store,
        command_id,
        runtime_id(RuntimeIdKind::DaemonBoot, 0x73),
        b"stable-id-nonce",
        7_301,
    )
    .await;
    let appended = store
        .append_execution_event(AppendExecutionEvent::item(
            conversation_id,
            command_id,
            turn_id,
            event_id,
            item_id,
            entity_id,
            AgentItem::UserMessage {
                text: "stable identity replay".to_owned(),
                meta: AgentItemMeta::default(),
            },
        ))
        .await
        .expect("append canonical item event");
    let canonical: RuntimeEvent = match appended {
        AppendExecutionEventOutcome::Appended { event } => {
            serde_json::from_slice(&event.payload).expect("decode appended item")
        }
        AppendExecutionEventOutcome::Replayed { .. } => panic!("fresh item cannot replay"),
    };
    let agentdeckd::runtime::store::RuntimeBackfillPlan::Pinned(pin) = store
        .acquire_backfill_pin(
            agentdeckd::runtime::store::RuntimeBackfillTarget::Conversation(conversation_id),
            Some(1),
        )
        .await
        .expect("pin canonical event")
    else {
        panic!("event two must be retained after event one");
    };
    let page = store
        .load_event_backfill_page(pin.clone(), Some(1))
        .await
        .expect("replay canonical event");
    let completion = page.completion().clone();
    assert_eq!(page.events.len(), 1);
    let replayed = &page.events[0];
    assert_eq!(replayed.conversation_id, canonical.conversation_id);
    assert_eq!(replayed.event_id, canonical.event_id);
    assert_eq!(replayed.event_seq, canonical.event_seq);
    assert_eq!(replayed.command_id, canonical.command_id);
    assert_eq!(replayed.item_id, canonical.item_id);
    assert_eq!(replayed.entity_id, canonical.entity_id);
    let replayed_page = store
        .load_event_backfill_page(pin.clone(), Some(1))
        .await
        .expect("unacknowledged page keeps the event pin at its original cursor");
    let stale_completion = replayed_page.completion().clone();
    store
        .complete_backfill_page(completion)
        .await
        .expect("transport flush completion releases final event page");
    assert!(matches!(
        store.complete_backfill_page(stale_completion).await,
        Err(RuntimeStoreError::InvalidBackfillPin)
    ));
    assert!(matches!(
        store.load_event_backfill_page(pin, Some(1)).await,
        Err(RuntimeStoreError::InvalidBackfillPin)
    ));
    store.shutdown().await.expect("shutdown store");
}

#[test]
fn retained_range_uses_backfill_without_advancing_outer_high_water() {
    let committed_outer = StreamCursor::At(17);
    let mut barrier = input(
        RuntimeStreamTarget::Conversation(conversation_id(0x13)),
        BarrierRequest::Backfill {
            after: StreamCursor::At(3),
        },
        StreamCursor::At(7),
        Some(4),
    );
    barrier.committed_outer = committed_outer;

    assert_eq!(
        plan_barrier(barrier).expect("retained range"),
        BarrierDecision::Backfill {
            after: StreamCursor::At(3),
            through: StreamCursor::At(7),
            committed_outer,
        }
    );
}

#[test]
fn trimmed_range_returns_need_snapshot_without_partial_backfill() {
    let decision = plan_barrier(input(
        RuntimeStreamTarget::Conversation(conversation_id(0x14)),
        BarrierRequest::Backfill {
            after: StreamCursor::At(1),
        },
        StreamCursor::At(7),
        Some(5),
    ))
    .expect("trimmed range is a typed plan");

    assert_eq!(
        decision,
        BarrierDecision::NeedSnapshot {
            base: StreamCursor::At(7),
        }
    );
}

#[test]
fn catalog_and_conversation_use_the_same_barrier_algorithm() {
    let catalog = plan_barrier(input(
        RuntimeStreamTarget::Catalog,
        BarrierRequest::Backfill {
            after: StreamCursor::At(2),
        },
        StreamCursor::At(4),
        Some(3),
    ))
    .expect("catalog plan");
    let conversation = plan_barrier(input(
        RuntimeStreamTarget::Conversation(conversation_id(0x15)),
        BarrierRequest::Backfill {
            after: StreamCursor::At(2),
        },
        StreamCursor::At(4),
        Some(3),
    ))
    .expect("conversation plan");

    assert_eq!(catalog, conversation);
}

#[tokio::test]
async fn snapshot_and_backfill_emit_capabilities_before_any_agent_item() {
    let root = TestRoot::new("capabilities-before-item");
    let keys = MemoryKeyStore::new();
    let configuration_event_id = runtime_id(RuntimeIdKind::Event, 0x40);
    let command_id = runtime_id(RuntimeIdKind::Command, 0x41);
    let turn_id = runtime_id(RuntimeIdKind::Turn, 0x42);
    let event_id = runtime_id(RuntimeIdKind::Event, 0x43);
    let started_event_id = runtime_id(RuntimeIdKind::Event, 0x45);
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()).with_id_source(SequenceIdSource::new([
            configuration_event_id,
            command_id,
            turn_id,
            started_event_id,
        ])),
        root.storage_kek(&keys),
    )
    .await
    .expect("open capabilities ordering store");
    let created = conversation(0x2a);
    let conversation_id = created.conversation_id;
    store
        .create_conversation(created)
        .await
        .expect("create capabilities ordering conversation");
    assert_eq!(accept_one(&store, conversation_id).await, command_id);

    let capabilities = SessionCapabilities {
        agent_kind: AgentKind::Codex,
        agent_version: "capabilities-first".to_owned(),
        features: BTreeSet::new(),
        vendor: VendorCapabilities::Codex(Default::default()),
    };
    let item_id = ItemId::new("capabilities-first-item");
    let entity_id = EntityId::new("capabilities-first-entity");
    store
        .mark_started_with_event(StartCommand {
            conversation_id,
            command_id,
            daemon_boot_id: runtime_id(RuntimeIdKind::DaemonBoot, 0x44),
            execution_nonce: b"capabilities-first-nonce".to_vec(),
        })
        .await
        .expect("commit canonical TurnStarted");
    authorize_test_execution_release(
        &store,
        command_id,
        runtime_id(RuntimeIdKind::DaemonBoot, 0x44),
        b"capabilities-first-nonce",
        7_302,
    )
    .await;
    let canonical: RuntimeEvent = match store
        .append_execution_event(AppendExecutionEvent::item(
            conversation_id,
            command_id,
            turn_id,
            event_id,
            item_id.clone(),
            entity_id.clone(),
            AgentItem::UserMessage {
                text: "canonical item after capabilities".to_owned(),
                meta: AgentItemMeta::default(),
            },
        ))
        .await
        .expect("append canonical item event")
    {
        AppendExecutionEventOutcome::Appended { event } => {
            serde_json::from_slice(&event.payload).expect("decode canonical item event")
        }
        AppendExecutionEventOutcome::Replayed { .. } => panic!("fresh item cannot replay"),
    };

    let snapshot_source = store
        .acquire_snapshot_build_source(conversation_id)
        .await
        .expect("capture exact snapshot source");
    let RuntimeBackfillPlan::Pinned(backfill_pin) = store
        .acquire_backfill_pin(
            RuntimeBackfillTarget::Conversation(conversation_id),
            Some(1),
        )
        .await
        .expect("pin production backfill")
    else {
        panic!("event two must produce a pinned backfill range after event one");
    };
    let page = store
        .load_event_backfill_page(backfill_pin, Some(1))
        .await
        .expect("load production backfill page");
    assert_eq!(page.events.len(), 1);
    assert_eq!(page.events[0].event_seq, canonical.event_seq);
    assert_eq!(page.events[0].event_id, canonical.event_id);
    assert_eq!(page.events[0].command_id, canonical.command_id);
    assert_eq!(page.events[0].item_id, canonical.item_id);
    assert_eq!(page.events[0].entity_id, canonical.entity_id);
    assert!(matches!(
        &page.events[0].body,
        RuntimeEventBody::Item { .. }
    ));

    let range = BackfillRange::new(StreamCursor::At(1), StreamCursor::At(2))
        .expect("single event backfill range");
    let backfill = BackfillChunk::conversation(
        ConversationId::new(conversation_id.to_canonical_string()),
        capabilities.clone(),
        range,
        page.events.clone(),
    )
    .expect("canonical conversation backfill");
    let encoded_backfill = serde_json::to_vec(&backfill).expect("encode canonical backfill");
    let decoded_backfill: BackfillChunk =
        serde_json::from_slice(&encoded_backfill).expect("decode canonical backfill");
    match decoded_backfill {
        BackfillChunk::Conversation {
            capabilities_preamble,
            events,
            ..
        } => {
            assert_eq!(
                serde_json::to_value(&capabilities_preamble).expect("encode backfill capabilities"),
                serde_json::to_value(&capabilities).expect("encode expected capabilities")
            );
            assert!(matches!(
                events.as_slice(),
                [RuntimeEvent {
                    body: RuntimeEventBody::Item { .. },
                    ..
                }]
            ));
        }
        BackfillChunk::Catalog { .. } => panic!("conversation backfill changed scope"),
    }

    let snapshot_item = SnapshotItem::Item {
        item_id,
        entity_id,
        command_id: canonical.command_id.clone(),
        item: match canonical.body.clone() {
            RuntimeEventBody::Item { item } => item,
            _ => unreachable!("fixture is an item event"),
        },
    };
    let (write, canonical_snapshot) = prepare_canonical_snapshot_write_with_items(
        &store,
        snapshot_source,
        "capabilities-first",
        vec![snapshot_item],
    )
    .await
    .expect("assemble production canonical snapshot");
    let decoded_snapshot: ConversationSnapshot =
        serde_json::from_slice(&canonical_snapshot).expect("decode canonical snapshot");
    let [
        SnapshotItem::Capabilities {
            capabilities: first,
            ..
        },
        SnapshotItem::Item { .. },
    ] = decoded_snapshot.items()
    else {
        panic!("canonical snapshot must place capabilities before its first AgentItem");
    };
    assert_eq!(
        serde_json::to_value(first).expect("encode snapshot capabilities"),
        serde_json::to_value(&capabilities).expect("encode expected snapshot capabilities")
    );
    let stored = store
        .store_conversation_snapshot(write)
        .await
        .expect("store exact canonical snapshot");
    assert_eq!(stored.payload, canonical_snapshot);

    let completion = page.completion().clone();
    drop(page);
    store
        .complete_backfill_page(completion)
        .await
        .expect("commit flushed backfill page");
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn snapshot_capture_holds_no_actor_lock_or_sqlite_transaction_during_io() {
    let root = TestRoot::new("snapshot-capture-no-long-lock");
    let keys = MemoryKeyStore::new();
    let configuration_event_id = runtime_id(RuntimeIdKind::Event, 0x50);
    let command_id = runtime_id(RuntimeIdKind::Command, 0x51);
    let turn_id = runtime_id(RuntimeIdKind::Turn, 0x52);
    let event_id = runtime_id(RuntimeIdKind::Event, 0x53);
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()).with_id_source(SequenceIdSource::new([
            configuration_event_id,
            command_id,
            turn_id,
            event_id,
        ])),
        root.storage_kek(&keys),
    )
    .await
    .expect("open snapshot capture store");
    let created = conversation(0x2b);
    let conversation_id = created.conversation_id;
    store
        .create_conversation(created)
        .await
        .expect("create snapshot capture conversation");

    // 持有 production snapshot source 模拟后续 reducer/网络 I/O 尚未完成。
    // capture 返回后若仍占用 SQLite transaction，独立 IMMEDIATE writer 会失败；
    // 若独占 store/actor 执行权，后续同 conversation COMMIT 会超时。
    let source = store
        .acquire_snapshot_build_source(conversation_id)
        .await
        .expect("capture snapshot source");
    assert_eq!(
        source
            .build_pin()
            .expect("fresh conversation uses build pin")
            .base_event_seq(),
        None
    );
    let external = rusqlite::Connection::open(root.database())
        .expect("open independent SQLite writer after capture");
    external
        .execute_batch("BEGIN IMMEDIATE; ROLLBACK;")
        .expect("snapshot capture must not retain a SQLite transaction");
    drop(external);

    let committed_command =
        tokio::time::timeout(Duration::from_secs(2), accept_one(&store, conversation_id))
            .await
            .expect("snapshot I/O must not block the store actor");
    assert_eq!(committed_command, command_id);
    tokio::time::timeout(
        Duration::from_secs(2),
        store.mark_started_with_event(StartCommand {
            conversation_id,
            command_id,
            daemon_boot_id: runtime_id(RuntimeIdKind::DaemonBoot, 0x54),
            execution_nonce: b"snapshot-no-lock-nonce".to_vec(),
        }),
    )
    .await
    .expect("snapshot I/O must not block a durable event COMMIT")
    .expect("commit event while snapshot source remains live");
    assert_eq!(
        source
            .build_pin()
            .expect("source remains an exact build pin")
            .base_event_seq(),
        None,
        "capture must remain frozen while writer advances"
    );
    drop(source);
    store.shutdown().await.expect("shutdown store");
}

#[test]
fn cursor_at_u64_max_requires_generation_rotation_without_wrap() {
    let error = plan_barrier(input(
        RuntimeStreamTarget::Catalog,
        BarrierRequest::Backfill {
            after: StreamCursor::At(u64::MAX),
        },
        StreamCursor::At(u64::MAX),
        Some(u64::MAX),
    ))
    .expect_err("exhausted cursor must rotate generation");

    assert_eq!(error, BarrierError::GenerationRotationRequired);
}
