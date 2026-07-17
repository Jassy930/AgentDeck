use super::*;

#[tokio::test]
async fn event_seq_and_catalog_revision_are_independent_and_start_at_zero() {
    let root = TestRoot::new("independent-sequences");
    let keys = MemoryKeyStore::new();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open store");
    let mut catalog = store
        .register_stream_barrier(RegisterStreamBarrier {
            target: RuntimeStreamTarget::Catalog,
            generation: WatchGeneration::new(1).expect("catalog generation"),
            request: BarrierRequest::Subscribe {
                cursor: StreamCursor::BeforeFirst,
            },
        })
        .await
        .expect("register empty catalog");
    assert_eq!(catalog.high_water, StreamCursor::BeforeFirst);

    let first = conversation(0x11);
    let first_id = first.conversation_id;
    store
        .create_conversation(first)
        .await
        .expect("create first conversation");
    assert_eq!(catalog.watch.take_coalesced(), Some(StreamCursor::At(0)));
    let second = conversation(0x12);
    let second_id = second.conversation_id;
    store
        .create_conversation(second)
        .await
        .expect("create second conversation");
    assert_eq!(catalog.watch.take_coalesced(), Some(StreamCursor::At(1)));

    let mut first_stream = store
        .register_stream_barrier(RegisterStreamBarrier {
            target: RuntimeStreamTarget::Conversation(first_id),
            generation: WatchGeneration::new(2).expect("first generation"),
            request: BarrierRequest::Subscribe {
                cursor: StreamCursor::BeforeFirst,
            },
        })
        .await
        .expect("register first empty conversation");
    let mut second_stream = store
        .register_stream_barrier(RegisterStreamBarrier {
            target: RuntimeStreamTarget::Conversation(second_id),
            generation: WatchGeneration::new(3).expect("second generation"),
            request: BarrierRequest::Subscribe {
                cursor: StreamCursor::BeforeFirst,
            },
        })
        .await
        .expect("register second empty conversation");
    assert_eq!(first_stream.high_water, StreamCursor::BeforeFirst);
    assert_eq!(second_stream.high_water, StreamCursor::BeforeFirst);

    let first_command = accept_one(&store, first_id).await;
    assert_eq!(
        first_stream.watch.take_coalesced(),
        Some(StreamCursor::At(0))
    );
    store
        .mark_started_with_event(StartCommand {
            conversation_id: first_id,
            command_id: first_command,
            daemon_boot_id: runtime_id(RuntimeIdKind::DaemonBoot, 0x21),
            execution_nonce: b"first-independent-nonce".to_vec(),
        })
        .await
        .expect("commit first started event one");
    assert_eq!(
        first_stream.watch.take_coalesced(),
        Some(StreamCursor::At(1))
    );
    assert_eq!(second_stream.watch.take_coalesced(), None);
    assert_eq!(catalog.watch.take_coalesced(), None);

    let second_command = accept_one(&store, second_id).await;
    assert_eq!(
        second_stream.watch.take_coalesced(),
        Some(StreamCursor::At(0))
    );
    store
        .mark_started_with_event(StartCommand {
            conversation_id: second_id,
            command_id: second_command,
            daemon_boot_id: runtime_id(RuntimeIdKind::DaemonBoot, 0x22),
            execution_nonce: b"second-independent-nonce".to_vec(),
        })
        .await
        .expect("commit second started event one");
    assert_eq!(
        second_stream.watch.take_coalesced(),
        Some(StreamCursor::At(1))
    );
    assert_eq!(first_stream.watch.take_coalesced(), None);
    assert_eq!(catalog.watch.take_coalesced(), None);
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn trim_never_crosses_unfrozen_publication_or_active_snapshot_pin() {
    let root = TestRoot::new("retention-production-rollback");
    let keys = MemoryKeyStore::new();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open production retention store");

    store
        .create_conversation(conversation(0x11))
        .await
        .expect("create oldest catalog victim");
    let publication_stream_id = [0x71; 16];
    store
        .create_publication_stream(
            publication_stream_id,
            PublicationScope::Catalog,
            [0x72; 16],
            [0x73; 16],
        )
        .await
        .expect("create still-unfrozen publication stream");
    let RuntimeBackfillPlan::Pinned(pin) = store
        .acquire_backfill_pin(RuntimeBackfillTarget::Catalog, None)
        .await
        .expect("pin oldest retained catalog revision")
    else {
        panic!("revision zero must produce a pinned catalog range");
    };

    let large_title = "r".repeat(900 * 1024);
    let mut committed_conversations = 1_i64;
    let mut rejected = None;
    for offset in 0_u8..80 {
        let seed = 0x20_u8.checked_add(offset).expect("bounded seed");
        let input = NewConversation {
            conversation_id: conversation_id(seed),
            adapter_state_key: runtime_id(RuntimeIdKind::AdapterState, seed.wrapping_add(0x70)),
            descriptor: ConversationDescriptor {
                agent_kind: AgentKind::Codex,
                title: Some(large_title.clone()),
                cwd: PathBuf::from("/tmp/runtime-retention-production-gate"),
            },
        };
        match store.create_conversation(input).await {
            Ok(_) => committed_conversations += 1,
            Err(error) => {
                rejected = Some(error);
                break;
            }
        }
    }
    let rejected = rejected.expect("catalog byte cap must trigger production trim");
    assert!(
        matches!(
            &rejected,
            RuntimeStoreError::WorkerBusy {
                lane: RuntimeStoreLane::Normal,
            }
        ),
        "active replay pin must reject writer trim, got {rejected:?}"
    );

    let connection = rusqlite::Connection::open(root.database()).expect("open retention readback");
    let (conversation_count, catalog_count, outbox_count): (i64, i64, i64) = connection
        .query_row(
            "SELECT
                 (SELECT COUNT(*) FROM conversations),
                 (SELECT COUNT(*) FROM catalog_journal),
                 (SELECT COUNT(*) FROM publication_outbox)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("read writer rollback and unfrozen outbox state");
    assert_eq!(conversation_count, committed_conversations);
    assert_eq!(catalog_count, committed_conversations);
    assert_eq!(outbox_count, 0, "unfrozen stream is not durable coverage");
    drop(connection);

    let page = store
        .load_catalog_backfill_page(pin.clone(), None)
        .await
        .expect("pinned reader remains usable after rejected writer");
    assert_eq!(page.deltas[0].catalog_revision, 0);
    drop(page);
    store
        .release_backfill_pin(pin.pin_id)
        .await
        .expect("release surviving catalog pin");
    assert!(
        store
            .load_pending_publications(publication_stream_id)
            .await
            .expect("load unfrozen publication stream")
            .is_empty()
    );
    store.shutdown().await.expect("shutdown store");
}

#[test]
fn empty_conversation_uses_before_first_and_delivers_event_zero() {
    let target = RuntimeStreamTarget::Conversation(conversation_id(0x12));
    let mut hub = StoreCommitHub::default();
    let watch = hub
        .register(target, WatchGeneration::new(1).expect("generation"))
        .expect("register watch");

    assert_eq!(watch.registered_after(), StreamCursor::BeforeFirst);
    hub.notify_committed(target, StreamCursor::At(0));
    assert_eq!(watch.latest(), StreamCursor::At(0));
}

#[test]
fn empty_catalog_uses_before_first_and_delivers_revision_zero() {
    let mut hub = StoreCommitHub::default();
    let watch = hub
        .register(
            RuntimeStreamTarget::Catalog,
            WatchGeneration::new(1).expect("generation"),
        )
        .expect("register watch");

    assert_eq!(watch.registered_after(), StreamCursor::BeforeFirst);
    hub.notify_committed(RuntimeStreamTarget::Catalog, StreamCursor::At(0));
    assert_eq!(watch.latest(), StreamCursor::At(0));
}

#[tokio::test]
async fn first_subscription_registers_h_plus_one_before_snapshot_and_releases_after_sync() {
    let root = TestRoot::new("first-subscription");
    let keys = MemoryKeyStore::new();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open store");

    let registration = store
        .register_stream_barrier(RegisterStreamBarrier {
            target: RuntimeStreamTarget::Catalog,
            generation: WatchGeneration::new(1).expect("generation"),
            request: BarrierRequest::Subscribe {
                cursor: StreamCursor::BeforeFirst,
            },
        })
        .await
        .expect("register catalog barrier");

    assert_eq!(registration.high_water, StreamCursor::BeforeFirst);
    assert_eq!(
        registration.ready_snapshot_base, None,
        "fresh store has no ready catalog snapshot until the snapshot builder commits one"
    );
    assert_eq!(
        registration.watch.registered_after(),
        StreamCursor::BeforeFirst
    );
    assert_eq!(registration.watch.next_sequence().expect("H+1"), 0);
    assert_eq!(
        registration.relay_committed.outer,
        StreamCursor::BeforeFirst
    );
    assert_eq!(
        registration.relay_committed.inner,
        StreamCursor::BeforeFirst
    );
    let token = registration.watch.token();
    assert!(
        store
            .release_stream_watch(token.clone())
            .await
            .expect("release watch")
    );
    assert!(
        !store
            .release_stream_watch(token)
            .await
            .expect("idempotent release")
    );
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn capture_failure_releases_watch_before_later_store_mutations() {
    let root = TestRoot::new("capture-failure-cleanup");
    let keys = MemoryKeyStore::new();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open store");
    let missing_id = conversation_id(0x13);

    assert!(matches!(
        store
            .register_stream_barrier(RegisterStreamBarrier {
                target: RuntimeStreamTarget::Conversation(missing_id),
                generation: WatchGeneration::new(41).expect("failed generation"),
                request: BarrierRequest::Subscribe {
                    cursor: StreamCursor::BeforeFirst,
                },
            })
            .await,
        Err(RuntimeStoreError::ConversationNotFound)
    ));

    store
        .create_conversation(conversation(0x14))
        .await
        .expect("unrelated mutation is not poisoned by a leaked missing-target watch");
    let missing = conversation(0x13);
    assert_eq!(missing.conversation_id, missing_id);
    store
        .create_conversation(missing)
        .await
        .expect("create formerly missing target");
    let registration = store
        .register_stream_barrier(RegisterStreamBarrier {
            target: RuntimeStreamTarget::Conversation(missing_id),
            generation: WatchGeneration::new(41).expect("reused generation"),
            request: BarrierRequest::Subscribe {
                cursor: StreamCursor::BeforeFirst,
            },
        })
        .await
        .expect("capture succeeds after target exists");
    assert_eq!(registration.high_water, StreamCursor::BeforeFirst);
    store.shutdown().await.expect("shutdown store");
}

#[test]
fn event_committed_between_watch_registration_and_high_water_capture_is_not_lost() {
    let target = RuntimeStreamTarget::Conversation(conversation_id(0x16));
    let mut hub = StoreCommitHub::default();

    let (mut watch, captured) = hub
        .register_then_capture(
            target,
            WatchGeneration::new(1).expect("generation"),
            |registered| {
                registered.notify_committed(target, StreamCursor::At(0));
                Ok::<_, ()>((StreamCursor::At(0), "captured after commit"))
            },
        )
        .expect("register then capture");

    assert_eq!(captured, "captured after commit");
    assert_eq!(watch.registered_after(), StreamCursor::At(0));
    assert_eq!(
        watch.take_coalesced(),
        None,
        "captured H belongs to snapshot"
    );
    hub.notify_committed(target, StreamCursor::At(1));
    assert_eq!(watch.take_coalesced(), Some(StreamCursor::At(1)));
}

#[test]
fn stale_watch_token_cannot_release_new_generation() {
    let target = RuntimeStreamTarget::Conversation(conversation_id(0x1d));
    let mut hub = StoreCommitHub::default();
    let first = hub
        .register(target, WatchGeneration::new(1).expect("generation one"))
        .expect("first watch");
    let stale = first.token();
    assert!(hub.release(&stale));
    let mut current = hub
        .register(target, WatchGeneration::new(2).expect("generation two"))
        .expect("replacement watch");

    assert!(!hub.is_current(&stale));
    assert!(hub.is_current(&current.token()));
    assert!(!hub.release(&stale));
    hub.notify_committed(target, StreamCursor::At(0));
    assert_eq!(current.take_coalesced(), Some(StreamCursor::At(0)));
}

#[test]
fn token_from_previous_hub_cannot_release_new_hub_watch() {
    let target = RuntimeStreamTarget::Conversation(conversation_id(0x1e));
    let generation = WatchGeneration::new(1).expect("generation");
    let stale = StoreCommitHub::default()
        .register(target, generation)
        .expect("previous hub watch")
        .token();
    let mut current_hub = StoreCommitHub::default();
    let mut current = current_hub
        .register(target, generation)
        .expect("current hub watch");

    assert!(
        !current_hub.release(&stale),
        "a previous hub incarnation cannot release the same target/generation/watch id"
    );
    assert!(current_hub.is_current(&current.token()));
    current_hub.notify_committed(target, StreamCursor::At(0));
    assert_eq!(current.take_coalesced(), Some(StreamCursor::At(0)));
}

#[test]
fn notify_only_visits_the_target_bucket() {
    let target = RuntimeStreamTarget::Conversation(conversation_id(0x1f));
    let unrelated = RuntimeStreamTarget::Conversation(conversation_id(0x20));
    let mut hub = StoreCommitHub::default();
    let target_watch = hub
        .register(target, WatchGeneration::new(1).expect("target generation"))
        .expect("target watch");
    let unrelated_watches: Vec<_> = (1..=32)
        .map(|generation| {
            hub.register(
                unrelated,
                WatchGeneration::new(generation).expect("unrelated generation"),
            )
            .expect("unrelated watch")
        })
        .collect();

    assert_eq!(
        hub.notify_committed(target, StreamCursor::At(0)),
        1,
        "notify must inspect only the selected target bucket"
    );
    assert!(hub.is_current(&target_watch.token()));
    assert!(
        unrelated_watches
            .iter()
            .all(|watch| hub.is_current(&watch.token()))
    );
}

#[tokio::test]
async fn event_committed_while_snapshot_is_sending_is_caught_up_exactly_once() {
    let root = TestRoot::new("snapshot-catchup");
    let keys = MemoryKeyStore::new();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open store");
    let input = conversation(0x17);
    let conversation_id = input.conversation_id;
    store
        .create_conversation(input)
        .await
        .expect("create conversation");
    let mut registration = store
        .register_stream_barrier(RegisterStreamBarrier {
            target: RuntimeStreamTarget::Conversation(conversation_id),
            generation: WatchGeneration::new(7).expect("generation"),
            request: BarrierRequest::Subscribe {
                cursor: StreamCursor::BeforeFirst,
            },
        })
        .await
        .expect("register conversation barrier");
    assert_eq!(registration.high_water, StreamCursor::BeforeFirst);

    let command_id = accept_one(&store, conversation_id).await;
    store
        .mark_started_with_event(StartCommand {
            conversation_id,
            command_id,
            daemon_boot_id: runtime_id(RuntimeIdKind::DaemonBoot, 0x70),
            execution_nonce: b"snapshot-catchup-nonce".to_vec(),
        })
        .await
        .expect("commit event while snapshot is sending");

    assert_eq!(
        registration
            .watch
            .next_committed()
            .await
            .expect("catch-up HWM"),
        StreamCursor::At(1)
    );
    assert_eq!(registration.watch.take_coalesced(), None);
    let token = registration.watch.token();
    store
        .release_stream_watch(token)
        .await
        .expect("release watch");
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn catalog_create_commit_notifies_registered_watch() {
    let root = TestRoot::new("catalog-notify");
    let keys = MemoryKeyStore::new();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open store");
    let mut registration = store
        .register_stream_barrier(RegisterStreamBarrier {
            target: RuntimeStreamTarget::Catalog,
            generation: WatchGeneration::new(2).expect("generation"),
            request: BarrierRequest::Subscribe {
                cursor: StreamCursor::BeforeFirst,
            },
        })
        .await
        .expect("register catalog");

    store
        .create_conversation(conversation(0x18))
        .await
        .expect("catalog revision zero commit");
    assert_eq!(
        registration
            .watch
            .next_committed()
            .await
            .expect("catalog HWM"),
        StreamCursor::At(0)
    );
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn barrier_uses_only_relay_committed_publication_cut() {
    let root = TestRoot::new("relay-committed-cut");
    let keys = MemoryKeyStore::new();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open store");
    store
        .create_conversation(conversation(0x1c))
        .await
        .expect("catalog revision zero");
    let publication_stream_id = [0x81; 16];
    let generation = [0x82; 16];
    store
        .create_publication_stream(
            publication_stream_id,
            PublicationScope::Catalog,
            [0x83; 16],
            generation,
        )
        .await
        .expect("create publication stream");
    let frozen = store
        .freeze_publication(FreezePublicationRequest {
            publication_id: [0x84; 16],
            publication_stream_id,
            generation,
            counter_scope_token: [0x85; 32],
            sender_counter: 1,
            inner_after: None,
            inner_through: Some(0),
            payload_kind: PublicationPayloadKind::Catalog,
            blob: b"frozen-but-not-relay-committed".to_vec(),
        })
        .await
        .expect("freeze publication");

    let frozen_barrier = store
        .register_stream_barrier(RegisterStreamBarrier {
            target: RuntimeStreamTarget::Catalog,
            generation: WatchGeneration::new(10).expect("generation"),
            request: BarrierRequest::Subscribe {
                cursor: StreamCursor::BeforeFirst,
            },
        })
        .await
        .expect("capture frozen barrier");
    assert_eq!(
        frozen_barrier.relay_committed.outer,
        StreamCursor::BeforeFirst
    );
    assert_eq!(
        frozen_barrier.relay_committed.inner,
        StreamCursor::BeforeFirst
    );
    store
        .release_stream_watch(frozen_barrier.watch.token())
        .await
        .expect("release frozen barrier watch");

    store
        .acknowledge_publication_commit(
            publication_stream_id,
            generation,
            frozen.stream_seq,
            frozen.blob_sha256,
        )
        .await
        .expect("Relay durable commit");
    let committed_barrier = store
        .register_stream_barrier(RegisterStreamBarrier {
            target: RuntimeStreamTarget::Catalog,
            generation: WatchGeneration::new(11).expect("generation"),
            request: BarrierRequest::Subscribe {
                cursor: StreamCursor::BeforeFirst,
            },
        })
        .await
        .expect("capture Relay-committed barrier");
    assert_eq!(committed_barrier.relay_committed.outer, StreamCursor::At(0));
    assert_eq!(committed_barrier.relay_committed.inner, StreamCursor::At(0));
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn after_commit_unknown_notifies_durable_event_high_water() {
    let root = TestRoot::new("after-commit-unknown");
    let keys = MemoryKeyStore::new();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()).with_fault_injector(Arc::new(OneShotFault::new(
            RuntimeStoreOperation::StartCommandAfterCommit,
        ))),
        root.storage_kek(&keys),
    )
    .await
    .expect("open store");
    let input = conversation(0x19);
    let conversation_id = input.conversation_id;
    store
        .create_conversation(input)
        .await
        .expect("create conversation");
    let mut registration = store
        .register_stream_barrier(RegisterStreamBarrier {
            target: RuntimeStreamTarget::Conversation(conversation_id),
            generation: WatchGeneration::new(3).expect("generation"),
            request: BarrierRequest::Subscribe {
                cursor: StreamCursor::BeforeFirst,
            },
        })
        .await
        .expect("register conversation");
    let command_id = accept_one(&store, conversation_id).await;
    assert_eq!(
        registration.watch.take_coalesced(),
        Some(StreamCursor::At(0)),
        "configuration commit must be observed before exercising after-COMMIT readback"
    );
    let error = store
        .mark_started_with_event(StartCommand {
            conversation_id,
            command_id,
            daemon_boot_id: runtime_id(RuntimeIdKind::DaemonBoot, 0x71),
            execution_nonce: b"unknown-nonce".to_vec(),
        })
        .await
        .expect_err("after-COMMIT response loss");
    assert!(matches!(
        error,
        RuntimeStoreError::CommitOutcomeUnknown {
            operation: RuntimeCommitOperation::StartCommand
        }
    ));
    assert_eq!(
        registration
            .watch
            .next_committed()
            .await
            .expect("durable readback HWM"),
        StreamCursor::At(1)
    );
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn before_commit_rollback_does_not_notify_event_high_water() {
    let root = TestRoot::new("before-commit-rollback");
    let keys = MemoryKeyStore::new();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()).with_fault_injector(Arc::new(OneShotFault::new(
            RuntimeStoreOperation::StartCommandBeforeCommit,
        ))),
        root.storage_kek(&keys),
    )
    .await
    .expect("open store");
    let input = conversation(0x1a);
    let conversation_id = input.conversation_id;
    store
        .create_conversation(input)
        .await
        .expect("create conversation");
    let mut registration = store
        .register_stream_barrier(RegisterStreamBarrier {
            target: RuntimeStreamTarget::Conversation(conversation_id),
            generation: WatchGeneration::new(4).expect("generation"),
            request: BarrierRequest::Subscribe {
                cursor: StreamCursor::BeforeFirst,
            },
        })
        .await
        .expect("register conversation");
    let command_id = accept_one(&store, conversation_id).await;
    assert_eq!(
        registration.watch.take_coalesced(),
        Some(StreamCursor::At(0)),
        "configuration commit must be observed before exercising Start rollback"
    );
    assert!(
        store
            .mark_started_with_event(StartCommand {
                conversation_id,
                command_id,
                daemon_boot_id: runtime_id(RuntimeIdKind::DaemonBoot, 0x72),
                execution_nonce: b"rollback-nonce".to_vec(),
            })
            .await
            .is_err()
    );
    assert_eq!(registration.watch.take_coalesced(), None);
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn no_watcher_preserves_after_commit_unknown_when_target_readback_would_fail() {
    let root = TestRoot::new("no-watcher-zero-readback");
    let keys = MemoryKeyStore::new();
    let input = conversation(0x31);
    let conversation_id = input.conversation_id;
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()).with_fault_injector(Arc::new(
            TamperRetentionAfterOperation::new(
                RuntimeStoreOperation::StartCommandAfterCommit,
                root.database(),
                conversation_id,
                true,
            ),
        )),
        root.storage_kek(&keys),
    )
    .await
    .expect("open store");
    store
        .create_conversation(input)
        .await
        .expect("create unwatched conversation");
    let command_id = accept_one(&store, conversation_id).await;

    let error = store
        .mark_started_with_event(StartCommand {
            conversation_id,
            command_id,
            daemon_boot_id: runtime_id(RuntimeIdKind::DaemonBoot, 0x73),
            execution_nonce: b"unwatched-unknown-nonce".to_vec(),
        })
        .await
        .expect_err("after-COMMIT response loss remains the mutation outcome");
    assert!(matches!(
        error,
        RuntimeStoreError::CommitOutcomeUnknown {
            operation: RuntimeCommitOperation::StartCommand
        }
    ));
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn no_watcher_performs_zero_authenticated_notification_readbacks() {
    let root = TestRoot::new("no-watcher-readback-count");
    let keys = MemoryKeyStore::new();
    let counter = Arc::new(NotificationReadbackCounter::default());
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()).with_fault_injector(counter.clone()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open store");
    let input = conversation(0x34);
    let conversation_id = input.conversation_id;
    store
        .create_conversation(input)
        .await
        .expect("create unwatched conversation");
    let command_id = accept_one(&store, conversation_id).await;
    store
        .mark_started_with_event(StartCommand {
            conversation_id,
            command_id,
            daemon_boot_id: runtime_id(RuntimeIdKind::DaemonBoot, 0x76),
            execution_nonce: b"zero-readback-nonce".to_vec(),
        })
        .await
        .expect("commit unwatched event");
    assert_eq!(
        counter.count(),
        0,
        "unwatched catalog and conversation effects must perform zero authenticated readbacks"
    );
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn expiry_and_main_commit_same_target_union_reads_back_once() {
    let root = TestRoot::new("same-target-effect-union");
    let keys = MemoryKeyStore::new();
    let accepted_at_ms = 5_000;
    let clock = ManualClock::new(accepted_at_ms);
    let counter = Arc::new(NotificationReadbackCounter::default());
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database())
            .with_clock(clock.clone())
            .with_fault_injector(counter.clone()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open store");
    let input = conversation(0x57);
    let conversation_id = input.conversation_id;
    store
        .create_conversation(input)
        .await
        .expect("create union conversation");
    runtime_configuration::configure_codex_revision_one(&store, conversation_id).await;
    store
        .accept_command(AcceptCommand {
            conversation_id,
            owner: owner(0x93),
            idempotency_key: "old-expiring-command".to_owned(),
            expected_configuration_revision: 1,
            payload: b"old expiring command".to_vec(),
        })
        .await
        .expect("accept old command");
    clock.set(accepted_at_ms + 1);
    let fresh_command = match store
        .accept_command(AcceptCommand {
            conversation_id,
            owner: owner(0x93),
            idempotency_key: "fresh-start-command".to_owned(),
            expected_configuration_revision: 1,
            payload: b"fresh start command".to_vec(),
        })
        .await
        .expect("accept fresh command")
    {
        AcceptOutcome::Accepted { command, .. } => command.command_id,
        AcceptOutcome::Replayed { .. } => panic!("fresh command cannot replay"),
    };
    let mut registration = store
        .register_stream_barrier(RegisterStreamBarrier {
            target: RuntimeStreamTarget::Conversation(conversation_id),
            generation: WatchGeneration::new(57).expect("union generation"),
            request: BarrierRequest::Subscribe {
                cursor: StreamCursor::BeforeFirst,
            },
        })
        .await
        .expect("watch union conversation");

    clock.set(accepted_at_ms + COMMAND_QUEUE_TTL_MS);
    store
        .mark_started_with_event(StartCommand {
            conversation_id,
            command_id: fresh_command,
            daemon_boot_id: runtime_id(RuntimeIdKind::DaemonBoot, 0x77),
            execution_nonce: b"same-target-union-nonce".to_vec(),
        })
        .await
        .expect("expiry and main start both commit");
    assert_eq!(
        registration.watch.take_coalesced(),
        Some(StreamCursor::At(2)),
        "one flush must expose the final durable HWM across both transactions"
    );
    assert_eq!(
        counter.count(),
        1,
        "the same target promoted by expiry and main commit must be read back once"
    );
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn unrelated_watcher_target_is_not_read_or_closed() {
    let root = TestRoot::new("unrelated-watcher-not-read");
    let keys = MemoryKeyStore::new();
    let mutated = conversation(0x32);
    let mutated_id = mutated.conversation_id;
    let unrelated = conversation(0x33);
    let unrelated_id = unrelated.conversation_id;
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()).with_fault_injector(Arc::new(
            TamperRetentionAfterOperation::new(
                RuntimeStoreOperation::StartCommandAfterCommit,
                root.database(),
                unrelated_id,
                false,
            ),
        )),
        root.storage_kek(&keys),
    )
    .await
    .expect("open store");
    store
        .create_conversation(mutated)
        .await
        .expect("create mutated conversation");
    let command_id = accept_one(&store, mutated_id).await;
    store
        .create_conversation(unrelated)
        .await
        .expect("create unrelated conversation");
    let mut unrelated_stream = store
        .register_stream_barrier(RegisterStreamBarrier {
            target: RuntimeStreamTarget::Conversation(unrelated_id),
            generation: WatchGeneration::new(33).expect("unrelated generation"),
            request: BarrierRequest::Subscribe {
                cursor: StreamCursor::BeforeFirst,
            },
        })
        .await
        .expect("watch unrelated conversation");

    store
        .mark_started_with_event(StartCommand {
            conversation_id: mutated_id,
            command_id,
            daemon_boot_id: runtime_id(RuntimeIdKind::DaemonBoot, 0x74),
            execution_nonce: b"unrelated-watch-nonce".to_vec(),
        })
        .await
        .expect("unrelated readback corruption must not affect mutation");
    assert!(
        tokio::time::timeout(
            Duration::from_millis(100),
            unrelated_stream.watch.next_committed(),
        )
        .await
        .is_err(),
        "unrelated watcher must remain open and receive no notification"
    );
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn expiry_commit_survives_main_rollback_without_touching_unrelated_watcher() {
    let root = TestRoot::new("expiry-commit-main-rollback");
    let keys = MemoryKeyStore::new();
    let accepted_at_ms = 4_000;
    let clock = ManualClock::new(accepted_at_ms);
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database())
            .with_clock(clock.clone())
            .with_fault_injector(Arc::new(OneShotFault::new(
                RuntimeStoreOperation::StartCommandBeforeCommit,
            ))),
        root.storage_kek(&keys),
    )
    .await
    .expect("open store");

    let expired = conversation(0x54);
    let expired_id = expired.conversation_id;
    store
        .create_conversation(expired)
        .await
        .expect("create expiring conversation");
    accept_one(&store, expired_id).await;
    let mut expired_stream = store
        .register_stream_barrier(RegisterStreamBarrier {
            target: RuntimeStreamTarget::Conversation(expired_id),
            generation: WatchGeneration::new(54).expect("expiry generation"),
            request: BarrierRequest::Subscribe {
                cursor: StreamCursor::BeforeFirst,
            },
        })
        .await
        .expect("watch expiring conversation");

    clock.set(accepted_at_ms + 1);
    let trigger = conversation(0x55);
    let trigger_id = trigger.conversation_id;
    store
        .create_conversation(trigger)
        .await
        .expect("create main-operation conversation");
    let trigger_command = accept_one(&store, trigger_id).await;

    let unrelated = conversation(0x56);
    let unrelated_id = unrelated.conversation_id;
    store
        .create_conversation(unrelated)
        .await
        .expect("create unrelated conversation");
    let mut unrelated_stream = store
        .register_stream_barrier(RegisterStreamBarrier {
            target: RuntimeStreamTarget::Conversation(unrelated_id),
            generation: WatchGeneration::new(56).expect("unrelated generation"),
            request: BarrierRequest::Subscribe {
                cursor: StreamCursor::BeforeFirst,
            },
        })
        .await
        .expect("watch unrelated conversation");
    tamper_retention_token(&root.database(), unrelated_id);

    clock.set(accepted_at_ms + COMMAND_QUEUE_TTL_MS);
    assert!(matches!(
        store
            .mark_started_with_event(StartCommand {
                conversation_id: trigger_id,
                command_id: trigger_command,
                daemon_boot_id: runtime_id(RuntimeIdKind::DaemonBoot, 0x75),
                execution_nonce: b"expiry-main-rollback-nonce".to_vec(),
            })
            .await,
        Err(RuntimeStoreError::InvalidConfig(
            "injected stream barrier fault"
        ))
    ));
    assert_eq!(
        expired_stream.watch.take_coalesced(),
        Some(StreamCursor::At(1)),
        "expiry COMMIT must notify even though the main transaction rolled back"
    );
    assert!(
        tokio::time::timeout(
            Duration::from_millis(100),
            unrelated_stream.watch.next_committed(),
        )
        .await
        .is_err(),
        "main rollback must not cause unrelated watcher readback"
    );
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn failed_target_readback_preserves_mutation_and_notifies_healthy_target() {
    let root = TestRoot::new("readback-failure-isolation");
    let keys = MemoryKeyStore::new();
    let accepted_at_ms = 3_000;
    let clock = ManualClock::new(accepted_at_ms);
    let failed = conversation(0x51);
    let failed_id = failed.conversation_id;
    let healthy = conversation(0x52);
    let healthy_id = healthy.conversation_id;
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database())
            .with_clock(clock.clone())
            .with_fault_injector(Arc::new(TamperRetentionAfterOperation::new(
                RuntimeStoreOperation::ExpireCommandsAfterCommit,
                root.database(),
                failed_id,
                false,
            ))),
        root.storage_kek(&keys),
    )
    .await
    .expect("open store");
    store
        .create_conversation(failed)
        .await
        .expect("create failed readback target");
    accept_one(&store, failed_id).await;
    let mut failed_stream = store
        .register_stream_barrier(RegisterStreamBarrier {
            target: RuntimeStreamTarget::Conversation(failed_id),
            generation: WatchGeneration::new(51).expect("failed target generation"),
            request: BarrierRequest::Subscribe {
                cursor: StreamCursor::BeforeFirst,
            },
        })
        .await
        .expect("watch failed readback target");

    store
        .create_conversation(healthy)
        .await
        .expect("create healthy readback target");
    accept_one(&store, healthy_id).await;
    let mut healthy_stream = store
        .register_stream_barrier(RegisterStreamBarrier {
            target: RuntimeStreamTarget::Conversation(healthy_id),
            generation: WatchGeneration::new(52).expect("healthy target generation"),
            request: BarrierRequest::Subscribe {
                cursor: StreamCursor::BeforeFirst,
            },
        })
        .await
        .expect("watch healthy readback target");

    let trigger = conversation(0x53);
    let trigger_id = trigger.conversation_id;
    store
        .create_conversation(trigger)
        .await
        .expect("create expiry trigger conversation");
    runtime_configuration::configure_codex_revision_one(&store, trigger_id).await;
    clock.set(accepted_at_ms + COMMAND_QUEUE_TTL_MS);

    assert!(matches!(
        store
            .accept_command(AcceptCommand {
                conversation_id: trigger_id,
                owner: owner(0x92),
                idempotency_key: "trigger-readback-isolation".to_owned(),
                expected_configuration_revision: 1,
                payload: b"trigger readback isolation".to_vec(),
            })
            .await
            .expect("notification readback failure must not replace mutation success"),
        AcceptOutcome::Accepted { .. }
    ));
    assert_eq!(
        healthy_stream.watch.take_coalesced(),
        Some(StreamCursor::At(1)),
        "healthy affected target must still receive its durable HWM"
    );
    assert!(
        tokio::time::timeout(Duration::from_secs(1), failed_stream.watch.next_committed())
            .await
            .expect("failed target watch must close promptly")
            .is_err(),
        "failed authenticated readback must fail-close that target watch"
    );
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn bulk_expiry_after_commit_unknown_notifies_every_affected_conversation() {
    let root = TestRoot::new("bulk-expiry-after-commit-unknown");
    let keys = MemoryKeyStore::new();
    let accepted_at_ms = 1_000;
    let clock = ManualClock::new(accepted_at_ms);
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database())
            .with_clock(clock.clone())
            .with_fault_injector(Arc::new(OneShotFault::new(
                RuntimeStoreOperation::ExpireCommandsAfterCommit,
            ))),
        root.storage_kek(&keys),
    )
    .await
    .expect("open store");

    let first = conversation(0x41);
    let first_id = first.conversation_id;
    store
        .create_conversation(first)
        .await
        .expect("create first expiring conversation");
    accept_one(&store, first_id).await;
    let mut first_stream = store
        .register_stream_barrier(RegisterStreamBarrier {
            target: RuntimeStreamTarget::Conversation(first_id),
            generation: WatchGeneration::new(41).expect("first generation"),
            request: BarrierRequest::Subscribe {
                cursor: StreamCursor::BeforeFirst,
            },
        })
        .await
        .expect("watch first expiring conversation");

    let second = conversation(0x42);
    let second_id = second.conversation_id;
    store
        .create_conversation(second)
        .await
        .expect("create second expiring conversation");
    accept_one(&store, second_id).await;
    let mut second_stream = store
        .register_stream_barrier(RegisterStreamBarrier {
            target: RuntimeStreamTarget::Conversation(second_id),
            generation: WatchGeneration::new(42).expect("second generation"),
            request: BarrierRequest::Subscribe {
                cursor: StreamCursor::BeforeFirst,
            },
        })
        .await
        .expect("watch second expiring conversation");

    let trigger = conversation(0x43);
    let trigger_id = trigger.conversation_id;
    store
        .create_conversation(trigger)
        .await
        .expect("create expiry trigger conversation");
    runtime_configuration::configure_codex_revision_one(&store, trigger_id).await;
    clock.set(accepted_at_ms + COMMAND_QUEUE_TTL_MS);

    let error = store
        .accept_command(AcceptCommand {
            conversation_id: trigger_id,
            owner: owner(0x91),
            idempotency_key: "trigger-bulk-expiry".to_owned(),
            expected_configuration_revision: 1,
            payload: b"trigger bulk expiry".to_vec(),
        })
        .await
        .expect_err("expiry commits before the injected reply loss");
    assert!(matches!(
        error,
        RuntimeStoreError::CommitOutcomeUnknown {
            operation: RuntimeCommitOperation::ExpireCommands
        }
    ));
    assert_eq!(
        first_stream.watch.take_coalesced(),
        Some(StreamCursor::At(1))
    );
    assert_eq!(
        second_stream.watch.take_coalesced(),
        Some(StreamCursor::At(1))
    );
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn safety_termination_notifies_conversation_high_water() {
    let root = TestRoot::new("safety-termination-notify");
    let keys = MemoryKeyStore::new();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open store");
    let input = conversation(0x44);
    let conversation_id = input.conversation_id;
    store
        .create_conversation(input)
        .await
        .expect("create safety conversation");
    let command_id = accept_one(&store, conversation_id).await;
    let mut registration = store
        .register_stream_barrier(RegisterStreamBarrier {
            target: RuntimeStreamTarget::Conversation(conversation_id),
            generation: WatchGeneration::new(44).expect("safety generation"),
            request: BarrierRequest::Subscribe {
                cursor: StreamCursor::BeforeFirst,
            },
        })
        .await
        .expect("watch safety conversation");

    assert!(matches!(
        store
            .terminate_accepted_command(TerminateAcceptedCommand {
                conversation_id,
                command_id,
                expected_owner: owner(0x90),
                reason: AcceptedTerminationReason::Canceled,
            })
            .await
            .expect("terminate accepted command on safety lane"),
        TerminateAcceptedOutcome::Transitioned { event, .. } if event.event_seq == 1
    ));
    assert_eq!(
        registration.watch.take_coalesced(),
        Some(StreamCursor::At(1))
    );
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn recovery_scan_expiry_notifies_conversation_high_water() {
    let root = TestRoot::new("recovery-expiry-notify");
    let keys = MemoryKeyStore::new();
    let accepted_at_ms = 2_000;
    let clock = ManualClock::new(accepted_at_ms);
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()).with_clock(clock.clone()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open store");
    let input = conversation(0x45);
    let conversation_id = input.conversation_id;
    store
        .create_conversation(input)
        .await
        .expect("create recovery conversation");
    accept_one(&store, conversation_id).await;
    let mut registration = store
        .register_stream_barrier(RegisterStreamBarrier {
            target: RuntimeStreamTarget::Conversation(conversation_id),
            generation: WatchGeneration::new(45).expect("recovery generation"),
            request: BarrierRequest::Subscribe {
                cursor: StreamCursor::BeforeFirst,
            },
        })
        .await
        .expect("watch recovery conversation");
    clock.set(accepted_at_ms + COMMAND_QUEUE_TTL_MS);

    let cursor = store
        .begin_recovery_scan()
        .await
        .expect("begin recovery scan after expiry boundary");
    assert_eq!(
        registration.watch.take_coalesced(),
        Some(StreamCursor::At(1))
    );
    let page = store
        .load_recovery_page(cursor)
        .await
        .expect("load recovery page after expiry");
    let recovered = page
        .conversation
        .as_ref()
        .expect("single recovery conversation");
    assert_eq!(recovered.conversation.conversation_id, conversation_id);
    assert_eq!(recovered.conversation.event_high_water, Some(1));
    assert!(recovered.accepted.is_empty());
    store
        .finish_recovery_scan(page.completion.expect("single page completion"))
        .await
        .expect("finish recovery scan");
    store.shutdown().await.expect("shutdown store");
}
