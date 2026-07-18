use super::*;

#[tokio::test]
async fn ready_snapshot_authenticated_base_is_captured_with_later_high_water() {
    let root = TestRoot::new("ready-snapshot-barrier-capture");
    let keys = MemoryKeyStore::new();
    let configuration_event_id = runtime_id(RuntimeIdKind::Event, 0x45);
    let command_id = runtime_id(RuntimeIdKind::Command, 0x47);
    let turn_id = runtime_id(RuntimeIdKind::Turn, 0x48);
    let started_event_id = runtime_id(RuntimeIdKind::Event, 0x49);
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
    let input = conversation(0x46);
    let conversation_id = input.conversation_id;
    store
        .create_conversation(input)
        .await
        .expect("create snapshot conversation");
    assert_eq!(accept_one(&store, conversation_id).await, command_id);

    let snapshot_pin = store
        .acquire_snapshot_build_source(conversation_id)
        .await
        .expect("capture configuration snapshot base");
    store_canonical_snapshot(&store, snapshot_pin, "capabilities-only-snapshot")
        .await
        .expect("store ready snapshot");

    store
        .mark_started_with_event(StartCommand {
            conversation_id,
            command_id,
            daemon_boot_id: runtime_id(RuntimeIdKind::DaemonBoot, 0x4A),
            execution_nonce: b"ready-snapshot-canonical-start".to_vec(),
        })
        .await
        .expect("advance event high-water with canonical TurnStarted after snapshot");

    let registration = store
        .register_stream_barrier(RegisterStreamBarrier {
            target: RuntimeStreamTarget::Conversation(conversation_id),
            generation: WatchGeneration::new(46).expect("snapshot generation"),
            request: BarrierRequest::Subscribe {
                cursor: StreamCursor::BeforeFirst,
            },
        })
        .await
        .expect("capture authenticated ready snapshot base");
    assert_eq!(registration.high_water, StreamCursor::At(1));
    assert_eq!(registration.ready_snapshot_base, Some(StreamCursor::At(0)));
    assert_eq!(
        registration.decision,
        BarrierDecision::Snapshot {
            base: StreamCursor::At(0),
            through: StreamCursor::At(1),
            committed_outer: StreamCursor::BeforeFirst,
        }
    );
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn snapshot_build_pin_is_bound_to_barrier_captured_h() {
    let root = TestRoot::new("snapshot-exact-barrier-h");
    let keys = MemoryKeyStore::new();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open store");
    let input = conversation(0x73);
    let conversation_id = input.conversation_id;
    store
        .create_conversation(input)
        .await
        .expect("create exact-H conversation");
    let command_id = accept_one(&store, conversation_id).await;

    let mut registration = store
        .register_stream_barrier(RegisterStreamBarrier {
            target: RuntimeStreamTarget::Conversation(conversation_id),
            generation: WatchGeneration::new(73).expect("exact-H generation"),
            request: BarrierRequest::Subscribe {
                cursor: StreamCursor::BeforeFirst,
            },
        })
        .await
        .expect("register and capture exact-H source");
    let source = registration
        .take_snapshot_source()
        .expect("empty conversation must capture an exact-H build source");
    let pin = match source.source() {
        SnapshotBarrierSource::Build(pin) => pin.clone(),
        SnapshotBarrierSource::Ready(_) | SnapshotBarrierSource::Dynamic(_) => {
            panic!("empty conversation must capture an exact-H build source")
        }
    };
    assert_eq!(pin.base_event_seq(), Some(0));

    store
        .terminate_accepted_command(TerminateAcceptedCommand {
            conversation_id,
            command_id,
            expected_owner: owner(0x90),
            reason: AcceptedTerminationReason::Canceled,
        })
        .await
        .expect("advance high-water after barrier capture");
    let later_pin = store
        .acquire_snapshot_build_source(conversation_id)
        .await
        .expect("capture later high-water independently");
    assert_eq!(
        later_pin
            .build_pin()
            .expect("direct acquire returns build source")
            .base_event_seq(),
        Some(1)
    );
    assert_eq!(
        pin.base_event_seq(),
        Some(0),
        "barrier source must not reacquire a later high-water"
    );

    drop(source);
    drop(later_pin);
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn ready_snapshot_reference_is_exact_and_replacement_safe() {
    let root = TestRoot::new("snapshot-ready-exact-reference");
    let keys = MemoryKeyStore::new();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open store");
    let input = conversation(0x74);
    let conversation_id = input.conversation_id;
    store
        .create_conversation(input)
        .await
        .expect("create ready snapshot conversation");
    let first_pin = store
        .acquire_snapshot_build_source(conversation_id)
        .await
        .expect("capture first snapshot base");
    let first = store_canonical_snapshot(&store, first_pin, "first-ready-snapshot")
        .await
        .expect("store first ready snapshot");
    let mut registration = store
        .register_stream_barrier(RegisterStreamBarrier {
            target: RuntimeStreamTarget::Conversation(conversation_id),
            generation: WatchGeneration::new(74).expect("ready generation"),
            request: BarrierRequest::Subscribe {
                cursor: StreamCursor::BeforeFirst,
            },
        })
        .await
        .expect("capture exact ready snapshot reference");
    let source = registration
        .take_snapshot_source()
        .expect("ready snapshot must return an exact reference");
    let reference = match source.source() {
        SnapshotBarrierSource::Ready(reference) => reference.clone(),
        SnapshotBarrierSource::Build(_) | SnapshotBarrierSource::Dynamic(_) => {
            panic!("ready snapshot must return an exact reference")
        }
    };
    assert_eq!(reference.snapshot_id, first.snapshot_id);
    assert_eq!(
        reference.target,
        RuntimeStreamTarget::Conversation(conversation_id)
    );
    assert_eq!(reference.base, StreamCursor::BeforeFirst);
    assert_eq!(reference.item_count, first.item_count);
    assert_eq!(reference.logical_bytes, first.payload.len() as u64);
    assert_eq!(reference.content_sha256, first.content_sha256);

    let replacement_pin = store
        .acquire_snapshot_build_source(conversation_id)
        .await
        .expect("capture replacement snapshot base");
    store_canonical_snapshot(&store, replacement_pin, "replacement-ready-snapshot")
        .await
        .expect("replace ready snapshot row");
    let error = store
        .load_conversation_snapshot_by_reference(reference)
        .await
        .expect_err("old exact reference must not resolve to replacement row");
    assert!(matches!(error, RuntimeStoreError::UnknownOrCorruptSchema));

    store
        .release_stream_watch(registration.watch.token())
        .await
        .expect("release ready watch");
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn snapshot_binding_tamper_is_rejected_before_barrier_can_fallback_to_latest_high_water() {
    let root = TestRoot::new("snapshot-binding-live-tamper");
    let keys = MemoryKeyStore::new();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open store");
    let target = conversation(0x60);
    let target_id = target.conversation_id;
    store
        .create_conversation(target)
        .await
        .expect("create snapshot target");
    let replacement = conversation(0x61);
    let replacement_id = replacement.conversation_id;
    store
        .create_conversation(replacement)
        .await
        .expect("create replacement binding target");
    let snapshot_pin = store
        .acquire_snapshot_build_source(target_id)
        .await
        .expect("capture snapshot base");
    store_canonical_snapshot(&store, snapshot_pin, "snapshot-binding-live-tamper")
        .await
        .expect("store ready snapshot");

    let tamper = rusqlite::Connection::open(root.database()).expect("open live tamper connection");
    tamper
        .busy_timeout(Duration::from_secs(1))
        .expect("configure live tamper busy timeout");
    assert_eq!(
        tamper
            .execute(
                "UPDATE snapshots SET conversation_id = ?1
                 WHERE target_scope = 'conversation' AND conversation_id = ?2",
                rusqlite::params![&replacement_id.as_bytes()[..], &target_id.as_bytes()[..]],
            )
            .expect("commit snapshot binding tamper"),
        1
    );
    drop(tamper);

    match store
        .register_stream_barrier(RegisterStreamBarrier {
            target: RuntimeStreamTarget::Conversation(target_id),
            generation: WatchGeneration::new(60).expect("snapshot tamper generation"),
            request: BarrierRequest::Subscribe {
                cursor: StreamCursor::BeforeFirst,
            },
        })
        .await
    {
        Err(RuntimeStoreError::UnknownOrCorruptSchema) => {}
        Err(error) => panic!("expected corrupt snapshot directory, got {error:?}"),
        Ok(registration) => {
            let high_water = registration.high_water;
            let ready_snapshot_base = registration.ready_snapshot_base;
            store
                .release_stream_watch(registration.watch.token())
                .await
                .expect("release incorrectly accepted watch");
            store.shutdown().await.expect("shutdown store after RED");
            panic!(
                "filtered snapshot loader returned Ok/fallback: high_water={high_water:?}, ready_snapshot_base={ready_snapshot_base:?}"
            );
        }
    }
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn snapshot_state_tamper_is_rejected_before_barrier_can_fallback_to_latest_high_water() {
    let root = TestRoot::new("snapshot-state-live-tamper");
    let keys = MemoryKeyStore::new();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open store");
    let target = conversation(0x62);
    let target_id = target.conversation_id;
    store
        .create_conversation(target)
        .await
        .expect("create snapshot target");
    let snapshot_pin = store
        .acquire_snapshot_build_source(target_id)
        .await
        .expect("capture snapshot base");
    store_canonical_snapshot(&store, snapshot_pin, "snapshot-state-live-tamper")
        .await
        .expect("store ready snapshot");

    let tamper = rusqlite::Connection::open(root.database()).expect("open live tamper connection");
    tamper
        .busy_timeout(Duration::from_secs(1))
        .expect("configure live tamper busy timeout");
    tamper
        .execute_batch("PRAGMA ignore_check_constraints = ON;")
        .expect("allow invalid state tamper");
    assert_eq!(
        tamper
            .execute(
                "UPDATE snapshots SET build_state = 'building'
                 WHERE target_scope = 'conversation' AND conversation_id = ?1",
                [&target_id.as_bytes()[..]],
            )
            .expect("commit snapshot state tamper"),
        1
    );
    drop(tamper);

    match store
        .register_stream_barrier(RegisterStreamBarrier {
            target: RuntimeStreamTarget::Conversation(target_id),
            generation: WatchGeneration::new(62).expect("snapshot tamper generation"),
            request: BarrierRequest::Subscribe {
                cursor: StreamCursor::BeforeFirst,
            },
        })
        .await
    {
        Err(RuntimeStoreError::UnknownOrCorruptSchema) => {}
        Err(error) => panic!("expected corrupt snapshot directory, got {error:?}"),
        Ok(registration) => {
            let high_water = registration.high_water;
            let ready_snapshot_base = registration.ready_snapshot_base;
            store
                .release_stream_watch(registration.watch.token())
                .await
                .expect("release incorrectly accepted watch");
            store.shutdown().await.expect("shutdown store after RED");
            panic!(
                "filtered snapshot loader returned Ok/fallback: high_water={high_water:?}, ready_snapshot_base={ready_snapshot_base:?}"
            );
        }
    }
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn snapshot_delete_is_rejected_against_ledger_before_barrier_can_fallback_to_latest_high_water()
 {
    let root = TestRoot::new("snapshot-delete-live-tamper");
    let keys = MemoryKeyStore::new();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open store");
    let target = conversation(0x63);
    let target_id = target.conversation_id;
    store
        .create_conversation(target)
        .await
        .expect("create snapshot target");
    let snapshot_pin = store
        .acquire_snapshot_build_source(target_id)
        .await
        .expect("capture snapshot base");
    store_canonical_snapshot(&store, snapshot_pin, "snapshot-delete-live-tamper")
        .await
        .expect("store ready snapshot");

    let tamper = rusqlite::Connection::open(root.database()).expect("open live tamper connection");
    tamper
        .busy_timeout(Duration::from_secs(1))
        .expect("configure live tamper busy timeout");
    assert_eq!(
        tamper
            .execute(
                "DELETE FROM snapshots
                 WHERE target_scope = 'conversation' AND conversation_id = ?1",
                [&target_id.as_bytes()[..]],
            )
            .expect("commit snapshot delete tamper"),
        1
    );
    drop(tamper);

    match store
        .register_stream_barrier(RegisterStreamBarrier {
            target: RuntimeStreamTarget::Conversation(target_id),
            generation: WatchGeneration::new(63).expect("snapshot tamper generation"),
            request: BarrierRequest::Subscribe {
                cursor: StreamCursor::BeforeFirst,
            },
        })
        .await
    {
        Err(RuntimeStoreError::UnknownOrCorruptSchema) => {}
        Err(error) => panic!("expected corrupt snapshot ledger, got {error:?}"),
        Ok(registration) => {
            let high_water = registration.high_water;
            let ready_snapshot_base = registration.ready_snapshot_base;
            store
                .release_stream_watch(registration.watch.token())
                .await
                .expect("release incorrectly accepted watch");
            store.shutdown().await.expect("shutdown store after RED");
            panic!(
                "deleted snapshot was hidden by fallback: high_water={high_water:?}, ready_snapshot_base={ready_snapshot_base:?}"
            );
        }
    }
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn snapshot_orphan_is_rejected_before_target_snapshot_is_selected() {
    let root = TestRoot::new("snapshot-orphan-live-tamper");
    let keys = MemoryKeyStore::new();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open store");
    let target = conversation(0x64);
    let target_id = target.conversation_id;
    store
        .create_conversation(target)
        .await
        .expect("create snapshot target");
    let snapshot_pin = store
        .acquire_snapshot_build_source(target_id)
        .await
        .expect("capture snapshot base");
    store_canonical_snapshot(&store, snapshot_pin, "snapshot-orphan-live-tamper")
        .await
        .expect("store ready snapshot");

    let tamper = rusqlite::Connection::open(root.database()).expect("open live tamper connection");
    tamper
        .busy_timeout(Duration::from_secs(1))
        .expect("configure live tamper busy timeout");
    tamper
        .execute_batch("PRAGMA foreign_keys = OFF;")
        .expect("disable foreign keys for orphan tamper");
    let orphan_snapshot_id = [0xef_u8; 16];
    let orphan_conversation_id = [0xfe_u8; 16];
    assert_eq!(
        tamper
            .execute(
                "INSERT INTO snapshots (
                     snapshot_id, target_scope, conversation_id, source_build_pin_id,
                     base_cursor, build_state, item_count, logical_snapshot_bytes,
                     content_sha256, sealed_snapshot_sha256, created_at_ms,
                     metadata_token, sealed_snapshot
                 )
                 SELECT ?1, target_scope, ?2, source_build_pin_id,
                        base_cursor, build_state, item_count, logical_snapshot_bytes,
                        content_sha256, sealed_snapshot_sha256, created_at_ms,
                        metadata_token, sealed_snapshot
                 FROM snapshots
                 WHERE target_scope = 'conversation' AND conversation_id = ?3",
                rusqlite::params![
                    &orphan_snapshot_id[..],
                    &orphan_conversation_id[..],
                    &target_id.as_bytes()[..]
                ],
            )
            .expect("commit orphan snapshot tamper"),
        1
    );
    drop(tamper);

    match store
        .register_stream_barrier(RegisterStreamBarrier {
            target: RuntimeStreamTarget::Conversation(target_id),
            generation: WatchGeneration::new(64).expect("snapshot tamper generation"),
            request: BarrierRequest::Subscribe {
                cursor: StreamCursor::BeforeFirst,
            },
        })
        .await
    {
        Err(RuntimeStoreError::UnknownOrCorruptSchema) => {}
        Err(error) => panic!("expected corrupt snapshot directory, got {error:?}"),
        Ok(registration) => {
            let selected_base = registration.ready_snapshot_base;
            store
                .release_stream_watch(registration.watch.token())
                .await
                .expect("release incorrectly accepted watch");
            store.shutdown().await.expect("shutdown store after RED");
            panic!(
                "target snapshot was selected before orphan authentication: ready_snapshot_base={selected_base:?}"
            );
        }
    }
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn authenticated_base_newer_than_historical_parent_cut_is_rejected() {
    let root = TestRoot::new("snapshot-authenticated-semantic-mix");
    let keys = MemoryKeyStore::new();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open store");
    let target = conversation(0x6a);
    let target_id = target.conversation_id;
    store
        .create_conversation(target)
        .await
        .expect("create semantic mix target");
    let command_id = accept_one(&store, target_id).await;

    let (historical_parent, historical_retention) = {
        let history =
            rusqlite::Connection::open(root.database()).expect("open historical cut connection");
        let parent = history
            .query_row(
                "SELECT adapter_state_key, catalog_revision, command_high_water,
                        event_high_water, lifecycle, created_at_ms, updated_at_ms,
                        accepted_count, metadata_token, sealed_descriptor
                 FROM conversations WHERE conversation_id = ?1",
                [&target_id.as_bytes()[..]],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, i64>(6)?,
                        row.get::<_, i64>(7)?,
                        row.get::<_, Vec<u8>>(8)?,
                        row.get::<_, Vec<u8>>(9)?,
                    ))
                },
            )
            .expect("capture authenticated historical parent");
        let retention = history
            .query_row(
                "SELECT oldest_retained_event_seq, indexed_through_event_seq,
                        retained_event_count, retained_logical_bytes, range_digest,
                        metadata_token
                 FROM event_retention WHERE conversation_id = ?1",
                [&target_id.as_bytes()[..]],
                |row| {
                    Ok((
                        row.get::<_, Option<String>>(0)?,
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, Vec<u8>>(4)?,
                        row.get::<_, Vec<u8>>(5)?,
                    ))
                },
            )
            .expect("capture authenticated historical retention");
        (parent, retention)
    };

    store
        .terminate_accepted_command(TerminateAcceptedCommand {
            conversation_id: target_id,
            command_id,
            expected_owner: owner(0x90),
            reason: AcceptedTerminationReason::Canceled,
        })
        .await
        .expect("advance event high-water");
    let snapshot_pin = store
        .acquire_snapshot_build_source(target_id)
        .await
        .expect("capture event-zero snapshot base");
    store_canonical_snapshot(
        &store,
        snapshot_pin,
        "authenticated snapshot from newer cut",
    )
    .await
    .expect("store authenticated newer snapshot");

    let tamper = rusqlite::Connection::open(root.database()).expect("open mix connection");
    tamper
        .busy_timeout(Duration::from_secs(1))
        .expect("configure mix busy timeout");
    assert_eq!(
        tamper
            .execute(
                "UPDATE conversations
                 SET adapter_state_key = ?1, catalog_revision = ?2,
                     command_high_water = ?3, event_high_water = ?4,
                     lifecycle = ?5, created_at_ms = ?6, updated_at_ms = ?7,
                     accepted_count = ?8, metadata_token = ?9, sealed_descriptor = ?10
                 WHERE conversation_id = ?11",
                rusqlite::params![
                    &historical_parent.0,
                    &historical_parent.1,
                    historical_parent.2.as_deref(),
                    historical_parent.3.as_deref(),
                    &historical_parent.4,
                    historical_parent.5,
                    historical_parent.6,
                    historical_parent.7,
                    &historical_parent.8,
                    &historical_parent.9,
                    &target_id.as_bytes()[..],
                ],
            )
            .expect("restore authenticated historical parent"),
        1
    );
    assert_eq!(
        tamper
            .execute(
                "UPDATE event_retention
                 SET oldest_retained_event_seq = ?1, indexed_through_event_seq = ?2,
                     retained_event_count = ?3, retained_logical_bytes = ?4,
                     range_digest = ?5, metadata_token = ?6
                 WHERE conversation_id = ?7",
                rusqlite::params![
                    historical_retention.0.as_deref(),
                    historical_retention.1.as_deref(),
                    historical_retention.2,
                    historical_retention.3,
                    &historical_retention.4,
                    &historical_retention.5,
                    &target_id.as_bytes()[..],
                ],
            )
            .expect("restore authenticated historical retention"),
        1
    );
    drop(tamper);

    match store
        .register_stream_barrier(RegisterStreamBarrier {
            target: RuntimeStreamTarget::Conversation(target_id),
            generation: WatchGeneration::new(70).expect("semantic mix generation"),
            request: BarrierRequest::Subscribe {
                cursor: StreamCursor::BeforeFirst,
            },
        })
        .await
    {
        Err(RuntimeStoreError::UnknownOrCorruptSchema) => {}
        Err(error) => panic!("expected corrupt snapshot semantic mix, got {error:?}"),
        Ok(registration) => {
            let decision = registration.decision;
            store
                .release_stream_watch(registration.watch.token())
                .await
                .expect("release incorrectly accepted semantic mix watch");
            panic!("authenticated snapshot base newer than parent was accepted: {decision:?}");
        }
    }
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn directory_prepare_failure_remains_sqlite_store_unavailable() {
    let root = TestRoot::new("snapshot-directory-sqlite-error");
    let keys = MemoryKeyStore::new();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open store");
    let tamper =
        rusqlite::Connection::open(root.database()).expect("open schema failure connection");
    tamper
        .execute_batch("DROP TABLE snapshots;")
        .expect("drop snapshot directory");
    drop(tamper);

    match store
        .register_stream_barrier(RegisterStreamBarrier {
            target: RuntimeStreamTarget::Catalog,
            generation: WatchGeneration::new(71).expect("sqlite failure generation"),
            request: BarrierRequest::Subscribe {
                cursor: StreamCursor::BeforeFirst,
            },
        })
        .await
    {
        Err(RuntimeStoreError::Sqlite(_)) => {}
        Err(error) => panic!("expected SQLite store-unavailable error, got {error:?}"),
        Ok(registration) => {
            store
                .release_stream_watch(registration.watch.token())
                .await
                .expect("release incorrectly accepted missing-directory watch");
            panic!("missing snapshot table was accepted");
        }
    }
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn directory_parent_authentication_does_not_open_sealed_descriptor() {
    let root = TestRoot::new("directory-parent-metadata-only");
    let keys = MemoryKeyStore::new();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open store");
    let target = conversation(0x6b);
    let target_id = target.conversation_id;
    store
        .create_conversation(target)
        .await
        .expect("create metadata-only parent");
    let snapshot_pin = store
        .acquire_snapshot_build_source(target_id)
        .await
        .expect("capture parent snapshot base");
    store_canonical_snapshot(&store, snapshot_pin, "metadata-only parent snapshot")
        .await
        .expect("store parent snapshot");

    let tamper =
        rusqlite::Connection::open(root.database()).expect("open descriptor tamper connection");
    assert_eq!(
        tamper
            .execute(
                "UPDATE conversations
                 SET sealed_descriptor = zeroblob(length(sealed_descriptor))
                 WHERE conversation_id = ?1",
                [&target_id.as_bytes()[..]],
            )
            .expect("tamper unrelated sealed descriptor"),
        1
    );
    drop(tamper);

    let registration = store
        .register_stream_barrier(RegisterStreamBarrier {
            target: RuntimeStreamTarget::Catalog,
            generation: WatchGeneration::new(72).expect("metadata-only generation"),
            request: BarrierRequest::Subscribe {
                cursor: StreamCursor::BeforeFirst,
            },
        })
        .await
        .expect("directory parent HWM authentication must not open sealed descriptor");
    store
        .release_stream_watch(registration.watch.token())
        .await
        .expect("release metadata-only directory watch");
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn publication_binding_tamper_is_rejected_before_barrier_can_fallback_to_default_committed_cut()
 {
    let root = TestRoot::new("publication-binding-live-tamper");
    let keys = MemoryKeyStore::new();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open store");
    let conversation = conversation(0x65);
    let conversation_id = conversation.conversation_id;
    store
        .create_conversation(conversation)
        .await
        .expect("create catalog revision zero and valid replacement parent");
    let publication_stream_id = [0x90_u8; 16];
    let generation = [0x91_u8; 16];
    store
        .create_publication_stream(
            publication_stream_id,
            PublicationScope::Catalog,
            [0x92; 16],
            generation,
        )
        .await
        .expect("create active catalog publication stream");
    let frozen = store
        .freeze_publication(FreezePublicationRequest {
            publication_id: [0x93; 16],
            publication_stream_id,
            generation,
            counter_scope_token: [0x94; 32],
            sender_counter: 1,
            inner_after: None,
            inner_through: Some(0),
            payload_kind: PublicationPayloadKind::Catalog,
            blob: b"publication-binding-live-tamper".to_vec(),
        })
        .await
        .expect("freeze catalog publication");
    store
        .acknowledge_publication_commit(
            publication_stream_id,
            generation,
            frozen.stream_seq,
            frozen.blob_sha256,
        )
        .await
        .expect("commit non-default Relay cut");

    let tamper = rusqlite::Connection::open(root.database()).expect("open live tamper connection");
    tamper
        .busy_timeout(Duration::from_secs(1))
        .expect("configure live tamper busy timeout");
    assert_eq!(
        tamper
            .execute(
                "UPDATE publication_streams
                 SET scope = 'conversation', conversation_id = ?1
                 WHERE publication_stream_id = ?2",
                rusqlite::params![&conversation_id.as_bytes()[..], &publication_stream_id[..]],
            )
            .expect("commit publication binding tamper"),
        1
    );
    drop(tamper);

    match store
        .register_stream_barrier(RegisterStreamBarrier {
            target: RuntimeStreamTarget::Catalog,
            generation: WatchGeneration::new(65).expect("publication tamper generation"),
            request: BarrierRequest::Subscribe {
                cursor: StreamCursor::BeforeFirst,
            },
        })
        .await
    {
        Err(RuntimeStoreError::UnknownOrCorruptSchema) => {}
        Err(error) => panic!("expected corrupt publication directory, got {error:?}"),
        Ok(registration) => {
            let committed = registration.relay_committed;
            store
                .release_stream_watch(registration.watch.token())
                .await
                .expect("release incorrectly accepted watch");
            store.shutdown().await.expect("shutdown store after RED");
            panic!("filtered publication loader returned Ok/default cut: {committed:?}");
        }
    }
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn publication_state_tamper_is_rejected_before_barrier_can_fallback_to_default_committed_cut()
{
    let root = TestRoot::new("publication-state-live-tamper");
    let keys = MemoryKeyStore::new();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open store");
    store
        .create_conversation(conversation(0x66))
        .await
        .expect("create catalog revision zero");
    let publication_stream_id = [0x95_u8; 16];
    let generation = [0x96_u8; 16];
    store
        .create_publication_stream(
            publication_stream_id,
            PublicationScope::Catalog,
            [0x97; 16],
            generation,
        )
        .await
        .expect("create active catalog publication stream");
    let frozen = store
        .freeze_publication(FreezePublicationRequest {
            publication_id: [0x98; 16],
            publication_stream_id,
            generation,
            counter_scope_token: [0x99; 32],
            sender_counter: 1,
            inner_after: None,
            inner_through: Some(0),
            payload_kind: PublicationPayloadKind::Catalog,
            blob: b"publication-state-live-tamper".to_vec(),
        })
        .await
        .expect("freeze catalog publication");
    store
        .acknowledge_publication_commit(
            publication_stream_id,
            generation,
            frozen.stream_seq,
            frozen.blob_sha256,
        )
        .await
        .expect("commit non-default Relay cut");

    let tamper = rusqlite::Connection::open(root.database()).expect("open live tamper connection");
    tamper
        .busy_timeout(Duration::from_secs(1))
        .expect("configure live tamper busy timeout");
    assert_eq!(
        tamper
            .execute(
                "UPDATE publication_streams SET state = 'retired'
                 WHERE publication_stream_id = ?1",
                [&publication_stream_id[..]],
            )
            .expect("commit publication state tamper"),
        1
    );
    drop(tamper);

    match store
        .register_stream_barrier(RegisterStreamBarrier {
            target: RuntimeStreamTarget::Catalog,
            generation: WatchGeneration::new(66).expect("publication tamper generation"),
            request: BarrierRequest::Subscribe {
                cursor: StreamCursor::BeforeFirst,
            },
        })
        .await
    {
        Err(RuntimeStoreError::UnknownOrCorruptSchema) => {}
        Err(error) => panic!("expected corrupt publication directory, got {error:?}"),
        Ok(registration) => {
            let committed = registration.relay_committed;
            store
                .release_stream_watch(registration.watch.token())
                .await
                .expect("release incorrectly accepted watch");
            store.shutdown().await.expect("shutdown store after RED");
            panic!("filtered publication loader returned Ok/default cut: {committed:?}");
        }
    }
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn publication_delete_is_rejected_against_ledger_before_barrier_can_fallback_to_default_committed_cut()
 {
    let root = TestRoot::new("publication-delete-live-tamper");
    let keys = MemoryKeyStore::new();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open store");
    let publication_stream_id = [0x9a_u8; 16];
    store
        .create_publication_stream(
            publication_stream_id,
            PublicationScope::Catalog,
            [0x9b; 16],
            [0x9c; 16],
        )
        .await
        .expect("create active catalog publication stream");

    let tamper = rusqlite::Connection::open(root.database()).expect("open live tamper connection");
    tamper
        .busy_timeout(Duration::from_secs(1))
        .expect("configure live tamper busy timeout");
    assert_eq!(
        tamper
            .execute(
                "DELETE FROM publication_streams WHERE publication_stream_id = ?1",
                [&publication_stream_id[..]],
            )
            .expect("commit publication stream delete tamper"),
        1
    );
    drop(tamper);

    match store
        .register_stream_barrier(RegisterStreamBarrier {
            target: RuntimeStreamTarget::Catalog,
            generation: WatchGeneration::new(67).expect("publication tamper generation"),
            request: BarrierRequest::Subscribe {
                cursor: StreamCursor::BeforeFirst,
            },
        })
        .await
    {
        Err(RuntimeStoreError::UnknownOrCorruptSchema) => {}
        Err(error) => panic!("expected corrupt publication ledger, got {error:?}"),
        Ok(registration) => {
            let committed = registration.relay_committed;
            store
                .release_stream_watch(registration.watch.token())
                .await
                .expect("release incorrectly accepted watch");
            store.shutdown().await.expect("shutdown store after RED");
            panic!("deleted publication stream was hidden by default cut: {committed:?}");
        }
    }
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn publication_orphan_outbox_is_rejected_before_active_target_is_selected() {
    let root = TestRoot::new("publication-orphan-outbox-live-tamper");
    let keys = MemoryKeyStore::new();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open store");
    store
        .create_conversation(conversation(0x68))
        .await
        .expect("create catalog revision zero");
    let publication_stream_id = [0x9d_u8; 16];
    let generation = [0x9e_u8; 16];
    let publication_id = [0x9f_u8; 16];
    store
        .create_publication_stream(
            publication_stream_id,
            PublicationScope::Catalog,
            [0xa0; 16],
            generation,
        )
        .await
        .expect("create active catalog publication stream");
    store
        .freeze_publication(FreezePublicationRequest {
            publication_id,
            publication_stream_id,
            generation,
            counter_scope_token: [0xa1; 32],
            sender_counter: 1,
            inner_after: None,
            inner_through: Some(0),
            payload_kind: PublicationPayloadKind::Catalog,
            blob: b"publication-orphan-outbox-live-tamper".to_vec(),
        })
        .await
        .expect("freeze publication outbox row");

    let tamper = rusqlite::Connection::open(root.database()).expect("open live tamper connection");
    tamper
        .busy_timeout(Duration::from_secs(1))
        .expect("configure live tamper busy timeout");
    tamper
        .execute_batch("PRAGMA foreign_keys = OFF;")
        .expect("disable foreign keys for orphan outbox tamper");
    let orphan_stream_id = [0xa2_u8; 16];
    let orphan_generation = [0xa3_u8; 16];
    assert_eq!(
        tamper
            .execute(
                "UPDATE publication_outbox
                 SET publication_stream_id = ?1, generation = ?2
                 WHERE publication_id = ?3",
                rusqlite::params![
                    &orphan_stream_id[..],
                    &orphan_generation[..],
                    &publication_id[..]
                ],
            )
            .expect("commit orphan publication outbox tamper"),
        1
    );
    drop(tamper);

    match store
        .register_stream_barrier(RegisterStreamBarrier {
            target: RuntimeStreamTarget::Catalog,
            generation: WatchGeneration::new(68).expect("publication tamper generation"),
            request: BarrierRequest::Subscribe {
                cursor: StreamCursor::BeforeFirst,
            },
        })
        .await
    {
        Err(RuntimeStoreError::UnknownOrCorruptSchema) => {}
        Err(error) => panic!("expected corrupt publication directory, got {error:?}"),
        Ok(registration) => {
            let committed = registration.relay_committed;
            store
                .release_stream_watch(registration.watch.token())
                .await
                .expect("release incorrectly accepted watch");
            store.shutdown().await.expect("shutdown store after RED");
            panic!(
                "active publication target was selected before orphan outbox authentication: {committed:?}"
            );
        }
    }
    store.shutdown().await.expect("shutdown store");
}
