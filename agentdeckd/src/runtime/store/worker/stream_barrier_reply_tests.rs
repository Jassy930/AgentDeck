use std::fs;
use std::sync::atomic::AtomicU64;

use agentdeck_protocol::AgentKind;
use agentdeck_protocol::runtime::StreamCursor;

use super::*;
use crate::runtime::backfill::BarrierDecision;
use crate::runtime::events::{RelayCommittedCut, StoreCleanup, WatchGeneration};
use crate::runtime::store::{ConversationDescriptor, NewConversation, RuntimeIdKind};
use crate::security::{MemoryKeyStore, load_or_create_storage_kek};

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

struct TestRoot(PathBuf);

impl TestRoot {
    fn new() -> Self {
        let sequence = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "agentdeckd-runtime-barrier-reply-unit-{}-{sequence}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).expect("create isolated barrier reply root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("secure barrier reply root");
        }
        Self(path)
    }

    fn open_state(&self) -> sqlite::RuntimeSqlite {
        self.open_config_state().1
    }

    fn open_config_state(&self) -> (RuntimeStoreConfig, sqlite::RuntimeSqlite) {
        let config = RuntimeStoreConfig::new(self.0.join("runtime.db"));
        let keys = MemoryKeyStore::new();
        let storage_kek = load_or_create_storage_kek(&keys, &self.0.join("key-state.db"))
            .expect("create barrier reply StorageKEK");
        let state = sqlite::open(&config, storage_kek).expect("open barrier reply RuntimeSqlite");
        (config, state)
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn canceled_barrier_caller_releases_registration_and_restores_watch_capacity() {
    let root = TestRoot::new();
    let state = root.open_state();
    let mut hub = StoreCommitHub::default();
    let target = RuntimeStreamTarget::Catalog;
    let (watch, ()) = hub
        .register_then_capture(target, WatchGeneration::new(1).expect("generation"), |_| {
            Ok::<_, ()>((StreamCursor::BeforeFirst, ()))
        })
        .expect("register first watch");
    let stale_token = watch.token();
    let registration = StreamBarrierRegistration {
        target,
        high_water: StreamCursor::BeforeFirst,
        retained_floor: None,
        ready_snapshot_base: None,
        snapshot_source: None,
        snapshot_cleanup: None,
        catalog_snapshot_source: None,
        backfill_pin: None,
        backfill_cleanup: None,
        relay_committed: RelayCommittedCut::default(),
        decision: BarrierDecision::SyncComplete {
            through: StreamCursor::BeforeFirst,
            committed_outer: StreamCursor::BeforeFirst,
        },
        watch,
    };
    let (reply, caller) =
        oneshot::channel::<Result<StreamBarrierRegistration, RuntimeStoreError>>();
    drop(caller);

    send_stream_barrier_reply(reply, Ok(registration), &state, &mut hub);

    assert!(
        hub.watched_targets().is_empty(),
        "global/target watch state"
    );
    assert!(!hub.is_current(&stale_token), "canceled token is stale");
    let replacement = hub
        .register(
            target,
            WatchGeneration::new(2).expect("replacement generation"),
        )
        .expect("watch capacity is reusable");
    assert!(hub.is_current(&replacement.token()));
    drop(state);
}

#[test]
fn successful_send_then_unpolled_receiver_drop_releases_watch_and_build_pin() {
    let root = TestRoot::new();
    let state = root.open_state();
    let (cleanup_tx, mut cleanup_rx) = mpsc::unbounded_channel();
    let mut hub = StoreCommitHub::with_cleanup_sender(cleanup_tx);
    let conversation_id =
        RuntimeId::from_bytes(RuntimeIdKind::Conversation, [0x71; 16]).expect("conversation id");
    let target = RuntimeStreamTarget::Conversation(conversation_id);
    let (watch, ()) = hub
        .register_then_capture(target, WatchGeneration::new(3).expect("generation"), |_| {
            Ok::<_, ()>((StreamCursor::BeforeFirst, ()))
        })
        .expect("register build watch");
    let pin = stream::acquire_snapshot_build_pin_at(&state.connection, conversation_id, None, 1)
        .expect("create exact-H build pin");
    let snapshot_cleanup = watch.snapshot_build_pin_cleanup(pin.clone());
    let registration = StreamBarrierRegistration {
        target,
        high_water: StreamCursor::BeforeFirst,
        retained_floor: None,
        ready_snapshot_base: None,
        snapshot_source: Some(SnapshotBarrierSource::Build(pin.clone())),
        snapshot_cleanup: Some(snapshot_cleanup),
        catalog_snapshot_source: None,
        backfill_pin: None,
        backfill_cleanup: None,
        relay_committed: RelayCommittedCut::default(),
        decision: BarrierDecision::Snapshot {
            base: StreamCursor::BeforeFirst,
            through: StreamCursor::BeforeFirst,
            committed_outer: StreamCursor::BeforeFirst,
        },
        watch,
    };
    let (reply, caller) =
        oneshot::channel::<Result<StreamBarrierRegistration, RuntimeStoreError>>();

    assert!(reply.send(Ok(registration)).is_ok());
    drop(caller);
    for _ in 0..2 {
        let cleanup = cleanup_rx
            .try_recv()
            .expect("watch and build pin each enqueue exact cleanup");
        apply_store_cleanup(&state, &mut hub, cleanup);
    }

    assert!(hub.watched_targets().is_empty());
    assert!(matches!(
        stream::validate_snapshot_build_pin(&state.connection, &pin, 1),
        Err(RuntimeStoreError::InvalidStateTransition)
    ));
    drop(state);
}

#[test]
fn successful_backfill_pin_send_then_unpolled_receiver_drop_releases_exact_pin() {
    // 威胁场景：worker 已把 live backfill pin 成功放进 oneshot，但同一时刻的
    // unsubscribe/disconnect 让 caller 尚未 poll 就丢弃 receiver；裸 pin 会占住
    // 全局 TEMP pin 配额直到 TTL，managed reply 必须在 channel slot drop 时回收。
    let root = TestRoot::new();
    let state = root.open_state();
    let (cleanup_tx, mut cleanup_rx) = mpsc::unbounded_channel();
    let mut hub = StoreCommitHub::with_cleanup_sender(cleanup_tx.clone());
    let pin_id = [0x81; 16];
    let first = crate::runtime::store::sequence::encode_sequence(0);
    state
        .connection
        .execute(
            "INSERT INTO temp.active_stream_pins (
                 pin_id, scope, target_id, first_seq, through_seq,
                 next_after_seq, expires_at_ms, state
             ) VALUES (?1, 'catalog', NULL, ?2, ?2, NULL, 10000, 'active')",
            rusqlite::params![&pin_id[..], &first],
        )
        .expect("insert direct backfill pin");
    let pin = RuntimeBackfillPin {
        pin_id,
        target: RuntimeBackfillTarget::Catalog,
        after: None,
        through: 0,
        expires_at_ms: 10_000,
    };
    let (reply, caller) = oneshot::channel();

    stream_pipeline::send_backfill_pin_reply(
        reply,
        Ok(RuntimeBackfillPlan::Pinned(pin)),
        &cleanup_tx,
    );
    assert!(
        cleanup_rx.try_recv().is_err(),
        "receiver still owns managed pin"
    );
    drop(caller);

    let cleanup = cleanup_rx
        .try_recv()
        .expect("unpolled managed reply enqueues exact backfill cleanup");
    assert!(matches!(cleanup, StoreCleanup::BackfillPin(id) if id == pin_id));
    apply_store_cleanup(&state, &mut hub, cleanup);
    let remaining: i64 = state
        .connection
        .query_row(
            "SELECT COUNT(*) FROM temp.active_stream_pins WHERE pin_id = ?1",
            [&pin_id[..]],
            |row| row.get(0),
        )
        .expect("count direct backfill pin after cleanup");
    assert_eq!(remaining, 0);
}

#[test]
fn successful_snapshot_pin_send_then_unpolled_receiver_drop_releases_exact_pin() {
    // 威胁场景与 backfill 同构：send 成功不代表 caller 已取得 ownership；task abort
    // 可以直接丢弃 oneshot slot，因此 snapshot pin cleanup 必须在 send 前进入 source。
    let root = TestRoot::new();
    let state = root.open_state();
    let (cleanup_tx, mut cleanup_rx) = mpsc::unbounded_channel();
    let mut hub = StoreCommitHub::with_cleanup_sender(cleanup_tx.clone());
    let conversation_id =
        RuntimeId::from_bytes(RuntimeIdKind::Conversation, [0x82; 16]).expect("conversation id");
    let pin = stream::acquire_snapshot_build_pin_at(&state.connection, conversation_id, None, 1)
        .expect("create direct snapshot build pin");
    let (reply, caller) = oneshot::channel();

    send_snapshot_build_pin_reply(
        reply,
        Ok(SnapshotBarrierSource::Build(pin.clone())),
        &state,
        &mut hub,
        &cleanup_tx,
    );
    assert!(
        cleanup_rx.try_recv().is_err(),
        "receiver still owns managed pin"
    );
    drop(caller);

    let cleanup = cleanup_rx
        .try_recv()
        .expect("unpolled managed reply enqueues exact snapshot cleanup");
    assert!(matches!(cleanup, StoreCleanup::SnapshotBuildPin(ref value) if value == &pin));
    apply_store_cleanup(&state, &mut hub, cleanup);
    assert!(matches!(
        stream::validate_snapshot_build_pin(&state.connection, &pin, 1),
        Err(RuntimeStoreError::InvalidStateTransition)
    ));
}

#[test]
fn authenticated_native_origin_rejects_stale_ready_reference() {
    let conversation_id =
        RuntimeId::from_bytes(RuntimeIdKind::Conversation, [0x83; 16]).expect("conversation id");
    let ready = super::super::snapshot::ReadySnapshotReference {
        snapshot_id: [0x84; 16],
        target: RuntimeStreamTarget::Conversation(conversation_id),
        base: StreamCursor::BeforeFirst,
        item_count: 1,
        logical_bytes: 1,
        content_sha256: [0x85; 32],
    };
    assert!(matches!(
        stream_pipeline::validate_ready_snapshot_origin(true, Some(&ready)),
        Err(RuntimeStoreError::UnknownOrCorruptSchema)
    ));
    stream_pipeline::validate_ready_snapshot_origin(true, None)
        .expect("native Dynamic path without Ready remains valid");
    stream_pipeline::validate_ready_snapshot_origin(false, Some(&ready))
        .expect("managed parent may use authenticated Ready");
}

#[test]
fn taking_snapshot_source_moves_build_pin_cleanup_ownership() {
    let root = TestRoot::new();
    let state = root.open_state();
    let (cleanup_tx, mut cleanup_rx) = mpsc::unbounded_channel();
    let mut hub = StoreCommitHub::with_cleanup_sender(cleanup_tx);
    let conversation_id =
        RuntimeId::from_bytes(RuntimeIdKind::Conversation, [0x72; 16]).expect("conversation id");
    let target = RuntimeStreamTarget::Conversation(conversation_id);
    let (watch, ()) = hub
        .register_then_capture(target, WatchGeneration::new(4).expect("generation"), |_| {
            Ok::<_, ()>((StreamCursor::BeforeFirst, ()))
        })
        .expect("register owned build watch");
    let pin = stream::acquire_snapshot_build_pin_at(&state.connection, conversation_id, None, 1)
        .expect("create owned exact-H build pin");
    let snapshot_cleanup = watch.snapshot_build_pin_cleanup(pin.clone());
    let mut registration = StreamBarrierRegistration {
        target,
        high_water: StreamCursor::BeforeFirst,
        retained_floor: None,
        ready_snapshot_base: None,
        snapshot_source: Some(SnapshotBarrierSource::Build(pin.clone())),
        snapshot_cleanup: Some(snapshot_cleanup),
        catalog_snapshot_source: None,
        backfill_pin: None,
        backfill_cleanup: None,
        relay_committed: RelayCommittedCut::default(),
        decision: BarrierDecision::Snapshot {
            base: StreamCursor::BeforeFirst,
            through: StreamCursor::BeforeFirst,
            committed_outer: StreamCursor::BeforeFirst,
        },
        watch,
    };

    let source = registration
        .take_snapshot_source()
        .expect("take managed build source");
    assert!(matches!(
        source.source(),
        SnapshotBarrierSource::Build(source_pin) if source_pin == &pin
    ));
    drop(registration);
    apply_store_cleanup(
        &state,
        &mut hub,
        cleanup_rx.try_recv().expect("watch cleanup remains armed"),
    );
    assert!(
        cleanup_rx.try_recv().is_err(),
        "managed source still owns build cleanup"
    );
    stream::validate_snapshot_build_pin(&state.connection, &pin, 1)
        .expect("managed source keeps the exact build pin live");
    drop(source);
    apply_store_cleanup(
        &state,
        &mut hub,
        cleanup_rx
            .try_recv()
            .expect("managed source drop enqueues exact build cleanup"),
    );
    assert!(matches!(
        stream::validate_snapshot_build_pin(&state.connection, &pin, 1),
        Err(RuntimeStoreError::InvalidStateTransition)
    ));
    drop(state);
}

#[test]
fn only_snapshot_decision_requires_snapshot_source() {
    let before_first = StreamCursor::BeforeFirst;
    let at_zero = StreamCursor::At(0);
    assert!(decision_requires_snapshot_source(
        &BarrierDecision::Snapshot {
            base: before_first,
            through: at_zero,
            committed_outer: before_first,
        }
    ));
    assert!(!decision_requires_snapshot_source(
        &BarrierDecision::Backfill {
            after: before_first,
            through: at_zero,
            committed_outer: before_first,
        }
    ));
    assert!(!decision_requires_snapshot_source(
        &BarrierDecision::SyncComplete {
            through: before_first,
            committed_outer: before_first,
        }
    ));
    assert!(!decision_requires_snapshot_source(
        &BarrierDecision::NeedSnapshot { base: at_zero }
    ));
    assert!(!decision_requires_snapshot_source(
        &BarrierDecision::CursorAhead {
            high_water: before_first,
        }
    ));
}

#[test]
fn sync_complete_does_not_consume_snapshot_pin_quota() {
    let root = TestRoot::new();
    let (config, mut state) = root.open_config_state();
    let conversation_id =
        RuntimeId::from_bytes(RuntimeIdKind::Conversation, [0x73; 16]).expect("conversation id");
    let descriptor = ConversationDescriptor {
        agent_kind: AgentKind::Codex,
        title: Some("barrier quota".to_owned()),
        cwd: PathBuf::from("/tmp/barrier-quota"),
    };
    let input = NewConversation {
        conversation_id,
        adapter_state_key: RuntimeId::from_bytes(RuntimeIdKind::AdapterState, [0x74; 16])
            .expect("adapter state key"),
        descriptor: descriptor.clone(),
    };
    let descriptor_bytes =
        journal::canonical_conversation_descriptor(&descriptor).expect("descriptor bytes");
    journal::create_conversation(
        &mut state,
        &config,
        input,
        descriptor_bytes,
        &mut CommandStreamEffects::default(),
    )
    .expect("create empty conversation");
    for value in 1..=stream::MAX_ACTIVE_BACKFILL_PINS {
        let mut pin_id = [0_u8; 16];
        pin_id[8..].copy_from_slice(&value.to_be_bytes());
        state
            .connection
            .execute(
                "INSERT INTO temp.active_stream_pins (
                         pin_id, scope, target_id, first_seq, through_seq,
                         next_after_seq, expires_at_ms, state
                     ) VALUES (?1, 'snapshot', ?2, NULL, NULL, NULL, ?3, 'active')",
                rusqlite::params![&pin_id[..], &conversation_id.as_bytes()[..], i64::MAX,],
            )
            .expect("fill snapshot pin quota");
    }
    let mut hub = StoreCommitHub::default();
    let mut registration = register_stream_barrier_on_worker(
        &state,
        &config,
        &mut hub,
        RegisterStreamBarrier {
            target: RuntimeStreamTarget::Conversation(conversation_id),
            generation: WatchGeneration::new(5).expect("generation"),
            request: crate::runtime::backfill::BarrierRequest::Backfill {
                after: StreamCursor::BeforeFirst,
            },
        },
    )
    .expect("SyncComplete does not need snapshot pin quota");
    assert!(matches!(
        registration.decision,
        BarrierDecision::SyncComplete { .. }
    ));
    assert!(registration.take_snapshot_source().is_none());
    assert!(hub.release(&registration.watch.token()));
    drop(state);
}

#[test]
fn canceled_barrier_caller_after_successful_send_releases_drop_lease() {
    let (cleanup_tx, mut cleanup_rx) = mpsc::unbounded_channel();
    let mut hub = StoreCommitHub::with_cleanup_sender(cleanup_tx);
    let target = RuntimeStreamTarget::Catalog;
    let (watch, ()) = hub
        .register_then_capture(target, WatchGeneration::new(1).expect("generation"), |_| {
            Ok::<_, ()>((StreamCursor::BeforeFirst, ()))
        })
        .expect("register first watch");
    let stale_token = watch.token();
    let registration = StreamBarrierRegistration {
        target,
        high_water: StreamCursor::BeforeFirst,
        retained_floor: None,
        ready_snapshot_base: None,
        snapshot_source: None,
        snapshot_cleanup: None,
        catalog_snapshot_source: None,
        backfill_pin: None,
        backfill_cleanup: None,
        relay_committed: RelayCommittedCut::default(),
        decision: BarrierDecision::SyncComplete {
            through: StreamCursor::BeforeFirst,
            committed_outer: StreamCursor::BeforeFirst,
        },
        watch,
    };
    let (reply, caller) =
        oneshot::channel::<Result<StreamBarrierRegistration, RuntimeStoreError>>();

    assert!(
        reply.send(Ok(registration)).is_ok(),
        "registration enters the unpolled oneshot slot"
    );
    drop(caller);

    let cleanup = cleanup_rx
        .try_recv()
        .expect("dropping the unpolled reply enqueues the exact watch token");
    let StoreCleanup::Watch(cleanup_token) = cleanup else {
        panic!("catalog registration only owns watch cleanup");
    };
    assert_eq!(cleanup_token, stale_token);
    assert!(hub.release(&cleanup_token), "worker applies Drop cleanup");
    assert!(
        hub.watched_targets().is_empty(),
        "global/target watch state"
    );
    assert!(!hub.is_current(&stale_token), "canceled token is stale");
    let replacement = hub
        .register(
            target,
            WatchGeneration::new(2).expect("replacement generation"),
        )
        .expect("watch capacity is reusable");
    assert!(hub.is_current(&replacement.token()));
}
