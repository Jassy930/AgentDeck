use super::key_transition::*;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::runtime::events::CommandStreamEffects;
use crate::runtime::model::{
    ConversationDescriptor, NewConversation, RuntimeCommitOperation, RuntimeStoreConfig,
    RuntimeStoreError, RuntimeStoreFaultInjector, RuntimeStoreOperation,
};
use crate::security::{MemoryKeyStore, load_or_create_storage_kek};
use agentdeck_protocol::e2ee::{KeyId, KeyPurpose, KeyUpdateSetV1, KeyUpdateV1};
use agentdeck_protocol::relay_v2::auth::Ed25519Signature;
use agentdeck_protocol::relay_v2::id::{
    DeviceRouteId, KeyDirectoryRevision as RelayKeyDirectoryRevision, StreamRouteId,
};
use agentdeck_protocol::runtime::sync::StreamCursor;
use tempfile::TempDir;

use super::identity::{RuntimeId, RuntimeIdKind};

fn recipient(route: u8, serial: u64) -> KeyTransitionRecipient {
    KeyTransitionRecipient {
        device_route: [route; 16],
        grant_serial: serial,
    }
}

fn maximal_canonical_key_update_set() -> Vec<u8> {
    let device_route = DeviceRouteId::from_bytes([0x22; 16]);
    let signed_update = |purpose, stream_route| KeyUpdateV1 {
        key_directory_revision: RelayKeyDirectoryRevision::new(12),
        key_id: KeyId { purpose, epoch: 4 },
        device_route,
        stream_route,
        enc: vec![0x61; 32],
        wrapped_key: vec![0x62; 48],
        signature: Ed25519Signature([0x63; 64]),
    };
    let mut updates = Vec::with_capacity(1_027);
    updates.push(signed_update(KeyPurpose::Catalog, None));
    for index in 0..1_024_u16 {
        let mut route = [0x31; 16];
        route[14..].copy_from_slice(&index.to_be_bytes());
        updates.push(signed_update(
            KeyPurpose::ConversationDek,
            Some(StreamRouteId::from_bytes(route)),
        ));
    }
    updates.push(signed_update(KeyPurpose::DeviceCommandTx, None));
    updates.push(signed_update(KeyPurpose::DeviceReplyTx, None));
    KeyUpdateSetV1 {
        key_directory_revision: RelayKeyDirectoryRevision::new(12),
        device_route,
        updates,
    }
    .canonical_bytes()
    .expect("encode production-shaped maximum KeyUpdateSet")
}

fn indexed_capacity_identity(prefix: u8, index: u16) -> [u8; 16] {
    let mut identity = [prefix; 16];
    identity[14..].copy_from_slice(&index.to_be_bytes());
    identity
}

fn maximum_attached_transition_state(
    mut transition: KeyTransitionRecord,
    mut update: KeyUpdateRecord,
) -> (KeyTransitionRecord, KeyUpdateRecord) {
    let authorization_hash = [0xA1; 32];
    let barrier_hash = [0xA2; 32];
    let sync_complete_hash = [0xA3; 32];
    let mut cuts = Vec::with_capacity(MAX_KEY_TRANSITION_CONVERSATIONS + 1);
    let mut snapshot_flushes = Vec::with_capacity(MAX_KEY_TRANSITION_CONVERSATIONS + 1);
    let mut stream_applied_acks = Vec::with_capacity(MAX_KEY_TRANSITION_CONVERSATIONS + 1);
    for index in 0..=MAX_KEY_TRANSITION_CONVERSATIONS as u16 {
        let scope = if index == 0 {
            KeyTransitionStreamScope::Catalog
        } else {
            KeyTransitionStreamScope::Conversation(indexed_capacity_identity(0x41, index))
        };
        let publication_stream_id = indexed_capacity_identity(0x51, index);
        let stream_route = indexed_capacity_identity(0x61, index);
        let generation = indexed_capacity_identity(0x71, index);
        let committed = u64::from(index);
        let barrier_sequence = committed + 1;
        cuts.push(KeyTransitionStreamCut {
            scope,
            publication_stream_id,
            stream_route,
            generation,
            relay_committed_outer: Some(committed),
            relay_committed_inner: Some(committed),
            barrier_sequence,
            old_epoch: 4,
            new_epoch: 5,
            epoch_barrier_sha256: barrier_hash,
        });
        snapshot_flushes.push(TransitionSnapshotFlushRecord {
            scope,
            publication_stream_id,
            stream_route,
            generation,
            relay_committed_outer: Some(committed),
            relay_committed_inner: Some(committed),
            barrier_sequence,
            key_directory_revision: transition.to_revision,
            key_epoch: 5,
            epoch_barrier_sha256: barrier_hash,
            authorization_hash,
            sync_complete_sha256: sync_complete_hash,
            flushed_at_ms: 103,
        });
        stream_applied_acks.push(StreamAppliedAckRecord {
            scope,
            stream_route,
            stream_generation: generation,
            applied_stream_seq: barrier_sequence,
            inner_cursor: Some(committed),
            key_revision: transition.to_revision,
            key_epoch: 5,
            epoch_barrier_sha256: barrier_hash,
            canonical_ack: vec![0xA4; 241],
            acknowledged_at_ms: 104,
        });
    }
    transition.phase = KeyTransitionPhase::Complete;
    transition.terminal = Some(KeyTransitionTerminal::Completed);
    transition.cuts = cuts;
    transition.state_changed_at_ms = 105;
    transition.terminal_at_ms = Some(105);
    transition.retain_until_ms = Some(105 + KEY_TRANSITION_TOMBSTONE_RETENTION_MS);
    update.lifecycle = KeyUpdateLifecycle::Acked;
    update.canonical_ack = Some(vec![0xA5; 91]);
    update.snapshot_flushes = snapshot_flushes;
    update.stream_applied_acks = stream_applied_acks;
    update.state_changed_at_ms = 104;
    (transition, update)
}

fn open_test_state() -> (
    TempDir,
    MemoryKeyStore,
    RuntimeStoreConfig,
    super::sqlite::RuntimeSqlite,
) {
    let root = tempfile::tempdir().expect("create key-transition test root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))
            .expect("secure key-transition test root");
    }
    let config = RuntimeStoreConfig::new(root.path().join("runtime.db"))
        .with_capacity_probe(super::pairing_tests::GenerousCapacity);
    let keys = MemoryKeyStore::new();
    let kek = load_or_create_storage_kek(&keys, &root.path().join("key-state.db"))
        .expect("create key-transition StorageKEK");
    let state = super::sqlite::open(&config, kek).expect("open key-transition sqlite state");
    (root, keys, config, state)
}

fn assert_v12_audit(state: &super::sqlite::RuntimeSqlite) {
    let ledger =
        super::sqlite::load_runtime_ledger(&state.connection, &state.key_bundle, state.database_id)
            .expect("load authenticated v12 ledger");
    validate_v12_integrity(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        &ledger,
    )
    .expect("audit authenticated key-transition state");
}

fn assert_replay_audit(state: &super::sqlite::RuntimeSqlite) {
    let ledger =
        super::sqlite::load_runtime_ledger(&state.connection, &state.key_bundle, state.database_id)
            .expect("load authenticated replay ledger");
    super::remote_replay::validate_v11_integrity(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        &ledger,
    )
    .expect("audit authenticated replay state");
}

fn artifact_snapshot(database: &Path) -> Vec<(PathBuf, Option<Vec<u8>>)> {
    let mut paths = vec![database.to_path_buf()];
    paths.push(PathBuf::from(format!("{}-wal", database.display())));
    paths.push(PathBuf::from(format!("{}-shm", database.display())));
    paths
        .into_iter()
        .map(|path| {
            let bytes = fs::read(&path).ok();
            (path, bytes)
        })
        .collect()
}

fn create_active_conversation_stream(
    state: &mut super::sqlite::RuntimeSqlite,
    config: &RuntimeStoreConfig,
    seed: u8,
) -> (RuntimeId, super::publication::PublicationStreamRecord) {
    let conversation_id =
        RuntimeId::from_bytes(RuntimeIdKind::Conversation, [seed; 16]).expect("conversation id");
    let descriptor = ConversationDescriptor {
        agent_kind: agentdeck_protocol::AgentKind::Codex,
        title: Some(format!("key-transition-subset-{seed}")),
        cwd: PathBuf::from(format!("/tmp/key-transition-subset-{seed}")),
    };
    let descriptor_bytes = super::journal::canonical_conversation_descriptor(&descriptor)
        .expect("encode conversation descriptor");
    let mut effects = CommandStreamEffects::default();
    super::journal::create_conversation(
        state,
        config,
        NewConversation {
            conversation_id,
            adapter_state_key: RuntimeId::from_bytes(
                RuntimeIdKind::AdapterState,
                [seed.wrapping_add(1); 16],
            )
            .expect("adapter state key"),
            descriptor,
        },
        descriptor_bytes,
        &mut effects,
    )
    .expect("create conversation with publication mapping");
    let stream = super::publication::load_conversation_publication_mapping(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        conversation_id,
    )
    .expect("load authenticated conversation publication mapping");
    (conversation_id, stream)
}

fn transition_cut(
    stream: &super::publication::PublicationStreamRecord,
    scope: KeyTransitionStreamScope,
    old_epoch: u64,
    barrier_hash: [u8; 32],
) -> KeyTransitionStreamCut {
    KeyTransitionStreamCut {
        scope,
        publication_stream_id: stream.publication_stream_id,
        stream_route: stream.stream_route,
        generation: stream.generation,
        relay_committed_outer: stream.committed_high_water,
        relay_committed_inner: stream.committed_inner_cursor,
        barrier_sequence: stream.committed_high_water.map_or(0, |value| value + 1),
        old_epoch,
        new_epoch: old_epoch + 1,
        epoch_barrier_sha256: barrier_hash,
    }
}

fn create_catalog_stream_committed_through_zero(
    state: &mut super::sqlite::RuntimeSqlite,
    config: &RuntimeStoreConfig,
    seed: u8,
    now_ms: u64,
) -> super::publication::PublicationStreamRecord {
    use super::publication::{FreezePublicationRequest, PublicationPayloadKind, PublicationScope};

    let publication_stream_id = [seed; 16];
    let stream_route = [seed.wrapping_add(1); 16];
    let generation = [seed.wrapping_add(2); 16];
    super::publication::create_publication_stream(
        state,
        config,
        publication_stream_id,
        PublicationScope::Catalog,
        stream_route,
        generation,
        now_ms,
    )
    .expect("create catalog publication stream for retention fence");

    // 使用 authenticated Gap 行建立真实 old-epoch counter identity；这样后续
    // freeze_key_barriers 的同事务 handoff 不是靠伪造 stream metadata 通过。
    let counter_scope_token = [seed.wrapping_add(3); 32];
    let key_id = KeyId {
        purpose: KeyPurpose::Catalog,
        epoch: 1,
    };
    let genesis = super::remote_counter::load_record(state, counter_scope_token, key_id)
        .expect("derive genesis catalog counter anchor");
    super::remote_counter::record_gap(
        state,
        config,
        super::remote_counter::RemoteCounterGapRequest {
            scope_token: counter_scope_token,
            key_id,
            expected_reserved_end: 0,
            expected_db_anchor: genesis.db_anchor,
            abandoned_through: 1,
            reservation_id: [seed.wrapping_add(4); 16],
            publication_id: [seed.wrapping_add(5); 16],
        },
    )
    .expect("persist old catalog counter identity");
    let frozen = super::publication::freeze_publication(
        state,
        config,
        FreezePublicationRequest {
            publication_id: [seed.wrapping_add(6); 16],
            publication_stream_id,
            generation,
            counter_scope_token,
            sender_counter: 1,
            inner_after: None,
            inner_through: Some(0),
            payload_kind: PublicationPayloadKind::Catalog,
            blob: b"catalog-zero-before-transition".to_vec(),
        },
        now_ms + 1,
    )
    .expect("freeze catalog revision zero publication");
    super::publication::acknowledge_publication_commit(
        state,
        config,
        publication_stream_id,
        generation,
        frozen.stream_seq,
        frozen.blob_sha256,
        now_ms + 2,
    )
    .expect("commit catalog revision zero publication");
    super::publication::acknowledge_publication_delivery(
        state,
        config,
        publication_stream_id,
        generation,
        frozen.stream_seq,
        frozen.blob_sha256,
        now_ms + 3,
    )
    .expect("locally acknowledge catalog revision zero publication");
    super::publication::load_stream(&state.connection, &state.key_bundle, publication_stream_id)
        .expect("load committed catalog stream")
}

fn stage_updates_frozen_zero_cut_candidate(
    state: &mut super::sqlite::RuntimeSqlite,
    config: &RuntimeStoreConfig,
    operation_id: [u8; 16],
    operation: KeyTransitionOperation,
    target: KeyTransitionRecipient,
    recipients: Vec<KeyTransitionRecipient>,
    base_ms: u64,
) -> KeyTransitionRecovery {
    begin_key_transition(
        state,
        config,
        BeginKeyTransition {
            operation_id,
            operation,
            target: KeyTransitionTarget::Device(target),
            from_revision: 7,
            to_revision: 8,
            recipients: recipients.clone(),
            replay_retirement: None,
            created_at_ms: base_ms,
        },
    )
    .expect("stage state-dependent zero-cut candidate");
    mark_rotated_preparing_updates(state, config, operation_id, base_ms + 1)
        .expect("rotate state-dependent zero-cut candidate");
    let updates = recipients
        .into_iter()
        .map(|recipient| FrozenKeyUpdate {
            recipient,
            key_revision: 8,
            canonical_update_set: format!("state-dependent-zero-cut-{operation_id:?}").into_bytes(),
        })
        .collect();
    freeze_key_updates(state, config, operation_id, updates, base_ms + 2)
        .expect("freeze state-dependent zero-cut updates");
    load_active_key_transition(state)
        .expect("load state-dependent zero-cut candidate")
        .expect("state-dependent zero-cut candidate remains active")
}

fn assert_active_projections_reject_empty_cuts(
    operation: KeyTransitionOperation,
    target: KeyTransitionRecipient,
    recipients: Vec<KeyTransitionRecipient>,
    seed: u8,
) {
    let (root, keys, config, mut state) = open_test_state();
    let (_conversation_id, conversation) =
        create_active_conversation_stream(&mut state, &config, seed);
    let base_ms = config
        .clock
        .now_ms()
        .expect("read state-dependent zero-cut test clock")
        .saturating_add(100);
    let catalog =
        create_catalog_stream_committed_through_zero(&mut state, &config, seed + 8, base_ms);
    let operation_id = [seed + 16; 16];
    let before_transition = stage_updates_frozen_zero_cut_candidate(
        &mut state,
        &config,
        operation_id,
        operation,
        target,
        recipients,
        base_ms + 10,
    );
    let before_catalog = super::publication::load_stream(
        &state.connection,
        &state.key_bundle,
        catalog.publication_stream_id,
    )
    .expect("authenticate catalog before rejected empty cuts");
    let before_conversation = super::publication::load_stream(
        &state.connection,
        &state.key_bundle,
        conversation.publication_stream_id,
    )
    .expect("authenticate conversation before rejected empty cuts");
    let counter_scope_token = before_catalog
        .counter_scope_token
        .expect("committed catalog carries counter scope");
    let counter_key_id = KeyId {
        purpose: KeyPurpose::Catalog,
        epoch: 1,
    };
    let before_counter =
        super::remote_counter::load_record(&state, counter_scope_token, counter_key_id)
            .expect("authenticate counter before rejected empty cuts");
    let before_ledger =
        super::sqlite::load_runtime_ledger(&state.connection, &state.key_bundle, state.database_id)
            .expect("load ledger before rejected empty cuts");

    assert!(matches!(
        freeze_key_barriers(&mut state, &config, operation_id, Vec::new(), base_ms + 13,),
        Err(RuntimeStoreError::PublicationMismatch)
    ));
    assert_eq!(
        load_active_key_transition(&state)
            .expect("load transition after rejected empty cuts")
            .expect("rejected empty cuts preserve active transition"),
        before_transition
    );
    assert_eq!(
        super::publication::load_stream(
            &state.connection,
            &state.key_bundle,
            before_catalog.publication_stream_id,
        )
        .expect("authenticate unchanged catalog after rejected empty cuts"),
        before_catalog
    );
    assert_eq!(
        super::publication::load_stream(
            &state.connection,
            &state.key_bundle,
            before_conversation.publication_stream_id,
        )
        .expect("authenticate unchanged conversation after rejected empty cuts"),
        before_conversation
    );
    assert_eq!(
        super::remote_counter::load_record(&state, counter_scope_token, counter_key_id)
            .expect("authenticate unchanged counter after rejected empty cuts"),
        before_counter
    );
    assert_eq!(
        super::sqlite::load_runtime_ledger(
            &state.connection,
            &state.key_bundle,
            state.database_id,
        )
        .expect("load unchanged ledger after rejected empty cuts"),
        before_ledger
    );
    assert_v12_audit(&state);

    drop(state);
    let kek = load_or_create_storage_kek(&keys, &root.path().join("key-state.db"))
        .expect("reload state-dependent zero-cut StorageKEK");
    let reopened =
        super::sqlite::open(&config, kek).expect("reopen state-dependent zero-cut rejection store");
    assert_v12_audit(&reopened);
    assert_eq!(
        load_active_key_transition(&reopened)
            .expect("load reopened rejected zero-cut transition")
            .expect("reopened rejected zero-cut transition remains active"),
        before_transition
    );
    assert_eq!(
        super::publication::load_stream(
            &reopened.connection,
            &reopened.key_bundle,
            before_catalog.publication_stream_id,
        )
        .expect("authenticate reopened catalog after rejected empty cuts"),
        before_catalog
    );
    assert_eq!(
        super::publication::load_stream(
            &reopened.connection,
            &reopened.key_bundle,
            before_conversation.publication_stream_id,
        )
        .expect("authenticate reopened conversation after rejected empty cuts"),
        before_conversation
    );
    assert_eq!(
        super::remote_counter::load_record(&reopened, counter_scope_token, counter_key_id)
            .expect("authenticate reopened counter after rejected empty cuts"),
        before_counter
    );
}

fn trim_catalog_to_limit(
    state: &mut super::sqlite::RuntimeSqlite,
    config: &RuntimeStoreConfig,
    max_deltas: u64,
    now_ms: u64,
) -> Result<(), RuntimeStoreError> {
    let key_bundle = Arc::clone(&state.key_bundle);
    let database_id = state.database_id;
    let transaction = state
        .connection
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let ledger = super::sqlite::load_runtime_ledger(&transaction, &key_bundle, database_id)?;
    let mut floor = ledger.catalog_retention_floor.clone();
    super::catalog::trim_catalog_window_with_limits(
        &transaction,
        &key_bundle,
        database_id,
        &mut floor,
        now_ms,
        max_deltas,
        super::catalog::MAX_CATALOG_DELTA_BYTES,
    )?;
    let (count, bytes): (i64, i64) = transaction.query_row(
        "SELECT COUNT(*), COALESCE(SUM(logical_delta_bytes), 0) FROM catalog_journal",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let mut next = ledger.clone();
    next.catalog_retention_floor = floor;
    next.catalog_delta_count =
        u64::try_from(count).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    next.catalog_delta_bytes =
        u64::try_from(bytes).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let _ = super::sqlite::update_runtime_ledger(
        &transaction,
        &key_bundle,
        database_id,
        &ledger,
        &next,
    )?;
    transaction.commit()?;
    super::sqlite::latch_post_commit_capacity(state, config);
    Ok(())
}

#[test]
fn active_catalog_transition_persistently_blocks_durable_d_from_trimming_frozen_h() {
    use super::publication::{FreezePublicationRequest, PublicationPayloadKind};

    let (root, keys, config, mut state) = open_test_state();
    create_active_conversation_stream(&mut state, &config, 0xa1);
    create_active_conversation_stream(&mut state, &config, 0xa3);
    let durable_d =
        super::snapshot::refresh_catalog_snapshot(&mut state, &config, None, StreamCursor::At(1))
            .expect("persist durable catalog D above transition H");
    assert_eq!(durable_d.base, StreamCursor::At(1));
    let base = config
        .clock
        .now_ms()
        .expect("retention-fence clock")
        .saturating_add(100);
    let catalog = create_catalog_stream_committed_through_zero(&mut state, &config, 0xb1, base);
    assert_eq!(catalog.committed_inner_cursor, Some(0));

    let operation_id = [0xb8; 16];
    let member = recipient(0xb9, 41);
    let canonical_update_set = b"renew-member-for-catalog-retention-fence".to_vec();
    begin_key_transition(
        &mut state,
        &config,
        BeginKeyTransition {
            operation_id,
            operation: KeyTransitionOperation::Renew,
            target: KeyTransitionTarget::Device(member),
            from_revision: 41,
            to_revision: 42,
            recipients: vec![member],
            replay_retirement: None,
            created_at_ms: base + 3,
        },
    )
    .expect("begin catalog retention-fence transition");
    mark_rotated_preparing_updates(&mut state, &config, operation_id, base + 4)
        .expect("mark catalog retention-fence transition rotated");
    freeze_key_updates(
        &mut state,
        &config,
        operation_id,
        vec![FrozenKeyUpdate {
            recipient: member,
            key_revision: 42,
            canonical_update_set: canonical_update_set.clone(),
        }],
        base + 5,
    )
    .expect("freeze catalog retention-fence update");
    let barrier_hash = [0xba; 32];
    let cut = transition_cut(&catalog, KeyTransitionStreamScope::Catalog, 1, barrier_hash);
    freeze_key_barriers(&mut state, &config, operation_id, vec![cut], base + 6)
        .expect("freeze catalog H while durable D remains newer");
    drop(state);

    // reopen 后 TEMP pin 已全部消失；active authenticated transition row 仍必须
    // 阻止 durable D 授权删除 revision zero。
    let kek = load_or_create_storage_kek(&keys, &root.path().join("key-state.db"))
        .expect("reload retention-fence StorageKEK");
    let mut reopened =
        super::sqlite::open(&config, kek).expect("reopen persistent catalog retention fence");
    let before = super::sqlite::load_runtime_ledger(
        &reopened.connection,
        &reopened.key_bundle,
        reopened.database_id,
    )
    .expect("load ledger before blocked catalog trim");
    let before_rows: i64 = reopened
        .connection
        .query_row("SELECT COUNT(*) FROM catalog_journal", [], |row| row.get(0))
        .expect("count catalog rows before blocked trim");
    assert!(matches!(
        trim_catalog_to_limit(&mut reopened, &config, 1, base + 7),
        Err(RuntimeStoreError::WorkerBusy {
            lane: crate::runtime::model::RuntimeStoreLane::Normal,
        })
    ));
    let after_block = super::sqlite::load_runtime_ledger(
        &reopened.connection,
        &reopened.key_bundle,
        reopened.database_id,
    )
    .expect("load ledger after blocked catalog trim");
    let after_block_rows: i64 = reopened
        .connection
        .query_row("SELECT COUNT(*) FROM catalog_journal", [], |row| row.get(0))
        .expect("count catalog rows after blocked trim");
    assert_eq!(after_block, before);
    assert_eq!(after_block_rows, before_rows);

    let barrier = super::publication::freeze_publication(
        &mut reopened,
        &config,
        FreezePublicationRequest {
            publication_id: [0xbb; 16],
            publication_stream_id: cut.publication_stream_id,
            generation: cut.generation,
            counter_scope_token: [0xbc; 32],
            sender_counter: 0,
            inner_after: None,
            inner_through: None,
            payload_kind: PublicationPayloadKind::Control,
            blob: b"catalog-retention-fence-epoch-barrier".to_vec(),
        },
        base + 8,
    )
    .expect("freeze catalog epoch barrier after persistent reopen");
    super::publication::acknowledge_publication_commit(
        &mut reopened,
        &config,
        cut.publication_stream_id,
        cut.generation,
        barrier.stream_seq,
        barrier.blob_sha256,
        base + 9,
    )
    .expect("commit catalog epoch barrier");
    mark_key_barriers_committed(&mut reopened, &config, operation_id, base + 10)
        .expect("mark catalog barrier committed");
    acknowledge_key_update(
        &mut reopened,
        &config,
        AcknowledgeKeyUpdate {
            operation_id,
            recipient: member,
            key_revision: 42,
            update_hash: canonical_update_hash(&canonical_update_set).expect("renew update hash"),
            canonical_ack: b"renew-key-update-ack".to_vec(),
            acknowledged_at_ms: base + 11,
        },
    )
    .expect("acknowledge renew key update");
    acknowledge_stream_applied(
        &mut reopened,
        &config,
        AcknowledgeStreamApplied {
            operation_id,
            recipient: member,
            key_revision: 42,
            scope: KeyTransitionStreamScope::Catalog,
            stream_route: cut.stream_route,
            stream_generation: cut.generation,
            applied_stream_seq: cut.barrier_sequence,
            inner_cursor: cut.relay_committed_inner,
            key_epoch: cut.new_epoch,
            epoch_barrier_sha256: cut.epoch_barrier_sha256,
            authorization_hash: [0xbd; 32],
            canonical_ack: b"renew-stream-applied-ack".to_vec(),
            acknowledged_at_ms: base + 12,
        },
    )
    .expect("acknowledge renew catalog cut");
    complete_key_transition(&mut reopened, &config, operation_id, base + 13)
        .expect("complete catalog retention-fence transition");

    trim_catalog_to_limit(&mut reopened, &config, 1, base + 14)
        .expect("completed transition releases durable D trim authorization");
    let released = super::sqlite::load_runtime_ledger(
        &reopened.connection,
        &reopened.key_bundle,
        reopened.database_id,
    )
    .expect("load ledger after released catalog trim");
    assert_eq!(released.catalog_delta_count, 1);
    assert_eq!(
        released.catalog_retention_floor,
        Some(super::sequence::encode_sequence(1))
    );
    assert_v12_audit(&reopened);
}

#[test]
fn catalog_barrier_freeze_fails_before_handoff_when_required_delta_was_trimmed() {
    let (_root, _keys, config, mut state) = open_test_state();
    create_active_conversation_stream(&mut state, &config, 0xc1);
    create_active_conversation_stream(&mut state, &config, 0xc3);
    super::snapshot::refresh_catalog_snapshot(&mut state, &config, None, StreamCursor::At(1))
        .expect("persist durable D before trimming required transition delta");
    let base = config
        .clock
        .now_ms()
        .expect("trimmed-transition-preflight clock")
        .saturating_add(100);
    let catalog = create_catalog_stream_committed_through_zero(&mut state, &config, 0xd1, base);
    trim_catalog_to_limit(&mut state, &config, 1, base + 3)
        .expect("durable D ordinarily authorizes trimming revision zero");

    let operation_id = [0xd8; 16];
    let member = recipient(0xd9, 51);
    begin_key_transition(
        &mut state,
        &config,
        BeginKeyTransition {
            operation_id,
            operation: KeyTransitionOperation::Renew,
            target: KeyTransitionTarget::Device(member),
            from_revision: 51,
            to_revision: 52,
            recipients: vec![member],
            replay_retirement: None,
            created_at_ms: base + 4,
        },
    )
    .expect("begin transition after required delta trim");
    mark_rotated_preparing_updates(&mut state, &config, operation_id, base + 5)
        .expect("mark trimmed-delta transition rotated");
    freeze_key_updates(
        &mut state,
        &config,
        operation_id,
        vec![FrozenKeyUpdate {
            recipient: member,
            key_revision: 52,
            canonical_update_set: b"trimmed-required-delta-update".to_vec(),
        }],
        base + 6,
    )
    .expect("freeze trimmed-delta key update");
    let cut = transition_cut(&catalog, KeyTransitionStreamScope::Catalog, 1, [0xda; 32]);
    let stream_before = super::publication::load_stream(
        &state.connection,
        &state.key_bundle,
        cut.publication_stream_id,
    )
    .expect("load stream before rejected barrier freeze");
    assert!(matches!(
        freeze_key_barriers(&mut state, &config, operation_id, vec![cut], base + 7,),
        Err(RuntimeStoreError::BackfillNeedSnapshot)
    ));
    let recovery = load_active_key_transition(&state)
        .expect("load active transition after rejected preflight")
        .expect("transition remains active after rejected preflight");
    assert_eq!(recovery.transition.phase, KeyTransitionPhase::UpdatesFrozen);
    assert!(recovery.transition.cuts.is_empty());
    let stream_after = super::publication::load_stream(
        &state.connection,
        &state.key_bundle,
        cut.publication_stream_id,
    )
    .expect("load stream after rejected barrier freeze");
    assert_eq!(stream_after, stream_before);
    assert!(
        !active_catalog_cut_covers_revision(
            &state.connection,
            &state.key_bundle,
            state.database_id,
            0,
        )
        .expect("no persistent catalog fence installed on failed preflight")
    );
}

fn complete_replay_retirement_fixture(
    state: &mut super::sqlite::RuntimeSqlite,
    config: &RuntimeStoreConfig,
    operation_id: [u8; 16],
    scope: [u8; super::remote_replay::REMOTE_REPLAY_SCOPE_BYTES],
) {
    let target = KeyTransitionRecipient {
        device_route: scope[26..42].try_into().expect("device route width"),
        grant_serial: u64::from_be_bytes(scope[42..50].try_into().expect("grant width")),
    };
    begin_key_transition(
        state,
        config,
        BeginKeyTransition {
            operation_id,
            operation: KeyTransitionOperation::Revoke,
            target: KeyTransitionTarget::Device(target),
            from_revision: 1,
            to_revision: 2,
            recipients: Vec::new(),
            replay_retirement: Some(
                ReplayRetirement::pending_device_command(scope, 9)
                    .expect("freeze old reply epoch with replay scope"),
            ),
            created_at_ms: 10,
        },
    )
    .expect("begin replay-retirement fixture");
    mark_rotated_preparing_updates(state, config, operation_id, 11)
        .expect("rotate replay-retirement fixture");
    freeze_key_updates(state, config, operation_id, Vec::new(), 12)
        .expect("freeze empty last-device update set");
    freeze_key_barriers(state, config, operation_id, Vec::new(), 13)
        .expect("freeze empty last-device barrier set");
    mark_key_barriers_committed(state, config, operation_id, 14)
        .expect("commit empty last-device barriers");
    assert!(matches!(
        try_complete_key_transition(state, config, operation_id, 15)
            .expect("complete replay-retirement fixture"),
        KeyTransitionCompletion::Completed(_)
    ));
}

#[test]
fn restart_applies_pending_device_command_replay_retirement_exactly_once() {
    let (root, keys, config, mut state) = open_test_state();
    let scope =
        super::remote_replay::canonical_device_command_scope([0x31; 16], 7, [0x41; 16], 3, 5)
            .expect("canonical observed DeviceCommandTx scope");
    assert_eq!(
        super::remote_replay::admit(
            &mut state,
            &config,
            super::remote_replay::RemoteReplayAdmission {
                scope,
                sender_counter: 1,
                ciphertext_sha256: [0x51; 32],
                scope_capacity: super::remote_replay::MAX_REMOTE_REPLAY_SCOPES,
            },
        )
        .expect("observe replay scope before renewal/revoke"),
        super::remote_replay::RemoteReplayStoreDecision::Fresh,
    );
    complete_replay_retirement_fixture(&mut state, &config, [0x61; 16], scope);
    drop(state);

    let kek = load_or_create_storage_kek(&keys, &root.path().join("key-state.db"))
        .expect("reload replay-retirement StorageKEK");
    let mut reopened =
        super::sqlite::open(&config, kek).expect("restart with pending replay retirement");
    let applied = apply_pending_replay_retirement(&mut reopened, &config)
        .expect("atomically retire replay scope and persist applied lifecycle");
    let ReplayRetirementApplyOutcome::Applied {
        transition,
        replay_scope_observed,
    } = applied
    else {
        panic!("restart must apply the frozen replay retirement")
    };
    assert!(replay_scope_observed);
    assert_eq!(
        transition.replay_retirement.map(|value| value.lifecycle),
        Some(ReplayRetirementLifecycle::Applied),
    );
    assert_eq!(
        transition.counter_retirement,
        CounterRetirementLifecycle::Pending
    );
    assert_eq!(
        super::remote_replay::admit(
            &mut reopened,
            &config,
            super::remote_replay::RemoteReplayAdmission {
                scope,
                sender_counter: 2,
                ciphertext_sha256: [0x52; 32],
                scope_capacity: super::remote_replay::MAX_REMOTE_REPLAY_SCOPES,
            },
        )
        .expect("read back retired replay scope"),
        super::remote_replay::RemoteReplayStoreDecision::Retired,
    );
    assert_eq!(
        apply_pending_replay_retirement(&mut reopened, &config)
            .expect("exact applied retry is a no-op"),
        ReplayRetirementApplyOutcome::NoPending,
    );
    assert_v12_audit(&reopened);
    assert_replay_audit(&reopened);
}

#[test]
fn never_observed_device_command_scope_retires_idempotently_without_forging_other_scopes() {
    let (_root, _keys, config, mut state) = open_test_state();
    let scope =
        super::remote_replay::canonical_device_command_scope([0x71; 16], 8, [0x81; 16], 4, 6)
            .expect("canonical never-observed DeviceCommandTx scope");
    let mut device_reply = scope;
    device_reply[1] = 2;
    assert!(ReplayRetirement::pending_device_command(device_reply, 9).is_err());
    let mut conversation = scope;
    conversation[1] = 3;
    conversation[42..50].fill(0);
    assert!(ReplayRetirement::pending_device_command(conversation, 9).is_err());
    let mut catalog = scope;
    catalog[1] = 4;
    catalog[26..50].fill(0);
    assert!(ReplayRetirement::pending_device_command(catalog, 9).is_err());
    complete_replay_retirement_fixture(&mut state, &config, [0x91; 16], scope);
    let ReplayRetirementApplyOutcome::Applied {
        transition,
        replay_scope_observed,
    } = apply_pending_replay_retirement(&mut state, &config)
        .expect("absent replay row is a successful retirement")
    else {
        panic!("absent replay row still consumes its pending lifecycle")
    };
    assert!(!replay_scope_observed);
    assert_eq!(transition.operation_id, [0x91; 16]);
    assert_eq!(
        transition.replay_retirement.map(|value| value.lifecycle),
        Some(ReplayRetirementLifecycle::Applied),
    );
    assert!(
        !super::remote_replay::contains_scope(&state, scope)
            .expect("absent DeviceCommandTx scope stays absent")
    );
    assert_eq!(
        apply_pending_replay_retirement(&mut state, &config)
            .expect("absent replay retirement exact retry"),
        ReplayRetirementApplyOutcome::NoPending,
    );
    assert_v12_audit(&state);
    assert_replay_audit(&state);
}

#[test]
fn cancelled_membership_marks_retirement_applied_without_retiring_active_scope() {
    let (_root, _keys, config, mut state) = open_test_state();
    let scope =
        super::remote_replay::canonical_device_command_scope([0xa1; 16], 9, [0xa2; 16], 5, 7)
            .expect("canonical cancellable DeviceCommandTx scope");
    let admission = super::remote_replay::RemoteReplayAdmission {
        scope,
        sender_counter: 1,
        ciphertext_sha256: [0xa3; 32],
        scope_capacity: super::remote_replay::MAX_REMOTE_REPLAY_SCOPES,
    };
    assert_eq!(
        super::remote_replay::admit(&mut state, &config, admission)
            .expect("observe active scope before cancelled membership"),
        super::remote_replay::RemoteReplayStoreDecision::Fresh,
    );
    let target = KeyTransitionRecipient {
        device_route: [0xa2; 16],
        grant_serial: 5,
    };
    begin_key_transition(
        &mut state,
        &config,
        BeginKeyTransition {
            operation_id: [0xa4; 16],
            operation: KeyTransitionOperation::Revoke,
            target: KeyTransitionTarget::Device(target),
            from_revision: 1,
            to_revision: 2,
            recipients: Vec::new(),
            replay_retirement: Some(
                ReplayRetirement::pending_device_command(scope, 8)
                    .expect("freeze cancellable retirement"),
            ),
            created_at_ms: 10,
        },
    )
    .expect("begin cancellable membership");
    cancel_key_transition(&mut state, &config, [0xa4; 16], 11).expect("cancel before key rotation");
    let ReplayRetirementApplyOutcome::Applied {
        replay_scope_observed,
        ..
    } = apply_pending_replay_retirement(&mut state, &config)
        .expect("consume cancelled retirement without touching replay")
    else {
        panic!("cancelled retirement must be terminally consumed")
    };
    assert!(!replay_scope_observed);
    assert_eq!(
        super::remote_replay::admit(
            &mut state,
            &config,
            super::remote_replay::RemoteReplayAdmission {
                sender_counter: 2,
                ciphertext_sha256: [0xa5; 32],
                ..admission
            },
        )
        .expect("cancelled membership leaves old scope active"),
        super::remote_replay::RemoteReplayStoreDecision::Fresh,
    );
}

#[test]
fn stream_cut_contract_requires_one_catalog_sorted_unique_and_checked_next_commit() {
    let catalog = KeyTransitionStreamCut {
        scope: KeyTransitionStreamScope::Catalog,
        publication_stream_id: [1; 16],
        stream_route: [2; 16],
        generation: [3; 16],
        relay_committed_outer: Some(7),
        relay_committed_inner: Some(11),
        barrier_sequence: 8,
        old_epoch: 4,
        new_epoch: 5,
        epoch_barrier_sha256: [0x81; 32],
    };
    assert!(validate_stream_cuts(KeyTransitionOperation::Add, &[catalog]).is_ok());

    let control_only_catalog = KeyTransitionStreamCut {
        relay_committed_inner: None,
        ..catalog
    };
    assert!(
        validate_stream_cuts(KeyTransitionOperation::Add, &[control_only_catalog]).is_ok(),
        "Relay control-only history advances outer while tagged inner stays BeforeFirst"
    );
    assert!(validate_stream_cuts(KeyTransitionOperation::Revoke, &[control_only_catalog]).is_ok());
    assert!(validate_stream_cuts(KeyTransitionOperation::Renew, &[control_only_catalog]).is_ok());

    let mut invalid = catalog;
    invalid.barrier_sequence = 7;
    assert!(validate_stream_cuts(KeyTransitionOperation::Add, &[invalid]).is_err());
    invalid = catalog;
    invalid.new_epoch = invalid.old_epoch;
    assert!(validate_stream_cuts(KeyTransitionOperation::Add, &[invalid]).is_err());

    let genesis_catalog = KeyTransitionStreamCut {
        relay_committed_outer: None,
        relay_committed_inner: Some(11),
        barrier_sequence: 0,
        old_epoch: 0,
        new_epoch: 1,
        ..catalog
    };
    assert!(
        validate_stream_cuts(KeyTransitionOperation::Add, &[genesis_catalog]).is_ok(),
        "first-device 0→1 handoff preserves an authenticated local inner H"
    );
    assert!(
        validate_stream_cuts(KeyTransitionOperation::Revoke, &[genesis_catalog]).is_err(),
        "genesis sentinel is not valid for later membership transitions"
    );
    let rotated_catalog = KeyTransitionStreamCut {
        old_epoch: 1,
        new_epoch: 2,
        ..genesis_catalog
    };
    assert!(
        validate_stream_cuts(KeyTransitionOperation::Add, &[rotated_catalog]).is_ok(),
        "authenticated rollover may preserve inner H while the new outer generation is empty"
    );
    assert!(validate_stream_cuts(KeyTransitionOperation::Revoke, &[rotated_catalog]).is_ok());
    assert!(validate_stream_cuts(KeyTransitionOperation::Renew, &[rotated_catalog]).is_ok());

    let conversation = KeyTransitionStreamCut {
        scope: KeyTransitionStreamScope::Conversation([4; 16]),
        publication_stream_id: [5; 16],
        stream_route: [6; 16],
        generation: [7; 16],
        relay_committed_outer: None,
        relay_committed_inner: None,
        barrier_sequence: 0,
        old_epoch: 9,
        new_epoch: 10,
        epoch_barrier_sha256: [0x82; 32],
    };
    assert!(validate_stream_cuts(KeyTransitionOperation::Revoke, &[catalog, conversation]).is_ok());
    assert!(validate_stream_cuts(KeyTransitionOperation::Renew, &[catalog]).is_ok());
    assert!(validate_stream_cuts(KeyTransitionOperation::Renew, &[catalog, conversation]).is_err());
    assert!(validate_stream_cuts(KeyTransitionOperation::Add, &[conversation, catalog]).is_err());
    assert!(validate_stream_cuts(KeyTransitionOperation::Add, &[catalog, catalog]).is_err());
    assert!(validate_stream_cuts(KeyTransitionOperation::Add, &[conversation]).is_err());
    assert!(validate_stream_cuts(KeyTransitionOperation::ActivateConversation, &[]).is_ok());
    assert!(
        validate_stream_cuts(KeyTransitionOperation::ActivateConversation, &[catalog]).is_err()
    );
}

#[test]
fn first_add_and_last_revoke_use_real_zero_cut_transitions() {
    let (root, keys, config, mut state) = open_test_state();
    let member = recipient(0x17, 1);
    let add_operation = [0x18; 16];
    begin_key_transition(
        &mut state,
        &config,
        BeginKeyTransition {
            operation_id: add_operation,
            operation: KeyTransitionOperation::Add,
            target: KeyTransitionTarget::Device(member),
            from_revision: 0,
            to_revision: 1,
            recipients: vec![member],
            replay_retirement: None,
            created_at_ms: 10,
        },
    )
    .expect("stage first-member 0->1 transition");
    mark_rotated_preparing_updates(&mut state, &config, add_operation, 11)
        .expect("rotate first-member guard");
    let canonical_update_set = b"first-member-key-update".to_vec();
    freeze_key_updates(
        &mut state,
        &config,
        add_operation,
        vec![FrozenKeyUpdate {
            recipient: member,
            key_revision: 1,
            canonical_update_set: canonical_update_set.clone(),
        }],
        12,
    )
    .expect("freeze first-member update");
    freeze_key_barriers(&mut state, &config, add_operation, Vec::new(), 13)
        .expect("first member has no old-audience barrier");
    mark_key_barriers_committed(&mut state, &config, add_operation, 14)
        .expect("commit empty first-member barrier set");
    acknowledge_key_update(
        &mut state,
        &config,
        AcknowledgeKeyUpdate {
            operation_id: add_operation,
            recipient: member,
            key_revision: 1,
            update_hash: canonical_update_hash(&canonical_update_set).expect("first update hash"),
            canonical_ack: b"first-member-key-ack".to_vec(),
            acknowledged_at_ms: 15,
        },
    )
    .expect("ack first-member key update");
    complete_key_transition(&mut state, &config, add_operation, 16)
        .expect("complete first-member transition without StreamAppliedAck");

    let revoke_operation = [0x19; 16];
    begin_key_transition(
        &mut state,
        &config,
        BeginKeyTransition {
            operation_id: revoke_operation,
            operation: KeyTransitionOperation::Revoke,
            target: KeyTransitionTarget::Device(member),
            from_revision: 1,
            to_revision: 2,
            recipients: Vec::new(),
            replay_retirement: None,
            created_at_ms: 17,
        },
    )
    .expect("stage last-member revoke transition");
    mark_rotated_preparing_updates(&mut state, &config, revoke_operation, 18)
        .expect("rotate last-member guard");
    freeze_key_updates(&mut state, &config, revoke_operation, Vec::new(), 19)
        .expect("last-member revoke has no recipient update");
    freeze_key_barriers(&mut state, &config, revoke_operation, Vec::new(), 20)
        .expect("last-member revoke has no old-audience barrier");
    mark_key_barriers_committed(&mut state, &config, revoke_operation, 21)
        .expect("commit empty last-member barrier set");
    let completed = try_complete_key_transition(&mut state, &config, revoke_operation, 22)
        .expect("auto-complete zero-recipient last-member revoke");
    assert!(matches!(
        completed,
        KeyTransitionCompletion::Completed(ref record)
            if record.phase == KeyTransitionPhase::Complete
                && record.terminal == Some(KeyTransitionTerminal::Completed)
                && record.terminal_at_ms == Some(22)
    ));
    assert!(
        load_active_key_transition(&state)
            .expect("read released last-member transition slot")
            .is_none()
    );
    assert_eq!(
        try_complete_key_transition(&mut state, &config, revoke_operation, 22)
            .expect("replay exact completed last-member revoke"),
        completed,
        "completion retry must preserve the first terminal timestamp"
    );

    let replacement = recipient(0x22, 2);
    let replacement_operation = [0x23; 16];
    begin_key_transition(
        &mut state,
        &config,
        BeginKeyTransition {
            operation_id: replacement_operation,
            operation: KeyTransitionOperation::Add,
            target: KeyTransitionTarget::Device(replacement),
            from_revision: 2,
            to_revision: 3,
            recipients: vec![replacement],
            replay_retirement: None,
            created_at_ms: 23,
        },
    )
    .expect("stage later add with zero active old audience");
    mark_rotated_preparing_updates(&mut state, &config, replacement_operation, 24)
        .expect("rotate replacement guard");
    let replacement_update = b"replacement-key-update".to_vec();
    freeze_key_updates(
        &mut state,
        &config,
        replacement_operation,
        vec![FrozenKeyUpdate {
            recipient: replacement,
            key_revision: 3,
            canonical_update_set: replacement_update.clone(),
        }],
        25,
    )
    .expect("freeze replacement key update");
    freeze_key_barriers(&mut state, &config, replacement_operation, Vec::new(), 26)
        .expect("later zero-audience add also has no fake barrier");
    mark_key_barriers_committed(&mut state, &config, replacement_operation, 27)
        .expect("commit later zero-audience barrier set");
    acknowledge_key_update(
        &mut state,
        &config,
        AcknowledgeKeyUpdate {
            operation_id: replacement_operation,
            recipient: replacement,
            key_revision: 3,
            update_hash: canonical_update_hash(&replacement_update)
                .expect("replacement update hash"),
            canonical_ack: b"replacement-key-ack".to_vec(),
            acknowledged_at_ms: 28,
        },
    )
    .expect("ack replacement key update");
    complete_key_transition(&mut state, &config, replacement_operation, 29)
        .expect("complete later zero-audience add");
    assert_v12_audit(&state);
    drop(state);
    let kek = load_or_create_storage_kek(&keys, &root.path().join("key-state.db"))
        .expect("reload zero-cut StorageKEK");
    let reopened = super::sqlite::open(&config, kek).expect("reopen zero-cut transition store");
    assert_v12_audit(&reopened);
}

#[test]
fn active_projections_reject_sole_target_add_empty_cuts_without_writes() {
    let target = recipient(0x31, 1);
    assert_active_projections_reject_empty_cuts(
        KeyTransitionOperation::Add,
        target,
        vec![target],
        0x41,
    );
}

#[test]
fn active_projections_reject_zero_recipient_revoke_empty_cuts_without_writes() {
    let target = recipient(0x32, 2);
    assert_active_projections_reject_empty_cuts(
        KeyTransitionOperation::Revoke,
        target,
        Vec::new(),
        0x61,
    );
}

#[test]
fn zero_cut_commit_rejects_projection_created_after_freeze_without_writes() {
    use super::publication::PublicationScope;

    let (root, keys, config, mut state) = open_test_state();
    let base_ms = config
        .clock
        .now_ms()
        .expect("read zero-cut commit race clock")
        .saturating_add(100);
    let target = recipient(0x71, 3);
    let operation_id = [0x72; 16];
    stage_updates_frozen_zero_cut_candidate(
        &mut state,
        &config,
        operation_id,
        KeyTransitionOperation::Add,
        target,
        vec![target],
        base_ms,
    );
    freeze_key_barriers(&mut state, &config, operation_id, Vec::new(), base_ms + 3)
        .expect("freeze zero cuts while authenticated publication directory is empty");

    let publication_stream_id = [0x73; 16];
    super::publication::create_publication_stream(
        &mut state,
        &config,
        publication_stream_id,
        PublicationScope::Catalog,
        [0x74; 16],
        [0x75; 16],
        base_ms + 4,
    )
    .expect("create required projection after zero-cut freeze");
    let before_transition = load_active_key_transition(&state)
        .expect("load zero-cut transition before rejected commit")
        .expect("zero-cut transition remains active before rejected commit");
    assert_eq!(
        before_transition.transition.phase,
        KeyTransitionPhase::BarriersFrozen
    );
    assert!(before_transition.transition.cuts.is_empty());
    let before_stream = super::publication::load_stream(
        &state.connection,
        &state.key_bundle,
        publication_stream_id,
    )
    .expect("authenticate projection before rejected zero-cut commit");
    assert!(before_stream.counter_scope_token.is_none());
    assert!(before_stream.sender_counter_high_water.is_none());
    let before_ledger =
        super::sqlite::load_runtime_ledger(&state.connection, &state.key_bundle, state.database_id)
            .expect("load ledger before rejected zero-cut commit");

    assert!(matches!(
        mark_key_barriers_committed(&mut state, &config, operation_id, base_ms + 5),
        Err(RuntimeStoreError::PublicationMismatch)
    ));
    assert_eq!(
        load_active_key_transition(&state)
            .expect("load transition after rejected zero-cut commit")
            .expect("rejected zero-cut commit preserves active transition"),
        before_transition
    );
    assert_eq!(
        super::publication::load_stream(
            &state.connection,
            &state.key_bundle,
            publication_stream_id,
        )
        .expect("authenticate unchanged projection after rejected zero-cut commit"),
        before_stream
    );
    assert_eq!(
        super::sqlite::load_runtime_ledger(
            &state.connection,
            &state.key_bundle,
            state.database_id,
        )
        .expect("load unchanged ledger after rejected zero-cut commit"),
        before_ledger
    );
    assert_v12_audit(&state);

    drop(state);
    let kek = load_or_create_storage_kek(&keys, &root.path().join("key-state.db"))
        .expect("reload zero-cut commit race StorageKEK");
    let reopened =
        super::sqlite::open(&config, kek).expect("reopen rejected zero-cut commit store");
    assert_v12_audit(&reopened);
    assert_eq!(
        load_active_key_transition(&reopened)
            .expect("load reopened zero-cut commit transition")
            .expect("reopened zero-cut commit transition remains active"),
        before_transition
    );
    assert_eq!(
        super::publication::load_stream(
            &reopened.connection,
            &reopened.key_bundle,
            publication_stream_id,
        )
        .expect("authenticate reopened projection after rejected zero-cut commit"),
        before_stream
    );
}

#[test]
fn durable_final_ack_reopen_try_complete_releases_transition_slot() {
    let (root, keys, config, mut state) = open_test_state();
    let member = recipient(0x31, 1);
    let operation_id = [0x32; 16];
    begin_key_transition(
        &mut state,
        &config,
        BeginKeyTransition {
            operation_id,
            operation: KeyTransitionOperation::Add,
            target: KeyTransitionTarget::Device(member),
            from_revision: 0,
            to_revision: 1,
            recipients: vec![member],
            replay_retirement: None,
            created_at_ms: 10,
        },
    )
    .expect("stage crash-window transition");
    mark_rotated_preparing_updates(&mut state, &config, operation_id, 11)
        .expect("rotate crash-window transition");
    let canonical_update_set = b"crash-window-key-update".to_vec();
    freeze_key_updates(
        &mut state,
        &config,
        operation_id,
        vec![FrozenKeyUpdate {
            recipient: member,
            key_revision: 1,
            canonical_update_set: canonical_update_set.clone(),
        }],
        12,
    )
    .expect("freeze crash-window update");
    freeze_key_barriers(&mut state, &config, operation_id, Vec::new(), 13)
        .expect("freeze empty crash-window barrier set");
    mark_key_barriers_committed(&mut state, &config, operation_id, 14)
        .expect("commit crash-window barriers");
    acknowledge_key_update(
        &mut state,
        &config,
        AcknowledgeKeyUpdate {
            operation_id,
            recipient: member,
            key_revision: 1,
            update_hash: canonical_update_hash(&canonical_update_set)
                .expect("hash crash-window update"),
            canonical_ack: b"crash-window-key-ack".to_vec(),
            acknowledged_at_ms: 15,
        },
    )
    .expect("durably ACK before simulated crash");
    assert!(
        load_active_key_transition(&state)
            .expect("read active crash-window transition")
            .is_some(),
        "the fixture must stop between ACK COMMIT and completion"
    );
    drop(state);

    let kek = load_or_create_storage_kek(&keys, &root.path().join("key-state.db"))
        .expect("reload crash-window StorageKEK");
    let mut reopened = super::sqlite::open(&config, kek).expect("reopen ACKed transition Store");
    assert!(matches!(
        try_complete_key_transition(&mut reopened, &config, operation_id, 16)
            .expect("recover completion after reopen"),
        KeyTransitionCompletion::Completed(ref record)
            if record.phase == KeyTransitionPhase::Complete
                && record.terminal == Some(KeyTransitionTerminal::Completed)
                && record.terminal_at_ms == Some(16)
    ));
    assert!(
        load_active_key_transition(&reopened)
            .expect("read released crash-window transition slot")
            .is_none()
    );
    assert_v12_audit(&reopened);
}

#[test]
fn barrier_freeze_rejects_old_key_reserved_commit_gap_without_transition_write() {
    use super::publication::{FreezePublicationRequest, PublicationPayloadKind, PublicationScope};

    let (_root, _keys, config, mut state) = open_test_state();
    let stream_id = [0x1a; 16];
    let stream_route = [0x1b; 16];
    let generation = [0x1c; 16];
    super::publication::create_publication_stream(
        &mut state,
        &config,
        stream_id,
        PublicationScope::Catalog,
        stream_route,
        generation,
        30,
    )
    .expect("create catalog stream");
    super::publication::freeze_publication(
        &mut state,
        &config,
        FreezePublicationRequest {
            publication_id: [0x1d; 16],
            publication_stream_id: stream_id,
            generation,
            counter_scope_token: [0x1e; 32],
            sender_counter: 0,
            inner_after: None,
            inner_through: None,
            payload_kind: PublicationPayloadKind::Control,
            blob: b"old-key-pending-publication".to_vec(),
        },
        31,
    )
    .expect("reserve old-key publication without Relay COMMIT");

    let operation_id = [0x1f; 16];
    let member = recipient(0x20, 2);
    begin_key_transition(
        &mut state,
        &config,
        BeginKeyTransition {
            operation_id,
            operation: KeyTransitionOperation::Add,
            target: KeyTransitionTarget::Device(member),
            from_revision: 1,
            to_revision: 2,
            recipients: vec![member],
            replay_retirement: None,
            created_at_ms: 32,
        },
    )
    .expect("begin add transition behind pending old-key row");
    mark_rotated_preparing_updates(&mut state, &config, operation_id, 33).expect("mark rotated");
    freeze_key_updates(
        &mut state,
        &config,
        operation_id,
        vec![FrozenKeyUpdate {
            recipient: member,
            key_revision: 2,
            canonical_update_set: b"member-update".to_vec(),
        }],
        34,
    )
    .expect("freeze member update");
    assert!(matches!(
        freeze_key_barriers(
            &mut state,
            &config,
            operation_id,
            vec![KeyTransitionStreamCut {
                scope: KeyTransitionStreamScope::Catalog,
                publication_stream_id: stream_id,
                stream_route,
                generation,
                relay_committed_outer: None,
                relay_committed_inner: None,
                barrier_sequence: 0,
                old_epoch: 1,
                new_epoch: 2,
                epoch_barrier_sha256: [0x21; 32],
            }],
            35,
        ),
        Err(RuntimeStoreError::PublicationMismatch)
    ));
    let recovery = load_active_key_transition(&state)
        .expect("load unchanged transition")
        .expect("transition remains active");
    assert_eq!(recovery.transition.phase, KeyTransitionPhase::UpdatesFrozen);
    assert!(recovery.transition.cuts.is_empty());
}

#[test]
fn renew_uses_only_catalog_cut_with_multiple_active_streams_through_reopen_audit() {
    use super::publication::{FreezePublicationRequest, PublicationPayloadKind, PublicationScope};

    let (root, keys, config, mut state) = open_test_state();
    let (_conversation_a, _stream_a) = create_active_conversation_stream(&mut state, &config, 0x81);
    let (_conversation_b, _stream_b) = create_active_conversation_stream(&mut state, &config, 0x83);
    let now = config.clock.now_ms().expect("renew fixture clock");
    let catalog = super::publication::create_publication_stream(
        &mut state,
        &config,
        [0x85; 16],
        PublicationScope::Catalog,
        [0x86; 16],
        [0x87; 16],
        now,
    )
    .expect("create catalog alongside two active conversations");

    let operation_id = [0x88; 16];
    let member = recipient(0x89, 18);
    begin_key_transition(
        &mut state,
        &config,
        BeginKeyTransition {
            operation_id,
            operation: KeyTransitionOperation::Renew,
            target: KeyTransitionTarget::Device(member),
            from_revision: 18,
            to_revision: 19,
            recipients: vec![member],
            replay_retirement: None,
            created_at_ms: now + 1,
        },
    )
    .expect("begin renew over the catalog axis only");
    mark_rotated_preparing_updates(&mut state, &config, operation_id, now + 2)
        .expect("prepare renew update");
    freeze_key_updates(
        &mut state,
        &config,
        operation_id,
        vec![FrozenKeyUpdate {
            recipient: member,
            key_revision: 19,
            canonical_update_set: b"renew-catalog-only-update".to_vec(),
        }],
        now + 3,
    )
    .expect("freeze renew update");
    let cut = transition_cut(&catalog, KeyTransitionStreamScope::Catalog, 18, [0x8a; 32]);
    freeze_key_barriers(&mut state, &config, operation_id, vec![cut], now + 4)
        .expect("freeze renew catalog cut despite unrelated active conversations");
    let barrier = super::publication::freeze_publication(
        &mut state,
        &config,
        FreezePublicationRequest {
            publication_id: [0x8b; 16],
            publication_stream_id: catalog.publication_stream_id,
            generation: catalog.generation,
            counter_scope_token: [0x8c; 32],
            sender_counter: 0,
            inner_after: None,
            inner_through: None,
            payload_kind: PublicationPayloadKind::Control,
            blob: b"renew-catalog-epoch-barrier".to_vec(),
        },
        now + 5,
    )
    .expect("freeze renew catalog barrier publication");
    super::publication::acknowledge_publication_commit(
        &mut state,
        &config,
        catalog.publication_stream_id,
        catalog.generation,
        barrier.stream_seq,
        barrier.blob_sha256,
        now + 6,
    )
    .expect("commit renew catalog barrier publication");
    mark_key_barriers_committed(&mut state, &config, operation_id, now + 7)
        .expect("commit renew catalog-only transition cut");
    assert_v12_audit(&state);

    drop(state);
    let kek = load_or_create_storage_kek(&keys, &root.path().join("key-state.db"))
        .expect("reload renew subset StorageKEK");
    let reopened = super::sqlite::open(&config, kek)
        .expect("reopen and audit renew with unrelated active conversations");
    assert_v12_audit(&reopened);
}

#[test]
fn conversation_counter_recovery_uses_only_target_cut_through_reopen_audit() {
    use super::publication::{FreezePublicationRequest, PublicationPayloadKind, PublicationScope};

    let (root, keys, config, mut state) = open_test_state();
    let (conversation_a, stream_a) = create_active_conversation_stream(&mut state, &config, 0x91);
    let (_conversation_b, _stream_b) = create_active_conversation_stream(&mut state, &config, 0x93);
    let now = config
        .clock
        .now_ms()
        .expect("counter-recovery fixture clock");
    let _catalog = super::publication::create_publication_stream(
        &mut state,
        &config,
        [0x95; 16],
        PublicationScope::Catalog,
        [0x96; 16],
        [0x97; 16],
        now,
    )
    .expect("create catalog alongside two active conversations");

    let operation_id = [0x98; 16];
    let member = recipient(0x99, 20);
    begin_key_transition(
        &mut state,
        &config,
        BeginKeyTransition {
            operation_id,
            operation: KeyTransitionOperation::CounterRecovery,
            target: KeyTransitionTarget::Conversation {
                conversation_id: *conversation_a.as_bytes(),
                stream_route: stream_a.stream_route,
            },
            from_revision: 20,
            to_revision: 21,
            recipients: vec![member],
            replay_retirement: None,
            created_at_ms: now + 1,
        },
    )
    .expect("begin target conversation counter recovery");
    mark_rotated_preparing_updates(&mut state, &config, operation_id, now + 2)
        .expect("prepare counter-recovery update");
    freeze_key_updates(
        &mut state,
        &config,
        operation_id,
        vec![FrozenKeyUpdate {
            recipient: member,
            key_revision: 21,
            canonical_update_set: b"conversation-counter-recovery-update".to_vec(),
        }],
        now + 3,
    )
    .expect("freeze counter-recovery update");
    let cut = transition_cut(
        &stream_a,
        KeyTransitionStreamScope::Conversation(*conversation_a.as_bytes()),
        20,
        [0x9a; 32],
    );
    freeze_key_barriers(&mut state, &config, operation_id, vec![cut], now + 4)
        .expect("freeze only the target conversation cut");
    let barrier = super::publication::freeze_publication(
        &mut state,
        &config,
        FreezePublicationRequest {
            publication_id: [0x9b; 16],
            publication_stream_id: stream_a.publication_stream_id,
            generation: stream_a.generation,
            counter_scope_token: [0x9c; 32],
            sender_counter: 0,
            inner_after: None,
            inner_through: None,
            payload_kind: PublicationPayloadKind::Control,
            blob: b"conversation-counter-recovery-barrier".to_vec(),
        },
        now + 5,
    )
    .expect("freeze target conversation barrier publication");
    super::publication::acknowledge_publication_commit(
        &mut state,
        &config,
        stream_a.publication_stream_id,
        stream_a.generation,
        barrier.stream_seq,
        barrier.blob_sha256,
        now + 6,
    )
    .expect("commit target conversation barrier publication");
    mark_key_barriers_committed(&mut state, &config, operation_id, now + 7)
        .expect("commit target-only counter-recovery transition cut");
    assert_v12_audit(&state);

    drop(state);
    let kek = load_or_create_storage_kek(&keys, &root.path().join("key-state.db"))
        .expect("reload counter-recovery subset StorageKEK");
    let reopened = super::sqlite::open(&config, kek)
        .expect("reopen and audit target-only counter recovery with unrelated active streams");
    assert_v12_audit(&reopened);
}

#[test]
fn canonical_update_hash_rejects_empty_and_oversize_payloads() {
    assert!(canonical_update_hash(&[]).is_err());
    assert!(canonical_update_hash(&[1]).is_ok());
    assert!(canonical_update_hash(&vec![1; MAX_CANONICAL_KEY_UPDATE_BYTES + 1]).is_err());
}

#[test]
fn maximum_protocol_key_update_freezes_and_reopens_byte_exact() {
    let (root, keys, config, mut state) = open_test_state();
    let operation_id = [0x2d; 16];
    let target = recipient(0x22, 9);
    let canonical_update_set = maximal_canonical_key_update_set();
    assert_eq!(canonical_update_set.len(), 277_297);
    assert!(canonical_update_set.len() <= MAX_CANONICAL_KEY_UPDATE_BYTES);

    begin_key_transition(
        &mut state,
        &config,
        BeginKeyTransition {
            operation_id,
            operation: KeyTransitionOperation::Add,
            target: KeyTransitionTarget::Device(target),
            from_revision: 11,
            to_revision: 12,
            recipients: vec![target],
            replay_retirement: None,
            created_at_ms: 100,
        },
    )
    .expect("begin maximum KeyUpdate transition");
    mark_rotated_preparing_updates(&mut state, &config, operation_id, 101)
        .expect("mark maximum KeyUpdate transition rotated");
    let expected = FrozenKeyUpdate {
        recipient: target,
        key_revision: 12,
        canonical_update_set,
    };
    freeze_key_updates(
        &mut state,
        &config,
        operation_id,
        vec![expected.clone()],
        102,
    )
    .expect("freeze production-shaped maximum KeyUpdate in SQLite");
    assert_eq!(
        load_key_update_for_sync(
            &state,
            KeySyncRead {
                recipient: target,
                known_revision: 11,
                requested_revision: 12,
            },
        )
        .expect("read maximum KeyUpdate before reopen"),
        expected
    );
    assert_v12_audit(&state);
    drop(state);

    let kek = load_or_create_storage_kek(&keys, &root.path().join("key-state.db"))
        .expect("reload maximum KeyUpdate StorageKEK");
    let reopened = super::sqlite::open(&config, kek).expect("reopen maximum KeyUpdate SQLite");
    assert_eq!(
        load_key_update_for_sync(
            &reopened,
            KeySyncRead {
                recipient: target,
                known_revision: 11,
                requested_revision: 12,
            },
        )
        .expect("read maximum KeyUpdate after reopen"),
        expected
    );
    assert_v12_audit(&reopened);
}

#[test]
fn maximum_attached_key_update_row_seals_and_reopens_byte_exact() {
    let (root, keys, config, mut state) = open_test_state();
    let operation_id = [0x2e; 16];
    let target = recipient(0x22, 10);
    begin_key_transition(
        &mut state,
        &config,
        BeginKeyTransition {
            operation_id,
            operation: KeyTransitionOperation::Add,
            target: KeyTransitionTarget::Device(target),
            from_revision: 11,
            to_revision: 12,
            recipients: vec![target],
            replay_retirement: None,
            created_at_ms: 100,
        },
    )
    .expect("begin maximum attached KeyUpdate transition");
    mark_rotated_preparing_updates(&mut state, &config, operation_id, 101)
        .expect("mark maximum attached KeyUpdate transition rotated");
    freeze_key_updates(
        &mut state,
        &config,
        operation_id,
        vec![FrozenKeyUpdate {
            recipient: target,
            key_revision: 12,
            canonical_update_set: maximal_canonical_key_update_set(),
        }],
        102,
    )
    .expect("freeze maximum attached KeyUpdate baseline");
    let baseline = load_active_key_transition(&state)
        .expect("load maximum attached baseline")
        .expect("maximum attached transition remains active");
    let (transition, update) = maximum_attached_transition_state(
        baseline.transition,
        baseline
            .updates
            .into_iter()
            .next()
            .expect("baseline update"),
    );
    let expected = KeyTransitionRecovery {
        transition: transition.clone(),
        updates: vec![update.clone()],
    };
    replace_transition_and_update_for_capacity_test(&mut state, &config, transition, update)
        .expect("seal production maximum attached KeyUpdate row");

    let sealed_state_bytes: i64 = state
        .connection
        .query_row(
            "SELECT sealed_state_bytes FROM remote_key_update_outbox
             WHERE operation_id = ?1",
            rusqlite::params![&operation_id[..]],
            |row| row.get(0),
        )
        .expect("read maximum attached sealed row bytes");
    let sealed_state_bytes = usize::try_from(sealed_state_bytes).expect("sealed bytes fit usize");
    let plaintext_bytes = sealed_state_bytes - super::cipher::ROW_BLOB_V1_OVERHEAD_LEN;
    assert_eq!(plaintext_bytes, 869_893);
    assert!(sealed_state_bytes > 524_328);
    assert!(sealed_state_bytes <= 1_048_616);
    assert_eq!(
        load_key_transition_for_capacity_test(&state, operation_id)
            .expect("read maximum attached row before reopen"),
        expected.clone()
    );
    assert_v12_audit(&state);
    drop(state);

    let kek = load_or_create_storage_kek(&keys, &root.path().join("key-state.db"))
        .expect("reload maximum attached StorageKEK");
    let reopened =
        super::sqlite::open(&config, kek).expect("reopen maximum attached KeyUpdate SQLite");
    assert_eq!(
        load_key_transition_for_capacity_test(&reopened, operation_id)
            .expect("read maximum attached row after reopen"),
        expected
    );
    assert_v12_audit(&reopened);
}

#[test]
fn activate_conversation_runs_exact_phase_ack_and_business_fence_contract() {
    let (_root, _keys, config, mut state) = open_test_state();
    let operation_id = [0x31; 16];
    let roster = vec![recipient(0x41, 7)];
    let begin = BeginKeyTransition {
        operation_id,
        operation: KeyTransitionOperation::ActivateConversation,
        target: KeyTransitionTarget::Conversation {
            conversation_id: [0x51; 16],
            stream_route: [0x52; 16],
        },
        from_revision: 8,
        to_revision: 9,
        recipients: roster.clone(),
        replay_retirement: None,
        created_at_ms: 100,
    };
    let started = begin_key_transition(&mut state, &config, begin.clone())
        .expect("begin conversation activation");
    assert_eq!(started.phase, KeyTransitionPhase::DrainingOld);
    assert!(matches!(
        ensure_remote_ingress_allowed(&state, RemoteTransitionIngressClass::Business),
        Err(RuntimeStoreError::InvalidStateTransition)
    ));
    assert!(ensure_remote_ingress_allowed(&state, RemoteTransitionIngressClass::KeySync).is_ok());
    assert!(matches!(
        begin_key_transition(
            &mut state,
            &config,
            BeginKeyTransition {
                operation_id: [0x32; 16],
                ..begin
            },
        ),
        Err(RuntimeStoreError::InvalidStateTransition)
    ));
    assert!(matches!(
        freeze_key_updates(&mut state, &config, operation_id, Vec::new(), 101),
        Err(RuntimeStoreError::PublicationMismatch)
    ));
    mark_rotated_preparing_updates(&mut state, &config, operation_id, 101)
        .expect("enter update preparation");
    let updates = vec![FrozenKeyUpdate {
        recipient: roster[0],
        key_revision: 9,
        canonical_update_set: b"exact-key-update".to_vec(),
    }];
    freeze_key_updates(&mut state, &config, operation_id, updates.clone(), 102)
        .expect("freeze exact update set");
    freeze_key_updates(&mut state, &config, operation_id, updates.clone(), 102)
        .expect("exact freeze retry is idempotent");
    assert_eq!(
        load_key_update_for_sync(
            &state,
            KeySyncRead {
                recipient: roster[0],
                known_revision: 8,
                requested_revision: 9,
            },
        )
        .expect("read exact frozen KeySync replay"),
        updates[0]
    );
    assert!(matches!(
        load_key_update_for_sync(
            &state,
            KeySyncRead {
                recipient: roster[0],
                known_revision: 7,
                requested_revision: 9,
            },
        ),
        Err(RuntimeStoreError::PublicationMismatch)
    ));
    assert_eq!(
        load_active_key_transition(&state)
            .expect("load authenticated active recovery")
            .expect("active transition")
            .updates
            .len(),
        1
    );
    freeze_key_barriers(&mut state, &config, operation_id, Vec::new(), 103)
        .expect("conversation activation uses an empty stream cut");
    mark_key_barriers_committed(&mut state, &config, operation_id, 104)
        .expect("mark empty activation barrier committed");
    assert!(matches!(
        ensure_remote_ingress_allowed(&state, RemoteTransitionIngressClass::Business),
        Err(RuntimeStoreError::InvalidStateTransition)
    ));

    assert!(matches!(
        complete_key_transition(&mut state, &config, operation_id, 105),
        Err(RuntimeStoreError::InvalidStateTransition)
    ));
    let update_hash = canonical_update_hash(&updates[0].canonical_update_set).expect("update hash");
    assert!(matches!(
        acknowledge_key_update(
            &mut state,
            &config,
            AcknowledgeKeyUpdate {
                operation_id,
                recipient: roster[0],
                key_revision: 9,
                update_hash: [0x99; 32],
                canonical_ack: b"exact-ack".to_vec(),
                acknowledged_at_ms: 105,
            },
        ),
        Err(RuntimeStoreError::PublicationMismatch)
    ));
    acknowledge_key_update(
        &mut state,
        &config,
        AcknowledgeKeyUpdate {
            operation_id,
            recipient: roster[0],
            key_revision: 9,
            update_hash,
            canonical_ack: b"exact-ack".to_vec(),
            acknowledged_at_ms: 105,
        },
    )
    .expect("bind exact ACK to exact update");
    acknowledge_key_update(
        &mut state,
        &config,
        AcknowledgeKeyUpdate {
            operation_id,
            recipient: roster[0],
            key_revision: 9,
            update_hash,
            canonical_ack: b"exact-ack".to_vec(),
            acknowledged_at_ms: 106,
        },
    )
    .expect("exact key ACK replay preserves first timestamp");
    let completed = complete_key_transition(&mut state, &config, operation_id, 106)
        .expect("complete only after every recipient ACK");
    assert_eq!(completed.terminal, Some(KeyTransitionTerminal::Completed));
    assert_eq!(
        completed.retain_until_ms,
        Some(106 + KEY_TRANSITION_TOMBSTONE_RETENTION_MS)
    );
    assert_v12_audit(&state);
    assert!(
        load_active_key_transition(&state)
            .expect("load terminal recovery state")
            .is_none()
    );
    assert!(ensure_remote_ingress_allowed(&state, RemoteTransitionIngressClass::Business).is_ok());
}

#[test]
fn key_update_ack_resolver_rejects_ambiguous_retained_candidates() {
    let (_root, _keys, config, mut state) = open_test_state();
    let member = recipient(0x42, 8);
    let canonical_update_set = b"same-revision-update".to_vec();
    for (operation_id, conversation_id, stream_route, base) in [
        ([0x43; 16], [0x44; 16], [0x45; 16], 200_u64),
        ([0x46; 16], [0x47; 16], [0x48; 16], 210_u64),
    ] {
        begin_key_transition(
            &mut state,
            &config,
            BeginKeyTransition {
                operation_id,
                operation: KeyTransitionOperation::ActivateConversation,
                target: KeyTransitionTarget::Conversation {
                    conversation_id,
                    stream_route,
                },
                from_revision: 8,
                to_revision: 9,
                recipients: vec![member],
                replay_retirement: None,
                created_at_ms: base,
            },
        )
        .expect("begin duplicate-revision fixture transition");
        mark_rotated_preparing_updates(&mut state, &config, operation_id, base + 1)
            .expect("mark duplicate-revision fixture rotated");
        freeze_key_updates(
            &mut state,
            &config,
            operation_id,
            vec![FrozenKeyUpdate {
                recipient: member,
                key_revision: 9,
                canonical_update_set: canonical_update_set.clone(),
            }],
            base + 2,
        )
        .expect("freeze duplicate-revision fixture update");
        freeze_key_barriers(&mut state, &config, operation_id, Vec::new(), base + 3)
            .expect("freeze empty activation barrier");
        mark_key_barriers_committed(&mut state, &config, operation_id, base + 4)
            .expect("commit empty activation barrier");
        acknowledge_key_update(
            &mut state,
            &config,
            AcknowledgeKeyUpdate {
                operation_id,
                recipient: member,
                key_revision: 9,
                update_hash: canonical_update_hash(&canonical_update_set)
                    .expect("duplicate update hash"),
                canonical_ack: format!("ack-{base}").into_bytes(),
                acknowledged_at_ms: base + 5,
            },
        )
        .expect("ack duplicate-revision fixture update");
        complete_key_transition(&mut state, &config, operation_id, base + 6)
            .expect("complete duplicate-revision fixture transition");
    }
    assert!(matches!(
        resolve_key_update_ack(
            &state,
            KeyUpdateAckResolve {
                recipient: member,
                key_revision: 9,
                update_hash: canonical_update_hash(&canonical_update_set)
                    .expect("ambiguous update hash"),
            },
        ),
        Err(RuntimeStoreError::PublicationMismatch)
    ));
}

#[test]
fn relay_commit_is_not_stream_applied_ack_and_complete_requires_both_ack_families() {
    use super::publication::{FreezePublicationRequest, PublicationPayloadKind, PublicationScope};

    let (root, keys, config, mut state) = open_test_state();
    let stream_id = [0x21; 16];
    let stream_route = [0x22; 16];
    let generation = [0x23; 16];
    super::publication::create_publication_stream(
        &mut state,
        &config,
        stream_id,
        PublicationScope::Catalog,
        stream_route,
        generation,
        400,
    )
    .expect("create authenticated catalog publication stream");
    let operation_id = [0x24; 16];
    let existing_device = recipient(0x20, 3);
    let new_device = recipient(0x25, 4);
    begin_key_transition(
        &mut state,
        &config,
        BeginKeyTransition {
            operation_id,
            operation: KeyTransitionOperation::Add,
            target: KeyTransitionTarget::Device(new_device),
            from_revision: 4,
            to_revision: 5,
            recipients: vec![new_device],
            replay_retirement: None,
            created_at_ms: 401,
        },
    )
    .expect("begin add transition");
    mark_rotated_preparing_updates(&mut state, &config, operation_id, 402)
        .expect("prepare add updates");
    let canonical_update_set = b"new-device-update".to_vec();
    freeze_key_updates(
        &mut state,
        &config,
        operation_id,
        vec![FrozenKeyUpdate {
            recipient: new_device,
            key_revision: 5,
            canonical_update_set: canonical_update_set.clone(),
        }],
        403,
    )
    .expect("freeze add update");
    let barrier_hash = [0x26; 32];
    let cut = KeyTransitionStreamCut {
        scope: KeyTransitionStreamScope::Catalog,
        publication_stream_id: stream_id,
        stream_route,
        generation,
        relay_committed_outer: None,
        relay_committed_inner: None,
        barrier_sequence: 0,
        old_epoch: 0,
        new_epoch: 1,
        epoch_barrier_sha256: barrier_hash,
    };
    freeze_key_barriers(&mut state, &config, operation_id, vec![cut], 404)
        .expect("freeze exact committed cut");
    let frozen = super::publication::freeze_publication(
        &mut state,
        &config,
        FreezePublicationRequest {
            publication_id: [0x27; 16],
            publication_stream_id: stream_id,
            generation,
            counter_scope_token: [0x28; 32],
            sender_counter: 0,
            inner_after: None,
            inner_through: None,
            payload_kind: PublicationPayloadKind::Control,
            blob: b"sealed-epoch-barrier".to_vec(),
        },
        405,
    )
    .expect("freeze barrier publication");
    super::publication::acknowledge_publication_commit(
        &mut state,
        &config,
        stream_id,
        generation,
        frozen.stream_seq,
        frozen.blob_sha256,
        406,
    )
    .expect("Relay COMMIT barrier publication");
    mark_key_barriers_committed(&mut state, &config, operation_id, 407)
        .expect("record committed barrier set");
    assert!(
        ensure_no_active_transition_for_business(
            &state.connection,
            &state.key_bundle,
            state.database_id,
        )
        .is_err(),
        "Relay COMMIT alone must not release business before every required device ACK"
    );
    let update_hash = canonical_update_hash(&canonical_update_set).expect("update hash");
    assert_eq!(
        resolve_key_update_ack(
            &state,
            KeyUpdateAckResolve {
                recipient: new_device,
                key_revision: 5,
                update_hash,
            },
        )
        .expect("resolve exact active KeyUpdateAck"),
        KeyUpdateAckBinding { operation_id }
    );
    assert!(
        resolve_key_update_ack(
            &state,
            KeyUpdateAckResolve {
                update_hash: [0x99; 32],
                recipient: new_device,
                key_revision: 5,
            },
        )
        .is_err()
    );
    assert!(
        resolve_transition_snapshot_permit_for_test(
            &state,
            TransitionSnapshotQuery {
                recipient: new_device,
                key_revision: 5,
                authorization_hash: [0x2b; 32],
                scope: KeyTransitionStreamScope::Catalog,
                requested_cursor: StreamCursor::BeforeFirst,
            },
        )
        .is_err(),
        "KeyUpdateAck must precede transition snapshot permit issuance"
    );
    acknowledge_key_update(
        &mut state,
        &config,
        AcknowledgeKeyUpdate {
            operation_id,
            recipient: new_device,
            key_revision: 5,
            update_hash,
            canonical_ack: b"key-update-ack".to_vec(),
            acknowledged_at_ms: 408,
        },
    )
    .expect("record key update ACK");
    assert!(matches!(
        complete_key_transition(&mut state, &config, operation_id, 409),
        Err(RuntimeStoreError::InvalidStateTransition)
    ));
    let stream_query = StreamAppliedAckResolve {
        recipient: new_device,
        key_revision: 5,
        scope: KeyTransitionStreamScope::Catalog,
        stream_route,
        stream_generation: generation,
        applied_stream_seq: 0,
        inner_cursor: None,
        key_epoch: 1,
        epoch_barrier_sha256: barrier_hash,
        authorization_hash: [0x2b; 32],
    };
    let stream_ack = AcknowledgeStreamApplied {
        operation_id,
        recipient: new_device,
        key_revision: 5,
        scope: KeyTransitionStreamScope::Catalog,
        stream_route,
        stream_generation: generation,
        applied_stream_seq: 0,
        inner_cursor: None,
        key_epoch: 1,
        epoch_barrier_sha256: barrier_hash,
        authorization_hash: [0x2b; 32],
        canonical_ack: b"stream-applied-ack".to_vec(),
        acknowledged_at_ms: 409,
    };
    assert!(
        resolve_stream_applied_ack(&state, stream_query).is_err(),
        "new Add target must not ACK a transition cut before its directed snapshot is durably flushed"
    );
    assert!(matches!(
        acknowledge_stream_applied(&mut state, &config, stream_ack.clone()),
        Err(RuntimeStoreError::PublicationMismatch)
    ));
    assert!(
        resolve_transition_snapshot_permit_for_test(
            &state,
            TransitionSnapshotQuery {
                recipient: existing_device,
                key_revision: 5,
                authorization_hash: [0x2b; 32],
                scope: KeyTransitionStreamScope::Catalog,
                requested_cursor: StreamCursor::BeforeFirst,
            },
        )
        .is_err(),
        "only the exact Add target may receive the transition snapshot permit"
    );
    assert!(
        resolve_transition_snapshot_permit_for_test(
            &state,
            TransitionSnapshotQuery {
                recipient: new_device,
                key_revision: 5,
                authorization_hash: [0x2b; 32],
                scope: KeyTransitionStreamScope::Catalog,
                requested_cursor: StreamCursor::At(0),
            },
        )
        .is_err(),
        "transition snapshot admission is restricted to Subscribe(BeforeFirst)"
    );
    let permit = resolve_transition_snapshot_permit_for_test(
        &state,
        TransitionSnapshotQuery {
            recipient: new_device,
            key_revision: 5,
            authorization_hash: [0x2b; 32],
            scope: KeyTransitionStreamScope::Catalog,
            requested_cursor: StreamCursor::BeforeFirst,
        },
    )
    .expect("issue exact target transition snapshot permit after KeyUpdateAck");
    assert_eq!(permit.operation_id(), operation_id);
    assert_eq!(permit.recipient(), new_device);
    assert_eq!(permit.publication_stream_id(), stream_id);
    assert_eq!(permit.stream_route(), stream_route);
    assert_eq!(permit.generation(), generation);
    assert_eq!(permit.relay_committed_outer(), None);
    assert_eq!(permit.relay_committed_inner(), None);
    assert_eq!(permit.barrier_sequence(), 0);
    assert_eq!(permit.key_directory_revision(), 5);
    assert_eq!(permit.key_epoch(), 1);
    assert_eq!(permit.epoch_barrier_sha256(), barrier_hash);
    assert!(permit.into_flush([0; 32]).is_err());
    let permit = resolve_transition_snapshot_permit_for_test(
        &state,
        TransitionSnapshotQuery {
            recipient: new_device,
            key_revision: 5,
            authorization_hash: [0x2b; 32],
            scope: KeyTransitionStreamScope::Catalog,
            requested_cursor: StreamCursor::BeforeFirst,
        },
    )
    .expect("reissue the same exact permit after invalid local flush proof");
    let flushed = mark_transition_snapshot_flushed(
        &mut state,
        &config,
        permit
            .into_flush([0x2a; 32])
            .expect("bind canonical SyncComplete hash"),
        409,
    )
    .expect("durably record snapshot and SyncComplete flush");
    assert_eq!(flushed.sync_complete_sha256, [0x2a; 32]);
    assert_eq!(
        resolve_stream_applied_ack(&state, stream_query)
            .expect("resolve exact active StreamAppliedAck"),
        StreamAppliedAckBinding { operation_id }
    );
    assert!(
        resolve_stream_applied_ack(
            &state,
            StreamAppliedAckResolve {
                scope: KeyTransitionStreamScope::Conversation([0x29; 16]),
                ..stream_query
            },
        )
        .is_err()
    );
    assert!(matches!(
        acknowledge_stream_applied(
            &mut state,
            &config,
            AcknowledgeStreamApplied {
                scope: KeyTransitionStreamScope::Conversation([0x29; 16]),
                ..stream_ack.clone()
            },
        ),
        Err(RuntimeStoreError::PublicationMismatch)
    ));
    let first = acknowledge_stream_applied(&mut state, &config, stream_ack.clone())
        .expect("persist exact StreamAppliedAck");
    assert_eq!(first.state_changed_at_ms, 409);
    let replayed = acknowledge_stream_applied(
        &mut state,
        &config,
        AcknowledgeStreamApplied {
            acknowledged_at_ms: 410,
            ..stream_ack.clone()
        },
    )
    .expect("exact StreamAppliedAck replay is idempotent");
    assert_eq!(replayed.state_changed_at_ms, 409);
    complete_key_transition(&mut state, &config, operation_id, 410)
        .expect("complete after both ACK families");
    ensure_no_active_transition_for_business(
        &state.connection,
        &state.key_bundle,
        state.database_id,
    )
    .expect("all required ACKs release the active transition business fence");
    assert_v12_audit(&state);
    assert_eq!(
        resolve_key_update_ack(
            &state,
            KeyUpdateAckResolve {
                recipient: new_device,
                key_revision: 5,
                update_hash,
            },
        )
        .expect("resolve retained terminal KeyUpdateAck"),
        KeyUpdateAckBinding { operation_id }
    );
    assert_eq!(
        resolve_stream_applied_ack(&state, stream_query)
            .expect("resolve retained terminal StreamAppliedAck"),
        StreamAppliedAckBinding { operation_id }
    );
    let terminal_replay = acknowledge_stream_applied(
        &mut state,
        &config,
        AcknowledgeStreamApplied {
            acknowledged_at_ms: 411,
            ..stream_ack.clone()
        },
    )
    .expect("terminal exact StreamAppliedAck replay remains idempotent");
    assert_eq!(terminal_replay.state_changed_at_ms, 409);

    drop(state);
    let kek = load_or_create_storage_kek(&keys, &root.path().join("key-state.db"))
        .expect("reload tagged ACK StorageKEK");
    let mut reopened = super::sqlite::open(&config, kek).expect("reopen tagged ACK store");
    assert_v12_audit(&reopened);
    assert_eq!(
        resolve_stream_applied_ack(&reopened, stream_query)
            .expect("resolve retained terminal StreamAppliedAck after reopen"),
        StreamAppliedAckBinding { operation_id }
    );
    let reopened_replay = acknowledge_stream_applied(
        &mut reopened,
        &config,
        AcknowledgeStreamApplied {
            acknowledged_at_ms: 412,
            ..stream_ack
        },
    )
    .expect("reopen preserves canonical StreamAppliedAck replay");
    assert_eq!(reopened_replay.state_changed_at_ms, 409);
}

#[test]
fn add_revoke_roster_rules_and_post_rotation_cancel_are_fail_closed() {
    let (_root, _keys, config, mut state) = open_test_state();
    let target = recipient(0x61, 11);
    assert!(matches!(
        begin_key_transition(
            &mut state,
            &config,
            BeginKeyTransition {
                operation_id: [0x62; 16],
                operation: KeyTransitionOperation::Add,
                target: KeyTransitionTarget::Device(target),
                from_revision: 1,
                to_revision: 2,
                recipients: vec![recipient(0x63, 12)],
                replay_retirement: None,
                created_at_ms: 200,
            },
        ),
        Err(RuntimeStoreError::PublicationMismatch)
    ));
    assert!(matches!(
        begin_key_transition(
            &mut state,
            &config,
            BeginKeyTransition {
                operation_id: [0x64; 16],
                operation: KeyTransitionOperation::Revoke,
                target: KeyTransitionTarget::Device(target),
                from_revision: 1,
                to_revision: 2,
                recipients: vec![target],
                replay_retirement: None,
                created_at_ms: 200,
            },
        ),
        Err(RuntimeStoreError::PublicationMismatch)
    ));

    let staged_operation_id = [0x65; 16];
    let survivor = recipient(0x66, 12);
    let staged = begin_key_transition(
        &mut state,
        &config,
        BeginKeyTransition {
            operation_id: staged_operation_id,
            operation: KeyTransitionOperation::Revoke,
            target: KeyTransitionTarget::Device(target),
            from_revision: 1,
            to_revision: 2,
            recipients: vec![survivor],
            replay_retirement: None,
            created_at_ms: 200,
        },
    )
    .expect("begin revoke with target excluded from new roster");
    assert_eq!(staged.phase, KeyTransitionPhase::DrainingOld);
    let cancelled = cancel_key_transition(&mut state, &config, staged_operation_id, 201)
        .expect("cancel staged transition before rotation");
    assert_eq!(cancelled.phase, KeyTransitionPhase::Complete);
    assert_eq!(cancelled.terminal, Some(KeyTransitionTerminal::Cancelled));
    assert!(
        load_active_key_transition(&state)
            .expect("load cancelled staged transition")
            .is_none()
    );
    assert!(ensure_remote_ingress_allowed(&state, RemoteTransitionIngressClass::Business).is_ok());

    let operation_id = [0x67; 16];
    let member = recipient(0x68, 13);
    begin_key_transition(
        &mut state,
        &config,
        BeginKeyTransition {
            operation_id,
            operation: KeyTransitionOperation::ActivateConversation,
            target: KeyTransitionTarget::Conversation {
                conversation_id: [0x69; 16],
                stream_route: [0x6a; 16],
            },
            from_revision: 1,
            to_revision: 2,
            recipients: vec![member],
            replay_retirement: None,
            created_at_ms: 202,
        },
    )
    .expect("begin transition used to exercise the rotation boundary");
    mark_rotated_preparing_updates(&mut state, &config, operation_id, 203)
        .expect("enter rotated phase");
    assert!(matches!(
        cancel_key_transition(&mut state, &config, operation_id, 204),
        Err(RuntimeStoreError::InvalidStateTransition)
    ));
    let rotated = load_active_key_transition(&state)
        .expect("load transition after rejected rotated cancel")
        .expect("rejected cancel must preserve active transition");
    assert_eq!(
        rotated.transition.phase,
        KeyTransitionPhase::RotatedPreparingUpdates
    );
    assert!(matches!(
        ensure_remote_ingress_allowed(&state, RemoteTransitionIngressClass::Business),
        Err(RuntimeStoreError::InvalidStateTransition)
    ));

    let canonical_update_set = b"member-update".to_vec();
    freeze_key_updates(
        &mut state,
        &config,
        operation_id,
        vec![FrozenKeyUpdate {
            recipient: member,
            key_revision: 2,
            canonical_update_set: canonical_update_set.clone(),
        }],
        205,
    )
    .expect("freeze member update");
    assert!(matches!(
        cancel_key_transition(&mut state, &config, operation_id, 206),
        Err(RuntimeStoreError::InvalidStateTransition)
    ));
    let updates_frozen = load_active_key_transition(&state)
        .expect("load transition after rejected updates-frozen cancel")
        .expect("rejected cancel must preserve active transition");
    assert_eq!(
        updates_frozen.transition.phase,
        KeyTransitionPhase::UpdatesFrozen
    );
    assert_eq!(
        updates_frozen.updates[0].lifecycle,
        KeyUpdateLifecycle::Frozen
    );
    assert!(matches!(
        ensure_remote_ingress_allowed(&state, RemoteTransitionIngressClass::Business),
        Err(RuntimeStoreError::InvalidStateTransition)
    ));

    freeze_key_barriers(&mut state, &config, operation_id, Vec::new(), 207)
        .expect("freeze empty activation barrier cut");
    assert!(matches!(
        cancel_key_transition(&mut state, &config, operation_id, 208),
        Err(RuntimeStoreError::InvalidStateTransition)
    ));
    let barriers_frozen = load_active_key_transition(&state)
        .expect("load transition after rejected barriers-frozen cancel")
        .expect("rejected cancel must preserve active transition");
    assert_eq!(
        barriers_frozen.transition.phase,
        KeyTransitionPhase::BarriersFrozen
    );
    assert_eq!(
        barriers_frozen.updates[0].lifecycle,
        KeyUpdateLifecycle::Frozen
    );
    assert!(matches!(
        ensure_remote_ingress_allowed(&state, RemoteTransitionIngressClass::Business),
        Err(RuntimeStoreError::InvalidStateTransition)
    ));

    mark_key_barriers_committed(&mut state, &config, operation_id, 209)
        .expect("commit empty activation barrier cut");
    assert!(matches!(
        cancel_key_transition(&mut state, &config, operation_id, 210),
        Err(RuntimeStoreError::InvalidStateTransition)
    ));
    let barriers_committed = load_active_key_transition(&state)
        .expect("load transition after rejected barriers-committed cancel")
        .expect("rejected cancel must preserve active transition");
    assert_eq!(
        barriers_committed.transition.phase,
        KeyTransitionPhase::BarriersCommitted
    );

    acknowledge_key_update(
        &mut state,
        &config,
        AcknowledgeKeyUpdate {
            operation_id,
            recipient: member,
            key_revision: 2,
            update_hash: canonical_update_hash(&canonical_update_set).expect("update hash"),
            canonical_ack: b"member-ack".to_vec(),
            acknowledged_at_ms: 211,
        },
    )
    .expect("ack member update");
    let completed = complete_key_transition(&mut state, &config, operation_id, 212)
        .expect("complete transition after member ACK");
    assert_eq!(completed.terminal, Some(KeyTransitionTerminal::Completed));
    assert!(matches!(
        cancel_key_transition(&mut state, &config, operation_id, 213),
        Err(RuntimeStoreError::PublicationMismatch)
    ));
    assert_v12_audit(&state);
    assert!(ensure_remote_ingress_allowed(&state, RemoteTransitionIngressClass::Business).is_ok());
}

#[test]
fn offline_transition_ciphertext_tamper_reopen_fails_without_rewriting_artifacts() {
    let (_root, keys, config, mut state) = open_test_state();
    let operation_id = [0x71; 16];
    begin_key_transition(
        &mut state,
        &config,
        BeginKeyTransition {
            operation_id,
            operation: KeyTransitionOperation::ActivateConversation,
            target: KeyTransitionTarget::Conversation {
                conversation_id: [0x72; 16],
                stream_route: [0x73; 16],
            },
            from_revision: 0,
            to_revision: 1,
            recipients: vec![recipient(0x74, 1)],
            replay_retirement: None,
            created_at_ms: 300,
        },
    )
    .expect("persist transition before tamper");
    let mut sealed: Vec<u8> = state
        .connection
        .query_row(
            "SELECT sealed_state FROM remote_key_transitions WHERE operation_id = ?1",
            [&operation_id[..]],
            |row| row.get(0),
        )
        .expect("read sealed transition");
    sealed[20] ^= 0x80;
    state
        .connection
        .execute(
            "UPDATE remote_key_transitions SET sealed_state = ?1 WHERE operation_id = ?2",
            rusqlite::params![&sealed, &operation_id[..]],
        )
        .expect("apply offline-equivalent ciphertext tamper");
    assert!(
        validate_v12_integrity(
            &state.connection,
            &state.key_bundle,
            state.database_id,
            &super::sqlite::load_runtime_ledger(
                &state.connection,
                &state.key_bundle,
                state.database_id,
            )
            .expect("load ledger after tamper"),
        )
        .is_err()
    );
    state
        .connection
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
        .expect("checkpoint tampered fixture");
    drop(state);
    let before = artifact_snapshot(&config.storage_path);
    let kek = load_or_create_storage_kek(&keys, &_root.path().join("key-state.db"))
        .expect("reload StorageKEK");
    let error = match super::sqlite::open(&config, kek) {
        Ok(_) => panic!("tampered v12 open must fail closed"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        RuntimeStoreError::UnknownOrCorruptSchema | RuntimeStoreError::Cipher(_)
    ));
    assert_eq!(artifact_snapshot(&config.storage_path), before);
}

fn complete_gc_fixture(
    state: &mut super::sqlite::RuntimeSqlite,
    config: &RuntimeStoreConfig,
    operation_id: [u8; 16],
    terminal_at_ms: u64,
) {
    let member = recipient(
        operation_id[0].wrapping_add(1),
        u64::from(operation_id[0]) + 1,
    );
    let base = terminal_at_ms - 5;
    begin_key_transition(
        state,
        config,
        BeginKeyTransition {
            operation_id,
            operation: KeyTransitionOperation::ActivateConversation,
            target: KeyTransitionTarget::Conversation {
                conversation_id: [operation_id[0].wrapping_add(2); 16],
                stream_route: [operation_id[0].wrapping_add(3); 16],
            },
            from_revision: 1,
            to_revision: 2,
            recipients: vec![member],
            replay_retirement: None,
            created_at_ms: base,
        },
    )
    .expect("begin GC fixture transition");
    mark_rotated_preparing_updates(state, config, operation_id, base + 1)
        .expect("rotate GC fixture transition");
    let canonical_update_set = vec![operation_id[0]; 32];
    freeze_key_updates(
        state,
        config,
        operation_id,
        vec![FrozenKeyUpdate {
            recipient: member,
            key_revision: 2,
            canonical_update_set: canonical_update_set.clone(),
        }],
        base + 2,
    )
    .expect("freeze GC fixture update");
    freeze_key_barriers(state, config, operation_id, Vec::new(), base + 3)
        .expect("freeze GC fixture empty barriers");
    mark_key_barriers_committed(state, config, operation_id, base + 4)
        .expect("commit GC fixture empty barriers");
    acknowledge_key_update(
        state,
        config,
        AcknowledgeKeyUpdate {
            operation_id,
            recipient: member,
            key_revision: 2,
            update_hash: canonical_update_hash(&canonical_update_set).expect("GC update hash"),
            canonical_ack: vec![operation_id[0].wrapping_add(4); 16],
            acknowledged_at_ms: terminal_at_ms,
        },
    )
    .expect("ack GC fixture update");
    complete_key_transition(state, config, operation_id, terminal_at_ms)
        .expect("complete GC fixture transition");
    let trust_domain = [0x7a; 32];
    let retirement_at_ms = terminal_at_ms + COUNTER_RETIREMENT_RETENTION_MS;
    let plan = load_pending_counter_retirement_plan(state, trust_domain, retirement_at_ms)
        .expect("load GC fixture counter-retirement plan")
        .expect("completed transition requires explicit counter-retirement finalization");
    assert!(plan.scope_tokens.is_empty());
    assert_eq!(
        apply_counter_retirement_after_guard_readback(
            state,
            config,
            trust_domain,
            &plan,
            retirement_at_ms,
        )
        .expect("apply empty GC fixture counter-retirement plan"),
        CounterRetirementApplyOutcome::Applied {
            operation_id,
            counter_rows_deleted: 0,
            manifest_rows_deleted: 0,
        }
    );
}

fn transition_row_count(state: &super::sqlite::RuntimeSqlite, operation_id: [u8; 16]) -> u64 {
    state
        .connection
        .query_row(
            "SELECT COUNT(*) FROM remote_key_transitions WHERE operation_id = ?1",
            [&operation_id[..]],
            |row| row.get::<_, u64>(0),
        )
        .expect("read transition row count")
}

#[derive(Debug)]
struct KeyTransitionGcFault {
    operation: RuntimeStoreOperation,
    armed: AtomicBool,
}

impl KeyTransitionGcFault {
    fn new(operation: RuntimeStoreOperation) -> Self {
        Self {
            operation,
            armed: AtomicBool::new(true),
        }
    }
}

impl RuntimeStoreFaultInjector for KeyTransitionGcFault {
    fn before_operation(&self, operation: RuntimeStoreOperation) -> Result<(), RuntimeStoreError> {
        if operation == self.operation && self.armed.swap(false, Ordering::SeqCst) {
            return Err(RuntimeStoreError::WorkerStopped);
        }
        Ok(())
    }
}

#[test]
fn key_transition_gc_is_stable_bounded_child_first_and_ledger_exact() {
    let (_root, _keys, config, mut state) = open_test_state();
    let config = config.with_capacity_probe(super::pairing_tests::GenerousCapacity);
    let first = [0xa1; 16];
    let second = [0xa2; 16];
    complete_gc_fixture(&mut state, &config, second, 10);
    complete_gc_fixture(&mut state, &config, first, 10);
    let active = [0xa3; 16];
    begin_key_transition(
        &mut state,
        &config,
        BeginKeyTransition {
            operation_id: active,
            operation: KeyTransitionOperation::ActivateConversation,
            target: KeyTransitionTarget::Conversation {
                conversation_id: [0xa4; 16],
                stream_route: [0xa5; 16],
            },
            from_revision: 1,
            to_revision: 2,
            recipients: vec![recipient(0xa6, 1)],
            replay_retirement: None,
            created_at_ms: 30,
        },
    )
    .expect("begin active GC exclusion fixture");
    let before =
        super::sqlite::load_runtime_ledger(&state.connection, &state.key_bundle, state.database_id)
            .expect("load pre-GC ledger");

    let outcome = gc_expired_key_transitions(
        &mut state,
        &config,
        10 + KEY_TRANSITION_TOMBSTONE_RETENTION_MS,
        KeyTransitionGcLimits {
            max_rows: 2,
            max_sealed_bytes: u64::MAX,
        },
    )
    .expect("collect first stable bounded transition");
    assert_eq!(outcome.transitions_deleted, 1);
    assert_eq!(outcome.updates_deleted, 1);
    assert!(outcome.limit_reached);
    let transition_exists = |operation_id: [u8; 16]| {
        state
            .connection
            .query_row(
                "SELECT COUNT(*) FROM remote_key_transitions WHERE operation_id = ?1",
                [&operation_id[..]],
                |row| row.get::<_, u64>(0),
            )
            .expect("read transition presence")
            == 1
    };
    assert!(!transition_exists(first));
    assert!(transition_exists(second));
    assert!(transition_exists(active));
    let after =
        super::sqlite::load_runtime_ledger(&state.connection, &state.key_bundle, state.database_id)
            .expect("load post-GC ledger");
    assert_eq!(
        after.remote_key_transition_count,
        before.remote_key_transition_count - 1
    );
    assert_eq!(
        after.remote_key_update_outbox_count,
        before.remote_key_update_outbox_count - 1
    );
    assert_eq!(
        after.remote_key_transition_active_count,
        before.remote_key_transition_active_count
    );
    assert_eq!(
        after.remote_key_transition_sealed_bytes,
        before.remote_key_transition_sealed_bytes - outcome.transition_sealed_bytes_deleted
    );
    assert_eq!(
        after.remote_key_update_outbox_sealed_bytes,
        before.remote_key_update_outbox_sealed_bytes - outcome.update_sealed_bytes_deleted
    );
    assert_v12_audit(&state);
}

#[test]
fn key_transition_gc_authenticates_before_any_delete() {
    let (_root, _keys, config, mut state) = open_test_state();
    let config = config.with_capacity_probe(super::pairing_tests::GenerousCapacity);
    let first = [0xb1; 16];
    let second = [0xb2; 16];
    complete_gc_fixture(&mut state, &config, first, 10);
    complete_gc_fixture(&mut state, &config, second, 11);
    state
        .connection
        .execute(
            "UPDATE remote_key_transitions SET metadata_token = ?1 WHERE operation_id = ?2",
            rusqlite::params![&[0xff_u8; 32][..], &second[..]],
        )
        .expect("tamper later eligible transition token");
    let before = (
        state
            .connection
            .query_row("SELECT COUNT(*) FROM remote_key_transitions", [], |row| {
                row.get::<_, u64>(0)
            })
            .unwrap(),
        state
            .connection
            .query_row("SELECT COUNT(*) FROM remote_key_update_outbox", [], |row| {
                row.get::<_, u64>(0)
            })
            .unwrap(),
    );
    assert!(
        gc_expired_key_transitions(
            &mut state,
            &config,
            11 + KEY_TRANSITION_TOMBSTONE_RETENTION_MS,
            KeyTransitionGcLimits::default(),
        )
        .is_err()
    );
    let after = (
        state
            .connection
            .query_row("SELECT COUNT(*) FROM remote_key_transitions", [], |row| {
                row.get::<_, u64>(0)
            })
            .unwrap(),
        state
            .connection
            .query_row("SELECT COUNT(*) FROM remote_key_update_outbox", [], |row| {
                row.get::<_, u64>(0)
            })
            .unwrap(),
    );
    assert_eq!(after, before);
}

#[test]
fn key_transition_gc_byte_limit_and_counter_recovery_are_non_destructive() {
    let (_root, _keys, config, mut state) = open_test_state();
    let config = config.with_capacity_probe(super::pairing_tests::GenerousCapacity);
    let ordinary = [0xc1; 16];
    complete_gc_fixture(&mut state, &config, ordinary, 10);
    let candidate_bytes: u64 = state
        .connection
        .query_row(
            "SELECT t.sealed_state_bytes + COALESCE(SUM(u.sealed_state_bytes), 0)
             FROM remote_key_transitions t
             LEFT JOIN remote_key_update_outbox u ON u.operation_id = t.operation_id
             WHERE t.operation_id = ?1 GROUP BY t.operation_id",
            [&ordinary[..]],
            |row| row.get(0),
        )
        .expect("read ordinary candidate sealed bytes");
    let byte_limited = gc_expired_key_transitions(
        &mut state,
        &config,
        10 + KEY_TRANSITION_TOMBSTONE_RETENTION_MS,
        KeyTransitionGcLimits {
            max_rows: u64::MAX,
            max_sealed_bytes: candidate_bytes - 1,
        },
    )
    .expect("byte-limited GC is a zero-delete outcome");
    assert_eq!(byte_limited.transitions_deleted, 0);
    assert!(byte_limited.limit_reached);

    let recovery = [0xc2; 16];
    let target = recipient(0xc3, 3);
    begin_key_transition(
        &mut state,
        &config,
        BeginKeyTransition {
            operation_id: recovery,
            operation: KeyTransitionOperation::CounterRecovery,
            target: KeyTransitionTarget::Device(target),
            from_revision: 2,
            to_revision: 3,
            recipients: vec![target],
            replay_retirement: None,
            created_at_ms: 20,
        },
    )
    .expect("begin blocked CounterRecovery tombstone fixture");
    cancel_key_transition(&mut state, &config, recovery, 21)
        .expect("terminalize pre-rotation CounterRecovery fixture");
    let outcome = gc_expired_key_transitions(
        &mut state,
        &config,
        21 + KEY_TRANSITION_TOMBSTONE_RETENTION_MS,
        KeyTransitionGcLimits::default(),
    )
    .expect("collect ordinary while preserving CounterRecovery");
    assert_eq!(outcome.transitions_deleted, 1);
    assert_eq!(outcome.counter_recovery_blocked, 1);
    assert_eq!(
        state
            .connection
            .query_row(
                "SELECT COUNT(*) FROM remote_key_transitions WHERE operation_id = ?1",
                [&recovery[..]],
                |row| row.get::<_, u64>(0),
            )
            .unwrap(),
        1
    );
    assert_v12_audit(&state);
}

#[test]
fn key_transition_gc_before_and_after_commit_retries_are_idempotent() {
    for (seed, fault) in [
        (0xd1, RuntimeStoreOperation::GcKeyTransitionsBeforeCommit),
        (0xd2, RuntimeStoreOperation::GcKeyTransitionsAfterCommit),
    ] {
        let (_root, _keys, config, mut state) = open_test_state();
        let config = config.with_capacity_probe(super::pairing_tests::GenerousCapacity);
        let operation_id = [seed; 16];
        complete_gc_fixture(&mut state, &config, operation_id, 10);
        let faulted = config
            .clone()
            .with_fault_injector(Arc::new(KeyTransitionGcFault::new(fault)));
        let result = gc_expired_key_transitions(
            &mut state,
            &faulted,
            10 + KEY_TRANSITION_TOMBSTONE_RETENTION_MS,
            KeyTransitionGcLimits::default(),
        );
        if fault == RuntimeStoreOperation::GcKeyTransitionsBeforeCommit {
            assert!(matches!(result, Err(RuntimeStoreError::WorkerStopped)));
            assert_eq!(transition_row_count(&state, operation_id), 1);
        } else {
            assert!(matches!(
                result,
                Err(RuntimeStoreError::CommitOutcomeUnknown {
                    operation: RuntimeCommitOperation::GcKeyTransitions
                })
            ));
            assert_eq!(transition_row_count(&state, operation_id), 0);
        }
        let retry = gc_expired_key_transitions(
            &mut state,
            &config,
            10 + KEY_TRANSITION_TOMBSTONE_RETENTION_MS,
            KeyTransitionGcLimits::default(),
        )
        .expect("retry GC after injected commit boundary");
        assert_eq!(transition_row_count(&state, operation_id), 0);
        assert_eq!(
            retry.transitions_deleted,
            u64::from(fault == RuntimeStoreOperation::GcKeyTransitionsBeforeCommit)
        );
        assert_v12_audit(&state);
    }
}

#[test]
fn counter_retirement_before_and_after_commit_faults_converge_exactly() {
    for (seed, fault) in [
        (
            0xe1,
            RuntimeStoreOperation::ApplyCounterRetirementBeforeCommit,
        ),
        (
            0xe2,
            RuntimeStoreOperation::ApplyCounterRetirementAfterCommit,
        ),
    ] {
        let (_root, _keys, config, mut state) = open_test_state();
        let operation_id = [seed; 16];
        begin_key_transition(
            &mut state,
            &config,
            BeginKeyTransition {
                operation_id,
                operation: KeyTransitionOperation::ActivateConversation,
                target: KeyTransitionTarget::Conversation {
                    conversation_id: [seed.wrapping_add(1); 16],
                    stream_route: [seed.wrapping_add(2); 16],
                },
                from_revision: 1,
                to_revision: 2,
                recipients: vec![recipient(seed.wrapping_add(3), 1)],
                replay_retirement: None,
                created_at_ms: 10,
            },
        )
        .expect("begin counter-retirement fault fixture");
        cancel_key_transition(&mut state, &config, operation_id, 11)
            .expect("terminalize counter-retirement fault fixture");
        let trust_domain = [0x6a; 32];
        let now_ms = 11 + COUNTER_RETIREMENT_RETENTION_MS;
        let plan = load_pending_counter_retirement_plan(&state, trust_domain, now_ms)
            .expect("load counter-retirement fault plan")
            .expect("cancelled transition has an empty exact plan");
        assert!(plan.scope_tokens.is_empty());
        let row_evidence = |state: &super::sqlite::RuntimeSqlite| {
            state
                .connection
                .query_row(
                    "SELECT sealed_state, metadata_token FROM remote_key_transitions
                     WHERE operation_id = ?1",
                    [&operation_id[..]],
                    |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
                )
                .expect("read counter-retirement transition evidence")
        };
        let before_row = row_evidence(&state);
        let before_ledger = super::sqlite::load_runtime_ledger(
            &state.connection,
            &state.key_bundle,
            state.database_id,
        )
        .expect("load pre-fault counter-retirement ledger");
        let faulted = config
            .clone()
            .with_fault_injector(Arc::new(KeyTransitionGcFault::new(fault)));
        let result = apply_counter_retirement_after_guard_readback(
            &mut state,
            &faulted,
            trust_domain,
            &plan,
            now_ms,
        );

        if fault == RuntimeStoreOperation::ApplyCounterRetirementBeforeCommit {
            assert!(matches!(result, Err(RuntimeStoreError::WorkerStopped)));
            assert_eq!(row_evidence(&state), before_row);
            assert_eq!(
                super::sqlite::load_runtime_ledger(
                    &state.connection,
                    &state.key_bundle,
                    state.database_id,
                )
                .expect("load rolled-back counter-retirement ledger"),
                before_ledger
            );
            assert_eq!(
                load_pending_counter_retirement_plan(&state, trust_domain, now_ms)
                    .expect("reload rolled-back counter-retirement plan"),
                Some(plan.clone())
            );
            assert_eq!(
                apply_counter_retirement_after_guard_readback(
                    &mut state,
                    &config,
                    trust_domain,
                    &plan,
                    now_ms,
                )
                .expect("retry before-COMMIT counter retirement"),
                CounterRetirementApplyOutcome::Applied {
                    operation_id,
                    counter_rows_deleted: 0,
                    manifest_rows_deleted: 0,
                }
            );
        } else {
            assert!(matches!(
                result,
                Err(RuntimeStoreError::CommitOutcomeUnknown {
                    operation: RuntimeCommitOperation::ApplyCounterRetirement,
                })
            ));
            assert_ne!(row_evidence(&state), before_row);
            assert!(
                load_pending_counter_retirement_plan(&state, trust_domain, now_ms)
                    .expect("reload committed counter-retirement state")
                    .is_none()
            );
            assert_eq!(
                apply_counter_retirement_after_guard_readback(
                    &mut state,
                    &config,
                    trust_domain,
                    &plan,
                    now_ms,
                )
                .expect("retry after-COMMIT counter retirement"),
                CounterRetirementApplyOutcome::AlreadyCollected { operation_id }
            );
        }
        assert_v12_audit(&state);
        let ledger = super::sqlite::load_runtime_ledger(
            &state.connection,
            &state.key_bundle,
            state.database_id,
        )
        .expect("load post-retry counter-retirement ledger");
        super::remote_counter::validate_full_integrity(
            &state.connection,
            &state.key_bundle,
            state.database_id,
            &ledger,
        )
        .expect("audit counter rows after retry");
        super::remote_counter_guard_manifest::validate_v12_integrity(
            &state.connection,
            &state.key_bundle,
            state.database_id,
            &ledger,
        )
        .expect("audit counter manifest after retry");
    }
}
