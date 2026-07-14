use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use super::*;
use crate::runtime::store::RuntimeStoreConfig;
use crate::security::{MemoryKeyStore, load_or_create_storage_kek};

static NEXT_ROOT: AtomicU64 = AtomicU64::new(1);

struct FailOnceAfterRotation(std::sync::atomic::AtomicBool);

impl crate::runtime::model::RuntimeStoreFaultInjector for FailOnceAfterRotation {
    fn before_operation(&self, operation: RuntimeStoreOperation) -> Result<(), RuntimeStoreError> {
        if operation == RuntimeStoreOperation::RotatePublicationStreamAfterCommit
            && !self.0.swap(true, Ordering::SeqCst)
        {
            Err(RuntimeStoreError::InvalidConfig(
                "injected post-rotation commit fault",
            ))
        } else {
            Ok(())
        }
    }
}

fn open_publication_test_store(
    label: &str,
) -> (
    PathBuf,
    RuntimeStoreConfig,
    super::super::sqlite::RuntimeSqlite,
) {
    let root = std::env::temp_dir().join(format!(
        "agentdeck-publication-{label}-{}-{}",
        std::process::id(),
        NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir(&root).expect("create publication test root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .expect("secure publication test root");
    }
    let keys = MemoryKeyStore::new();
    let kek = load_or_create_storage_kek(&keys, &root.join("key-state.db"))
        .expect("create publication test KEK");
    let config = RuntimeStoreConfig::new(root.join("runtime.db"));
    let state = super::super::sqlite::open(&config, kek).expect("open publication test store");
    (root, config, state)
}

fn open_reopenable_publication_test_store(
    label: &str,
) -> (
    PathBuf,
    MemoryKeyStore,
    RuntimeStoreConfig,
    super::super::sqlite::RuntimeSqlite,
) {
    let root = std::env::temp_dir().join(format!(
        "agentdeck-publication-{label}-{}-{}",
        std::process::id(),
        NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir(&root).expect("create reopenable publication test root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .expect("secure reopenable publication test root");
    }
    let keys = MemoryKeyStore::new();
    let kek = load_or_create_storage_kek(&keys, &root.join("key-state.db"))
        .expect("create reopenable publication test KEK");
    let config = RuntimeStoreConfig::new(root.join("runtime.db"));
    let state =
        super::super::sqlite::open(&config, kek).expect("open reopenable publication test store");
    (root, keys, config, state)
}

fn authenticate_catalog_directory(
    state: &super::super::sqlite::RuntimeSqlite,
) -> Result<Option<PublicationStreamRecord>, RuntimeStoreError> {
    let transaction = Transaction::new_unchecked(&state.connection, TransactionBehavior::Deferred)?;
    let ledger = super::super::sqlite::load_runtime_ledger(
        &transaction,
        &state.key_bundle,
        state.database_id,
    )?;
    let result = authenticate_directory(
        &transaction,
        &state.key_bundle,
        &ledger,
        PublicationScope::Catalog,
    );
    drop(transaction);
    result
}

fn create_catalog_entry(
    state: &mut super::super::sqlite::RuntimeSqlite,
    config: &RuntimeStoreConfig,
    seed: u8,
) {
    let conversation_id =
        RuntimeId::from_bytes(RuntimeIdKind::Conversation, [seed; 16]).expect("conversation id");
    let input = crate::runtime::model::NewConversation {
        conversation_id,
        adapter_state_key: RuntimeId::from_bytes(
            RuntimeIdKind::AdapterState,
            [seed.wrapping_add(0x40); 16],
        )
        .expect("adapter state key"),
        descriptor: crate::runtime::model::ConversationDescriptor {
            agent_kind: agentdeck_protocol::AgentKind::Codex,
            title: Some(format!("publication-catalog-{seed}")),
            cwd: PathBuf::from(format!("/tmp/publication-catalog-{seed}")),
        },
    };
    let descriptor = super::super::journal::canonical_conversation_descriptor(&input.descriptor)
        .expect("canonical conversation descriptor");
    let mut effects = crate::runtime::events::CommandStreamEffects::default();
    super::super::journal::create_conversation(state, config, input, descriptor, &mut effects)
        .expect("create catalog entry");
}

#[allow(clippy::too_many_arguments)]
fn acknowledge_one_control_and_mark_needs_snapshot(
    state: &mut super::super::sqlite::RuntimeSqlite,
    config: &RuntimeStoreConfig,
    stream_id: [u8; 16],
    generation: [u8; 16],
    counter_scope: [u8; 32],
    publication_id: [u8; 16],
    sender_counter: u64,
    now_ms: u64,
) -> FrozenPublication {
    let limits = PublicationLimits {
        rows_per_stream: 1,
        bytes_per_stream: MAX_PUBLICATION_BYTES_PER_STREAM,
        rows_global: MAX_PUBLICATION_ROWS_GLOBAL,
        bytes_global: MAX_PUBLICATION_BYTES_GLOBAL,
    };
    let frozen = freeze_publication_with_limits(
        state,
        config,
        FreezePublicationRequest {
            publication_id,
            publication_stream_id: stream_id,
            generation,
            counter_scope_token: counter_scope,
            sender_counter,
            inner_after: None,
            inner_through: None,
            payload_kind: PublicationPayloadKind::Control,
            blob: vec![publication_id[0]],
        },
        now_ms,
        limits,
    )
    .expect("freeze one control publication");
    let mut rejected_id = publication_id;
    rejected_id[15] = rejected_id[15].wrapping_add(1);
    assert!(matches!(
        freeze_publication_with_limits(
            state,
            config,
            FreezePublicationRequest {
                publication_id: rejected_id,
                publication_stream_id: stream_id,
                generation,
                counter_scope_token: counter_scope,
                sender_counter: sender_counter + 1,
                inner_after: None,
                inner_through: None,
                payload_kind: PublicationPayloadKind::Control,
                blob: vec![rejected_id[0]],
            },
            now_ms + 1,
            limits,
        ),
        Err(RuntimeStoreError::PublicationNeedsSnapshot)
    ));
    acknowledge_publication_commit(
        state,
        config,
        stream_id,
        generation,
        frozen.stream_seq,
        frozen.blob_sha256,
        now_ms + 2,
    )
    .expect("commit control publication");
    acknowledge_publication_delivery(
        state,
        config,
        stream_id,
        generation,
        frozen.stream_seq,
        frozen.blob_sha256,
        now_ms + 3,
    )
    .expect("ack control publication");
    frozen
}

#[test]
fn publication_directory_rejects_valid_mac_outer_gap() {
    let (root, config, mut state) = open_publication_test_store("directory-outer-gap");
    let stream_id = [0x81; 16];
    let generation = [0x82; 16];
    let counter_scope = [0x83; 32];
    create_publication_stream(
        &mut state,
        &config,
        stream_id,
        PublicationScope::Catalog,
        [0x84; 16],
        generation,
        1,
    )
    .expect("create catalog publication stream");
    for (publication_id, sender_counter, after, through, now_ms, blob) in [
        ([0x85; 16], 1, None, Some(0), 2, b"outer-zero".as_slice()),
        ([0x86; 16], 2, Some(0), Some(1), 3, b"outer-one".as_slice()),
    ] {
        freeze_publication(
            &mut state,
            &config,
            FreezePublicationRequest {
                publication_id,
                publication_stream_id: stream_id,
                generation,
                counter_scope_token: counter_scope,
                sender_counter,
                inner_after: after,
                inner_through: through,
                payload_kind: PublicationPayloadKind::Catalog,
                blob: blob.to_vec(),
            },
            now_ms,
        )
        .expect("freeze contiguous publication row");
    }

    let gap_seq = encode_sequence(2);
    let inner_after = encode_sequence(0);
    let inner_through = encode_sequence(1);
    let blob_hash: [u8; 32] = Sha256::digest(b"outer-one").into();
    let token = outbox_token(
        &state.key_bundle,
        [0x86; 16],
        stream_id,
        generation,
        &gap_seq,
        counter_scope,
        2,
        Some(&inner_after),
        Some(&inner_through),
        PublicationPayloadKind::Catalog,
        blob_hash,
        u64::try_from(b"outer-one".len()).expect("logical bytes fit"),
        3,
    )
    .expect("recompute valid gap metadata token");
    state
        .connection
        .execute(
            "UPDATE publication_outbox SET stream_seq = ?1, metadata_token = ?2
                 WHERE publication_id = ?3",
            params![&gap_seq, &token[..], &[0x86_u8; 16][..]],
        )
        .expect("install valid-MAC outer gap");
    let transaction = Transaction::new_unchecked(&state.connection, TransactionBehavior::Immediate)
        .expect("begin stream HWM tamper transaction");
    let mut stream = load_stream(&transaction, &state.key_bundle, stream_id)
        .expect("load stream for HWM tamper");
    stream.reserved_high_water = Some(2);
    update_stream(&transaction, &state.key_bundle, &stream)
        .expect("authenticate updated reserved HWM");
    transaction.commit().expect("commit reserved HWM tamper");

    assert!(matches!(
        authenticate_catalog_directory(&state),
        Err(RuntimeStoreError::UnknownOrCorruptSchema)
    ));
    drop(state);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn publication_directory_rejects_valid_mac_inner_discontinuity() {
    let (root, config, mut state) = open_publication_test_store("directory-inner-gap");
    let stream_id = [0x91; 16];
    let generation = [0x92; 16];
    let counter_scope = [0x93; 32];
    create_publication_stream(
        &mut state,
        &config,
        stream_id,
        PublicationScope::Catalog,
        [0x94; 16],
        generation,
        1,
    )
    .expect("create catalog publication stream");
    for (publication_id, sender_counter, after, through, now_ms, blob) in [
        ([0x95; 16], 1, None, Some(0), 2, b"inner-zero".as_slice()),
        ([0x96; 16], 2, Some(0), Some(1), 3, b"inner-one".as_slice()),
    ] {
        freeze_publication(
            &mut state,
            &config,
            FreezePublicationRequest {
                publication_id,
                publication_stream_id: stream_id,
                generation,
                counter_scope_token: counter_scope,
                sender_counter,
                inner_after: after,
                inner_through: through,
                payload_kind: PublicationPayloadKind::Catalog,
                blob: blob.to_vec(),
            },
            now_ms,
        )
        .expect("freeze contiguous publication row");
    }

    let stream_seq = encode_sequence(1);
    let discontinuous_after = encode_sequence(5);
    let discontinuous_through = encode_sequence(6);
    let blob_hash: [u8; 32] = Sha256::digest(b"inner-one").into();
    let token = outbox_token(
        &state.key_bundle,
        [0x96; 16],
        stream_id,
        generation,
        &stream_seq,
        counter_scope,
        2,
        Some(&discontinuous_after),
        Some(&discontinuous_through),
        PublicationPayloadKind::Catalog,
        blob_hash,
        u64::try_from(b"inner-one".len()).expect("logical bytes fit"),
        3,
    )
    .expect("recompute valid inner-gap metadata token");
    state
        .connection
        .execute(
            "UPDATE publication_outbox
                 SET inner_after_seq = ?1, inner_through_seq = ?2, metadata_token = ?3
                 WHERE publication_id = ?4",
            params![
                &discontinuous_after,
                &discontinuous_through,
                &token[..],
                &[0x96_u8; 16][..]
            ],
        )
        .expect("install valid-MAC inner discontinuity");

    assert!(matches!(
        authenticate_catalog_directory(&state),
        Err(RuntimeStoreError::UnknownOrCorruptSchema)
    ));
    drop(state);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn publication_directory_rejects_valid_mac_sender_counter_regression() {
    let (root, config, mut state) = open_publication_test_store("directory-counter-gap");
    let stream_id = [0xa1; 16];
    let generation = [0xa2; 16];
    let counter_scope = [0xa3; 32];
    create_publication_stream(
        &mut state,
        &config,
        stream_id,
        PublicationScope::Catalog,
        [0xa4; 16],
        generation,
        1,
    )
    .expect("create catalog publication stream");
    for (publication_id, sender_counter, after, through, now_ms, blob) in [
        ([0xa5; 16], 1, None, Some(0), 2, b"counter-one".as_slice()),
        (
            [0xa6; 16],
            2,
            Some(0),
            Some(1),
            3,
            b"counter-two".as_slice(),
        ),
    ] {
        freeze_publication(
            &mut state,
            &config,
            FreezePublicationRequest {
                publication_id,
                publication_stream_id: stream_id,
                generation,
                counter_scope_token: counter_scope,
                sender_counter,
                inner_after: after,
                inner_through: through,
                payload_kind: PublicationPayloadKind::Catalog,
                blob: blob.to_vec(),
            },
            now_ms,
        )
        .expect("freeze increasing-counter publication row");
    }

    let stream_seq = encode_sequence(1);
    let inner_after = encode_sequence(0);
    let inner_through = encode_sequence(1);
    let regressed_counter = encode_sequence(0);
    let blob_hash: [u8; 32] = Sha256::digest(b"counter-two").into();
    let token = outbox_token(
        &state.key_bundle,
        [0xa6; 16],
        stream_id,
        generation,
        &stream_seq,
        counter_scope,
        0,
        Some(&inner_after),
        Some(&inner_through),
        PublicationPayloadKind::Catalog,
        blob_hash,
        u64::try_from(b"counter-two".len()).expect("logical bytes fit"),
        3,
    )
    .expect("recompute valid regressed-counter metadata token");
    state
        .connection
        .execute(
            "UPDATE publication_outbox SET sender_counter = ?1, metadata_token = ?2
                 WHERE publication_id = ?3",
            params![&regressed_counter, &token[..], &[0xa6_u8; 16][..]],
        )
        .expect("install valid-MAC sender counter regression");
    let transaction = Transaction::new_unchecked(&state.connection, TransactionBehavior::Immediate)
        .expect("begin counter HWM tamper transaction");
    let mut stream = load_stream(&transaction, &state.key_bundle, stream_id)
        .expect("load stream for counter HWM tamper");
    stream.sender_counter_high_water = Some(0);
    update_stream(&transaction, &state.key_bundle, &stream)
        .expect("authenticate updated counter HWM");
    transaction.commit().expect("commit counter HWM tamper");

    assert!(matches!(
        authenticate_catalog_directory(&state),
        Err(RuntimeStoreError::UnknownOrCorruptSchema)
    ));
    drop(state);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn publication_directory_authenticates_metadata_without_opening_sealed_blob() {
    let (root, config, mut state) = open_publication_test_store("directory-metadata-only");
    let stream_id = [0xb1; 16];
    let generation = [0xb2; 16];
    let publication_id = [0xb3; 16];
    create_publication_stream(
        &mut state,
        &config,
        stream_id,
        PublicationScope::Catalog,
        [0xb4; 16],
        generation,
        1,
    )
    .expect("create catalog publication stream");
    freeze_publication(
        &mut state,
        &config,
        FreezePublicationRequest {
            publication_id,
            publication_stream_id: stream_id,
            generation,
            counter_scope_token: [0xb5; 32],
            sender_counter: 1,
            inner_after: None,
            inner_through: Some(0),
            payload_kind: PublicationPayloadKind::Catalog,
            blob: b"directory-must-not-open-this-sealed-blob".to_vec(),
        },
        2,
    )
    .expect("freeze publication row");
    state
        .connection
        .execute(
            "UPDATE publication_outbox
                 SET sealed_publication = zeroblob(length(sealed_publication))
                 WHERE publication_id = ?1",
            [&publication_id[..]],
        )
        .expect("break sealed publication without touching metadata");

    let selected = authenticate_catalog_directory(&state)
        .expect("directory must not open sealed publication")
        .expect("catalog stream remains selectable");
    assert_eq!(selected.publication_stream_id, stream_id);

    state
        .connection
        .execute(
            "UPDATE publication_outbox SET metadata_token = zeroblob(32)
                 WHERE publication_id = ?1",
            [&publication_id[..]],
        )
        .expect("break outbox metadata token");
    assert!(matches!(
        authenticate_catalog_directory(&state),
        Err(RuntimeStoreError::UnknownOrCorruptSchema)
    ));
    drop(state);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn publication_directory_accepts_valid_mac_zero_blob_hash_without_opening_sealed_blob() {
    let (root, config, mut state) = open_publication_test_store("directory-zero-blob-hash");
    let stream_id = [0xb6; 16];
    let generation = [0xb7; 16];
    let publication_id = [0xb8; 16];
    let counter_scope = [0xb9; 32];
    let blob = b"directory-zero-hash-does-not-open-sealed-blob";
    create_publication_stream(
        &mut state,
        &config,
        stream_id,
        PublicationScope::Catalog,
        [0xba; 16],
        generation,
        1,
    )
    .expect("create catalog publication stream");
    freeze_publication(
        &mut state,
        &config,
        FreezePublicationRequest {
            publication_id,
            publication_stream_id: stream_id,
            generation,
            counter_scope_token: counter_scope,
            sender_counter: 1,
            inner_after: None,
            inner_through: Some(0),
            payload_kind: PublicationPayloadKind::Catalog,
            blob: blob.to_vec(),
        },
        2,
    )
    .expect("freeze publication row");

    let stream_seq = encode_sequence(0);
    let inner_through = encode_sequence(0);
    let token = outbox_token(
        &state.key_bundle,
        publication_id,
        stream_id,
        generation,
        &stream_seq,
        counter_scope,
        1,
        None,
        Some(&inner_through),
        PublicationPayloadKind::Catalog,
        [0; 32],
        u64::try_from(blob.len()).expect("logical bytes fit"),
        2,
    )
    .expect("recompute valid zero-hash metadata token");
    state
        .connection
        .execute(
            "UPDATE publication_outbox
                 SET blob_sha256 = zeroblob(32), metadata_token = ?1
                 WHERE publication_id = ?2",
            params![&token[..], &publication_id[..]],
        )
        .expect("install valid-MAC zero blob hash");

    let selected = authenticate_catalog_directory(&state)
        .expect("zero blob hash is valid authenticated metadata")
        .expect("catalog stream remains selectable");
    assert_eq!(selected.publication_stream_id, stream_id);
    drop(state);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn publication_directory_preserves_sqlite_error_when_outbox_table_is_missing() {
    let (root, _config, state) = open_publication_test_store("directory-drop-outbox");
    state
        .connection
        .execute_batch("DROP TABLE publication_outbox")
        .expect("drop publication outbox");
    assert!(matches!(
        authenticate_catalog_directory(&state),
        Err(RuntimeStoreError::Sqlite(_))
    ));
    drop(state);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn publication_directory_maps_outbox_row_type_error_to_corruption() {
    let (root, config, mut state) = open_publication_test_store("directory-row-type");
    let stream_id = [0xc1; 16];
    let generation = [0xc2; 16];
    let publication_id = [0xc3; 16];
    create_publication_stream(
        &mut state,
        &config,
        stream_id,
        PublicationScope::Catalog,
        [0xc4; 16],
        generation,
        1,
    )
    .expect("create catalog publication stream");
    freeze_publication(
        &mut state,
        &config,
        FreezePublicationRequest {
            publication_id,
            publication_stream_id: stream_id,
            generation,
            counter_scope_token: [0xc5; 32],
            sender_counter: 1,
            inner_after: None,
            inner_through: Some(0),
            payload_kind: PublicationPayloadKind::Catalog,
            blob: b"directory-row-type".to_vec(),
        },
        2,
    )
    .expect("freeze publication row");
    state
        .connection
        .execute_batch("PRAGMA ignore_check_constraints = ON")
        .expect("allow row-type corruption fixture");
    state
        .connection
        .execute(
            "UPDATE publication_outbox SET stream_seq = x'0001'
                 WHERE publication_id = ?1",
            [&publication_id[..]],
        )
        .expect("install stream-seq row type corruption");

    assert!(matches!(
        authenticate_catalog_directory(&state),
        Err(RuntimeStoreError::UnknownOrCorruptSchema)
    ));
    drop(state);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn publication_directory_accepts_retired_max_ack_with_empty_outbox() {
    let (root, config, mut state) = open_publication_test_store("directory-max-ack");
    let stream_id = [0xd1; 16];
    let generation = [0xd2; 16];
    create_publication_stream(
        &mut state,
        &config,
        stream_id,
        PublicationScope::Catalog,
        [0xd3; 16],
        generation,
        1,
    )
    .expect("create catalog publication stream");
    let transaction = Transaction::new_unchecked(&state.connection, TransactionBehavior::Immediate)
        .expect("begin terminal max-HWM fixture transaction");
    let mut stream = load_stream(&transaction, &state.key_bundle, stream_id)
        .expect("load stream for terminal max-HWM fixture");
    stream.counter_scope_token = Some([0xd4; 32]);
    stream.sender_counter_high_water = Some(9);
    stream.reserved_high_water = Some(u64::MAX);
    stream.committed_high_water = Some(u64::MAX);
    stream.last_committed_blob_hash = Some([0xd5; 32]);
    stream.acknowledged_high_water = Some(u64::MAX);
    stream.last_acknowledged_blob_hash = Some([0xd5; 32]);
    stream.state = PublicationStreamState::Retired;
    update_stream(&transaction, &state.key_bundle, &stream)
        .expect("authenticate terminal max-HWM fixture");
    transaction
        .commit()
        .expect("commit terminal max-HWM fixture");

    assert_eq!(
        authenticate_catalog_directory(&state)
            .expect("retired max-HWM stream remains authenticatable"),
        None
    );
    drop(state);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn publication_outbox_cap_marks_stream_needs_snapshot_without_dropping_unacked_row() {
    let root = std::env::temp_dir().join(format!(
        "agentdeck-publication-cap-{}-{}",
        std::process::id(),
        NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir(&root).expect("create publication cap root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .expect("secure publication cap root");
    }
    let database = root.join("runtime.db");
    let keys = MemoryKeyStore::new();
    let kek =
        load_or_create_storage_kek(&keys, &root.join("key-state.db")).expect("create test KEK");
    let config = RuntimeStoreConfig::new(database);
    let mut state = super::super::sqlite::open(&config, kek).expect("open test store");
    let stream_id = [0x71; 16];
    let generation = [0x72; 16];
    create_publication_stream(
        &mut state,
        &config,
        stream_id,
        PublicationScope::Catalog,
        [0x73; 16],
        generation,
        1,
    )
    .expect("create catalog publication stream");
    let request = |publication_id: [u8; 16], after, through| FreezePublicationRequest {
        publication_id,
        publication_stream_id: stream_id,
        generation,
        counter_scope_token: [0x76; 32],
        sender_counter: u64::from(publication_id[0]),
        inner_after: after,
        inner_through: through,
        payload_kind: PublicationPayloadKind::Catalog,
        blob: vec![publication_id[0]],
    };
    let first_request = request([0x74; 16], None, Some(0));
    let first = freeze_publication_with_limits(
        &mut state,
        &config,
        first_request.clone(),
        2,
        PublicationLimits {
            rows_per_stream: 1,
            bytes_per_stream: MAX_PUBLICATION_BYTES_PER_STREAM,
            rows_global: MAX_PUBLICATION_ROWS_GLOBAL,
            bytes_global: MAX_PUBLICATION_BYTES_GLOBAL,
        },
    )
    .expect("freeze first row");
    let error = freeze_publication_with_limits(
        &mut state,
        &config,
        request([0x75; 16], Some(0), Some(1)),
        3,
        PublicationLimits {
            rows_per_stream: 1,
            bytes_per_stream: MAX_PUBLICATION_BYTES_PER_STREAM,
            rows_global: MAX_PUBLICATION_ROWS_GLOBAL,
            bytes_global: MAX_PUBLICATION_BYTES_GLOBAL,
        },
    )
    .expect_err("cap must stop new publication");
    assert!(matches!(error, RuntimeStoreError::PublicationNeedsSnapshot));
    assert_eq!(
        load_stream(&state.connection, &state.key_bundle, stream_id)
            .expect("load capped stream")
            .state,
        PublicationStreamState::NeedsSnapshot
    );
    assert_eq!(
        load_pending_publications(&state, stream_id).expect("load retained outbox"),
        std::slice::from_ref(&first),
        "unacked row must never be evicted"
    );
    assert_eq!(
        freeze_publication_with_limits(
            &mut state,
            &config,
            first_request,
            4,
            PublicationLimits {
                rows_per_stream: 1,
                bytes_per_stream: MAX_PUBLICATION_BYTES_PER_STREAM,
                rows_global: MAX_PUBLICATION_ROWS_GLOBAL,
                bytes_global: MAX_PUBLICATION_BYTES_GLOBAL,
            },
        )
        .expect("exact retry remains available after cap"),
        first
    );
    drop(state);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn repeated_rollover_keeps_stream_count_constant_and_commit_unknown_is_idempotent() {
    let (root, config, mut state) = open_publication_test_store("repeated-rollover");
    let stream_id = [0x21; 16];
    let first_generation = [0x22; 16];
    create_publication_stream(
        &mut state,
        &config,
        stream_id,
        PublicationScope::Catalog,
        [0x23; 16],
        first_generation,
        1,
    )
    .expect("create publication stream");
    let first_publication_id = [0x24; 16];
    acknowledge_one_control_and_mark_needs_snapshot(
        &mut state,
        &config,
        stream_id,
        first_generation,
        [0x25; 32],
        first_publication_id,
        1,
        2,
    );
    let initial_count = super::super::sqlite::load_runtime_ledger(
        &state.connection,
        &state.key_bundle,
        state.database_id,
    )
    .expect("load initial publication count")
    .publication_stream_count;
    assert_eq!(initial_count, 1);

    let first_rotation = RotatePublicationStreamRequest {
        publication_stream_id: stream_id,
        expected_generation: first_generation,
    };
    let fault_config = config
        .clone()
        .with_fault_injector(Arc::new(FailOnceAfterRotation(
            std::sync::atomic::AtomicBool::new(false),
        )));
    assert!(matches!(
        rotate_publication_stream(&mut state, &fault_config, first_rotation, 6),
        Err(RuntimeStoreError::CommitOutcomeUnknown {
            operation: RuntimeCommitOperation::RotatePublicationStream
        })
    ));
    let first_retry = rotate_publication_stream(&mut state, &fault_config, first_rotation, 6)
        .expect("exact rotation retry reads committed row");
    assert_ne!(first_retry.generation, first_generation);
    assert_ne!(first_retry.stream_route, [0x23; 16]);
    assert_eq!(first_retry.rotation_serial, 1);
    assert_eq!(first_retry.state, PublicationStreamState::Active);
    assert!(first_retry.reserved_high_water.is_none());
    assert_eq!(
        first_retry.last_acknowledged_publication_id,
        Some(first_publication_id),
        "rollover must preserve the latest ACK tombstone"
    );
    assert!(matches!(
        rotate_publication_stream(
            &mut state,
            &fault_config,
            RotatePublicationStreamRequest {
                expected_generation: [0x28; 16],
                ..first_rotation
            },
            7,
        ),
        Err(RuntimeStoreError::PublicationMismatch)
    ));
    assert!(matches!(
        freeze_publication(
            &mut state,
            &fault_config,
            FreezePublicationRequest {
                publication_id: first_publication_id,
                publication_stream_id: stream_id,
                generation: first_generation,
                counter_scope_token: [0x25; 32],
                sender_counter: 1,
                inner_after: None,
                inner_through: None,
                payload_kind: PublicationPayloadKind::Control,
                blob: vec![first_publication_id[0]],
            },
            7,
        ),
        Err(RuntimeStoreError::PublicationAlreadyAcknowledged)
    ));

    acknowledge_one_control_and_mark_needs_snapshot(
        &mut state,
        &fault_config,
        stream_id,
        first_retry.generation,
        [0x25; 32],
        [0x2a; 16],
        2,
        10,
    );
    let second_rotation = RotatePublicationStreamRequest {
        publication_stream_id: stream_id,
        expected_generation: first_retry.generation,
    };
    let second = rotate_publication_stream(&mut state, &fault_config, second_rotation, 14)
        .expect("perform second in-place rollover");
    assert_ne!(second.generation, first_retry.generation);
    assert_ne!(second.generation, first_generation);
    assert_eq!(second.rotation_serial, 2);
    assert_eq!(
        rotate_publication_stream(&mut state, &fault_config, second_rotation, 14)
            .expect("second exact retry"),
        second
    );
    assert!(matches!(
        rotate_publication_stream(&mut state, &fault_config, first_rotation, 15),
        Err(RuntimeStoreError::PublicationMismatch)
    ));
    assert_eq!(
        super::super::sqlite::load_runtime_ledger(
            &state.connection,
            &state.key_bundle,
            state.database_id,
        )
        .expect("load final publication count")
        .publication_stream_count,
        initial_count
    );
    drop(state);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn rotation_exact_retry_survives_progress_in_the_new_generation() {
    // 威胁场景：rotation 的成功回复丢失后，内部 owner 已在新 generation
    // freeze 下一帧；原 rotation 的 exact retry 仍必须读回已提交结果，不能把
    // outcome unknown 永久误报为 mismatch。
    let (root, config, mut state) = open_publication_test_store("rotation-retry-progress");
    let stream_id = [0x8a; 16];
    let initial_generation = [0x8b; 16];
    let counter_scope = [0x8c; 32];
    create_publication_stream(
        &mut state,
        &config,
        stream_id,
        PublicationScope::Catalog,
        [0x8d; 16],
        initial_generation,
        1,
    )
    .expect("create rotation retry stream");
    acknowledge_one_control_and_mark_needs_snapshot(
        &mut state,
        &config,
        stream_id,
        initial_generation,
        counter_scope,
        [0x8e; 16],
        1,
        2,
    );
    let request = RotatePublicationStreamRequest {
        publication_stream_id: stream_id,
        expected_generation: initial_generation,
    };
    let rotated = rotate_publication_stream(&mut state, &config, request, 6)
        .expect("rotate to a new generation");
    let frozen = freeze_publication(
        &mut state,
        &config,
        FreezePublicationRequest {
            publication_id: [0x8f; 16],
            publication_stream_id: stream_id,
            generation: rotated.generation,
            counter_scope_token: counter_scope,
            sender_counter: 2,
            inner_after: None,
            inner_through: None,
            payload_kind: PublicationPayloadKind::Control,
            blob: b"new-generation-progress".to_vec(),
        },
        7,
    )
    .expect("advance the new generation before retrying rotation");

    let replayed = rotate_publication_stream(&mut state, &config, request, 8)
        .expect("exact rotation retry must survive later generation progress");
    assert_eq!(replayed.generation, rotated.generation);
    assert_eq!(replayed.rotation_serial, rotated.rotation_serial);
    assert_eq!(replayed.reserved_high_water, Some(frozen.stream_seq));
    assert_eq!(replayed.sender_counter_high_water, Some(2));
    assert_eq!(replayed.last_committed_blob_hash, None);

    drop(state);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn rotation_lineage_survives_restart_and_rejects_old_request_or_serial_rollback() {
    let (root, keys, config, mut state) =
        open_reopenable_publication_test_store("rotation-lineage-restart");
    let stream_id = [0x2d; 16];
    let initial_generation = [0x2e; 16];
    create_publication_stream(
        &mut state,
        &config,
        stream_id,
        PublicationScope::Catalog,
        [0x2f; 16],
        initial_generation,
        1,
    )
    .expect("create restart lineage stream");
    acknowledge_one_control_and_mark_needs_snapshot(
        &mut state,
        &config,
        stream_id,
        initial_generation,
        [0x30; 32],
        [0x31; 16],
        1,
        2,
    );
    let first_request = RotatePublicationStreamRequest {
        publication_stream_id: stream_id,
        expected_generation: initial_generation,
    };
    let first = rotate_publication_stream(&mut state, &config, first_request, 6)
        .expect("first derived rotation");
    acknowledge_one_control_and_mark_needs_snapshot(
        &mut state,
        &config,
        stream_id,
        first.generation,
        [0x30; 32],
        [0x33; 16],
        2,
        10,
    );
    let second = rotate_publication_stream(
        &mut state,
        &config,
        RotatePublicationStreamRequest {
            publication_stream_id: stream_id,
            expected_generation: first.generation,
        },
        14,
    )
    .expect("second derived rotation");
    assert_eq!(second.rotation_serial, 2);
    assert_ne!(second.generation, initial_generation);
    drop(state);

    let kek =
        load_or_create_storage_kek(&keys, &root.join("key-state.db")).expect("reload lineage KEK");
    let reopened =
        super::super::sqlite::open(&config, kek).expect("reopen authenticated rotation lineage");
    let persisted = load_stream(&reopened.connection, &reopened.key_bundle, stream_id)
        .expect("load persisted rotation lineage");
    assert_eq!(persisted.rotation_serial, 2);
    assert_eq!(persisted.generation, second.generation);
    let mut reopened = reopened;
    assert!(matches!(
        rotate_publication_stream(&mut reopened, &config, first_request, 15),
        Err(RuntimeStoreError::PublicationMismatch)
    ));
    assert!(matches!(
        freeze_publication(
            &mut reopened,
            &config,
            FreezePublicationRequest {
                publication_id: [0x38; 16],
                publication_stream_id: stream_id,
                generation: persisted.generation,
                counter_scope_token: [0x30; 32],
                sender_counter: 1,
                inner_after: None,
                inner_through: None,
                payload_kind: PublicationPayloadKind::Control,
                blob: b"counter-rollback-after-restart".to_vec(),
            },
            16,
        ),
        Err(RuntimeStoreError::PublicationMismatch)
    ));
    let advanced = freeze_publication(
        &mut reopened,
        &config,
        FreezePublicationRequest {
            publication_id: [0x39; 16],
            publication_stream_id: stream_id,
            generation: persisted.generation,
            counter_scope_token: [0x30; 32],
            sender_counter: 3,
            inner_after: None,
            inner_through: None,
            payload_kind: PublicationPayloadKind::Control,
            blob: b"counter-continues-after-restart".to_vec(),
        },
        16,
    )
    .expect("same scope with a strictly higher counter remains usable");
    assert_eq!(advanced.sender_counter, 3);
    reopened
        .connection
        .execute(
            "UPDATE publication_streams SET rotation_serial = ?1
                 WHERE publication_stream_id = ?2",
            params![encode_sequence(1), &stream_id[..]],
        )
        .expect("install unauthenticated serial rollback");
    drop(reopened);

    let kek =
        load_or_create_storage_kek(&keys, &root.join("key-state.db")).expect("reload rollback KEK");
    assert!(matches!(
        super::super::sqlite::open(&config, kek),
        Err(RuntimeStoreError::UnknownOrCorruptSchema)
    ));
    let _ = fs::remove_dir_all(root);
}

#[test]
fn rotation_serial_at_u64_max_fails_closed_without_wrap() {
    let (root, config, mut state) = open_publication_test_store("rotation-serial-max");
    let stream_id = [0x34; 16];
    let generation = [0x35; 16];
    create_publication_stream(
        &mut state,
        &config,
        stream_id,
        PublicationScope::Catalog,
        [0x36; 16],
        generation,
        1,
    )
    .expect("create serial max stream");
    let transaction = Transaction::new_unchecked(&state.connection, TransactionBehavior::Immediate)
        .expect("begin serial max fixture");
    let mut stream =
        load_stream(&transaction, &state.key_bundle, stream_id).expect("load serial max stream");
    stream.rotation_serial = u64::MAX;
    stream.last_rotation_request_digest = Some([0x37; 32]);
    stream.state = PublicationStreamState::NeedsSnapshot;
    update_stream(&transaction, &state.key_bundle, &stream)
        .expect("authenticate serial max fixture");
    transaction.commit().expect("commit serial max fixture");
    assert!(matches!(
        rotate_publication_stream(
            &mut state,
            &config,
            RotatePublicationStreamRequest {
                publication_stream_id: stream_id,
                expected_generation: generation,
            },
            2,
        ),
        Err(RuntimeStoreError::PublicationMismatch)
    ));
    assert_eq!(
        load_stream(&state.connection, &state.key_bundle, stream_id)
            .expect("serial remains authenticated")
            .rotation_serial,
        u64::MAX
    );
    drop(state);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn rollover_requires_authenticated_ready_snapshot_covering_committed_inner() {
    let (root, config, mut state) = open_publication_test_store("rollover-snapshot");
    create_catalog_entry(&mut state, &config, 0x31);
    let stream_id = [0x32; 16];
    let generation = [0x33; 16];
    create_publication_stream(
        &mut state,
        &config,
        stream_id,
        PublicationScope::Catalog,
        [0x34; 16],
        generation,
        1,
    )
    .expect("create catalog publication stream");
    let limits = PublicationLimits {
        rows_per_stream: 1,
        bytes_per_stream: MAX_PUBLICATION_BYTES_PER_STREAM,
        rows_global: MAX_PUBLICATION_ROWS_GLOBAL,
        bytes_global: MAX_PUBLICATION_BYTES_GLOBAL,
    };
    let frozen = freeze_publication_with_limits(
        &mut state,
        &config,
        FreezePublicationRequest {
            publication_id: [0x35; 16],
            publication_stream_id: stream_id,
            generation,
            counter_scope_token: [0x36; 32],
            sender_counter: 1,
            inner_after: None,
            inner_through: Some(0),
            payload_kind: PublicationPayloadKind::Catalog,
            blob: b"catalog-zero".to_vec(),
        },
        2,
        limits,
    )
    .expect("freeze catalog revision zero");
    assert!(matches!(
        freeze_publication_with_limits(
            &mut state,
            &config,
            FreezePublicationRequest {
                publication_id: [0x37; 16],
                publication_stream_id: stream_id,
                generation,
                counter_scope_token: [0x36; 32],
                sender_counter: 2,
                inner_after: Some(0),
                inner_through: Some(1),
                payload_kind: PublicationPayloadKind::Catalog,
                blob: b"catalog-one".to_vec(),
            },
            3,
            limits,
        ),
        Err(RuntimeStoreError::PublicationNeedsSnapshot)
    ));
    acknowledge_publication_commit(
        &mut state,
        &config,
        stream_id,
        generation,
        frozen.stream_seq,
        frozen.blob_sha256,
        4,
    )
    .expect("commit catalog publication");
    acknowledge_publication_delivery(
        &mut state,
        &config,
        stream_id,
        generation,
        frozen.stream_seq,
        frozen.blob_sha256,
        5,
    )
    .expect("ack catalog publication");
    let rotation = RotatePublicationStreamRequest {
        publication_stream_id: stream_id,
        expected_generation: generation,
    };
    assert!(matches!(
        rotate_publication_stream(&mut state, &config, rotation, 6),
        Err(RuntimeStoreError::PublicationNeedsSnapshot)
    ));
    super::super::snapshot::refresh_catalog_snapshot(
        &mut state,
        &config,
        None,
        agentdeck_protocol::runtime::StreamCursor::At(0),
    )
    .expect("materialize authenticated catalog snapshot through revision zero");
    let rotated = rotate_publication_stream(&mut state, &config, rotation, 6)
        .expect("covered rollover succeeds");
    assert_ne!(rotated.generation, generation);
    assert_eq!(rotated.rotation_serial, 1);
    drop(state);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn max_sequence_rolls_over_without_wrapping_and_tombstone_is_token_authenticated() {
    let (root, config, mut state) = open_publication_test_store("rollover-u64-max");
    let stream_id = [0x41; 16];
    let generation = [0x42; 16];
    create_publication_stream(
        &mut state,
        &config,
        stream_id,
        PublicationScope::Catalog,
        [0x43; 16],
        generation,
        1,
    )
    .expect("create max-sequence stream");
    let transaction = Transaction::new_unchecked(&state.connection, TransactionBehavior::Immediate)
        .expect("begin max-sequence fixture");
    let mut stream =
        load_stream(&transaction, &state.key_bundle, stream_id).expect("load max-sequence stream");
    stream.counter_scope_token = Some([0x44; 32]);
    stream.sender_counter_high_water = Some(40);
    stream.reserved_high_water = Some(u64::MAX - 1);
    stream.committed_high_water = Some(u64::MAX - 1);
    stream.last_committed_blob_hash = Some([0x45; 32]);
    stream.acknowledged_high_water = Some(u64::MAX - 1);
    stream.last_acknowledged_blob_hash = Some([0x45; 32]);
    update_stream(&transaction, &state.key_bundle, &stream)
        .expect("install authenticated max-sequence fixture");
    transaction.commit().expect("commit max-sequence fixture");

    let publication_id = [0x46; 16];
    let request = FreezePublicationRequest {
        publication_id,
        publication_stream_id: stream_id,
        generation,
        counter_scope_token: [0x44; 32],
        sender_counter: 41,
        inner_after: None,
        inner_through: None,
        payload_kind: PublicationPayloadKind::Control,
        blob: b"terminal-sequence".to_vec(),
    };
    let frozen = freeze_publication(&mut state, &config, request.clone(), 2)
        .expect("reserve u64::MAX exactly once");
    assert_eq!(frozen.stream_seq, u64::MAX);
    assert_eq!(
        load_stream(&state.connection, &state.key_bundle, stream_id)
            .expect("load terminal stream")
            .state,
        PublicationStreamState::NeedsSnapshot
    );
    acknowledge_publication_commit(
        &mut state,
        &config,
        stream_id,
        generation,
        u64::MAX,
        frozen.blob_sha256,
        3,
    )
    .expect("commit terminal sequence");
    acknowledge_publication_delivery(
        &mut state,
        &config,
        stream_id,
        generation,
        u64::MAX,
        frozen.blob_sha256,
        4,
    )
    .expect("ack terminal sequence");
    let rotated = rotate_publication_stream(
        &mut state,
        &config,
        RotatePublicationStreamRequest {
            publication_stream_id: stream_id,
            expected_generation: generation,
        },
        5,
    )
    .expect("roll over terminal sequence without wrapping");
    assert!(rotated.reserved_high_water.is_none());
    assert_eq!(rotated.rotation_serial, 1);
    assert_eq!(rotated.sender_counter_high_water, Some(41));
    assert_eq!(
        rotated.last_acknowledged_publication_id,
        Some(publication_id)
    );
    assert!(matches!(
        freeze_publication(&mut state, &config, request, 6),
        Err(RuntimeStoreError::PublicationAlreadyAcknowledged)
    ));
    let continued = freeze_publication(
        &mut state,
        &config,
        FreezePublicationRequest {
            publication_id: [0x47; 16],
            publication_stream_id: stream_id,
            generation: rotated.generation,
            counter_scope_token: [0x44; 32],
            sender_counter: 42,
            inner_after: None,
            inner_through: None,
            payload_kind: PublicationPayloadKind::Control,
            blob: b"continued-after-outer-rollover".to_vec(),
        },
        6,
    )
    .expect("outer rollover keeps the unexhausted counter scope usable");
    assert_eq!(continued.stream_seq, 0);
    assert_eq!(continued.sender_counter, 42);

    state
        .connection
        .execute(
            "UPDATE publication_streams
                 SET last_acknowledged_request_digest = zeroblob(32)
                 WHERE publication_stream_id = ?1",
            [&stream_id[..]],
        )
        .expect("tamper ACK tombstone digest without its token");
    assert!(matches!(
        load_stream(&state.connection, &state.key_bundle, stream_id),
        Err(RuntimeStoreError::UnknownOrCorruptSchema)
    ));
    drop(state);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn exhausted_sender_counter_rejects_rollover_and_stays_needs_snapshot() {
    let (root, config, mut state) = open_publication_test_store("counter-u64-max");
    let stream_id = [0x49; 16];
    let generation = [0x4a; 16];
    create_publication_stream(
        &mut state,
        &config,
        stream_id,
        PublicationScope::Catalog,
        [0x4b; 16],
        generation,
        1,
    )
    .expect("create counter exhaustion stream");
    let frozen = freeze_publication(
        &mut state,
        &config,
        FreezePublicationRequest {
            publication_id: [0x4c; 16],
            publication_stream_id: stream_id,
            generation,
            counter_scope_token: [0x4d; 32],
            sender_counter: u64::MAX,
            inner_after: None,
            inner_through: None,
            payload_kind: PublicationPayloadKind::Control,
            blob: b"counter-terminal".to_vec(),
        },
        2,
    )
    .expect("freeze the terminal sender counter exactly once");
    acknowledge_publication_commit(
        &mut state,
        &config,
        stream_id,
        generation,
        frozen.stream_seq,
        frozen.blob_sha256,
        3,
    )
    .expect("commit terminal counter publication");
    acknowledge_publication_delivery(
        &mut state,
        &config,
        stream_id,
        generation,
        frozen.stream_seq,
        frozen.blob_sha256,
        4,
    )
    .expect("ack terminal counter publication");
    assert!(matches!(
        rotate_publication_stream(
            &mut state,
            &config,
            RotatePublicationStreamRequest {
                publication_stream_id: stream_id,
                expected_generation: generation,
            },
            5,
        ),
        Err(RuntimeStoreError::PublicationCounterExhausted)
    ));
    let persisted = load_stream(&state.connection, &state.key_bundle, stream_id)
        .expect("load counter-exhausted stream");
    assert_eq!(persisted.generation, generation);
    assert_eq!(persisted.rotation_serial, 0);
    assert_eq!(persisted.sender_counter_high_water, Some(u64::MAX));
    assert_eq!(persisted.state, PublicationStreamState::NeedsSnapshot);
    drop(state);
    let _ = fs::remove_dir_all(root);
}

#[tokio::test]
async fn snapshot_and_outbox_retained_memory_stay_within_global_budgets() {
    use crate::runtime::read_pool::{
        MAX_RUNTIME_READ_RETAINED_BYTES, MAX_RUNTIME_READ_SNAPSHOT_BYTES, ReadPool, ReadPoolError,
    };

    assert_eq!(MAX_RUNTIME_READ_RETAINED_BYTES, 128 * 1024 * 1024);
    assert_eq!(MAX_RUNTIME_READ_SNAPSHOT_BYTES, 128 * 1024 * 1024);
    assert_eq!(
        super::super::snapshot::MAX_SNAPSHOT_BYTES_GLOBAL,
        512 * 1024 * 1024
    );
    assert_eq!(MAX_PUBLICATION_BYTES_GLOBAL, 512 * 1024 * 1024);

    let (root, config, mut state) = open_publication_test_store("retained-global-budgets");
    let stream_id = [0x91; 16];
    let generation = [0x92; 16];
    create_publication_stream(
        &mut state,
        &config,
        stream_id,
        PublicationScope::Catalog,
        [0x93; 16],
        generation,
        1,
    )
    .expect("create budget publication stream through production admission");
    assert_eq!(
        state.admission_state,
        super::super::admission::RuntimeAdmissionState::Normal
    );

    let scaled_limits = PublicationLimits {
        rows_per_stream: 8,
        bytes_per_stream: 8,
        rows_global: 8,
        bytes_global: 1,
    };
    let first_request = FreezePublicationRequest {
        publication_id: [0x94; 16],
        publication_stream_id: stream_id,
        generation,
        counter_scope_token: [0x95; 32],
        sender_counter: 1,
        inner_after: None,
        inner_through: Some(0),
        payload_kind: PublicationPayloadKind::Catalog,
        blob: vec![0x96],
    };
    let first =
        freeze_publication_with_limits(&mut state, &config, first_request, 2, scaled_limits)
            .expect("freeze one-byte outbox row through production admission");
    let after_first = super::super::sqlite::load_runtime_ledger(
        &state.connection,
        &state.key_bundle,
        state.database_id,
    )
    .expect("load authenticated ledger after first outbox row");
    assert_eq!(after_first.publication_outbox_count, 1);
    assert_eq!(after_first.publication_outbox_bytes, 1);

    let rejected = freeze_publication_with_limits(
        &mut state,
        &config,
        FreezePublicationRequest {
            publication_id: [0x97; 16],
            publication_stream_id: stream_id,
            generation,
            counter_scope_token: [0x95; 32],
            sender_counter: 2,
            inner_after: Some(0),
            inner_through: Some(1),
            payload_kind: PublicationPayloadKind::Catalog,
            blob: vec![0x98],
        },
        3,
        scaled_limits,
    )
    .expect_err("scaled global byte cap must reject the second retained row");
    assert!(matches!(
        rejected,
        RuntimeStoreError::PublicationNeedsSnapshot
    ));
    let after_rejection = super::super::sqlite::load_runtime_ledger(
        &state.connection,
        &state.key_bundle,
        state.database_id,
    )
    .expect("load authenticated ledger after budget rejection");
    assert_eq!(after_rejection.publication_outbox_count, 1);
    assert_eq!(after_rejection.publication_outbox_bytes, 1);
    assert_eq!(
        load_pending_publications(&state, stream_id).expect("load retained unacked row"),
        [first],
        "budget rejection must not evict the existing unacked publication"
    );

    // `run_sqlite_snapshot` 是 production snapshot retained-memory seam：第一份
    // handoff lease 存活期间必须占满 128 MiB 全池，第二份不能绕过全局预算。
    let pool = ReadPool::open_sqlite(&state.storage_path, 2, config.busy_timeout_ms)
        .expect("open production read-only WAL pool");
    let retained = pool
        .run_sqlite_snapshot(|connection| {
            connection
                .query_row("SELECT COUNT(*) FROM publication_outbox", [], |row| {
                    row.get::<_, i64>(0)
                })
                .map_err(ReadPoolError::from)
        })
        .await
        .expect("acquire full snapshot retained-memory lease");
    let (visible_outbox_rows, lease) = retained.into_parts();
    assert_eq!(visible_outbox_rows, 1);
    assert!(matches!(
        pool.run_sqlite_snapshot(|_| Ok(())).await,
        Err(ReadPoolError::Busy)
    ));
    drop(lease);
    let released = pool
        .run_sqlite_snapshot(|_| Ok(()))
        .await
        .expect("dropping the first lease returns the full snapshot budget");
    drop(released);
    pool.close_and_wait().await;

    drop(state);
    let _ = fs::remove_dir_all(root);
}
