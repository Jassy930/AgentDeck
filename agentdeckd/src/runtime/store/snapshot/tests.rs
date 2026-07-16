use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use agentdeck_protocol::AgentKind;
use agentdeck_protocol::runtime::StreamCursor;
use sha2::{Digest, Sha256};

use super::*;
use crate::runtime::model::{ConversationDescriptor, NewConversation};
use crate::security::{MemoryKeyStore, load_or_create_storage_kek};

static NEXT_ROOT: AtomicU64 = AtomicU64::new(1);

fn open_test_state(label: &str) -> (PathBuf, RuntimeStoreConfig, RuntimeSqlite) {
    let root = std::env::temp_dir().join(format!(
        "agentdeck-snapshot-{label}-{}-{}",
        std::process::id(),
        NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir(&root).expect("create snapshot test root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .expect("secure snapshot test root");
    }
    let config = RuntimeStoreConfig::new(root.join("runtime.db"));
    let keys = MemoryKeyStore::new();
    let kek =
        load_or_create_storage_kek(&keys, &root.join("key-state.db")).expect("create test KEK");
    let state = super::super::sqlite::open(&config, kek).expect("open test store");
    (root, config, state)
}

fn insert_catalog_directory_row(
    state: &RuntimeSqlite,
    snapshot_id: [u8; 16],
    base: Option<u64>,
    item_count: u64,
    logical_bytes: u64,
) {
    let base_encoded = base.map(encode_sequence);
    let content_sha256 = [snapshot_id[0].wrapping_add(1); 32];
    let sealed_snapshot = vec![0_u8; 40];
    let sealed_snapshot_sha256 = snapshot_ciphertext_sha256(&sealed_snapshot);
    let token = snapshot_token(
        &state.key_bundle,
        "catalog",
        None,
        &snapshot_id,
        None,
        base_encoded.as_deref(),
        item_count,
        logical_bytes,
        &content_sha256,
        &sealed_snapshot_sha256,
        1,
    )
    .expect("authenticate catalog directory row");
    state
        .connection
        .execute(
            "INSERT INTO snapshots (
                     snapshot_id, target_scope, conversation_id, source_build_pin_id,
                     base_cursor, build_state, item_count, logical_snapshot_bytes,
                     content_sha256, sealed_snapshot_sha256, created_at_ms,
                     metadata_token, sealed_snapshot
                 ) VALUES (?1, 'catalog', NULL, NULL, ?2, 'ready',
                           ?3, ?4, ?5, ?6, 1, ?7, ?8)",
            rusqlite::params![
                &snapshot_id[..],
                base_encoded.as_deref(),
                i64::try_from(item_count).expect("item count fits SQLite"),
                i64::try_from(logical_bytes).expect("logical bytes fit SQLite"),
                &content_sha256[..],
                &sealed_snapshot_sha256[..],
                &token[..],
                sealed_snapshot,
            ],
        )
        .expect("insert catalog directory row");
}

fn create_directory_conversation(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    seed: u8,
) -> RuntimeId {
    let conversation_id =
        RuntimeId::from_bytes(RuntimeIdKind::Conversation, [seed; 16]).expect("conversation id");
    let input = NewConversation {
        conversation_id,
        adapter_state_key: RuntimeId::from_bytes(
            RuntimeIdKind::AdapterState,
            [seed.wrapping_add(0x40); 16],
        )
        .expect("adapter id"),
        descriptor: ConversationDescriptor {
            agent_kind: AgentKind::Codex,
            title: Some(format!("directory-parent-{seed}")),
            cwd: PathBuf::from(format!("/tmp/snapshot-directory-parent-{seed}")),
        },
    };
    let descriptor = super::super::journal::canonical_conversation_descriptor(&input.descriptor)
        .expect("canonical descriptor");
    let mut effects = crate::runtime::events::CommandStreamEffects::default();
    super::super::journal::create_conversation(state, config, input, descriptor, &mut effects)
        .expect("create conversation");
    conversation_id
}

#[test]
fn legacy_runtime_v1_catalog_baseline_dual_decodes_without_rewrite() {
    let legacy = LegacyCatalogBaselineV4 {
        version: 1,
        base_catalog_cursor: StreamCursor::At(4),
        entries: vec![super::super::catalog::LegacyConversationEntryV4 {
            conversation_id: agentdeck_protocol::runtime::identity::ConversationId::new(
                "conversation-legacy",
            ),
            adapter_state_key: "adapter-private".into(),
            agent_kind: AgentKind::Codex,
            title: Some("legacy baseline".into()),
            cwd: Some(PathBuf::from("/tmp/legacy-baseline")),
            last_active_ms: 5,
            archived: false,
        }],
    };
    let payload = serde_json::to_vec(&legacy).expect("encode canonical v1 catalog baseline");
    let persisted = decode_persisted_catalog_baseline(&payload)
        .expect("retain the authenticated baseline format until canonical validation");
    let PersistedCatalogBaseline::Legacy(original) = &persisted else {
        panic!("v1 baseline must retain its legacy DTO before conversion");
    };
    assert_eq!(serde_json::to_vec(original).unwrap(), payload);
    let preserved = persisted.into_current();
    assert_eq!(preserved.entries[0].entry_revision, 0);
    let (decoded, was_legacy) =
        decode_catalog_baseline_with_format(&payload).expect("dual decode v1 catalog baseline");
    assert!(was_legacy);
    assert_eq!(decoded.entries[0].entry_revision, 0);
    assert!(
        !serde_json::to_string(&decoded)
            .unwrap()
            .contains("adapterStateKey")
    );
}

#[test]
fn expired_snapshot_write_is_consumed_and_cannot_revive_after_clock_rollback() {
    // 威胁场景：snapshot pin 在 exact expiry 被拒后，系统时钟回拨；若事务
    // rollback 恢复了 pin 且错误返还 exact payload，旧 capability 就能重新提交。
    let (root, config, mut state) = open_test_state("expired-write-clock-rollback");
    let conversation_id = create_directory_conversation(&mut state, &config, 0x2A);
    let issued_at_ms = 1_000;
    let pin =
        super::super::stream::acquire_snapshot_build_pin(&state, conversation_id, issued_at_ms)
            .expect("acquire snapshot build pin");
    let mut payload = br#"{"snapshot":"expired"}"#.to_vec();
    payload
        .try_reserve_exact(ROW_BLOB_V1_OVERHEAD_LEN)
        .expect("reserve production in-place seal overhead");
    let failure = store_conversation_snapshot_owned(
        &mut state,
        &config,
        &pin,
        1,
        payload,
        pin.expires_at_ms(),
        PRODUCTION_LIMITS,
    )
    .expect_err("exact-expiry snapshot write must fail closed");
    assert!(matches!(
        failure.error,
        RuntimeStoreError::InvalidStateTransition
    ));

    if let Some(payload) = failure.retry_payload {
        let revived = store_conversation_snapshot_owned(
            &mut state,
            &config,
            &pin,
            1,
            payload,
            issued_at_ms,
            PRODUCTION_LIMITS,
        );
        match revived {
            Ok(_) => panic!("expired snapshot capability revived after clock rollback"),
            Err(second) => panic!(
                "expired snapshot failure returned a reusable payload; retry failed as {:?}",
                second.error
            ),
        }
    }
    let pin_id = pin.pin_id();
    let pin_count: i64 = state
        .connection
        .query_row(
            "SELECT COUNT(*) FROM temp.active_stream_pins WHERE pin_id = ?1",
            [&pin_id[..]],
            |row| row.get(0),
        )
        .expect("read back consumed expired pin");
    assert_eq!(pin_count, 0, "expired snapshot pin was not consumed");

    drop(state);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn catalog_refresh_preflight_authenticates_exact_source_and_delta_metadata_without_payloads() {
    let (root, config, mut state) = open_test_state("catalog-refresh-preflight");
    create_directory_conversation(&mut state, &config, 0x31);
    assert!(
        load_catalog_snapshot_metadata(&state.connection, &state.key_bundle)
            .expect("load fresh catalog source metadata")
            .is_none(),
        "direct SQLite fixture starts before the first catalog baseline refresh"
    );

    begin_snapshot_read_allocation_probe();
    let preflight = preflight_catalog_snapshot_refresh(&state, None, StreamCursor::At(0))
        .expect("authenticate absent source and revision-zero delta");
    let observation = finish_snapshot_read_allocation_probe();
    assert!(preflight.peak_retained_bytes > 0);
    assert!(preflight.refresh_required);
    assert_eq!(
        observation.materialized_blob_bytes, 0,
        "metadata-only preflight must not materialize snapshot or delta ciphertext"
    );

    let original_delta_bytes: i64 = state
        .connection
        .query_row(
            "SELECT logical_delta_bytes FROM catalog_journal
                 WHERE catalog_revision = ?1",
            [encode_sequence(0)],
            |row| row.get(0),
        )
        .expect("read original authenticated delta byte count");
    assert_eq!(
        state
            .connection
            .execute(
                "UPDATE catalog_journal
                     SET logical_delta_bytes = logical_delta_bytes + 1
                     WHERE catalog_revision = ?1",
                [encode_sequence(0)],
            )
            .expect("tamper authenticated delta byte count"),
        1
    );
    assert!(matches!(
        preflight_catalog_snapshot_refresh(&state, None, StreamCursor::At(0)),
        Err(RuntimeStoreError::UnknownOrCorruptSchema)
    ));
    assert_eq!(
        state
            .connection
            .execute(
                "UPDATE catalog_journal SET logical_delta_bytes = ?1
                     WHERE catalog_revision = ?2",
                rusqlite::params![original_delta_bytes, encode_sequence(0)],
            )
            .expect("restore authenticated delta byte count"),
        1
    );

    let source = refresh_catalog_snapshot(&mut state, &config, None, StreamCursor::At(0))
        .expect("materialize first exact catalog baseline after preflight");
    let same_cut = preflight_catalog_snapshot_refresh(&state, Some(&source), StreamCursor::At(0))
        .expect("exact current snapshot reference remains accepted");
    assert!(!same_cut.refresh_required);
    let mut wrong_source = source.clone();
    wrong_source.content_sha256[0] ^= 0x80;
    assert!(matches!(
        preflight_catalog_snapshot_refresh(&state, Some(&wrong_source), StreamCursor::At(0),),
        Err(RuntimeStoreError::InvalidStateTransition)
    ));

    drop(state);
    let _ = fs::remove_dir_all(root);
}

fn insert_conversation_directory_row(
    state: &RuntimeSqlite,
    conversation_id: RuntimeId,
    snapshot_id: [u8; 16],
    logical_bytes: u64,
) {
    let source_build_pin_id = [snapshot_id[0].wrapping_add(1); 16];
    let content_sha256 = [snapshot_id[0].wrapping_add(2); 32];
    let sealed_snapshot = vec![0_u8; 40];
    let sealed_snapshot_sha256 = snapshot_ciphertext_sha256(&sealed_snapshot);
    let token = snapshot_token(
        &state.key_bundle,
        "conversation",
        Some(conversation_id.as_bytes()),
        &snapshot_id,
        Some(&source_build_pin_id),
        None,
        1,
        logical_bytes,
        &content_sha256,
        &sealed_snapshot_sha256,
        1,
    )
    .expect("authenticate conversation directory row");
    state
        .connection
        .execute(
            "INSERT INTO snapshots (
                     snapshot_id, target_scope, conversation_id, source_build_pin_id,
                     base_cursor, build_state, item_count, logical_snapshot_bytes,
                     content_sha256, sealed_snapshot_sha256, created_at_ms,
                     metadata_token, sealed_snapshot
                 ) VALUES (?1, 'conversation', ?2, ?3, NULL, 'ready',
                           1, ?4, ?5, ?6, 1, ?7, ?8)",
            rusqlite::params![
                &snapshot_id[..],
                &conversation_id.as_bytes()[..],
                &source_build_pin_id[..],
                i64::try_from(logical_bytes).expect("logical bytes fit SQLite"),
                &content_sha256[..],
                &sealed_snapshot_sha256[..],
                &token[..],
                sealed_snapshot,
            ],
        )
        .expect("insert conversation directory row");
}

#[derive(Clone, Copy)]
struct SeededDirectoryRow {
    conversation_id: RuntimeId,
    snapshot_id: [u8; 16],
    source_build_pin_id: [u8; 16],
    content_sha256: [u8; 32],
    sealed_snapshot_sha256: [u8; 32],
    parent_metadata_token: [u8; 32],
    snapshot_metadata_token: [u8; 32],
}

fn indexed_id_bytes(prefix: u8, index: u16) -> [u8; 16] {
    let mut bytes = [prefix; 16];
    bytes[14..].copy_from_slice(&index.to_be_bytes());
    bytes
}

fn seed_conversation_directory_rows(state: &RuntimeSqlite, row_count: u64) -> SeededDirectoryRow {
    let transaction = rusqlite::Transaction::new_unchecked(
        &state.connection,
        rusqlite::TransactionBehavior::Immediate,
    )
    .expect("open directory seed transaction");
    let mut last = None;
    for index in 0..row_count {
        let index = u16::try_from(index).expect("directory index fits u16");
        let conversation_id =
            RuntimeId::from_bytes(RuntimeIdKind::Conversation, indexed_id_bytes(0xa1, index))
                .expect("seed conversation id");
        let adapter_state_key =
            RuntimeId::from_bytes(RuntimeIdKind::AdapterState, indexed_id_bytes(0xa2, index))
                .expect("seed adapter id");
        let catalog_revision = u64::from(index);
        let parent_metadata_token = super::super::journal::conversation_metadata_token_for_test(
            &state.key_bundle,
            conversation_id,
            adapter_state_key,
            catalog_revision,
            None,
            None,
            0,
            crate::runtime::model::ConversationLifecycle::Active,
            1,
            1,
        )
        .expect("authenticate seeded parent metadata");
        transaction
            .execute(
                "INSERT INTO conversations (
                         conversation_id, adapter_state_key, catalog_revision,
                         command_high_water, event_high_water, lifecycle,
                         created_at_ms, updated_at_ms, accepted_count,
                         metadata_token, sealed_descriptor
                     ) VALUES (?1, ?2, ?3, NULL, NULL, 'active', 1, 1, 0, ?4, ?5)",
                rusqlite::params![
                    &conversation_id.as_bytes()[..],
                    &adapter_state_key.as_bytes()[..],
                    encode_sequence(catalog_revision),
                    &parent_metadata_token[..],
                    vec![0_u8; 40],
                ],
            )
            .expect("insert seeded parent");

        let snapshot_id = indexed_id_bytes(0xa3, index);
        let source_build_pin_id = indexed_id_bytes(0xa4, index);
        let content_sha256: [u8; 32] = Sha256::digest(index.to_be_bytes()).into();
        let sealed_snapshot = vec![0_u8; 40];
        let sealed_snapshot_sha256 = snapshot_ciphertext_sha256(&sealed_snapshot);
        let snapshot_metadata_token = snapshot_token(
            &state.key_bundle,
            "conversation",
            Some(conversation_id.as_bytes()),
            &snapshot_id,
            Some(&source_build_pin_id),
            None,
            1,
            1,
            &content_sha256,
            &sealed_snapshot_sha256,
            1,
        )
        .expect("authenticate seeded snapshot metadata");
        transaction
            .execute(
                "INSERT INTO snapshots (
                         snapshot_id, target_scope, conversation_id, source_build_pin_id,
                         base_cursor, build_state, item_count, logical_snapshot_bytes,
                         content_sha256, sealed_snapshot_sha256, created_at_ms,
                         metadata_token, sealed_snapshot
                     ) VALUES (?1, 'conversation', ?2, ?3, NULL, 'ready',
                               1, 1, ?4, ?5, 1, ?6, ?7)",
                rusqlite::params![
                    &snapshot_id[..],
                    &conversation_id.as_bytes()[..],
                    &source_build_pin_id[..],
                    &content_sha256[..],
                    &sealed_snapshot_sha256[..],
                    &snapshot_metadata_token[..],
                    sealed_snapshot,
                ],
            )
            .expect("insert seeded snapshot");
        last = Some(SeededDirectoryRow {
            conversation_id,
            snapshot_id,
            source_build_pin_id,
            content_sha256,
            sealed_snapshot_sha256,
            parent_metadata_token,
            snapshot_metadata_token,
        });
    }
    transaction.commit().expect("commit directory seed");
    last.expect("directory seed must contain at least one row")
}

fn authenticate_test_directory(
    state: &RuntimeSqlite,
    ledger: &RuntimeLedger,
    target: crate::runtime::events::RuntimeStreamTarget,
) -> Result<Option<ReadySnapshotReference>, RuntimeStoreError> {
    let transaction = rusqlite::Transaction::new_unchecked(
        &state.connection,
        rusqlite::TransactionBehavior::Deferred,
    )
    .expect("open test directory transaction");
    let result = authenticate_directory(&transaction, &state.key_bundle, ledger, target);
    drop(transaction);
    result
}

#[test]
fn directory_batches_parent_metadata_authentication_into_one_query() {
    let (root, config, mut state) = open_test_state("parent-query-count");
    let first = create_directory_conversation(&mut state, &config, 0x61);
    let second = create_directory_conversation(&mut state, &config, 0x62);
    insert_conversation_directory_row(&state, first, [0x63; 16], 4);
    insert_conversation_directory_row(&state, second, [0x64; 16], 5);
    let mut ledger = super::super::sqlite::load_runtime_ledger(
        &state.connection,
        &state.key_bundle,
        state.database_id,
    )
    .expect("load authenticated ledger");
    ledger.snapshot_count = 2;
    ledger.snapshot_bytes = 9;
    let transaction = rusqlite::Transaction::new_unchecked(
        &state.connection,
        rusqlite::TransactionBehavior::Deferred,
    )
    .expect("open directory transaction");

    super::super::journal::reset_authenticated_event_high_water_query_count();
    let reference = authenticate_directory(
        &transaction,
        &state.key_bundle,
        &ledger,
        crate::runtime::events::RuntimeStreamTarget::Conversation(first),
    )
    .expect("authenticate snapshot directory")
    .expect("requested snapshot reference");

    assert_eq!(
        reference.target,
        crate::runtime::events::RuntimeStreamTarget::Conversation(first)
    );
    assert_eq!(
        super::super::journal::authenticated_event_high_water_query_count(),
        1,
        "parent metadata must be authenticated by one bounded query regardless of directory size"
    );
    drop(transaction);
    drop(state);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn directory_batches_maximum_parent_set_and_still_checks_every_parent() {
    let (root, _config, state) = open_test_state("maximum-parent-query-count");
    let last = seed_conversation_directory_rows(&state, MAX_DIRECTORY_ROWS);
    let ledger = RuntimeLedger {
        conversation_count: MAX_DIRECTORY_ROWS,
        snapshot_count: MAX_DIRECTORY_ROWS,
        snapshot_bytes: MAX_DIRECTORY_ROWS,
        ..RuntimeLedger::default()
    };
    let target = crate::runtime::events::RuntimeStreamTarget::Conversation(last.conversation_id);

    super::super::journal::reset_authenticated_event_high_water_query_count();
    let reference = authenticate_test_directory(&state, &ledger, target)
        .expect("authenticate maximum legal directory")
        .expect("requested maximum-directory snapshot");
    assert_eq!(reference.target, target);
    assert_eq!(
        super::super::journal::authenticated_event_high_water_query_count(),
        1
    );

    assert_eq!(
        state
            .connection
            .execute(
                "UPDATE conversations SET metadata_token = zeroblob(32)
                     WHERE conversation_id = ?1",
                [&last.conversation_id.as_bytes()[..]],
            )
            .expect("tamper last parent metadata MAC"),
        1
    );
    super::super::journal::reset_authenticated_event_high_water_query_count();
    assert!(matches!(
        authenticate_test_directory(&state, &ledger, target),
        Err(RuntimeStoreError::UnknownOrCorruptSchema)
    ));
    assert_eq!(
        super::super::journal::authenticated_event_high_water_query_count(),
        1
    );

    assert_eq!(
        state
            .connection
            .execute(
                "UPDATE conversations SET metadata_token = ?1
                     WHERE conversation_id = ?2",
                rusqlite::params![
                    &last.parent_metadata_token[..],
                    &last.conversation_id.as_bytes()[..]
                ],
            )
            .expect("restore last parent metadata MAC"),
        1
    );
    let base = encode_sequence(0);
    let newer_base_token = snapshot_token(
        &state.key_bundle,
        "conversation",
        Some(last.conversation_id.as_bytes()),
        &last.snapshot_id,
        Some(&last.source_build_pin_id),
        Some(&base),
        1,
        1,
        &last.content_sha256,
        &last.sealed_snapshot_sha256,
        1,
    )
    .expect("authenticate snapshot with newer base");
    assert_eq!(
        state
            .connection
            .execute(
                "UPDATE snapshots SET base_cursor = ?1, metadata_token = ?2
                     WHERE snapshot_id = ?3",
                rusqlite::params![&base, &newer_base_token[..], &last.snapshot_id[..]],
            )
            .expect("install authenticated newer snapshot base"),
        1
    );
    super::super::journal::reset_authenticated_event_high_water_query_count();
    assert!(matches!(
        authenticate_test_directory(&state, &ledger, target),
        Err(RuntimeStoreError::UnknownOrCorruptSchema)
    ));
    assert_eq!(
        super::super::journal::authenticated_event_high_water_query_count(),
        1
    );

    assert_eq!(
        state
            .connection
            .execute(
                "UPDATE snapshots SET base_cursor = NULL, metadata_token = ?1
                     WHERE snapshot_id = ?2",
                rusqlite::params![&last.snapshot_metadata_token[..], &last.snapshot_id[..]],
            )
            .expect("restore snapshot base"),
        1
    );
    state
        .connection
        .pragma_update(None, "foreign_keys", false)
        .expect("disable foreign keys for missing-parent fixture");
    assert_eq!(
        state
            .connection
            .execute(
                "DELETE FROM conversations WHERE conversation_id = ?1",
                [&last.conversation_id.as_bytes()[..]],
            )
            .expect("delete last parent"),
        1
    );
    super::super::journal::reset_authenticated_event_high_water_query_count();
    assert!(matches!(
        authenticate_test_directory(&state, &ledger, target),
        Err(RuntimeStoreError::UnknownOrCorruptSchema)
    ));
    assert_eq!(
        super::super::journal::authenticated_event_high_water_query_count(),
        1
    );

    drop(state);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn directory_rejects_catalog_base_newer_than_authenticated_ledger() {
    let (root, _config, state) = open_test_state("catalog-base-cut");
    let ledger = RuntimeLedger {
        catalog_high_water: Some(encode_sequence(0)),
        snapshot_count: 1,
        snapshot_bytes: 4,
        ..RuntimeLedger::default()
    };
    insert_catalog_directory_row(&state, [0x71; 16], Some(1), 0, 4);
    let transaction = rusqlite::Transaction::new_unchecked(
        &state.connection,
        rusqlite::TransactionBehavior::Deferred,
    )
    .expect("open directory transaction");
    assert!(matches!(
        authenticate_directory(
            &transaction,
            &state.key_bundle,
            &ledger,
            crate::runtime::events::RuntimeStreamTarget::Catalog,
        ),
        Err(RuntimeStoreError::UnknownOrCorruptSchema)
    ));
    drop(transaction);
    drop(state);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn directory_rejects_catalog_items_above_authenticated_conversation_count() {
    let (root, _config, state) = open_test_state("catalog-item-count");
    let ledger = RuntimeLedger {
        catalog_high_water: Some(encode_sequence(0)),
        conversation_count: 0,
        snapshot_count: 1,
        snapshot_bytes: 4,
        ..RuntimeLedger::default()
    };
    insert_catalog_directory_row(&state, [0x72; 16], Some(0), 1, 4);
    let transaction = rusqlite::Transaction::new_unchecked(
        &state.connection,
        rusqlite::TransactionBehavior::Deferred,
    )
    .expect("open directory transaction");
    assert!(matches!(
        authenticate_directory(
            &transaction,
            &state.key_bundle,
            &ledger,
            crate::runtime::events::RuntimeStreamTarget::Catalog,
        ),
        Err(RuntimeStoreError::UnknownOrCorruptSchema)
    ));
    drop(transaction);
    drop(state);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn directory_rejects_zero_item_conversation_row_with_valid_mac() {
    let (root, config, mut state) = open_test_state("conversation-zero-items");
    let input = NewConversation {
        conversation_id: RuntimeId::from_bytes(RuntimeIdKind::Conversation, [0x73; 16])
            .expect("conversation id"),
        adapter_state_key: RuntimeId::from_bytes(RuntimeIdKind::AdapterState, [0x74; 16])
            .expect("adapter id"),
        descriptor: ConversationDescriptor {
            agent_kind: AgentKind::Codex,
            title: Some("zero-item-directory-row".to_owned()),
            cwd: PathBuf::from("/tmp/snapshot-zero-items"),
        },
    };
    let conversation_id = input.conversation_id;
    let descriptor = super::super::journal::canonical_conversation_descriptor(&input.descriptor)
        .expect("canonical descriptor");
    let mut effects = crate::runtime::events::CommandStreamEffects::default();
    super::super::journal::create_conversation(
        &mut state,
        &config,
        input,
        descriptor,
        &mut effects,
    )
    .expect("create conversation");
    let snapshot_id = [0x75; 16];
    let source_build_pin_id = [0x76; 16];
    let content_sha256 = [0x77; 32];
    let logical_bytes = 4_u64;
    let sealed_snapshot = vec![0_u8; 40];
    let sealed_snapshot_sha256 = snapshot_ciphertext_sha256(&sealed_snapshot);
    let token = snapshot_token(
        &state.key_bundle,
        "conversation",
        Some(conversation_id.as_bytes()),
        &snapshot_id,
        Some(&source_build_pin_id),
        None,
        0,
        logical_bytes,
        &content_sha256,
        &sealed_snapshot_sha256,
        1,
    )
    .expect("authenticate zero-item directory row");
    state
        .connection
        .execute(
            "INSERT INTO snapshots (
                     snapshot_id, target_scope, conversation_id, source_build_pin_id,
                     base_cursor, build_state, item_count, logical_snapshot_bytes,
                     content_sha256, sealed_snapshot_sha256, created_at_ms,
                     metadata_token, sealed_snapshot
                 ) VALUES (?1, 'conversation', ?2, ?3, NULL, 'ready',
                           0, ?4, ?5, ?6, 1, ?7, ?8)",
            rusqlite::params![
                &snapshot_id[..],
                &conversation_id.as_bytes()[..],
                &source_build_pin_id[..],
                i64::try_from(logical_bytes).expect("logical bytes fit SQLite"),
                &content_sha256[..],
                &sealed_snapshot_sha256[..],
                &token[..],
                sealed_snapshot,
            ],
        )
        .expect("insert zero-item directory row");
    let mut ledger = super::super::sqlite::load_runtime_ledger(
        &state.connection,
        &state.key_bundle,
        state.database_id,
    )
    .expect("load authenticated ledger");
    ledger.snapshot_count = 1;
    ledger.snapshot_bytes = logical_bytes;
    let transaction = rusqlite::Transaction::new_unchecked(
        &state.connection,
        rusqlite::TransactionBehavior::Deferred,
    )
    .expect("open directory transaction");
    assert!(matches!(
        authenticate_directory(
            &transaction,
            &state.key_bundle,
            &ledger,
            crate::runtime::events::RuntimeStreamTarget::Conversation(conversation_id),
        ),
        Err(RuntimeStoreError::UnknownOrCorruptSchema)
    ));
    drop(transaction);
    drop(state);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn directory_parent_error_classification_separates_shape_from_engine_failures() {
    let connection = Connection::open_in_memory().expect("open classification database");
    connection
        .execute_batch(
            "CREATE TABLE shape_fixture (value TEXT NOT NULL);
                 INSERT INTO shape_fixture (value) VALUES ('not-an-integer');",
        )
        .expect("create shape fixture");
    let shape_error = connection
        .query_row("SELECT value FROM shape_fixture", [], |row| {
            row.get::<_, i64>(0)
        })
        .expect_err("TEXT to i64 must be an explicit row-shape error");
    assert!(matches!(
        snapshot_parent_error(RuntimeStoreError::Sqlite(shape_error)),
        RuntimeStoreError::UnknownOrCorruptSchema
    ));

    let engine_error = match connection.prepare("SELECT * FROM missing_parent_table") {
        Ok(_) => panic!("missing table prepare unexpectedly succeeded"),
        Err(error) => error,
    };
    assert!(matches!(
        snapshot_parent_error(RuntimeStoreError::Sqlite(engine_error)),
        RuntimeStoreError::Sqlite(_)
    ));
}

#[test]
fn snapshot_global_cap_rejects_new_conversation_without_evicting_ready_snapshot() {
    let root = std::env::temp_dir().join(format!(
        "agentdeck-snapshot-cap-{}-{}",
        std::process::id(),
        NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir(&root).expect("create snapshot cap root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .expect("secure snapshot cap root");
    }
    let config = RuntimeStoreConfig::new(root.join("runtime.db"));
    let keys = MemoryKeyStore::new();
    let kek =
        load_or_create_storage_kek(&keys, &root.join("key-state.db")).expect("create test KEK");
    let mut state = super::super::sqlite::open(&config, kek).expect("open test store");
    let mut conversations = Vec::new();
    for seed in [0x31_u8, 0x32] {
        let input = NewConversation {
            conversation_id: RuntimeId::from_bytes(RuntimeIdKind::Conversation, [seed; 16])
                .expect("conversation id"),
            adapter_state_key: RuntimeId::from_bytes(
                RuntimeIdKind::AdapterState,
                [seed.wrapping_add(0x40); 16],
            )
            .expect("adapter id"),
            descriptor: ConversationDescriptor {
                agent_kind: AgentKind::Codex,
                title: Some(format!("snapshot-{seed}")),
                cwd: PathBuf::from("/tmp/snapshot-cap"),
            },
        };
        let id = input.conversation_id;
        let descriptor =
            super::super::journal::canonical_conversation_descriptor(&input.descriptor)
                .expect("canonical descriptor");
        let mut effects = crate::runtime::events::CommandStreamEffects::default();
        super::super::journal::create_conversation(
            &mut state,
            &config,
            input,
            descriptor,
            &mut effects,
        )
        .expect("create conversation");
        conversations.push(id);
    }
    let limits = SnapshotLimits {
        max_items: MAX_SNAPSHOT_ITEMS,
        max_snapshot_bytes: MAX_SNAPSHOT_BYTES,
        max_global_bytes: 5,
    };
    let first_pin = super::super::stream::acquire_snapshot_build_pin(&state, conversations[0], 10)
        .expect("capture first snapshot");
    let first = store_conversation_snapshot_with_limits(
        &mut state,
        &config,
        first_pin,
        1,
        vec![1; 4],
        10,
        limits,
    )
    .expect("store first snapshot");
    let rejected_pin =
        super::super::stream::acquire_snapshot_build_pin(&state, conversations[1], 11)
            .expect("capture rejected snapshot");
    assert!(matches!(
        store_conversation_snapshot_with_limits(
            &mut state,
            &config,
            rejected_pin,
            1,
            vec![2; 4],
            11,
            limits,
        ),
        Err(RuntimeStoreError::PayloadTooLarge)
    ));
    assert_eq!(
        load_conversation_snapshot(&state, conversations[0])
            .expect("load retained snapshot")
            .expect("snapshot exists"),
        first
    );
    assert!(
        load_conversation_snapshot(&state, conversations[1])
            .expect("load rejected snapshot target")
            .is_none()
    );
    let replacement_pin =
        super::super::stream::acquire_snapshot_build_pin(&state, conversations[0], 12)
            .expect("capture replacement snapshot");
    let replacement = store_conversation_snapshot_with_limits(
        &mut state,
        &config,
        replacement_pin,
        1,
        vec![3; 5],
        12,
        limits,
    )
    .expect("replace same conversation within global cap");
    assert_eq!(
        load_conversation_snapshot(&state, conversations[0])
            .expect("load replacement")
            .expect("replacement exists"),
        replacement
    );
    drop(state);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn maximum_snapshot_store_crypto_stays_within_build_memory_cap() {
    const MAX_BUILD_MEMORY_BYTES: usize = 128 * 1024 * 1024;

    let (root, config, mut state) = open_test_state("maximum-store-crypto-peak");
    let conversation_id = create_directory_conversation(&mut state, &config, 0x81);
    let pin = super::super::stream::acquire_snapshot_build_pin(&state, conversation_id, 10)
        .expect("capture maximum snapshot pin");
    let mut payload = Vec::with_capacity(MAX_SNAPSHOT_BYTES + ROW_BLOB_V1_OVERHEAD_LEN);
    payload.resize(MAX_SNAPSHOT_BYTES, 0x5a);
    let probe = super::super::cipher::begin_cipher_allocation_probe(payload.capacity());

    let stored = store_conversation_snapshot_with_limits(
        &mut state,
        &config,
        pin,
        1,
        payload,
        10,
        PRODUCTION_LIMITS,
    )
    .expect("store maximum legal snapshot");
    let observation = probe.finish();

    assert!(
        observation.peak_retained_bytes() <= MAX_BUILD_MEMORY_BYTES,
        "snapshot store retained {} bytes, above the {}-byte build cap",
        observation.peak_retained_bytes(),
        MAX_BUILD_MEMORY_BYTES,
    );
    drop(stored);
    drop(state);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn maximum_snapshot_replacement_stays_within_build_memory_cap() {
    const MAX_BUILD_MEMORY_BYTES: usize = 128 * 1024 * 1024;

    let (root, config, mut state) = open_test_state("maximum-replacement-peak");
    let conversation_id = create_directory_conversation(&mut state, &config, 0x84);
    let first_pin = super::super::stream::acquire_snapshot_build_pin(&state, conversation_id, 10)
        .expect("capture initial maximum snapshot pin");
    let mut first_payload = Vec::with_capacity(MAX_SNAPSHOT_BYTES + ROW_BLOB_V1_OVERHEAD_LEN);
    first_payload.resize(MAX_SNAPSHOT_BYTES, 0x41);
    drop(
        store_conversation_snapshot_with_limits(
            &mut state,
            &config,
            first_pin,
            1,
            first_payload,
            10,
            PRODUCTION_LIMITS,
        )
        .expect("store initial maximum snapshot"),
    );
    let replacement_pin =
        super::super::stream::acquire_snapshot_build_pin(&state, conversation_id, 11)
            .expect("capture maximum replacement pin");
    let mut replacement_payload = Vec::with_capacity(MAX_SNAPSHOT_BYTES + ROW_BLOB_V1_OVERHEAD_LEN);
    replacement_payload.resize(MAX_SNAPSHOT_BYTES, 0x42);
    begin_snapshot_read_allocation_probe_with_retained(replacement_payload.capacity());

    let stored = store_conversation_snapshot_with_limits(
        &mut state,
        &config,
        replacement_pin,
        1,
        replacement_payload,
        11,
        PRODUCTION_LIMITS,
    )
    .expect("replace maximum legal snapshot");
    let observation = finish_snapshot_read_allocation_probe();

    assert!(
        observation.peak_retained_bytes <= MAX_BUILD_MEMORY_BYTES,
        "maximum replacement retained {} bytes, above the {}-byte build cap",
        observation.peak_retained_bytes,
        MAX_BUILD_MEMORY_BYTES,
    );
    drop(stored);
    drop(state);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn maximum_snapshot_exact_replay_stays_within_build_memory_cap() {
    const MAX_BUILD_MEMORY_BYTES: usize = 128 * 1024 * 1024;

    let (root, config, mut state) = open_test_state("maximum-exact-replay-peak");
    let conversation_id = create_directory_conversation(&mut state, &config, 0x85);
    let first_pin = super::super::stream::acquire_snapshot_build_pin(&state, conversation_id, 10)
        .expect("capture initial exact snapshot pin");
    let mut first_payload = Vec::with_capacity(MAX_SNAPSHOT_BYTES + ROW_BLOB_V1_OVERHEAD_LEN);
    first_payload.resize(MAX_SNAPSHOT_BYTES, 0x43);
    drop(
        store_conversation_snapshot_with_limits(
            &mut state,
            &config,
            first_pin,
            1,
            first_payload,
            10,
            PRODUCTION_LIMITS,
        )
        .expect("store initial exact maximum snapshot"),
    );
    let replay_pin = super::super::stream::acquire_snapshot_build_pin(&state, conversation_id, 11)
        .expect("capture maximum exact replay pin");
    let mut replay_payload = Vec::with_capacity(MAX_SNAPSHOT_BYTES + ROW_BLOB_V1_OVERHEAD_LEN);
    replay_payload.resize(MAX_SNAPSHOT_BYTES, 0x43);
    begin_snapshot_read_allocation_probe_with_retained(replay_payload.capacity());

    let replayed = store_conversation_snapshot_with_limits(
        &mut state,
        &config,
        replay_pin,
        1,
        replay_payload,
        11,
        PRODUCTION_LIMITS,
    )
    .expect("replay maximum legal snapshot");
    let observation = finish_snapshot_read_allocation_probe();

    assert!(
        observation.peak_retained_bytes <= MAX_BUILD_MEMORY_BYTES,
        "maximum exact replay retained {} bytes, above the {}-byte build cap",
        observation.peak_retained_bytes,
        MAX_BUILD_MEMORY_BYTES,
    );
    drop(replayed);
    drop(state);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn maximum_snapshot_ready_open_stays_within_read_memory_cap() {
    const MAX_READ_MEMORY_BYTES: usize = 128 * 1024 * 1024;

    let (root, config, mut state) = open_test_state("maximum-ready-open-peak");
    let conversation_id = create_directory_conversation(&mut state, &config, 0x82);
    let pin = super::super::stream::acquire_snapshot_build_pin(&state, conversation_id, 10)
        .expect("capture maximum ready snapshot pin");
    let mut payload = Vec::with_capacity(MAX_SNAPSHOT_BYTES + ROW_BLOB_V1_OVERHEAD_LEN);
    payload.resize(MAX_SNAPSHOT_BYTES, 0x6b);
    drop(
        store_conversation_snapshot_with_limits(
            &mut state,
            &config,
            pin,
            1,
            payload,
            10,
            PRODUCTION_LIMITS,
        )
        .expect("store maximum ready snapshot"),
    );
    let read_crypto = state.key_bundle.read_only_capability();
    begin_snapshot_read_allocation_probe();

    let loaded = load_snapshot_row_read(
        &state.connection,
        &read_crypto,
        state.database_id,
        conversation_id,
    )
    .expect("open maximum ready snapshot")
    .expect("maximum ready snapshot exists");
    let observation = finish_snapshot_read_allocation_probe();

    assert_eq!(loaded.payload.len(), MAX_SNAPSHOT_BYTES);
    assert!(
        observation.peak_retained_bytes <= MAX_READ_MEMORY_BYTES,
        "snapshot ready open retained {} bytes, above the {}-byte read cap",
        observation.peak_retained_bytes,
        MAX_READ_MEMORY_BYTES,
    );
    drop(loaded);
    drop(state);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn oversized_snapshot_blob_is_rejected_before_materialization() {
    let (root, config, mut state) = open_test_state("oversized-blob-preflight");
    let conversation_id = create_directory_conversation(&mut state, &config, 0x83);
    let pin = super::super::stream::acquire_snapshot_build_pin(&state, conversation_id, 10)
        .expect("capture oversized fixture snapshot pin");
    drop(
        store_conversation_snapshot_with_limits(
            &mut state,
            &config,
            pin,
            1,
            vec![0x7c; 4],
            10,
            PRODUCTION_LIMITS,
        )
        .expect("store small authenticated snapshot"),
    );
    state
        .connection
        .execute_batch("PRAGMA ignore_check_constraints = ON")
        .expect("enable corruption fixture CHECK bypass");
    let oversized_blob_bytes =
        i64::try_from(MAX_SNAPSHOT_BYTES + super::super::cipher::ROW_BLOB_V1_HEADER_LEN + 1024)
            .expect("oversized blob length fits SQLite");
    assert_eq!(
        state
            .connection
            .execute(
                "UPDATE snapshots SET sealed_snapshot = zeroblob(?1)
                     WHERE target_scope = 'conversation' AND conversation_id = ?2",
                rusqlite::params![oversized_blob_bytes, &conversation_id.as_bytes()[..]],
            )
            .expect("install oversized snapshot BLOB"),
        1
    );
    let read_crypto = state.key_bundle.read_only_capability();
    begin_snapshot_read_allocation_probe();

    let error = load_snapshot_row_read(
        &state.connection,
        &read_crypto,
        state.database_id,
        conversation_id,
    )
    .expect_err("oversized persisted BLOB must fail before AEAD open");
    let observation = finish_snapshot_read_allocation_probe();

    assert!(matches!(
        error,
        RuntimeStoreError::Cipher(super::super::cipher::CipherError::InputTooLarge)
    ));
    assert_eq!(
        observation.materialized_blob_bytes, 0,
        "oversized BLOB was materialized before its length gate"
    );
    drop(state);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn reopen_rejects_oversized_conversation_blob_before_materialization() {
    let root = std::env::temp_dir().join(format!(
        "agentdeck-snapshot-reopen-conversation-{}-{}",
        std::process::id(),
        NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir(&root).expect("create reopen conversation root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .expect("secure reopen conversation root");
    }
    let config = RuntimeStoreConfig::new(root.join("runtime.db"));
    let keys = MemoryKeyStore::new();
    let kek = load_or_create_storage_kek(&keys, &root.join("key-state.db"))
        .expect("create reopen conversation KEK");
    let mut state = super::super::sqlite::open(&config, kek).expect("open conversation store");
    let conversation_id = create_directory_conversation(&mut state, &config, 0x86);
    let pin = super::super::stream::acquire_snapshot_build_pin(&state, conversation_id, 10)
        .expect("capture reopen conversation pin");
    drop(
        store_conversation_snapshot_with_limits(
            &mut state,
            &config,
            pin,
            1,
            vec![0x44; 4],
            10,
            PRODUCTION_LIMITS,
        )
        .expect("store reopen conversation snapshot"),
    );
    drop(state);
    let connection = rusqlite::Connection::open(config.storage_path.as_path())
        .expect("open conversation corruption connection");
    connection
        .execute_batch("PRAGMA ignore_check_constraints = ON")
        .expect("enable conversation CHECK bypass");
    let oversized_blob_bytes = i64::try_from(MAX_SNAPSHOT_BYTES + ROW_BLOB_V1_OVERHEAD_LEN + 1024)
        .expect("oversized conversation length fits SQLite");
    connection
        .execute(
            "UPDATE snapshots SET sealed_snapshot = zeroblob(?1)
                 WHERE target_scope = 'conversation' AND conversation_id = ?2",
            params![oversized_blob_bytes, &conversation_id.as_bytes()[..]],
        )
        .expect("install oversized conversation BLOB");
    drop(connection);
    let kek = load_or_create_storage_kek(&keys, &root.join("key-state.db"))
        .expect("reload reopen conversation KEK");
    begin_snapshot_read_allocation_probe();

    let error = match super::super::sqlite::open(&config, kek) {
        Ok(_) => panic!("oversized conversation BLOB cannot reopen"),
        Err(error) => error,
    };
    let observation = finish_snapshot_read_allocation_probe();

    assert!(matches!(
        error,
        RuntimeStoreError::Cipher(super::super::cipher::CipherError::InputTooLarge)
    ));
    assert_eq!(
        observation.materialized_blob_bytes, 0,
        "reopen materialized oversized conversation BLOB before its length gate"
    );
    let _ = fs::remove_dir_all(root);
}

#[test]
fn reopen_rejects_oversized_catalog_blob_before_materialization() {
    let root = std::env::temp_dir().join(format!(
        "agentdeck-snapshot-reopen-catalog-{}-{}",
        std::process::id(),
        NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir(&root).expect("create reopen catalog root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .expect("secure reopen catalog root");
    }
    let config = RuntimeStoreConfig::new(root.join("runtime.db"));
    let keys = MemoryKeyStore::new();
    let kek = load_or_create_storage_kek(&keys, &root.join("key-state.db"))
        .expect("create reopen catalog KEK");
    let mut state = super::super::sqlite::open(&config, kek).expect("open catalog store");
    create_directory_conversation(&mut state, &config, 0x87);
    let ledger = super::super::sqlite::load_runtime_ledger(
        &state.connection,
        &state.key_bundle,
        state.database_id,
    )
    .expect("load catalog fixture ledger");
    let key_bundle = std::sync::Arc::clone(&state.key_bundle);
    let database_id = state.database_id;
    let transaction = state
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .expect("begin catalog baseline transaction");
    let mut next = ledger.clone();
    migrate_catalog_snapshot_baseline(&transaction, &key_bundle, database_id, &mut next)
        .expect("store catalog snapshot baseline");
    let _ = super::super::sqlite::update_runtime_ledger(
        &transaction,
        &key_bundle,
        database_id,
        &ledger,
        &next,
    )
    .expect("publish catalog snapshot ledger");
    transaction
        .commit()
        .expect("commit catalog snapshot baseline");
    drop(state);
    let connection = rusqlite::Connection::open(config.storage_path.as_path())
        .expect("open catalog corruption connection");
    connection
        .execute_batch("PRAGMA ignore_check_constraints = ON")
        .expect("enable catalog CHECK bypass");
    let oversized_blob_bytes = i64::try_from(MAX_SNAPSHOT_BYTES + ROW_BLOB_V1_OVERHEAD_LEN + 1024)
        .expect("oversized catalog length fits SQLite");
    connection
        .execute(
            "UPDATE snapshots SET sealed_snapshot = zeroblob(?1)
                 WHERE target_scope = 'catalog' AND conversation_id IS NULL",
            [oversized_blob_bytes],
        )
        .expect("install oversized catalog BLOB");
    drop(connection);
    let kek = load_or_create_storage_kek(&keys, &root.join("key-state.db"))
        .expect("reload reopen catalog KEK");
    begin_snapshot_read_allocation_probe();

    let error = match super::super::sqlite::open(&config, kek) {
        Ok(_) => panic!("oversized catalog BLOB cannot reopen"),
        Err(error) => error,
    };
    let observation = finish_snapshot_read_allocation_probe();

    assert!(matches!(
        error,
        RuntimeStoreError::Cipher(super::super::cipher::CipherError::InputTooLarge)
    ));
    assert_eq!(
        observation.materialized_blob_bytes, 0,
        "reopen materialized oversized catalog BLOB before its length gate"
    );
    let _ = fs::remove_dir_all(root);
}
