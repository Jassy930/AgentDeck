//! Runtime SQLite 的安全打开、schema inspection、migration 与 PRAGMA 读回。

use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use rusqlite::limits::Limit;
use rusqlite::{
    Connection, DropBehavior, OpenFlags, OptionalExtension, Transaction, TransactionBehavior,
    params,
};

use crate::runtime::model::{
    MAX_APPROVAL_DECISION_BYTES, MAX_APPROVAL_REQUEST_BYTES, MAX_APPROVAL_STATUS_DETAIL_BYTES,
    MAX_COMMAND_RESULT_BYTES, MAX_EXECUTION_FENCE_BYTES, MAX_EXECUTION_NONCE_BYTES,
    MAX_RUNTIME_BUSY_TIMEOUT_MS, MAX_RUNTIME_EVENT_BYTES, MAX_RUNTIME_STORE_COMMAND_CAPACITY,
    MachineEnrollmentReceiptRecord, RecoveryCompletion, RecoveryCursor, RuntimeCommitOperation,
    RuntimeStoreConfig, RuntimeStoreError, RuntimeStoreOperation, RuntimeStoreSnapshot,
};
use crate::security::StorageKek;

use super::admission::{
    AdmissionRejection, RUNTIME_DB_HARD_LIMIT_BYTES, RuntimeAdmissionInput, RuntimeAdmissionState,
    RuntimeCapacityObservation, RuntimeCapacityProbe, evaluate_runtime_admission,
    evaluate_runtime_safety_admission, filesystem_reserve_bytes,
};
use super::cipher::{KeyWrapAad, RuntimeKeyBundle, WRAPPED_KEY_BUNDLE_V1_LEN};
use super::schema::{
    EXPECTED_TABLES, EXPECTED_TABLES_V1, EXPECTED_TABLES_V2, EXPECTED_TABLES_V3,
    RUNTIME_CRYPTO_CONTEXT_VERSION, RUNTIME_DDL_V1, RUNTIME_KEY_GENERATION, RUNTIME_MIGRATION_V2,
    RUNTIME_MIGRATION_V3, RUNTIME_MIGRATION_V4, RUNTIME_SCHEMA_FAMILY, RUNTIME_SCHEMA_VERSION,
    schema_signature, schema_signature_v1, schema_signature_v2, schema_signature_v3,
};

const DATABASE_MODE: u32 = 0o600;
const DIRECTORY_MODE: u32 = 0o700;
const SQLITE_LENGTH_LIMIT_BYTES: i32 = 72 * 1024 * 1024;
/// 为 page/WAL 对齐、密文与索引元数据、checkpoint 暂时不可回收留出的固定闭包。
pub(crate) const RUNTIME_WRITE_SAFETY_MARGIN_BYTES: u64 = 1024 * 1024;
const CHECKPOINT_TRIGGER_BYTES: u64 = RUNTIME_DB_HARD_LIMIT_BYTES * 9 / 10;
const WAL_CHECKPOINT_TRIGGER_BYTES: u64 = 64 * 1024 * 1024;
const FIXED_SAFETY_RESERVE_BYTES: u64 = 1024 * 1024;
const ACCEPTED_EXPIRY_RESERVE_BYTES: u64 = 64 * 1024;
const FENCE_RESERVE_BYTES: u64 =
    (MAX_EXECUTION_FENCE_BYTES + MAX_EXECUTION_NONCE_BYTES) as u64 + 1024 * 1024;
const RELEASE_RESERVE_BYTES: u64 = 64 * 1024;
const TERMINAL_RESERVE_BYTES: u64 =
    (MAX_COMMAND_RESULT_BYTES + MAX_RUNTIME_EVENT_BYTES) as u64 + 4 * 1024 * 1024;
/// Approval terminal transition 的 canonical event 不携带原始 request，只携带稳定
/// identity、state、winner decision 与有界 status detail；64 KiB 覆盖其最大编码。
const MAX_APPROVAL_TRANSITION_EVENT_BYTES: u64 = 64 * 1024;
const APPROVAL_TERMINATION_LOGICAL_BYTES: u64 = MAX_APPROVAL_REQUEST_BYTES as u64
    + MAX_APPROVAL_DECISION_BYTES as u64
    + MAX_APPROVAL_STATUS_DETAIL_BYTES as u64
    + MAX_APPROVAL_TRANSITION_EVENT_BYTES;
/// 每个 active approval 固定保留 1 MiB：448 KiB 最大 request/decision/status/event，
/// 剩余 576 KiB 覆盖三段 row ciphertext overhead、SQLite 全行重写、event row、
/// metadata/token、B-tree index 与 WAL/page 对齐闭包。
pub(crate) const MAX_APPROVAL_TERMINATION_RESERVE_BYTES: u64 = 1024 * 1024;
const APPROVAL_TERMINATION_PAGE_INDEX_WAL_CLOSURE_BYTES: u64 =
    MAX_APPROVAL_TERMINATION_RESERVE_BYTES - APPROVAL_TERMINATION_LOGICAL_BYTES;
const _: () = {
    assert!(APPROVAL_TERMINATION_LOGICAL_BYTES == 448 * 1024);
    assert!(APPROVAL_TERMINATION_PAGE_INDEX_WAL_CLOSURE_BYTES == 576 * 1024);
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SafetyReserveProjection {
    Current,
    AcceptCommand,
    StartCommand,
    // Approval journal 在同一 P3.5 阶段接线；先把 reserve projection 固定为 store contract。
    #[allow(dead_code)]
    RegisterApproval,
}

#[cfg(test)]
mod migration_tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    use rusqlite::{Connection, params};

    use super::*;
    use crate::runtime::model::{
        AcceptCommand, AcceptOutcome, ConversationDescriptor, ExecutionFence, IdempotencyOwner,
        MachineEnrollmentReceiptRecord, NewConversation, RuntimeCapacityObservation,
        RuntimeCapacityProbe, RuntimeCapacityProbeError, RuntimeStoreFaultInjector, StartCommand,
    };
    use crate::runtime::store::cipher::RowAad;
    use crate::runtime::store::identity::{RuntimeId, RuntimeIdKind};
    use crate::runtime::store::worker::RuntimeStoreHandle;
    use crate::security::{MemoryKeyStore, SecretBytes, load_or_create_storage_kek};

    static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new(name: &str) -> Self {
            let sequence = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "agentdeckd-runtime-v1-migration-{name}-{}-{sequence}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir(&path).expect("create migration test root");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                    .expect("secure migration test root");
            }
            Self(path)
        }

        fn source(&self) -> PathBuf {
            self.0.join("source-v2.db")
        }

        fn database(&self) -> PathBuf {
            self.0.join("runtime.db")
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn runtime_id(kind: RuntimeIdKind, byte: u8) -> RuntimeId {
        RuntimeId::from_bytes(kind, [byte; 16]).expect("valid stable RuntimeId")
    }

    fn conversation(seed: u8, descriptor: &[u8]) -> NewConversation {
        NewConversation {
            conversation_id: runtime_id(RuntimeIdKind::Conversation, seed),
            adapter_state_key: runtime_id(RuntimeIdKind::AdapterState, seed.wrapping_add(0x20)),
            descriptor: ConversationDescriptor {
                agent_kind: agentdeck_protocol::AgentKind::Codex,
                title: Some(
                    String::from_utf8(descriptor.to_vec()).expect("migration descriptor UTF-8"),
                ),
                cwd: PathBuf::from("/tmp/agentdeck-runtime-migration"),
            },
        }
    }

    fn owner(seed: u8) -> IdempotencyOwner {
        IdempotencyOwner::Local {
            machine_trust_domain: [0x71; 32],
            uid: 501,
            client_installation_id: [seed; 16],
        }
    }

    #[derive(Debug, Eq, PartialEq)]
    struct CipherEvidence {
        wrapped_key_bundle: Vec<u8>,
        descriptors: Vec<Vec<u8>>,
        commands: Vec<Vec<u8>>,
        intents: Vec<Vec<u8>>,
        fences: Vec<Vec<u8>>,
        events: Vec<Vec<u8>>,
        codex_adapter_states: Vec<Vec<u8>>,
        claude_code_adapter_states: Vec<Vec<u8>>,
    }

    fn collect_blobs(connection: &Connection, sql: &str) -> Vec<Vec<u8>> {
        connection
            .prepare(sql)
            .expect("prepare ciphertext evidence query")
            .query_map([], |row| row.get::<_, Vec<u8>>(0))
            .expect("query ciphertext evidence")
            .collect::<Result<Vec<_>, _>>()
            .expect("collect ciphertext evidence")
    }

    fn cipher_evidence(path: &Path) -> CipherEvidence {
        let connection = Connection::open(path).expect("open ciphertext evidence database");
        let has_table = |table: &str| {
            connection
                .query_row(
                    "SELECT EXISTS(
                         SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = ?1
                     )",
                    [table],
                    |row| row.get::<_, bool>(0),
                )
                .expect("inspect ciphertext table")
        };
        CipherEvidence {
            wrapped_key_bundle: connection
                .query_row(
                    "SELECT wrapped_key_bundle FROM runtime_meta WHERE singleton = 1",
                    [],
                    |row| row.get(0),
                )
                .expect("read wrapped key evidence"),
            descriptors: collect_blobs(
                &connection,
                "SELECT sealed_descriptor FROM conversations ORDER BY conversation_id",
            ),
            commands: collect_blobs(
                &connection,
                "SELECT sealed_command FROM commands ORDER BY conversation_id, command_seq",
            ),
            intents: collect_blobs(
                &connection,
                "SELECT sealed_intent FROM execution_intents ORDER BY command_id",
            ),
            fences: collect_blobs(
                &connection,
                "SELECT sealed_fence FROM execution_fences ORDER BY command_id",
            ),
            events: collect_blobs(
                &connection,
                "SELECT sealed_event FROM event_journal ORDER BY conversation_id, event_seq",
            ),
            codex_adapter_states: if has_table("codex_adapter_state") {
                collect_blobs(
                    &connection,
                    "SELECT sealed_state_reference FROM codex_adapter_state ORDER BY conversation_id",
                )
            } else {
                Vec::new()
            },
            claude_code_adapter_states: if has_table("claude_code_adapter_state") {
                collect_blobs(
                    &connection,
                    "SELECT sealed_state_reference FROM claude_code_adapter_state ORDER BY conversation_id",
                )
            } else {
                Vec::new()
            },
        }
    }

    fn artifact_evidence(database: &Path) -> Vec<(PathBuf, Option<Vec<u8>>)> {
        [
            database.to_path_buf(),
            PathBuf::from(format!("{}-wal", database.display())),
            PathBuf::from(format!("{}-shm", database.display())),
            PathBuf::from(format!("{}-journal", database.display())),
        ]
        .into_iter()
        .map(|path| {
            let bytes = match fs::read(&path) {
                Ok(bytes) => Some(bytes),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                Err(error) => panic!("read {}: {error}", path.display()),
            };
            (path, bytes)
        })
        .collect()
    }

    fn replace_first_descriptor_with_authenticated_bytes(
        root: &TestRoot,
        keys: &MemoryKeyStore,
        plaintext: &[u8],
    ) {
        let connection = Connection::open(root.database()).expect("open v1 descriptor fixture");
        let meta = read_meta_v1(&connection)
            .expect("read v1 descriptor meta")
            .expect("v1 descriptor meta exists");
        let storage_kek =
            load_or_create_storage_kek(keys, &root.database()).expect("reload descriptor KEK");
        let key_bundle = RuntimeKeyBundle::unwrap(
            &storage_kek,
            &KeyWrapAad {
                schema_family: RUNTIME_SCHEMA_FAMILY.as_bytes(),
                schema_version: RUNTIME_CRYPTO_CONTEXT_VERSION,
                database_id: &meta.database_id,
            },
            &meta.wrapped_key_bundle,
        )
        .expect("unwrap descriptor row keys");
        let conversation_id: Vec<u8> = connection
            .query_row(
                "SELECT conversation_id FROM conversations ORDER BY conversation_id LIMIT 1",
                [],
                |row| row.get(0),
            )
            .expect("read descriptor conversation id");
        let sealed = key_bundle
            .row_cipher()
            .seal_bounded(
                &RowAad {
                    schema_family: RUNTIME_SCHEMA_FAMILY.as_bytes(),
                    schema_version: RUNTIME_CRYPTO_CONTEXT_VERSION,
                    database_id: &meta.database_id,
                    table: b"conversations",
                    primary_key: &conversation_id,
                    column: b"sealed_descriptor",
                },
                plaintext,
                crate::runtime::model::MAX_CONVERSATION_DESCRIPTOR_BYTES,
            )
            .expect("seal authenticated malformed descriptor");
        connection
            .execute(
                "UPDATE conversations SET sealed_descriptor = ?1 WHERE conversation_id = ?2",
                params![sealed, conversation_id],
            )
            .expect("replace descriptor with authenticated malformed plaintext");
    }

    async fn build_strict_v1_fixture(root: &TestRoot, keys: &MemoryKeyStore) -> CipherEvidence {
        let source = root.source();
        let store = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(source.clone()),
            load_or_create_storage_kek(keys, &source).expect("create migration test KEK"),
        )
        .await
        .expect("open source v2 journal");
        let accepted_conversation = store
            .create_conversation(conversation(0x11, b"legacy accepted descriptor"))
            .await
            .expect("create accepted legacy conversation");
        let started_conversation = store
            .create_conversation(conversation(0x12, b"legacy started descriptor"))
            .await
            .expect("create started legacy conversation");
        store
            .accept_command(AcceptCommand {
                conversation_id: accepted_conversation.conversation_id,
                owner: owner(1),
                idempotency_key: "legacy-accepted".to_owned(),
                payload: b"legacy accepted payload".to_vec(),
            })
            .await
            .expect("persist legacy Accepted command");
        let started_command = match store
            .accept_command(AcceptCommand {
                conversation_id: started_conversation.conversation_id,
                owner: owner(2),
                idempotency_key: "legacy-started".to_owned(),
                payload: b"legacy started payload".to_vec(),
            })
            .await
            .expect("accept command to start")
        {
            AcceptOutcome::Accepted { command, .. } => command,
            AcceptOutcome::Replayed { .. } => panic!("fresh legacy command cannot replay"),
        };
        let daemon_boot_id = runtime_id(RuntimeIdKind::DaemonBoot, 0x41);
        let execution_nonce = b"legacy-execution-nonce".to_vec();
        store
            .mark_started_with_event(StartCommand {
                conversation_id: started_conversation.conversation_id,
                command_id: started_command.command_id,
                daemon_boot_id,
                execution_nonce: execution_nonce.clone(),
                intent_payload: b"legacy intent payload".to_vec(),
                event_payload: b"legacy started event".to_vec(),
            })
            .await
            .expect("persist legacy intent and event");
        store
            .persist_execution_fence(ExecutionFence {
                command_id: started_command.command_id,
                daemon_boot_id,
                execution_nonce,
                process_group_id: 71,
                leader_pid: 72,
                leader_start_time: 73,
                payload: b"legacy fence payload".to_vec(),
            })
            .await
            .expect("persist legacy fence");
        store
            .record_machine_enrollment_receipt(MachineEnrollmentReceiptRecord {
                relay_server_id: [0x81; 16],
                machine_route: [0x82; 16],
                root_fingerprint: [0x83; 32],
            })
            .await
            .expect("persist legacy rescue receipt");
        store
            .codex_adapter_state_vault()
            .bind(
                accepted_conversation.adapter_state_key,
                SecretBytes::new(b"legacy codex state reference".to_vec()),
            )
            .await
            .expect("persist legacy v2 adapter state");
        store.shutdown().await.expect("shutdown source journal");

        let source_connection = Connection::open(&source).expect("open source journal");
        let meta = read_meta(&source_connection)
            .expect("read source meta")
            .expect("source meta exists");
        let storage_kek = load_or_create_storage_kek(keys, &source).expect("reload migration KEK");
        let key_bundle = RuntimeKeyBundle::unwrap(
            &storage_kek,
            &KeyWrapAad {
                schema_family: RUNTIME_SCHEMA_FAMILY.as_bytes(),
                schema_version: RUNTIME_CRYPTO_CONTEXT_VERSION,
                database_id: &meta.database_id,
            },
            &meta.wrapped_key_bundle,
        )
        .expect("unwrap source Runtime keys");
        let legacy_token = runtime_ledger_token_v1(&key_bundle, meta.database_id, &meta.ledger)
            .expect("authenticate frozen v1 ledger");

        let destination = root.database();
        let legacy = Connection::open(&destination).expect("create strict v1 fixture");
        legacy
            .execute_batch(RUNTIME_DDL_V1)
            .expect("create exact v1 schema");
        legacy
            .execute(
                "INSERT INTO runtime_meta (
                     singleton, schema_family, schema_version, schema_signature, database_id,
                     key_generation, wrapped_key_bundle, catalog_high_water,
                     conversation_count, command_count, event_count, intent_count, fence_count,
                     accepted_count, accepted_payload_bytes, started_without_fence_count,
                     started_without_release_count, started_released_count, metadata_token
                 ) VALUES (1, ?1, 1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
                           ?12, ?13, ?14, ?15, ?16, ?17)",
                params![
                    RUNTIME_SCHEMA_FAMILY,
                    &schema_signature_v1()[..],
                    &meta.database_id[..],
                    i64::from(meta.key_generation),
                    &meta.wrapped_key_bundle,
                    meta.ledger.catalog_high_water.as_deref(),
                    i64::try_from(meta.ledger.conversation_count).unwrap(),
                    i64::try_from(meta.ledger.command_count).unwrap(),
                    i64::try_from(meta.ledger.event_count).unwrap(),
                    i64::try_from(meta.ledger.intent_count).unwrap(),
                    i64::try_from(meta.ledger.fence_count).unwrap(),
                    i64::try_from(meta.ledger.accepted_count).unwrap(),
                    i64::try_from(meta.ledger.accepted_payload_bytes).unwrap(),
                    i64::try_from(meta.ledger.started_without_fence_count).unwrap(),
                    i64::try_from(meta.ledger.started_without_release_count).unwrap(),
                    i64::try_from(meta.ledger.started_released_count).unwrap(),
                    &legacy_token[..],
                ],
            )
            .expect("insert authenticated v1 meta");
        let source_path = source.to_string_lossy();
        legacy
            .execute("ATTACH DATABASE ?1 AS source", [source_path.as_ref()])
            .expect("attach source journal");
        for table in [
            "conversations",
            "commands",
            "execution_intents",
            "execution_fences",
            "event_journal",
            "machine_enrollment_receipts",
        ] {
            legacy
                .execute_batch(&format!(
                    "INSERT INTO main.{table} SELECT * FROM source.{table};"
                ))
                .unwrap_or_else(|error| panic!("copy {table} into v1 fixture: {error}"));
        }
        legacy
            .execute_batch("DETACH DATABASE source")
            .expect("detach source journal");
        drop(legacy);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&destination, fs::Permissions::from_mode(0o600))
                .expect("secure v1 fixture");
        }
        cipher_evidence(&destination)
    }

    async fn build_strict_v2_fixture(root: &TestRoot, keys: &MemoryKeyStore) -> CipherEvidence {
        build_strict_v1_fixture(root, keys).await;
        let destination = root.database();
        let connection = Connection::open(&destination).expect("open strict v1 fixture for v2");
        connection
            .execute_batch(RUNTIME_MIGRATION_V2)
            .expect("apply exact v2 migration");
        let source = root.source();
        let source_path = source.to_string_lossy();
        connection
            .execute("ATTACH DATABASE ?1 AS source", [source_path.as_ref()])
            .expect("attach source v3 journal for v2 adapter rows");
        for table in ["codex_adapter_state", "claude_code_adapter_state"] {
            connection
                .execute_batch(&format!(
                    "INSERT INTO main.{table} SELECT * FROM source.{table};"
                ))
                .unwrap_or_else(|error| panic!("copy {table} into v2 fixture: {error}"));
        }
        connection
            .execute_batch("DETACH DATABASE source")
            .expect("detach source v3 journal");

        let mut meta = read_meta_v2(&connection)
            .expect("read strict v2 fixture meta")
            .expect("strict v2 fixture meta exists");
        meta.ledger.codex_adapter_state_count = 1;
        meta.ledger.claude_code_adapter_state_count = 0;
        let storage_kek =
            load_or_create_storage_kek(keys, &destination).expect("reload strict v2 KEK");
        let key_bundle = RuntimeKeyBundle::unwrap(
            &storage_kek,
            &KeyWrapAad {
                schema_family: RUNTIME_SCHEMA_FAMILY.as_bytes(),
                schema_version: RUNTIME_CRYPTO_CONTEXT_VERSION,
                database_id: &meta.database_id,
            },
            &meta.wrapped_key_bundle,
        )
        .expect("unwrap strict v2 key bundle");
        let v2_token = runtime_ledger_token_v2(&key_bundle, meta.database_id, &meta.ledger)
            .expect("authenticate strict v2 ledger");
        connection
            .execute(
                "UPDATE runtime_meta
                 SET schema_version = 2, schema_signature = ?1,
                     codex_adapter_state_count = ?2, claude_code_adapter_state_count = ?3,
                     metadata_token = ?4
                 WHERE singleton = 1 AND schema_version = 1",
                params![
                    &schema_signature_v2()[..],
                    i64::try_from(meta.ledger.codex_adapter_state_count).unwrap(),
                    i64::try_from(meta.ledger.claude_code_adapter_state_count).unwrap(),
                    &v2_token[..],
                ],
            )
            .expect("publish authenticated strict v2 meta");
        drop(connection);
        cipher_evidence(&destination)
    }

    async fn build_strict_v3_fixture(root: &TestRoot, keys: &MemoryKeyStore) -> CipherEvidence {
        build_strict_v2_fixture(root, keys).await;
        let destination = root.database();
        let connection = Connection::open(&destination).expect("open strict v2 fixture for v3");
        connection
            .execute_batch(RUNTIME_MIGRATION_V3)
            .expect("apply exact v3 migration");
        let meta = read_meta_v3(&connection)
            .expect("read strict v3 fixture meta")
            .expect("strict v3 fixture meta exists");
        let storage_kek =
            load_or_create_storage_kek(keys, &destination).expect("reload strict v3 KEK");
        let key_bundle = RuntimeKeyBundle::unwrap(
            &storage_kek,
            &KeyWrapAad {
                schema_family: RUNTIME_SCHEMA_FAMILY.as_bytes(),
                schema_version: RUNTIME_CRYPTO_CONTEXT_VERSION,
                database_id: &meta.database_id,
            },
            &meta.wrapped_key_bundle,
        )
        .expect("unwrap strict v3 key bundle");
        let token = runtime_ledger_token_v3(&key_bundle, meta.database_id, &meta.ledger)
            .expect("authenticate strict v3 ledger");
        connection
            .execute(
                "UPDATE runtime_meta
                 SET schema_version = 3, schema_signature = ?1, metadata_token = ?2
                 WHERE singleton = 1 AND schema_version = 2",
                params![&schema_signature_v3()[..], &token[..]],
            )
            .expect("publish authenticated strict v3 meta");
        drop(connection);
        cipher_evidence(&destination)
    }

    fn assert_ready_catalog_baseline(path: &Path) {
        let connection = Connection::open(path).expect("open migrated catalog baseline");
        let (catalog_high_water, catalog_retention_floor, catalog_delta_count): (
            Option<String>,
            Option<String>,
            i64,
        ) = connection
            .query_row(
                "SELECT catalog_high_water, catalog_retention_floor, catalog_delta_count
                 FROM runtime_meta WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("read migrated catalog retention state");
        assert_eq!(catalog_retention_floor, None);
        assert_eq!(catalog_delta_count, 0);
        let (count, base_cursor, state, conversation_target_count): (
            i64,
            Option<String>,
            String,
            i64,
        ) = connection
            .query_row(
                "SELECT COUNT(*), MIN(base_cursor), MIN(build_state),
                        SUM(CASE WHEN conversation_id IS NOT NULL THEN 1 ELSE 0 END)
                 FROM snapshots WHERE target_scope = 'catalog'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .expect("read catalog snapshot baseline");
        assert_eq!(count, 1);
        assert_eq!(base_cursor, catalog_high_water);
        assert_eq!(state, "ready");
        assert_eq!(conversation_target_count, 0);
        let (ledger_count, ledger_bytes): (i64, i64) = connection
            .query_row(
                "SELECT snapshot_count, snapshot_bytes FROM runtime_meta WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("read migrated snapshot ledger");
        assert_eq!(ledger_count, 1);
        assert!(ledger_bytes > 0);
    }

    #[test]
    fn v3_ledger_token_authenticates_both_approval_totals_without_changing_v2_domain() {
        let key_bundle = RuntimeKeyBundle::fresh(RUNTIME_KEY_GENERATION).expect("fresh test keys");
        let database_id = [0x42; 16];
        let ledger = RuntimeLedger {
            catalog_high_water: None,
            conversation_count: 0,
            command_count: 0,
            event_count: 0,
            intent_count: 0,
            fence_count: 0,
            codex_adapter_state_count: 0,
            claude_code_adapter_state_count: 0,
            approval_count: 0,
            active_approval_count: 0,
            accepted_count: 0,
            accepted_payload_bytes: 0,
            started_without_fence_count: 0,
            started_without_release_count: 0,
            started_released_count: 0,
            ..RuntimeLedger::default()
        };
        let baseline_v3 = runtime_ledger_token_v3(&key_bundle, database_id, &ledger)
            .expect("authenticate baseline v3 ledger");
        let baseline_v2 = runtime_ledger_token_v2(&key_bundle, database_id, &ledger)
            .expect("authenticate baseline v2 ledger");

        let mut approval_changed = ledger.clone();
        approval_changed.approval_count = 2;
        approval_changed.active_approval_count = 1;
        assert_ne!(
            runtime_ledger_token_v3(&key_bundle, database_id, &approval_changed)
                .expect("authenticate changed v3 ledger"),
            baseline_v3
        );
        assert_eq!(
            runtime_ledger_token_v2(&key_bundle, database_id, &approval_changed)
                .expect("authenticate legacy v2 projection"),
            baseline_v2,
            "legacy v2 token ignores approval fields and is only used while authenticating migration"
        );
    }

    #[test]
    fn v4_ledger_token_authenticates_every_stream_count_bytes_and_floor() {
        let key_bundle = RuntimeKeyBundle::fresh(RUNTIME_KEY_GENERATION).expect("fresh test keys");
        let database_id = [0x43; 16];
        let ledger = RuntimeLedger::default();
        let baseline = runtime_ledger_token(&key_bundle, database_id, &ledger)
            .expect("authenticate baseline v4 ledger");
        let mut variants = Vec::new();
        let mut changed = ledger.clone();
        changed.audit_event_logical_bytes = 1;
        variants.push(changed);
        let mut changed = ledger.clone();
        changed.event_stream_count = 1;
        variants.push(changed);
        let mut changed = ledger.clone();
        changed.event_stream_bytes = 1;
        variants.push(changed);
        let mut changed = ledger.clone();
        changed.catalog_delta_count = 1;
        variants.push(changed);
        let mut changed = ledger.clone();
        changed.catalog_delta_bytes = 1;
        variants.push(changed);
        let mut changed = ledger.clone();
        changed.catalog_retention_floor = Some(super::super::sequence::encode_sequence(0));
        variants.push(changed);
        let mut changed = ledger.clone();
        changed.snapshot_count = 1;
        variants.push(changed);
        let mut changed = ledger.clone();
        changed.snapshot_bytes = 1;
        variants.push(changed);
        let mut changed = ledger.clone();
        changed.publication_stream_count = 1;
        variants.push(changed);
        let mut changed = ledger.clone();
        changed.publication_outbox_count = 1;
        variants.push(changed);
        let mut changed = ledger;
        changed.publication_outbox_bytes = 1;
        variants.push(changed);
        for changed in variants {
            assert_ne!(
                runtime_ledger_token(&key_bundle, database_id, &changed)
                    .expect("authenticate changed v4 ledger"),
                baseline
            );
        }
    }

    #[tokio::test]
    async fn strict_v1_migrates_without_rewrapping_or_reencrypting_existing_rows() {
        let root = TestRoot::new("full");
        let keys = MemoryKeyStore::new();
        let before = build_strict_v1_fixture(&root, &keys).await;
        assert_eq!(before.descriptors.len(), 2);
        assert_eq!(before.commands.len(), 2);
        assert_eq!(before.intents.len(), 1);
        assert_eq!(before.fences.len(), 1);
        assert_eq!(before.events.len(), 1);
        assert_eq!(
            read_rescue_index(&root.database()).expect("read v1 rescue locator without KEK"),
            vec![MachineEnrollmentReceiptRecord {
                relay_server_id: [0x81; 16],
                machine_route: [0x82; 16],
                root_fingerprint: [0x83; 32],
            }]
        );

        let store = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.database()),
            load_or_create_storage_kek(&keys, &root.database()).expect("reload v1 KEK"),
        )
        .await
        .expect("migrate strict v1 fixture");
        let migrated_snapshot = store.inspect().await.expect("inspect migrated schema");
        assert_eq!(migrated_snapshot.schema_version, RUNTIME_SCHEMA_VERSION);
        assert_eq!(migrated_snapshot.journal_mode.to_ascii_lowercase(), "wal");
        let mut cursor = store
            .begin_recovery_scan()
            .await
            .expect("begin migrated recovery");
        let mut accepted_seen = false;
        let mut started_seen = false;
        let completion = loop {
            let page = store
                .load_recovery_page(cursor.clone())
                .await
                .expect("load migrated recovery page");
            if let Some(record) = page.conversation {
                accepted_seen |= record
                    .accepted
                    .iter()
                    .any(|command| command.payload == b"legacy accepted payload");
                if let Some(started) = record.started {
                    started_seen = started.command.payload == b"legacy started payload"
                        && started.intent.payload == b"legacy intent payload"
                        && started.event.payload == b"legacy started event"
                        && started
                            .fence
                            .is_some_and(|fence| fence.payload == b"legacy fence payload");
                }
            }
            match (page.next_cursor, page.completion) {
                (Some(next), None) => cursor = next,
                (None, Some(completion)) => break completion,
                _ => panic!("recovery page cursor contract"),
            }
        };
        assert!(accepted_seen);
        assert!(started_seen);
        store
            .finish_recovery_scan(completion)
            .await
            .expect("finish migrated recovery");
        store.shutdown().await.expect("shutdown migrated store");
        let artifacts = artifact_evidence(&root.database());
        assert!(
            artifacts[1].1.is_some(),
            "successful migration must leave the persistent WAL artifact"
        );
        assert!(
            artifacts[3].1.is_none(),
            "successful migration must not leave a rollback journal"
        );
        let after = cipher_evidence(&root.database());
        assert_eq!(
            after, before,
            "migration must not rewrite key bundle or rows"
        );
        assert_ready_catalog_baseline(&root.database());
    }

    #[tokio::test]
    async fn strict_v2_migrates_after_authenticating_adapter_rows_without_rewriting_ciphertext() {
        let root = TestRoot::new("v2-full");
        let keys = MemoryKeyStore::new();
        let before = build_strict_v2_fixture(&root, &keys).await;
        assert_eq!(before.codex_adapter_states.len(), 1);

        let store = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.database()),
            load_or_create_storage_kek(&keys, &root.database()).expect("reload v2 KEK"),
        )
        .await
        .expect("migrate strict v2 fixture");
        let snapshot = store.inspect().await.expect("inspect migrated v2 schema");
        assert_eq!(snapshot.schema_version, 4);
        assert_eq!(snapshot.table_names, EXPECTED_TABLES);
        store.shutdown().await.expect("shutdown migrated v2 store");

        assert_eq!(cipher_evidence(&root.database()), before);
        assert_ready_catalog_baseline(&root.database());
        let connection = Connection::open(root.database()).expect("inspect migrated v3 meta");
        let (approval_count, active_approval_count): (i64, i64) = connection
            .query_row(
                "SELECT approval_count, active_approval_count
                 FROM runtime_meta WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("read migrated approval totals");
        assert_eq!((approval_count, active_approval_count), (0, 0));
    }

    #[tokio::test]
    async fn strict_v3_migrates_to_v4_without_rewrapping_or_reencrypting_existing_rows() {
        let root = TestRoot::new("v3-full");
        let keys = MemoryKeyStore::new();
        let before = build_strict_v3_fixture(&root, &keys).await;
        assert_eq!(
            read_rescue_index(&root.database()).expect("read strict v3 rescue locator"),
            vec![MachineEnrollmentReceiptRecord {
                relay_server_id: [0x81; 16],
                machine_route: [0x82; 16],
                root_fingerprint: [0x83; 32],
            }]
        );
        let store = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.database()),
            load_or_create_storage_kek(&keys, &root.database()).expect("reload v3 KEK"),
        )
        .await
        .expect("migrate strict v3 fixture");
        assert_eq!(
            store
                .inspect()
                .await
                .expect("inspect migrated v3")
                .schema_version,
            4
        );
        store.shutdown().await.expect("shutdown migrated v3 store");
        assert_eq!(cipher_evidence(&root.database()), before);
        assert_ready_catalog_baseline(&root.database());
    }

    #[tokio::test]
    async fn corrupt_authenticated_v2_adapter_payload_is_rejected_before_migration() {
        let root = TestRoot::new("v2-corrupt-adapter");
        let keys = MemoryKeyStore::new();
        build_strict_v2_fixture(&root, &keys).await;
        let connection = Connection::open(root.database()).expect("open v2 adapter tamper fixture");
        connection
            .execute(
                "UPDATE codex_adapter_state
                 SET sealed_state_reference = zeroblob(length(sealed_state_reference))",
                [],
            )
            .expect("tamper v2 adapter ciphertext");
        drop(connection);
        let artifacts_before = artifact_evidence(&root.database());

        RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.database()),
            load_or_create_storage_kek(&keys, &root.database()).expect("reload tampered v2 KEK"),
        )
        .await
        .expect_err("corrupt v2 adapter state must fail before migration");
        assert_eq!(artifact_evidence(&root.database()), artifacts_before);
        let legacy = Connection::open(root.database()).expect("inspect rejected v2 fixture");
        let version: i64 = legacy
            .query_row(
                "SELECT schema_version FROM runtime_meta WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .expect("read rejected v2 version");
        assert_eq!(version, 2);
        assert_eq!(
            table_names(&legacy).expect("read rejected v2 manifest"),
            EXPECTED_TABLES_V2
        );
    }

    struct FailMigrationAfterCommit {
        failed: AtomicBool,
    }

    struct FailMigrationBeforeCommit {
        failed: AtomicBool,
    }

    struct MigrationLowDisk;

    impl RuntimeCapacityProbe for MigrationLowDisk {
        fn observe(
            &self,
            _database_path: &Path,
        ) -> Result<RuntimeCapacityObservation, RuntimeCapacityProbeError> {
            Ok(RuntimeCapacityObservation {
                main_bytes: 1024 * 1024,
                wal_bytes: 0,
                shm_bytes: 0,
                filesystem_total_bytes: 4 * 1024 * 1024 * 1024,
                filesystem_available_bytes: 1,
            })
        }
    }

    #[tokio::test]
    async fn migration_capacity_rejection_leaves_the_exact_v1_database_untouched() {
        let root = TestRoot::new("capacity");
        let keys = MemoryKeyStore::new();
        let cipher_before = build_strict_v1_fixture(&root, &keys).await;
        let artifacts_before = artifact_evidence(&root.database());
        let error = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.database()).with_capacity_probe(MigrationLowDisk),
            load_or_create_storage_kek(&keys, &root.database()).expect("reload v1 KEK"),
        )
        .await
        .expect_err("migration must pass capacity admission before DDL");
        assert!(matches!(error, RuntimeStoreError::DiskLow { .. }));
        assert_eq!(
            artifact_evidence(&root.database()),
            artifacts_before,
            "capacity rejection must not rewrite main or create/change WAL/SHM"
        );
        let legacy = Connection::open(root.database()).expect("inspect capacity-rejected v1");
        assert_eq!(
            table_names(&legacy).expect("read capacity-rejected manifest"),
            EXPECTED_TABLES_V1
        );
        drop(legacy);
        assert_eq!(cipher_evidence(&root.database()), cipher_before);
    }

    impl RuntimeStoreFaultInjector for FailMigrationBeforeCommit {
        fn before_operation(
            &self,
            operation: RuntimeStoreOperation,
        ) -> Result<(), RuntimeStoreError> {
            if operation == RuntimeStoreOperation::MigrateSchemaBeforeCommit
                && !self.failed.swap(true, Ordering::SeqCst)
            {
                return Err(RuntimeStoreError::WorkerStopped);
            }
            Ok(())
        }
    }

    #[tokio::test]
    async fn migration_before_commit_fault_rolls_back_to_exact_v1_then_retries_cleanly() {
        let root = TestRoot::new("before-commit");
        let keys = MemoryKeyStore::new();
        let before = build_strict_v1_fixture(&root, &keys).await;
        let artifacts_before = artifact_evidence(&root.database());
        let error = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.database()).with_fault_injector(Arc::new(
                FailMigrationBeforeCommit {
                    failed: AtomicBool::new(false),
                },
            )),
            load_or_create_storage_kek(&keys, &root.database()).expect("reload v1 KEK"),
        )
        .await
        .expect_err("before-commit hook must abort migration");
        assert!(matches!(error, RuntimeStoreError::WorkerStopped));
        assert_eq!(
            artifact_evidence(&root.database()),
            artifacts_before,
            "before-COMMIT rollback must restore main/WAL/SHM/journal exactly"
        );
        let legacy = Connection::open(root.database()).expect("inspect rolled back v1");
        let version: i64 = legacy
            .query_row(
                "SELECT schema_version FROM runtime_meta WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .expect("read rolled back schema version");
        assert_eq!(version, 1);
        assert_eq!(
            table_names(&legacy).expect("read rolled back table manifest"),
            EXPECTED_TABLES_V1
        );
        drop(legacy);
        assert_eq!(cipher_evidence(&root.database()), before);

        let reopened = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.database()),
            load_or_create_storage_kek(&keys, &root.database()).expect("retry migration KEK"),
        )
        .await
        .expect("retry rolled back migration");
        assert_eq!(
            reopened
                .inspect()
                .await
                .expect("inspect retried migration")
                .schema_version,
            RUNTIME_SCHEMA_VERSION
        );
        reopened
            .shutdown()
            .await
            .expect("shutdown retried migration");
        assert_eq!(cipher_evidence(&root.database()), before);
    }

    #[tokio::test]
    async fn v2_migration_before_commit_fault_rolls_back_then_reopens_to_v3() {
        let root = TestRoot::new("v2-before-commit");
        let keys = MemoryKeyStore::new();
        let before = build_strict_v2_fixture(&root, &keys).await;
        let artifacts_before = artifact_evidence(&root.database());
        let error = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.database()).with_fault_injector(Arc::new(
                FailMigrationBeforeCommit {
                    failed: AtomicBool::new(false),
                },
            )),
            load_or_create_storage_kek(&keys, &root.database()).expect("reload v2 KEK"),
        )
        .await
        .expect_err("before-commit hook must abort v2 migration");
        assert!(matches!(error, RuntimeStoreError::WorkerStopped));
        assert_eq!(artifact_evidence(&root.database()), artifacts_before);
        let legacy = Connection::open(root.database()).expect("inspect rolled back v2");
        assert_eq!(
            table_names(&legacy).expect("read rolled back v2 manifest"),
            EXPECTED_TABLES_V2
        );
        let version: i64 = legacy
            .query_row(
                "SELECT schema_version FROM runtime_meta WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .expect("read rolled back v2 version");
        assert_eq!(version, 2);
        drop(legacy);
        assert_eq!(cipher_evidence(&root.database()), before);

        let reopened = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.database()),
            load_or_create_storage_kek(&keys, &root.database()).expect("retry v2 migration KEK"),
        )
        .await
        .expect("retry rolled back v2 migration");
        assert_eq!(
            reopened
                .inspect()
                .await
                .expect("inspect retried v2 migration")
                .schema_version,
            4
        );
        reopened
            .shutdown()
            .await
            .expect("shutdown retried v2 migration");
        assert_eq!(cipher_evidence(&root.database()), before);
    }

    #[tokio::test]
    async fn corrupt_v1_payload_is_rejected_before_any_schema_migration_write() {
        let root = TestRoot::new("corrupt");
        let keys = MemoryKeyStore::new();
        build_strict_v1_fixture(&root, &keys).await;
        let connection = Connection::open(root.database()).expect("open v1 tamper fixture");
        connection
            .execute(
                "UPDATE conversations
                 SET sealed_descriptor = zeroblob(length(sealed_descriptor))
                 WHERE conversation_id = (SELECT MIN(conversation_id) FROM conversations)",
                [],
            )
            .expect("tamper v1 descriptor");
        connection
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
            .expect("checkpoint v1 tamper");
        drop(connection);
        let tampered = cipher_evidence(&root.database());
        let artifacts_before = artifact_evidence(&root.database());
        RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.database()),
            load_or_create_storage_kek(&keys, &root.database()).expect("reload v1 KEK"),
        )
        .await
        .expect_err("corrupt v1 row must fail before migration");
        assert_eq!(
            artifact_evidence(&root.database()),
            artifacts_before,
            "integrity rejection must not rewrite main or create/change WAL/SHM"
        );
        let legacy = Connection::open(root.database()).expect("inspect rejected corrupt v1");
        assert_eq!(
            table_names(&legacy).expect("read rejected corrupt manifest"),
            EXPECTED_TABLES_V1
        );
        drop(legacy);
        assert_eq!(cipher_evidence(&root.database()), tampered);
    }

    #[tokio::test]
    async fn authenticated_v1_descriptor_with_vendor_identity_is_rejected_before_migration() {
        let root = TestRoot::new("descriptor-shape");
        let keys = MemoryKeyStore::new();
        build_strict_v1_fixture(&root, &keys).await;
        replace_first_descriptor_with_authenticated_bytes(
            &root,
            &keys,
            br#"{"agentKind":"codex","title":"legacy","cwd":"/tmp","threadId":"private"}"#,
        );
        let before = artifact_evidence(&root.database());

        RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.database()),
            load_or_create_storage_kek(&keys, &root.database()).expect("reload v1 KEK"),
        )
        .await
        .expect_err("vendor identity in authenticated descriptor must fail before migration");

        assert_eq!(artifact_evidence(&root.database()), before);
        let legacy = Connection::open(root.database()).expect("inspect rejected v1 descriptor");
        assert_eq!(
            table_names(&legacy).expect("read rejected descriptor manifest"),
            EXPECTED_TABLES_V1
        );
    }

    #[tokio::test]
    async fn wrong_kek_rejects_strict_v1_before_rw_open_or_migration() {
        let root = TestRoot::new("wrong-kek");
        let keys = MemoryKeyStore::new();
        build_strict_v1_fixture(&root, &keys).await;
        let before = artifact_evidence(&root.database());
        let wrong_keys = MemoryKeyStore::new();
        let wrong_namespace = root.0.join("wrong-key-namespace.db");
        let wrong_kek = load_or_create_storage_kek(&wrong_keys, &wrong_namespace)
            .expect("create independent wrong KEK");
        RuntimeStoreHandle::open(RuntimeStoreConfig::new(root.database()), wrong_kek)
            .await
            .expect_err("wrong KEK must reject strict v1 before migration");
        assert_eq!(artifact_evidence(&root.database()), before);
        let legacy = Connection::open(root.database()).expect("inspect wrong-KEK v1");
        assert_eq!(
            table_names(&legacy).expect("read wrong-KEK table manifest"),
            EXPECTED_TABLES_V1
        );
    }

    impl RuntimeStoreFaultInjector for FailMigrationAfterCommit {
        fn before_operation(
            &self,
            operation: RuntimeStoreOperation,
        ) -> Result<(), RuntimeStoreError> {
            if operation == RuntimeStoreOperation::MigrateSchemaAfterCommit
                && !self.failed.swap(true, Ordering::SeqCst)
            {
                return Err(RuntimeStoreError::WorkerStopped);
            }
            Ok(())
        }
    }

    #[tokio::test]
    async fn migration_after_commit_unknown_converges_on_reopen_without_second_rewrite() {
        let root = TestRoot::new("after-commit");
        let keys = MemoryKeyStore::new();
        let before = build_strict_v1_fixture(&root, &keys).await;
        let error = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.database()).with_fault_injector(Arc::new(
                FailMigrationAfterCommit {
                    failed: AtomicBool::new(false),
                },
            )),
            load_or_create_storage_kek(&keys, &root.database()).expect("reload v1 KEK"),
        )
        .await
        .expect_err("after-commit hook must surface unknown migration outcome");
        assert!(matches!(
            error,
            RuntimeStoreError::CommitOutcomeUnknown {
                operation: RuntimeCommitOperation::MigrateSchema
            }
        ));

        let reopened = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.database()),
            load_or_create_storage_kek(&keys, &root.database()).expect("reload migrated KEK"),
        )
        .await
        .expect("reopen committed migration");
        let reopened_snapshot = reopened
            .inspect()
            .await
            .expect("inspect reopened migration");
        assert_eq!(reopened_snapshot.schema_version, RUNTIME_SCHEMA_VERSION);
        assert_eq!(reopened_snapshot.journal_mode.to_ascii_lowercase(), "wal");
        reopened
            .shutdown()
            .await
            .expect("shutdown reopened migration");
        let artifacts = artifact_evidence(&root.database());
        assert!(
            artifacts[1].1.is_some(),
            "reopen must restore persistent WAL"
        );
        assert!(
            artifacts[3].1.is_none(),
            "after-COMMIT reopen must not leave a rollback journal"
        );
        assert_eq!(cipher_evidence(&root.database()), before);
    }

    #[tokio::test]
    async fn v2_migration_after_commit_unknown_converges_on_reopen() {
        let root = TestRoot::new("v2-after-commit");
        let keys = MemoryKeyStore::new();
        let before = build_strict_v2_fixture(&root, &keys).await;
        let error = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.database()).with_fault_injector(Arc::new(
                FailMigrationAfterCommit {
                    failed: AtomicBool::new(false),
                },
            )),
            load_or_create_storage_kek(&keys, &root.database()).expect("reload v2 KEK"),
        )
        .await
        .expect_err("after-commit hook must surface unknown v2 migration outcome");
        assert!(matches!(
            error,
            RuntimeStoreError::CommitOutcomeUnknown {
                operation: RuntimeCommitOperation::MigrateSchema
            }
        ));

        let reopened = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.database()),
            load_or_create_storage_kek(&keys, &root.database()).expect("reload migrated v3 KEK"),
        )
        .await
        .expect("reopen committed v2 migration");
        assert_eq!(
            reopened
                .inspect()
                .await
                .expect("inspect reopened v2 migration")
                .schema_version,
            4
        );
        reopened
            .shutdown()
            .await
            .expect("shutdown reopened v2 migration");
        assert_eq!(cipher_evidence(&root.database()), before);
    }
}

pub(crate) struct RuntimeSqlite {
    pub connection: Connection,
    pub key_bundle: Arc<RuntimeKeyBundle>,
    pub storage_path: PathBuf,
    pub database_id: [u8; 16],
    pub admission_state: RuntimeAdmissionState,
    pub recovery_scan: Option<RecoveryScanState>,
    pub last_finished_recovery: Option<RecoveryCompletion>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct RecoveryScanCounts {
    pub conversations: u64,
    pub accepted_count: u64,
    pub accepted_payload_bytes: u64,
    pub started_without_fence_count: u64,
    pub started_without_release_count: u64,
    pub started_released_count: u64,
}

#[derive(Clone, Debug)]
pub(crate) struct RecoveryScanState {
    pub scan_id: [u8; 16],
    pub replay_through: Option<u64>,
    pub expected_counts: RecoveryScanCounts,
    pub observed_counts: RecoveryScanCounts,
    pub initial_cursor: RecoveryCursor,
    pub next_cursor: Option<RecoveryCursor>,
    pub last_cursor: Option<RecoveryCursor>,
    pub last_next_cursor: Option<RecoveryCursor>,
    pub last_completion: Option<RecoveryCompletion>,
}

struct RescueConnection {
    connection: Option<Connection>,
    temporary_root: Option<PathBuf>,
}

impl RescueConnection {
    fn connection(&self) -> &Connection {
        self.connection
            .as_ref()
            .expect("rescue connection is present until drop")
    }
}

impl Drop for RescueConnection {
    fn drop(&mut self) {
        drop(self.connection.take());
        if let Some(root) = self.temporary_root.take() {
            let _ = fs::remove_dir_all(root);
        }
    }
}

#[derive(Debug)]
struct MetaRow {
    family: String,
    version: u32,
    signature: [u8; 32],
    database_id: [u8; 16],
    key_generation: u32,
    wrapped_key_bundle: Vec<u8>,
    ledger: RuntimeLedger,
    metadata_token: Vec<u8>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct RuntimeLedger {
    pub catalog_high_water: Option<String>,
    pub conversation_count: u64,
    pub command_count: u64,
    pub event_count: u64,
    pub intent_count: u64,
    pub fence_count: u64,
    pub codex_adapter_state_count: u64,
    pub claude_code_adapter_state_count: u64,
    pub approval_count: u64,
    pub active_approval_count: u64,
    pub audit_event_logical_bytes: u64,
    pub event_stream_count: u64,
    pub event_stream_bytes: u64,
    pub catalog_delta_count: u64,
    pub catalog_delta_bytes: u64,
    pub catalog_retention_floor: Option<String>,
    pub snapshot_count: u64,
    pub snapshot_bytes: u64,
    pub publication_stream_count: u64,
    pub publication_outbox_count: u64,
    pub publication_outbox_bytes: u64,
    pub accepted_count: u64,
    pub accepted_payload_bytes: u64,
    pub started_without_fence_count: u64,
    pub started_without_release_count: u64,
    pub started_released_count: u64,
}

enum SchemaState {
    Fresh,
    LegacyV1(MetaRow, StoreFileIdentity),
    LegacyV2(MetaRow, StoreFileIdentity),
    LegacyV3(MetaRow, StoreFileIdentity),
    Current(MetaRow, StoreFileIdentity),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LegacySchemaVersion {
    V1,
    V2,
    V3,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StoreFileIdentity {
    database: ArtifactIdentity,
    wal: Option<ArtifactIdentity>,
    shm: Option<ArtifactIdentity>,
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ArtifactIdentity {
    device: u64,
    inode: u64,
    length: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

#[cfg(not(unix))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ArtifactIdentity {
    length: u64,
}

pub(crate) fn normalize_storage_path(path: &Path) -> Result<PathBuf, RuntimeStoreError> {
    if !path.is_absolute() {
        return Err(RuntimeStoreError::PathNotAbsolute);
    }
    let parent = path.parent().ok_or(RuntimeStoreError::PathNotAbsolute)?;
    let file_name = path.file_name().ok_or(RuntimeStoreError::PathNotAbsolute)?;
    let canonical_parent = fs::canonicalize(parent)?;
    validate_private_directory(&canonical_parent)?;
    Ok(canonical_parent.join(file_name))
}

pub(crate) fn open(
    config: &RuntimeStoreConfig,
    storage_kek: StorageKek,
) -> Result<RuntimeSqlite, RuntimeStoreError> {
    if config.command_capacity == 0 || config.command_capacity > MAX_RUNTIME_STORE_COMMAND_CAPACITY
    {
        return Err(RuntimeStoreError::InvalidConfig(
            "command capacity must be between 1 and 1024",
        ));
    }
    if config.busy_timeout_ms == 0 || config.busy_timeout_ms > MAX_RUNTIME_BUSY_TIMEOUT_MS {
        return Err(RuntimeStoreError::InvalidConfig(
            "busy timeout must be between 1 and 30000 milliseconds",
        ));
    }
    if WRAPPED_KEY_BUNDLE_V1_LEN != 112 {
        return Err(RuntimeStoreError::InvalidConfig(
            "schema and wrapped key bundle length disagree",
        ));
    }

    let storage_path = normalize_storage_path(&config.storage_path)?;
    let state = inspect_schema(&storage_path)?;
    match state {
        SchemaState::Fresh => open_fresh(config, storage_path, &storage_kek),
        SchemaState::LegacyV1(meta, identity) => open_legacy(
            config,
            storage_path,
            &storage_kek,
            meta,
            identity,
            LegacySchemaVersion::V1,
        ),
        SchemaState::LegacyV2(meta, identity) => open_legacy(
            config,
            storage_path,
            &storage_kek,
            meta,
            identity,
            LegacySchemaVersion::V2,
        ),
        SchemaState::LegacyV3(meta, identity) => open_legacy(
            config,
            storage_path,
            &storage_kek,
            meta,
            identity,
            LegacySchemaVersion::V3,
        ),
        SchemaState::Current(meta, identity) => {
            open_current(config, storage_path, &storage_kek, meta, identity)
        }
    }
}

fn open_fresh(
    config: &RuntimeStoreConfig,
    storage_path: PathBuf,
    storage_kek: &StorageKek,
) -> Result<RuntimeSqlite, RuntimeStoreError> {
    // 正式路径直到完整 schema/meta 已提交、文件已 fsync 前都不存在。这样任一
    // 初始化 crash 最多留下私有随机临时文件，不会把半初始化 DB 发布成事实源。
    cleanup_stale_initializers(&storage_path)?;
    let temporary_path = temporary_database_path(&storage_path)?;
    let result = (|| {
        create_database_file(&temporary_path)?;
        let mut connection = open_read_write(&temporary_path)?;
        configure_defensive_limits(&connection)?;
        configure_connection(&connection, config.busy_timeout_ms, false)?;
        let mut database_id = [0_u8; 16];
        getrandom::fill(&mut database_id)
            .map_err(|_| RuntimeStoreError::InvalidConfig("OS entropy unavailable"))?;
        let key_bundle = RuntimeKeyBundle::fresh(RUNTIME_KEY_GENERATION)?;
        let key_context = KeyWrapAad {
            schema_family: RUNTIME_SCHEMA_FAMILY.as_bytes(),
            schema_version: RUNTIME_CRYPTO_CONTEXT_VERSION,
            database_id: &database_id,
        };
        let wrapped = key_bundle.wrap(storage_kek, &key_context)?;
        let signature = schema_signature();
        let ledger = RuntimeLedger {
            catalog_high_water: None,
            conversation_count: 0,
            command_count: 0,
            event_count: 0,
            intent_count: 0,
            fence_count: 0,
            codex_adapter_state_count: 0,
            claude_code_adapter_state_count: 0,
            approval_count: 0,
            active_approval_count: 0,
            accepted_count: 0,
            accepted_payload_bytes: 0,
            started_without_fence_count: 0,
            started_without_release_count: 0,
            started_released_count: 0,
            ..RuntimeLedger::default()
        };
        let metadata_token = runtime_ledger_token(&key_bundle, database_id, &ledger)?;

        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute_batch(RUNTIME_DDL_V1)?;
        transaction.execute_batch(RUNTIME_MIGRATION_V2)?;
        transaction.execute_batch(RUNTIME_MIGRATION_V3)?;
        transaction.execute_batch(RUNTIME_MIGRATION_V4)?;
        transaction.execute(
            "INSERT INTO runtime_meta (
                 singleton, schema_family, schema_version, schema_signature,
                 database_id, key_generation, wrapped_key_bundle, catalog_high_water,
                 conversation_count, command_count, event_count, intent_count, fence_count,
                 codex_adapter_state_count, claude_code_adapter_state_count,
                 approval_count, active_approval_count,
                 accepted_count, accepted_payload_bytes, started_without_fence_count,
                 started_without_release_count, started_released_count, metadata_token
             ) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, NULL,
                       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, ?7)",
            params![
                RUNTIME_SCHEMA_FAMILY,
                i64::from(RUNTIME_SCHEMA_VERSION),
                &signature[..],
                &database_id[..],
                i64::from(RUNTIME_KEY_GENERATION),
                wrapped,
                &metadata_token[..],
            ],
        )?;
        transaction.commit()?;
        if schema_manifest(&connection)? != expected_schema_manifest(RUNTIME_SCHEMA_VERSION)? {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        drop(connection);
        OpenOptions::new()
            .read(true)
            .open(&temporary_path)?
            .sync_all()?;
        validate_database_file(&temporary_path)?;

        config
            .fault_injector
            .before_operation(RuntimeStoreOperation::InitializeBeforePublish)?;
        rename_no_replace(&temporary_path, &storage_path)?;
        sync_parent_directory(&storage_path)?;

        let connection = open_read_write(&storage_path)?;
        configure_connection(&connection, config.busy_timeout_ms, true)?;
        validate_store_files(&storage_path)?;
        super::journal::validate_store_integrity(&connection, &key_bundle, database_id)?;
        snapshot(&connection, config.busy_timeout_ms)?;
        sync_parent_directory(&storage_path)?;
        super::stream::initialize_ephemeral_state(&connection)?;
        Ok(RuntimeSqlite {
            connection,
            key_bundle: Arc::new(key_bundle),
            storage_path: storage_path.clone(),
            database_id,
            admission_state: RuntimeAdmissionState::Normal,
            recovery_scan: None,
            last_finished_recovery: None,
        })
    })();
    if result.is_err() {
        cleanup_temporary_database(&temporary_path);
    }
    result
}

fn open_current(
    config: &RuntimeStoreConfig,
    storage_path: PathBuf,
    storage_kek: &StorageKek,
    inspected: MetaRow,
    inspected_identity: StoreFileIdentity,
) -> Result<RuntimeSqlite, RuntimeStoreError> {
    ensure_store_identity(&storage_path, &inspected_identity)?;
    // 必须先用 immutable inspection 得到的 meta 完成 KEK authentication；错误
    // KEK 绝不能以 RW 模式碰原始 DB，也不能触发 crash WAL 的 SHM 重建。
    let key_context = KeyWrapAad {
        schema_family: RUNTIME_SCHEMA_FAMILY.as_bytes(),
        schema_version: RUNTIME_CRYPTO_CONTEXT_VERSION,
        database_id: &inspected.database_id,
    };
    let key_bundle =
        RuntimeKeyBundle::unwrap(storage_kek, &key_context, &inspected.wrapped_key_bundle)?;
    if key_bundle.generation() != inspected.key_generation {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    verify_runtime_ledger_token(&key_bundle, &inspected)?;

    validate_database_file(&storage_path)?;
    let connection = open_read_write(&storage_path)?;
    let after_open = capture_store_identity(&storage_path)?;
    if after_open.database != inspected_identity.database {
        return Err(RuntimeStoreError::SchemaInspectionRaced);
    }
    configure_defensive_limits(&connection)?;
    let current = read_and_validate_current_schema(&connection)?;
    if !same_meta(&inspected, &current) {
        return Err(RuntimeStoreError::SchemaInspectionRaced);
    }
    // 持久化 PRAGMA（尤其 journal_mode=WAL）只能在 schema/meta 与 KEK
    // authentication 均成功后执行，错误 KEK 路径必须保持零写入。
    configure_connection(&connection, config.busy_timeout_ms, true)?;
    validate_store_files(&storage_path)?;
    super::journal::validate_store_integrity(&connection, &key_bundle, current.database_id)?;
    snapshot(&connection, config.busy_timeout_ms)?;
    super::stream::initialize_ephemeral_state(&connection)?;
    Ok(RuntimeSqlite {
        connection,
        key_bundle: Arc::new(key_bundle),
        storage_path,
        database_id: current.database_id,
        admission_state: RuntimeAdmissionState::Normal,
        recovery_scan: None,
        last_finished_recovery: None,
    })
}

fn open_legacy(
    config: &RuntimeStoreConfig,
    storage_path: PathBuf,
    storage_kek: &StorageKek,
    inspected: MetaRow,
    inspected_identity: StoreFileIdentity,
    legacy_version: LegacySchemaVersion,
) -> Result<RuntimeSqlite, RuntimeStoreError> {
    ensure_store_identity(&storage_path, &inspected_identity)?;
    let key_context = KeyWrapAad {
        schema_family: RUNTIME_SCHEMA_FAMILY.as_bytes(),
        schema_version: RUNTIME_CRYPTO_CONTEXT_VERSION,
        database_id: &inspected.database_id,
    };
    let key_bundle =
        RuntimeKeyBundle::unwrap(storage_kek, &key_context, &inspected.wrapped_key_bundle)?;
    if key_bundle.generation() != inspected.key_generation {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    match legacy_version {
        LegacySchemaVersion::V1 => verify_runtime_ledger_token_v1(&key_bundle, &inspected)?,
        LegacySchemaVersion::V2 => verify_runtime_ledger_token_v2(&key_bundle, &inspected)?,
        LegacySchemaVersion::V3 => verify_runtime_ledger_token_v3(&key_bundle, &inspected)?,
    }

    validate_database_file(&storage_path)?;
    let mut connection = open_read_write(&storage_path)?;
    let after_open = capture_store_identity(&storage_path)?;
    if after_open.database != inspected_identity.database {
        return Err(RuntimeStoreError::SchemaInspectionRaced);
    }
    configure_defensive_limits(&connection)?;
    let current = match legacy_version {
        LegacySchemaVersion::V1 => read_and_validate_legacy_v1_schema(&connection)?,
        LegacySchemaVersion::V2 => read_and_validate_legacy_v2_schema(&connection)?,
        LegacySchemaVersion::V3 => read_and_validate_legacy_v3_schema(&connection)?,
    };
    if !same_meta(&inspected, &current) {
        return Err(RuntimeStoreError::SchemaInspectionRaced);
    }
    validate_store_files(&storage_path)?;
    // migration 前先用旧版 authenticated ledger 与 stable crypto context 完整认证既有行；
    // corrupt legacy DB 不得被“升级”成可识别的新 schema。
    match legacy_version {
        LegacySchemaVersion::V1 => super::journal::validate_store_integrity_v1(
            &connection,
            &key_bundle,
            current.database_id,
            &current.ledger,
        )?,
        LegacySchemaVersion::V2 | LegacySchemaVersion::V3 => {
            super::journal::validate_store_integrity(
                &connection,
                &key_bundle,
                current.database_id,
            )?;
        }
    }

    let migration_reserve = safety_reserve_bytes_for_ledger(&current.ledger)?
        .checked_add(RUNTIME_WRITE_SAFETY_MARGIN_BYTES)
        .ok_or(RuntimeStoreError::CapacityArithmeticOverflow {
            field: "migration_safety_reserve_bytes",
        })?;
    // migration 的所有拒绝门禁必须先于 journal_mode/max_page_count 等持久化
    // PRAGMA。这里用当前只读 page_size/page_count 与最终目标 page limit 做纯
    // admission；v1 migration 不执行 checkpoint，避免在返回 capacity error 前
    // 改写 main/WAL/SHM。
    let migration_projection = super::stream::migration_projection_bytes(&connection)?;
    evaluate_migration_capacity_before_wal(
        &connection,
        &storage_path,
        config.capacity_probe.as_ref(),
        migration_projection,
        migration_reserve,
    )?;
    configure_migration_connection(&connection, config.busy_timeout_ms)?;
    let old_signature = match legacy_version {
        LegacySchemaVersion::V1 => schema_signature_v1(),
        LegacySchemaVersion::V2 => schema_signature_v2(),
        LegacySchemaVersion::V3 => schema_signature_v3(),
    };
    let new_signature = schema_signature();
    let old_token = match legacy_version {
        LegacySchemaVersion::V1 => {
            runtime_ledger_token_v1(&key_bundle, current.database_id, &current.ledger)?
        }
        LegacySchemaVersion::V2 => {
            runtime_ledger_token_v2(&key_bundle, current.database_id, &current.ledger)?
        }
        LegacySchemaVersion::V3 => {
            runtime_ledger_token_v3(&key_bundle, current.database_id, &current.ledger)?
        }
    };
    let mut transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if legacy_version == LegacySchemaVersion::V1 {
        transaction.execute_batch(RUNTIME_MIGRATION_V2)?;
    }
    if matches!(
        legacy_version,
        LegacySchemaVersion::V1 | LegacySchemaVersion::V2
    ) {
        transaction.execute_batch(RUNTIME_MIGRATION_V3)?;
    }
    transaction.execute_batch(RUNTIME_MIGRATION_V4)?;
    let migrated_ledger = super::stream::migrate_v4_rows(
        &transaction,
        &key_bundle,
        current.database_id,
        &current.ledger,
    )?;
    let new_token = runtime_ledger_token(&key_bundle, current.database_id, &migrated_ledger)?;
    if transaction.execute(
        "UPDATE runtime_meta
         SET schema_version = ?1, schema_signature = ?2,
             codex_adapter_state_count = ?3, claude_code_adapter_state_count = ?4,
             approval_count = ?5, active_approval_count = ?6,
             audit_event_logical_bytes = ?7,
             event_stream_count = ?8, event_stream_bytes = ?9,
             catalog_delta_count = ?10, catalog_delta_bytes = ?11,
             catalog_retention_floor = ?12,
             snapshot_count = ?13, snapshot_bytes = ?14,
             publication_stream_count = ?15,
             publication_outbox_count = ?16, publication_outbox_bytes = ?17,
             metadata_token = ?18
         WHERE singleton = 1 AND schema_version = ?19 AND schema_signature = ?20
           AND metadata_token = ?21",
        params![
            i64::from(RUNTIME_SCHEMA_VERSION),
            &new_signature[..],
            i64::try_from(current.ledger.codex_adapter_state_count)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            i64::try_from(current.ledger.claude_code_adapter_state_count)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            i64::try_from(migrated_ledger.approval_count)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            i64::try_from(migrated_ledger.active_approval_count)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            i64::try_from(migrated_ledger.audit_event_logical_bytes)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            i64::try_from(migrated_ledger.event_stream_count)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            i64::try_from(migrated_ledger.event_stream_bytes)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            i64::try_from(migrated_ledger.catalog_delta_count)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            i64::try_from(migrated_ledger.catalog_delta_bytes)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            migrated_ledger.catalog_retention_floor.as_deref(),
            i64::try_from(migrated_ledger.snapshot_count)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            i64::try_from(migrated_ledger.snapshot_bytes)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            i64::try_from(migrated_ledger.publication_stream_count)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            i64::try_from(migrated_ledger.publication_outbox_count)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            i64::try_from(migrated_ledger.publication_outbox_bytes)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            &new_token[..],
            match legacy_version {
                LegacySchemaVersion::V1 => 1_i64,
                LegacySchemaVersion::V2 => 2_i64,
                LegacySchemaVersion::V3 => 3_i64,
            },
            &old_signature[..],
            &old_token[..],
        ],
    )? != 1
    {
        return Err(RuntimeStoreError::SchemaInspectionRaced);
    }
    if let Err(injected_error) = config
        .fault_injector
        .before_operation(RuntimeStoreOperation::MigrateSchemaBeforeCommit)
    {
        let rollback_succeeded = transaction.execute_batch("ROLLBACK").is_ok();
        let definitely_rolled_back = rollback_succeeded && transaction.is_autocommit();
        transaction.set_drop_behavior(DropBehavior::Ignore);
        return if definitely_rolled_back {
            Err(injected_error)
        } else {
            Err(RuntimeStoreError::CommitOutcomeUnknown {
                operation: RuntimeCommitOperation::MigrateSchema,
            })
        };
    }
    commit_transaction(transaction, RuntimeCommitOperation::MigrateSchema)?;
    configure_connection(&connection, config.busy_timeout_ms, true).map_err(|_| {
        RuntimeStoreError::CommitOutcomeUnknown {
            operation: RuntimeCommitOperation::MigrateSchema,
        }
    })?;
    if config
        .fault_injector
        .before_operation(RuntimeStoreOperation::MigrateSchemaAfterCommit)
        .is_err()
    {
        return Err(RuntimeStoreError::CommitOutcomeUnknown {
            operation: RuntimeCommitOperation::MigrateSchema,
        });
    }

    let migrated = read_and_validate_current_schema(&connection)?;
    if migrated.database_id != current.database_id
        || migrated.key_generation != current.key_generation
        || migrated.wrapped_key_bundle != current.wrapped_key_bundle
        || migrated.ledger != migrated_ledger
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    validate_store_files(&storage_path)?;
    super::journal::validate_store_integrity(&connection, &key_bundle, migrated.database_id)?;
    snapshot(&connection, config.busy_timeout_ms)?;
    super::stream::initialize_ephemeral_state(&connection)?;
    Ok(RuntimeSqlite {
        connection,
        key_bundle: Arc::new(key_bundle),
        storage_path,
        database_id: migrated.database_id,
        admission_state: RuntimeAdmissionState::Normal,
        recovery_scan: None,
        last_finished_recovery: None,
    })
}

fn inspect_schema(path: &Path) -> Result<SchemaState, RuntimeStoreError> {
    match preflight_store_files(path)? {
        None => Ok(SchemaState::Fresh),
        Some(metadata) => {
            // 新实现从不公开空/半初始化 DB；遇到它们只能 fail-close，不能原地补写。
            if metadata.len() == 0 {
                return Err(RuntimeStoreError::UnknownOrCorruptSchema);
            }
            let identity = capture_store_identity(path)?;
            let rescue = open_rescue_connection(path)?;
            let connection = rescue.connection();
            configure_defensive_limits(connection)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
            connection
                .pragma_update(None, "query_only", true)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
            connection
                .pragma_update(None, "trusted_schema", false)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
            let (family, version) = read_schema_header(connection)?;
            if family == RUNTIME_SCHEMA_FAMILY && version > RUNTIME_SCHEMA_VERSION {
                return Err(RuntimeStoreError::SchemaTooNew {
                    found: version,
                    supported: RUNTIME_SCHEMA_VERSION,
                });
            }
            let state = match version {
                1 if family == RUNTIME_SCHEMA_FAMILY => SchemaState::LegacyV1(
                    read_and_validate_legacy_v1_schema(connection)?,
                    identity.clone(),
                ),
                2 if family == RUNTIME_SCHEMA_FAMILY => SchemaState::LegacyV2(
                    read_and_validate_legacy_v2_schema(connection)?,
                    identity.clone(),
                ),
                3 if family == RUNTIME_SCHEMA_FAMILY => SchemaState::LegacyV3(
                    read_and_validate_legacy_v3_schema(connection)?,
                    identity.clone(),
                ),
                RUNTIME_SCHEMA_VERSION if family == RUNTIME_SCHEMA_FAMILY => SchemaState::Current(
                    read_and_validate_current_schema(connection)?,
                    identity.clone(),
                ),
                _ => return Err(RuntimeStoreError::UnknownOrCorruptSchema),
            };
            validate_store_files(path)?;
            ensure_store_identity(path, &identity)?;
            Ok(state)
        }
    }
}

fn read_schema_header(connection: &Connection) -> Result<(String, u32), RuntimeStoreError> {
    let (family, version): (String, i64) = connection
        .query_row(
            "SELECT schema_family, schema_version FROM runtime_meta WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let version = u32::try_from(version).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    Ok((family, version))
}

fn read_and_validate_legacy_v1_schema(
    connection: &Connection,
) -> Result<MetaRow, RuntimeStoreError> {
    let Some(meta) =
        read_meta_v1(connection).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
    else {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    };
    if meta.family != RUNTIME_SCHEMA_FAMILY
        || meta.version != 1
        || meta.signature != schema_signature_v1()
        || meta.key_generation != RUNTIME_KEY_GENERATION
        || meta.wrapped_key_bundle.len() != WRAPPED_KEY_BUNDLE_V1_LEN
        || meta.metadata_token.len() != 32
        || table_names(connection)? != EXPECTED_TABLES_V1
        || schema_manifest(connection)? != expected_schema_manifest(1)?
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(meta)
}

fn read_and_validate_current_schema(connection: &Connection) -> Result<MetaRow, RuntimeStoreError> {
    let Some(meta) =
        read_meta(connection).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
    else {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    };
    if meta.family == RUNTIME_SCHEMA_FAMILY && meta.version > RUNTIME_SCHEMA_VERSION {
        return Err(RuntimeStoreError::SchemaTooNew {
            found: meta.version,
            supported: RUNTIME_SCHEMA_VERSION,
        });
    }
    if meta.family != RUNTIME_SCHEMA_FAMILY
        || meta.version != RUNTIME_SCHEMA_VERSION
        || meta.signature != schema_signature()
        || meta.key_generation != RUNTIME_KEY_GENERATION
        || meta.wrapped_key_bundle.len() != WRAPPED_KEY_BUNDLE_V1_LEN
        || meta.metadata_token.len() != 32
        || table_names(connection)? != EXPECTED_TABLES
        || schema_manifest(connection)? != expected_schema_manifest(RUNTIME_SCHEMA_VERSION)?
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(meta)
}

fn read_and_validate_legacy_v2_schema(
    connection: &Connection,
) -> Result<MetaRow, RuntimeStoreError> {
    let Some(meta) =
        read_meta_v2(connection).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
    else {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    };
    if meta.family != RUNTIME_SCHEMA_FAMILY
        || meta.version != 2
        || meta.signature != schema_signature_v2()
        || meta.key_generation != RUNTIME_KEY_GENERATION
        || meta.wrapped_key_bundle.len() != WRAPPED_KEY_BUNDLE_V1_LEN
        || meta.metadata_token.len() != 32
        || table_names(connection)? != EXPECTED_TABLES_V2
        || schema_manifest(connection)? != expected_schema_manifest(2)?
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(meta)
}

fn read_and_validate_legacy_v3_schema(
    connection: &Connection,
) -> Result<MetaRow, RuntimeStoreError> {
    let Some(meta) =
        read_meta_v3(connection).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
    else {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    };
    if meta.family != RUNTIME_SCHEMA_FAMILY
        || meta.version != 3
        || meta.signature != schema_signature_v3()
        || meta.key_generation != RUNTIME_KEY_GENERATION
        || meta.wrapped_key_bundle.len() != WRAPPED_KEY_BUNDLE_V1_LEN
        || meta.metadata_token.len() != 32
        || table_names(connection)? != EXPECTED_TABLES_V3
        || schema_manifest(connection)? != expected_schema_manifest(3)?
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(meta)
}

fn create_database_file(path: &Path) -> Result<(), RuntimeStoreError> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(DATABASE_MODE).custom_flags(libc::O_NOFOLLOW);
    }
    match options.open(path) {
        Ok(file) => {
            file.sync_all()?;
            validate_database_file(path)?;
            sync_parent_directory(path)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            Err(RuntimeStoreError::SchemaInspectionRaced)
        }
        Err(error) => Err(error.into()),
    }
}

fn open_read_write(path: &Path) -> Result<Connection, RuntimeStoreError> {
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_NO_MUTEX
        | OpenFlags::SQLITE_OPEN_NOFOLLOW;
    Ok(Connection::open_with_flags(path, flags)?)
}

fn configure_connection(
    connection: &Connection,
    busy_timeout_ms: u64,
    enable_wal: bool,
) -> Result<(), RuntimeStoreError> {
    configure_defensive_limits(connection)?;
    connection.busy_timeout(Duration::from_millis(busy_timeout_ms))?;
    connection.pragma_update(None, "foreign_keys", true)?;
    connection.pragma_update(None, "trusted_schema", false)?;
    connection.pragma_update(None, "temp_store", "MEMORY")?;
    connection.pragma_update(None, "synchronous", "FULL")?;
    // 自动 checkpoint 会绕过 main+WAL 峰值预算；所有 checkpoint 只能走下方
    // admission-protected PASSIVE 路径。
    connection.pragma_update(None, "wal_autocheckpoint", 0_i64)?;
    configure_max_page_count(connection)?;
    if enable_wal {
        let mode: String = connection.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))?;
        if !mode.eq_ignore_ascii_case("wal") {
            return Err(RuntimeStoreError::PragmaMismatch {
                name: "journal_mode",
                expected: "wal".to_owned(),
                actual: mode,
            });
        }
        configure_persistent_wal(connection)?;
    }
    Ok(())
}

fn configure_migration_connection(
    connection: &Connection,
    busy_timeout_ms: u64,
) -> Result<(), RuntimeStoreError> {
    configure_defensive_limits(connection)?;
    connection.busy_timeout(Duration::from_millis(busy_timeout_ms))?;
    connection.pragma_update(None, "foreign_keys", true)?;
    connection.pragma_update(None, "trusted_schema", false)?;
    connection.pragma_update(None, "temp_store", "MEMORY")?;
    connection.pragma_update(None, "synchronous", "FULL")?;
    Ok(())
}

fn configure_persistent_wal(connection: &Connection) -> Result<(), RuntimeStoreError> {
    let database_name = b"main\0";
    let mut enabled = 1_i32;
    // SAFETY: `connection.handle()` stays valid for the call, database_name is a static
    // NUL-terminated C string, and SQLite reads/writes exactly one i32 through the final pointer.
    let result = unsafe {
        rusqlite::ffi::sqlite3_file_control(
            connection.handle(),
            database_name.as_ptr().cast(),
            rusqlite::ffi::SQLITE_FCNTL_PERSIST_WAL,
            std::ptr::from_mut(&mut enabled).cast(),
        )
    };
    if result != rusqlite::ffi::SQLITE_OK {
        return Err(RuntimeStoreError::Sqlite(rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(result),
            Some("failed to enable persistent WAL".to_owned()),
        )));
    }
    let mut readback = -1_i32;
    // SAFETY: same pointer/string/connection lifetime argument as the set call above; -1 asks
    // SQLite to read back the current PERSIST_WAL flag into `readback`.
    let result = unsafe {
        rusqlite::ffi::sqlite3_file_control(
            connection.handle(),
            database_name.as_ptr().cast(),
            rusqlite::ffi::SQLITE_FCNTL_PERSIST_WAL,
            std::ptr::from_mut(&mut readback).cast(),
        )
    };
    if result != rusqlite::ffi::SQLITE_OK || readback != 1 {
        return Err(RuntimeStoreError::PragmaMismatch {
            name: "persist_wal",
            expected: "1".to_owned(),
            actual: format!("result={result}, value={readback}"),
        });
    }
    Ok(())
}

fn configure_defensive_limits(connection: &Connection) -> Result<(), RuntimeStoreError> {
    let _ = connection.set_limit(Limit::SQLITE_LIMIT_LENGTH, SQLITE_LENGTH_LIMIT_BYTES);
    let actual = connection.limit(Limit::SQLITE_LIMIT_LENGTH);
    if actual != SQLITE_LENGTH_LIMIT_BYTES {
        return Err(RuntimeStoreError::PragmaMismatch {
            name: "sqlite_limit_length",
            expected: SQLITE_LENGTH_LIMIT_BYTES.to_string(),
            actual: actual.to_string(),
        });
    }
    Ok(())
}

pub(crate) fn snapshot(
    connection: &Connection,
    expected_busy_timeout_ms: u64,
) -> Result<RuntimeStoreSnapshot, RuntimeStoreError> {
    let meta = read_meta(connection)?.ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let journal_mode: String = connection.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
    let wal_autocheckpoint: i64 =
        connection.query_row("PRAGMA wal_autocheckpoint", [], |row| row.get(0))?;
    let synchronous: i64 = connection.query_row("PRAGMA synchronous", [], |row| row.get(0))?;
    let foreign_keys: i64 = connection.query_row("PRAGMA foreign_keys", [], |row| row.get(0))?;
    let busy_timeout: i64 = connection.query_row("PRAGMA busy_timeout", [], |row| row.get(0))?;
    let (page_size_bytes, page_count, max_page_count) = read_page_budget(connection)?;
    let busy_timeout_ms =
        u64::try_from(busy_timeout).map_err(|_| RuntimeStoreError::PragmaMismatch {
            name: "busy_timeout",
            expected: expected_busy_timeout_ms.to_string(),
            actual: busy_timeout.to_string(),
        })?;
    if !journal_mode.eq_ignore_ascii_case("wal") {
        return Err(RuntimeStoreError::PragmaMismatch {
            name: "journal_mode",
            expected: "wal".to_owned(),
            actual: journal_mode,
        });
    }
    let wal_autocheckpoint_pages =
        u64::try_from(wal_autocheckpoint).map_err(|_| RuntimeStoreError::PragmaMismatch {
            name: "wal_autocheckpoint",
            expected: "0".to_owned(),
            actual: wal_autocheckpoint.to_string(),
        })?;
    if wal_autocheckpoint_pages != 0 {
        return Err(RuntimeStoreError::PragmaMismatch {
            name: "wal_autocheckpoint",
            expected: "0".to_owned(),
            actual: wal_autocheckpoint_pages.to_string(),
        });
    }
    if synchronous != 2 {
        return Err(RuntimeStoreError::PragmaMismatch {
            name: "synchronous",
            expected: "2".to_owned(),
            actual: synchronous.to_string(),
        });
    }
    if foreign_keys != 1 {
        return Err(RuntimeStoreError::PragmaMismatch {
            name: "foreign_keys",
            expected: "1".to_owned(),
            actual: foreign_keys.to_string(),
        });
    }
    if busy_timeout_ms != expected_busy_timeout_ms {
        return Err(RuntimeStoreError::PragmaMismatch {
            name: "busy_timeout",
            expected: expected_busy_timeout_ms.to_string(),
            actual: busy_timeout_ms.to_string(),
        });
    }
    if page_size_bytes == 0 {
        return Err(RuntimeStoreError::InvalidCapacityBudget {
            reason: "page_size_zero",
        });
    }
    let expected_max_page_count = RUNTIME_DB_HARD_LIMIT_BYTES / page_size_bytes;
    if max_page_count != expected_max_page_count {
        return Err(RuntimeStoreError::PragmaMismatch {
            name: "max_page_count",
            expected: expected_max_page_count.to_string(),
            actual: max_page_count.to_string(),
        });
    }
    if page_count > max_page_count {
        return Err(RuntimeStoreError::InvalidCapacityBudget {
            reason: "page_count_above_max",
        });
    }
    Ok(RuntimeStoreSnapshot {
        schema_family: meta.family,
        schema_version: meta.version,
        schema_signature: meta.signature,
        database_id: meta.database_id,
        key_generation: meta.key_generation,
        table_names: table_names(connection)?,
        journal_mode,
        wal_autocheckpoint_pages,
        synchronous,
        foreign_keys: true,
        busy_timeout_ms,
        page_size_bytes,
        page_count,
        max_page_count,
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn admit_ordinary_write(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    storage_path: &Path,
    admission_state: &mut RuntimeAdmissionState,
    capacity_probe: &dyn RuntimeCapacityProbe,
    projected_write_bytes: u64,
    reserve_projection: SafetyReserveProjection,
) -> Result<(), RuntimeStoreError> {
    if *admission_state == RuntimeAdmissionState::SafetyOnly {
        return Err(RuntimeStoreError::SafetyOnly);
    }
    let safety_reserve_bytes =
        safety_reserve_bytes(connection, key_bundle, database_id, reserve_projection)?
            .checked_add(RUNTIME_WRITE_SAFETY_MARGIN_BYTES)
            .ok_or(RuntimeStoreError::CapacityArithmeticOverflow {
                field: "ordinary_safety_reserve_bytes",
            })?;
    match evaluate_ordinary_capacity_with_checkpoint(
        connection,
        storage_path,
        capacity_probe,
        projected_write_bytes,
        safety_reserve_bytes,
    ) {
        Ok(()) => Ok(()),
        Err(error) => {
            if !matches!(error, RuntimeStoreError::DiskLow { .. }) {
                *admission_state = RuntimeAdmissionState::SafetyOnly;
            }
            Err(error)
        }
    }
}

pub(crate) fn admit_safety_write(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    storage_path: &Path,
    capacity_probe: &dyn RuntimeCapacityProbe,
) -> Result<(), RuntimeStoreError> {
    let safety_reserve_bytes = safety_reserve_bytes(
        connection,
        key_bundle,
        database_id,
        SafetyReserveProjection::Current,
    )?;
    let observed = capacity_probe.observe(storage_path)?;
    let (page_size_bytes, page_count, max_page_count) = read_page_budget(connection)?;
    evaluate_runtime_safety_admission(RuntimeAdmissionInput {
        main_bytes: observed.main_bytes,
        wal_bytes: observed.wal_bytes,
        shm_bytes: observed.shm_bytes,
        projected_write_bytes: 0,
        safety_margin_bytes: safety_reserve_bytes,
        filesystem_total_bytes: observed.filesystem_total_bytes,
        filesystem_available_bytes: observed.filesystem_available_bytes,
        page_size_bytes,
        page_count,
        max_page_count,
    })
    .map(|_| ())
    .map_err(map_admission_rejection)
}

pub(crate) fn latch_post_commit_capacity(state: &mut RuntimeSqlite, config: &RuntimeStoreConfig) {
    if state.admission_state == RuntimeAdmissionState::SafetyOnly {
        return;
    }
    let safety_reserve_bytes = match safety_reserve_bytes(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        SafetyReserveProjection::Current,
    ) {
        Ok(value) => value,
        Err(_) => {
            state.admission_state = RuntimeAdmissionState::SafetyOnly;
            return;
        }
    };
    let result = evaluate_current_capacity(
        &state.connection,
        &state.storage_path,
        config.capacity_probe.as_ref(),
        0,
        safety_reserve_bytes,
    );
    if result.is_err() && !matches!(result, Err(RuntimeStoreError::DiskLow { .. })) {
        state.admission_state = RuntimeAdmissionState::SafetyOnly;
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct SafetyCounts {
    accepted: u64,
    started_without_fence: u64,
    started_without_release: u64,
    started_released: u64,
    active_approvals: u64,
}

fn safety_reserve_bytes(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    projection: SafetyReserveProjection,
) -> Result<u64, RuntimeStoreError> {
    let ledger = load_runtime_ledger(connection, key_bundle, database_id)?;
    safety_reserve_bytes_for_ledger_projection(&ledger, projection)
}

fn safety_reserve_bytes_for_ledger_projection(
    ledger: &RuntimeLedger,
    projection: SafetyReserveProjection,
) -> Result<u64, RuntimeStoreError> {
    let mut counts = SafetyCounts {
        accepted: ledger.accepted_count,
        started_without_fence: ledger.started_without_fence_count,
        started_without_release: ledger.started_without_release_count,
        started_released: ledger.started_released_count,
        active_approvals: ledger.active_approval_count,
    };
    match projection {
        SafetyReserveProjection::Current => {}
        SafetyReserveProjection::AcceptCommand => {
            counts.accepted = counts.accepted.checked_add(1).ok_or(
                RuntimeStoreError::CapacityArithmeticOverflow {
                    field: "accepted_safety_count",
                },
            )?;
        }
        SafetyReserveProjection::StartCommand => {
            counts.accepted = counts
                .accepted
                .checked_sub(1)
                .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
            counts.started_without_fence = counts.started_without_fence.checked_add(1).ok_or(
                RuntimeStoreError::CapacityArithmeticOverflow {
                    field: "started_safety_count",
                },
            )?;
        }
        SafetyReserveProjection::RegisterApproval => {
            counts.active_approvals = counts.active_approvals.checked_add(1).ok_or(
                RuntimeStoreError::CapacityArithmeticOverflow {
                    field: "active_approval_safety_count",
                },
            )?;
        }
    }
    safety_reserve_bytes_for_counts(counts)
}

fn safety_reserve_bytes_for_ledger(ledger: &RuntimeLedger) -> Result<u64, RuntimeStoreError> {
    safety_reserve_bytes_for_ledger_projection(ledger, SafetyReserveProjection::Current)
}

fn safety_reserve_bytes_for_counts(counts: SafetyCounts) -> Result<u64, RuntimeStoreError> {
    let accepted = counts
        .accepted
        .checked_mul(ACCEPTED_EXPIRY_RESERVE_BYTES)
        .ok_or(RuntimeStoreError::CapacityArithmeticOverflow {
            field: "accepted_safety_reserve",
        })?;
    let without_fence = counts
        .started_without_fence
        .checked_mul(
            FENCE_RESERVE_BYTES
                .checked_add(RELEASE_RESERVE_BYTES)
                .and_then(|value| value.checked_add(TERMINAL_RESERVE_BYTES))
                .ok_or(RuntimeStoreError::CapacityArithmeticOverflow {
                    field: "started_without_fence_unit_reserve",
                })?,
        )
        .ok_or(RuntimeStoreError::CapacityArithmeticOverflow {
            field: "started_without_fence_reserve",
        })?;
    let without_release = counts
        .started_without_release
        .checked_mul(
            RELEASE_RESERVE_BYTES
                .checked_add(TERMINAL_RESERVE_BYTES)
                .ok_or(RuntimeStoreError::CapacityArithmeticOverflow {
                    field: "started_without_release_unit_reserve",
                })?,
        )
        .ok_or(RuntimeStoreError::CapacityArithmeticOverflow {
            field: "started_without_release_reserve",
        })?;
    let released = counts
        .started_released
        .checked_mul(TERMINAL_RESERVE_BYTES)
        .ok_or(RuntimeStoreError::CapacityArithmeticOverflow {
            field: "started_released_reserve",
        })?;
    let active_approvals = counts
        .active_approvals
        .checked_mul(MAX_APPROVAL_TERMINATION_RESERVE_BYTES)
        .ok_or(RuntimeStoreError::CapacityArithmeticOverflow {
            field: "active_approval_safety_reserve",
        })?;
    [
        accepted,
        without_fence,
        without_release,
        released,
        active_approvals,
    ]
    .into_iter()
    .try_fold(FIXED_SAFETY_RESERVE_BYTES, |total, value| {
        total
            .checked_add(value)
            .ok_or(RuntimeStoreError::CapacityArithmeticOverflow {
                field: "total_safety_reserve",
            })
    })
}

fn configure_max_page_count(connection: &Connection) -> Result<(), RuntimeStoreError> {
    let page_size_bytes = read_u64_pragma(connection, "page_size")?;
    if page_size_bytes == 0 {
        return Err(RuntimeStoreError::InvalidCapacityBudget {
            reason: "page_size_zero",
        });
    }
    let expected = RUNTIME_DB_HARD_LIMIT_BYTES / page_size_bytes;
    if expected == 0 {
        return Err(RuntimeStoreError::InvalidCapacityBudget {
            reason: "page_size_above_hard_limit",
        });
    }
    connection.pragma_update(None, "max_page_count", expected)?;
    let actual = read_u64_pragma(connection, "max_page_count")?;
    if actual != expected {
        return Err(RuntimeStoreError::PragmaMismatch {
            name: "max_page_count",
            expected: expected.to_string(),
            actual: actual.to_string(),
        });
    }
    Ok(())
}

fn evaluate_current_capacity(
    connection: &Connection,
    storage_path: &Path,
    capacity_probe: &dyn RuntimeCapacityProbe,
    projected_write_bytes: u64,
    safety_margin_bytes: u64,
) -> Result<(), RuntimeStoreError> {
    let observed = capacity_probe.observe(storage_path)?;
    evaluate_capacity_observation(
        connection,
        observed,
        projected_write_bytes,
        safety_margin_bytes,
    )
}

fn evaluate_migration_capacity_before_wal(
    connection: &Connection,
    storage_path: &Path,
    capacity_probe: &dyn RuntimeCapacityProbe,
    projected_write_bytes: u64,
    safety_margin_bytes: u64,
) -> Result<(), RuntimeStoreError> {
    let observed = capacity_probe.observe(storage_path)?;
    let page_size_bytes = read_u64_pragma(connection, "page_size")?;
    if page_size_bytes == 0 {
        return Err(RuntimeStoreError::InvalidCapacityBudget {
            reason: "page_size_zero",
        });
    }
    let max_page_count = RUNTIME_DB_HARD_LIMIT_BYTES / page_size_bytes;
    if max_page_count == 0 {
        return Err(RuntimeStoreError::InvalidCapacityBudget {
            reason: "page_size_above_hard_limit",
        });
    }
    let page_count = read_u64_pragma(connection, "page_count")?;
    evaluate_runtime_admission(RuntimeAdmissionInput {
        main_bytes: observed.main_bytes,
        wal_bytes: observed.wal_bytes,
        shm_bytes: observed.shm_bytes,
        projected_write_bytes,
        safety_margin_bytes,
        filesystem_total_bytes: observed.filesystem_total_bytes,
        filesystem_available_bytes: observed.filesystem_available_bytes,
        page_size_bytes,
        page_count,
        max_page_count,
    })
    .map(|_| ())
    .map_err(map_admission_rejection)
}

fn evaluate_ordinary_capacity_with_checkpoint(
    connection: &Connection,
    storage_path: &Path,
    capacity_probe: &dyn RuntimeCapacityProbe,
    projected_write_bytes: u64,
    safety_margin_bytes: u64,
) -> Result<(), RuntimeStoreError> {
    let mut observed = capacity_probe.observe(storage_path)?;
    // 任何可能有副作用的 checkpoint 前先完成原始 write admission。低盘、page budget
    // 或当前 footprint 越界时必须零 checkpoint 返回。
    evaluate_capacity_observation(
        connection,
        observed,
        projected_write_bytes,
        safety_margin_bytes,
    )?;
    let closure = projected_write_bytes
        .checked_add(safety_margin_bytes)
        .ok_or(RuntimeStoreError::CapacityArithmeticOverflow {
            field: "checkpoint_growth_closure",
        })?;
    let projected_footprint = observed
        .main_bytes
        .checked_add(observed.wal_bytes)
        .and_then(|value| value.checked_add(observed.shm_bytes))
        .and_then(|value| value.checked_add(closure))
        .ok_or(RuntimeStoreError::CapacityArithmeticOverflow {
            field: "checkpoint_projected_footprint",
        })?;
    if observed.wal_bytes >= WAL_CHECKPOINT_TRIGGER_BYTES
        || projected_footprint >= CHECKPOINT_TRIGGER_BYTES
    {
        ensure_checkpoint_copy_budget(observed, closure)?;
        if !connection.is_autocommit() {
            return Err(RuntimeStoreError::InvalidCapacityBudget {
                reason: "checkpoint_requires_autocommit",
            });
        }
        let (busy, log_frames, checkpointed_frames): (i64, i64, i64) =
            connection.query_row("PRAGMA wal_checkpoint(PASSIVE)", [], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })?;
        observed = capacity_probe.observe(storage_path)?;
        let after_projected = observed
            .main_bytes
            .checked_add(observed.wal_bytes)
            .and_then(|value| value.checked_add(observed.shm_bytes))
            .and_then(|value| value.checked_add(closure))
            .ok_or(RuntimeStoreError::CapacityArithmeticOverflow {
                field: "checkpoint_after_projected_footprint",
            })?;
        if (busy != 0 || (log_frames > 0 && checkpointed_frames < log_frames))
            && after_projected >= CHECKPOINT_TRIGGER_BYTES
        {
            return Err(RuntimeStoreError::CheckpointBlocked {
                log_frames,
                checkpointed_frames,
            });
        }
    }
    evaluate_capacity_observation(
        connection,
        observed,
        projected_write_bytes,
        safety_margin_bytes,
    )
}

/// `PASSIVE` checkpoint 可能先把整个 WAL 的有效页复制进 main，而 WAL 文件尚未 reset；
/// 因此 checkpoint 峰值按 `current footprint + future closure + wal_bytes` 保守预算。
fn ensure_checkpoint_copy_budget(
    observed: RuntimeCapacityObservation,
    future_growth_closure_bytes: u64,
) -> Result<(), RuntimeStoreError> {
    let observed_footprint_bytes = observed
        .main_bytes
        .checked_add(observed.wal_bytes)
        .and_then(|value| value.checked_add(observed.shm_bytes))
        .ok_or(RuntimeStoreError::CapacityArithmeticOverflow {
            field: "checkpoint_observed_footprint",
        })?;
    let checkpoint_growth_bytes = observed
        .wal_bytes
        .checked_add(future_growth_closure_bytes)
        .ok_or(RuntimeStoreError::CapacityArithmeticOverflow {
            field: "checkpoint_peak_growth",
        })?;
    let peak_footprint_bytes = observed_footprint_bytes
        .checked_add(checkpoint_growth_bytes)
        .ok_or(RuntimeStoreError::CapacityArithmeticOverflow {
            field: "checkpoint_peak_footprint",
        })?;
    if peak_footprint_bytes > RUNTIME_DB_HARD_LIMIT_BYTES {
        return Err(RuntimeStoreError::StoreFull {
            projected_footprint_bytes: peak_footprint_bytes,
            hard_limit_bytes: RUNTIME_DB_HARD_LIMIT_BYTES,
        });
    }
    let required_available_bytes = filesystem_reserve_bytes(observed.filesystem_total_bytes)
        .checked_add(checkpoint_growth_bytes)
        .ok_or(RuntimeStoreError::CapacityArithmeticOverflow {
            field: "checkpoint_required_available",
        })?;
    if observed.filesystem_available_bytes < required_available_bytes {
        return Err(RuntimeStoreError::DiskLow {
            available_bytes: observed.filesystem_available_bytes,
            required_available_bytes,
        });
    }
    Ok(())
}

fn evaluate_capacity_observation(
    connection: &Connection,
    observed: RuntimeCapacityObservation,
    projected_write_bytes: u64,
    safety_margin_bytes: u64,
) -> Result<(), RuntimeStoreError> {
    let (page_size_bytes, page_count, max_page_count) = read_page_budget(connection)?;
    evaluate_runtime_admission(RuntimeAdmissionInput {
        main_bytes: observed.main_bytes,
        wal_bytes: observed.wal_bytes,
        shm_bytes: observed.shm_bytes,
        projected_write_bytes,
        safety_margin_bytes,
        filesystem_total_bytes: observed.filesystem_total_bytes,
        filesystem_available_bytes: observed.filesystem_available_bytes,
        page_size_bytes,
        page_count,
        max_page_count,
    })
    .map(|_| ())
    .map_err(map_admission_rejection)
}

fn read_page_budget(connection: &Connection) -> Result<(u64, u64, u64), RuntimeStoreError> {
    Ok((
        read_u64_pragma(connection, "page_size")?,
        read_u64_pragma(connection, "page_count")?,
        read_u64_pragma(connection, "max_page_count")?,
    ))
}

fn read_u64_pragma(connection: &Connection, name: &'static str) -> Result<u64, RuntimeStoreError> {
    let value: i64 = connection.query_row(&format!("PRAGMA {name}"), [], |row| row.get(0))?;
    u64::try_from(value).map_err(|_| RuntimeStoreError::PragmaMismatch {
        name,
        expected: "non-negative integer".to_owned(),
        actual: value.to_string(),
    })
}

fn map_admission_rejection(rejection: AdmissionRejection) -> RuntimeStoreError {
    match rejection {
        AdmissionRejection::ArithmeticOverflow { field } => {
            RuntimeStoreError::CapacityArithmeticOverflow { field }
        }
        AdmissionRejection::DatabaseHardLimit {
            projected_footprint_bytes,
            hard_limit_bytes,
        } => RuntimeStoreError::StoreFull {
            projected_footprint_bytes,
            hard_limit_bytes,
        },
        AdmissionRejection::DiskLow {
            available_bytes,
            required_available_bytes,
        } => RuntimeStoreError::DiskLow {
            available_bytes,
            required_available_bytes,
        },
        AdmissionRejection::InvalidPageBudget { reason } => {
            RuntimeStoreError::InvalidCapacityBudget { reason }
        }
        AdmissionRejection::PageLimit {
            projected_page_count,
            max_page_count,
        } => RuntimeStoreError::PageLimit {
            projected_page_count,
            max_page_count,
        },
    }
}

fn read_meta(connection: &Connection) -> Result<Option<MetaRow>, rusqlite::Error> {
    read_meta_with_sql(
        connection,
        "SELECT schema_family, schema_version, schema_signature, database_id,
                key_generation, wrapped_key_bundle, catalog_high_water,
                conversation_count, command_count, event_count, intent_count, fence_count,
                accepted_count, accepted_payload_bytes, started_without_fence_count,
                started_without_release_count, started_released_count, metadata_token,
                codex_adapter_state_count, claude_code_adapter_state_count,
                approval_count, active_approval_count,
                audit_event_logical_bytes, event_stream_count, event_stream_bytes,
                catalog_delta_count, catalog_delta_bytes, catalog_retention_floor,
                snapshot_count, snapshot_bytes, publication_stream_count,
                publication_outbox_count, publication_outbox_bytes
         FROM runtime_meta WHERE singleton = 1",
    )
}

fn read_meta_v3(connection: &Connection) -> Result<Option<MetaRow>, rusqlite::Error> {
    read_meta_with_sql(
        connection,
        "SELECT schema_family, schema_version, schema_signature, database_id,
                key_generation, wrapped_key_bundle, catalog_high_water,
                conversation_count, command_count, event_count, intent_count, fence_count,
                accepted_count, accepted_payload_bytes, started_without_fence_count,
                started_without_release_count, started_released_count, metadata_token,
                codex_adapter_state_count, claude_code_adapter_state_count,
                approval_count, active_approval_count,
                0, 0, 0, 0, 0, NULL, 0, 0, 0, 0, 0
         FROM runtime_meta WHERE singleton = 1",
    )
}

fn read_meta_v2(connection: &Connection) -> Result<Option<MetaRow>, rusqlite::Error> {
    read_meta_with_sql(
        connection,
        "SELECT schema_family, schema_version, schema_signature, database_id,
                key_generation, wrapped_key_bundle, catalog_high_water,
                conversation_count, command_count, event_count, intent_count, fence_count,
                accepted_count, accepted_payload_bytes, started_without_fence_count,
                started_without_release_count, started_released_count, metadata_token,
                codex_adapter_state_count, claude_code_adapter_state_count, 0, 0,
                0, 0, 0, 0, 0, NULL, 0, 0, 0, 0, 0
         FROM runtime_meta WHERE singleton = 1",
    )
}

fn read_meta_v1(connection: &Connection) -> Result<Option<MetaRow>, rusqlite::Error> {
    read_meta_with_sql(
        connection,
        "SELECT schema_family, schema_version, schema_signature, database_id,
                key_generation, wrapped_key_bundle, catalog_high_water,
                conversation_count, command_count, event_count, intent_count, fence_count,
                accepted_count, accepted_payload_bytes, started_without_fence_count,
                started_without_release_count, started_released_count, metadata_token,
                0, 0, 0, 0, 0, 0, 0, 0, 0, NULL, 0, 0, 0, 0, 0
         FROM runtime_meta WHERE singleton = 1",
    )
}

fn read_meta_with_sql(
    connection: &Connection,
    sql: &str,
) -> Result<Option<MetaRow>, rusqlite::Error> {
    connection
        .query_row(sql, [], |row| {
            let version: i64 = row.get(1)?;
            let signature: Vec<u8> = row.get(2)?;
            let database_id: Vec<u8> = row.get(3)?;
            let generation: i64 = row.get(4)?;
            Ok((
                row.get::<_, String>(0)?,
                version,
                signature,
                database_id,
                generation,
                row.get::<_, Vec<u8>>(5)?,
                row.get::<_, Option<String>>(6)?,
                row.get::<_, i64>(7)?,
                row.get::<_, i64>(8)?,
                row.get::<_, i64>(9)?,
                row.get::<_, i64>(10)?,
                row.get::<_, i64>(11)?,
                row.get::<_, i64>(12)?,
                row.get::<_, i64>(13)?,
                row.get::<_, i64>(14)?,
                row.get::<_, i64>(15)?,
                row.get::<_, i64>(16)?,
                row.get::<_, Vec<u8>>(17)?,
                row.get::<_, i64>(18)?,
                row.get::<_, i64>(19)?,
                row.get::<_, i64>(20)?,
                row.get::<_, i64>(21)?,
                row.get::<_, i64>(22)?,
                row.get::<_, i64>(23)?,
                row.get::<_, i64>(24)?,
                row.get::<_, i64>(25)?,
                row.get::<_, i64>(26)?,
                row.get::<_, Option<String>>(27)?,
                row.get::<_, i64>(28)?,
                row.get::<_, i64>(29)?,
                row.get::<_, i64>(30)?,
                row.get::<_, i64>(31)?,
                row.get::<_, i64>(32)?,
            ))
        })
        .optional()?
        .map(
            |(
                family,
                version,
                signature,
                database_id,
                generation,
                wrapped,
                catalog_high_water,
                conversation_count,
                command_count,
                event_count,
                intent_count,
                fence_count,
                accepted_count,
                accepted_payload_bytes,
                started_without_fence_count,
                started_without_release_count,
                started_released_count,
                metadata_token,
                codex_adapter_state_count,
                claude_code_adapter_state_count,
                approval_count,
                active_approval_count,
                audit_event_logical_bytes,
                event_stream_count,
                event_stream_bytes,
                catalog_delta_count,
                catalog_delta_bytes,
                catalog_retention_floor,
                snapshot_count,
                snapshot_bytes,
                publication_stream_count,
                publication_outbox_count,
                publication_outbox_bytes,
            )| {
                let version = u32::try_from(version)
                    .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(1, version))?;
                let key_generation = u32::try_from(generation)
                    .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(4, generation))?;
                let signature = signature.try_into().map_err(|value: Vec<u8>| {
                    rusqlite::Error::FromSqlConversionFailure(
                        value.len(),
                        rusqlite::types::Type::Blob,
                        "schema signature must be 32 bytes".into(),
                    )
                })?;
                let database_id = database_id.try_into().map_err(|value: Vec<u8>| {
                    rusqlite::Error::FromSqlConversionFailure(
                        value.len(),
                        rusqlite::types::Type::Blob,
                        "database id must be 16 bytes".into(),
                    )
                })?;
                let conversation_count = sqlite_nonnegative_u64(7, conversation_count)?;
                let command_count = sqlite_nonnegative_u64(8, command_count)?;
                let event_count = sqlite_nonnegative_u64(9, event_count)?;
                let intent_count = sqlite_nonnegative_u64(10, intent_count)?;
                let fence_count = sqlite_nonnegative_u64(11, fence_count)?;
                let accepted_count = sqlite_nonnegative_u64(12, accepted_count)?;
                let accepted_payload_bytes = sqlite_nonnegative_u64(13, accepted_payload_bytes)?;
                let started_without_fence_count =
                    sqlite_nonnegative_u64(14, started_without_fence_count)?;
                let started_without_release_count =
                    sqlite_nonnegative_u64(15, started_without_release_count)?;
                let started_released_count = sqlite_nonnegative_u64(16, started_released_count)?;
                let codex_adapter_state_count =
                    sqlite_nonnegative_u64(18, codex_adapter_state_count)?;
                let claude_code_adapter_state_count =
                    sqlite_nonnegative_u64(19, claude_code_adapter_state_count)?;
                let approval_count = sqlite_nonnegative_u64(20, approval_count)?;
                let active_approval_count = sqlite_nonnegative_u64(21, active_approval_count)?;
                let audit_event_logical_bytes =
                    sqlite_nonnegative_u64(22, audit_event_logical_bytes)?;
                let event_stream_count = sqlite_nonnegative_u64(23, event_stream_count)?;
                let event_stream_bytes = sqlite_nonnegative_u64(24, event_stream_bytes)?;
                let catalog_delta_count = sqlite_nonnegative_u64(25, catalog_delta_count)?;
                let catalog_delta_bytes = sqlite_nonnegative_u64(26, catalog_delta_bytes)?;
                let snapshot_count = sqlite_nonnegative_u64(28, snapshot_count)?;
                let snapshot_bytes = sqlite_nonnegative_u64(29, snapshot_bytes)?;
                let publication_stream_count =
                    sqlite_nonnegative_u64(30, publication_stream_count)?;
                let publication_outbox_count =
                    sqlite_nonnegative_u64(31, publication_outbox_count)?;
                let publication_outbox_bytes =
                    sqlite_nonnegative_u64(32, publication_outbox_bytes)?;
                if active_approval_count > approval_count {
                    return Err(rusqlite::Error::IntegralValueOutOfRange(
                        21,
                        i64::try_from(active_approval_count).unwrap_or(i64::MAX),
                    ));
                }
                Ok(MetaRow {
                    family,
                    version,
                    signature,
                    database_id,
                    key_generation,
                    wrapped_key_bundle: wrapped,
                    ledger: RuntimeLedger {
                        catalog_high_water,
                        conversation_count,
                        command_count,
                        event_count,
                        intent_count,
                        fence_count,
                        codex_adapter_state_count,
                        claude_code_adapter_state_count,
                        approval_count,
                        active_approval_count,
                        audit_event_logical_bytes,
                        event_stream_count,
                        event_stream_bytes,
                        catalog_delta_count,
                        catalog_delta_bytes,
                        catalog_retention_floor,
                        snapshot_count,
                        snapshot_bytes,
                        publication_stream_count,
                        publication_outbox_count,
                        publication_outbox_bytes,
                        accepted_count,
                        accepted_payload_bytes,
                        started_without_fence_count,
                        started_without_release_count,
                        started_released_count,
                    },
                    metadata_token,
                })
            },
        )
        .transpose()
}

fn sqlite_nonnegative_u64(column: usize, value: i64) -> Result<u64, rusqlite::Error> {
    u64::try_from(value).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(column, value))
}

#[derive(Debug, Eq, PartialEq)]
struct SchemaObject {
    object_type: String,
    name: String,
    table_name: String,
    sql: String,
}

fn schema_manifest(connection: &Connection) -> Result<Vec<SchemaObject>, RuntimeStoreError> {
    let mut statement = connection.prepare(
        "SELECT type, name, tbl_name, sql
         FROM sqlite_schema
         WHERE type IN ('table', 'index', 'trigger', 'view')
           AND name NOT LIKE 'sqlite_%'
         ORDER BY type, name, tbl_name",
    )?;
    Ok(statement
        .query_map([], |row| {
            Ok(SchemaObject {
                object_type: row.get(0)?,
                name: row.get(1)?,
                table_name: row.get(2)?,
                sql: row.get::<_, Option<String>>(3)?.unwrap_or_default(),
            })
        })?
        .collect::<Result<Vec<_>, _>>()?)
}

fn expected_schema_manifest(version: u32) -> Result<Vec<SchemaObject>, RuntimeStoreError> {
    let connection = Connection::open_in_memory()?;
    connection.execute_batch(RUNTIME_DDL_V1)?;
    match version {
        1 => {}
        2 => connection.execute_batch(RUNTIME_MIGRATION_V2)?,
        3 => {
            connection.execute_batch(RUNTIME_MIGRATION_V2)?;
            connection.execute_batch(RUNTIME_MIGRATION_V3)?;
        }
        RUNTIME_SCHEMA_VERSION => {
            connection.execute_batch(RUNTIME_MIGRATION_V2)?;
            connection.execute_batch(RUNTIME_MIGRATION_V3)?;
            connection.execute_batch(RUNTIME_MIGRATION_V4)?;
        }
        _ => return Err(RuntimeStoreError::UnknownOrCorruptSchema),
    }
    schema_manifest(&connection)
}

fn table_names(connection: &Connection) -> Result<Vec<String>, RuntimeStoreError> {
    let mut statement = connection.prepare(
        "SELECT name FROM sqlite_schema
         WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
         ORDER BY name",
    )?;
    let names = statement
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(names)
}

fn same_meta(left: &MetaRow, right: &MetaRow) -> bool {
    left.family == right.family
        && left.version == right.version
        && left.signature == right.signature
        && left.database_id == right.database_id
        && left.key_generation == right.key_generation
        && left.wrapped_key_bundle == right.wrapped_key_bundle
        && left.ledger == right.ledger
        && left.metadata_token == right.metadata_token
}

fn runtime_ledger_token_v3(
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    ledger: &RuntimeLedger,
) -> Result<[u8; 32], RuntimeStoreError> {
    let mut message = Vec::with_capacity(149);
    message.extend_from_slice(&database_id);
    match ledger.catalog_high_water.as_deref() {
        None => message.push(0),
        Some(value) => {
            message.push(1);
            message.extend_from_slice(value.as_bytes());
        }
    }
    message.extend_from_slice(&ledger.conversation_count.to_be_bytes());
    message.extend_from_slice(&ledger.command_count.to_be_bytes());
    message.extend_from_slice(&ledger.event_count.to_be_bytes());
    message.extend_from_slice(&ledger.intent_count.to_be_bytes());
    message.extend_from_slice(&ledger.fence_count.to_be_bytes());
    message.extend_from_slice(&ledger.codex_adapter_state_count.to_be_bytes());
    message.extend_from_slice(&ledger.claude_code_adapter_state_count.to_be_bytes());
    message.extend_from_slice(&ledger.approval_count.to_be_bytes());
    message.extend_from_slice(&ledger.active_approval_count.to_be_bytes());
    message.extend_from_slice(&ledger.accepted_count.to_be_bytes());
    message.extend_from_slice(&ledger.accepted_payload_bytes.to_be_bytes());
    message.extend_from_slice(&ledger.started_without_fence_count.to_be_bytes());
    message.extend_from_slice(&ledger.started_without_release_count.to_be_bytes());
    message.extend_from_slice(&ledger.started_released_count.to_be_bytes());
    let token = key_bundle.blind_index(b"runtime.meta.ledger.v3", &message)?;
    Ok(*token.as_bytes())
}

fn runtime_ledger_token(
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    ledger: &RuntimeLedger,
) -> Result<[u8; 32], RuntimeStoreError> {
    let mut message = Vec::with_capacity(256);
    message.extend_from_slice(&database_id);
    encode_optional_ledger_sequence(&mut message, ledger.catalog_high_water.as_deref());
    message.extend_from_slice(&ledger.conversation_count.to_be_bytes());
    message.extend_from_slice(&ledger.command_count.to_be_bytes());
    message.extend_from_slice(&ledger.event_count.to_be_bytes());
    message.extend_from_slice(&ledger.intent_count.to_be_bytes());
    message.extend_from_slice(&ledger.fence_count.to_be_bytes());
    message.extend_from_slice(&ledger.codex_adapter_state_count.to_be_bytes());
    message.extend_from_slice(&ledger.claude_code_adapter_state_count.to_be_bytes());
    message.extend_from_slice(&ledger.approval_count.to_be_bytes());
    message.extend_from_slice(&ledger.active_approval_count.to_be_bytes());
    message.extend_from_slice(&ledger.audit_event_logical_bytes.to_be_bytes());
    message.extend_from_slice(&ledger.event_stream_count.to_be_bytes());
    message.extend_from_slice(&ledger.event_stream_bytes.to_be_bytes());
    message.extend_from_slice(&ledger.catalog_delta_count.to_be_bytes());
    message.extend_from_slice(&ledger.catalog_delta_bytes.to_be_bytes());
    encode_optional_ledger_sequence(&mut message, ledger.catalog_retention_floor.as_deref());
    message.extend_from_slice(&ledger.snapshot_count.to_be_bytes());
    message.extend_from_slice(&ledger.snapshot_bytes.to_be_bytes());
    message.extend_from_slice(&ledger.publication_stream_count.to_be_bytes());
    message.extend_from_slice(&ledger.publication_outbox_count.to_be_bytes());
    message.extend_from_slice(&ledger.publication_outbox_bytes.to_be_bytes());
    message.extend_from_slice(&ledger.accepted_count.to_be_bytes());
    message.extend_from_slice(&ledger.accepted_payload_bytes.to_be_bytes());
    message.extend_from_slice(&ledger.started_without_fence_count.to_be_bytes());
    message.extend_from_slice(&ledger.started_without_release_count.to_be_bytes());
    message.extend_from_slice(&ledger.started_released_count.to_be_bytes());
    let token = key_bundle.blind_index(b"runtime.meta.ledger.v4", &message)?;
    Ok(*token.as_bytes())
}

fn encode_optional_ledger_sequence(message: &mut Vec<u8>, value: Option<&str>) {
    match value {
        None => message.push(0),
        Some(value) => {
            message.push(1);
            message.extend_from_slice(value.as_bytes());
        }
    }
}

fn runtime_ledger_token_v2(
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    ledger: &RuntimeLedger,
) -> Result<[u8; 32], RuntimeStoreError> {
    let mut message = Vec::with_capacity(133);
    message.extend_from_slice(&database_id);
    match ledger.catalog_high_water.as_deref() {
        None => message.push(0),
        Some(value) => {
            message.push(1);
            message.extend_from_slice(value.as_bytes());
        }
    }
    message.extend_from_slice(&ledger.conversation_count.to_be_bytes());
    message.extend_from_slice(&ledger.command_count.to_be_bytes());
    message.extend_from_slice(&ledger.event_count.to_be_bytes());
    message.extend_from_slice(&ledger.intent_count.to_be_bytes());
    message.extend_from_slice(&ledger.fence_count.to_be_bytes());
    message.extend_from_slice(&ledger.codex_adapter_state_count.to_be_bytes());
    message.extend_from_slice(&ledger.claude_code_adapter_state_count.to_be_bytes());
    message.extend_from_slice(&ledger.accepted_count.to_be_bytes());
    message.extend_from_slice(&ledger.accepted_payload_bytes.to_be_bytes());
    message.extend_from_slice(&ledger.started_without_fence_count.to_be_bytes());
    message.extend_from_slice(&ledger.started_without_release_count.to_be_bytes());
    message.extend_from_slice(&ledger.started_released_count.to_be_bytes());
    let token = key_bundle.blind_index(b"runtime.meta.ledger.v2", &message)?;
    Ok(*token.as_bytes())
}

fn runtime_ledger_token_v1(
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    ledger: &RuntimeLedger,
) -> Result<[u8; 32], RuntimeStoreError> {
    let mut message = Vec::with_capacity(117);
    message.extend_from_slice(&database_id);
    match ledger.catalog_high_water.as_deref() {
        None => message.push(0),
        Some(value) => {
            message.push(1);
            message.extend_from_slice(value.as_bytes());
        }
    }
    message.extend_from_slice(&ledger.conversation_count.to_be_bytes());
    message.extend_from_slice(&ledger.command_count.to_be_bytes());
    message.extend_from_slice(&ledger.event_count.to_be_bytes());
    message.extend_from_slice(&ledger.intent_count.to_be_bytes());
    message.extend_from_slice(&ledger.fence_count.to_be_bytes());
    message.extend_from_slice(&ledger.accepted_count.to_be_bytes());
    message.extend_from_slice(&ledger.accepted_payload_bytes.to_be_bytes());
    message.extend_from_slice(&ledger.started_without_fence_count.to_be_bytes());
    message.extend_from_slice(&ledger.started_without_release_count.to_be_bytes());
    message.extend_from_slice(&ledger.started_released_count.to_be_bytes());
    let token = key_bundle.blind_index(b"runtime.meta.ledger.v1", &message)?;
    Ok(*token.as_bytes())
}

fn verify_runtime_ledger_token(
    key_bundle: &RuntimeKeyBundle,
    meta: &MetaRow,
) -> Result<(), RuntimeStoreError> {
    let expected = runtime_ledger_token(key_bundle, meta.database_id, &meta.ledger)?;
    if meta.metadata_token.as_slice() != expected {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(())
}

fn verify_runtime_ledger_token_v1(
    key_bundle: &RuntimeKeyBundle,
    meta: &MetaRow,
) -> Result<(), RuntimeStoreError> {
    let expected = runtime_ledger_token_v1(key_bundle, meta.database_id, &meta.ledger)?;
    if meta.metadata_token.as_slice() != expected {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(())
}

fn verify_runtime_ledger_token_v2(
    key_bundle: &RuntimeKeyBundle,
    meta: &MetaRow,
) -> Result<(), RuntimeStoreError> {
    let expected = runtime_ledger_token_v2(key_bundle, meta.database_id, &meta.ledger)?;
    if meta.metadata_token.as_slice() != expected {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(())
}

fn verify_runtime_ledger_token_v3(
    key_bundle: &RuntimeKeyBundle,
    meta: &MetaRow,
) -> Result<(), RuntimeStoreError> {
    let expected = runtime_ledger_token_v3(key_bundle, meta.database_id, &meta.ledger)?;
    if meta.metadata_token.as_slice() != expected {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(())
}

pub(crate) fn load_runtime_ledger(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
) -> Result<RuntimeLedger, RuntimeStoreError> {
    let (family, version) = read_schema_header(connection)?;
    if family != RUNTIME_SCHEMA_FAMILY {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let meta = match version {
        2 => read_meta_v2(connection)?,
        3 => read_meta_v3(connection)?,
        RUNTIME_SCHEMA_VERSION => read_meta(connection)?,
        _ => return Err(RuntimeStoreError::UnknownOrCorruptSchema),
    }
    .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    if meta.database_id != database_id {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    match version {
        2 => verify_runtime_ledger_token_v2(key_bundle, &meta)?,
        3 => verify_runtime_ledger_token_v3(key_bundle, &meta)?,
        RUNTIME_SCHEMA_VERSION => verify_runtime_ledger_token(key_bundle, &meta)?,
        _ => unreachable!("version matched above"),
    }
    Ok(meta.ledger)
}

pub(crate) fn update_runtime_ledger(
    transaction: &Transaction<'_>,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    previous: &RuntimeLedger,
    next: &RuntimeLedger,
) -> Result<(), RuntimeStoreError> {
    let reconciled_next = super::stream::reconcile_event_stream(
        transaction,
        key_bundle,
        database_id,
        previous,
        next,
    )?;
    let reconciled_next = super::catalog::reconcile_catalog_journal(
        transaction,
        key_bundle,
        database_id,
        previous,
        &reconciled_next,
    )?;
    let next = &reconciled_next;
    let previous_token = runtime_ledger_token(key_bundle, database_id, previous)?;
    let next_token = runtime_ledger_token(key_bundle, database_id, next)?;
    if transaction.execute(
        "UPDATE runtime_meta
         SET catalog_high_water = ?1, conversation_count = ?2, command_count = ?3,
             event_count = ?4, intent_count = ?5, fence_count = ?6,
             codex_adapter_state_count = ?7, claude_code_adapter_state_count = ?8,
             approval_count = ?9, active_approval_count = ?10,
             audit_event_logical_bytes = ?11,
             event_stream_count = ?12, event_stream_bytes = ?13,
             catalog_delta_count = ?14, catalog_delta_bytes = ?15,
             catalog_retention_floor = ?16,
             snapshot_count = ?17, snapshot_bytes = ?18,
             publication_stream_count = ?19,
             publication_outbox_count = ?20, publication_outbox_bytes = ?21,
             accepted_count = ?22, accepted_payload_bytes = ?23,
             started_without_fence_count = ?24, started_without_release_count = ?25,
             started_released_count = ?26, metadata_token = ?27
         WHERE singleton = 1 AND metadata_token = ?28",
        params![
            next.catalog_high_water.as_deref(),
            i64::try_from(next.conversation_count)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            i64::try_from(next.command_count)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            i64::try_from(next.event_count)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            i64::try_from(next.intent_count)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            i64::try_from(next.fence_count)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            i64::try_from(next.codex_adapter_state_count)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            i64::try_from(next.claude_code_adapter_state_count)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            i64::try_from(next.approval_count)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            i64::try_from(next.active_approval_count)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            i64::try_from(next.audit_event_logical_bytes)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            i64::try_from(next.event_stream_count)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            i64::try_from(next.event_stream_bytes)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            i64::try_from(next.catalog_delta_count)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            i64::try_from(next.catalog_delta_bytes)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            next.catalog_retention_floor.as_deref(),
            i64::try_from(next.snapshot_count)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            i64::try_from(next.snapshot_bytes)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            i64::try_from(next.publication_stream_count)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            i64::try_from(next.publication_outbox_count)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            i64::try_from(next.publication_outbox_bytes)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            i64::try_from(next.accepted_count)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            i64::try_from(next.accepted_payload_bytes)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            i64::try_from(next.started_without_fence_count)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            i64::try_from(next.started_without_release_count)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            i64::try_from(next.started_released_count)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            &next_token[..],
            &previous_token[..],
        ],
    )? != 1
    {
        return Err(RuntimeStoreError::SchemaInspectionRaced);
    }
    Ok(())
}

pub(crate) fn commit_transaction(
    mut transaction: Transaction<'_>,
    operation: RuntimeCommitOperation,
) -> Result<(), RuntimeStoreError> {
    match transaction.execute_batch("COMMIT") {
        Ok(()) => {
            transaction.set_drop_behavior(DropBehavior::Ignore);
            Ok(())
        }
        Err(commit_error) => {
            if transaction.is_autocommit() {
                transaction.set_drop_behavior(DropBehavior::Ignore);
                return Err(RuntimeStoreError::CommitOutcomeUnknown { operation });
            }
            let rollback_succeeded = transaction.execute_batch("ROLLBACK").is_ok();
            let definitely_rolled_back = rollback_succeeded && transaction.is_autocommit();
            transaction.set_drop_behavior(DropBehavior::Ignore);
            if definitely_rolled_back {
                Err(RuntimeStoreError::Sqlite(commit_error))
            } else {
                Err(RuntimeStoreError::CommitOutcomeUnknown { operation })
            }
        }
    }
}

pub(crate) fn record_machine_enrollment_receipt(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    receipt: MachineEnrollmentReceiptRecord,
) -> Result<MachineEnrollmentReceiptRecord, RuntimeStoreError> {
    let existing: Option<Vec<u8>> = state
        .connection
        .query_row(
            "SELECT root_fingerprint
             FROM machine_enrollment_receipts
             WHERE relay_server_id = ?1 AND machine_route = ?2",
            params![&receipt.relay_server_id[..], &receipt.machine_route[..]],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(existing) = existing {
        if existing.as_slice() == receipt.root_fingerprint {
            return Ok(receipt);
        }
        return Err(RuntimeStoreError::RescueReceiptConflict);
    }
    admit_safety_write(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        &state.storage_path,
        config.capacity_probe.as_ref(),
    )?;
    let transaction = state
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute(
        "INSERT INTO machine_enrollment_receipts (
             relay_server_id, machine_route, root_fingerprint
         ) VALUES (?1, ?2, ?3)
         ON CONFLICT(relay_server_id, machine_route) DO NOTHING",
        params![
            &receipt.relay_server_id[..],
            &receipt.machine_route[..],
            &receipt.root_fingerprint[..],
        ],
    )?;
    let existing: Vec<u8> = transaction.query_row(
        "SELECT root_fingerprint
         FROM machine_enrollment_receipts
         WHERE relay_server_id = ?1 AND machine_route = ?2",
        params![&receipt.relay_server_id[..], &receipt.machine_route[..]],
        |row| row.get(0),
    )?;
    if existing.as_slice() != receipt.root_fingerprint {
        return Err(RuntimeStoreError::RescueReceiptConflict);
    }
    config
        .fault_injector
        .before_operation(RuntimeStoreOperation::RecordEnrollmentReceiptBeforeCommit)?;
    commit_transaction(transaction, RuntimeCommitOperation::RecordEnrollmentReceipt)?;
    latch_post_commit_capacity(state, config);
    config
        .fault_injector
        .before_operation(RuntimeStoreOperation::RecordEnrollmentReceiptAfterCommit)
        .map_err(|_| RuntimeStoreError::CommitOutcomeUnknown {
            operation: RuntimeCommitOperation::RecordEnrollmentReceipt,
        })?;
    Ok(receipt)
}

pub(crate) fn read_rescue_index(
    storage_path: &Path,
) -> Result<Vec<MachineEnrollmentReceiptRecord>, RuntimeStoreError> {
    let storage_path = normalize_storage_path(storage_path)?;
    let metadata =
        preflight_store_files(&storage_path)?.ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    if metadata.len() == 0 {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    // 无 WAL 时用 immutable 只读打开；存在已提交 WAL 时复制 main+WAL 到
    // 私有临时目录并只在副本上恢复，保证原始三文件字节不变。
    let original_identity = capture_store_identity(&storage_path)?;
    let rescue = open_rescue_connection(&storage_path)?;
    let connection = rescue.connection();
    configure_defensive_limits(connection)
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    connection
        .pragma_update(None, "query_only", true)
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    connection
        .pragma_update(None, "trusted_schema", false)
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let (family, version) = read_schema_header(connection)?;
    match (family.as_str(), version) {
        (RUNTIME_SCHEMA_FAMILY, 1) => {
            read_and_validate_legacy_v1_schema(connection)?;
        }
        (RUNTIME_SCHEMA_FAMILY, 2) => {
            read_and_validate_legacy_v2_schema(connection)?;
        }
        (RUNTIME_SCHEMA_FAMILY, 3) => {
            read_and_validate_legacy_v3_schema(connection)?;
        }
        (RUNTIME_SCHEMA_FAMILY, RUNTIME_SCHEMA_VERSION) => {
            read_and_validate_current_schema(connection)?;
        }
        _ => return Err(RuntimeStoreError::UnknownOrCorruptSchema),
    }
    let mut statement = connection.prepare(
        "SELECT relay_server_id, machine_route, root_fingerprint
         FROM machine_enrollment_receipts
         ORDER BY relay_server_id, machine_route",
    )?;
    let raw = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let mut receipts = Vec::with_capacity(raw.len());
    for (relay_server_id, machine_route, root_fingerprint) in raw {
        receipts.push(MachineEnrollmentReceiptRecord {
            relay_server_id: relay_server_id
                .try_into()
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            machine_route: machine_route
                .try_into()
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            root_fingerprint: root_fingerprint
                .try_into()
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
        });
    }
    validate_store_files(&storage_path)?;
    ensure_store_identity(&storage_path, &original_identity)?;
    Ok(receipts)
}

fn open_rescue_connection(storage_path: &Path) -> Result<RescueConnection, RuntimeStoreError> {
    let wal = sidecar(storage_path, "-wal");
    let has_committed_wal = match fs::metadata(&wal) {
        Ok(metadata) => metadata.len() > 0,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(error.into()),
    };
    if !has_committed_wal {
        return Ok(RescueConnection {
            connection: Some(
                open_immutable_read_only(storage_path)
                    .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            ),
            temporary_root: None,
        });
    }

    let temporary_root = create_rescue_temporary_root(storage_path)?;
    let copy_path = temporary_root.join("runtime.db");
    let result = (|| {
        copy_private_artifact(storage_path, &copy_path)?;
        copy_private_artifact(&wal, &sidecar(&copy_path, "-wal"))?;
        let connection = open_read_write(&copy_path)?;
        configure_defensive_limits(&connection)?;
        Ok(RescueConnection {
            connection: Some(connection),
            temporary_root: Some(temporary_root.clone()),
        })
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&temporary_root);
    }
    result
}

fn create_rescue_temporary_root(storage_path: &Path) -> Result<PathBuf, RuntimeStoreError> {
    let parent = storage_path
        .parent()
        .ok_or(RuntimeStoreError::PathNotAbsolute)?;
    let file_name = storage_path
        .file_name()
        .ok_or(RuntimeStoreError::PathNotAbsolute)?
        .to_string_lossy();
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random)
        .map_err(|_| RuntimeStoreError::InvalidConfig("OS entropy unavailable"))?;
    let suffix = random
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let root = parent.join(format!(".{file_name}.rescue-{suffix}"));
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(DIRECTORY_MODE);
    }
    builder.create(&root)?;
    validate_private_directory(&root)?;
    sync_parent_directory(&root)?;
    Ok(root)
}

fn copy_private_artifact(source: &Path, destination: &Path) -> Result<(), RuntimeStoreError> {
    fs::copy(source, destination)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(destination, fs::Permissions::from_mode(DATABASE_MODE))?;
    }
    validate_database_file(destination)?;
    OpenOptions::new()
        .read(true)
        .open(destination)?
        .sync_all()?;
    Ok(())
}

fn preflight_store_files(database: &Path) -> Result<Option<fs::Metadata>, RuntimeStoreError> {
    let database_metadata = match fs::symlink_metadata(database) {
        Ok(metadata) => {
            validate_artifact_metadata(database, &metadata)?;
            Some(metadata)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    let mut has_sidecar = false;
    for path in [sidecar(database, "-wal"), sidecar(database, "-shm")] {
        match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                has_sidecar = true;
                validate_artifact_metadata(&path, &metadata)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    if database_metadata.is_none() && has_sidecar {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    if database_metadata
        .as_ref()
        .is_some_and(|metadata| metadata.len() == 0)
        && has_sidecar
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(database_metadata)
}

fn capture_store_identity(database: &Path) -> Result<StoreFileIdentity, RuntimeStoreError> {
    let database_metadata = fs::symlink_metadata(database)?;
    validate_artifact_metadata(database, &database_metadata)?;
    Ok(StoreFileIdentity {
        database: artifact_identity(&database_metadata),
        wal: capture_optional_artifact_identity(&sidecar(database, "-wal"))?,
        shm: capture_optional_artifact_identity(&sidecar(database, "-shm"))?,
    })
}

fn ensure_store_identity(
    database: &Path,
    expected: &StoreFileIdentity,
) -> Result<(), RuntimeStoreError> {
    if &capture_store_identity(database)? == expected {
        Ok(())
    } else {
        Err(RuntimeStoreError::SchemaInspectionRaced)
    }
}

fn capture_optional_artifact_identity(
    path: &Path,
) -> Result<Option<ArtifactIdentity>, RuntimeStoreError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            validate_artifact_metadata(path, &metadata)?;
            Ok(Some(artifact_identity(&metadata)))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

#[cfg(unix)]
fn artifact_identity(metadata: &fs::Metadata) -> ArtifactIdentity {
    use std::os::unix::fs::MetadataExt;

    ArtifactIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        length: metadata.len(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
    }
}

#[cfg(not(unix))]
fn artifact_identity(metadata: &fs::Metadata) -> ArtifactIdentity {
    ArtifactIdentity {
        length: metadata.len(),
    }
}

fn validate_store_files(database: &Path) -> Result<(), RuntimeStoreError> {
    validate_database_file(database)?;
    for sidecar in [sidecar(database, "-wal"), sidecar(database, "-shm")] {
        match fs::symlink_metadata(&sidecar) {
            Ok(metadata) => validate_artifact_metadata(&sidecar, &metadata)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn validate_database_file(path: &Path) -> Result<(), RuntimeStoreError> {
    let metadata = fs::symlink_metadata(path)?;
    validate_artifact_metadata(path, &metadata)
}

fn validate_artifact_metadata(
    path: &Path,
    metadata: &fs::Metadata,
) -> Result<(), RuntimeStoreError> {
    if metadata.file_type().is_symlink() {
        return Err(RuntimeStoreError::SymlinkRejected {
            path: path.to_path_buf(),
        });
    }
    validate_database_metadata(path, metadata)
}

#[cfg(unix)]
fn validate_database_metadata(
    path: &Path,
    metadata: &fs::Metadata,
) -> Result<(), RuntimeStoreError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    if !metadata.file_type().is_file() {
        return Err(RuntimeStoreError::NotRegularFile {
            path: path.to_path_buf(),
        });
    }
    // SAFETY: geteuid has no preconditions and reads only process identity.
    let uid = unsafe { libc::geteuid() };
    if metadata.uid() != uid
        || metadata.permissions().mode() & 0o7777 != DATABASE_MODE
        || metadata.nlink() != 1
    {
        return Err(RuntimeStoreError::UnsafeFile {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_database_metadata(
    path: &Path,
    metadata: &fs::Metadata,
) -> Result<(), RuntimeStoreError> {
    if !metadata.file_type().is_file() {
        return Err(RuntimeStoreError::NotRegularFile {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

#[cfg(unix)]
fn validate_private_directory(path: &Path) -> Result<(), RuntimeStoreError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let metadata = fs::symlink_metadata(path)?;
    // SAFETY: geteuid has no preconditions and reads only process identity.
    let uid = unsafe { libc::geteuid() };
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != uid
        || metadata.permissions().mode() & 0o7777 != DIRECTORY_MODE
    {
        return Err(RuntimeStoreError::UnsafeFile {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_private_directory(path: &Path) -> Result<(), RuntimeStoreError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(RuntimeStoreError::UnsafeFile {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

fn temporary_database_path(storage_path: &Path) -> Result<PathBuf, RuntimeStoreError> {
    let file_name = storage_path
        .file_name()
        .ok_or(RuntimeStoreError::PathNotAbsolute)?
        .to_string_lossy();
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random)
        .map_err(|_| RuntimeStoreError::InvalidConfig("OS entropy unavailable"))?;
    let suffix = random
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok(storage_path.with_file_name(format!(".{file_name}.init-{suffix}")))
}

fn cleanup_temporary_database(path: &Path) {
    for candidate in [
        path.to_path_buf(),
        sidecar(path, "-journal"),
        sidecar(path, "-wal"),
        sidecar(path, "-shm"),
    ] {
        let _ = fs::remove_file(candidate);
    }
}

fn cleanup_stale_initializers(storage_path: &Path) -> Result<(), RuntimeStoreError> {
    let parent = storage_path
        .parent()
        .ok_or(RuntimeStoreError::PathNotAbsolute)?;
    let file_name = storage_path
        .file_name()
        .ok_or(RuntimeStoreError::PathNotAbsolute)?
        .to_string_lossy();
    let prefix = format!(".{file_name}.init-");
    let mut removed = false;
    for entry in fs::read_dir(parent)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(rest) = name.strip_prefix(&prefix) else {
            continue;
        };
        let random = ["-journal", "-wal", "-shm"]
            .into_iter()
            .find_map(|suffix| rest.strip_suffix(suffix))
            .unwrap_or(rest);
        if random.len() != 32 || !random.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            continue;
        }
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        validate_artifact_metadata(&path, &metadata)?;
        fs::remove_file(path)?;
        removed = true;
    }
    if removed {
        sync_parent_directory(storage_path)?;
    }
    Ok(())
}

#[cfg(unix)]
fn open_immutable_read_only(path: &Path) -> Result<Connection, rusqlite::Error> {
    use std::os::unix::ffi::OsStrExt;

    let mut uri = String::from("file:");
    for byte in path.as_os_str().as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(*byte, b'/' | b'.' | b'_' | b'-' | b'~') {
            uri.push(char::from(*byte));
        } else {
            use std::fmt::Write as _;
            let _ = write!(uri, "%{byte:02X}");
        }
    }
    uri.push_str("?immutable=1&mode=ro");
    Connection::open_with_flags(
        uri,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW
            | OpenFlags::SQLITE_OPEN_URI,
    )
}

#[cfg(not(unix))]
fn open_immutable_read_only(path: &Path) -> Result<Connection, rusqlite::Error> {
    Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
}

#[cfg(unix)]
fn sync_parent_directory(path: &Path) -> Result<(), RuntimeStoreError> {
    use std::os::unix::fs::OpenOptionsExt;

    let parent = path.parent().ok_or(RuntimeStoreError::PathNotAbsolute)?;
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(parent)?;
    directory.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_parent_directory(path: &Path) -> Result<(), RuntimeStoreError> {
    let parent = path.parent().ok_or(RuntimeStoreError::PathNotAbsolute)?;
    OpenOptions::new().read(true).open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn rename_no_replace(from: &Path, to: &Path) -> Result<(), RuntimeStoreError> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let from = CString::new(from.as_os_str().as_bytes()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "runtime path contains NUL",
        )
    })?;
    let to = CString::new(to.as_os_str().as_bytes()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "runtime path contains NUL",
        )
    })?;
    #[cfg(target_os = "macos")]
    // SAFETY: both C strings are NUL-terminated and live for the duration of the call.
    let result = unsafe { libc::renamex_np(from.as_ptr(), to.as_ptr(), libc::RENAME_EXCL) };
    #[cfg(target_os = "linux")]
    // SAFETY: both C strings are NUL-terminated and live for the duration of the call.
    let result = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            from.as_ptr(),
            libc::AT_FDCWD,
            to.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result == 0 {
        return Ok(());
    }
    let error = std::io::Error::last_os_error();
    if error.kind() == std::io::ErrorKind::AlreadyExists {
        Err(RuntimeStoreError::SchemaInspectionRaced)
    } else {
        Err(error.into())
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn rename_no_replace(_from: &Path, _to: &Path) -> Result<(), RuntimeStoreError> {
    Err(RuntimeStoreError::InvalidConfig(
        "atomic no-replace database publish is unsupported on this platform",
    ))
}

fn sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;
    use crate::runtime::model::RuntimeCapacityProbeError;

    static NEXT_TEST_ID: AtomicU64 = AtomicU64::new(1);

    #[derive(Clone, Copy)]
    struct FixedProbe(RuntimeCapacityObservation);

    impl RuntimeCapacityProbe for FixedProbe {
        fn observe(
            &self,
            _database: &Path,
        ) -> Result<RuntimeCapacityObservation, RuntimeCapacityProbeError> {
            Ok(self.0)
        }
    }

    struct TestDatabase {
        path: PathBuf,
    }

    impl TestDatabase {
        fn new(label: &str) -> Self {
            let sequence = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);
            let path = Path::new("/tmp").join(format!(
                "agentdeckd-runtime-checkpoint-{label}-{}-{sequence}.db",
                std::process::id()
            ));
            for artifact in [path.clone(), sidecar(&path, "-wal"), sidecar(&path, "-shm")] {
                let _ = fs::remove_file(artifact);
            }
            Self { path }
        }
    }

    impl Drop for TestDatabase {
        fn drop(&mut self) {
            for artifact in [
                self.path.clone(),
                sidecar(&self.path, "-wal"),
                sidecar(&self.path, "-shm"),
            ] {
                let _ = fs::remove_file(artifact);
            }
        }
    }

    fn near_checkpoint_threshold() -> RuntimeCapacityObservation {
        RuntimeCapacityObservation {
            main_bytes: CHECKPOINT_TRIGGER_BYTES - 4 * 1024 * 1024,
            wal_bytes: 2 * 1024 * 1024,
            shm_bytes: 32 * 1024,
            filesystem_total_bytes: 100 * 1024 * 1024 * 1024,
            filesystem_available_bytes: 50 * 1024 * 1024 * 1024,
        }
    }

    fn wal_writer(path: &Path) -> Connection {
        let connection = Connection::open(path).expect("open checkpoint test database");
        connection
            .execute_batch(
                "PRAGMA journal_mode = WAL;
                 PRAGMA wal_autocheckpoint = 0;
                 CREATE TABLE payloads (id INTEGER PRIMARY KEY, payload BLOB NOT NULL);
                 INSERT INTO payloads(payload) VALUES (zeroblob(8192));",
            )
            .expect("initialize checkpoint WAL");
        configure_max_page_count(&connection).expect("configure checkpoint page budget");
        connection
    }

    fn ledger_with_active_approvals(active_approval_count: u64) -> RuntimeLedger {
        RuntimeLedger {
            catalog_high_water: None,
            conversation_count: 0,
            command_count: 0,
            event_count: 0,
            intent_count: 0,
            fence_count: 0,
            codex_adapter_state_count: 0,
            claude_code_adapter_state_count: 0,
            approval_count: active_approval_count,
            active_approval_count,
            accepted_count: 0,
            accepted_payload_bytes: 0,
            started_without_fence_count: 0,
            started_without_release_count: 0,
            started_released_count: 0,
            ..RuntimeLedger::default()
        }
    }

    #[test]
    fn current_and_migration_reserve_include_every_active_approval_exactly() {
        let ledger = ledger_with_active_approvals(2);
        assert_eq!(
            safety_reserve_bytes_for_ledger(&ledger).expect("current/migration reserve"),
            FIXED_SAFETY_RESERVE_BYTES + 2 * 1024 * 1024
        );
    }

    #[test]
    fn register_approval_projection_pre_reserves_one_additional_terminal_closure() {
        let ledger = ledger_with_active_approvals(2);
        let current =
            safety_reserve_bytes_for_ledger_projection(&ledger, SafetyReserveProjection::Current)
                .expect("current reserve");
        let register = safety_reserve_bytes_for_ledger_projection(
            &ledger,
            SafetyReserveProjection::RegisterApproval,
        )
        .expect("register projection reserve");
        assert_eq!(register, current + MAX_APPROVAL_TERMINATION_RESERVE_BYTES);
    }

    #[test]
    fn active_approval_reserve_is_exact_at_the_1024_schema_limit() {
        let ledger = ledger_with_active_approvals(1024);
        assert_eq!(
            safety_reserve_bytes_for_ledger(&ledger).expect("maximum active approval reserve"),
            FIXED_SAFETY_RESERVE_BYTES + 1024 * 1024 * 1024
        );
    }

    #[test]
    fn active_approval_reserve_multiplication_overflow_fails_closed() {
        let ledger = ledger_with_active_approvals(u64::MAX);
        assert!(matches!(
            safety_reserve_bytes_for_ledger(&ledger),
            Err(RuntimeStoreError::CapacityArithmeticOverflow {
                field: "active_approval_safety_reserve"
            })
        ));
    }

    #[test]
    fn register_approval_projection_count_overflow_fails_closed() {
        let ledger = ledger_with_active_approvals(u64::MAX);
        assert!(matches!(
            safety_reserve_bytes_for_ledger_projection(
                &ledger,
                SafetyReserveProjection::RegisterApproval,
            ),
            Err(RuntimeStoreError::CapacityArithmeticOverflow {
                field: "active_approval_safety_count"
            })
        ));
    }

    #[test]
    fn low_space_rejects_ordinary_register_while_current_safety_terminal_stays_admissible() {
        let ledger = ledger_with_active_approvals(1);
        let current = safety_reserve_bytes_for_ledger(&ledger).expect("current safety reserve");
        let register = safety_reserve_bytes_for_ledger_projection(
            &ledger,
            SafetyReserveProjection::RegisterApproval,
        )
        .expect("register projection reserve");
        let page_size_bytes = 4096;
        let common = RuntimeAdmissionInput {
            main_bytes: 0,
            wal_bytes: 0,
            shm_bytes: 0,
            projected_write_bytes: 0,
            safety_margin_bytes: register + RUNTIME_WRITE_SAFETY_MARGIN_BYTES,
            filesystem_total_bytes: 4 * 1024 * 1024 * 1024,
            filesystem_available_bytes: current,
            page_size_bytes,
            page_count: 0,
            max_page_count: RUNTIME_DB_HARD_LIMIT_BYTES / page_size_bytes,
        };
        assert!(matches!(
            evaluate_runtime_admission(common),
            Err(AdmissionRejection::DiskLow { .. })
        ));
        evaluate_runtime_safety_admission(RuntimeAdmissionInput {
            safety_margin_bytes: current,
            ..common
        })
        .expect("the already reserved terminal safety write remains admissible");
    }

    #[test]
    fn bounded_passive_checkpoint_fails_closed_while_a_reader_pins_old_wal_frames() {
        let database = TestDatabase::new("pinned-reader");
        let writer = wal_writer(&database.path);
        let reader = Connection::open(&database.path).expect("open checkpoint reader");
        reader
            .execute_batch("BEGIN DEFERRED")
            .expect("begin reader transaction");
        let _: i64 = reader
            .query_row("SELECT COUNT(*) FROM payloads", [], |row| row.get(0))
            .expect("pin reader snapshot");
        writer
            .execute_batch(
                "BEGIN IMMEDIATE;
                 UPDATE payloads SET payload = zeroblob(16384) WHERE id = 1;
                 INSERT INTO payloads(payload) VALUES (zeroblob(16384));
                 COMMIT;",
            )
            .expect("append WAL frames newer than reader snapshot");

        let error = evaluate_ordinary_capacity_with_checkpoint(
            &writer,
            &database.path,
            &FixedProbe(near_checkpoint_threshold()),
            1024 * 1024,
            1024 * 1024,
        )
        .expect_err("partial checkpoint near the hard threshold must fail closed");
        assert!(matches!(
            error,
            RuntimeStoreError::CheckpointBlocked {
                log_frames,
                checkpointed_frames,
            } if log_frames > 0 && checkpointed_frames < log_frames
        ));
        reader
            .execute_batch("ROLLBACK")
            .expect("release reader snapshot");
    }

    #[test]
    fn bounded_passive_checkpoint_allows_admission_after_all_frames_are_checkpointed() {
        let database = TestDatabase::new("fully-checkpointed");
        let writer = wal_writer(&database.path);
        evaluate_ordinary_capacity_with_checkpoint(
            &writer,
            &database.path,
            &FixedProbe(near_checkpoint_threshold()),
            1024 * 1024,
            1024 * 1024,
        )
        .expect("complete passive checkpoint keeps the bounded write admissible");
    }

    #[test]
    fn rejected_admission_has_zero_checkpoint_side_effects_even_when_wal_trigger_is_set() {
        let database = TestDatabase::new("rejected-before-checkpoint");
        let writer = wal_writer(&database.path);
        let wal_path = sidecar(&database.path, "-wal");
        let shm_path = sidecar(&database.path, "-shm");
        let main_before = fs::read(&database.path).expect("read main before rejection");
        let wal_before = fs::read(&wal_path).expect("read WAL before rejection");
        let shm_before = fs::read(&shm_path).expect("read SHM before rejection");
        let mut low_disk = near_checkpoint_threshold();
        low_disk.wal_bytes = WAL_CHECKPOINT_TRIGGER_BYTES;
        low_disk.filesystem_total_bytes = 4 * 1024 * 1024 * 1024;
        low_disk.filesystem_available_bytes = 512 * 1024 * 1024;

        let error = evaluate_ordinary_capacity_with_checkpoint(
            &writer,
            &database.path,
            &FixedProbe(low_disk),
            1024 * 1024,
            1024 * 1024,
        )
        .expect_err("low disk must reject before checkpoint executes");
        assert!(matches!(error, RuntimeStoreError::DiskLow { .. }));
        assert_eq!(
            fs::read(&database.path).expect("read main after rejection"),
            main_before,
            "rejected admission must not copy WAL pages into main"
        );
        assert_eq!(
            fs::read(&wal_path).expect("read WAL after rejection"),
            wal_before,
            "rejected admission must not mutate WAL"
        );
        assert_eq!(
            fs::read(&shm_path).expect("read SHM after rejection"),
            shm_before,
            "rejected admission must not advance checkpoint state in SHM"
        );
    }

    #[test]
    fn checkpoint_copy_peak_rejection_is_zero_side_effect_after_base_admission_passes() {
        let database = TestDatabase::new("checkpoint-copy-peak");
        let writer = wal_writer(&database.path);
        let wal_path = sidecar(&database.path, "-wal");
        let shm_path = sidecar(&database.path, "-shm");
        let main_before = fs::read(&database.path).expect("read main before peak rejection");
        let wal_before = fs::read(&wal_path).expect("read WAL before peak rejection");
        let shm_before = fs::read(&shm_path).expect("read SHM before peak rejection");
        let observation = RuntimeCapacityObservation {
            main_bytes: 1_700 * 1024 * 1024,
            wal_bytes: 200 * 1024 * 1024,
            shm_bytes: 32 * 1024,
            filesystem_total_bytes: 100 * 1024 * 1024 * 1024,
            filesystem_available_bytes: 50 * 1024 * 1024 * 1024,
        };

        let error = evaluate_ordinary_capacity_with_checkpoint(
            &writer,
            &database.path,
            &FixedProbe(observation),
            1024 * 1024,
            1024 * 1024,
        )
        .expect_err("checkpoint WAL copy peak must stay below the physical hard limit");
        assert!(matches!(error, RuntimeStoreError::StoreFull { .. }));
        assert_eq!(fs::read(&database.path).unwrap(), main_before);
        assert_eq!(fs::read(&wal_path).unwrap(), wal_before);
        assert_eq!(fs::read(&shm_path).unwrap(), shm_before);
    }
}
