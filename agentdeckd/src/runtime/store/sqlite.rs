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
    EXPECTED_TABLES_V4, EXPECTED_TABLES_V5, EXPECTED_TABLES_V6, RUNTIME_CRYPTO_CONTEXT_VERSION,
    RUNTIME_DDL_V1, RUNTIME_KEY_GENERATION, RUNTIME_MIGRATION_V2, RUNTIME_MIGRATION_V3,
    RUNTIME_MIGRATION_V4, RUNTIME_MIGRATION_V5, RUNTIME_MIGRATION_V6, RUNTIME_MIGRATION_V7,
    RUNTIME_SCHEMA_FAMILY, RUNTIME_SCHEMA_VERSION, RUNTIME_SCHEMA_VERSION_V5,
    RUNTIME_SCHEMA_VERSION_V6, schema_signature, schema_signature_v1, schema_signature_v2,
    schema_signature_v3, schema_signature_v4, schema_signature_v5, schema_signature_v6,
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
/// 继续保留旧版“最大 result + 最大 event + 4 MiB closure”的保守尾部。
///
/// typed critical terminal 当前实际更小，但 fragmented DB + pinned WAL 的真实样本尚未同时
/// 覆盖近 2 GiB page tree 与每 turn 32 个 active approvals；在完整量化前不能用结构上限猜测
/// 更小 reserve。锁产物而非锁过程：后续若收窄，必须先记录真实 WAL/page 增量上界。
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
    // B4 先冻结 native claim 的物理 terminal reserve；真正 vendor claim 在 C0-C 接线。
    #[allow(dead_code)]
    ClaimMetadataMutation,
    AcceptAdminUpgrade,
}

#[cfg(test)]
mod migration_tests {
    use std::fs::{self, OpenOptions};
    use std::io::Read;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    use agentdeck_protocol::runtime::{
        ClaudeCodeConversationConfiguration, CodexConversationConfiguration,
        ConversationConfiguration, ConversationMetadataMutation, VendorConfigurationSnapshot,
    };
    use agentdeck_protocol::{
        AgentKind, ClaudeCodePermissionMode, CodexApprovalPolicy, CodexReasoningEffort,
        CodexSandboxMode,
    };
    use rusqlite::{Connection, params};

    use super::*;
    use crate::runtime::model::{
        AcceptCommand, AcceptOutcome, CommandExecutionConfiguration, CommandReceiptSelector,
        CommandState, ConversationDescriptor, ConversationLifecycle, ExecutionFence,
        IdempotencyOwner, MachineEnrollmentReceiptRecord, NewConversation, QueryCommandReceipt,
        RuntimeCapacityObservation, RuntimeCapacityProbe, RuntimeCapacityProbeError,
        RuntimeStoreFaultInjector, StartCommand, StartOutcome,
    };
    use crate::runtime::store::cipher::RowAad;
    use crate::runtime::store::identity::{RuntimeId, RuntimeIdKind};
    use crate::runtime::store::sequence::{SequenceScope, decode_sequence, encode_sequence};
    use crate::runtime::store::worker::RuntimeStoreHandle;
    use crate::runtime::store::{
        ConfigureConversation, ConfigureConversationOutcome, ImportNativeProjection,
        ImportNativeProjectionOutcome, UpdateConversationMetadataOutcome,
        UpdateManagedConversationMetadata,
    };
    use crate::security::{MemoryKeyStore, SecretBytes, StorageKek, load_or_create_storage_kek};

    static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);
    const MAX_ARTIFACT_EVIDENCE_BYTES: u64 = 64 * 1024 * 1024;

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

    async fn configure_source_conversation(
        store: &RuntimeStoreHandle,
        conversation_id: RuntimeId,
        seed: u8,
    ) {
        assert!(matches!(
            store
                .configure_conversation(ConfigureConversation {
                    conversation_id,
                    owner: owner(seed),
                    idempotency_key: format!("legacy-source-configuration-{seed}"),
                    expected_configuration_revision: 0,
                    configuration: ConversationConfiguration::new(
                        VendorConfigurationSnapshot::Codex(
                            CodexConversationConfiguration::new(
                                CodexApprovalPolicy::OnRequest,
                                CodexSandboxMode::WorkspaceWrite,
                                CodexReasoningEffort::Medium,
                            ),
                        ),
                    ),
                })
                .await
                .expect("configure current source conversation"),
            ConfigureConversationOutcome::Applied { configuration }
                if configuration.configuration_revision == 1 && configuration.event_seq == 0
        ));
    }

    fn fixture_runtime_id(kind: RuntimeIdKind, raw: Vec<u8>) -> RuntimeId {
        RuntimeId::from_bytes(
            kind,
            raw.try_into()
                .expect("strict legacy RuntimeId has 16 bytes"),
        )
        .expect("strict legacy RuntimeId kind")
    }

    fn fixture_optional_runtime_id(kind: RuntimeIdKind, raw: Option<Vec<u8>>) -> Option<RuntimeId> {
        raw.map(|value| fixture_runtime_id(kind, value))
    }

    fn rewrite_command_as_legacy_v1(
        connection: &Connection,
        key_bundle: &RuntimeKeyBundle,
        command_id: RuntimeId,
        payload: &[u8],
    ) {
        type RawCommand = (
            (
                Vec<u8>,
                String,
                String,
                i64,
                i64,
                i64,
                i64,
                Option<i64>,
                Option<i64>,
            ),
            (
                Option<Vec<u8>>,
                Option<Vec<u8>>,
                Option<Vec<u8>>,
                Vec<u8>,
                Vec<u8>,
                Option<Vec<u8>>,
            ),
        );
        let raw: RawCommand = connection
            .query_row(
                "SELECT conversation_id, command_seq, state, logical_payload_bytes,
                        accepted_at_ms, expires_at_ms, retain_until_ms,
                        started_at_ms, terminal_at_ms, turn_id, started_event_id,
                        terminal_event_id, owner_token, idempotency_token, terminal_token
                 FROM commands WHERE command_id = ?1",
                [&command_id.as_bytes()[..]],
                |row| {
                    Ok((
                        (
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                            row.get(5)?,
                            row.get(6)?,
                            row.get(7)?,
                            row.get(8)?,
                        ),
                        (
                            row.get(9)?,
                            row.get(10)?,
                            row.get(11)?,
                            row.get(12)?,
                            row.get(13)?,
                            row.get(14)?,
                        ),
                    ))
                },
            )
            .expect("read current command for strict v1 projection");
        let (
            (
                raw_conversation_id,
                command_seq_encoded,
                state,
                logical_payload_bytes,
                accepted_at_ms,
                expires_at_ms,
                retain_until_ms,
                started_at_ms,
                terminal_at_ms,
            ),
            (
                turn_id,
                started_event_id,
                terminal_event_id,
                owner_token,
                idempotency_token,
                terminal_token,
            ),
        ) = raw;
        let conversation_id = fixture_runtime_id(RuntimeIdKind::Conversation, raw_conversation_id);
        let command_seq = decode_sequence(SequenceScope::CommandSeq, &command_seq_encoded)
            .expect("strict legacy command sequence");
        let state = match state.as_str() {
            "accepted" => CommandState::Accepted,
            "started" => CommandState::Started,
            other => panic!("unexpected strict legacy command state {other}"),
        };
        assert_eq!(
            usize::try_from(logical_payload_bytes).expect("legacy payload length"),
            payload.len()
        );
        let payload_token =
            super::super::command_configuration::command_payload_token(key_bundle, 0, payload)
                .expect("authenticate strict v1 payload token");
        let logical_payload_bytes = u64::try_from(logical_payload_bytes)
            .expect("non-negative strict v1 logical payload bytes");
        let accepted_at_ms =
            u64::try_from(accepted_at_ms).expect("non-negative strict v1 accepted time");
        let expires_at_ms =
            u64::try_from(expires_at_ms).expect("non-negative strict v1 expiry time");
        let retain_until_ms =
            u64::try_from(retain_until_ms).expect("non-negative strict v1 retention time");
        let started_at_ms = started_at_ms
            .map(|value| u64::try_from(value).expect("non-negative strict v1 started time"));
        let terminal_at_ms = terminal_at_ms
            .map(|value| u64::try_from(value).expect("non-negative strict v1 terminal time"));
        let turn_id = fixture_optional_runtime_id(RuntimeIdKind::Turn, turn_id);
        let started_event_id = fixture_optional_runtime_id(RuntimeIdKind::Event, started_event_id);
        let terminal_event_id =
            fixture_optional_runtime_id(RuntimeIdKind::Event, terminal_event_id);
        let metadata_token = super::super::journal::command_metadata_token_for_test(
            key_bundle,
            conversation_id,
            command_id,
            command_seq,
            &owner_token,
            &idempotency_token,
            &payload_token,
            terminal_token.as_deref(),
            state,
            logical_payload_bytes,
            accepted_at_ms,
            expires_at_ms,
            retain_until_ms,
            started_at_ms,
            terminal_at_ms,
            turn_id,
            started_event_id,
            terminal_event_id,
        )
        .expect("authenticate strict v1 command metadata");
        assert_eq!(
            connection
                .execute(
                    "UPDATE commands SET payload_token = ?1, metadata_token = ?2
                    WHERE command_id = ?3",
                    params![
                        &payload_token[..],
                        &metadata_token[..],
                        &command_id.as_bytes()[..],
                    ],
                )
                .expect("publish strict v1 command authentication"),
            1
        );
    }

    fn rewrite_conversation_event_high_water(
        connection: &Connection,
        key_bundle: &RuntimeKeyBundle,
        conversation_id: RuntimeId,
        event_high_water: Option<u64>,
    ) {
        let raw = connection
            .query_row(
                "SELECT adapter_state_key, catalog_revision, command_high_water,
                        accepted_count, lifecycle, created_at_ms, updated_at_ms
                 FROM conversations WHERE conversation_id = ?1",
                [&conversation_id.as_bytes()[..]],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, i64>(6)?,
                    ))
                },
            )
            .expect("read current conversation for strict v1 projection");
        let adapter_state_key = fixture_runtime_id(RuntimeIdKind::AdapterState, raw.0);
        let catalog_revision = decode_sequence(SequenceScope::CatalogRevision, &raw.1)
            .expect("strict legacy catalog revision");
        let command_high_water = raw
            .2
            .as_deref()
            .map(|value| decode_sequence(SequenceScope::CommandSeq, value))
            .transpose()
            .expect("strict legacy command high water");
        let accepted_command_count =
            u32::try_from(raw.3).expect("strict legacy accepted command count");
        assert_eq!(raw.4, "active", "strict legacy conversation stays active");
        let created_at_ms = u64::try_from(raw.5).expect("strict legacy creation time");
        let updated_at_ms = u64::try_from(raw.6).expect("strict legacy update time");
        let metadata_token = super::super::journal::conversation_metadata_token_for_test(
            key_bundle,
            conversation_id,
            adapter_state_key,
            catalog_revision,
            command_high_water,
            event_high_water,
            accepted_command_count,
            ConversationLifecycle::Active,
            created_at_ms,
            updated_at_ms,
        )
        .expect("authenticate strict v1 conversation metadata");
        let event_high_water = event_high_water.map(encode_sequence);
        assert_eq!(
            connection
                .execute(
                    "UPDATE conversations SET event_high_water = ?1, metadata_token = ?2
                     WHERE conversation_id = ?3",
                    params![
                        event_high_water.as_deref(),
                        &metadata_token[..],
                        &conversation_id.as_bytes()[..],
                    ],
                )
                .expect("publish strict v1 conversation metadata"),
            1
        );
    }

    fn rewrite_started_event_as_legacy_seq_zero(
        connection: &Connection,
        key_bundle: &RuntimeKeyBundle,
        event_id: RuntimeId,
    ) {
        let raw = connection
            .query_row(
                "SELECT conversation_id, event_seq, command_id,
                        logical_event_bytes, created_at_ms
                 FROM event_journal WHERE event_id = ?1",
                [&event_id.as_bytes()[..]],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<Vec<u8>>>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                    ))
                },
            )
            .expect("read started event for strict v1 projection");
        let conversation_id = fixture_runtime_id(RuntimeIdKind::Conversation, raw.0);
        assert_eq!(
            decode_sequence(SequenceScope::EventSeq, &raw.1)
                .expect("current started event sequence"),
            1,
            "configuration event must be the only earlier source event"
        );
        let command_id = fixture_optional_runtime_id(RuntimeIdKind::Command, raw.2);
        let logical_event_bytes = u64::try_from(raw.3).expect("strict legacy logical event bytes");
        let created_at_ms = u64::try_from(raw.4).expect("strict legacy event time");
        let metadata_token = super::super::journal::event_metadata_token(
            key_bundle,
            conversation_id,
            event_id,
            0,
            command_id,
            logical_event_bytes,
            created_at_ms,
        )
        .expect("authenticate strict v1 event metadata");
        assert_eq!(
            connection
                .execute(
                    "UPDATE event_journal SET event_seq = ?1, metadata_token = ?2
                     WHERE event_id = ?3",
                    params![
                        encode_sequence(0),
                        &metadata_token[..],
                        &event_id.as_bytes()[..],
                    ],
                )
                .expect("publish strict v1 event sequence"),
            1
        );
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

    fn authenticated_blob_evidence(connection: &Connection) -> Vec<(String, Vec<Vec<u8>>)> {
        let mut columns = Vec::new();
        let tables = connection
            .prepare(
                "SELECT name FROM sqlite_schema
                 WHERE type = 'table' AND name NOT LIKE 'sqlite_%' AND name <> 'runtime_meta'
                 ORDER BY name",
            )
            .expect("prepare authenticated evidence tables")
            .query_map([], |row| row.get::<_, String>(0))
            .expect("query authenticated evidence tables")
            .collect::<Result<Vec<_>, _>>()
            .expect("collect authenticated evidence tables");
        for table in tables {
            let escaped_table = table.replace('"', "\"\"");
            let pragma = format!("PRAGMA table_info(\"{escaped_table}\")");
            let names = connection
                .prepare(&pragma)
                .expect("prepare authenticated evidence columns")
                .query_map([], |row| row.get::<_, String>(1))
                .expect("query authenticated evidence columns")
                .collect::<Result<Vec<_>, _>>()
                .expect("collect authenticated evidence columns");
            for column in names
                .into_iter()
                .filter(|name| name.contains("token") || name.starts_with("sealed_"))
            {
                let escaped_column = column.replace('"', "\"\"");
                let sql = format!(
                    "SELECT \"{escaped_column}\" FROM \"{escaped_table}\"
                     WHERE \"{escaped_column}\" IS NOT NULL ORDER BY rowid"
                );
                let values = collect_blobs(connection, &sql);
                if !values.is_empty() {
                    columns.push((format!("{table}.{column}"), values));
                }
            }
        }
        columns
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
        .map(|path| (path.clone(), read_artifact_evidence(&path)))
        .collect()
    }

    fn read_artifact_evidence(path: &Path) -> Option<Vec<u8>> {
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        }
        let file = match options.open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
            Err(error) => panic!("open runtime artifact {}: {error}", path.display()),
        };
        let metadata = file
            .metadata()
            .unwrap_or_else(|error| panic!("inspect open artifact {}: {error}", path.display()));
        assert!(
            metadata.file_type().is_file(),
            "runtime artifact must be a regular file: {}",
            path.display()
        );
        assert!(
            metadata.len() <= MAX_ARTIFACT_EVIDENCE_BYTES,
            "runtime artifact {} has {} bytes, exceeding the {}-byte test oracle cap",
            path.display(),
            metadata.len(),
            MAX_ARTIFACT_EVIDENCE_BYTES
        );
        let mut bytes = Vec::with_capacity(
            usize::try_from(metadata.len()).expect("bounded artifact length fits usize"),
        );
        let mut bounded = file.take(MAX_ARTIFACT_EVIDENCE_BYTES + 1);
        bounded
            .read_to_end(&mut bytes)
            .unwrap_or_else(|error| panic!("read open artifact {}: {error}", path.display()));
        assert!(
            bytes.len() as u64 <= MAX_ARTIFACT_EVIDENCE_BYTES,
            "runtime artifact {} grew beyond the {}-byte test oracle cap while reading",
            path.display(),
            MAX_ARTIFACT_EVIDENCE_BYTES
        );
        Some(bytes)
    }

    fn assert_main_and_wal_unchanged(
        before: &[(PathBuf, Option<Vec<u8>>)],
        after: &[(PathBuf, Option<Vec<u8>>)],
        label: &str,
    ) {
        assert_eq!(before.len(), after.len(), "{label}: artifact arity drifted");
        for index in 0..2 {
            assert_eq!(
                before[index],
                after[index],
                "{label}: {} drifted",
                before[index].0.display()
            );
        }
    }

    #[derive(Clone)]
    struct ReceiptIdentity {
        conversation_id: RuntimeId,
        command_id: RuntimeId,
        owner: IdempotencyOwner,
        idempotency_key: String,
    }

    struct MigratedStrictV1Fixture {
        root: TestRoot,
        keys: MemoryKeyStore,
        store: Option<RuntimeStoreHandle>,
        legacy_accepted: ReceiptIdentity,
    }

    impl MigratedStrictV1Fixture {
        async fn create(label: &str) -> Self {
            let root = TestRoot::new(label);
            let keys = MemoryKeyStore::new();
            build_strict_v1_fixture(&root, &keys).await;
            let store = RuntimeStoreHandle::open(
                RuntimeStoreConfig::new(root.database()),
                load_or_create_storage_kek(&keys, &root.database())
                    .expect("reload strict v1 tamper KEK"),
            )
            .await
            .expect("migrate strict v1 tamper fixture");
            assert_eq!(
                store
                    .inspect()
                    .await
                    .expect("inspect migrated strict v1 tamper fixture")
                    .schema_version,
                RUNTIME_SCHEMA_VERSION
            );

            let conversation_id = runtime_id(RuntimeIdKind::Conversation, 0x11);
            let legacy_owner = owner(1);
            let legacy_idempotency_key = "legacy-accepted".to_owned();
            let receipt = store
                .query_command_receipt(QueryCommandReceipt {
                    expected_owner: legacy_owner.clone(),
                    selector: CommandReceiptSelector::Idempotency {
                        conversation_id,
                        idempotency_key: legacy_idempotency_key.clone(),
                    },
                })
                .await
                .expect("read migrated strict v1 legacy receipt");
            let legacy_accepted = ReceiptIdentity {
                conversation_id,
                command_id: receipt.command_id,
                owner: legacy_owner,
                idempotency_key: legacy_idempotency_key,
            };
            assert_receipt_revision(&store, &legacy_accepted, 0, "migrated baseline").await;
            assert_recovery_revision(&store, legacy_accepted.command_id, 0, "migrated baseline")
                .await;

            Self {
                root,
                keys,
                store: Some(store),
                legacy_accepted,
            }
        }

        fn store(&self) -> &RuntimeStoreHandle {
            self.store.as_ref().expect("strict v1 fixture is live")
        }

        fn database(&self) -> PathBuf {
            self.root.database()
        }

        fn storage_kek(&self) -> StorageKek {
            load_or_create_storage_kek(&self.keys, &self.database())
                .expect("reload migrated strict v1 tamper KEK")
        }

        async fn shutdown_and_assert_reopen_rejected(mut self, label: &str) {
            self.store
                .take()
                .expect("take live strict v1 tamper store")
                .shutdown()
                .await
                .expect("shutdown tampered strict v1 store");
            let storage_kek = self.storage_kek();
            // Clean shutdown 关闭最后一个 SQLite connection 时允许合法整理 WAL/SHM；
            // 因此 full-artifact 零写契约从 shutdown 完成后开始，只约束 rejected reopen。
            let before_reopen = artifact_evidence(&self.database());
            let error =
                RuntimeStoreHandle::open(RuntimeStoreConfig::new(self.database()), storage_kek)
                    .await
                    .expect_err("tampered migrated strict v1 store must fail closed on reopen");
            assert_unknown_or_corrupt(error, &format!("{label}/reopen"));
            assert_eq!(
                artifact_evidence(&self.database()),
                before_reopen,
                "{label}: rejected reopen must not rewrite any runtime artifact"
            );
        }
    }

    async fn assert_receipt_revision(
        store: &RuntimeStoreHandle,
        identity: &ReceiptIdentity,
        expected_revision: u64,
        label: &str,
    ) {
        let by_command = store
            .query_command_receipt(QueryCommandReceipt {
                expected_owner: identity.owner.clone(),
                selector: CommandReceiptSelector::Command {
                    conversation_id: identity.conversation_id,
                    command_id: identity.command_id,
                },
            })
            .await
            .unwrap_or_else(|error| panic!("{label}: command-id receipt failed: {error:?}"));
        let by_idempotency = store
            .query_command_receipt(QueryCommandReceipt {
                expected_owner: identity.owner.clone(),
                selector: CommandReceiptSelector::Idempotency {
                    conversation_id: identity.conversation_id,
                    idempotency_key: identity.idempotency_key.clone(),
                },
            })
            .await
            .unwrap_or_else(|error| panic!("{label}: idempotency receipt failed: {error:?}"));
        assert_eq!(by_command, by_idempotency, "{label}: selector drift");
        assert_eq!(
            by_command.configuration_revision, expected_revision,
            "{label}: frozen configuration revision drift"
        );
    }

    async fn assert_receipts_rejected(
        store: &RuntimeStoreHandle,
        identity: &ReceiptIdentity,
        label: &str,
    ) {
        for (selector_label, selector) in [
            (
                "command-id",
                CommandReceiptSelector::Command {
                    conversation_id: identity.conversation_id,
                    command_id: identity.command_id,
                },
            ),
            (
                "idempotency",
                CommandReceiptSelector::Idempotency {
                    conversation_id: identity.conversation_id,
                    idempotency_key: identity.idempotency_key.clone(),
                },
            ),
        ] {
            let error = store
                .query_command_receipt(QueryCommandReceipt {
                    expected_owner: identity.owner.clone(),
                    selector,
                })
                .await
                .expect_err("tampered strict v1 receipt must fail closed");
            assert_unknown_or_corrupt(error, &format!("{label}/{selector_label}"));
        }
    }

    async fn complete_recovery_revisions(
        store: &RuntimeStoreHandle,
    ) -> Result<Vec<(RuntimeId, u64)>, RuntimeStoreError> {
        let mut cursor = store.begin_recovery_scan().await?;
        let mut recovered = Vec::new();
        let completion = loop {
            let page = store.load_recovery_page(cursor).await?;
            if let Some(conversation) = page.conversation {
                recovered.extend(
                    conversation
                        .accepted
                        .into_iter()
                        .map(|command| (command.command_id, command.configuration_revision)),
                );
                if let Some(started) = conversation.started {
                    recovered.push((
                        started.command.command_id,
                        started.command.configuration_revision,
                    ));
                }
            }
            match (page.next_cursor, page.completion) {
                (Some(next), None) => cursor = next,
                (None, Some(completion)) => break completion,
                _ => return Err(RuntimeStoreError::UnknownOrCorruptSchema),
            }
        };
        store.finish_recovery_scan(completion).await?;
        Ok(recovered)
    }

    async fn assert_recovery_revision(
        store: &RuntimeStoreHandle,
        command_id: RuntimeId,
        expected_revision: u64,
        label: &str,
    ) {
        let recovered = complete_recovery_revisions(store)
            .await
            .unwrap_or_else(|error| panic!("{label}: baseline recovery failed: {error:?}"));
        assert!(
            recovered.iter().any(|(recovered_id, revision)| {
                *recovered_id == command_id && *revision == expected_revision
            }),
            "{label}: recovery lost command revision {expected_revision}"
        );
    }

    async fn assert_live_recovery_rejected(store: &RuntimeStoreHandle, label: &str) {
        let error = store
            .begin_recovery_scan()
            .await
            .expect_err("tampered strict v1 recovery must fail closed");
        assert_unknown_or_corrupt(error, &format!("{label}/live-recovery"));
    }

    fn assert_unknown_or_corrupt(error: RuntimeStoreError, label: &str) {
        assert!(
            matches!(error, RuntimeStoreError::UnknownOrCorruptSchema),
            "{label} must return authenticated corruption, got {error:?}"
        );
    }

    struct VerifiedV5TamperContext {
        connection: Connection,
        key_bundle: RuntimeKeyBundle,
        database_id: [u8; 16],
        ledger: RuntimeLedger,
        ledger_token: Vec<u8>,
    }

    impl VerifiedV5TamperContext {
        fn open(database: &Path, storage_kek: &StorageKek) -> Self {
            let connection = Connection::open(database).expect("open strict v1 tamper connection");
            connection
                .pragma_update(None, "wal_autocheckpoint", 0_i64)
                .expect("disable tamper connection WAL autocheckpoint");
            assert_eq!(
                connection
                    .query_row("PRAGMA wal_autocheckpoint", [], |row| row.get::<_, i64>(0))
                    .expect("read back tamper WAL autocheckpoint"),
                0,
                "tamper connection must not checkpoint before artifact capture"
            );
            connection
                .pragma_update(None, "foreign_keys", true)
                .expect("enable tamper connection foreign keys");
            assert_eq!(
                connection
                    .query_row("PRAGMA foreign_keys", [], |row| row.get::<_, i64>(0))
                    .expect("read back tamper foreign keys"),
                1
            );

            let meta = read_meta(&connection)
                .expect("read migrated strict v1 current meta")
                .expect("migrated strict v1 current meta exists");
            assert_eq!(meta.version, RUNTIME_SCHEMA_VERSION);
            let key_bundle = RuntimeKeyBundle::unwrap(
                storage_kek,
                &KeyWrapAad {
                    schema_family: RUNTIME_SCHEMA_FAMILY.as_bytes(),
                    schema_version: RUNTIME_CRYPTO_CONTEXT_VERSION,
                    database_id: &meta.database_id,
                },
                &meta.wrapped_key_bundle,
            )
            .expect("unwrap migrated strict v1 row keys");
            assert_eq!(key_bundle.generation(), meta.key_generation);
            let ledger = load_runtime_ledger(&connection, &key_bundle, meta.database_id)
                .expect("authenticate existing migrated strict v1 ledger");
            assert_eq!(ledger, meta.ledger);
            let ledger_token = runtime_ledger_token(&key_bundle, meta.database_id, &ledger)
                .expect("recompute existing migrated strict v1 ledger token");
            assert_eq!(ledger_token.as_slice(), meta.metadata_token.as_slice());
            assert_eq!(
                super::super::command_configuration::validate_v5_integrity(
                    &connection,
                    &key_bundle,
                    &ledger,
                )
                .expect("authenticate existing migrated strict v1 command pins"),
                ledger.command_configuration_pin_count
            );

            Self {
                connection,
                key_bundle,
                database_id: meta.database_id,
                ledger,
                ledger_token: meta.metadata_token,
            }
        }
    }

    fn update_resigned_pin_count(
        transaction: &Transaction<'_>,
        key_bundle: &RuntimeKeyBundle,
        database_id: [u8; 16],
        previous: &RuntimeLedger,
        previous_token: &[u8],
        next_pin_count: u64,
    ) {
        let mut next = previous.clone();
        next.command_configuration_pin_count = next_pin_count;
        let next_token = runtime_ledger_token(key_bundle, database_id, &next)
            .expect("authenticate tampered strict v1 pin ledger");
        assert_eq!(
            transaction
                .execute(
                    "UPDATE runtime_meta
                     SET command_configuration_pin_count = ?1, metadata_token = ?2
                     WHERE singleton = 1
                       AND command_configuration_pin_count = ?3
                       AND metadata_token = ?4",
                    params![
                        i64::try_from(next_pin_count).expect("pin count fits SQLite integer"),
                        &next_token[..],
                        i64::try_from(previous.command_configuration_pin_count)
                            .expect("previous pin count fits SQLite integer"),
                        previous_token,
                    ],
                )
                .expect("publish resigned strict v1 pin ledger"),
            1
        );
    }

    fn delete_fresh_pin_and_resign(
        database: &Path,
        storage_kek: &StorageKek,
        conversation_id: RuntimeId,
    ) {
        let VerifiedV5TamperContext {
            mut connection,
            key_bundle,
            database_id,
            ledger,
            ledger_token,
        } = VerifiedV5TamperContext::open(database, storage_kek);
        assert_eq!(ledger.command_configuration_pin_count, 1);
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("begin fresh pin deletion transaction");
        assert_eq!(
            transaction
                .execute(
                    "DELETE FROM command_configuration_pins
                     WHERE conversation_id = ?1 AND command_seq = ?2",
                    params![&conversation_id.as_bytes()[..], encode_sequence(1)],
                )
                .expect("delete fresh seq-one command pin"),
            1
        );
        update_resigned_pin_count(
            &transaction,
            &key_bundle,
            database_id,
            &ledger,
            &ledger_token,
            0,
        );
        transaction
            .commit()
            .expect("commit fresh pin deletion tamper");
    }

    fn insert_cutoff_pin_and_resign(
        database: &Path,
        storage_kek: &StorageKek,
        conversation_id: RuntimeId,
    ) {
        let VerifiedV5TamperContext {
            mut connection,
            key_bundle,
            database_id,
            ledger,
            ledger_token,
        } = VerifiedV5TamperContext::open(database, storage_kek);
        assert_eq!(ledger.command_configuration_pin_count, 0);
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("begin cutoff pin insertion transaction");
        super::super::command_configuration::insert_pin(
            &transaction,
            &key_bundle,
            conversation_id,
            0,
            1,
        )
        .expect("insert MAC-valid cutoff pin with real configuration FK");
        update_resigned_pin_count(
            &transaction,
            &key_bundle,
            database_id,
            &ledger,
            &ledger_token,
            1,
        );
        transaction
            .commit()
            .expect("commit cutoff pin insertion tamper");
    }

    fn diverge_resigned_pin_ledger(database: &Path, storage_kek: &StorageKek) {
        let VerifiedV5TamperContext {
            mut connection,
            key_bundle,
            database_id,
            ledger,
            ledger_token,
        } = VerifiedV5TamperContext::open(database, storage_kek);
        assert_eq!(ledger.command_configuration_pin_count, 0);
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("begin authenticated pin ledger divergence transaction");
        update_resigned_pin_count(
            &transaction,
            &key_bundle,
            database_id,
            &ledger,
            &ledger_token,
            1,
        );
        transaction
            .commit()
            .expect("commit authenticated pin ledger divergence");
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
            .create_conversation(conversation(0x13, b"legacy empty descriptor"))
            .await
            .expect("create empty legacy conversation");
        configure_source_conversation(&store, accepted_conversation.conversation_id, 1).await;
        configure_source_conversation(&store, started_conversation.conversation_id, 2).await;
        let accepted_command = match store
            .accept_command(AcceptCommand {
                conversation_id: accepted_conversation.conversation_id,
                owner: owner(1),
                idempotency_key: "legacy-accepted".to_owned(),
                expected_configuration_revision: 1,
                payload: b"legacy accepted payload".to_vec(),
            })
            .await
            .expect("persist current source Accepted command")
        {
            AcceptOutcome::Accepted { command, .. } => command,
            AcceptOutcome::Replayed { .. } => panic!("fresh source command cannot replay"),
        };
        let started_command = match store
            .accept_command(AcceptCommand {
                conversation_id: started_conversation.conversation_id,
                owner: owner(2),
                idempotency_key: "legacy-started".to_owned(),
                expected_configuration_revision: 1,
                payload: b"legacy started payload".to_vec(),
            })
            .await
            .expect("accept current source command to start")
        {
            AcceptOutcome::Accepted { command, .. } => command,
            AcceptOutcome::Replayed { .. } => panic!("fresh source command cannot replay"),
        };
        let daemon_boot_id = runtime_id(RuntimeIdKind::DaemonBoot, 0x41);
        let execution_nonce = b"legacy-execution-nonce".to_vec();
        let started_event = match store
            .mark_started_with_legacy_v1_fixture_for_test(
                StartCommand {
                    conversation_id: started_conversation.conversation_id,
                    command_id: started_command.command_id,
                    daemon_boot_id,
                    execution_nonce: execution_nonce.clone(),
                },
                b"legacy intent payload".to_vec(),
                b"legacy started event".to_vec(),
            )
            .await
            .expect("persist legacy intent and event")
        {
            StartOutcome::Started { event, .. } => event,
            StartOutcome::Replayed { .. } => panic!("fresh source start cannot replay"),
        };
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
        rewrite_command_as_legacy_v1(
            &source_connection,
            &key_bundle,
            accepted_command.command_id,
            b"legacy accepted payload",
        );
        rewrite_command_as_legacy_v1(
            &source_connection,
            &key_bundle,
            started_command.command_id,
            b"legacy started payload",
        );
        source_connection
            .pragma_update(None, "foreign_keys", false)
            .expect("detach current-only sidecar references for strict v1 projection");
        assert_eq!(
            source_connection
                .execute(
                    "DELETE FROM event_journal
                     WHERE EXISTS (
                         SELECT 1 FROM configuration_journal AS configuration
                         WHERE configuration.conversation_id = event_journal.conversation_id
                           AND configuration.event_seq = event_journal.event_seq
                     )",
                    [],
                )
                .expect("remove current-only configuration events from strict v1 projection"),
            2
        );
        rewrite_started_event_as_legacy_seq_zero(
            &source_connection,
            &key_bundle,
            started_event.event_id,
        );
        rewrite_conversation_event_high_water(
            &source_connection,
            &key_bundle,
            accepted_conversation.conversation_id,
            None,
        );
        rewrite_conversation_event_high_water(
            &source_connection,
            &key_bundle,
            started_conversation.conversation_id,
            Some(0),
        );
        let mut legacy_ledger = meta.ledger.clone();
        legacy_ledger.event_count = legacy_ledger
            .event_count
            .checked_sub(2)
            .expect("two current-only configuration events");
        let legacy_token = runtime_ledger_token_v1(&key_bundle, meta.database_id, &legacy_ledger)
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
                    legacy_ledger.catalog_high_water.as_deref(),
                    i64::try_from(legacy_ledger.conversation_count).unwrap(),
                    i64::try_from(legacy_ledger.command_count).unwrap(),
                    i64::try_from(legacy_ledger.event_count).unwrap(),
                    i64::try_from(legacy_ledger.intent_count).unwrap(),
                    i64::try_from(legacy_ledger.fence_count).unwrap(),
                    i64::try_from(legacy_ledger.accepted_count).unwrap(),
                    i64::try_from(legacy_ledger.accepted_payload_bytes).unwrap(),
                    i64::try_from(legacy_ledger.started_without_fence_count).unwrap(),
                    i64::try_from(legacy_ledger.started_without_release_count).unwrap(),
                    i64::try_from(legacy_ledger.started_released_count).unwrap(),
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

    async fn build_populated_strict_v4_fixture(
        root: &TestRoot,
        keys: &MemoryKeyStore,
    ) -> CipherEvidence {
        let before = build_strict_v3_fixture(root, keys).await;
        let destination = root.database();
        let mut connection = Connection::open(&destination).expect("open strict v3 fixture for v4");
        let meta = read_meta_v3(&connection)
            .expect("read strict v3 fixture meta for v4")
            .expect("strict v3 fixture meta exists for v4");
        let storage_kek =
            load_or_create_storage_kek(keys, &destination).expect("reload strict v4 KEK");
        let key_bundle = RuntimeKeyBundle::unwrap(
            &storage_kek,
            &KeyWrapAad {
                schema_family: RUNTIME_SCHEMA_FAMILY.as_bytes(),
                schema_version: RUNTIME_CRYPTO_CONTEXT_VERSION,
                database_id: &meta.database_id,
            },
            &meta.wrapped_key_bundle,
        )
        .expect("unwrap strict v4 key bundle");
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("begin strict v4 fixture migration");
        transaction
            .execute_batch(RUNTIME_MIGRATION_V4)
            .expect("apply exact v4 migration");
        let migrated_ledger = super::super::stream::migrate_v4_rows(
            &transaction,
            &key_bundle,
            meta.database_id,
            &meta.ledger,
        )
        .expect("materialize strict v4 stream rows");
        let metadata_token =
            runtime_ledger_token_v4(&key_bundle, meta.database_id, &migrated_ledger)
                .expect("authenticate strict v4 ledger");
        assert_eq!(
            transaction
                .execute(
                    "UPDATE runtime_meta
                     SET schema_version = 4, schema_signature = ?1,
                         codex_adapter_state_count = ?2, claude_code_adapter_state_count = ?3,
                         approval_count = ?4, active_approval_count = ?5,
                         audit_event_logical_bytes = ?6,
                         event_stream_count = ?7, event_stream_bytes = ?8,
                         catalog_delta_count = ?9, catalog_delta_bytes = ?10,
                         catalog_retention_floor = ?11,
                         snapshot_count = ?12, snapshot_bytes = ?13,
                         publication_stream_count = ?14,
                         publication_outbox_count = ?15, publication_outbox_bytes = ?16,
                         metadata_token = ?17
                     WHERE singleton = 1 AND schema_version = 3",
                    params![
                        &schema_signature_v4()[..],
                        i64::try_from(meta.ledger.codex_adapter_state_count).unwrap(),
                        i64::try_from(meta.ledger.claude_code_adapter_state_count).unwrap(),
                        i64::try_from(migrated_ledger.approval_count).unwrap(),
                        i64::try_from(migrated_ledger.active_approval_count).unwrap(),
                        i64::try_from(migrated_ledger.audit_event_logical_bytes).unwrap(),
                        i64::try_from(migrated_ledger.event_stream_count).unwrap(),
                        i64::try_from(migrated_ledger.event_stream_bytes).unwrap(),
                        i64::try_from(migrated_ledger.catalog_delta_count).unwrap(),
                        i64::try_from(migrated_ledger.catalog_delta_bytes).unwrap(),
                        migrated_ledger.catalog_retention_floor.as_deref(),
                        i64::try_from(migrated_ledger.snapshot_count).unwrap(),
                        i64::try_from(migrated_ledger.snapshot_bytes).unwrap(),
                        i64::try_from(migrated_ledger.publication_stream_count).unwrap(),
                        i64::try_from(migrated_ledger.publication_outbox_count).unwrap(),
                        i64::try_from(migrated_ledger.publication_outbox_bytes).unwrap(),
                        &metadata_token[..],
                    ],
                )
                .expect("publish authenticated strict v4 meta"),
            1
        );
        transaction
            .commit()
            .expect("commit populated strict v4 fixture");
        assert_eq!(
            schema_manifest(&connection).expect("read populated strict v4 manifest"),
            expected_schema_manifest(4).expect("build exact v4 manifest")
        );
        drop(connection);
        assert_eq!(cipher_evidence(&destination), before);
        before
    }

    fn build_empty_strict_v4_fixture(root: &TestRoot, keys: &MemoryKeyStore) -> CipherEvidence {
        let destination = root.database();
        let storage_kek =
            load_or_create_storage_kek(keys, &destination).expect("create strict v4 KEK");
        let database_id = [0x94; 16];
        let key_bundle =
            RuntimeKeyBundle::fresh(RUNTIME_KEY_GENERATION).expect("create strict v4 key bundle");
        let wrapped_key_bundle = key_bundle
            .wrap(
                &storage_kek,
                &KeyWrapAad {
                    schema_family: RUNTIME_SCHEMA_FAMILY.as_bytes(),
                    schema_version: RUNTIME_CRYPTO_CONTEXT_VERSION,
                    database_id: &database_id,
                },
            )
            .expect("wrap strict v4 key bundle");
        let ledger = RuntimeLedger::default();
        let metadata_token = runtime_ledger_token_v4(&key_bundle, database_id, &ledger)
            .expect("authenticate empty strict v4 ledger");
        let connection = Connection::open(&destination).expect("create strict v4 fixture");
        for ddl in [
            RUNTIME_DDL_V1,
            RUNTIME_MIGRATION_V2,
            RUNTIME_MIGRATION_V3,
            RUNTIME_MIGRATION_V4,
        ] {
            connection
                .execute_batch(ddl)
                .expect("apply strict v4 schema");
        }
        connection
            .execute(
                "INSERT INTO runtime_meta (
                     singleton, schema_family, schema_version, schema_signature, database_id,
                     key_generation, wrapped_key_bundle, catalog_high_water,
                     conversation_count, command_count, event_count, intent_count, fence_count,
                     accepted_count, accepted_payload_bytes, started_without_fence_count,
                     started_without_release_count, started_released_count, metadata_token
                 ) VALUES (1, ?1, 4, ?2, ?3, ?4, ?5, NULL,
                           0, 0, 0, 0, 0, 0, 0, 0, 0, 0, ?6)",
                params![
                    RUNTIME_SCHEMA_FAMILY,
                    &schema_signature_v4()[..],
                    &database_id[..],
                    i64::from(RUNTIME_KEY_GENERATION),
                    wrapped_key_bundle,
                    &metadata_token[..],
                ],
            )
            .expect("insert strict v4 meta");
        drop(connection);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&destination, fs::Permissions::from_mode(0o600))
                .expect("secure strict v4 fixture");
        }
        cipher_evidence(&destination)
    }

    fn build_empty_strict_v5_fixture(root: &TestRoot, keys: &MemoryKeyStore) -> CipherEvidence {
        let before = build_empty_strict_v4_fixture(root, keys);
        let destination = root.database();
        let connection = Connection::open(&destination).expect("open strict v4 fixture for v5");
        connection
            .execute_batch(RUNTIME_MIGRATION_V5)
            .expect("apply exact v5 migration");
        let meta = read_meta_v5(&connection)
            .expect("read strict v5 fixture meta")
            .expect("strict v5 fixture meta exists");
        let storage_kek =
            load_or_create_storage_kek(keys, &destination).expect("reload strict v5 KEK");
        let key_bundle = RuntimeKeyBundle::unwrap(
            &storage_kek,
            &KeyWrapAad {
                schema_family: RUNTIME_SCHEMA_FAMILY.as_bytes(),
                schema_version: RUNTIME_CRYPTO_CONTEXT_VERSION,
                database_id: &meta.database_id,
            },
            &meta.wrapped_key_bundle,
        )
        .expect("unwrap strict v5 key bundle");
        let token = runtime_ledger_token_v5(&key_bundle, meta.database_id, &meta.ledger)
            .expect("authenticate strict v5 ledger");
        connection
            .execute(
                "UPDATE runtime_meta
                 SET schema_version = 5, schema_signature = ?1, metadata_token = ?2
                 WHERE singleton = 1 AND schema_version = 4",
                params![&schema_signature_v5()[..], &token[..]],
            )
            .expect("publish authenticated strict v5 meta");
        drop(connection);
        assert_eq!(cipher_evidence(&destination), before);
        before
    }

    async fn build_populated_strict_v5_fixture(
        root: &TestRoot,
        keys: &MemoryKeyStore,
    ) -> (CipherEvidence, Vec<(String, Vec<Vec<u8>>)>, RuntimeId) {
        build_populated_strict_v5_fixture_with_metadata_mutation(root, keys, true).await
    }

    async fn build_populated_strict_v6_fixture(
        root: &TestRoot,
        keys: &MemoryKeyStore,
    ) -> (CipherEvidence, Vec<(String, Vec<Vec<u8>>)>) {
        let (before, authenticated_before, _) = build_populated_strict_v5_fixture(root, keys).await;
        let connection = Connection::open(root.database()).expect("open strict v5 fixture for v6");
        let meta = read_meta_v5(&connection)
            .expect("read strict v5 meta for v6")
            .expect("strict v5 meta exists");
        let storage_kek = load_or_create_storage_kek(keys, &root.database())
            .expect("reload strict v6 fixture KEK");
        let key_bundle = RuntimeKeyBundle::unwrap(
            &storage_kek,
            &KeyWrapAad {
                schema_family: RUNTIME_SCHEMA_FAMILY.as_bytes(),
                schema_version: RUNTIME_CRYPTO_CONTEXT_VERSION,
                database_id: &meta.database_id,
            },
            &meta.wrapped_key_bundle,
        )
        .expect("unwrap strict v6 fixture key bundle");
        connection
            .execute_batch(RUNTIME_MIGRATION_V6)
            .expect("apply exact v6 migration");
        let token = runtime_ledger_token_v6(&key_bundle, meta.database_id, &meta.ledger)
            .expect("authenticate strict v6 ledger");
        assert_eq!(
            connection
                .execute(
                    "UPDATE runtime_meta
                     SET schema_version = 6, schema_signature = ?1, metadata_token = ?2
                     WHERE singleton = 1 AND schema_version = 5",
                    params![&schema_signature_v6()[..], &token[..]],
                )
                .expect("publish authenticated strict v6 meta"),
            1
        );
        assert_eq!(
            schema_manifest(&connection).expect("read strict v6 manifest"),
            expected_schema_manifest(RUNTIME_SCHEMA_VERSION_V6).expect("build exact v6 manifest")
        );
        drop(connection);
        assert_eq!(cipher_evidence(&root.database()), before);
        let authenticated_after = {
            let connection =
                Connection::open(root.database()).expect("open strict v6 authenticated evidence");
            authenticated_blob_evidence(&connection)
        };
        assert_eq!(authenticated_after, authenticated_before);
        (before, authenticated_before)
    }

    async fn build_populated_strict_v5_fixture_with_metadata_mutation(
        root: &TestRoot,
        keys: &MemoryKeyStore,
        apply_metadata_mutation: bool,
    ) -> (CipherEvidence, Vec<(String, Vec<Vec<u8>>)>, RuntimeId) {
        let store = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.database()),
            load_or_create_storage_kek(keys, &root.database()).expect("create populated v6 KEK"),
        )
        .await
        .expect("create populated current fixture");
        let input = conversation(0xA5, b"populated v5 descriptor");
        let conversation_id = input.conversation_id;
        let adapter_state_key = input.adapter_state_key;
        store
            .create_conversation(input)
            .await
            .expect("create populated fixture conversation");
        store
            .codex_adapter_state_vault()
            .bind(
                adapter_state_key,
                SecretBytes::new(b"populated-v5-private-reference".to_vec()),
            )
            .await
            .expect("bind populated fixture adapter state");
        configure_source_conversation(&store, conversation_id, 0xA6).await;
        assert!(matches!(
            store
                .accept_command(AcceptCommand {
                    conversation_id,
                    owner: owner(0xA7),
                    idempotency_key: "populated-v5-command".to_owned(),
                    expected_configuration_revision: 1,
                    payload: b"populated v5 command".to_vec(),
                })
                .await
                .expect("persist populated v5 command pin"),
            AcceptOutcome::Accepted { .. }
        ));
        if apply_metadata_mutation {
            assert!(matches!(
                store
                    .update_managed_conversation_metadata(UpdateManagedConversationMetadata {
                        conversation_id,
                        owner: owner(0xA8),
                        idempotency_key: "populated-v5-metadata".to_owned(),
                        expected_entry_revision: 0,
                        mutation: ConversationMetadataMutation::rename(Some(
                            "populated v5 renamed".to_owned()
                        ))
                        .expect("valid populated v5 title"),
                    })
                    .await
                    .expect("persist populated v5 metadata mutation"),
                UpdateConversationMetadataOutcome::Applied { .. }
            ));
        }
        store
            .shutdown()
            .await
            .expect("shutdown populated current fixture");
        let current_evidence = cipher_evidence(&root.database());
        let current_authenticated = {
            let connection = Connection::open(root.database())
                .expect("open current authenticated evidence fixture");
            authenticated_blob_evidence(&connection)
        };

        let connection = Connection::open(root.database()).expect("open populated fixture");
        let meta = read_meta(&connection)
            .expect("read populated current meta")
            .expect("populated current meta exists");
        let storage_kek = load_or_create_storage_kek(keys, &root.database())
            .expect("reload populated fixture KEK");
        let key_bundle = RuntimeKeyBundle::unwrap(
            &storage_kek,
            &KeyWrapAad {
                schema_family: RUNTIME_SCHEMA_FAMILY.as_bytes(),
                schema_version: RUNTIME_CRYPTO_CONTEXT_VERSION,
                database_id: &meta.database_id,
            },
            &meta.wrapped_key_bundle,
        )
        .expect("unwrap populated fixture key bundle");
        let v5_token = runtime_ledger_token_v5(&key_bundle, meta.database_id, &meta.ledger)
            .expect("authenticate populated v5 ledger");
        connection
            .execute(
                "UPDATE runtime_meta
                 SET schema_version = 5, schema_signature = ?1, metadata_token = ?2
                 WHERE singleton = 1 AND schema_version = ?3",
                params![
                    &schema_signature_v5()[..],
                    &v5_token[..],
                    i64::from(RUNTIME_SCHEMA_VERSION),
                ],
            )
            .expect("publish populated v5 meta");
        connection
            .execute_batch(
                "DROP TABLE admin_commands;
                 ALTER TABLE runtime_meta DROP COLUMN admin_command_charged_bytes;
                 ALTER TABLE runtime_meta DROP COLUMN admin_command_pending_count;
                 ALTER TABLE runtime_meta DROP COLUMN admin_command_count;
                 DROP TABLE native_metadata_effect_fences;
                 DROP TABLE native_projection_state;
                 ALTER TABLE runtime_meta DROP COLUMN native_metadata_effect_released_count;
                 ALTER TABLE runtime_meta DROP COLUMN native_metadata_effect_unreleased_count;
                 ALTER TABLE runtime_meta DROP COLUMN native_metadata_effect_fence_count;
                 ALTER TABLE runtime_meta DROP COLUMN native_projection_charged_bytes;
                 ALTER TABLE runtime_meta DROP COLUMN native_projection_physical_count;
                 ALTER TABLE runtime_meta DROP COLUMN native_projection_retired_count;
                 ALTER TABLE runtime_meta DROP COLUMN native_projection_tombstone_count;
                 ALTER TABLE runtime_meta DROP COLUMN native_projection_present_count;",
            )
            .expect("project current fixture to exact v5 physical shape");
        assert_eq!(
            schema_manifest(&connection).expect("read populated v5 manifest"),
            expected_schema_manifest(5).expect("build exact v5 manifest")
        );
        drop(connection);

        let v5_evidence = cipher_evidence(&root.database());
        let v5_authenticated = {
            let connection =
                Connection::open(root.database()).expect("open v5 authenticated evidence fixture");
            authenticated_blob_evidence(&connection)
        };
        assert_eq!(
            v5_evidence, current_evidence,
            "fixture projection must preserve every populated non-meta token/MAC/ciphertext"
        );
        assert_eq!(
            v5_authenticated, current_authenticated,
            "fixture projection must preserve every populated non-meta authenticated blob"
        );
        (v5_evidence, v5_authenticated, conversation_id)
    }

    fn assert_migrated_conversation_states(path: &Path) {
        let connection = Connection::open(path).expect("open migrated conversation states");
        let rows = connection
            .prepare(
                "SELECT s.current_configuration_revision, s.entry_revision,
                        s.origin_kind, s.origin_namespace, s.legacy_command_high_water,
                        c.command_high_water, length(s.metadata_token)
                 FROM conversation_state AS s
                 JOIN conversations AS c USING (conversation_id)
                 ORDER BY s.conversation_id",
            )
            .expect("prepare migrated conversation states")
            .query_map([], |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, i64>(6)?,
                ))
            })
            .expect("query migrated conversation states")
            .collect::<Result<Vec<_>, _>>()
            .expect("collect migrated conversation states");
        assert_eq!(rows.len(), 3);
        let mut null_cutoffs = 0;
        for (current, entry, origin, namespace, cutoff, command_high_water, token_len) in rows {
            assert_eq!(current, None);
            assert_eq!(entry, super::super::sequence::encode_sequence(0));
            assert_eq!(origin, "managed");
            assert_eq!(namespace, None);
            assert_eq!(cutoff, command_high_water);
            null_cutoffs += usize::from(cutoff.is_none());
            assert_eq!(token_len, 32);
        }
        assert_eq!(
            null_cutoffs, 1,
            "empty legacy conversation keeps BeforeFirst NULL"
        );
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
        let baseline = runtime_ledger_token_v4(&key_bundle, database_id, &ledger)
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
                runtime_ledger_token_v4(&key_bundle, database_id, &changed)
                    .expect("authenticate changed v4 ledger"),
                baseline
            );
        }
    }

    #[test]
    fn v5_ledger_token_authenticates_all_sidecar_totals_without_changing_v4_domain() {
        let key_bundle = RuntimeKeyBundle::fresh(RUNTIME_KEY_GENERATION).expect("fresh test keys");
        let database_id = [0x44; 16];
        let ledger = RuntimeLedger::default();
        let baseline_v5 = runtime_ledger_token_v5(&key_bundle, database_id, &ledger)
            .expect("authenticate baseline v5 ledger");
        let baseline_v4 = runtime_ledger_token_v4(&key_bundle, database_id, &ledger)
            .expect("authenticate baseline v4 ledger");
        let mut variants = Vec::new();
        let mut changed = ledger.clone();
        changed.configuration_count = 1;
        variants.push(changed);
        let mut changed = ledger.clone();
        changed.configuration_sealed_bytes = 40;
        variants.push(changed);
        let mut changed = ledger.clone();
        changed.command_configuration_pin_count = 1;
        variants.push(changed);
        let mut changed = ledger.clone();
        changed.metadata_mutation_count = 1;
        variants.push(changed);
        let mut changed = ledger.clone();
        changed.active_metadata_mutation_count = 1;
        variants.push(changed);
        let mut changed = ledger;
        changed.metadata_mutation_charged_bytes = 80;
        variants.push(changed);
        for changed in variants {
            assert_ne!(
                runtime_ledger_token_v5(&key_bundle, database_id, &changed)
                    .expect("authenticate changed v5 ledger"),
                baseline_v5
            );
            assert_eq!(
                runtime_ledger_token_v4(&key_bundle, database_id, &changed)
                    .expect("authenticate legacy v4 projection"),
                baseline_v4,
                "v4 token must ignore all v5-only totals while authenticating migration"
            );
        }
    }

    #[test]
    fn v6_ledger_token_authenticates_all_native_totals_without_changing_v5_domain() {
        let key_bundle = RuntimeKeyBundle::fresh(RUNTIME_KEY_GENERATION).expect("fresh test keys");
        let database_id = [0x45; 16];
        let ledger = RuntimeLedger::default();
        let baseline_v6 = runtime_ledger_token(&key_bundle, database_id, &ledger)
            .expect("authenticate baseline v6 ledger");
        let baseline_v5 = runtime_ledger_token_v5(&key_bundle, database_id, &ledger)
            .expect("authenticate baseline v5 ledger");
        let mut variants = Vec::new();
        for mutate in [
            |ledger: &mut RuntimeLedger| ledger.native_projection_present_count = 1,
            |ledger: &mut RuntimeLedger| ledger.native_projection_tombstone_count = 1,
            |ledger: &mut RuntimeLedger| ledger.native_projection_retired_count = 1,
            |ledger: &mut RuntimeLedger| ledger.native_projection_physical_count = 1,
            |ledger: &mut RuntimeLedger| ledger.native_projection_charged_bytes = 60,
            |ledger: &mut RuntimeLedger| ledger.native_metadata_effect_fence_count = 1,
            |ledger: &mut RuntimeLedger| ledger.native_metadata_effect_unreleased_count = 1,
            |ledger: &mut RuntimeLedger| ledger.native_metadata_effect_released_count = 1,
        ] {
            let mut changed = ledger.clone();
            mutate(&mut changed);
            variants.push(changed);
        }
        for changed in variants {
            assert_ne!(
                runtime_ledger_token(&key_bundle, database_id, &changed)
                    .expect("authenticate changed v6 ledger"),
                baseline_v6
            );
            assert_eq!(
                runtime_ledger_token_v5(&key_bundle, database_id, &changed)
                    .expect("authenticate legacy v5 projection"),
                baseline_v5,
                "v5 token must ignore all v6-only totals while authenticating migration"
            );
        }
    }

    #[tokio::test]
    async fn strict_v1_migrates_without_rewrapping_or_reencrypting_existing_rows() {
        let root = TestRoot::new("full");
        let keys = MemoryKeyStore::new();
        let before = build_strict_v1_fixture(&root, &keys).await;
        assert_eq!(before.descriptors.len(), 3);
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
                for command in record.accepted {
                    if command.payload == b"legacy accepted payload" {
                        assert_eq!(
                            command.configuration_revision, 0,
                            "strict v1 Accepted 必须恢复为 frozen legacy revision 0"
                        );
                        accepted_seen = true;
                    }
                }
                if let Some(started) = record.started {
                    if started.command.payload == b"legacy started payload" {
                        assert_eq!(
                            started.command.configuration_revision, 0,
                            "strict v1 Started 必须恢复为 frozen legacy revision 0"
                        );
                    }
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
        assert_migrated_conversation_states(&root.database());
        let connection = Connection::open(root.database()).expect("inspect migrated v1 pin state");
        let pin_counts: (i64, i64) = connection
            .query_row(
                "SELECT
                     (SELECT COUNT(*) FROM command_configuration_pins),
                     command_configuration_pin_count
                 FROM runtime_meta WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("read migrated v1 physical and ledger pin counts");
        assert_eq!(
            pin_counts,
            (0, 0),
            "strict v1 cutoff 内命令不得伪造 current revision pin"
        );
    }

    #[tokio::test]
    async fn migrated_revision_zero_start_requires_explicit_startup_recovery_provenance() {
        // B3b：合法 migration cutoff 内的 rev0 command 也不能从普通 live queue
        // 偷用 defaults；只有 daemon startup recovery 的窄入口可以取得 legacy variant。
        let mut fixture = MigratedStrictV1Fixture::create("rev0-startup-provenance").await;
        let start = StartCommand {
            conversation_id: fixture.legacy_accepted.conversation_id,
            command_id: fixture.legacy_accepted.command_id,
            daemon_boot_id: runtime_id(RuntimeIdKind::DaemonBoot, 0xA1),
            execution_nonce: b"legacy-startup-recovery-nonce".to_vec(),
        };
        let ordinary_error = fixture
            .store()
            .mark_started_with_event(start.clone())
            .await
            .expect_err("ordinary queue must reject migrated revision zero");
        assert!(matches!(
            ordinary_error,
            RuntimeStoreError::InvalidStateTransition
        ));

        let assert_legacy = |outcome: StartOutcome, expected_started: bool| match outcome {
            StartOutcome::Started {
                command,
                execution_configuration:
                    CommandExecutionConfiguration::LegacyRevisionZero { agent_kind },
                ..
            } if expected_started => {
                assert_eq!(command.configuration_revision, 0);
                assert_eq!(agent_kind, agentdeck_protocol::AgentKind::Codex);
            }
            StartOutcome::Replayed {
                command,
                execution_configuration:
                    CommandExecutionConfiguration::LegacyRevisionZero { agent_kind },
                ..
            } if !expected_started => {
                assert_eq!(command.configuration_revision, 0);
                assert_eq!(agent_kind, agentdeck_protocol::AgentKind::Codex);
            }
            other => panic!("unexpected legacy startup outcome: {other:?}"),
        };
        assert_legacy(
            fixture
                .store()
                .mark_started_for_startup_recovery(start.clone())
                .await
                .expect("startup recovery may start migrated revision zero"),
            true,
        );
        assert_legacy(
            fixture
                .store()
                .mark_started_for_startup_recovery(start)
                .await
                .expect("startup recovery replay preserves legacy revision zero"),
            false,
        );
        fixture
            .store
            .take()
            .expect("take migrated revision zero store")
            .shutdown()
            .await
            .expect("shutdown migrated revision zero store");
    }

    #[tokio::test]
    async fn strict_v1_fresh_command_missing_pin_fails_local_and_global_reads() {
        let fixture = MigratedStrictV1Fixture::create("fresh-command-missing-pin").await;
        let conversation_id = fixture.legacy_accepted.conversation_id;
        configure_source_conversation(fixture.store(), conversation_id, 0x51).await;
        let fresh_owner = owner(0x52);
        let fresh_idempotency_key = "strict-v1-fresh-seq-one".to_owned();
        let fresh_command = match fixture
            .store()
            .accept_command(AcceptCommand {
                conversation_id,
                owner: fresh_owner.clone(),
                idempotency_key: fresh_idempotency_key.clone(),
                expected_configuration_revision: 1,
                payload: b"strict v1 fresh command after cutoff".to_vec(),
            })
            .await
            .expect("accept production fresh command after strict v1 cutoff")
        {
            AcceptOutcome::Accepted { command, .. } => command,
            AcceptOutcome::Replayed { .. } => panic!("fresh seq-one command cannot replay"),
        };
        assert_eq!(fresh_command.command_seq, 1);
        assert_eq!(fresh_command.configuration_revision, 1);
        let fresh_identity = ReceiptIdentity {
            conversation_id,
            command_id: fresh_command.command_id,
            owner: fresh_owner,
            idempotency_key: fresh_idempotency_key,
        };
        assert_receipt_revision(fixture.store(), &fresh_identity, 1, "fresh pin baseline").await;
        assert_recovery_revision(
            fixture.store(),
            fresh_identity.command_id,
            1,
            "fresh pin baseline",
        )
        .await;

        let database = fixture.database();
        let storage_kek = fixture.storage_kek();
        delete_fresh_pin_and_resign(&database, &storage_kek, conversation_id);
        let post_tamper = artifact_evidence(&database);
        assert_receipts_rejected(fixture.store(), &fresh_identity, "fresh-pin-missing").await;
        assert_live_recovery_rejected(fixture.store(), "fresh-pin-missing").await;
        assert_main_and_wal_unchanged(
            &post_tamper,
            &artifact_evidence(&database),
            "fresh-pin-missing live rejection",
        );
        fixture
            .shutdown_and_assert_reopen_rejected("fresh-pin-missing")
            .await;
    }

    #[tokio::test]
    async fn strict_v1_cutoff_command_rejects_authenticated_nonzero_pin() {
        let fixture = MigratedStrictV1Fixture::create("cutoff-command-gains-pin").await;
        let conversation_id = fixture.legacy_accepted.conversation_id;
        configure_source_conversation(fixture.store(), conversation_id, 0x61).await;
        assert_receipt_revision(
            fixture.store(),
            &fixture.legacy_accepted,
            0,
            "cutoff pin baseline",
        )
        .await;
        assert_recovery_revision(
            fixture.store(),
            fixture.legacy_accepted.command_id,
            0,
            "cutoff pin baseline",
        )
        .await;

        let database = fixture.database();
        let storage_kek = fixture.storage_kek();
        insert_cutoff_pin_and_resign(&database, &storage_kek, conversation_id);
        let post_tamper = artifact_evidence(&database);
        assert_receipts_rejected(
            fixture.store(),
            &fixture.legacy_accepted,
            "cutoff-gains-pin",
        )
        .await;
        assert_live_recovery_rejected(fixture.store(), "cutoff-gains-pin").await;
        assert_main_and_wal_unchanged(
            &post_tamper,
            &artifact_evidence(&database),
            "cutoff-gains-pin live rejection",
        );
        fixture
            .shutdown_and_assert_reopen_rejected("cutoff-gains-pin")
            .await;
    }

    #[tokio::test]
    async fn strict_v1_authenticated_pin_ledger_divergence_stays_local_then_fails_global_audit() {
        let fixture = MigratedStrictV1Fixture::create("pin-ledger-divergence").await;
        let database = fixture.database();
        let storage_kek = fixture.storage_kek();
        diverge_resigned_pin_ledger(&database, &storage_kek);
        let post_tamper = artifact_evidence(&database);

        assert_receipt_revision(
            fixture.store(),
            &fixture.legacy_accepted,
            0,
            "authenticated pin ledger divergence remains row-local",
        )
        .await;
        assert_live_recovery_rejected(fixture.store(), "pin-ledger-divergence").await;
        assert_main_and_wal_unchanged(
            &post_tamper,
            &artifact_evidence(&database),
            "pin-ledger-divergence live rejection",
        );
        fixture
            .shutdown_and_assert_reopen_rejected("pin-ledger-divergence")
            .await;
    }

    #[tokio::test]
    async fn fresh_v7_has_exact_empty_admin_manifest_and_reopens_without_migration() {
        let root = TestRoot::new("v7-fresh-admin-manifest");
        let keys = MemoryKeyStore::new();
        let store = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.database()),
            load_or_create_storage_kek(&keys, &root.database()).expect("create fresh v7 KEK"),
        )
        .await
        .expect("open fresh v7 store");
        let snapshot = store.inspect().await.expect("inspect fresh v7 store");
        assert_eq!(snapshot.schema_version, RUNTIME_SCHEMA_VERSION);
        assert_eq!(snapshot.table_names, EXPECTED_TABLES);
        store.shutdown().await.expect("shutdown fresh v7 store");

        let connection = Connection::open(root.database()).expect("inspect fresh v7 database");
        assert_eq!(
            schema_manifest(&connection).expect("read fresh v7 manifest"),
            expected_schema_manifest(RUNTIME_SCHEMA_VERSION).expect("build exact v7 manifest")
        );
        let empty_admin: (i64, i64, i64, i64) = connection
            .query_row(
                "SELECT (SELECT COUNT(*) FROM admin_commands),
                        admin_command_count, admin_command_pending_count,
                        admin_command_charged_bytes
                 FROM runtime_meta WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .expect("read fresh v7 admin totals");
        assert_eq!(empty_admin, (0, 0, 0, 0));
        drop(connection);

        let reopened = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.database()),
            load_or_create_storage_kek(&keys, &root.database()).expect("reload fresh v7 KEK"),
        )
        .await
        .expect("reopen fresh v7 store without migration");
        reopened
            .shutdown()
            .await
            .expect("shutdown reopened v7 store");
    }

    #[tokio::test]
    async fn populated_v6_migrates_to_v7_without_rewrapping_or_reencrypting_existing_rows() {
        let root = TestRoot::new("v6-populated-to-v7");
        let keys = MemoryKeyStore::new();
        let (before, authenticated_before) = build_populated_strict_v6_fixture(&root, &keys).await;

        let store = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.database()),
            load_or_create_storage_kek(&keys, &root.database()).expect("reload strict v6 KEK"),
        )
        .await
        .expect("migrate populated strict v6 fixture to v7");
        let snapshot = store.inspect().await.expect("inspect migrated v7 store");
        assert_eq!(snapshot.schema_version, RUNTIME_SCHEMA_VERSION);
        assert_eq!(snapshot.table_names, EXPECTED_TABLES);
        store.shutdown().await.expect("shutdown migrated v7 store");

        assert_eq!(
            cipher_evidence(&root.database()),
            before,
            "v6 to v7 must preserve wrapped keys and existing ciphertext byte-exact"
        );
        let connection = Connection::open(root.database()).expect("inspect migrated v7 database");
        assert_eq!(
            authenticated_blob_evidence(&connection),
            authenticated_before,
            "v6 to v7 must preserve every existing non-meta token and ciphertext byte-exact"
        );
        assert_eq!(
            schema_manifest(&connection).expect("read migrated v7 manifest"),
            expected_schema_manifest(RUNTIME_SCHEMA_VERSION).expect("build exact v7 manifest")
        );
        let empty_admin: (i64, i64, i64, i64) = connection
            .query_row(
                "SELECT (SELECT COUNT(*) FROM admin_commands),
                        admin_command_count, admin_command_pending_count,
                        admin_command_charged_bytes
                 FROM runtime_meta WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .expect("read migrated v7 admin totals");
        assert_eq!(empty_admin, (0, 0, 0, 0));
    }

    #[tokio::test]
    async fn v7_unauthenticated_admin_row_fails_closed_before_runtime_artifact_rewrite() {
        let root = TestRoot::new("v7-nonempty-admin-fail-close");
        let keys = MemoryKeyStore::new();
        let store = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.database()),
            load_or_create_storage_kek(&keys, &root.database()).expect("create v7 guard KEK"),
        )
        .await
        .expect("open v7 guard fixture");
        store.shutdown().await.expect("shutdown v7 guard fixture");

        let connection = Connection::open(root.database()).expect("open v7 admin tamper fixture");
        assert_eq!(
            connection
                .execute(
                    "INSERT INTO admin_commands (
                         idempotency_token, command_kind, request_token, state,
                         sealed_request, sealed_outcome, created_at_ms, state_changed_at_ms,
                         retain_until_ms, charged_bytes, metadata_token
                     ) VALUES (?1, 'stageUpgrade', ?2, 'pending', ?3, ?4, 7, 7,
                               2592000007, 80, ?5)",
                    params![
                        &[0xA1_u8; 32][..],
                        &[0xA2_u8; 32][..],
                        &[0xA3_u8; 40][..],
                        &[0xA4_u8; 40][..],
                        &[0xA5_u8; 32][..],
                    ],
                )
                .expect("insert structurally valid but unaudited admin row"),
            1
        );
        drop(connection);
        let artifacts_before = artifact_evidence(&root.database());

        let error = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.database()),
            load_or_create_storage_kek(&keys, &root.database()).expect("reload v7 guard KEK"),
        )
        .await
        .expect_err("A2 streaming audit must reject an unauthenticated admin row");
        assert!(matches!(
            error,
            RuntimeStoreError::UnknownOrCorruptSchema | RuntimeStoreError::Cipher(_)
        ));
        assert_eq!(
            artifact_evidence(&root.database()),
            artifacts_before,
            "rejected v7 admin row must not rewrite main/WAL/SHM/journal artifacts"
        );
    }

    #[tokio::test]
    async fn strict_empty_v5_migrates_to_v6_once_with_zero_sidecar_totals() {
        let root = TestRoot::new("v5-empty-to-v6");
        let keys = MemoryKeyStore::new();
        let before = build_empty_strict_v5_fixture(&root, &keys);
        let store = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.database()),
            load_or_create_storage_kek(&keys, &root.database()).expect("reload v5 KEK"),
        )
        .await
        .expect("migrate strict v5 fixture");
        let snapshot = store.inspect().await.expect("inspect migrated v6 schema");
        assert_eq!(snapshot.schema_version, RUNTIME_SCHEMA_VERSION);
        assert_eq!(snapshot.table_names, EXPECTED_TABLES);
        store.shutdown().await.expect("shutdown migrated v6 store");
        assert_eq!(cipher_evidence(&root.database()), before);

        let connection = Connection::open(root.database()).expect("inspect migrated v6 totals");
        let totals: (i64, i64, i64, i64, i64, i64, i64, i64) = connection
            .query_row(
                "SELECT native_projection_present_count,
                        native_projection_tombstone_count,
                        native_projection_retired_count,
                        native_projection_physical_count,
                        native_projection_charged_bytes,
                        native_metadata_effect_fence_count,
                        native_metadata_effect_unreleased_count,
                        native_metadata_effect_released_count
                 FROM runtime_meta WHERE singleton = 1",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                    ))
                },
            )
            .expect("read zero v6 totals");
        assert_eq!(totals, (0, 0, 0, 0, 0, 0, 0, 0));
        assert_eq!(
            table_names(&connection).expect("read v6 manifest"),
            EXPECTED_TABLES
        );
        drop(connection);

        let reopened = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.database()),
            load_or_create_storage_kek(&keys, &root.database()).expect("reload migrated v6 KEK"),
        )
        .await
        .expect("reopen current v6 without a second migration");
        reopened.shutdown().await.expect("shutdown reopened v6");
        assert_eq!(cipher_evidence(&root.database()), before);
    }

    #[test]
    fn strict_v5_rescue_index_reads_without_migration_or_artifact_rewrite() {
        let root = TestRoot::new("v5-rescue-index");
        let keys = MemoryKeyStore::new();
        build_empty_strict_v5_fixture(&root, &keys);
        let artifacts_before = artifact_evidence(&root.database());

        assert_eq!(
            read_rescue_index(&root.database()).expect("read strict v5 rescue index without KEK"),
            Vec::<MachineEnrollmentReceiptRecord>::new()
        );
        assert_eq!(artifact_evidence(&root.database()), artifacts_before);
    }

    #[tokio::test]
    async fn legacy_v1_to_v4_offline_authenticated_wal_tamper_is_rejected_without_artifact_rewrite()
    {
        for legacy_version in [
            LegacySchemaVersion::V1,
            LegacySchemaVersion::V2,
            LegacySchemaVersion::V3,
            LegacySchemaVersion::V4,
        ] {
            let label = match legacy_version {
                LegacySchemaVersion::V1 => "v1",
                LegacySchemaVersion::V2 => "v2",
                LegacySchemaVersion::V3 => "v3",
                LegacySchemaVersion::V4 => "v4",
                LegacySchemaVersion::V5 | LegacySchemaVersion::V6 => {
                    unreachable!("table only covers legacy v1-v4")
                }
            };
            let root = TestRoot::new(&format!("{label}-offline-authenticated-wal-tamper"));
            let keys = MemoryKeyStore::new();
            match legacy_version {
                LegacySchemaVersion::V1 => {
                    build_strict_v1_fixture(&root, &keys).await;
                }
                LegacySchemaVersion::V2 => {
                    build_strict_v2_fixture(&root, &keys).await;
                }
                LegacySchemaVersion::V3 => {
                    build_strict_v3_fixture(&root, &keys).await;
                }
                LegacySchemaVersion::V4 => {
                    build_populated_strict_v4_fixture(&root, &keys).await;
                }
                LegacySchemaVersion::V5 | LegacySchemaVersion::V6 => {
                    unreachable!("table only covers legacy v1-v4")
                }
            }
            let database = normalize_storage_path(&root.database())
                .expect("normalize legacy offline tamper path");

            // 在冻结 oracle 前把 legacy main 正常切到 WAL header；此后不再用 SQLite
            // 打开目标库，tamper 只从 shadow writer 移植 committed WAL。
            let baseline = open_read_write(&database).expect("open legacy WAL baseline handle");
            let mode: String = baseline
                .query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))
                .expect("enable legacy WAL baseline");
            assert!(mode.eq_ignore_ascii_case("wal"));
            configure_persistent_wal(&baseline).expect("persist legacy WAL baseline");
            let (busy, log_frames, checkpointed_frames): (i64, i64, i64) = baseline
                .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?))
                })
                .expect("checkpoint legacy WAL baseline");
            assert_eq!(busy, 0, "{label} baseline checkpoint must not be busy");
            assert_eq!(log_frames, checkpointed_frames);
            drop(baseline);
            for suffix in ["-wal", "-shm"] {
                let path = sidecar(&database, suffix);
                match fs::remove_file(&path) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => {
                        panic!(
                            "remove {label} baseline sidecar {}: {error}",
                            path.display()
                        )
                    }
                }
            }

            let shadow_database = database.with_file_name(format!("{label}-tamper-shadow.db"));
            fs::copy(&database, &shadow_database).expect("clone legacy main for offline tamper");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&shadow_database, fs::Permissions::from_mode(DATABASE_MODE))
                    .expect("secure legacy offline tamper shadow");
            }
            let writer = open_read_write(&shadow_database).expect("open legacy tamper writer");
            writer
                .pragma_update(None, "wal_autocheckpoint", 0_i64)
                .expect("disable legacy tamper autocheckpoint");
            configure_persistent_wal(&writer).expect("persist legacy tamper WAL after close");
            assert_eq!(
                writer
                    .execute(
                        "UPDATE conversations SET metadata_token = zeroblob(32)
                         WHERE conversation_id = (
                             SELECT conversation_id FROM conversations
                             ORDER BY conversation_id LIMIT 1
                         )",
                        [],
                    )
                    .expect("commit invalid authenticated legacy conversation row"),
                1,
                "{label} fixture must contain an authenticated conversation row"
            );
            drop(writer);

            let shadow_wal = sidecar(&shadow_database, "-wal");
            let target_wal = sidecar(&database, "-wal");
            let copied = fs::copy(&shadow_wal, &target_wal)
                .expect("install closed-writer committed legacy tamper WAL");
            assert!(copied > 0, "{label} tamper WAL must be non-empty");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&target_wal, fs::Permissions::from_mode(DATABASE_MODE))
                    .expect("secure installed legacy tamper WAL");
            }

            let artifacts_before = artifact_evidence(&database);
            let identity_before =
                capture_store_identity(&database).expect("capture legacy offline tamper identity");
            let error = RuntimeStoreHandle::open(
                RuntimeStoreConfig::new(database.clone()),
                load_or_create_storage_kek(&keys, &database).expect("reload legacy tamper KEK"),
            )
            .await
            .expect_err("legacy offline authenticated WAL tamper must fail closed");
            assert_unknown_or_corrupt(error, &format!("offline-{label}-authenticated-row"));
            assert_eq!(
                artifact_evidence(&database),
                artifacts_before,
                "rejected offline {label} tamper must not rewrite any runtime artifact"
            );
            assert_eq!(
                capture_store_identity(&database)
                    .expect("recapture rejected legacy offline tamper identity"),
                identity_before,
                "rejected offline {label} tamper must preserve artifact identity"
            );
        }
    }

    #[tokio::test]
    async fn offline_v5_authenticated_sidecar_corruption_fails_before_artifact_rewrite() {
        for (label, tamper_sql) in [
            (
                "configuration",
                "UPDATE configuration_journal SET metadata_token = zeroblob(32)",
            ),
            (
                "pin",
                "UPDATE command_configuration_pins SET metadata_token = zeroblob(32)",
            ),
            (
                "metadata",
                "UPDATE metadata_mutation_ledger SET metadata_token = zeroblob(32)",
            ),
        ] {
            let root = TestRoot::new(&format!("v5-offline-{label}-tamper"));
            let keys = MemoryKeyStore::new();
            build_populated_strict_v5_fixture(&root, &keys).await;
            let database =
                normalize_storage_path(&root.database()).expect("normalize offline v5 tamper path");

            let checkpoint = open_read_write(&database).expect("open v5 checkpoint handle");
            let (busy, log_frames, checkpointed_frames): (i64, i64, i64) = checkpoint
                .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?))
                })
                .expect("checkpoint v5 tamper baseline");
            assert_eq!(busy, 0, "v5 tamper baseline checkpoint must not be busy");
            assert_eq!(log_frames, checkpointed_frames);
            drop(checkpoint);
            for suffix in ["-wal", "-shm"] {
                let path = sidecar(&database, suffix);
                match fs::remove_file(&path) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => panic!("remove v5 baseline sidecar {}: {error}", path.display()),
                }
            }

            let shadow_database = database.with_file_name(format!("v5-{label}-shadow.db"));
            fs::copy(&database, &shadow_database).expect("clone v5 main for offline tamper");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&shadow_database, fs::Permissions::from_mode(DATABASE_MODE))
                    .expect("secure v5 offline tamper shadow");
            }
            let writer = open_read_write(&shadow_database).expect("open v5 offline tamper writer");
            writer
                .pragma_update(None, "wal_autocheckpoint", 0_i64)
                .expect("disable v5 tamper autocheckpoint");
            configure_persistent_wal(&writer).expect("persist v5 tamper WAL after writer close");
            assert_eq!(
                writer
                    .execute(tamper_sql, [])
                    .expect("commit v5 sidecar tamper"),
                1,
                "populated v5 fixture must contain one {label} row"
            );
            drop(writer);

            let shadow_wal = sidecar(&shadow_database, "-wal");
            let target_wal = sidecar(&database, "-wal");
            let copied = fs::copy(&shadow_wal, &target_wal)
                .expect("install closed-writer committed v5 tamper WAL");
            assert!(copied > 0, "offline v5 tamper WAL must be non-empty");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&target_wal, fs::Permissions::from_mode(DATABASE_MODE))
                    .expect("secure installed v5 tamper WAL");
            }

            let artifacts_before = artifact_evidence(&database);
            let identity_before =
                capture_store_identity(&database).expect("capture offline v5 tamper identity");
            let error = RuntimeStoreHandle::open(
                RuntimeStoreConfig::new(database.clone()),
                load_or_create_storage_kek(&keys, &database).expect("reload v5 tamper KEK"),
            )
            .await
            .expect_err("offline v5 authenticated sidecar tamper must fail closed");
            assert_unknown_or_corrupt(error, &format!("offline-v5-{label}"));
            assert_eq!(
                artifact_evidence(&database),
                artifacts_before,
                "offline v5 {label} rejection must not rewrite any runtime artifact"
            );
            assert_eq!(
                capture_store_identity(&database)
                    .expect("recapture rejected offline v5 tamper identity"),
                identity_before,
                "offline v5 {label} rejection must preserve artifact identity"
            );
        }
    }

    #[tokio::test]
    async fn populated_v5_migrates_to_v6_with_non_meta_bytes_exact() {
        let root = TestRoot::new("v5-populated-to-v6");
        let keys = MemoryKeyStore::new();
        let (before, authenticated_before, _) =
            build_populated_strict_v5_fixture(&root, &keys).await;
        assert_eq!(before.descriptors.len(), 1);
        assert_eq!(before.codex_adapter_states.len(), 1);
        assert!(
            authenticated_before
                .iter()
                .any(|(column, values)| column == "conversations.metadata_token"
                    && !values.is_empty())
        );
        assert!(authenticated_before.iter().any(|(column, values)| column
            == "catalog_journal.metadata_token"
            && !values.is_empty()));

        let store = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.database()),
            load_or_create_storage_kek(&keys, &root.database()).expect("reload populated v5 KEK"),
        )
        .await
        .expect("migrate populated v5 fixture");
        assert_eq!(
            store
                .inspect()
                .await
                .expect("inspect populated v6 schema")
                .schema_version,
            RUNTIME_SCHEMA_VERSION
        );
        store.shutdown().await.expect("shutdown populated v6 store");
        let authenticated_after = {
            let connection =
                Connection::open(root.database()).expect("open migrated authenticated evidence");
            authenticated_blob_evidence(&connection)
        };
        assert_eq!(
            cipher_evidence(&root.database()),
            before,
            "v5 to v6 must preserve every old non-meta token/MAC/ciphertext and wrapped key"
        );
        assert_eq!(
            authenticated_after, authenticated_before,
            "v5 to v6 must preserve every old non-meta token/MAC/ciphertext"
        );
    }

    #[tokio::test]
    async fn migrated_v5_pruned_catalog_baseline_allows_first_native_import() {
        let root = TestRoot::new("v5-pruned-catalog-native-import");
        let keys = MemoryKeyStore::new();
        build_populated_strict_v5_fixture_with_metadata_mutation(&root, &keys, false).await;

        let connection = Connection::open(root.database()).expect("open populated v5 fixture");
        let mut meta = read_meta_v5(&connection)
            .expect("read populated v5 meta")
            .expect("populated v5 meta exists");
        assert!(meta.ledger.catalog_high_water.is_some());
        assert!(meta.ledger.catalog_delta_count > 0);
        assert!(
            connection
                .execute("DELETE FROM catalog_journal", [])
                .expect("prune the complete v5 catalog journal")
                > 0
        );
        meta.ledger.catalog_delta_count = 0;
        meta.ledger.catalog_delta_bytes = 0;
        meta.ledger.catalog_retention_floor = None;
        let storage_kek =
            load_or_create_storage_kek(&keys, &root.database()).expect("reload pruned v5 KEK");
        let key_bundle = RuntimeKeyBundle::unwrap(
            &storage_kek,
            &KeyWrapAad {
                schema_family: RUNTIME_SCHEMA_FAMILY.as_bytes(),
                schema_version: RUNTIME_CRYPTO_CONTEXT_VERSION,
                database_id: &meta.database_id,
            },
            &meta.wrapped_key_bundle,
        )
        .expect("unwrap pruned v5 key bundle");
        let token = runtime_ledger_token_v5(&key_bundle, meta.database_id, &meta.ledger)
            .expect("authenticate pruned v5 ledger");
        meta.metadata_token = token.to_vec();
        connection
            .execute(
                "UPDATE runtime_meta
                 SET catalog_delta_count = 0, catalog_delta_bytes = 0,
                     catalog_retention_floor = NULL, metadata_token = ?1
                 WHERE singleton = 1",
                [&token[..]],
            )
            .expect("publish authenticated pruned v5 catalog baseline");
        verify_runtime_ledger_token_v5(&key_bundle, &meta)
            .expect("verify authenticated pruned v5 ledger");
        super::super::journal::validate_store_integrity(&connection, &key_bundle, meta.database_id)
            .expect("validate complete pruned v5 fixture");
        drop(connection);

        let store = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.database()),
            load_or_create_storage_kek(&keys, &root.database()).expect("reload migrated v6 KEK"),
        )
        .await
        .expect("migrate authenticated pruned v5 fixture");
        let outcome = store
            .claude_code_native_projection_store()
            .import(ImportNativeProjection {
                descriptor: ConversationDescriptor {
                    agent_kind: AgentKind::ClaudeCode,
                    title: None,
                    cwd: PathBuf::new(),
                },
                default_configuration: ConversationConfiguration::new(
                    VendorConfigurationSnapshot::ClaudeCode(
                        ClaudeCodeConversationConfiguration::new(
                            ClaudeCodePermissionMode::Default,
                            None,
                            None,
                            None,
                        )
                        .expect("valid migrated native configuration"),
                    ),
                ),
                private_reference: SecretBytes::new(b"migrated-v5-native-reference".to_vec()),
                scan_generation: [0xC6; 16],
            })
            .await
            .expect("first native import after v5 migration");
        assert!(matches!(
            outcome,
            ImportNativeProjectionOutcome::Imported { .. }
        ));
        store
            .shutdown()
            .await
            .expect("shutdown migrated native import store");
    }

    #[tokio::test]
    async fn v5_before_commit_fault_rolls_back_v6_then_retries_once() {
        let root = TestRoot::new("v5-v6-before-commit");
        let keys = MemoryKeyStore::new();
        let before = build_empty_strict_v5_fixture(&root, &keys);
        let artifacts_before = artifact_evidence(&root.database());
        let error = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.database()).with_fault_injector(Arc::new(
                FailMigrationBeforeCommit {
                    failed: AtomicBool::new(false),
                },
            )),
            load_or_create_storage_kek(&keys, &root.database()).expect("reload v5 KEK"),
        )
        .await
        .expect_err("before-commit hook must abort v5 to v6 migration");
        assert!(matches!(error, RuntimeStoreError::WorkerStopped));
        assert_eq!(artifact_evidence(&root.database()), artifacts_before);
        assert_eq!(cipher_evidence(&root.database()), before);
        let legacy = Connection::open(root.database()).expect("inspect rolled back v5");
        assert_eq!(
            table_names(&legacy).expect("read rolled back v5 manifest"),
            EXPECTED_TABLES_V5
        );
        drop(legacy);

        let reopened = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.database()),
            load_or_create_storage_kek(&keys, &root.database()).expect("retry v6 migration KEK"),
        )
        .await
        .expect("retry rolled back v5 migration");
        reopened.shutdown().await.expect("shutdown retried v6");
        assert_eq!(cipher_evidence(&root.database()), before);
    }

    #[tokio::test]
    async fn v5_after_commit_unknown_reopens_as_v6_without_second_migration() {
        let root = TestRoot::new("v5-v6-after-commit");
        let keys = MemoryKeyStore::new();
        let before = build_empty_strict_v5_fixture(&root, &keys);
        let error = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.database()).with_fault_injector(Arc::new(
                FailMigrationAfterCommit {
                    failed: AtomicBool::new(false),
                },
            )),
            load_or_create_storage_kek(&keys, &root.database()).expect("reload v5 KEK"),
        )
        .await
        .expect_err("after-commit hook must surface unknown v6 migration outcome");
        assert!(matches!(
            error,
            RuntimeStoreError::CommitOutcomeUnknown {
                operation: RuntimeCommitOperation::MigrateSchema
            }
        ));
        let reopened = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.database()),
            load_or_create_storage_kek(&keys, &root.database()).expect("reload committed v6 KEK"),
        )
        .await
        .expect("reopen committed v6 migration");
        assert_eq!(
            reopened
                .inspect()
                .await
                .expect("inspect reopened v6")
                .schema_version,
            RUNTIME_SCHEMA_VERSION
        );
        reopened.shutdown().await.expect("shutdown reopened v6");
        assert_eq!(cipher_evidence(&root.database()), before);
    }

    #[tokio::test]
    async fn v5_native_projected_origin_is_rejected_before_v6_migration() {
        let root = TestRoot::new("v5-native-projected-reject");
        let keys = MemoryKeyStore::new();
        let (_, _, conversation_id) =
            build_populated_strict_v5_fixture_with_metadata_mutation(&root, &keys, false).await;
        let connection = Connection::open(root.database()).expect("open strict v5 native fixture");
        let meta = read_meta_v5(&connection)
            .expect("read strict v5 native meta")
            .expect("strict v5 native meta exists");
        let storage_kek = load_or_create_storage_kek(&keys, &root.database())
            .expect("reload strict v5 native KEK");
        let key_bundle = RuntimeKeyBundle::unwrap(
            &storage_kek,
            &KeyWrapAad {
                schema_family: RUNTIME_SCHEMA_FAMILY.as_bytes(),
                schema_version: RUNTIME_CRYPTO_CONTEXT_VERSION,
                database_id: &meta.database_id,
            },
            &meta.wrapped_key_bundle,
        )
        .expect("unwrap strict v5 native keys");
        let (current_revision, entry_revision): (Option<String>, String) = connection
            .query_row(
                "SELECT current_configuration_revision, entry_revision
                     FROM conversation_state WHERE conversation_id = ?1",
                [&conversation_id.as_bytes()[..]],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("read populated v5 conversation state");
        let token = super::super::configuration::conversation_state_metadata_token(
            &key_bundle,
            conversation_id.as_bytes(),
            current_revision.as_deref(),
            &entry_revision,
            "nativeProjected",
            Some("codex"),
            None,
        )
        .expect("authenticate legacy native origin row");
        assert_eq!(
            connection
                .execute(
                    "UPDATE conversation_state
                 SET origin_kind = 'nativeProjected', origin_namespace = 'codex',
                     legacy_command_high_water = NULL,
                     metadata_token = ?1
                 WHERE conversation_id = ?2",
                    params![&token[..], &conversation_id.as_bytes()[..]],
                )
                .expect("publish authenticated legacy native origin row"),
            1
        );
        super::super::journal::validate_store_integrity(&connection, &key_bundle, meta.database_id)
            .expect("legacy native fixture remains ledger/FK/MAC self-consistent");
        drop(connection);
        let artifacts_before = artifact_evidence(&root.database());
        let error = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.database()),
            load_or_create_storage_kek(&keys, &root.database()).expect("reload v5 native KEK"),
        )
        .await
        .expect_err("legacy native projection cannot be guessed during v6 migration");
        assert!(matches!(error, RuntimeStoreError::UnknownOrCorruptSchema));
        assert_eq!(artifact_evidence(&root.database()), artifacts_before);
        let legacy = Connection::open(root.database()).expect("inspect rejected v5 native schema");
        assert_eq!(
            table_names(&legacy).expect("read rejected v5 manifest"),
            EXPECTED_TABLES_V5
        );
    }

    #[tokio::test]
    async fn current_v6_rejects_offline_committed_wal_sidecar_tamper_without_rewriting_artifacts() {
        for table in ["native_projection_state", "native_metadata_effect_fences"] {
            let root = TestRoot::new(&format!("v6-nonempty-{table}"));
            let keys = MemoryKeyStore::new();
            let database =
                normalize_storage_path(&root.database()).expect("normalize current v6 path");
            let store = RuntimeStoreHandle::open(
                RuntimeStoreConfig::new(database.clone()),
                load_or_create_storage_kek(&keys, &database).expect("create v6 KEK"),
            )
            .await
            .expect("create current v6 fixture");
            store.shutdown().await.expect("shutdown current v6 fixture");

            let checkpoint = open_read_write(&database).expect("open current v6 checkpoint handle");
            let (busy, log_frames, checkpointed_frames): (i64, i64, i64) = checkpoint
                .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?))
                })
                .expect("checkpoint current v6 baseline");
            assert_eq!(busy, 0, "current v6 baseline checkpoint must not be busy");
            assert_eq!(log_frames, checkpointed_frames);
            drop(checkpoint);
            for suffix in ["-wal", "-shm"] {
                let path = sidecar(&database, suffix);
                match fs::remove_file(&path) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => panic!("remove current v6 sidecar {}: {error}", path.display()),
                }
            }

            let shadow_database = database.with_file_name(format!("v6-{table}-shadow.db"));
            fs::copy(&database, &shadow_database).expect("clone current v6 main for WAL tamper");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&shadow_database, fs::Permissions::from_mode(DATABASE_MODE))
                    .expect("secure current v6 WAL shadow");
            }
            let writer = open_read_write(&shadow_database).expect("open current v6 shadow writer");
            writer
                .pragma_update(None, "wal_autocheckpoint", 0_i64)
                .expect("disable current v6 shadow autocheckpoint");
            configure_persistent_wal(&writer).expect("persist current v6 shadow WAL");
            writer
                .pragma_update(None, "foreign_keys", false)
                .expect("disable FK only for unaudited WAL fixture");
            match table {
                "native_projection_state" => {
                    writer
                        .execute(
                            "INSERT INTO native_projection_state (
                                 conversation_id, origin_namespace, state_reference_token,
                                 projection_state, scan_generation, observation_token,
                                 projection_catalog_revision, reconciled_at_ms,
                                 state_changed_at_ms, private_binding_retain_until_ms,
                                 charged_reference_bytes, metadata_token
                             ) VALUES (
                                 ?1, 'claude-code', ?2, 'present', ?3, ?4,
                                 '00000000000000000000', 1, 1, NULL, 60, ?5
                             )",
                            params![
                                &[0x11_u8; 16][..],
                                &[0x22_u8; 32][..],
                                &[0x33_u8; 16][..],
                                &[0x44_u8; 32][..],
                                &[0x55_u8; 32][..],
                            ],
                        )
                        .expect("insert unaudited projection row");
                }
                "native_metadata_effect_fences" => {
                    writer
                        .execute(
                            "INSERT INTO native_metadata_effect_fences (
                                 conversation_id, idempotency_token, daemon_boot_id,
                                 effect_nonce_token, effect_spec_token, process_group_id,
                                 leader_pid, leader_start_time, release_authorized_at_ms,
                                 release_token_commitment, logical_fence_bytes,
                                 metadata_token, sealed_fence
                             ) VALUES (
                                 ?1, ?2, ?3, ?4, ?5, 71, 71,
                                 '00000000000000000073', NULL, NULL, 126, ?6, zeroblob(166)
                             )",
                            params![
                                &[0x61_u8; 16][..],
                                &[0x62_u8; 32][..],
                                &[0x63_u8; 16][..],
                                &[0x64_u8; 32][..],
                                &[0x65_u8; 32][..],
                                &[0x66_u8; 32][..],
                            ],
                        )
                        .expect("insert unaudited effect-fence row");
                }
                _ => unreachable!("fixed sidecar fixture"),
            }
            drop(writer);

            let shadow_wal = sidecar(&shadow_database, "-wal");
            let target_wal = sidecar(&database, "-wal");
            let copied = fs::copy(&shadow_wal, &target_wal)
                .expect("install closed-writer committed current v6 tamper WAL");
            assert!(copied > 0, "current v6 tamper WAL must be non-empty");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&target_wal, fs::Permissions::from_mode(DATABASE_MODE))
                    .expect("secure installed current v6 tamper WAL");
            }

            let artifacts_before = artifact_evidence(&database);
            let identity_before =
                capture_store_identity(&database).expect("capture current v6 tamper identity");
            let error = RuntimeStoreHandle::open(
                RuntimeStoreConfig::new(database.clone()),
                load_or_create_storage_kek(&keys, &database).expect("reload v6 KEK"),
            )
            .await
            .expect_err("nonempty unaudited v6 sidecar must fail closed");
            assert!(matches!(error, RuntimeStoreError::UnknownOrCorruptSchema));
            assert_eq!(
                artifact_evidence(&database),
                artifacts_before,
                "rejected {table} row must not rewrite runtime artifacts"
            );
            assert_eq!(
                capture_store_identity(&database)
                    .expect("recapture rejected current v6 tamper identity"),
                identity_before,
                "rejected {table} row must preserve runtime artifact identity"
            );
        }
    }

    #[tokio::test]
    async fn strict_empty_v4_migrates_to_v6_once_without_rewrapping_keys() {
        let root = TestRoot::new("v4-empty");
        let keys = MemoryKeyStore::new();
        let before = build_empty_strict_v4_fixture(&root, &keys);
        assert_eq!(
            read_rescue_index(&root.database()).expect("read v4 rescue locator without KEK"),
            Vec::<MachineEnrollmentReceiptRecord>::new()
        );
        let store = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.database()),
            load_or_create_storage_kek(&keys, &root.database()).expect("reload v4 KEK"),
        )
        .await
        .expect("migrate strict v4 fixture");
        let snapshot = store.inspect().await.expect("inspect migrated v6 schema");
        assert_eq!(snapshot.schema_version, RUNTIME_SCHEMA_VERSION);
        assert_eq!(snapshot.table_names, EXPECTED_TABLES);
        store.shutdown().await.expect("shutdown migrated v6 store");
        assert_eq!(cipher_evidence(&root.database()), before);

        let connection = Connection::open(root.database()).expect("inspect empty v6 sidecars");
        let counts: (i64, i64, i64, i64) = connection
            .query_row(
                "SELECT
                     (SELECT COUNT(*) FROM conversation_state),
                     (SELECT COUNT(*) FROM configuration_journal),
                     (SELECT COUNT(*) FROM command_configuration_pins),
                     (SELECT COUNT(*) FROM metadata_mutation_ledger)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .expect("read empty v6 sidecars");
        assert_eq!(counts, (0, 0, 0, 0));
        drop(connection);

        let reopened = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.database()),
            load_or_create_storage_kek(&keys, &root.database()).expect("reload migrated v6 KEK"),
        )
        .await
        .expect("reopen current v6 fixture without a second migration");
        assert_eq!(
            reopened
                .inspect()
                .await
                .expect("inspect reopened v6")
                .schema_version,
            RUNTIME_SCHEMA_VERSION
        );
        reopened.shutdown().await.expect("shutdown reopened v6");
        assert_eq!(cipher_evidence(&root.database()), before);
    }

    #[tokio::test]
    async fn fresh_v6_state_keeps_null_before_first_and_tamper_fails_closed() {
        let root = TestRoot::new("v6-fresh-state");
        let keys = MemoryKeyStore::new();
        let store = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.database()),
            load_or_create_storage_kek(&keys, &root.database()).expect("create fresh v6 KEK"),
        )
        .await
        .expect("open fresh v6 store");
        store
            .create_conversation(conversation(0x31, b"fresh v6 descriptor"))
            .await
            .expect("create fresh v6 conversation");
        store.shutdown().await.expect("shutdown fresh v6 store");

        let connection = Connection::open(root.database()).expect("inspect fresh v6 state");
        let state: (Option<String>, String, Option<String>, i64) = connection
            .query_row(
                "SELECT current_configuration_revision, entry_revision,
                        legacy_command_high_water, length(metadata_token)
                 FROM conversation_state",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .expect("read fresh v6 state");
        assert_eq!(
            state,
            (None, super::super::sequence::encode_sequence(0), None, 32)
        );
        connection
            .execute(
                "UPDATE conversation_state SET legacy_command_high_water = ?1",
                [super::super::sequence::encode_sequence(0)],
            )
            .expect("tamper fresh cutoff without its MAC");
        drop(connection);
        RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.database()),
            load_or_create_storage_kek(&keys, &root.database()).expect("reload tampered v6 KEK"),
        )
        .await
        .expect_err("tampered fresh state must fail closed");

        let connection = Connection::open(root.database()).expect("restore then delete v6 state");
        connection
            .execute(
                "UPDATE conversation_state SET legacy_command_high_water = NULL",
                [],
            )
            .expect("restore authenticated fresh cutoff");
        connection
            .execute("DELETE FROM conversation_state", [])
            .expect("delete required conversation state");
        drop(connection);
        RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.database()),
            load_or_create_storage_kek(&keys, &root.database()).expect("reload deleted-state KEK"),
        )
        .await
        .expect_err("missing one-to-one conversation state must fail closed");
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[tokio::test]
    async fn current_open_rejects_post_inspection_wal_tamper_without_rewriting_artifacts() {
        let root = TestRoot::new("current-open-race");
        let keys = MemoryKeyStore::new();
        let database = root.database();
        let store = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(database.clone()),
            load_or_create_storage_kek(&keys, &database).expect("create current-open race KEK"),
        )
        .await
        .expect("open fresh current v6 store");
        let created = store
            .create_conversation(conversation(0x39, b"current open race descriptor"))
            .await
            .expect("create current-open race conversation");
        configure_source_conversation(&store, created.conversation_id, 0x3a).await;
        let accepted = match store
            .accept_command(AcceptCommand {
                conversation_id: created.conversation_id,
                owner: owner(0x3b),
                idempotency_key: "current-open-race-accepted".to_owned(),
                expected_configuration_revision: 1,
                payload: b"current open race payload".to_vec(),
            })
            .await
            .expect("persist current-open race command and pin")
        {
            AcceptOutcome::Accepted { command, .. } => command,
            AcceptOutcome::Replayed { .. } => panic!("fresh current-open command cannot replay"),
        };
        assert_eq!(accepted.configuration_revision, 1);
        store
            .shutdown()
            .await
            .expect("shutdown current-open race baseline");

        // 先把 production state 完整 checkpoint 到 main，并移除空 sidecar。这样
        // open_inner inspection 固定的 main identity 不会被攻击者的 SQLite handle
        // 本身改变；hook 只移植 shadow writer 产出的有效 committed WAL。
        let canonical_database =
            normalize_storage_path(&database).expect("normalize current-open checkpoint path");
        let checkpoint =
            open_read_write(&canonical_database).expect("open current-open checkpoint handle");
        let (busy, log_frames, checkpointed_frames): (i64, i64, i64) = checkpoint
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .expect("checkpoint current-open baseline");
        assert_eq!(busy, 0, "current-open baseline checkpoint must not be busy");
        assert_eq!(
            log_frames, checkpointed_frames,
            "current-open baseline checkpoint must copy every frame"
        );
        drop(checkpoint);
        for sidecar_path in [
            sidecar(&canonical_database, "-wal"),
            sidecar(&canonical_database, "-shm"),
        ] {
            match fs::remove_file(&sidecar_path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => panic!(
                    "remove checkpointed current-open sidecar {}: {error}",
                    sidecar_path.display()
                ),
            }
        }

        let mut post_hook_path = None;
        let mut post_hook_evidence = None;
        let mut post_hook_identity = None;
        let result = open_inner(
            &RuntimeStoreConfig::new(database.clone()),
            load_or_create_storage_kek(&keys, &database).expect("reload current-open race KEK"),
            |path| {
                let shadow_database = path.with_file_name("current-open-race-shadow.db");
                fs::copy(path, &shadow_database).expect("clone current main for race writer");
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(
                        &shadow_database,
                        fs::Permissions::from_mode(DATABASE_MODE),
                    )
                    .expect("secure current-open race shadow");
                }
                let mut writer =
                    open_read_write(&shadow_database).expect("open independent race writer");
                writer
                    .pragma_update(None, "wal_autocheckpoint", 0_i64)
                    .expect("disable race writer WAL autocheckpoint");
                assert_eq!(
                    writer
                        .query_row("PRAGMA wal_autocheckpoint", [], |row| row.get::<_, i64>(0))
                        .expect("read back race writer WAL autocheckpoint"),
                    0
                );
                configure_persistent_wal(&writer).expect("keep race writer WAL artifact");

                let original_token: Vec<u8> = writer
                    .query_row(
                        "SELECT metadata_token FROM command_configuration_pins",
                        [],
                        |row| row.get(0),
                    )
                    .expect("read current command pin token");
                assert_eq!(original_token.len(), 32);
                let mut tampered_token = original_token.clone();
                tampered_token[0] ^= 0xff;
                let transaction = writer
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .expect("begin current-open WAL tamper");
                assert_eq!(
                    transaction
                        .execute(
                            "UPDATE command_configuration_pins
                             SET metadata_token = ?1
                             WHERE metadata_token = ?2",
                            params![&tampered_token, &original_token],
                        )
                        .expect("tamper current command pin token"),
                    1
                );
                transaction
                    .commit()
                    .expect("commit current-open WAL tamper");
                assert_eq!(
                    writer
                        .query_row(
                            "SELECT metadata_token FROM command_configuration_pins",
                            [],
                            |row| row.get::<_, Vec<u8>>(0),
                        )
                        .expect("read back current command pin tamper"),
                    tampered_token
                );
                drop(writer);

                let shadow_wal = sidecar(&shadow_database, "-wal");
                let target_wal = sidecar(path, "-wal");
                let copied = fs::copy(&shadow_wal, &target_wal)
                    .expect("move committed shadow WAL into current-open race window");
                assert!(copied > 0, "committed shadow WAL must be non-empty");
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(&target_wal, fs::Permissions::from_mode(DATABASE_MODE))
                        .expect("secure current-open transplanted WAL");
                }

                let evidence = artifact_evidence(path);
                assert!(
                    evidence[1]
                        .1
                        .as_ref()
                        .is_some_and(|bytes| !bytes.is_empty()),
                    "committed race tamper must remain in a non-empty WAL"
                );
                post_hook_path = Some(path.to_path_buf());
                post_hook_evidence = Some(evidence);
                post_hook_identity = Some(
                    capture_store_identity(path)
                        .expect("capture current-open post-hook artifact identity"),
                );
                Ok(())
            },
        );
        let error = match result {
            Ok(_) => panic!("post-inspection current WAL tamper must fail closed"),
            Err(error) => error,
        };
        assert!(
            matches!(error, RuntimeStoreError::SchemaInspectionRaced),
            "post-inspection identity drift must win before RW open, got {error:?}"
        );
        let post_hook_evidence =
            post_hook_evidence.expect("current hook fixed its post-attack artifact baseline");
        let post_hook_identity =
            post_hook_identity.expect("current hook fixed its post-attack identity baseline");
        let post_hook_path = post_hook_path.expect("current hook exposed the canonical DB path");
        // 该 byte-exact 契约只从攻击者 hook 已提交并关闭 writer 后开始；不把攻击写入
        // 本身算作 store 写入。Unix identity 的 ctime/mtime/device/inode 边界仅在当前
        // 支持的 macOS/Linux 门禁上锁定。
        assert_eq!(
            artifact_evidence(&post_hook_path),
            post_hook_evidence,
            "identity-raced open must not rewrite any post-hook runtime artifact"
        );
        assert_eq!(
            capture_store_identity(&post_hook_path)
                .expect("recapture rejected current-open artifact identity"),
            post_hook_identity,
            "identity-raced open must not touch post-hook runtime artifact metadata"
        );

        let error = match open(
            &RuntimeStoreConfig::new(database.clone()),
            load_or_create_storage_kek(&keys, &database)
                .expect("reload corrupt current-open race KEK"),
        ) {
            Ok(_) => panic!("ordinary reopen must reject the tampered current pin"),
            Err(error) => error,
        };
        assert_unknown_or_corrupt(error, "post-race ordinary reopen");
        assert_eq!(
            artifact_evidence(&post_hook_path),
            post_hook_evidence,
            "authenticated corruption rejection must preserve the post-hook baseline"
        );
        assert_eq!(
            capture_store_identity(&post_hook_path)
                .expect("recapture ordinary-reopen artifact identity"),
            post_hook_identity,
            "authenticated corruption rejection must preserve post-hook artifact metadata"
        );
    }

    #[tokio::test]
    async fn v4_capacity_rejection_is_zero_write_before_m5() {
        let root = TestRoot::new("v4-capacity");
        let keys = MemoryKeyStore::new();
        let cipher_before = build_empty_strict_v4_fixture(&root, &keys);
        let artifacts_before = artifact_evidence(&root.database());
        let error = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.database()).with_capacity_probe(MigrationLowDisk),
            load_or_create_storage_kek(&keys, &root.database()).expect("reload v4 KEK"),
        )
        .await
        .expect_err("v4 migration capacity gate must run before M5");
        assert!(matches!(error, RuntimeStoreError::DiskLow { .. }));
        assert_eq!(artifact_evidence(&root.database()), artifacts_before);
        let legacy = Connection::open(root.database()).expect("inspect capacity-rejected v4");
        assert_eq!(
            table_names(&legacy).expect("read rejected v4 manifest"),
            EXPECTED_TABLES_V4
        );
        drop(legacy);
        assert_eq!(cipher_evidence(&root.database()), cipher_before);
    }

    #[tokio::test]
    async fn v4_before_commit_fault_rolls_back_m5_then_retries_once() {
        let root = TestRoot::new("v4-before-commit");
        let keys = MemoryKeyStore::new();
        let before = build_empty_strict_v4_fixture(&root, &keys);
        let artifacts_before = artifact_evidence(&root.database());
        let error = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.database()).with_fault_injector(Arc::new(
                FailMigrationBeforeCommit {
                    failed: AtomicBool::new(false),
                },
            )),
            load_or_create_storage_kek(&keys, &root.database()).expect("reload v4 KEK"),
        )
        .await
        .expect_err("before-commit hook must abort v4 migration");
        assert!(matches!(error, RuntimeStoreError::WorkerStopped));
        assert_eq!(artifact_evidence(&root.database()), artifacts_before);
        let legacy = Connection::open(root.database()).expect("inspect rolled back v4");
        assert_eq!(
            table_names(&legacy).expect("read rolled back v4 manifest"),
            EXPECTED_TABLES_V4
        );
        drop(legacy);
        assert_eq!(cipher_evidence(&root.database()), before);

        let reopened = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.database()),
            load_or_create_storage_kek(&keys, &root.database()).expect("retry v4 migration KEK"),
        )
        .await
        .expect("retry rolled back v4 migration");
        assert_eq!(
            reopened
                .inspect()
                .await
                .expect("inspect retried v6")
                .schema_version,
            RUNTIME_SCHEMA_VERSION
        );
        reopened.shutdown().await.expect("shutdown retried v6");
        assert_eq!(cipher_evidence(&root.database()), before);
    }

    #[tokio::test]
    async fn v4_after_commit_unknown_reopens_as_current_without_second_m5() {
        let root = TestRoot::new("v4-after-commit");
        let keys = MemoryKeyStore::new();
        let before = build_empty_strict_v4_fixture(&root, &keys);
        let error = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.database()).with_fault_injector(Arc::new(
                FailMigrationAfterCommit {
                    failed: AtomicBool::new(false),
                },
            )),
            load_or_create_storage_kek(&keys, &root.database()).expect("reload v4 KEK"),
        )
        .await
        .expect_err("after-commit hook must surface unknown v4 migration outcome");
        assert!(matches!(
            error,
            RuntimeStoreError::CommitOutcomeUnknown {
                operation: RuntimeCommitOperation::MigrateSchema
            }
        ));
        let reopened = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.database()),
            load_or_create_storage_kek(&keys, &root.database()).expect("reload committed v6 KEK"),
        )
        .await
        .expect("reopen committed v4 migration");
        assert_eq!(
            reopened
                .inspect()
                .await
                .expect("inspect reopened v6")
                .schema_version,
            RUNTIME_SCHEMA_VERSION
        );
        reopened.shutdown().await.expect("shutdown reopened v6");
        assert_eq!(cipher_evidence(&root.database()), before);
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
        assert_eq!(snapshot.schema_version, RUNTIME_SCHEMA_VERSION);
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
    async fn strict_v3_migrates_to_v6_without_rewrapping_or_reencrypting_existing_rows() {
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
            RUNTIME_SCHEMA_VERSION
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

    struct TamperAfterLegacyAuthentication {
        tampered: AtomicBool,
    }

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

    impl RuntimeCapacityProbe for TamperAfterLegacyAuthentication {
        fn observe(
            &self,
            database_path: &Path,
        ) -> Result<RuntimeCapacityObservation, RuntimeCapacityProbeError> {
            if !self.tampered.swap(true, Ordering::SeqCst) {
                let connection = Connection::open(database_path).expect("open post-auth tamper DB");
                connection
                    .execute(
                        "UPDATE codex_adapter_state
                         SET sealed_state_reference = zeroblob(length(sealed_state_reference))",
                        [],
                    )
                    .expect("tamper legacy adapter row after preflight authentication");
            }
            Ok(RuntimeCapacityObservation {
                main_bytes: fs::metadata(database_path)
                    .expect("read post-auth tamper DB size")
                    .len(),
                wal_bytes: 0,
                shm_bytes: 0,
                filesystem_total_bytes: 4 * 1024 * 1024 * 1024,
                filesystem_available_bytes: 4 * 1024 * 1024 * 1024,
            })
        }
    }

    #[tokio::test]
    async fn row_tamper_between_preflight_and_begin_cannot_publish_v5() {
        let root = TestRoot::new("post-auth-row-tamper");
        let keys = MemoryKeyStore::new();
        build_strict_v2_fixture(&root, &keys).await;
        RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.database()).with_capacity_probe(
                TamperAfterLegacyAuthentication {
                    tampered: AtomicBool::new(false),
                },
            ),
            load_or_create_storage_kek(&keys, &root.database()).expect("reload tampered v2 KEK"),
        )
        .await
        .expect_err("post-auth legacy row tamper must fail before migration DDL");
        let connection = Connection::open(root.database()).expect("inspect rejected row tamper");
        let version: i64 = connection
            .query_row(
                "SELECT schema_version FROM runtime_meta WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .expect("read rejected row-tamper version");
        assert_eq!(version, 2, "M3-M5 must not commit after post-auth tamper");
        assert_eq!(
            table_names(&connection).expect("read rejected row-tamper manifest"),
            EXPECTED_TABLES_V2
        );
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
    async fn v2_migration_before_commit_fault_rolls_back_then_reopens_to_v6() {
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
            RUNTIME_SCHEMA_VERSION
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
            RUNTIME_SCHEMA_VERSION
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
    pub configuration_count: u64,
    pub configuration_sealed_bytes: u64,
    pub command_configuration_pin_count: u64,
    pub metadata_mutation_count: u64,
    pub active_metadata_mutation_count: u64,
    pub metadata_mutation_charged_bytes: u64,
    pub native_projection_present_count: u64,
    pub native_projection_tombstone_count: u64,
    pub native_projection_retired_count: u64,
    pub native_projection_physical_count: u64,
    pub native_projection_charged_bytes: u64,
    pub native_metadata_effect_fence_count: u64,
    pub native_metadata_effect_unreleased_count: u64,
    pub native_metadata_effect_released_count: u64,
    pub admin_command_count: u64,
    pub admin_command_pending_count: u64,
    pub admin_command_charged_bytes: u64,
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
    LegacyV4(MetaRow, StoreFileIdentity),
    LegacyV5(MetaRow, StoreFileIdentity),
    LegacyV6(MetaRow, StoreFileIdentity),
    Current(MetaRow, StoreFileIdentity),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LegacySchemaVersion {
    V1,
    V2,
    V3,
    V4,
    V5,
    V6,
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
    open_inner(config, storage_kek, noop_current_open_hook)
}

fn noop_current_open_hook(_storage_path: &Path) -> Result<(), RuntimeStoreError> {
    Ok(())
}

fn open_inner<F>(
    config: &RuntimeStoreConfig,
    storage_kek: StorageKek,
    current_open_hook: F,
) -> Result<RuntimeSqlite, RuntimeStoreError>
where
    F: FnOnce(&Path) -> Result<(), RuntimeStoreError>,
{
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
    let state = inspect_schema(&storage_path, &storage_kek)?;
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
        SchemaState::LegacyV4(meta, identity) => open_legacy(
            config,
            storage_path,
            &storage_kek,
            meta,
            identity,
            LegacySchemaVersion::V4,
        ),
        SchemaState::LegacyV5(meta, identity) => open_legacy(
            config,
            storage_path,
            &storage_kek,
            meta,
            identity,
            LegacySchemaVersion::V5,
        ),
        SchemaState::LegacyV6(meta, identity) => open_legacy(
            config,
            storage_path,
            &storage_kek,
            meta,
            identity,
            LegacySchemaVersion::V6,
        ),
        SchemaState::Current(meta, identity) => open_current(
            config,
            storage_path,
            &storage_kek,
            meta,
            identity,
            current_open_hook,
        ),
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
        transaction.execute_batch(RUNTIME_MIGRATION_V5)?;
        transaction.execute_batch(RUNTIME_MIGRATION_V6)?;
        transaction.execute_batch(RUNTIME_MIGRATION_V7)?;
        transaction.execute(
            "INSERT INTO runtime_meta (
                 singleton, schema_family, schema_version, schema_signature,
                 database_id, key_generation, wrapped_key_bundle, catalog_high_water,
                 conversation_count, command_count, event_count, intent_count, fence_count,
                 codex_adapter_state_count, claude_code_adapter_state_count,
                 approval_count, active_approval_count,
                 configuration_count, configuration_sealed_bytes,
                 command_configuration_pin_count, metadata_mutation_count,
                 active_metadata_mutation_count, metadata_mutation_charged_bytes,
                 accepted_count, accepted_payload_bytes, started_without_fence_count,
                 started_without_release_count, started_released_count, metadata_token
             ) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, NULL,
                       0, 0, 0, 0, 0, 0, 0, 0, 0,
                       0, 0, 0, 0, 0, 0,
                       0, 0, 0, 0, 0, ?7)",
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

fn open_current<F>(
    config: &RuntimeStoreConfig,
    storage_path: PathBuf,
    storage_kek: &StorageKek,
    inspected: MetaRow,
    inspected_identity: StoreFileIdentity,
    current_open_hook: F,
) -> Result<RuntimeSqlite, RuntimeStoreError>
where
    F: FnOnce(&Path) -> Result<(), RuntimeStoreError>,
{
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
    current_open_hook(&storage_path)?;
    // Hook 代表 rescue validation 完成后同 UID writer 可用的最宽竞态窗口。
    // 在原库 RW open 前最后一次比较完整 main/WAL/SHM identity；否则即使随后
    // fail-close，sqlite3_open/drop 仍可能把攻击者 WAL checkpoint 进 main。
    ensure_store_identity(&storage_path, &inspected_identity)?;
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
        LegacySchemaVersion::V4 => verify_runtime_ledger_token_v4(&key_bundle, &inspected)?,
        LegacySchemaVersion::V5 => verify_runtime_ledger_token_v5(&key_bundle, &inspected)?,
        LegacySchemaVersion::V6 => verify_runtime_ledger_token_v6(&key_bundle, &inspected)?,
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
        LegacySchemaVersion::V4 => read_and_validate_legacy_v4_schema(&connection)?,
        LegacySchemaVersion::V5 => read_and_validate_legacy_v5_schema(&connection)?,
        LegacySchemaVersion::V6 => read_and_validate_legacy_v6_schema(&connection)?,
    };
    if !same_meta(&inspected, &current) {
        return Err(RuntimeStoreError::SchemaInspectionRaced);
    }
    validate_store_files(&storage_path)?;
    if legacy_version == LegacySchemaVersion::V5 {
        reject_legacy_v5_native_projection(&connection)?;
    }
    // migration 前先用旧版 authenticated ledger 与 stable crypto context 完整认证既有行；
    // corrupt legacy DB 不得被“升级”成可识别的新 schema。
    match legacy_version {
        LegacySchemaVersion::V1 => super::journal::validate_store_integrity_v1(
            &connection,
            &key_bundle,
            current.database_id,
            &current.ledger,
        )?,
        LegacySchemaVersion::V2
        | LegacySchemaVersion::V3
        | LegacySchemaVersion::V4
        | LegacySchemaVersion::V5
        | LegacySchemaVersion::V6 => {
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
    let v5_projection = if matches!(
        legacy_version,
        LegacySchemaVersion::V5 | LegacySchemaVersion::V6
    ) {
        0
    } else {
        super::configuration::migration_projection_bytes(current.ledger.conversation_count)?
    };
    let migration_projection = match legacy_version {
        LegacySchemaVersion::V4 => v5_projection,
        LegacySchemaVersion::V5 | LegacySchemaVersion::V6 => 0,
        LegacySchemaVersion::V1 | LegacySchemaVersion::V2 | LegacySchemaVersion::V3 => {
            super::stream::migration_projection_bytes(&connection)?
                .checked_add(v5_projection)
                .ok_or(RuntimeStoreError::CapacityArithmeticOverflow {
                    field: "v1-v3 to v6 migration projection bytes",
                })?
        }
    };
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
        LegacySchemaVersion::V4 => schema_signature_v4(),
        LegacySchemaVersion::V5 => schema_signature_v5(),
        LegacySchemaVersion::V6 => schema_signature_v6(),
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
        LegacySchemaVersion::V4 => {
            runtime_ledger_token_v4(&key_bundle, current.database_id, &current.ledger)?
        }
        LegacySchemaVersion::V5 => {
            runtime_ledger_token_v5(&key_bundle, current.database_id, &current.ledger)?
        }
        LegacySchemaVersion::V6 => {
            runtime_ledger_token_v6(&key_bundle, current.database_id, &current.ledger)?
        }
    };
    let mut transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    // 容量 probe 与 BEGIN 之间不能沿用先前认证结果：同 UID 的另一 SQLite
    // writer 可能只改数据行而保持 runtime_meta CAS 不变。取得 write lock 后先
    // 重读旧 meta/token 并在同一 transaction 内再次认证全部 legacy 行；在此
    // 之前不执行任何 migration DDL 或 sidecar materialization。
    let locked = match legacy_version {
        LegacySchemaVersion::V1 => read_and_validate_legacy_v1_schema(&transaction)?,
        LegacySchemaVersion::V2 => read_and_validate_legacy_v2_schema(&transaction)?,
        LegacySchemaVersion::V3 => read_and_validate_legacy_v3_schema(&transaction)?,
        LegacySchemaVersion::V4 => read_and_validate_legacy_v4_schema(&transaction)?,
        LegacySchemaVersion::V5 => read_and_validate_legacy_v5_schema(&transaction)?,
        LegacySchemaVersion::V6 => read_and_validate_legacy_v6_schema(&transaction)?,
    };
    if !same_meta(&current, &locked) {
        return Err(RuntimeStoreError::SchemaInspectionRaced);
    }
    if legacy_version == LegacySchemaVersion::V5 {
        reject_legacy_v5_native_projection(&transaction)?;
    }
    match legacy_version {
        LegacySchemaVersion::V1 => {
            verify_runtime_ledger_token_v1(&key_bundle, &locked)?;
            super::journal::validate_store_integrity_v1(
                &transaction,
                &key_bundle,
                locked.database_id,
                &locked.ledger,
            )?;
        }
        LegacySchemaVersion::V2 => verify_runtime_ledger_token_v2(&key_bundle, &locked)?,
        LegacySchemaVersion::V3 => verify_runtime_ledger_token_v3(&key_bundle, &locked)?,
        LegacySchemaVersion::V4 => verify_runtime_ledger_token_v4(&key_bundle, &locked)?,
        LegacySchemaVersion::V5 => verify_runtime_ledger_token_v5(&key_bundle, &locked)?,
        LegacySchemaVersion::V6 => verify_runtime_ledger_token_v6(&key_bundle, &locked)?,
    }
    if legacy_version != LegacySchemaVersion::V1 {
        super::journal::validate_store_integrity(&transaction, &key_bundle, locked.database_id)?;
    }
    if legacy_version == LegacySchemaVersion::V1 {
        transaction.execute_batch(RUNTIME_MIGRATION_V2)?;
    }
    if matches!(
        legacy_version,
        LegacySchemaVersion::V1 | LegacySchemaVersion::V2
    ) {
        transaction.execute_batch(RUNTIME_MIGRATION_V3)?;
    }
    let migrated_ledger = if matches!(
        legacy_version,
        LegacySchemaVersion::V4 | LegacySchemaVersion::V5 | LegacySchemaVersion::V6
    ) {
        current.ledger.clone()
    } else {
        transaction.execute_batch(RUNTIME_MIGRATION_V4)?;
        super::stream::migrate_v4_rows(
            &transaction,
            &key_bundle,
            current.database_id,
            &current.ledger,
        )?
    };
    if !matches!(
        legacy_version,
        LegacySchemaVersion::V5 | LegacySchemaVersion::V6
    ) {
        transaction.execute_batch(RUNTIME_MIGRATION_V5)?;
        super::configuration::materialize_legacy_v4_states(
            &transaction,
            &key_bundle,
            &migrated_ledger,
        )?;
    }
    if legacy_version != LegacySchemaVersion::V6 {
        transaction.execute_batch(RUNTIME_MIGRATION_V6)?;
    }
    transaction.execute_batch(RUNTIME_MIGRATION_V7)?;
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
             configuration_count = ?18, configuration_sealed_bytes = ?19,
             command_configuration_pin_count = ?20,
             metadata_mutation_count = ?21, active_metadata_mutation_count = ?22,
             metadata_mutation_charged_bytes = ?23,
             metadata_token = ?24
         WHERE singleton = 1 AND schema_version = ?25 AND schema_signature = ?26
           AND metadata_token = ?27",
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
            i64::try_from(migrated_ledger.configuration_count)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            i64::try_from(migrated_ledger.configuration_sealed_bytes)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            i64::try_from(migrated_ledger.command_configuration_pin_count)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            i64::try_from(migrated_ledger.metadata_mutation_count)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            i64::try_from(migrated_ledger.active_metadata_mutation_count)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            i64::try_from(migrated_ledger.metadata_mutation_charged_bytes)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            &new_token[..],
            match legacy_version {
                LegacySchemaVersion::V1 => 1_i64,
                LegacySchemaVersion::V2 => 2_i64,
                LegacySchemaVersion::V3 => 3_i64,
                LegacySchemaVersion::V4 => 4_i64,
                LegacySchemaVersion::V5 => 5_i64,
                LegacySchemaVersion::V6 => 6_i64,
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

fn inspect_schema(path: &Path, storage_kek: &StorageKek) -> Result<SchemaState, RuntimeStoreError> {
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
                1 if family == RUNTIME_SCHEMA_FAMILY => {
                    let legacy = read_and_validate_legacy_v1_schema(connection)?;
                    validate_legacy_before_read_write_open(
                        connection,
                        storage_kek,
                        &legacy,
                        LegacySchemaVersion::V1,
                    )?;
                    SchemaState::LegacyV1(legacy, identity.clone())
                }
                2 if family == RUNTIME_SCHEMA_FAMILY => {
                    let legacy = read_and_validate_legacy_v2_schema(connection)?;
                    validate_legacy_before_read_write_open(
                        connection,
                        storage_kek,
                        &legacy,
                        LegacySchemaVersion::V2,
                    )?;
                    SchemaState::LegacyV2(legacy, identity.clone())
                }
                3 if family == RUNTIME_SCHEMA_FAMILY => {
                    let legacy = read_and_validate_legacy_v3_schema(connection)?;
                    validate_legacy_before_read_write_open(
                        connection,
                        storage_kek,
                        &legacy,
                        LegacySchemaVersion::V3,
                    )?;
                    SchemaState::LegacyV3(legacy, identity.clone())
                }
                4 if family == RUNTIME_SCHEMA_FAMILY => {
                    let legacy = read_and_validate_legacy_v4_schema(connection)?;
                    validate_legacy_before_read_write_open(
                        connection,
                        storage_kek,
                        &legacy,
                        LegacySchemaVersion::V4,
                    )?;
                    SchemaState::LegacyV4(legacy, identity.clone())
                }
                RUNTIME_SCHEMA_VERSION_V5 if family == RUNTIME_SCHEMA_FAMILY => {
                    let legacy = read_and_validate_legacy_v5_schema(connection)?;
                    validate_legacy_before_read_write_open(
                        connection,
                        storage_kek,
                        &legacy,
                        LegacySchemaVersion::V5,
                    )?;
                    SchemaState::LegacyV5(legacy, identity.clone())
                }
                RUNTIME_SCHEMA_VERSION_V6 if family == RUNTIME_SCHEMA_FAMILY => {
                    let legacy = read_and_validate_legacy_v6_schema(connection)?;
                    validate_legacy_before_read_write_open(
                        connection,
                        storage_kek,
                        &legacy,
                        LegacySchemaVersion::V6,
                    )?;
                    SchemaState::LegacyV6(legacy, identity.clone())
                }
                RUNTIME_SCHEMA_VERSION if family == RUNTIME_SCHEMA_FAMILY => {
                    let current = read_and_validate_current_schema(connection)?;
                    // WAL recovery 的 schema inspection 已在私有 rescue 副本上看到完整
                    // committed state。必须在碰原库 RW handle 前认证 configuration state/pin：
                    // 否则 corrupt current v6 虽会 fail-close，RW connection drop 仍可能把
                    // 原 WAL checkpoint 进 main，破坏“拒绝即零改写”的证据边界。
                    validate_current_before_read_write_open(connection, storage_kek, &current)?;
                    SchemaState::Current(current, identity.clone())
                }
                _ => return Err(RuntimeStoreError::UnknownOrCorruptSchema),
            };
            validate_store_files(path)?;
            ensure_store_identity(path, &identity)?;
            Ok(state)
        }
    }
}

fn reject_legacy_v5_native_projection(connection: &Connection) -> Result<(), RuntimeStoreError> {
    let native_present: i64 = connection.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM conversation_state WHERE origin_kind = 'nativeProjected'
         )",
        [],
        |row| row.get(0),
    )?;
    if native_present != 0 {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(())
}

fn validate_legacy_before_read_write_open(
    connection: &Connection,
    storage_kek: &StorageKek,
    legacy: &MetaRow,
    legacy_version: LegacySchemaVersion,
) -> Result<(), RuntimeStoreError> {
    let key_context = KeyWrapAad {
        schema_family: RUNTIME_SCHEMA_FAMILY.as_bytes(),
        schema_version: RUNTIME_CRYPTO_CONTEXT_VERSION,
        database_id: &legacy.database_id,
    };
    let key_bundle =
        RuntimeKeyBundle::unwrap(storage_kek, &key_context, &legacy.wrapped_key_bundle)?;
    if key_bundle.generation() != legacy.key_generation {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    match legacy_version {
        LegacySchemaVersion::V1 => verify_runtime_ledger_token_v1(&key_bundle, legacy)?,
        LegacySchemaVersion::V2 => verify_runtime_ledger_token_v2(&key_bundle, legacy)?,
        LegacySchemaVersion::V3 => verify_runtime_ledger_token_v3(&key_bundle, legacy)?,
        LegacySchemaVersion::V4 => verify_runtime_ledger_token_v4(&key_bundle, legacy)?,
        LegacySchemaVersion::V5 => verify_runtime_ledger_token_v5(&key_bundle, legacy)?,
        LegacySchemaVersion::V6 => verify_runtime_ledger_token_v6(&key_bundle, legacy)?,
    }
    if legacy_version == LegacySchemaVersion::V5 {
        reject_legacy_v5_native_projection(connection)?;
    }
    // WAL recovery 已在私有 rescue 副本上得到完整 committed state；所有 legacy
    // 版本都必须先认证 metadata ledger 与既有行，再触碰原库 RW。v1 保持冻结的
    // strict-v1 ledger 语义，其余版本复用当前版本化 ledger validator。
    match legacy_version {
        LegacySchemaVersion::V1 => super::journal::validate_store_integrity_v1(
            connection,
            &key_bundle,
            legacy.database_id,
            &legacy.ledger,
        )?,
        LegacySchemaVersion::V2
        | LegacySchemaVersion::V3
        | LegacySchemaVersion::V4
        | LegacySchemaVersion::V5
        | LegacySchemaVersion::V6 => {
            super::journal::validate_store_integrity(connection, &key_bundle, legacy.database_id)?;
        }
    }
    Ok(())
}

fn validate_current_before_read_write_open(
    connection: &Connection,
    storage_kek: &StorageKek,
    current: &MetaRow,
) -> Result<(), RuntimeStoreError> {
    let key_context = KeyWrapAad {
        schema_family: RUNTIME_SCHEMA_FAMILY.as_bytes(),
        schema_version: RUNTIME_CRYPTO_CONTEXT_VERSION,
        database_id: &current.database_id,
    };
    let key_bundle =
        RuntimeKeyBundle::unwrap(storage_kek, &key_context, &current.wrapped_key_bundle)?;
    if key_bundle.generation() != current.key_generation {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    verify_runtime_ledger_token(&key_bundle, current)?;
    super::journal::validate_store_integrity(connection, &key_bundle, current.database_id)?;
    Ok(())
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

pub(crate) fn runtime_schema_version(connection: &Connection) -> Result<u32, RuntimeStoreError> {
    let (family, version) = read_schema_header(connection)?;
    if family != RUNTIME_SCHEMA_FAMILY {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(version)
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

fn read_and_validate_legacy_v4_schema(
    connection: &Connection,
) -> Result<MetaRow, RuntimeStoreError> {
    let Some(meta) =
        read_meta_v4(connection).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
    else {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    };
    if meta.family != RUNTIME_SCHEMA_FAMILY
        || meta.version != 4
        || meta.signature != schema_signature_v4()
        || meta.key_generation != RUNTIME_KEY_GENERATION
        || meta.wrapped_key_bundle.len() != WRAPPED_KEY_BUNDLE_V1_LEN
        || meta.metadata_token.len() != 32
        || table_names(connection)? != EXPECTED_TABLES_V4
        || schema_manifest(connection)? != expected_schema_manifest(4)?
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(meta)
}

fn read_and_validate_legacy_v5_schema(
    connection: &Connection,
) -> Result<MetaRow, RuntimeStoreError> {
    let Some(meta) =
        read_meta_v5(connection).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
    else {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    };
    if meta.family != RUNTIME_SCHEMA_FAMILY
        || meta.version != RUNTIME_SCHEMA_VERSION_V5
        || meta.signature != schema_signature_v5()
        || meta.key_generation != RUNTIME_KEY_GENERATION
        || meta.wrapped_key_bundle.len() != WRAPPED_KEY_BUNDLE_V1_LEN
        || meta.metadata_token.len() != 32
        || table_names(connection)? != EXPECTED_TABLES_V5
        || schema_manifest(connection)? != expected_schema_manifest(5)?
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(meta)
}

fn read_and_validate_legacy_v6_schema(
    connection: &Connection,
) -> Result<MetaRow, RuntimeStoreError> {
    let Some(meta) =
        read_meta_v6(connection).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
    else {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    };
    if meta.family != RUNTIME_SCHEMA_FAMILY
        || meta.version != RUNTIME_SCHEMA_VERSION_V6
        || meta.signature != schema_signature_v6()
        || meta.key_generation != RUNTIME_KEY_GENERATION
        || meta.wrapped_key_bundle.len() != WRAPPED_KEY_BUNDLE_V1_LEN
        || meta.metadata_token.len() != 32
        || table_names(connection)? != EXPECTED_TABLES_V6
        || schema_manifest(connection)? != expected_schema_manifest(RUNTIME_SCHEMA_VERSION_V6)?
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
    admit_safety_write_with_credit(
        connection,
        key_bundle,
        database_id,
        storage_path,
        capacity_probe,
        0,
    )
}

/// 单个 authenticated native metadata mutation 已经消费的 pre-terminal obligation
/// 可作为 safety margin credit。普通写仍按完整 claimed write set 保留；只有该 mutation
/// 的下一笔 safety transition 才能使用精确 credit，避免 fence 已提交后仍要求重复保留
/// 同一 persist 空间而阻断 release/terminal。
pub(crate) fn admit_safety_write_with_credit(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    storage_path: &Path,
    capacity_probe: &dyn RuntimeCapacityProbe,
    consumed_metadata_reserve_bytes: u64,
) -> Result<(), RuntimeStoreError> {
    let safety_reserve_bytes = safety_reserve_bytes(
        connection,
        key_bundle,
        database_id,
        SafetyReserveProjection::Current,
    )?
    .checked_sub(consumed_metadata_reserve_bytes)
    .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
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
    active_metadata_mutations: u64,
    pending_admin_commands: u64,
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
        active_metadata_mutations: ledger.active_metadata_mutation_count,
        pending_admin_commands: ledger.admin_command_pending_count,
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
        SafetyReserveProjection::ClaimMetadataMutation => {
            counts.active_metadata_mutations = counts
                .active_metadata_mutations
                .checked_add(1)
                .ok_or(RuntimeStoreError::CapacityArithmeticOverflow {
                    field: "active_metadata_mutation_safety_count",
                })?;
        }
        SafetyReserveProjection::AcceptAdminUpgrade => {
            counts.pending_admin_commands = counts.pending_admin_commands.checked_add(1).ok_or(
                RuntimeStoreError::CapacityArithmeticOverflow {
                    field: "pending_admin_command_safety_count",
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
    let active_metadata_mutations = counts
        .active_metadata_mutations
        .checked_mul(super::metadata::MAX_NATIVE_METADATA_MUTATION_SAFETY_RESERVE_BYTES)
        .ok_or(RuntimeStoreError::CapacityArithmeticOverflow {
            field: "active_metadata_mutation_safety_reserve",
        })?;
    let pending_admin_commands = counts
        .pending_admin_commands
        .checked_mul(super::admin::MAX_ADMIN_COMMAND_TERMINAL_RESERVE_BYTES)
        .ok_or(RuntimeStoreError::CapacityArithmeticOverflow {
            field: "pending_admin_command_safety_reserve",
        })?;
    [
        accepted,
        without_fence,
        without_release,
        released,
        active_approvals,
        active_metadata_mutations,
        pending_admin_commands,
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

fn read_meta_v6(connection: &Connection) -> Result<Option<MetaRow>, rusqlite::Error> {
    let Some(mut meta) = read_meta_v5(connection)? else {
        return Ok(None);
    };
    let raw: (i64, i64, i64, i64, i64, i64, i64, i64) = connection.query_row(
        "SELECT native_projection_present_count,
                native_projection_tombstone_count,
                native_projection_retired_count,
                native_projection_physical_count,
                native_projection_charged_bytes,
                native_metadata_effect_fence_count,
                native_metadata_effect_unreleased_count,
                native_metadata_effect_released_count
         FROM runtime_meta WHERE singleton = 1",
        [],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
                row.get(7)?,
            ))
        },
    )?;
    let present = sqlite_nonnegative_u64(39, raw.0)?;
    let tombstone = sqlite_nonnegative_u64(40, raw.1)?;
    let retired = sqlite_nonnegative_u64(41, raw.2)?;
    let physical = sqlite_nonnegative_u64(42, raw.3)?;
    let charged_bytes = sqlite_nonnegative_u64(43, raw.4)?;
    let effect_fence = sqlite_nonnegative_u64(44, raw.5)?;
    let effect_unreleased = sqlite_nonnegative_u64(45, raw.6)?;
    let effect_released = sqlite_nonnegative_u64(46, raw.7)?;
    let nonlive = tombstone.checked_add(retired).ok_or_else(|| {
        rusqlite::Error::IntegralValueOutOfRange(41, i64::try_from(retired).unwrap_or(i64::MAX))
    })?;
    let charged_rows = present.checked_add(tombstone).ok_or_else(|| {
        rusqlite::Error::IntegralValueOutOfRange(40, i64::try_from(tombstone).unwrap_or(i64::MAX))
    })?;
    if present
        .checked_add(nonlive)
        .is_none_or(|expected| expected != physical)
        || nonlive > 8_192
        || physical > meta.ledger.conversation_count
        || meta
            .ledger
            .conversation_count
            .checked_sub(nonlive)
            .is_none_or(|live| live > 1_024)
        || ((charged_rows == 0) != (charged_bytes == 0))
        || effect_unreleased
            .checked_add(effect_released)
            .is_none_or(|expected| expected != effect_fence)
        || effect_fence > meta.ledger.metadata_mutation_count
    {
        return Err(rusqlite::Error::IntegralValueOutOfRange(
            42,
            i64::try_from(physical).unwrap_or(i64::MAX),
        ));
    }
    meta.ledger.native_projection_present_count = present;
    meta.ledger.native_projection_tombstone_count = tombstone;
    meta.ledger.native_projection_retired_count = retired;
    meta.ledger.native_projection_physical_count = physical;
    meta.ledger.native_projection_charged_bytes = charged_bytes;
    meta.ledger.native_metadata_effect_fence_count = effect_fence;
    meta.ledger.native_metadata_effect_unreleased_count = effect_unreleased;
    meta.ledger.native_metadata_effect_released_count = effect_released;
    Ok(Some(meta))
}

fn read_meta(connection: &Connection) -> Result<Option<MetaRow>, rusqlite::Error> {
    let Some(mut meta) = read_meta_v6(connection)? else {
        return Ok(None);
    };
    let raw: (i64, i64, i64) = connection.query_row(
        "SELECT admin_command_count, admin_command_pending_count,
                admin_command_charged_bytes
         FROM runtime_meta WHERE singleton = 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    let count = sqlite_nonnegative_u64(47, raw.0)?;
    let pending = sqlite_nonnegative_u64(48, raw.1)?;
    let charged_bytes = sqlite_nonnegative_u64(49, raw.2)?;
    if pending > count || ((count == 0) != (charged_bytes == 0)) {
        return Err(rusqlite::Error::IntegralValueOutOfRange(
            48,
            i64::try_from(pending).unwrap_or(i64::MAX),
        ));
    }
    meta.ledger.admin_command_count = count;
    meta.ledger.admin_command_pending_count = pending;
    meta.ledger.admin_command_charged_bytes = charged_bytes;
    Ok(Some(meta))
}

fn read_meta_v5(connection: &Connection) -> Result<Option<MetaRow>, rusqlite::Error> {
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
                publication_outbox_count, publication_outbox_bytes,
                configuration_count, configuration_sealed_bytes,
                command_configuration_pin_count, metadata_mutation_count,
                active_metadata_mutation_count, metadata_mutation_charged_bytes
         FROM runtime_meta WHERE singleton = 1",
    )
}

fn read_meta_v4(connection: &Connection) -> Result<Option<MetaRow>, rusqlite::Error> {
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
                publication_outbox_count, publication_outbox_bytes,
                0, 0, 0, 0, 0, 0
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
                0, 0, 0, 0, 0, NULL, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0
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
                0, 0, 0, 0, 0, NULL, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0
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
                0, 0, 0, 0, 0, 0, 0, 0, 0, NULL, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0
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
                row.get::<_, i64>(33)?,
                row.get::<_, i64>(34)?,
                row.get::<_, i64>(35)?,
                row.get::<_, i64>(36)?,
                row.get::<_, i64>(37)?,
                row.get::<_, i64>(38)?,
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
                configuration_count,
                configuration_sealed_bytes,
                command_configuration_pin_count,
                metadata_mutation_count,
                active_metadata_mutation_count,
                metadata_mutation_charged_bytes,
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
                let configuration_count = sqlite_nonnegative_u64(33, configuration_count)?;
                let configuration_sealed_bytes =
                    sqlite_nonnegative_u64(34, configuration_sealed_bytes)?;
                let command_configuration_pin_count =
                    sqlite_nonnegative_u64(35, command_configuration_pin_count)?;
                let metadata_mutation_count = sqlite_nonnegative_u64(36, metadata_mutation_count)?;
                let active_metadata_mutation_count =
                    sqlite_nonnegative_u64(37, active_metadata_mutation_count)?;
                let metadata_mutation_charged_bytes =
                    sqlite_nonnegative_u64(38, metadata_mutation_charged_bytes)?;
                if active_approval_count > approval_count {
                    return Err(rusqlite::Error::IntegralValueOutOfRange(
                        21,
                        i64::try_from(active_approval_count).unwrap_or(i64::MAX),
                    ));
                }
                if active_metadata_mutation_count > metadata_mutation_count
                    || command_configuration_pin_count > command_count
                    || (configuration_count == 0) != (configuration_sealed_bytes == 0)
                    || (metadata_mutation_count == 0) != (metadata_mutation_charged_bytes == 0)
                {
                    return Err(rusqlite::Error::IntegralValueOutOfRange(
                        37,
                        i64::try_from(active_metadata_mutation_count).unwrap_or(i64::MAX),
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
                        configuration_count,
                        configuration_sealed_bytes,
                        command_configuration_pin_count,
                        metadata_mutation_count,
                        active_metadata_mutation_count,
                        metadata_mutation_charged_bytes,
                        native_projection_present_count: 0,
                        native_projection_tombstone_count: 0,
                        native_projection_retired_count: 0,
                        native_projection_physical_count: 0,
                        native_projection_charged_bytes: 0,
                        native_metadata_effect_fence_count: 0,
                        native_metadata_effect_unreleased_count: 0,
                        native_metadata_effect_released_count: 0,
                        admin_command_count: 0,
                        admin_command_pending_count: 0,
                        admin_command_charged_bytes: 0,
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
        4 => {
            connection.execute_batch(RUNTIME_MIGRATION_V2)?;
            connection.execute_batch(RUNTIME_MIGRATION_V3)?;
            connection.execute_batch(RUNTIME_MIGRATION_V4)?;
        }
        RUNTIME_SCHEMA_VERSION_V5 => {
            connection.execute_batch(RUNTIME_MIGRATION_V2)?;
            connection.execute_batch(RUNTIME_MIGRATION_V3)?;
            connection.execute_batch(RUNTIME_MIGRATION_V4)?;
            connection.execute_batch(RUNTIME_MIGRATION_V5)?;
        }
        RUNTIME_SCHEMA_VERSION_V6 => {
            connection.execute_batch(RUNTIME_MIGRATION_V2)?;
            connection.execute_batch(RUNTIME_MIGRATION_V3)?;
            connection.execute_batch(RUNTIME_MIGRATION_V4)?;
            connection.execute_batch(RUNTIME_MIGRATION_V5)?;
            connection.execute_batch(RUNTIME_MIGRATION_V6)?;
        }
        RUNTIME_SCHEMA_VERSION => {
            connection.execute_batch(RUNTIME_MIGRATION_V2)?;
            connection.execute_batch(RUNTIME_MIGRATION_V3)?;
            connection.execute_batch(RUNTIME_MIGRATION_V4)?;
            connection.execute_batch(RUNTIME_MIGRATION_V5)?;
            connection.execute_batch(RUNTIME_MIGRATION_V6)?;
            connection.execute_batch(RUNTIME_MIGRATION_V7)?;
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

fn runtime_ledger_message_v4(database_id: [u8; 16], ledger: &RuntimeLedger) -> Vec<u8> {
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
    message
}

fn runtime_ledger_token_v4(
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    ledger: &RuntimeLedger,
) -> Result<[u8; 32], RuntimeStoreError> {
    let message = runtime_ledger_message_v4(database_id, ledger);
    let token = key_bundle.blind_index(super::schema::RUNTIME_LEDGER_DOMAIN_V4, &message)?;
    Ok(*token.as_bytes())
}

fn runtime_ledger_message_v5(database_id: [u8; 16], ledger: &RuntimeLedger) -> Vec<u8> {
    let mut message = runtime_ledger_message_v4(database_id, ledger);
    message.reserve(6 * std::mem::size_of::<u64>());
    message.extend_from_slice(&ledger.configuration_count.to_be_bytes());
    message.extend_from_slice(&ledger.configuration_sealed_bytes.to_be_bytes());
    message.extend_from_slice(&ledger.command_configuration_pin_count.to_be_bytes());
    message.extend_from_slice(&ledger.metadata_mutation_count.to_be_bytes());
    message.extend_from_slice(&ledger.active_metadata_mutation_count.to_be_bytes());
    message.extend_from_slice(&ledger.metadata_mutation_charged_bytes.to_be_bytes());
    message
}

fn runtime_ledger_token_v5(
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    ledger: &RuntimeLedger,
) -> Result<[u8; 32], RuntimeStoreError> {
    let message = runtime_ledger_message_v5(database_id, ledger);
    let token = key_bundle.blind_index(super::schema::RUNTIME_LEDGER_DOMAIN_V5, &message)?;
    Ok(*token.as_bytes())
}

fn runtime_ledger_message_v6(database_id: [u8; 16], ledger: &RuntimeLedger) -> Vec<u8> {
    let mut message = runtime_ledger_message_v5(database_id, ledger);
    message.reserve(8 * std::mem::size_of::<u64>());
    message.extend_from_slice(&ledger.native_projection_present_count.to_be_bytes());
    message.extend_from_slice(&ledger.native_projection_tombstone_count.to_be_bytes());
    message.extend_from_slice(&ledger.native_projection_retired_count.to_be_bytes());
    message.extend_from_slice(&ledger.native_projection_physical_count.to_be_bytes());
    message.extend_from_slice(&ledger.native_projection_charged_bytes.to_be_bytes());
    message.extend_from_slice(&ledger.native_metadata_effect_fence_count.to_be_bytes());
    message.extend_from_slice(&ledger.native_metadata_effect_unreleased_count.to_be_bytes());
    message.extend_from_slice(&ledger.native_metadata_effect_released_count.to_be_bytes());
    message
}

fn runtime_ledger_token_v6(
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    ledger: &RuntimeLedger,
) -> Result<[u8; 32], RuntimeStoreError> {
    let message = runtime_ledger_message_v6(database_id, ledger);
    let token = key_bundle.blind_index(super::schema::RUNTIME_LEDGER_DOMAIN_V6, &message)?;
    Ok(*token.as_bytes())
}

fn runtime_ledger_token(
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    ledger: &RuntimeLedger,
) -> Result<[u8; 32], RuntimeStoreError> {
    let mut message = runtime_ledger_message_v6(database_id, ledger);
    message.reserve(3 * std::mem::size_of::<u64>());
    message.extend_from_slice(&ledger.admin_command_count.to_be_bytes());
    message.extend_from_slice(&ledger.admin_command_pending_count.to_be_bytes());
    message.extend_from_slice(&ledger.admin_command_charged_bytes.to_be_bytes());
    let token = key_bundle.blind_index(super::schema::RUNTIME_LEDGER_DOMAIN_V7, &message)?;
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

fn verify_runtime_ledger_token_v4(
    key_bundle: &RuntimeKeyBundle,
    meta: &MetaRow,
) -> Result<(), RuntimeStoreError> {
    let expected = runtime_ledger_token_v4(key_bundle, meta.database_id, &meta.ledger)?;
    if meta.metadata_token.as_slice() != expected {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(())
}

fn verify_runtime_ledger_token_v5(
    key_bundle: &RuntimeKeyBundle,
    meta: &MetaRow,
) -> Result<(), RuntimeStoreError> {
    let expected = runtime_ledger_token_v5(key_bundle, meta.database_id, &meta.ledger)?;
    if meta.metadata_token.as_slice() != expected {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(())
}

fn verify_runtime_ledger_token_v6(
    key_bundle: &RuntimeKeyBundle,
    meta: &MetaRow,
) -> Result<(), RuntimeStoreError> {
    let expected = runtime_ledger_token_v6(key_bundle, meta.database_id, &meta.ledger)?;
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
        4 => read_meta_v4(connection)?,
        RUNTIME_SCHEMA_VERSION_V5 => read_meta_v5(connection)?,
        RUNTIME_SCHEMA_VERSION_V6 => read_meta_v6(connection)?,
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
        4 => verify_runtime_ledger_token_v4(key_bundle, &meta)?,
        RUNTIME_SCHEMA_VERSION_V5 => verify_runtime_ledger_token_v5(key_bundle, &meta)?,
        RUNTIME_SCHEMA_VERSION_V6 => verify_runtime_ledger_token_v6(key_bundle, &meta)?,
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
) -> Result<crate::runtime::events::PendingStreamTargets, RuntimeStoreError> {
    update_runtime_ledger_inner(transaction, key_bundle, database_id, previous, next, None)
}

pub(crate) fn update_runtime_ledger_with_trim_clock(
    transaction: &Transaction<'_>,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    previous: &RuntimeLedger,
    next: &RuntimeLedger,
    trim_now_ms: u64,
) -> Result<crate::runtime::events::PendingStreamTargets, RuntimeStoreError> {
    update_runtime_ledger_inner(
        transaction,
        key_bundle,
        database_id,
        previous,
        next,
        Some(trim_now_ms),
    )
}

fn update_runtime_ledger_inner(
    transaction: &Transaction<'_>,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    previous: &RuntimeLedger,
    next: &RuntimeLedger,
    trim_now_ms: Option<u64>,
) -> Result<crate::runtime::events::PendingStreamTargets, RuntimeStoreError> {
    let (reconciled_next, mut pending_targets) =
        super::stream::reconcile_event_stream_with_trim_clock(
            transaction,
            key_bundle,
            database_id,
            previous,
            next,
            trim_now_ms,
        )?;
    let reconciled_next = super::catalog::reconcile_catalog_journal(
        transaction,
        key_bundle,
        database_id,
        previous,
        &reconciled_next,
        trim_now_ms,
    )?;
    let next = &reconciled_next;
    if previous.catalog_high_water != next.catalog_high_water {
        pending_targets.insert(crate::runtime::events::RuntimeStreamTarget::Catalog);
    }
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
             configuration_count = ?22, configuration_sealed_bytes = ?23,
             command_configuration_pin_count = ?24,
             metadata_mutation_count = ?25, active_metadata_mutation_count = ?26,
             metadata_mutation_charged_bytes = ?27,
             native_projection_present_count = ?28,
             native_projection_tombstone_count = ?29,
             native_projection_retired_count = ?30,
             native_projection_physical_count = ?31,
             native_projection_charged_bytes = ?32,
             native_metadata_effect_fence_count = ?33,
             native_metadata_effect_unreleased_count = ?34,
             native_metadata_effect_released_count = ?35,
             admin_command_count = ?36, admin_command_pending_count = ?37,
             admin_command_charged_bytes = ?38,
             accepted_count = ?39, accepted_payload_bytes = ?40,
             started_without_fence_count = ?41, started_without_release_count = ?42,
             started_released_count = ?43, metadata_token = ?44
         WHERE singleton = 1 AND metadata_token = ?45",
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
            i64::try_from(next.configuration_count)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            i64::try_from(next.configuration_sealed_bytes)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            i64::try_from(next.command_configuration_pin_count)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            i64::try_from(next.metadata_mutation_count)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            i64::try_from(next.active_metadata_mutation_count)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            i64::try_from(next.metadata_mutation_charged_bytes)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            i64::try_from(next.native_projection_present_count)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            i64::try_from(next.native_projection_tombstone_count)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            i64::try_from(next.native_projection_retired_count)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            i64::try_from(next.native_projection_physical_count)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            i64::try_from(next.native_projection_charged_bytes)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            i64::try_from(next.native_metadata_effect_fence_count)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            i64::try_from(next.native_metadata_effect_unreleased_count)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            i64::try_from(next.native_metadata_effect_released_count)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            i64::try_from(next.admin_command_count)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            i64::try_from(next.admin_command_pending_count)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            i64::try_from(next.admin_command_charged_bytes)
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
    Ok(pending_targets)
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
        (RUNTIME_SCHEMA_FAMILY, 4) => {
            read_and_validate_legacy_v4_schema(connection)?;
        }
        (RUNTIME_SCHEMA_FAMILY, RUNTIME_SCHEMA_VERSION_V5) => {
            read_and_validate_legacy_v5_schema(connection)?;
        }
        (RUNTIME_SCHEMA_FAMILY, RUNTIME_SCHEMA_VERSION_V6) => {
            read_and_validate_legacy_v6_schema(connection)?;
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
    fn terminal_reserve_remains_conservative_until_full_real_sqlite_calibration() {
        assert_eq!(TERMINAL_RESERVE_BYTES, 132 * 1024 * 1024);
    }

    #[test]
    fn command_lifecycle_reserves_are_exact_and_non_overlapping() {
        let mut ledger = ledger_with_active_approvals(0);
        ledger.accepted_count = 1;
        assert_eq!(
            safety_reserve_bytes_for_ledger(&ledger).expect("accepted reserve"),
            FIXED_SAFETY_RESERVE_BYTES + ACCEPTED_EXPIRY_RESERVE_BYTES
        );

        ledger.accepted_count = 0;
        ledger.started_without_fence_count = 1;
        assert_eq!(
            safety_reserve_bytes_for_ledger(&ledger).expect("without-fence reserve"),
            FIXED_SAFETY_RESERVE_BYTES
                + FENCE_RESERVE_BYTES
                + RELEASE_RESERVE_BYTES
                + TERMINAL_RESERVE_BYTES
        );

        ledger.started_without_fence_count = 0;
        ledger.started_without_release_count = 1;
        assert_eq!(
            safety_reserve_bytes_for_ledger(&ledger).expect("without-release reserve"),
            FIXED_SAFETY_RESERVE_BYTES + RELEASE_RESERVE_BYTES + TERMINAL_RESERVE_BYTES
        );

        ledger.started_without_release_count = 0;
        ledger.started_released_count = 1;
        assert_eq!(
            safety_reserve_bytes_for_ledger(&ledger).expect("released reserve"),
            FIXED_SAFETY_RESERVE_BYTES + TERMINAL_RESERVE_BYTES
        );
    }

    #[test]
    fn released_terminal_reserve_overflow_fails_closed() {
        let mut ledger = ledger_with_active_approvals(0);
        ledger.started_released_count = u64::MAX;
        assert!(matches!(
            safety_reserve_bytes_for_ledger(&ledger),
            Err(RuntimeStoreError::CapacityArithmeticOverflow {
                field: "started_released_reserve"
            })
        ));
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
    fn pending_admin_commands_reserve_terminal_closure_and_accept_projects_one_more() {
        let mut ledger = RuntimeLedger {
            admin_command_count: 2,
            admin_command_pending_count: 2,
            ..RuntimeLedger::default()
        };
        let current =
            safety_reserve_bytes_for_ledger_projection(&ledger, SafetyReserveProjection::Current)
                .expect("current pending admin reserve");
        assert_eq!(
            current,
            FIXED_SAFETY_RESERVE_BYTES
                + 2 * super::super::admin::MAX_ADMIN_COMMAND_TERMINAL_RESERVE_BYTES
        );
        let accepting = safety_reserve_bytes_for_ledger_projection(
            &ledger,
            SafetyReserveProjection::AcceptAdminUpgrade,
        )
        .expect("accept pending admin projection");
        assert_eq!(
            accepting,
            current + super::super::admin::MAX_ADMIN_COMMAND_TERMINAL_RESERVE_BYTES
        );

        ledger.admin_command_pending_count = super::super::schema::MAX_PENDING_ADMIN_COMMANDS;
        assert_eq!(
            safety_reserve_bytes_for_ledger(&ledger).expect("1,024 pending admin reserve"),
            FIXED_SAFETY_RESERVE_BYTES
                + super::super::schema::MAX_PENDING_ADMIN_COMMANDS
                    * super::super::admin::MAX_ADMIN_COMMAND_TERMINAL_RESERVE_BYTES
        );
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

    #[test]
    fn active_metadata_projection_reserves_the_complete_terminal_write_set() {
        let ledger = RuntimeLedger::default();
        let current =
            safety_reserve_bytes_for_ledger_projection(&ledger, SafetyReserveProjection::Current)
                .expect("calculate current safety reserve");
        let claimed = safety_reserve_bytes_for_ledger_projection(
            &ledger,
            SafetyReserveProjection::ClaimMetadataMutation,
        )
        .expect("calculate claimed metadata safety reserve");
        assert_eq!(
            claimed - current,
            crate::runtime::store::metadata::MAX_NATIVE_METADATA_MUTATION_SAFETY_RESERVE_BYTES
        );
        assert_eq!(
            crate::runtime::store::metadata::MAX_NATIVE_METADATA_MUTATION_SAFETY_RESERVE_BYTES
                - crate::runtime::store::metadata::MAX_METADATA_MUTATION_TERMINAL_RESERVE_BYTES,
            crate::runtime::store::metadata::MAX_NATIVE_METADATA_PRE_TERMINAL_RESERVE_BYTES,
            "native effect/release/outcomeUnknown reserve must stay independent from terminal"
        );
        assert!(
            claimed - current
                > u64::try_from(crate::runtime::model::MAX_CONVERSATION_DESCRIPTOR_BYTES)
                    .expect("descriptor bound fits u64")
                    * 2,
            "terminal reserve must cover descriptor and CatalogDelta, not only sealed outcome"
        );
    }

    #[test]
    fn native_metadata_transition_credits_preserve_each_remaining_safety_obligation() {
        let ledger = RuntimeLedger {
            active_metadata_mutation_count: 1,
            ..RuntimeLedger::default()
        };
        let claimed =
            safety_reserve_bytes_for_ledger_projection(&ledger, SafetyReserveProjection::Current)
                .expect("calculate claimed native metadata reserve");
        let persist =
            crate::runtime::store::metadata::MAX_NATIVE_METADATA_EFFECT_PERSIST_RESERVE_BYTES;
        let release =
            crate::runtime::store::metadata::MAX_NATIVE_METADATA_EFFECT_RELEASE_RESERVE_BYTES;
        let unknown =
            crate::runtime::store::metadata::MAX_NATIVE_METADATA_OUTCOME_UNKNOWN_RESERVE_BYTES;
        let terminal =
            crate::runtime::store::metadata::MAX_METADATA_MUTATION_TERMINAL_RESERVE_BYTES;
        let fixed = claimed
            .checked_sub(
                crate::runtime::store::metadata::MAX_NATIVE_METADATA_MUTATION_SAFETY_RESERVE_BYTES,
            )
            .expect("claimed reserve contains one native obligation");
        let common = RuntimeAdmissionInput {
            main_bytes: 0,
            wal_bytes: 0,
            shm_bytes: 0,
            projected_write_bytes: 0,
            safety_margin_bytes: claimed,
            filesystem_total_bytes: 4 * 1024 * 1024 * 1024,
            filesystem_available_bytes: claimed,
            page_size_bytes: 4096,
            page_count: 0,
            max_page_count: RUNTIME_DB_HARD_LIMIT_BYTES / 4096,
        };
        evaluate_runtime_safety_admission(common)
            .expect("claimed reserve admits the maximum persist write");
        evaluate_runtime_safety_admission(RuntimeAdmissionInput {
            safety_margin_bytes: fixed + release + unknown + terminal,
            filesystem_available_bytes: claimed - persist,
            ..common
        })
        .expect("persist credit leaves release, unknown, and terminal admissible");
        evaluate_runtime_safety_admission(RuntimeAdmissionInput {
            safety_margin_bytes: fixed + unknown + terminal,
            filesystem_available_bytes: claimed - persist - release,
            ..common
        })
        .expect("persist+release credit leaves unknown and terminal admissible");
        evaluate_runtime_safety_admission(RuntimeAdmissionInput {
            safety_margin_bytes: fixed + terminal,
            filesystem_available_bytes: claimed - persist - release - unknown,
            ..common
        })
        .expect("full pre-terminal credit leaves the terminal write admissible");
    }
}
