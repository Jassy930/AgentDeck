//! Runtime SQLite 的安全打开、schema inspection、migration 与 PRAGMA 读回。

use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};
use std::time::Duration;

use rusqlite::limits::Limit;
use rusqlite::{
    Connection, DropBehavior, OpenFlags, OptionalExtension, Transaction, TransactionBehavior,
    params,
};

use crate::runtime::model::{
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
    EXPECTED_TABLES, RUNTIME_DDL, RUNTIME_KEY_GENERATION, RUNTIME_SCHEMA_FAMILY,
    RUNTIME_SCHEMA_VERSION, schema_signature,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SafetyReserveProjection {
    Current,
    AcceptCommand,
    StartCommand,
}

pub(crate) struct RuntimeSqlite {
    pub connection: Connection,
    pub key_bundle: RuntimeKeyBundle,
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RuntimeLedger {
    pub catalog_high_water: Option<String>,
    pub conversation_count: u64,
    pub command_count: u64,
    pub event_count: u64,
    pub intent_count: u64,
    pub fence_count: u64,
    pub accepted_count: u64,
    pub accepted_payload_bytes: u64,
    pub started_without_fence_count: u64,
    pub started_without_release_count: u64,
    pub started_released_count: u64,
}

enum SchemaState {
    Fresh,
    Current(MetaRow, StoreFileIdentity),
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
            schema_version: RUNTIME_SCHEMA_VERSION,
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
            accepted_count: 0,
            accepted_payload_bytes: 0,
            started_without_fence_count: 0,
            started_without_release_count: 0,
            started_released_count: 0,
        };
        let metadata_token = runtime_ledger_token(&key_bundle, database_id, &ledger)?;

        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute_batch(RUNTIME_DDL)?;
        transaction.execute(
            "INSERT INTO runtime_meta (
                 singleton, schema_family, schema_version, schema_signature,
                 database_id, key_generation, wrapped_key_bundle, catalog_high_water,
                 conversation_count, command_count, event_count, intent_count, fence_count,
                 accepted_count, accepted_payload_bytes, started_without_fence_count,
                 started_without_release_count, started_released_count, metadata_token
             ) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, NULL, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, ?7)",
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
        if schema_manifest(&connection)? != expected_schema_manifest()? {
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
        Ok(RuntimeSqlite {
            connection,
            key_bundle,
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
        schema_version: RUNTIME_SCHEMA_VERSION,
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
    Ok(RuntimeSqlite {
        connection,
        key_bundle,
        storage_path,
        database_id: current.database_id,
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
            let meta = read_and_validate_current_schema(connection)?;
            validate_store_files(path)?;
            ensure_store_identity(path, &identity)?;
            Ok(SchemaState::Current(meta, identity))
        }
    }
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
        || schema_manifest(connection)? != expected_schema_manifest()?
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
}

fn safety_reserve_bytes(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    projection: SafetyReserveProjection,
) -> Result<u64, RuntimeStoreError> {
    let ledger = load_runtime_ledger(connection, key_bundle, database_id)?;
    let mut counts = SafetyCounts {
        accepted: ledger.accepted_count,
        started_without_fence: ledger.started_without_fence_count,
        started_without_release: ledger.started_without_release_count,
        started_released: ledger.started_released_count,
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
    }
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
    [accepted, without_fence, without_release, released]
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
    connection
        .query_row(
            "SELECT schema_family, schema_version, schema_signature, database_id,
                    key_generation, wrapped_key_bundle, catalog_high_water,
                    conversation_count, command_count, event_count, intent_count, fence_count,
                    accepted_count, accepted_payload_bytes, started_without_fence_count,
                    started_without_release_count, started_released_count, metadata_token
             FROM runtime_meta WHERE singleton = 1",
            [],
            |row| {
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
                ))
            },
        )
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

fn expected_schema_manifest() -> Result<Vec<SchemaObject>, RuntimeStoreError> {
    let connection = Connection::open_in_memory()?;
    connection.execute_batch(RUNTIME_DDL)?;
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

fn runtime_ledger_token(
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

pub(crate) fn load_runtime_ledger(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
) -> Result<RuntimeLedger, RuntimeStoreError> {
    let meta = read_meta(connection)?.ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    if meta.database_id != database_id {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    verify_runtime_ledger_token(key_bundle, &meta)?;
    Ok(meta.ledger)
}

pub(crate) fn update_runtime_ledger(
    transaction: &Transaction<'_>,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    previous: &RuntimeLedger,
    next: &RuntimeLedger,
) -> Result<(), RuntimeStoreError> {
    let previous_token = runtime_ledger_token(key_bundle, database_id, previous)?;
    let next_token = runtime_ledger_token(key_bundle, database_id, next)?;
    if transaction.execute(
        "UPDATE runtime_meta
         SET catalog_high_water = ?1, conversation_count = ?2, command_count = ?3,
             event_count = ?4, intent_count = ?5, fence_count = ?6,
             accepted_count = ?7, accepted_payload_bytes = ?8,
             started_without_fence_count = ?9, started_without_release_count = ?10,
             started_released_count = ?11, metadata_token = ?12
         WHERE singleton = 1 AND metadata_token = ?13",
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
    read_and_validate_current_schema(connection)?;
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
