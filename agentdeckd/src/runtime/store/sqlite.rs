//! Runtime SQLite 的安全打开、schema inspection、migration 与 PRAGMA 读回。

use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};
use std::time::Duration;

use rusqlite::limits::Limit;
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};

use crate::runtime::model::{
    MAX_RUNTIME_BUSY_TIMEOUT_MS, MAX_RUNTIME_STORE_COMMAND_CAPACITY,
    MachineEnrollmentReceiptRecord, RuntimeStoreConfig, RuntimeStoreError, RuntimeStoreOperation,
    RuntimeStoreSnapshot,
};
use crate::security::StorageKek;

use super::cipher::{KeyWrapAad, RuntimeKeyBundle, WRAPPED_KEY_BUNDLE_V1_LEN};
use super::schema::{
    EXPECTED_TABLES, RUNTIME_DDL, RUNTIME_KEY_GENERATION, RUNTIME_SCHEMA_FAMILY,
    RUNTIME_SCHEMA_VERSION, schema_signature,
};

const DATABASE_MODE: u32 = 0o600;
const DIRECTORY_MODE: u32 = 0o700;
const SQLITE_LENGTH_LIMIT_BYTES: i32 = 72 * 1024 * 1024;

pub(crate) struct RuntimeSqlite {
    pub connection: Connection,
    pub _key_bundle: RuntimeKeyBundle,
    pub _storage_path: PathBuf,
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

        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute_batch(RUNTIME_DDL)?;
        transaction.execute(
            "INSERT INTO runtime_meta (
                 singleton, schema_family, schema_version, schema_signature,
                 database_id, key_generation, wrapped_key_bundle, catalog_high_water
             ) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, NULL)",
            params![
                RUNTIME_SCHEMA_FAMILY,
                i64::from(RUNTIME_SCHEMA_VERSION),
                &signature[..],
                &database_id[..],
                i64::from(RUNTIME_KEY_GENERATION),
                wrapped,
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
        snapshot(&connection, config.busy_timeout_ms)?;
        sync_parent_directory(&storage_path)?;
        Ok(RuntimeSqlite {
            connection,
            _key_bundle: key_bundle,
            _storage_path: storage_path.clone(),
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
    snapshot(&connection, config.busy_timeout_ms)?;
    Ok(RuntimeSqlite {
        connection,
        _key_bundle: key_bundle,
        _storage_path: storage_path,
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
            let connection = open_immutable_read_only(path)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
            configure_defensive_limits(&connection)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
            connection
                .pragma_update(None, "query_only", true)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
            connection
                .pragma_update(None, "trusted_schema", false)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
            let meta = read_and_validate_current_schema(&connection)?;
            validate_store_files(path)?;
            let identity = capture_store_identity(path)?;
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
    connection.pragma_update(None, "wal_autocheckpoint", 1_000_i64)?;
    if enable_wal {
        let mode: String = connection.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))?;
        if !mode.eq_ignore_ascii_case("wal") {
            return Err(RuntimeStoreError::PragmaMismatch {
                name: "journal_mode",
                expected: "wal".to_owned(),
                actual: mode,
            });
        }
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
    let synchronous: i64 = connection.query_row("PRAGMA synchronous", [], |row| row.get(0))?;
    let foreign_keys: i64 = connection.query_row("PRAGMA foreign_keys", [], |row| row.get(0))?;
    let busy_timeout: i64 = connection.query_row("PRAGMA busy_timeout", [], |row| row.get(0))?;
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
    Ok(RuntimeStoreSnapshot {
        schema_family: meta.family,
        schema_version: meta.version,
        schema_signature: meta.signature,
        database_id: meta.database_id,
        key_generation: meta.key_generation,
        table_names: table_names(connection)?,
        journal_mode,
        synchronous,
        foreign_keys: true,
        busy_timeout_ms,
    })
}

fn read_meta(connection: &Connection) -> Result<Option<MetaRow>, rusqlite::Error> {
    connection
        .query_row(
            "SELECT schema_family, schema_version, schema_signature, database_id,
                    key_generation, wrapped_key_bundle
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
                ))
            },
        )
        .optional()?
        .map(
            |(family, version, signature, database_id, generation, wrapped)| {
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
                Ok(MetaRow {
                    family,
                    version,
                    signature,
                    database_id,
                    key_generation,
                    wrapped_key_bundle: wrapped,
                })
            },
        )
        .transpose()
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
}

pub(crate) fn record_machine_enrollment_receipt(
    connection: &mut Connection,
    receipt: MachineEnrollmentReceiptRecord,
) -> Result<MachineEnrollmentReceiptRecord, RuntimeStoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
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
    transaction.commit()?;
    let (busy, _, _): (i64, i64, i64) =
        connection.query_row("PRAGMA wal_checkpoint(FULL)", [], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })?;
    if busy != 0 {
        return Err(RuntimeStoreError::PragmaMismatch {
            name: "wal_checkpoint",
            expected: "busy=0".to_owned(),
            actual: format!("busy={busy}"),
        });
    }
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
