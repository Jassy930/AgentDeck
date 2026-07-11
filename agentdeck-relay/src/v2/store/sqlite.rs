//! Relay v2 SQLite 的生产路径检查、启动与只读快照。

use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};

use agentdeck_protocol::relay_v2::{
    CertRole, DeviceRouteId, GrantSerial, LinkGeneration, MachineRouteId, PublicKeyBytes,
    RelayFrameBody, RelayServerId, RootKeyId, StreamCursor, StreamGenerationId, StreamRouteId,
    TrustEpoch,
};
use fs2::FileExt;
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use sha2::{Digest, Sha256};

use super::migrations::{self, SCHEMA_VERSION, SchemaError, SchemaState};
use super::model::{
    CommitMachineLinkAuth, ConfirmDeviceAuth, DeviceTrustView, EMPTY_HIGH_WATER_TEXT,
    EnrollmentCodeSeed, FaultPoint, GrantCommit, InstallGrantRecord, MAX_CONTROL_BLOB_BYTES,
    MAX_ENROLLMENT_CODES, MachineLinkAuthCommit, MachineRecord, MachineTrustView,
    MaintenanceReport, PersistAck, PersistPublish, PersistRevocation, PersistSubscription,
    PersistUnsubscribe, PublishCommit, PublishDisposition, PurgeMachine, PurgeReadback,
    RegisterMachine, RelayV2StoreConfig, ReplayCursor, ReplayFrame, ReplayPage, ReplayPageRequest,
    ReplayPosition, RevocationCommit, StoreError, StoreSnapshot, StreamRecord, StreamRegistration,
    SubscriptionLease, UnsubscribeCommit, high_water_from_text, high_water_text, monotonic_blob,
    monotonic_from_blob, normalize_platform_root_alias, sql_i64, stream_seq_from_text,
    stream_seq_text, validate_store_path,
};

const DIRECTORY_MODE: u32 = 0o700;
const DATABASE_MODE: u32 = 0o600;
const INSPECTION_DIRECTORY_PREFIX: &str = ".agentdeck-relay-schema-inspect-";
const INSPECTION_MARKER_NAME: &str = ".agentdeck-schema-snapshot-v1";
const INSPECTION_MARKER_MAGIC: &[u8] = b"agentdeck-relay-schema-snapshot-v1\0";

/// 打开并完整准备生产 store。
///
/// 目标 DB 的第一次打开始终是只读 schema inspection。只有 fresh/current
/// 才会继续检查权限、创建文件和打开读写连接；fresh schema 先在 rollback
/// journal 下原子迁移，再切到 WAL，避免把初始 schema 只留在 WAL sidecar。
pub(crate) fn open(config: &RelayV2StoreConfig) -> Result<Connection, StoreError> {
    config.retention.validate()?;
    if config.max_enrollment_codes == 0 || config.max_enrollment_codes > MAX_ENROLLMENT_CODES {
        return Err(StoreError::InvalidValue {
            field: "max_enrollment_codes",
            reason: "enrollment code bound must be in 1...4096",
        });
    }
    validate_store_path(&config.storage_path)?;
    let normalized_path = normalize_platform_root_alias(&config.storage_path);
    let path = normalized_path.as_path();

    reject_symlink_components(path)?;
    let parent = path.parent().ok_or(StoreError::InvalidValue {
        field: "storage_path",
        reason: "absolute database path must have a parent directory",
    })?;
    let existing_metadata = metadata_if_exists(path)?;
    if let Some(metadata) = &existing_metadata
        && !metadata.file_type().is_file()
    {
        return Err(StoreError::NotRegularFile {
            path: path.to_path_buf(),
        });
    }
    let parent_metadata = metadata_if_exists(parent)?;
    if let Some(parent_metadata) = &parent_metadata {
        validate_parent(parent, parent_metadata)?;
    }
    if let Some(metadata) = &existing_metadata {
        validate_database(path, metadata)?;
    }
    if parent_metadata.is_some() {
        cleanup_stale_schema_snapshots(parent, path)?;
    }
    let schema_state = match existing_metadata {
        Some(_) => inspect_read_only(path, config)?,
        None => SchemaState::Fresh,
    };
    require_supported_schema(schema_state)?;

    prepare_secure_path(path)?;
    reject_symlink_components(path)?;

    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_NO_MUTEX
        | OpenFlags::SQLITE_OPEN_NOFOLLOW;
    let mut conn = Connection::open_with_flags(path, flags)?;

    let generated_server_id = nonzero_relay_server_id();
    migrations::migrate_or_validate(&mut conn, generated_server_id)?;
    migrations::configure_connection(&conn)?;

    // `open` 只在 marker、精确 schema 和全部 PRAGMA 都能从 worker 所持连接
    // 读回后返回；ready oneshot 因而不会早于完整 startup gate。
    snapshot(&conn)?;
    run_maintenance(&mut conn, config)?;
    Ok(conn)
}

pub(crate) fn snapshot(conn: &Connection) -> Result<StoreSnapshot, StoreError> {
    let expected_server_id = match migrations::inspect(conn)? {
        SchemaState::Current { relay_server_id } => relay_server_id,
        state => return Err(schema_state_error(state)),
    };

    let (schema_family, schema_version_raw, schema_signature_raw, relay_server_id_raw) = conn
        .query_row(
            "SELECT schema_family, schema_version, schema_signature, relay_server_id
             FROM relay_meta WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                ))
            },
        )?;

    let schema_version =
        u32::try_from(schema_version_raw).map_err(|_| StoreError::InvalidValue {
            field: "relay_meta.schema_version",
            reason: "value does not fit u32",
        })?;
    let schema_signature =
        <[u8; 32]>::try_from(schema_signature_raw).map_err(|_| StoreError::InvalidValue {
            field: "relay_meta.schema_signature",
            reason: "value must contain exactly 32 bytes",
        })?;
    let relay_server_id_bytes =
        <[u8; 16]>::try_from(relay_server_id_raw).map_err(|_| StoreError::InvalidValue {
            field: "relay_meta.relay_server_id",
            reason: "value must contain exactly 16 bytes",
        })?;
    let relay_server_id = RelayServerId::from_bytes(relay_server_id_bytes);
    if relay_server_id != expected_server_id {
        return Err(StoreError::UnknownOrCorruptSchema);
    }

    let mut statement = conn.prepare(
        "SELECT name FROM sqlite_schema
         WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
         ORDER BY name",
    )?;
    let names = statement.query_map([], |row| row.get::<_, String>(0))?;
    let mut table_names = Vec::new();
    for name in names {
        table_names.push(name?);
    }

    let journal_mode =
        conn.pragma_query_value(None, "journal_mode", |row| row.get::<_, String>(0))?;
    let synchronous = conn.pragma_query_value(None, "synchronous", |row| row.get::<_, i64>(0))?;
    let foreign_keys =
        conn.pragma_query_value(None, "foreign_keys", |row| row.get::<_, i64>(0))? != 0;
    let busy_timeout_raw =
        conn.pragma_query_value(None, "busy_timeout", |row| row.get::<_, i64>(0))?;
    let busy_timeout_ms =
        u64::try_from(busy_timeout_raw).map_err(|_| StoreError::InvalidValue {
            field: "PRAGMA busy_timeout",
            reason: "value must be a non-negative integer",
        })?;

    Ok(StoreSnapshot {
        schema_family,
        schema_version,
        schema_signature,
        relay_server_id,
        table_names,
        journal_mode,
        synchronous,
        foreign_keys,
        busy_timeout_ms,
    })
}

pub(crate) fn seed_enrollment_code(
    conn: &mut Connection,
    config: &RelayV2StoreConfig,
    request: EnrollmentCodeSeed,
) -> Result<(), StoreError> {
    let expires_at = sql_i64(request.expires_at_ms, "enrollment_codes.expires_at")?;
    let now = sql_i64(config.clock.now_ms()?, "enrollment_codes.expires_at")?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    tx.execute(
        "DELETE FROM enrollment_codes WHERE expires_at < ?1",
        params![now],
    )?;
    let existing = tx
        .query_row(
            "SELECT expires_at FROM enrollment_codes WHERE code_hash = ?1",
            params![request.code_hash.as_slice()],
            |row| row.get::<_, i64>(0),
        )
        .optional()?;
    match existing {
        Some(value) if value == expires_at => {}
        Some(_) => {
            return Err(StoreError::IdempotencyConflict {
                field: "enrollment_code",
            });
        }
        None => {
            if query_u64(
                &tx,
                "SELECT COUNT(*) FROM enrollment_codes",
                [],
                "enrollment_codes.count",
            )? >= config.max_enrollment_codes
            {
                return Err(StoreError::QuotaExceeded {
                    scope: "enrollment_codes",
                });
            }
            tx.execute(
                "INSERT INTO enrollment_codes(code_hash, expires_at) VALUES (?1, ?2)",
                params![request.code_hash.as_slice(), expires_at],
            )?;
        }
    }
    tx.commit()?;
    Ok(())
}

pub(crate) fn register_machine(
    conn: &mut Connection,
    config: &RelayV2StoreConfig,
    request: RegisterMachine,
) -> Result<MachineRecord, StoreError> {
    validate_machine_request(&request)?;
    let now = sql_i64(config.clock.now_ms()?, "enrollment_codes.consumed_at")?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let code = tx
        .query_row(
            "SELECT expires_at, consumed_at, request_hash, response_blob, receipt_hash
             FROM enrollment_codes WHERE code_hash = ?1",
            params![request.code_hash.as_slice()],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Option<i64>>(1)?,
                    row.get::<_, Option<Vec<u8>>>(2)?,
                    row.get::<_, Option<Vec<u8>>>(3)?,
                    row.get::<_, Option<Vec<u8>>>(4)?,
                ))
            },
        )
        .optional()?
        .ok_or(StoreError::EnrollmentCodeNotFound)?;

    if now > code.0 {
        return Err(StoreError::EnrollmentCodeExpired);
    }

    if code.1.is_some() {
        let stored_request = required_array::<32>(code.2, "enrollment_codes.request_hash")?;
        if stored_request != request.request_hash {
            return Err(StoreError::EnrollmentCodeConflict);
        }
        let response_blob = code.3.ok_or(StoreError::UnknownOrCorruptSchema)?;
        let receipt_hash = required_array::<32>(code.4, "enrollment_codes.receipt_hash")?;
        let record = load_machine_record(
            &tx,
            request.machine_route,
            response_blob,
            receipt_hash,
            true,
        )?;
        tx.commit()?;
        return Ok(record);
    }

    if tx
        .query_row(
            "SELECT 1 FROM machine_routes WHERE machine_route = ?1",
            params![request.machine_route.as_bytes().as_slice()],
            |_| Ok(()),
        )
        .optional()?
        .is_some()
    {
        return Err(StoreError::IdempotencyConflict {
            field: "machine_route",
        });
    }

    let relay_server_id = load_relay_server_id(&tx)?;
    tx.execute(
        "INSERT INTO machine_routes(
            machine_route, relay_server_id, root_key_id, root_pubkey, trust_epoch,
            highest_link_generation, link_cert_hash, data_cert_hash, status
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'active')",
        params![
            request.machine_route.as_bytes().as_slice(),
            relay_server_id.as_bytes().as_slice(),
            request.link_cert.root_key_id.as_bytes().as_slice(),
            request.root_pubkey.0.as_slice(),
            monotonic_blob(request.link_cert.trust_epoch.value()).as_slice(),
            monotonic_blob(request.link_cert.generation.value()).as_slice(),
            request.link_cert_hash.as_slice(),
            request.data_cert_hash.as_slice(),
        ],
    )?;
    tx.execute(
        "UPDATE enrollment_codes
         SET consumed_at = ?2, request_hash = ?3, response_blob = ?4, receipt_hash = ?5
         WHERE code_hash = ?1 AND consumed_at IS NULL",
        params![
            request.code_hash.as_slice(),
            now,
            request.request_hash.as_slice(),
            request.response_blob.as_slice(),
            request.receipt_hash.as_slice(),
        ],
    )?;
    config
        .fault_injector
        .check(FaultPoint::RegisterMachineBeforeCommit)?;
    tx.commit()?;
    config
        .fault_injector
        .check(FaultPoint::RegisterMachineAfterCommit)?;

    Ok(MachineRecord {
        relay_server_id,
        machine_route: request.machine_route,
        root_key_id: request.link_cert.root_key_id,
        trust_epoch: request.link_cert.trust_epoch,
        highest_link_generation: request.link_cert.generation,
        response_blob: request.response_blob,
        receipt_hash: request.receipt_hash,
        duplicate: false,
    })
}

pub(crate) fn machine_trust(
    conn: &Connection,
    machine_route: MachineRouteId,
) -> Result<MachineTrustView, StoreError> {
    let row = conn
        .query_row(
            "SELECT relay_server_id, root_key_id, root_pubkey, trust_epoch,
                    highest_link_generation, link_cert_hash, status
             FROM machine_routes WHERE machine_route = ?1",
            params![machine_route.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, String>(6)?,
                ))
            },
        )
        .optional()?
        .ok_or(StoreError::MachineNotFound)?;
    if row.6 != "active" {
        return Err(StoreError::MachineNotFound);
    }
    Ok(MachineTrustView {
        relay_server_id: RelayServerId::from_bytes(array_from_blob::<16>(
            row.0,
            "machine_routes.relay_server_id",
        )?),
        machine_route,
        root_key_id: RootKeyId::from_bytes(array_from_blob::<16>(
            row.1,
            "machine_routes.root_key_id",
        )?),
        root_pubkey: PublicKeyBytes(array_from_blob::<32>(row.2, "machine_routes.root_pubkey")?),
        trust_epoch: TrustEpoch::new(monotonic_from_blob(row.3, "machine_routes.trust_epoch")?),
        highest_link_generation: LinkGeneration::new(monotonic_from_blob(
            row.4,
            "machine_routes.highest_link_generation",
        )?),
        link_cert_hash: array_from_blob::<32>(row.5, "machine_routes.link_cert_hash")?,
    })
}

pub(crate) fn device_trust(
    conn: &Connection,
    machine_route: MachineRouteId,
    device_route: DeviceRouteId,
) -> Result<DeviceTrustView, StoreError> {
    let row = conn
        .query_row(
            "SELECT m.relay_server_id, m.root_key_id, m.root_pubkey, m.trust_epoch,
                    m.highest_link_generation, m.link_cert_hash, m.status,
                    d.auth_pubkey, d.auth_fingerprint, d.grant_serial, d.grant_hash,
                    d.tombstone
             FROM machine_routes m
             JOIN device_grants d ON d.machine_route = m.machine_route
             WHERE m.machine_route = ?1 AND d.device_route = ?2",
            params![
                machine_route.as_bytes().as_slice(),
                device_route.as_bytes().as_slice(),
            ],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, Vec<u8>>(7)?,
                    row.get::<_, Vec<u8>>(8)?,
                    row.get::<_, Vec<u8>>(9)?,
                    row.get::<_, Vec<u8>>(10)?,
                    row.get::<_, i64>(11)?,
                ))
            },
        )
        .optional()?
        .ok_or(StoreError::GrantNotFound)?;
    if row.6 != "active" {
        return Err(StoreError::MachineNotFound);
    }
    Ok(DeviceTrustView {
        machine: MachineTrustView {
            relay_server_id: RelayServerId::from_bytes(array_from_blob::<16>(
                row.0,
                "machine_routes.relay_server_id",
            )?),
            machine_route,
            root_key_id: RootKeyId::from_bytes(array_from_blob::<16>(
                row.1,
                "machine_routes.root_key_id",
            )?),
            root_pubkey: PublicKeyBytes(array_from_blob::<32>(
                row.2,
                "machine_routes.root_pubkey",
            )?),
            trust_epoch: TrustEpoch::new(monotonic_from_blob(row.3, "machine_routes.trust_epoch")?),
            highest_link_generation: LinkGeneration::new(monotonic_from_blob(
                row.4,
                "machine_routes.highest_link_generation",
            )?),
            link_cert_hash: array_from_blob::<32>(row.5, "machine_routes.link_cert_hash")?,
        },
        device_route,
        auth_pubkey: PublicKeyBytes(array_from_blob::<32>(row.7, "device_grants.auth_pubkey")?),
        auth_fingerprint: array_from_blob::<32>(row.8, "device_grants.auth_fingerprint")?,
        grant_serial: GrantSerial::new(monotonic_from_blob(row.9, "device_grants.grant_serial")?),
        grant_hash: array_from_blob::<32>(row.10, "device_grants.grant_hash")?,
        revoked: row.11 != 0,
    })
}

pub(crate) fn commit_machine_link_auth(
    conn: &mut Connection,
    config: &RelayV2StoreConfig,
    request: CommitMachineLinkAuth,
) -> Result<MachineLinkAuthCommit, StoreError> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let row = tx
        .query_row(
            "SELECT root_key_id, trust_epoch, highest_link_generation, link_cert_hash, status
             FROM machine_routes WHERE machine_route = ?1",
            params![request.machine_route.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, String>(4)?,
                ))
            },
        )
        .optional()?
        .ok_or(StoreError::MachineNotFound)?;
    if row.4 != "active" {
        return Err(StoreError::MachineNotFound);
    }
    let root_key_id =
        RootKeyId::from_bytes(array_from_blob::<16>(row.0, "machine_routes.root_key_id")?);
    let trust_epoch = TrustEpoch::new(monotonic_from_blob(row.1, "machine_routes.trust_epoch")?);
    if root_key_id != request.root_key_id || trust_epoch != request.trust_epoch {
        return Err(StoreError::AuthenticationMismatch {
            field: "machine_trust",
        });
    }
    let stored_generation = LinkGeneration::new(monotonic_from_blob(
        row.2,
        "machine_routes.highest_link_generation",
    )?);
    let stored_hash = array_from_blob::<32>(row.3, "machine_routes.link_cert_hash")?;
    let duplicate = match request.generation.cmp(&stored_generation) {
        std::cmp::Ordering::Less => {
            return Err(StoreError::MonotonicRollback {
                field: "link_generation",
            });
        }
        std::cmp::Ordering::Equal if stored_hash != request.cert_hash => {
            return Err(StoreError::IdempotencyConflict {
                field: "link_generation",
            });
        }
        std::cmp::Ordering::Equal => true,
        std::cmp::Ordering::Greater => {
            tx.execute(
                "UPDATE machine_routes
                 SET highest_link_generation = ?2, link_cert_hash = ?3
                 WHERE machine_route = ?1 AND status = 'active'",
                params![
                    request.machine_route.as_bytes().as_slice(),
                    monotonic_blob(request.generation.value()).as_slice(),
                    request.cert_hash.as_slice(),
                ],
            )?;
            false
        }
    };
    config
        .fault_injector
        .check(FaultPoint::MachineLinkAuthBeforeCommit)?;
    tx.commit()?;
    Ok(MachineLinkAuthCommit {
        machine_route: request.machine_route,
        generation: request.generation,
        cert_hash: request.cert_hash,
        duplicate,
    })
}

pub(crate) fn confirm_device_auth(
    conn: &Connection,
    config: &RelayV2StoreConfig,
    request: ConfirmDeviceAuth,
) -> Result<(), StoreError> {
    let trust = device_trust(conn, request.machine_route, request.device_route)?;
    if trust.revoked {
        return Err(StoreError::Revoked);
    }
    if trust.grant_serial != request.grant_serial {
        return Err(StoreError::AuthenticationMismatch {
            field: "grant_serial",
        });
    }
    if trust.grant_hash != request.grant_hash {
        return Err(StoreError::AuthenticationMismatch {
            field: "grant_hash",
        });
    }
    if trust.auth_pubkey != request.auth_pubkey {
        return Err(StoreError::AuthenticationMismatch {
            field: "auth_pubkey",
        });
    }
    if trust.auth_fingerprint != request.auth_fingerprint {
        return Err(StoreError::AuthenticationMismatch {
            field: "auth_fingerprint",
        });
    }
    config
        .fault_injector
        .check(FaultPoint::DeviceAuthBeforeConfirm)?;
    Ok(())
}

pub(crate) fn install_grant(
    conn: &mut Connection,
    config: &RelayV2StoreConfig,
    request: InstallGrantRecord,
) -> Result<GrantCommit, StoreError> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let (root_key_id, trust_epoch) = load_active_machine_trust(&tx, request.grant.machine_route)?;
    if root_key_id != request.grant.root_key_id || trust_epoch != request.grant.trust_epoch {
        return Err(StoreError::MonotonicRollback {
            field: "grant_trust",
        });
    }

    let existing = tx
        .query_row(
            "SELECT grant_serial, grant_hash, tombstone FROM device_grants
             WHERE machine_route = ?1 AND device_route = ?2",
            params![
                request.grant.machine_route.as_bytes().as_slice(),
                request.grant.device_route.as_bytes().as_slice(),
            ],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .optional()?;
    let mut duplicate = false;
    match existing {
        Some((serial_blob, hash_blob, tombstone)) => {
            if tombstone != 0 {
                return Err(StoreError::Revoked);
            }
            let stored_serial = monotonic_from_blob(serial_blob, "device_grants.grant_serial")?;
            let stored_hash = array_from_blob::<32>(hash_blob, "device_grants.grant_hash")?;
            match request.grant.grant_serial.value().cmp(&stored_serial) {
                std::cmp::Ordering::Less => {
                    return Err(StoreError::MonotonicRollback {
                        field: "grant_serial",
                    });
                }
                std::cmp::Ordering::Equal if stored_hash != request.grant_hash => {
                    return Err(StoreError::IdempotencyConflict {
                        field: "grant_serial",
                    });
                }
                std::cmp::Ordering::Equal => duplicate = true,
                std::cmp::Ordering::Greater => {
                    tx.execute(
                        "DELETE FROM subscriptions WHERE machine_route = ?1 AND device_route = ?2",
                        params![
                            request.grant.machine_route.as_bytes().as_slice(),
                            request.grant.device_route.as_bytes().as_slice(),
                        ],
                    )?;
                    trim_fully_acked_prefixes(&tx)?;
                    recompute_stream_stats(&tx)?;
                    tx.execute(
                        "UPDATE device_grants SET auth_pubkey = ?3, auth_fingerprint = ?4,
                            grant_serial = ?5, grant_hash = ?6, revoked_at = NULL, tombstone = 0
                         WHERE machine_route = ?1 AND device_route = ?2",
                        params![
                            request.grant.machine_route.as_bytes().as_slice(),
                            request.grant.device_route.as_bytes().as_slice(),
                            request.grant.device_sign_pubkey.0.as_slice(),
                            Sha256::digest(request.grant.device_sign_pubkey.0).as_slice(),
                            monotonic_blob(request.grant.grant_serial.value()).as_slice(),
                            request.grant_hash.as_slice(),
                        ],
                    )?;
                }
            }
        }
        None => {
            tx.execute(
                "INSERT INTO device_grants(
                    machine_route, device_route, auth_pubkey, auth_fingerprint,
                    grant_serial, grant_hash, revoked_at, tombstone
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, 0)",
                params![
                    request.grant.machine_route.as_bytes().as_slice(),
                    request.grant.device_route.as_bytes().as_slice(),
                    request.grant.device_sign_pubkey.0.as_slice(),
                    Sha256::digest(request.grant.device_sign_pubkey.0).as_slice(),
                    monotonic_blob(request.grant.grant_serial.value()).as_slice(),
                    request.grant_hash.as_slice(),
                ],
            )?;
        }
    }
    config
        .fault_injector
        .check(FaultPoint::InstallGrantBeforeCommit)?;
    tx.commit()?;
    Ok(GrantCommit {
        device_route: request.grant.device_route,
        grant_serial: request.grant.grant_serial,
        grant_hash: request.grant_hash,
        duplicate,
    })
}

pub(crate) fn register_stream(
    conn: &mut Connection,
    config: &RelayV2StoreConfig,
    request: StreamRegistration,
) -> Result<StreamRecord, StoreError> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    load_active_machine_trust(&tx, request.machine_route)?;
    let existing = tx
        .query_row(
            "SELECT machine_route, generation, high_water_seq, oldest_seq, retained_bytes
             FROM streams WHERE stream_route = ?1",
            params![request.stream_route.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .optional()?;
    if let Some((machine_blob, generation_blob, high_water, oldest, retained)) = existing {
        let machine = MachineRouteId::from_bytes(array_from_blob::<16>(
            machine_blob,
            "streams.machine_route",
        )?);
        let generation = agentdeck_protocol::relay_v2::StreamGenerationId::from_bytes(
            array_from_blob::<16>(generation_blob, "streams.generation")?,
        );
        if machine != request.machine_route || generation != request.generation {
            return Err(StoreError::StreamBindingConflict);
        }
        let retained_bytes = u64::try_from(retained).map_err(|_| StoreError::InvalidValue {
            field: "streams.retained_bytes",
            reason: "value must be non-negative",
        })?;
        let oldest_seq = oldest
            .map(|value| super::model::stream_seq_from_text(value, "streams.oldest_seq"))
            .transpose()?;
        let record = StreamRecord {
            machine_route: machine,
            stream_route: request.stream_route,
            generation,
            high_water_seq: high_water_from_text(high_water, "streams.high_water_seq")?,
            oldest_seq,
            retained_bytes,
            duplicate: true,
        };
        tx.commit()?;
        return Ok(record);
    }

    if tx
        .query_row(
            "SELECT 1 FROM streams WHERE generation = ?1",
            params![request.generation.as_bytes().as_slice()],
            |_| Ok(()),
        )
        .optional()?
        .is_some()
    {
        return Err(StoreError::StreamBindingConflict);
    }
    tx.execute(
        "INSERT INTO streams(
            stream_route, machine_route, generation, high_water_seq, oldest_seq, retained_bytes
         ) VALUES (?1, ?2, ?3, ?4, NULL, 0)",
        params![
            request.stream_route.as_bytes().as_slice(),
            request.machine_route.as_bytes().as_slice(),
            request.generation.as_bytes().as_slice(),
            EMPTY_HIGH_WATER_TEXT,
        ],
    )?;
    config
        .fault_injector
        .check(FaultPoint::RegisterStreamBeforeCommit)?;
    tx.commit()?;
    Ok(StreamRecord {
        machine_route: request.machine_route,
        stream_route: request.stream_route,
        generation: request.generation,
        high_water_seq: None,
        oldest_seq: None,
        retained_bytes: 0,
        duplicate: false,
    })
}

pub(crate) fn publish(
    conn: &mut Connection,
    config: &RelayV2StoreConfig,
    request: PersistPublish,
) -> Result<PublishCommit, StoreError> {
    let canonical = request.canonical_bytes()?;
    let (stream_route, generation, stream_seq, sealed_blob) = match &request.frame.body {
        RelayFrameBody::Publish(frame) => (
            frame.stream_route,
            frame.generation,
            frame.stream_seq,
            frame.sealed_blob.0.clone(),
        ),
        _ => {
            return Err(StoreError::InvalidValue {
                field: "publish.frame",
                reason: "expected Publish frame",
            });
        }
    };
    if stream_seq == u64::MAX {
        return Err(StoreError::InvalidValue {
            field: "stream_seq",
            reason: "counter exhausted; create a new stream generation before u64::MAX",
        });
    }
    let size = u64::try_from(canonical.len()).map_err(|_| StoreError::FrameTooLarge)?;
    let frame_hash: [u8; 32] = Sha256::digest(&canonical).into();
    let seq_text = stream_seq_text(stream_seq);

    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    load_active_machine_trust(&tx, request.machine_route)?;
    let stream = load_stream_state(&tx, stream_route)?;
    if stream.machine_route != request.machine_route || stream.generation != generation {
        return Err(StoreError::StreamBindingConflict);
    }

    let existing_hash = tx
        .query_row(
            "SELECT frame_hash FROM frames
             WHERE stream_route = ?1 AND generation = ?2 AND stream_seq = ?3",
            params![
                stream_route.as_bytes().as_slice(),
                generation.as_bytes().as_slice(),
                &seq_text,
            ],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?;
    if let Some(existing_hash) = existing_hash {
        if array_from_blob::<32>(existing_hash, "frames.frame_hash")? != frame_hash {
            return Err(StoreError::IdempotencyConflict {
                field: "stream_seq",
            });
        }
        tx.commit()?;
        return Ok(PublishCommit {
            stream_route,
            generation,
            stream_seq,
            frame_hash,
            size,
            disposition: PublishDisposition::Duplicate,
        });
    }

    // Idempotent duplicate consumes no new storage and must remain recoverable even
    // after quotas changed or the filesystem crossed the disk-low threshold. Apply
    // all mutable capacity gates only after ruling out the canonical duplicate.
    if size > config.retention.max_bytes_per_stream {
        return Err(StoreError::QuotaExceeded { scope: "stream" });
    }
    if size > config.retention.max_bytes_per_machine {
        return Err(StoreError::QuotaExceeded { scope: "machine" });
    }
    if size > config.retention.max_bytes_global {
        return Err(StoreError::QuotaExceeded { scope: "global" });
    }
    let disk = config.disk_space_probe.space(&config.storage_path)?;
    let reserve = config.retention.disk_reserve_for(disk.total_bytes);
    if disk
        .available_bytes
        .checked_sub(size)
        .is_none_or(|left| left < reserve)
    {
        return Err(StoreError::DiskSpaceLow);
    }
    let received_at_ms = config.clock.now_ms()?;
    let received_at = sql_i64(received_at_ms, "frames.received_at")?;
    let size_i64 = sql_i64(size, "frames.size")?;

    let expected = match stream.high_water_seq {
        None => 0,
        Some(value) => value.checked_add(1).ok_or(StoreError::InvalidValue {
            field: "stream_seq",
            reason: "counter exhausted; create a new stream generation",
        })?,
    };
    if stream_seq != expected {
        return Err(StoreError::SequenceConflict {
            expected,
            found: stream_seq,
        });
    }

    tx.execute(
        "INSERT INTO frames(
            stream_route, generation, stream_seq, frame_hash, sealed_blob, size, received_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            stream_route.as_bytes().as_slice(),
            generation.as_bytes().as_slice(),
            &seq_text,
            frame_hash.as_slice(),
            sealed_blob.as_slice(),
            size_i64,
            received_at,
        ],
    )?;
    tx.execute(
        "UPDATE streams SET high_water_seq = ?3
         WHERE stream_route = ?1 AND generation = ?2",
        params![
            stream_route.as_bytes().as_slice(),
            generation.as_bytes().as_slice(),
            high_water_text(Some(stream_seq)),
        ],
    )?;
    enforce_retention(
        &tx,
        config,
        received_at_ms,
        request.machine_route,
        stream_route,
    )?;
    config
        .fault_injector
        .check(FaultPoint::PublishBeforeCommit)?;
    tx.commit()?;
    config
        .fault_injector
        .check(FaultPoint::PublishAfterCommit)?;
    Ok(PublishCommit {
        stream_route,
        generation,
        stream_seq,
        frame_hash,
        size,
        disposition: PublishDisposition::Inserted,
    })
}

#[derive(Debug)]
struct StoredStreamState {
    machine_route: MachineRouteId,
    generation: StreamGenerationId,
    high_water_seq: Option<u64>,
    oldest_seq: Option<u64>,
}

fn load_stream_state(
    conn: &Connection,
    stream_route: StreamRouteId,
) -> Result<StoredStreamState, StoreError> {
    let row = conn
        .query_row(
            "SELECT machine_route, generation, high_water_seq, oldest_seq
             FROM streams WHERE stream_route = ?1",
            params![stream_route.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                ))
            },
        )
        .optional()?
        .ok_or(StoreError::StreamNotFound)?;
    Ok(StoredStreamState {
        machine_route: MachineRouteId::from_bytes(array_from_blob::<16>(
            row.0,
            "streams.machine_route",
        )?),
        generation: StreamGenerationId::from_bytes(array_from_blob::<16>(
            row.1,
            "streams.generation",
        )?),
        high_water_seq: high_water_from_text(row.2, "streams.high_water_seq")?,
        oldest_seq: row
            .3
            .map(|value| stream_seq_from_text(value, "streams.oldest_seq"))
            .transpose()?,
    })
}

fn enforce_retention(
    tx: &rusqlite::Transaction<'_>,
    config: &RelayV2StoreConfig,
    now_ms: u64,
    publishing_machine: MachineRouteId,
    publishing_stream: StreamRouteId,
) -> Result<(), StoreError> {
    let cutoff = sql_i64(
        now_ms.saturating_sub(config.retention.max_age_ms),
        "frames.received_at",
    )?;
    tx.execute("DELETE FROM frames WHERE received_at < ?1", params![cutoff])?;
    trim_fully_acked_prefixes(tx)?;

    enforce_stream_capacity(tx, config, publishing_stream)?;
    enforce_machine_capacity(tx, config, publishing_machine)?;
    enforce_global_capacity(tx, config)?;
    recompute_stream_stats(tx)
}

fn enforce_all_capacity_limits(
    tx: &rusqlite::Transaction<'_>,
    config: &RelayV2StoreConfig,
) -> Result<u64, StoreError> {
    let mut deleted = 0_u64;
    let mut last_stream_route: Option<Vec<u8>> = None;
    while let Some(route_blob) =
        next_route_blob(tx, "streams", "stream_route", last_stream_route.as_deref())?
    {
        let stream_route = StreamRouteId::from_bytes(array_from_blob::<16>(
            route_blob.clone(),
            "streams.stream_route",
        )?);
        deleted = checked_deleted_add(deleted, enforce_stream_capacity(tx, config, stream_route)?)?;
        last_stream_route = Some(route_blob);
    }
    let mut last_machine_route: Option<Vec<u8>> = None;
    while let Some(route_blob) = next_route_blob(
        tx,
        "machine_routes",
        "machine_route",
        last_machine_route.as_deref(),
    )? {
        let machine_route = MachineRouteId::from_bytes(array_from_blob::<16>(
            route_blob.clone(),
            "machine_routes.machine_route",
        )?);
        deleted = checked_deleted_add(
            deleted,
            enforce_machine_capacity(tx, config, machine_route)?,
        )?;
        last_machine_route = Some(route_blob);
    }
    checked_deleted_add(deleted, enforce_global_capacity(tx, config)?)
}

fn next_route_blob(
    tx: &rusqlite::Transaction<'_>,
    table: &'static str,
    column: &'static str,
    after: Option<&[u8]>,
) -> Result<Option<Vec<u8>>, StoreError> {
    let sql = match (table, column, after.is_some()) {
        ("streams", "stream_route", false) => {
            "SELECT stream_route FROM streams ORDER BY stream_route LIMIT 1"
        }
        ("streams", "stream_route", true) => {
            "SELECT stream_route FROM streams WHERE stream_route > ?1 ORDER BY stream_route LIMIT 1"
        }
        ("machine_routes", "machine_route", false) => {
            "SELECT machine_route FROM machine_routes ORDER BY machine_route LIMIT 1"
        }
        ("machine_routes", "machine_route", true) => {
            "SELECT machine_route FROM machine_routes WHERE machine_route > ?1 ORDER BY machine_route LIMIT 1"
        }
        _ => {
            return Err(StoreError::InvalidValue {
                field: "maintenance.keyset",
                reason: "unsupported keyset table or column",
            });
        }
    };
    if let Some(after) = after {
        tx.query_row(sql, params![after], |row| row.get::<_, Vec<u8>>(0))
            .optional()
            .map_err(StoreError::from)
    } else {
        tx.query_row(sql, [], |row| row.get::<_, Vec<u8>>(0))
            .optional()
            .map_err(StoreError::from)
    }
}

fn enforce_stream_capacity(
    tx: &rusqlite::Transaction<'_>,
    config: &RelayV2StoreConfig,
    stream_route: StreamRouteId,
) -> Result<u64, StoreError> {
    let mut deleted = 0_u64;
    while query_u64(
        tx,
        "SELECT COUNT(*) FROM frames WHERE stream_route = ?1",
        params![stream_route.as_bytes().as_slice()],
        "frames.count",
    )? > config.retention.max_frames_per_stream
    {
        deleted = checked_deleted_add(
            deleted,
            require_deleted(delete_oldest_for_stream(tx, stream_route)?)?,
        )?;
    }
    while query_u64(
        tx,
        "SELECT COALESCE(SUM(size), 0) FROM frames WHERE stream_route = ?1",
        params![stream_route.as_bytes().as_slice()],
        "frames.stream_bytes",
    )? > config.retention.max_bytes_per_stream
    {
        deleted = checked_deleted_add(
            deleted,
            require_deleted(delete_oldest_for_stream(tx, stream_route)?)?,
        )?;
    }
    Ok(deleted)
}

fn enforce_machine_capacity(
    tx: &rusqlite::Transaction<'_>,
    config: &RelayV2StoreConfig,
    machine_route: MachineRouteId,
) -> Result<u64, StoreError> {
    let mut deleted = 0_u64;
    while query_u64(
        tx,
        "SELECT COALESCE(SUM(f.size), 0) FROM frames f
         JOIN streams s ON s.stream_route = f.stream_route AND s.generation = f.generation
         WHERE s.machine_route = ?1",
        params![machine_route.as_bytes().as_slice()],
        "frames.machine_bytes",
    )? > config.retention.max_bytes_per_machine
    {
        deleted = checked_deleted_add(
            deleted,
            require_deleted(delete_oldest_for_machine(tx, machine_route)?)?,
        )?;
    }
    Ok(deleted)
}

fn enforce_global_capacity(
    tx: &rusqlite::Transaction<'_>,
    config: &RelayV2StoreConfig,
) -> Result<u64, StoreError> {
    let mut deleted = 0_u64;
    while query_u64(
        tx,
        "SELECT COALESCE(SUM(size), 0) FROM frames",
        [],
        "frames.global_bytes",
    )? > config.retention.max_bytes_global
    {
        deleted = checked_deleted_add(deleted, require_deleted(delete_oldest_global(tx)?)?)?;
    }
    Ok(deleted)
}

fn checked_deleted_add(current: u64, deleted: u64) -> Result<u64, StoreError> {
    current
        .checked_add(deleted)
        .ok_or(StoreError::InvalidValue {
            field: "maintenance.quota_evicted_frames",
            reason: "deleted frame count overflow",
        })
}

fn require_deleted(deleted: u64) -> Result<u64, StoreError> {
    if deleted == 0 {
        Err(StoreError::UnknownOrCorruptSchema)
    } else {
        Ok(deleted)
    }
}

fn trim_fully_acked_prefixes(tx: &rusqlite::Transaction<'_>) -> Result<u64, StoreError> {
    let mut statement = tx.prepare(
        "SELECT stream_route, stream_generation, MIN(ack)
         FROM subscriptions
         GROUP BY stream_route, stream_generation
         HAVING COUNT(*) = COUNT(ack)",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, Vec<u8>>(0)?,
            row.get::<_, Vec<u8>>(1)?,
            row.get::<_, String>(2)?,
        ))
    })?;
    let mut prefixes = Vec::new();
    for row in rows {
        prefixes.push(row?);
    }
    drop(statement);
    let mut deleted = 0_u64;
    for (stream_route, generation, ack) in prefixes {
        let count = tx.execute(
            "DELETE FROM frames
             WHERE stream_route = ?1 AND generation = ?2 AND stream_seq <= ?3",
            params![stream_route, generation, ack],
        )?;
        deleted = deleted
            .checked_add(u64::try_from(count).map_err(|_| StoreError::InvalidValue {
                field: "maintenance.ack_trimmed_frames",
                reason: "deleted frame count does not fit u64",
            })?)
            .ok_or(StoreError::InvalidValue {
                field: "maintenance.ack_trimmed_frames",
                reason: "deleted frame count overflow",
            })?;
    }
    Ok(deleted)
}

fn delete_oldest_for_stream(
    tx: &rusqlite::Transaction<'_>,
    stream_route: StreamRouteId,
) -> Result<u64, StoreError> {
    u64::try_from(tx.execute(
        "DELETE FROM frames WHERE rowid = (
            SELECT rowid FROM frames WHERE stream_route = ?1
            ORDER BY stream_seq, rowid LIMIT 1
         )",
        params![stream_route.as_bytes().as_slice()],
    )?)
    .map_err(|_| StoreError::InvalidValue {
        field: "maintenance.quota_evicted_frames",
        reason: "deleted frame count does not fit u64",
    })
}

fn delete_oldest_for_machine(
    tx: &rusqlite::Transaction<'_>,
    machine_route: MachineRouteId,
) -> Result<u64, StoreError> {
    u64::try_from(tx.execute(
        "DELETE FROM frames WHERE rowid = (
            SELECT f.rowid FROM frames f
            JOIN streams s ON s.stream_route = f.stream_route AND s.generation = f.generation
            WHERE s.machine_route = ?1
            ORDER BY f.rowid LIMIT 1
         )",
        params![machine_route.as_bytes().as_slice()],
    )?)
    .map_err(|_| StoreError::InvalidValue {
        field: "maintenance.quota_evicted_frames",
        reason: "deleted frame count does not fit u64",
    })
}

fn delete_oldest_global(tx: &rusqlite::Transaction<'_>) -> Result<u64, StoreError> {
    u64::try_from(tx.execute(
        "DELETE FROM frames WHERE rowid = (
            SELECT rowid FROM frames
            ORDER BY rowid LIMIT 1
         )",
        [],
    )?)
    .map_err(|_| StoreError::InvalidValue {
        field: "maintenance.quota_evicted_frames",
        reason: "deleted frame count does not fit u64",
    })
}

fn recompute_stream_stats(tx: &rusqlite::Transaction<'_>) -> Result<(), StoreError> {
    tx.execute(
        "UPDATE streams SET
            oldest_seq = (
                SELECT MIN(f.stream_seq) FROM frames f
                WHERE f.stream_route = streams.stream_route AND f.generation = streams.generation
            ),
            retained_bytes = COALESCE((
                SELECT SUM(f.size) FROM frames f
                WHERE f.stream_route = streams.stream_route AND f.generation = streams.generation
            ), 0)",
        [],
    )?;
    Ok(())
}

fn recompute_one_stream_stats(
    tx: &rusqlite::Transaction<'_>,
    stream_route: StreamRouteId,
    generation: StreamGenerationId,
) -> Result<(), StoreError> {
    tx.execute(
        "UPDATE streams SET
            oldest_seq = (
                SELECT MIN(f.stream_seq) FROM frames f
                WHERE f.stream_route = streams.stream_route AND f.generation = streams.generation
            ),
            retained_bytes = COALESCE((
                SELECT SUM(f.size) FROM frames f
                WHERE f.stream_route = streams.stream_route AND f.generation = streams.generation
            ), 0)
         WHERE stream_route = ?1 AND generation = ?2",
        params![
            stream_route.as_bytes().as_slice(),
            generation.as_bytes().as_slice(),
        ],
    )?;
    Ok(())
}

fn query_u64<P: rusqlite::Params>(
    conn: &Connection,
    sql: &str,
    params: P,
    field: &'static str,
) -> Result<u64, StoreError> {
    let value = conn.query_row(sql, params, |row| row.get::<_, i64>(0))?;
    u64::try_from(value).map_err(|_| StoreError::InvalidValue {
        field,
        reason: "SQLite aggregate must be non-negative",
    })
}

pub(crate) fn subscribe(
    conn: &mut Connection,
    config: &RelayV2StoreConfig,
    request: PersistSubscription,
) -> Result<SubscriptionLease, StoreError> {
    let now = sql_i64(config.clock.now_ms()?, "subscriptions.updated_at")?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    load_active_machine_trust(&tx, request.machine_route)?;
    ensure_current_grant(
        &tx,
        request.machine_route,
        request.device_route,
        request.grant_serial,
        false,
    )?;
    let stream = load_stream_state(&tx, request.stream_route)?;
    if stream.machine_route != request.machine_route || stream.generation != request.generation {
        return Err(StoreError::StreamBindingConflict);
    }
    match (stream.high_water_seq, request.start) {
        (None, StreamCursor::At(_)) => return Err(StoreError::InvalidReplayCursor),
        (Some(high_water), StreamCursor::At(cursor)) if cursor > high_water => {
            return Err(StoreError::InvalidReplayCursor);
        }
        _ => {}
    }
    if let Some(needed) = next_after_cursor(request.start)?
        && let Some(high_water) = stream.high_water_seq
        && needed <= high_water
    {
        match stream.oldest_seq {
            Some(oldest) if needed < oldest => {
                return Err(StoreError::ReplayGap { needed, oldest });
            }
            None => {
                return Err(StoreError::ReplayGap {
                    needed,
                    oldest: high_water.saturating_add(1),
                });
            }
            Some(_) => {}
        }
    }
    let start_text = match request.start {
        StreamCursor::BeforeFirst => None,
        StreamCursor::At(value) => Some(stream_seq_text(value)),
    };
    let existing_ack = tx
        .query_row(
            "SELECT ack FROM subscriptions
             WHERE machine_route = ?1 AND device_route = ?2 AND grant_serial = ?3
               AND stream_route = ?4 AND stream_generation = ?5",
            params![
                request.machine_route.as_bytes().as_slice(),
                request.device_route.as_bytes().as_slice(),
                monotonic_blob(request.grant_serial.value()).as_slice(),
                request.stream_route.as_bytes().as_slice(),
                request.generation.as_bytes().as_slice(),
            ],
            |row| row.get::<_, Option<String>>(0),
        )
        .optional()?;
    let duplicate = existing_ack.is_some();
    tx.execute(
        "INSERT INTO subscriptions(
            machine_route, device_route, grant_serial, stream_route, stream_generation,
            start_cursor_seq, ack, updated_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, ?7)
         ON CONFLICT(machine_route, device_route, grant_serial, stream_route, stream_generation)
         DO UPDATE SET start_cursor_seq = excluded.start_cursor_seq, updated_at = excluded.updated_at",
        params![
            request.machine_route.as_bytes().as_slice(),
            request.device_route.as_bytes().as_slice(),
            monotonic_blob(request.grant_serial.value()).as_slice(),
            request.stream_route.as_bytes().as_slice(),
            request.generation.as_bytes().as_slice(),
            start_text,
            now,
        ],
    )?;
    config
        .fault_injector
        .check(FaultPoint::SubscribeBeforeCommit)?;
    tx.commit()?;
    let ack = existing_ack
        .flatten()
        .map(|value| stream_seq_from_text(value, "subscriptions.ack"))
        .transpose()?;
    Ok(SubscriptionLease {
        start: request.start,
        ack,
        duplicate,
    })
}

pub(crate) fn unsubscribe(
    conn: &mut Connection,
    _config: &RelayV2StoreConfig,
    request: PersistUnsubscribe,
) -> Result<UnsubscribeCommit, StoreError> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let removed = tx.execute(
        "DELETE FROM subscriptions
         WHERE machine_route = ?1 AND device_route = ?2 AND grant_serial = ?3
           AND stream_route = ?4 AND stream_generation = ?5",
        params![
            request.machine_route.as_bytes().as_slice(),
            request.device_route.as_bytes().as_slice(),
            monotonic_blob(request.grant_serial.value()).as_slice(),
            request.stream_route.as_bytes().as_slice(),
            request.generation.as_bytes().as_slice(),
        ],
    )? > 0;
    trim_fully_acked_prefixes(&tx)?;
    recompute_stream_stats(&tx)?;
    tx.commit()?;
    Ok(UnsubscribeCommit { removed })
}

pub(crate) fn ack(
    conn: &mut Connection,
    config: &RelayV2StoreConfig,
    request: PersistAck,
) -> Result<(), StoreError> {
    let now = sql_i64(config.clock.now_ms()?, "subscriptions.updated_at")?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    ensure_current_grant(
        &tx,
        request.machine_route,
        request.device_route,
        request.grant_serial,
        false,
    )?;
    let stream = load_stream_state(&tx, request.stream_route)?;
    if stream.machine_route != request.machine_route || stream.generation != request.generation {
        return Err(StoreError::StreamBindingConflict);
    }
    let high_water = stream.high_water_seq.ok_or(StoreError::SequenceConflict {
        expected: 0,
        found: request.up_to_seq,
    })?;
    if request.up_to_seq > high_water {
        return Err(StoreError::SequenceConflict {
            expected: high_water,
            found: request.up_to_seq,
        });
    }
    let current = tx
        .query_row(
            "SELECT ack FROM subscriptions
             WHERE machine_route = ?1 AND device_route = ?2 AND grant_serial = ?3
               AND stream_route = ?4 AND stream_generation = ?5",
            params![
                request.machine_route.as_bytes().as_slice(),
                request.device_route.as_bytes().as_slice(),
                monotonic_blob(request.grant_serial.value()).as_slice(),
                request.stream_route.as_bytes().as_slice(),
                request.generation.as_bytes().as_slice(),
            ],
            |row| row.get::<_, Option<String>>(0),
        )
        .optional()?
        .ok_or(StoreError::GrantNotFound)?;
    let current = current
        .map(|value| stream_seq_from_text(value, "subscriptions.ack"))
        .transpose()?;
    if current.is_none_or(|value| request.up_to_seq > value) {
        tx.execute(
            "UPDATE subscriptions SET ack = ?6, updated_at = ?7
             WHERE machine_route = ?1 AND device_route = ?2 AND grant_serial = ?3
               AND stream_route = ?4 AND stream_generation = ?5",
            params![
                request.machine_route.as_bytes().as_slice(),
                request.device_route.as_bytes().as_slice(),
                monotonic_blob(request.grant_serial.value()).as_slice(),
                request.stream_route.as_bytes().as_slice(),
                request.generation.as_bytes().as_slice(),
                stream_seq_text(request.up_to_seq),
                now,
            ],
        )?;
    }
    trim_fully_acked_prefixes(&tx)?;
    recompute_stream_stats(&tx)?;
    config.fault_injector.check(FaultPoint::AckBeforeCommit)?;
    tx.commit()?;
    Ok(())
}

pub(crate) fn replay_page(
    conn: &mut Connection,
    config: &RelayV2StoreConfig,
    request: ReplayPageRequest,
) -> Result<ReplayPage, StoreError> {
    run_replay_maintenance(conn, config, request.stream_route, request.generation)?;
    let stream = load_stream_state(conn, request.stream_route)?;
    if stream.machine_route != request.machine_route || stream.generation != request.generation {
        return Err(StoreError::StreamBindingConflict);
    }
    let Some(current_high_water) = stream.high_water_seq else {
        return match request.position {
            ReplayPosition::Start(StreamCursor::BeforeFirst) => Ok(ReplayPage {
                frames: Vec::new(),
                replay_through: StreamCursor::BeforeFirst,
                next: None,
            }),
            ReplayPosition::Start(StreamCursor::At(_)) | ReplayPosition::Continue(_) => {
                Err(StoreError::InvalidReplayCursor)
            }
        };
    };
    let (needed, through) = match request.position {
        ReplayPosition::Start(cursor) => {
            if matches!(cursor, StreamCursor::At(value) if value > current_high_water) {
                return Err(StoreError::InvalidReplayCursor);
            }
            (next_after_cursor(cursor)?, current_high_water)
        }
        ReplayPosition::Continue(cursor) => {
            if cursor.stream_route != request.stream_route
                || cursor.generation != request.generation
                || cursor.through_seq > current_high_water
                || cursor.next_seq > cursor.through_seq
            {
                return Err(StoreError::InvalidReplayCursor);
            }
            (Some(cursor.next_seq), cursor.through_seq)
        }
    };
    let Some(needed) = needed else {
        return Ok(ReplayPage {
            frames: Vec::new(),
            replay_through: StreamCursor::At(through),
            next: None,
        });
    };
    if needed > through {
        return Ok(ReplayPage {
            frames: Vec::new(),
            replay_through: StreamCursor::At(through),
            next: None,
        });
    }
    if let Some(oldest) = stream.oldest_seq {
        if needed < oldest {
            return Err(StoreError::ReplayGap { needed, oldest });
        }
    } else {
        return Err(StoreError::ReplayGap {
            needed,
            oldest: through.saturating_add(1),
        });
    }

    let limit = i64::try_from(config.retention.replay_page_max_frames).map_err(|_| {
        StoreError::InvalidValue {
            field: "retention.replay_page_max_frames",
            reason: "page limit does not fit SQLite LIMIT",
        }
    })?;
    let mut statement = conn.prepare(
        "SELECT stream_seq, size FROM frames
         WHERE stream_route = ?1 AND generation = ?2 AND stream_seq >= ?3 AND stream_seq <= ?4
         ORDER BY stream_seq LIMIT ?5",
    )?;
    let rows = statement.query_map(
        params![
            request.stream_route.as_bytes().as_slice(),
            request.generation.as_bytes().as_slice(),
            stream_seq_text(needed),
            stream_seq_text(through),
            limit,
        ],
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
    )?;
    let mut selected = Vec::new();
    let mut bytes = 0_u64;
    let mut expected = needed;
    for row in rows {
        let (seq_text, size_raw) = row?;
        let seq = stream_seq_from_text(seq_text, "frames.stream_seq")?;
        if seq != expected {
            return Err(StoreError::ReplayGap {
                needed: expected,
                oldest: seq,
            });
        }
        let size = u64::try_from(size_raw).map_err(|_| StoreError::InvalidValue {
            field: "frames.size",
            reason: "frame size must be non-negative",
        })?;
        if !selected.is_empty()
            && bytes
                .checked_add(size)
                .is_none_or(|sum| sum > config.retention.replay_page_max_bytes)
        {
            break;
        }
        bytes = bytes.checked_add(size).ok_or(StoreError::InvalidValue {
            field: "replay_page.bytes",
            reason: "page byte count overflow",
        })?;
        selected.push((seq, size));
        expected = seq.saturating_add(1);
    }
    drop(statement);
    if selected.is_empty() {
        return Err(StoreError::ReplayGap {
            needed,
            oldest: stream.oldest_seq.unwrap_or(through.saturating_add(1)),
        });
    }

    let mut frames = Vec::with_capacity(selected.len());
    for (seq, expected_size) in &selected {
        let row = conn.query_row(
            "SELECT frame_hash, sealed_blob, size, received_at FROM frames
             WHERE stream_route = ?1 AND generation = ?2 AND stream_seq = ?3",
            params![
                request.stream_route.as_bytes().as_slice(),
                request.generation.as_bytes().as_slice(),
                stream_seq_text(*seq),
            ],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )?;
        let size = u64::try_from(row.2).map_err(|_| StoreError::InvalidValue {
            field: "frames.size",
            reason: "frame size must be non-negative",
        })?;
        if size != *expected_size {
            return Err(StoreError::UnknownOrCorruptSchema);
        }
        frames.push(ReplayFrame {
            stream_seq: *seq,
            frame_hash: array_from_blob::<32>(row.0, "frames.frame_hash")?,
            sealed_blob: row.1,
            size,
            received_at_ms: u64::try_from(row.3).map_err(|_| StoreError::InvalidValue {
                field: "frames.received_at",
                reason: "timestamp must be non-negative",
            })?,
        });
    }
    let last = selected
        .last()
        .map(|item| item.0)
        .ok_or(StoreError::ReplayGap {
            needed,
            oldest: needed,
        })?;
    let next = if last < through {
        Some(ReplayCursor {
            stream_route: request.stream_route,
            generation: request.generation,
            next_seq: last.checked_add(1).ok_or(StoreError::InvalidReplayCursor)?,
            through_seq: through,
        })
    } else {
        None
    };
    Ok(ReplayPage {
        frames,
        replay_through: StreamCursor::At(through),
        next,
    })
}

fn next_after_cursor(cursor: StreamCursor) -> Result<Option<u64>, StoreError> {
    match cursor {
        StreamCursor::BeforeFirst => Ok(Some(0)),
        StreamCursor::At(value) => Ok(value.checked_add(1)),
    }
}

fn ensure_current_grant(
    conn: &Connection,
    machine_route: MachineRouteId,
    device_route: DeviceRouteId,
    grant_serial: GrantSerial,
    allow_revoked: bool,
) -> Result<bool, StoreError> {
    let row = conn
        .query_row(
            "SELECT grant_serial, tombstone FROM device_grants
             WHERE machine_route = ?1 AND device_route = ?2",
            params![
                machine_route.as_bytes().as_slice(),
                device_route.as_bytes().as_slice(),
            ],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()?
        .ok_or(StoreError::GrantNotFound)?;
    let stored_serial = monotonic_from_blob(row.0, "device_grants.grant_serial")?;
    if stored_serial != grant_serial.value() {
        return Err(StoreError::GrantNotFound);
    }
    let revoked = row.1 != 0;
    if revoked && !allow_revoked {
        return Err(StoreError::Revoked);
    }
    Ok(revoked)
}

pub(crate) fn revoke(
    conn: &mut Connection,
    config: &RelayV2StoreConfig,
    request: PersistRevocation,
) -> Result<RevocationCommit, StoreError> {
    if request.signed_revocation_blob.is_empty()
        || request.signed_revocation_blob.len() > MAX_CONTROL_BLOB_BYTES
    {
        return Err(StoreError::InvalidValue {
            field: "revocation.signed_blob",
            reason: "signed revocation blob must contain 1...65536 bytes",
        });
    }
    let now = sql_i64(config.clock.now_ms()?, "revocations.committed_at")?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let (root_key_id, trust_epoch) =
        load_active_machine_trust(&tx, request.revocation.machine_route)?;
    if root_key_id != request.revocation.root_key_id
        || trust_epoch != request.revocation.trust_epoch
    {
        return Err(StoreError::MonotonicRollback {
            field: "revocation_trust",
        });
    }
    let already_revoked = ensure_current_grant(
        &tx,
        request.revocation.machine_route,
        request.revocation.device_route,
        request.revocation.grant_serial,
        true,
    )?;
    let existing = tx
        .query_row(
            "SELECT revocation_hash, signed_revocation_blob FROM revocations
             WHERE machine_route = ?1 AND device_route = ?2 AND grant_serial = ?3",
            params![
                request.revocation.machine_route.as_bytes().as_slice(),
                request.revocation.device_route.as_bytes().as_slice(),
                monotonic_blob(request.revocation.grant_serial.value()).as_slice(),
            ],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )
        .optional()?;
    if let Some((hash, blob)) = existing {
        if array_from_blob::<32>(hash, "revocations.revocation_hash")? != request.revocation_hash
            || blob != request.signed_revocation_blob
        {
            return Err(StoreError::IdempotencyConflict {
                field: "grant_serial",
            });
        }
        tx.commit()?;
        return Ok(RevocationCommit {
            device_route: request.revocation.device_route,
            grant_serial: request.revocation.grant_serial,
            revocation_hash: request.revocation_hash,
            signed_revocation_blob: request.signed_revocation_blob,
            duplicate: true,
        });
    }
    if already_revoked {
        return Err(StoreError::UnknownOrCorruptSchema);
    }
    tx.execute(
        "INSERT INTO revocations(
            machine_route, device_route, grant_serial, revocation_hash,
            signed_revocation_blob, committed_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            request.revocation.machine_route.as_bytes().as_slice(),
            request.revocation.device_route.as_bytes().as_slice(),
            monotonic_blob(request.revocation.grant_serial.value()).as_slice(),
            request.revocation_hash.as_slice(),
            request.signed_revocation_blob.as_slice(),
            now,
        ],
    )?;
    tx.execute(
        "UPDATE device_grants SET revoked_at = ?3, tombstone = 1
         WHERE machine_route = ?1 AND device_route = ?2",
        params![
            request.revocation.machine_route.as_bytes().as_slice(),
            request.revocation.device_route.as_bytes().as_slice(),
            now,
        ],
    )?;
    tx.execute(
        "DELETE FROM subscriptions
         WHERE machine_route = ?1 AND device_route = ?2 AND grant_serial = ?3",
        params![
            request.revocation.machine_route.as_bytes().as_slice(),
            request.revocation.device_route.as_bytes().as_slice(),
            monotonic_blob(request.revocation.grant_serial.value()).as_slice(),
        ],
    )?;
    trim_fully_acked_prefixes(&tx)?;
    recompute_stream_stats(&tx)?;
    config
        .fault_injector
        .check(FaultPoint::RevokeBeforeCommit)?;
    tx.commit()?;
    Ok(RevocationCommit {
        device_route: request.revocation.device_route,
        grant_serial: request.revocation.grant_serial,
        revocation_hash: request.revocation_hash,
        signed_revocation_blob: request.signed_revocation_blob,
        duplicate: false,
    })
}

pub(crate) fn run_maintenance(
    conn: &mut Connection,
    config: &RelayV2StoreConfig,
) -> Result<MaintenanceReport, StoreError> {
    let now_ms = config.clock.now_ms()?;
    let now = sql_i64(now_ms, "maintenance.now")?;
    let cutoff = sql_i64(
        now_ms.saturating_sub(config.retention.max_age_ms),
        "frames.received_at",
    )?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let expired_frames =
        u64::try_from(tx.execute("DELETE FROM frames WHERE received_at < ?1", params![cutoff])?)
            .map_err(|_| StoreError::InvalidValue {
                field: "maintenance.expired_frames",
                reason: "deleted frame count does not fit u64",
            })?;
    let expired_enrollment_codes = u64::try_from(tx.execute(
        "DELETE FROM enrollment_codes WHERE expires_at < ?1",
        params![now],
    )?)
    .map_err(|_| StoreError::InvalidValue {
        field: "maintenance.expired_enrollment_codes",
        reason: "deleted enrollment count does not fit u64",
    })?;
    let ack_trimmed_frames = trim_fully_acked_prefixes(&tx)?;
    let quota_evicted_frames = enforce_all_capacity_limits(&tx, config)?;
    recompute_stream_stats(&tx)?;
    config
        .fault_injector
        .check(FaultPoint::MaintenanceBeforeCommit)?;
    tx.commit()?;
    Ok(MaintenanceReport {
        expired_frames,
        expired_enrollment_codes,
        ack_trimmed_frames,
        quota_evicted_frames,
    })
}

fn run_replay_maintenance(
    conn: &mut Connection,
    config: &RelayV2StoreConfig,
    stream_route: StreamRouteId,
    generation: StreamGenerationId,
) -> Result<(), StoreError> {
    let now_ms = config.clock.now_ms()?;
    let cutoff = sql_i64(
        now_ms.saturating_sub(config.retention.max_age_ms),
        "frames.received_at",
    )?;
    let has_expired = conn
        .query_row(
            "SELECT 1 FROM frames
             WHERE stream_route = ?1 AND generation = ?2 AND received_at < ?3
             LIMIT 1",
            params![
                stream_route.as_bytes().as_slice(),
                generation.as_bytes().as_slice(),
                cutoff,
            ],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if !has_expired {
        return Ok(());
    }
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    tx.execute(
        "DELETE FROM frames
         WHERE stream_route = ?1 AND generation = ?2 AND received_at < ?3",
        params![
            stream_route.as_bytes().as_slice(),
            generation.as_bytes().as_slice(),
            cutoff,
        ],
    )?;
    recompute_one_stream_stats(&tx, stream_route, generation)?;
    tx.commit()?;
    Ok(())
}

pub(crate) fn purge_machine(
    conn: &mut Connection,
    config: &RelayV2StoreConfig,
    request: PurgeMachine,
) -> Result<PurgeReadback, StoreError> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let exists = tx
        .query_row(
            "SELECT 1 FROM machine_routes WHERE machine_route = ?1",
            params![request.machine_route.as_bytes().as_slice()],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if !exists {
        tx.commit()?;
        return Ok(PurgeReadback::default());
    }
    let stream_routes = {
        let mut statement = tx.prepare(
            "SELECT stream_route FROM streams WHERE machine_route = ?1 ORDER BY stream_route",
        )?;
        let rows = statement.query_map(
            params![request.machine_route.as_bytes().as_slice()],
            |row| row.get::<_, Vec<u8>>(0),
        )?;
        let mut routes = Vec::new();
        for row in rows {
            routes.push(row?);
        }
        routes
    };
    tx.execute(
        "DELETE FROM subscriptions WHERE machine_route = ?1",
        params![request.machine_route.as_bytes().as_slice()],
    )?;
    tx.execute(
        "DELETE FROM revocations WHERE machine_route = ?1",
        params![request.machine_route.as_bytes().as_slice()],
    )?;
    tx.execute(
        "DELETE FROM device_grants WHERE machine_route = ?1",
        params![request.machine_route.as_bytes().as_slice()],
    )?;
    tx.execute(
        "DELETE FROM streams WHERE machine_route = ?1",
        params![request.machine_route.as_bytes().as_slice()],
    )?;
    tx.execute(
        "UPDATE machine_routes SET
            root_pubkey = zeroblob(32), highest_link_generation = zeroblob(8),
            link_cert_hash = zeroblob(32), data_cert_hash = zeroblob(32), status = 'retired'
         WHERE machine_route = ?1",
        params![request.machine_route.as_bytes().as_slice()],
    )?;
    config.fault_injector.check(FaultPoint::PurgeBeforeCommit)?;
    let active_machine_routes = scoped_count(
        &tx,
        "SELECT COUNT(*) FROM machine_routes WHERE machine_route = ?1 AND status = 'active'",
        request.machine_route,
        "purge.active_machine_routes",
    )?;
    let retired_tombstones = scoped_count(
        &tx,
        "SELECT COUNT(*) FROM machine_routes WHERE machine_route = ?1 AND status = 'retired'",
        request.machine_route,
        "purge.retired_tombstones",
    )?;
    let device_grants = scoped_count(
        &tx,
        "SELECT COUNT(*) FROM device_grants WHERE machine_route = ?1",
        request.machine_route,
        "purge.device_grants",
    )?;
    let revocations = scoped_count(
        &tx,
        "SELECT COUNT(*) FROM revocations WHERE machine_route = ?1",
        request.machine_route,
        "purge.revocations",
    )?;
    let streams = scoped_count(
        &tx,
        "SELECT COUNT(*) FROM streams WHERE machine_route = ?1",
        request.machine_route,
        "purge.streams",
    )?;
    let mut frames = 0_u64;
    for stream_route in stream_routes {
        frames = frames
            .checked_add(query_u64(
                &tx,
                "SELECT COUNT(*) FROM frames WHERE stream_route = ?1",
                params![stream_route],
                "purge.frames",
            )?)
            .ok_or(StoreError::InvalidValue {
                field: "purge.frames",
                reason: "frame count overflow",
            })?;
    }
    let subscriptions = scoped_count(
        &tx,
        "SELECT COUNT(*) FROM subscriptions WHERE machine_route = ?1",
        request.machine_route,
        "purge.subscriptions",
    )?;
    tx.commit()?;
    Ok(PurgeReadback {
        active_machine_routes,
        retired_tombstones,
        device_grants,
        revocations,
        streams,
        frames,
        subscriptions,
    })
}

fn scoped_count(
    conn: &Connection,
    sql: &str,
    machine_route: MachineRouteId,
    field: &'static str,
) -> Result<u64, StoreError> {
    query_u64(
        conn,
        sql,
        params![machine_route.as_bytes().as_slice()],
        field,
    )
}

fn validate_machine_request(request: &RegisterMachine) -> Result<(), StoreError> {
    if request.link_cert.cert_role != CertRole::Link
        || request.data_cert.cert_role != CertRole::Data
        || request.link_cert.root_key_id != request.data_cert.root_key_id
        || request.link_cert.trust_epoch != request.data_cert.trust_epoch
    {
        return Err(StoreError::InvalidValue {
            field: "register_machine.certificates",
            reason: "link/data certificates must bind the same root and trust epoch",
        });
    }
    if request.response_blob.is_empty() || request.response_blob.len() > MAX_CONTROL_BLOB_BYTES {
        return Err(StoreError::InvalidValue {
            field: "register_machine.response_blob",
            reason: "frozen enrollment response must contain 1...65536 bytes",
        });
    }
    Ok(())
}

fn load_relay_server_id(tx: &rusqlite::Transaction<'_>) -> Result<RelayServerId, StoreError> {
    let blob = tx.query_row(
        "SELECT relay_server_id FROM relay_meta WHERE singleton = 1",
        [],
        |row| row.get::<_, Vec<u8>>(0),
    )?;
    Ok(RelayServerId::from_bytes(array_from_blob::<16>(
        blob,
        "relay_meta.relay_server_id",
    )?))
}

fn load_active_machine_trust(
    tx: &rusqlite::Transaction<'_>,
    machine_route: MachineRouteId,
) -> Result<(RootKeyId, TrustEpoch), StoreError> {
    let row = tx
        .query_row(
            "SELECT root_key_id, trust_epoch, status FROM machine_routes WHERE machine_route = ?1",
            params![machine_route.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .optional()?
        .ok_or(StoreError::MachineNotFound)?;
    if row.2 != "active" {
        return Err(StoreError::MachineNotFound);
    }
    Ok((
        RootKeyId::from_bytes(array_from_blob::<16>(row.0, "machine_routes.root_key_id")?),
        TrustEpoch::new(monotonic_from_blob(row.1, "machine_routes.trust_epoch")?),
    ))
}

fn load_machine_record(
    tx: &rusqlite::Transaction<'_>,
    machine_route: MachineRouteId,
    response_blob: Vec<u8>,
    receipt_hash: [u8; 32],
    duplicate: bool,
) -> Result<MachineRecord, StoreError> {
    let row = tx
        .query_row(
            "SELECT relay_server_id, root_key_id, trust_epoch, highest_link_generation, status
             FROM machine_routes WHERE machine_route = ?1",
            params![machine_route.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, String>(4)?,
                ))
            },
        )
        .optional()?
        .ok_or(StoreError::MachineNotFound)?;
    if row.4 != "active" {
        return Err(StoreError::MachineNotFound);
    }
    Ok(MachineRecord {
        relay_server_id: RelayServerId::from_bytes(array_from_blob::<16>(
            row.0,
            "machine_routes.relay_server_id",
        )?),
        machine_route,
        root_key_id: RootKeyId::from_bytes(array_from_blob::<16>(
            row.1,
            "machine_routes.root_key_id",
        )?),
        trust_epoch: TrustEpoch::new(monotonic_from_blob(row.2, "machine_routes.trust_epoch")?),
        highest_link_generation: LinkGeneration::new(monotonic_from_blob(
            row.3,
            "machine_routes.highest_link_generation",
        )?),
        response_blob,
        receipt_hash,
        duplicate,
    })
}

fn required_array<const N: usize>(
    value: Option<Vec<u8>>,
    field: &'static str,
) -> Result<[u8; N], StoreError> {
    array_from_blob(value.ok_or(StoreError::UnknownOrCorruptSchema)?, field)
}

fn array_from_blob<const N: usize>(
    value: Vec<u8>,
    field: &'static str,
) -> Result<[u8; N], StoreError> {
    value.try_into().map_err(|_| StoreError::InvalidValue {
        field,
        reason: "unexpected SQLite blob length",
    })
}

fn inspect_read_only(path: &Path, config: &RelayV2StoreConfig) -> Result<SchemaState, StoreError> {
    let parent = path.parent().ok_or(StoreError::InvalidValue {
        field: "storage_path",
        reason: "absolute database path must have a parent directory",
    })?;
    let source_wal = sqlite_sidecar(path, "-wal");
    if metadata_if_exists(&source_wal)?.is_none() {
        let flags = OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW
            | OpenFlags::SQLITE_OPEN_URI;
        let conn = Connection::open_with_flags(immutable_sqlite_uri(path)?, flags)?;
        return migrations::inspect(&conn).map_err(StoreError::from);
    }

    // SQLite immutable mode deliberately ignores WAL, so it cannot distinguish a
    // fresh main DB from a higher/legacy schema whose transaction lives only in a
    // hot WAL. Build a private 0700 view in the already-validated store directory:
    // CoW-clone the DB/WAL (separate inode without a multi-GiB copy), copy only SHM
    // because a reader may update its read marks, then inspect the snapshot path. On
    // filesystems without reflink support, fall back to a physical copy only after a
    // projected disk-reserve preflight. Source DB/WAL/SHM bytes remain exact.
    let source_before = sqlite_source_fingerprint(path)?;
    let source_shm = sqlite_sidecar(path, "-shm");
    let shm_bytes = source_before.shm.as_ref().map_or(0, |value| value.len);
    ensure_snapshot_copy_capacity(config, shm_bytes)?;
    let snapshot_dir = tempfile::Builder::new()
        .prefix(INSPECTION_DIRECTORY_PREFIX)
        .tempdir_in(parent)?;
    let _snapshot_lock = create_snapshot_marker(snapshot_dir.path(), path)?;
    let snapshot_db = snapshot_dir.path().join("relay.db");
    let snapshot_wal = sqlite_sidecar(&snapshot_db, "-wal");
    let database_cloned = try_clone_regular_file(path, &snapshot_db)?;
    let wal_cloned = try_clone_regular_file(&source_wal, &snapshot_wal)?;
    let database_copy_bytes = if database_cloned {
        0
    } else {
        source_before.database.len
    };
    let wal_copy_bytes = if wal_cloned {
        0
    } else {
        source_before.wal.as_ref().map_or(0, |value| value.len)
    };
    let physical_copy_bytes = database_copy_bytes
        .checked_add(wal_copy_bytes)
        .and_then(|value| value.checked_add(shm_bytes))
        .ok_or(StoreError::InvalidValue {
            field: "schema_snapshot.bytes",
            reason: "snapshot byte projection overflow",
        })?;
    ensure_snapshot_copy_capacity(config, physical_copy_bytes)?;
    if !database_cloned {
        copy_regular_file(path, &snapshot_db)?;
    }
    set_private_file_mode(&snapshot_db)?;
    if !wal_cloned {
        copy_regular_file(&source_wal, &snapshot_wal)?;
    }
    set_private_file_mode(&snapshot_wal)?;
    if source_before.shm.is_some() {
        let snapshot_shm = sqlite_sidecar(&snapshot_db, "-shm");
        copy_regular_file(&source_shm, &snapshot_shm)?;
        set_private_file_mode(&snapshot_shm)?;
    }

    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY
        | OpenFlags::SQLITE_OPEN_NO_MUTEX
        | OpenFlags::SQLITE_OPEN_NOFOLLOW;
    let conn = Connection::open_with_flags(&snapshot_db, flags)?;
    let source_after_copy = sqlite_source_fingerprint(path)?;
    if source_after_copy != source_before {
        return Err(StoreError::SchemaInspectionRaced);
    }
    let state = migrations::inspect(&conn).map_err(StoreError::from)?;
    if sqlite_source_fingerprint(path)? != source_before {
        return Err(StoreError::SchemaInspectionRaced);
    }
    Ok(state)
}

fn ensure_snapshot_copy_capacity(
    config: &RelayV2StoreConfig,
    physical_copy_bytes: u64,
) -> Result<(), StoreError> {
    if physical_copy_bytes == 0 {
        return Ok(());
    }
    let disk = config.disk_space_probe.space(&config.storage_path)?;
    let reserve = config.retention.disk_reserve_for(disk.total_bytes);
    if disk
        .available_bytes
        .checked_sub(physical_copy_bytes)
        .is_none_or(|remaining| remaining < reserve)
    {
        return Err(StoreError::DiskSpaceLow);
    }
    Ok(())
}

fn snapshot_marker_bytes(source_path: &Path) -> Vec<u8> {
    #[cfg(unix)]
    let digest = {
        use std::os::unix::ffi::OsStrExt;
        Sha256::digest(source_path.as_os_str().as_bytes())
    };
    #[cfg(not(unix))]
    let digest = Sha256::digest(source_path.to_string_lossy().as_bytes());

    let mut marker = Vec::with_capacity(INSPECTION_MARKER_MAGIC.len() + digest.len());
    marker.extend_from_slice(INSPECTION_MARKER_MAGIC);
    marker.extend_from_slice(&digest);
    marker
}

fn create_snapshot_marker(
    snapshot_directory: &Path,
    source_path: &Path,
) -> Result<File, StoreError> {
    let marker_path = snapshot_directory.join(INSPECTION_MARKER_NAME);
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(DATABASE_MODE).custom_flags(libc::O_NOFOLLOW);
    }
    let mut marker = options.open(marker_path)?;
    marker.lock_exclusive()?;
    marker.write_all(&snapshot_marker_bytes(source_path))?;
    marker.sync_all()?;
    #[cfg(unix)]
    File::open(snapshot_directory)?.sync_all()?;
    Ok(marker)
}

#[cfg(unix)]
fn cleanup_stale_schema_snapshots(parent: &Path, source_path: &Path) -> Result<(), StoreError> {
    use std::ffi::OsStr;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

    let expected_marker = snapshot_marker_bytes(source_path);
    for entry in fs::read_dir(parent)? {
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if !name.starts_with(INSPECTION_DIRECTORY_PREFIX) {
            continue;
        }
        let directory = entry.path();
        let directory_metadata = fs::symlink_metadata(&directory)?;
        // SAFETY: geteuid has no preconditions and only reads the process identity.
        let current_uid = unsafe { libc::geteuid() };
        if !directory_metadata.file_type().is_dir()
            || directory_metadata.file_type().is_symlink()
            || directory_metadata.uid() != current_uid
            || directory_metadata.permissions().mode() & 0o777 != DIRECTORY_MODE
        {
            continue;
        }

        let marker_path = directory.join(INSPECTION_MARKER_NAME);
        let mut marker_options = OpenOptions::new();
        marker_options
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW);
        let mut marker = match marker_options.open(&marker_path) {
            Ok(marker) => marker,
            Err(error) if error.kind() == ErrorKind::NotFound => continue,
            Err(error) => return Err(StoreError::Io(error)),
        };
        let marker_metadata = marker.metadata()?;
        if !marker_metadata.file_type().is_file()
            || marker_metadata.uid() != current_uid
            || marker_metadata.permissions().mode() & 0o777 != DATABASE_MODE
        {
            continue;
        }
        match marker.try_lock_exclusive() {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::WouldBlock => continue,
            Err(error) => return Err(StoreError::Io(error)),
        }
        let mut actual_marker = Vec::with_capacity(expected_marker.len() + 1);
        Read::by_ref(&mut marker)
            .take(u64::try_from(expected_marker.len() + 1).map_err(|_| {
                StoreError::InvalidValue {
                    field: "schema_snapshot.marker",
                    reason: "marker length does not fit u64",
                }
            })?)
            .read_to_end(&mut actual_marker)?;
        if actual_marker != expected_marker {
            continue;
        }

        let mut snapshot_files = Vec::new();
        let mut safe = true;
        for child in fs::read_dir(&directory)? {
            let child = child?;
            let child_name = child.file_name();
            if child_name == OsStr::new(INSPECTION_MARKER_NAME) {
                continue;
            }
            if !matches!(
                child_name.to_str(),
                Some("relay.db" | "relay.db-wal" | "relay.db-shm")
            ) {
                safe = false;
                break;
            }
            let child_path = child.path();
            let metadata = fs::symlink_metadata(&child_path)?;
            if !metadata.file_type().is_file()
                || metadata.file_type().is_symlink()
                || metadata.uid() != current_uid
                || metadata.permissions().mode() & 0o777 != DATABASE_MODE
            {
                safe = false;
                break;
            }
            snapshot_files.push(child_path);
        }
        if !safe {
            continue;
        }
        for snapshot_file in snapshot_files {
            fs::remove_file(snapshot_file)?;
        }
        fs::remove_file(&marker_path)?;
        drop(marker);
        fs::remove_dir(&directory)?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn cleanup_stale_schema_snapshots(_parent: &Path, _source_path: &Path) -> Result<(), StoreError> {
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileFingerprint {
    len: u64,
    modified: std::time::SystemTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SqliteSourceFingerprint {
    database: FileFingerprint,
    wal: Option<FileFingerprint>,
    shm: Option<FileFingerprint>,
}

fn sqlite_source_fingerprint(path: &Path) -> Result<SqliteSourceFingerprint, StoreError> {
    Ok(SqliteSourceFingerprint {
        database: file_fingerprint(path)?,
        wal: optional_file_fingerprint(&sqlite_sidecar(path, "-wal"))?,
        shm: optional_file_fingerprint(&sqlite_sidecar(path, "-shm"))?,
    })
}

fn optional_file_fingerprint(path: &Path) -> Result<Option<FileFingerprint>, StoreError> {
    metadata_if_exists(path)?
        .map(|_| file_fingerprint(path))
        .transpose()
}

fn file_fingerprint(path: &Path) -> Result<FileFingerprint, StoreError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(StoreError::NotRegularFile {
            path: path.to_path_buf(),
        });
    }
    Ok(FileFingerprint {
        len: metadata.len(),
        modified: metadata.modified()?,
    })
}

fn sqlite_sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

fn immutable_sqlite_uri(path: &Path) -> Result<String, StoreError> {
    #[cfg(unix)]
    let bytes: &[u8] = {
        use std::os::unix::ffi::OsStrExt;
        path.as_os_str().as_bytes()
    };
    #[cfg(not(unix))]
    let owned = path.to_string_lossy().into_owned();
    #[cfg(not(unix))]
    let bytes: &[u8] = owned.as_bytes();

    let mut encoded = String::with_capacity(bytes.len() + 32);
    for byte in bytes {
        match *byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'/' | b'-' | b'.' | b'_' | b'~' => {
                encoded.push(char::from(*byte));
            }
            value => {
                const HEX: &[u8; 16] = b"0123456789ABCDEF";
                encoded.push('%');
                encoded.push(char::from(HEX[usize::from(value >> 4)]));
                encoded.push(char::from(HEX[usize::from(value & 0x0f)]));
            }
        }
    }
    Ok(format!("file:{encoded}?mode=ro&immutable=1"))
}

fn copy_regular_file(source: &Path, destination: &Path) -> Result<(), StoreError> {
    let metadata = fs::symlink_metadata(source)?;
    if metadata.file_type().is_symlink() {
        return Err(StoreError::SymlinkRejected {
            path: source.to_path_buf(),
        });
    }
    if !metadata.file_type().is_file() {
        return Err(StoreError::NotRegularFile {
            path: source.to_path_buf(),
        });
    }
    fs::copy(source, destination)?;
    Ok(())
}

#[cfg(unix)]
fn set_private_file_mode(path: &Path) -> Result<(), StoreError> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(DATABASE_MODE))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_file_mode(_path: &Path) -> Result<(), StoreError> {
    Ok(())
}

fn validate_clone_source(source: &Path) -> Result<(), StoreError> {
    let metadata = fs::symlink_metadata(source)?;
    if metadata.file_type().is_symlink() {
        return Err(StoreError::SymlinkRejected {
            path: source.to_path_buf(),
        });
    }
    if !metadata.file_type().is_file() {
        return Err(StoreError::NotRegularFile {
            path: source.to_path_buf(),
        });
    }
    Ok(())
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn clone_unsupported(error: &std::io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(code) if code == libc::ENOTSUP || code == libc::EXDEV || code == libc::EINVAL
    )
}

#[cfg(target_os = "macos")]
fn try_clone_regular_file(source: &Path, destination: &Path) -> Result<bool, StoreError> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    validate_clone_source(source)?;
    let source_c =
        CString::new(source.as_os_str().as_bytes()).map_err(|_| StoreError::InvalidValue {
            field: "storage_path",
            reason: "path contains an embedded NUL byte",
        })?;
    let destination_c =
        CString::new(destination.as_os_str().as_bytes()).map_err(|_| StoreError::InvalidValue {
            field: "storage_path",
            reason: "path contains an embedded NUL byte",
        })?;
    // SAFETY: both C strings are NUL-terminated and remain alive for the call;
    // destination does not exist inside our private temporary directory.
    if unsafe { libc::clonefile(source_c.as_ptr(), destination_c.as_ptr(), 0) } == 0 {
        Ok(true)
    } else {
        let error = std::io::Error::last_os_error();
        if destination.exists() {
            fs::remove_file(destination)?;
        }
        if clone_unsupported(&error) {
            Ok(false)
        } else {
            Err(StoreError::Io(error))
        }
    }
}

#[cfg(target_os = "linux")]
fn try_clone_regular_file(source: &Path, destination: &Path) -> Result<bool, StoreError> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;

    validate_clone_source(source)?;
    let source_file = OpenOptions::new().read(true).open(source)?;
    let destination_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(DATABASE_MODE)
        .open(destination)?;
    // SAFETY: FICLONE receives two valid file descriptors that remain open for
    // the ioctl and creates a filesystem-managed copy-on-write clone.
    if unsafe {
        libc::ioctl(
            destination_file.as_raw_fd(),
            libc::FICLONE,
            source_file.as_raw_fd(),
        )
    } == 0
    {
        Ok(true)
    } else {
        let error = std::io::Error::last_os_error();
        drop(destination_file);
        drop(source_file);
        fs::remove_file(destination)?;
        if clone_unsupported(&error) || error.raw_os_error() == Some(libc::ENOTTY) {
            Ok(false)
        } else {
            Err(StoreError::Io(error))
        }
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn try_clone_regular_file(source: &Path, _destination: &Path) -> Result<bool, StoreError> {
    validate_clone_source(source)?;
    Ok(false)
}

fn require_supported_schema(state: SchemaState) -> Result<(), StoreError> {
    match state {
        SchemaState::Fresh | SchemaState::Current { .. } => Ok(()),
        state => Err(schema_state_error(state)),
    }
}

fn schema_state_error(state: SchemaState) -> StoreError {
    match state {
        SchemaState::Higher { found } => StoreError::SchemaTooNew {
            found,
            supported: SCHEMA_VERSION,
        },
        SchemaState::LegacyV1 => StoreError::LegacyV1ResetRequired,
        SchemaState::Fresh | SchemaState::Current { .. } | SchemaState::UnknownOrCorrupt => {
            StoreError::UnknownOrCorruptSchema
        }
    }
}

fn prepare_secure_path(path: &Path) -> Result<(), StoreError> {
    let parent = path.parent().ok_or(StoreError::InvalidValue {
        field: "storage_path",
        reason: "absolute database path must have a parent directory",
    })?;

    match metadata_if_exists(parent)? {
        Some(metadata) => validate_parent(parent, &metadata)?,
        None => create_private_directory(parent)?,
    }

    reject_symlink_components(parent)?;
    let parent_metadata = fs::symlink_metadata(parent)?;
    validate_parent(parent, &parent_metadata)?;

    match metadata_if_exists(path)? {
        Some(metadata) => validate_database(path, &metadata)?,
        None => create_private_database(path)?,
    }

    let database_metadata = fs::symlink_metadata(path)?;
    validate_database(path, &database_metadata)
}

fn metadata_if_exists(path: &Path) -> Result<Option<fs::Metadata>, StoreError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
        Err(error) => Err(StoreError::Io(error)),
    }
}

fn reject_symlink_components(path: &Path) -> Result<(), StoreError> {
    for component_path in path.ancestors() {
        match fs::symlink_metadata(component_path) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(StoreError::SymlinkRejected {
                    path: component_path.to_path_buf(),
                });
            }
            Ok(_) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => return Err(StoreError::Io(error)),
        }
    }
    Ok(())
}

fn validate_parent(path: &Path, metadata: &fs::Metadata) -> Result<(), StoreError> {
    if metadata.file_type().is_symlink() {
        return Err(StoreError::SymlinkRejected {
            path: path.to_path_buf(),
        });
    }
    if !metadata.file_type().is_dir() {
        return Err(StoreError::NotRegularFile {
            path: path.to_path_buf(),
        });
    }
    validate_owner(path, metadata)?;
    validate_mode(path, metadata, DIRECTORY_MODE)
}

fn validate_database(path: &Path, metadata: &fs::Metadata) -> Result<(), StoreError> {
    if metadata.file_type().is_symlink() {
        return Err(StoreError::SymlinkRejected {
            path: path.to_path_buf(),
        });
    }
    if !metadata.file_type().is_file() {
        return Err(StoreError::NotRegularFile {
            path: path.to_path_buf(),
        });
    }
    validate_owner(path, metadata)?;
    validate_mode(path, metadata, DATABASE_MODE)
}

#[cfg(unix)]
fn validate_owner(path: &Path, metadata: &fs::Metadata) -> Result<(), StoreError> {
    use std::os::unix::fs::MetadataExt;

    // SAFETY: geteuid has no preconditions and only reads the process identity.
    let expected = unsafe { libc::geteuid() };
    let actual = metadata.uid();
    if actual == expected {
        Ok(())
    } else {
        Err(StoreError::UnexpectedOwner {
            path: path.to_path_buf(),
            expected,
            actual,
        })
    }
}

#[cfg(not(unix))]
fn validate_owner(_path: &Path, _metadata: &fs::Metadata) -> Result<(), StoreError> {
    Ok(())
}

#[cfg(unix)]
fn validate_mode(path: &Path, metadata: &fs::Metadata, expected: u32) -> Result<(), StoreError> {
    use std::os::unix::fs::PermissionsExt;

    let actual = metadata.permissions().mode() & 0o777;
    if actual == expected {
        Ok(())
    } else {
        Err(StoreError::InsecurePermissions {
            path: path.to_path_buf(),
            expected,
            actual,
        })
    }
}

#[cfg(not(unix))]
fn validate_mode(_path: &Path, _metadata: &fs::Metadata, _expected: u32) -> Result<(), StoreError> {
    Ok(())
}

#[cfg(unix)]
fn create_private_directory(path: &Path) -> Result<(), StoreError> {
    use std::os::unix::fs::DirBuilderExt;

    let mut builder = fs::DirBuilder::new();
    builder.recursive(true).mode(DIRECTORY_MODE);
    builder.create(path)?;
    Ok(())
}

#[cfg(not(unix))]
fn create_private_directory(path: &Path) -> Result<(), StoreError> {
    fs::create_dir_all(path)?;
    Ok(())
}

#[cfg(unix)]
fn create_private_database(path: &Path) -> Result<(), StoreError> {
    use std::os::unix::fs::OpenOptionsExt;

    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(DATABASE_MODE)
        .open(path)?;
    Ok(())
}

#[cfg(not(unix))]
fn create_private_database(path: &Path) -> Result<(), StoreError> {
    OpenOptions::new().write(true).create_new(true).open(path)?;
    Ok(())
}

fn nonzero_relay_server_id() -> RelayServerId {
    loop {
        let relay_server_id = RelayServerId::random();
        if relay_server_id.as_bytes() != &[0_u8; 16] {
            return relay_server_id;
        }
    }
}

impl From<SchemaError> for StoreError {
    fn from(error: SchemaError) -> Self {
        match error {
            SchemaError::Sqlite(error) if sqlite_error_is_corrupt(&error) => {
                Self::UnknownOrCorruptSchema
            }
            SchemaError::Sqlite(error) => Self::Sqlite(error),
            SchemaError::SchemaTooNew { found, supported } => {
                Self::SchemaTooNew { found, supported }
            }
            SchemaError::LegacyV1ResetRequired => Self::LegacyV1ResetRequired,
            SchemaError::UnknownOrCorruptSchema => Self::UnknownOrCorruptSchema,
            SchemaError::PragmaMismatch {
                name,
                expected,
                actual,
            } => Self::PragmaMismatch {
                name,
                expected,
                actual,
            },
        }
    }
}

fn sqlite_error_is_corrupt(error: &rusqlite::Error) -> bool {
    matches!(
        error,
        rusqlite::Error::SqliteFailure(details, _)
            if matches!(
                details.code,
                rusqlite::ErrorCode::DatabaseCorrupt | rusqlite::ErrorCode::NotADatabase
            )
    )
}
