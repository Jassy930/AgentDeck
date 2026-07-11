//! Relay v2 SQLite schema marker、连接配置与启动迁移。

use std::collections::BTreeMap;
use std::time::Duration;

use agentdeck_protocol::relay_v2::RelayServerId;
use rusqlite::{Connection, TransactionBehavior, params};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const SCHEMA_FAMILY: &str = "agentdeck-relay-v2";
pub const SCHEMA_VERSION: u32 = 1;
pub const SCHEMA_SIGNATURE: [u8; 32] = [
    0x0a, 0x66, 0x67, 0x20, 0x39, 0x4a, 0xfd, 0x28, 0xd4, 0x7d, 0x43, 0x43, 0x90, 0x60, 0xa2, 0x08,
    0x9c, 0x2d, 0x3f, 0xdc, 0x6b, 0x63, 0x42, 0x27, 0x86, 0x14, 0x44, 0x5c, 0x55, 0xaf, 0x54, 0x23,
];

type RawSchemaMarker = (i64, String, i64, Vec<u8>, Vec<u8>);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PragmaReadback {
    pub journal_mode: String,
    pub synchronous: i64,
    pub foreign_keys: bool,
    pub busy_timeout_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchemaState {
    Fresh,
    Current { relay_server_id: RelayServerId },
    Higher { found: u32 },
    LegacyV1,
    UnknownOrCorrupt,
}

#[derive(Debug, Error)]
pub enum SchemaError {
    #[error("SQLite schema operation failed: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("relay schema version {found} is newer than supported version {supported}")]
    SchemaTooNew { found: u32, supported: u32 },
    #[error("legacy Relay v1 schema requires an explicit reset")]
    LegacyV1ResetRequired,
    #[error("unknown or corrupt relay schema")]
    UnknownOrCorruptSchema,
    #[error("SQLite pragma {name} read back {actual}, expected {expected}")]
    PragmaMismatch {
        name: &'static str,
        expected: String,
        actual: String,
    },
}

const SCHEMA_V1_DDL: &str = r#"
CREATE TABLE relay_meta (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    schema_family TEXT NOT NULL CHECK(schema_family = 'agentdeck-relay-v2'),
    schema_version INTEGER NOT NULL CHECK(schema_version = 1),
    schema_signature BLOB NOT NULL CHECK(typeof(schema_signature) = 'blob' AND length(schema_signature) = 32),
    relay_server_id BLOB NOT NULL UNIQUE CHECK(typeof(relay_server_id) = 'blob' AND length(relay_server_id) = 16)
);
CREATE TABLE machine_routes (
    machine_route BLOB NOT NULL PRIMARY KEY CHECK(typeof(machine_route) = 'blob' AND length(machine_route) = 16),
    relay_server_id BLOB NOT NULL CHECK(typeof(relay_server_id) = 'blob' AND length(relay_server_id) = 16),
    root_key_id BLOB NOT NULL CHECK(typeof(root_key_id) = 'blob' AND length(root_key_id) = 16),
    root_pubkey BLOB NOT NULL CHECK(typeof(root_pubkey) = 'blob' AND length(root_pubkey) = 32),
    trust_epoch BLOB NOT NULL CHECK(typeof(trust_epoch) = 'blob' AND length(trust_epoch) = 8),
    highest_link_generation BLOB NOT NULL CHECK(typeof(highest_link_generation) = 'blob' AND length(highest_link_generation) = 8),
    link_cert_hash BLOB NOT NULL CHECK(typeof(link_cert_hash) = 'blob' AND length(link_cert_hash) = 32),
    data_cert_hash BLOB NOT NULL CHECK(typeof(data_cert_hash) = 'blob' AND length(data_cert_hash) = 32),
    retirement_hash BLOB CHECK(retirement_hash IS NULL OR (typeof(retirement_hash) = 'blob' AND length(retirement_hash) = 32)),
    retirement_terminal_blob BLOB CHECK(
        retirement_terminal_blob IS NULL
        OR (typeof(retirement_terminal_blob) = 'blob' AND length(retirement_terminal_blob) BETWEEN 1 AND 4096)
    ),
    status TEXT NOT NULL CHECK(status IN ('active', 'retired')),
    CHECK(
        (status = 'active' AND retirement_hash IS NULL AND retirement_terminal_blob IS NULL)
        OR
        (status = 'retired' AND (
            (retirement_hash IS NULL AND retirement_terminal_blob IS NULL)
            OR (retirement_hash IS NOT NULL AND retirement_terminal_blob IS NOT NULL)
        ))
    ),
    FOREIGN KEY(relay_server_id) REFERENCES relay_meta(relay_server_id) ON UPDATE RESTRICT ON DELETE RESTRICT
);
CREATE INDEX idx_machine_routes_status ON machine_routes(status);
CREATE TABLE device_grants (
    machine_route BLOB NOT NULL CHECK(typeof(machine_route) = 'blob' AND length(machine_route) = 16),
    device_route BLOB NOT NULL CHECK(typeof(device_route) = 'blob' AND length(device_route) = 16),
    auth_pubkey BLOB NOT NULL CHECK(typeof(auth_pubkey) = 'blob' AND length(auth_pubkey) = 32),
    auth_fingerprint BLOB NOT NULL CHECK(typeof(auth_fingerprint) = 'blob' AND length(auth_fingerprint) = 32),
    grant_serial BLOB NOT NULL CHECK(typeof(grant_serial) = 'blob' AND length(grant_serial) = 8),
    grant_hash BLOB NOT NULL CHECK(typeof(grant_hash) = 'blob' AND length(grant_hash) = 32),
    revoked_at INTEGER CHECK(revoked_at IS NULL OR revoked_at >= 0),
    tombstone INTEGER NOT NULL DEFAULT 0 CHECK(tombstone IN (0, 1)),
    CHECK(
        (tombstone = 0 AND revoked_at IS NULL)
        OR (tombstone = 1 AND revoked_at IS NOT NULL)
    ),
    PRIMARY KEY(machine_route, device_route),
    UNIQUE(machine_route, device_route, grant_serial),
    FOREIGN KEY(machine_route) REFERENCES machine_routes(machine_route) ON UPDATE RESTRICT ON DELETE CASCADE
);
CREATE INDEX idx_device_grants_serial ON device_grants(machine_route, grant_serial);
CREATE INDEX idx_device_grants_tombstone ON device_grants(machine_route, tombstone, revoked_at);
CREATE TABLE revocations (
    machine_route BLOB NOT NULL CHECK(typeof(machine_route) = 'blob' AND length(machine_route) = 16),
    device_route BLOB NOT NULL CHECK(typeof(device_route) = 'blob' AND length(device_route) = 16),
    grant_serial BLOB NOT NULL CHECK(typeof(grant_serial) = 'blob' AND length(grant_serial) = 8),
    revocation_hash BLOB NOT NULL CHECK(typeof(revocation_hash) = 'blob' AND length(revocation_hash) = 32),
    signed_revocation_blob BLOB NOT NULL CHECK(
        typeof(signed_revocation_blob) = 'blob'
        AND length(signed_revocation_blob) BETWEEN 1 AND 65536
    ),
    committed_at INTEGER NOT NULL CHECK(committed_at >= 0),
    PRIMARY KEY(machine_route, device_route, grant_serial),
    FOREIGN KEY(machine_route) REFERENCES machine_routes(machine_route) ON UPDATE RESTRICT ON DELETE CASCADE
);
CREATE TRIGGER validate_revocation_principal
BEFORE INSERT ON revocations
WHEN NOT EXISTS (
    SELECT 1 FROM device_grants
    WHERE machine_route = NEW.machine_route
      AND device_route = NEW.device_route
      AND grant_serial = NEW.grant_serial
)
BEGIN
    SELECT RAISE(ABORT, 'revocation principal serial mismatch');
END;
CREATE TABLE streams (
    stream_route BLOB NOT NULL PRIMARY KEY CHECK(typeof(stream_route) = 'blob' AND length(stream_route) = 16),
    machine_route BLOB NOT NULL CHECK(typeof(machine_route) = 'blob' AND length(machine_route) = 16),
    generation BLOB NOT NULL UNIQUE CHECK(typeof(generation) = 'blob' AND length(generation) = 16),
    high_water_seq TEXT NOT NULL DEFAULT '-1' CHECK(
        high_water_seq = '-1'
        OR (
            typeof(high_water_seq) = 'text'
            AND length(high_water_seq) = 20
            AND high_water_seq NOT GLOB '*[^0-9]*'
            AND high_water_seq <= '18446744073709551615'
        )
    ),
    oldest_seq TEXT CHECK(
        oldest_seq IS NULL
        OR (
            typeof(oldest_seq) = 'text'
            AND length(oldest_seq) = 20
            AND oldest_seq NOT GLOB '*[^0-9]*'
            AND oldest_seq <= '18446744073709551615'
            AND high_water_seq != '-1'
            AND oldest_seq <= high_water_seq
        )
    ),
    retained_bytes INTEGER NOT NULL DEFAULT 0 CHECK(retained_bytes >= 0),
    CHECK(
        (oldest_seq IS NULL AND retained_bytes = 0)
        OR (oldest_seq IS NOT NULL AND retained_bytes > 0)
    ),
    UNIQUE(stream_route, generation),
    UNIQUE(stream_route, generation, machine_route),
    FOREIGN KEY(machine_route) REFERENCES machine_routes(machine_route) ON UPDATE RESTRICT ON DELETE CASCADE
);
CREATE INDEX idx_streams_machine ON streams(machine_route, stream_route, generation);
CREATE TABLE frames (
    stream_route BLOB NOT NULL CHECK(typeof(stream_route) = 'blob' AND length(stream_route) = 16),
    generation BLOB NOT NULL CHECK(typeof(generation) = 'blob' AND length(generation) = 16),
    stream_seq TEXT NOT NULL CHECK(
        typeof(stream_seq) = 'text'
        AND length(stream_seq) = 20
        AND stream_seq NOT GLOB '*[^0-9]*'
        AND stream_seq <= '18446744073709551615'
    ),
    frame_hash BLOB NOT NULL CHECK(typeof(frame_hash) = 'blob' AND length(frame_hash) = 32),
    sealed_blob BLOB NOT NULL CHECK(typeof(sealed_blob) = 'blob'),
    size INTEGER NOT NULL CHECK(size = length(sealed_blob) + 53 AND size <= 4194304),
    received_at INTEGER NOT NULL CHECK(received_at >= 0),
    PRIMARY KEY(stream_route, generation, stream_seq),
    FOREIGN KEY(stream_route, generation) REFERENCES streams(stream_route, generation) ON UPDATE RESTRICT ON DELETE CASCADE
);
CREATE INDEX idx_frames_retention ON frames(received_at, stream_route, generation, stream_seq);
CREATE TABLE subscriptions (
    machine_route BLOB NOT NULL CHECK(typeof(machine_route) = 'blob' AND length(machine_route) = 16),
    device_route BLOB NOT NULL CHECK(typeof(device_route) = 'blob' AND length(device_route) = 16),
    grant_serial BLOB NOT NULL CHECK(typeof(grant_serial) = 'blob' AND length(grant_serial) = 8),
    stream_route BLOB NOT NULL CHECK(typeof(stream_route) = 'blob' AND length(stream_route) = 16),
    stream_generation BLOB NOT NULL CHECK(typeof(stream_generation) = 'blob' AND length(stream_generation) = 16),
    start_cursor_seq TEXT CHECK(
        start_cursor_seq IS NULL
        OR (
            typeof(start_cursor_seq) = 'text'
            AND length(start_cursor_seq) = 20
            AND start_cursor_seq NOT GLOB '*[^0-9]*'
            AND start_cursor_seq <= '18446744073709551615'
        )
    ),
    ack TEXT CHECK(
        ack IS NULL
        OR (
            typeof(ack) = 'text'
            AND length(ack) = 20
            AND ack NOT GLOB '*[^0-9]*'
            AND ack <= '18446744073709551615'
        )
    ),
    updated_at INTEGER NOT NULL CHECK(updated_at >= 0),
    PRIMARY KEY(machine_route, device_route, grant_serial, stream_route, stream_generation),
    FOREIGN KEY(machine_route, device_route, grant_serial)
        REFERENCES device_grants(machine_route, device_route, grant_serial) ON UPDATE RESTRICT ON DELETE CASCADE,
    FOREIGN KEY(stream_route, stream_generation, machine_route)
        REFERENCES streams(stream_route, generation, machine_route) ON UPDATE RESTRICT ON DELETE CASCADE
);
CREATE INDEX idx_subscriptions_stream_ack ON subscriptions(stream_route, stream_generation, ack);
CREATE TABLE enrollment_codes (
    code_hash BLOB NOT NULL PRIMARY KEY CHECK(typeof(code_hash) = 'blob' AND length(code_hash) = 32),
    expires_at INTEGER NOT NULL CHECK(expires_at >= 0),
    consumed_at INTEGER CHECK(consumed_at IS NULL OR consumed_at >= 0),
    request_hash BLOB CHECK(request_hash IS NULL OR (typeof(request_hash) = 'blob' AND length(request_hash) = 32)),
    response_blob BLOB CHECK(
        response_blob IS NULL
        OR (typeof(response_blob) = 'blob' AND length(response_blob) BETWEEN 1 AND 65536)
    ),
    receipt_hash BLOB CHECK(receipt_hash IS NULL OR (typeof(receipt_hash) = 'blob' AND length(receipt_hash) = 32)),
    CHECK(consumed_at IS NULL OR consumed_at <= expires_at),
    CHECK(
        (consumed_at IS NULL AND request_hash IS NULL AND response_blob IS NULL AND receipt_hash IS NULL)
        OR
        (consumed_at IS NOT NULL AND request_hash IS NOT NULL AND response_blob IS NOT NULL AND receipt_hash IS NOT NULL)
    )
);
CREATE INDEX idx_enrollment_codes_expiry ON enrollment_codes(expires_at, consumed_at);
"#;

const LEGACY_V1_DDL: &str = r#"
CREATE TABLE accounts (
    account_id TEXT PRIMARY KEY,
    owner_sign_pubkey TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL
);
CREATE TABLE devices (
    device_id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(account_id),
    role TEXT NOT NULL CHECK (role IN ('machine', 'device')),
    credential_hash TEXT NOT NULL UNIQUE,
    sign_pubkey TEXT NOT NULL,
    box_pubkey TEXT NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0,
    created_at_ms INTEGER NOT NULL
);
CREATE INDEX idx_devices_credential_hash ON devices(credential_hash);
CREATE TABLE challenges (
    device_sign_pubkey TEXT PRIMARY KEY,
    nonce TEXT NOT NULL,
    expires_at_ms INTEGER NOT NULL
);
CREATE TABLE seq_high_water_marks (
    conversation_id TEXT PRIMARY KEY,
    next_seq INTEGER NOT NULL DEFAULT 0,
    acked_seq INTEGER NOT NULL DEFAULT -1
);
CREATE TABLE conv_events (
    conversation_id TEXT NOT NULL,
    seq INTEGER NOT NULL,
    turn_session_id TEXT NOT NULL,
    encryption_version INTEGER NOT NULL DEFAULT 0,
    payload BLOB,
    created_at_ms INTEGER NOT NULL,
    PRIMARY KEY (conversation_id, seq)
);
"#;

#[derive(Debug)]
struct SchemaMarker {
    family: String,
    version: u32,
    signature: [u8; 32],
    relay_server_id: RelayServerId,
}

/// 配置每个 Relay v2 SQLite 连接并立即读回验证。
///
/// 调用方必须先完成只读 schema inspection；`journal_mode=WAL` 会写数据库，不能在
/// higher/legacy/unknown schema 的拒绝路径上调用本函数。
pub fn configure_connection(conn: &Connection) -> Result<PragmaReadback, SchemaError> {
    conn.busy_timeout(Duration::from_millis(5_000))?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.pragma_update(None, "synchronous", "FULL")?;
    let _: String = conn.query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))?;

    let readback = read_pragmas(conn)?;
    ensure_pragma(
        readback.journal_mode.eq_ignore_ascii_case("wal"),
        "journal_mode",
        "wal",
        &readback.journal_mode,
    )?;
    ensure_pragma(
        readback.synchronous == 2,
        "synchronous",
        "2 (FULL)",
        &readback.synchronous.to_string(),
    )?;
    ensure_pragma(
        readback.foreign_keys,
        "foreign_keys",
        "1 (ON)",
        if readback.foreign_keys { "1" } else { "0" },
    )?;
    ensure_pragma(
        readback.busy_timeout_ms == 5_000,
        "busy_timeout",
        "5000",
        &readback.busy_timeout_ms.to_string(),
    )?;
    Ok(readback)
}

/// 只读识别当前连接指向的 schema；拒绝分支不执行任何 PRAGMA 写或 DDL。
pub fn inspect(conn: &Connection) -> Result<SchemaState, SchemaError> {
    ensure_schema_signature_bound()?;
    let user_version = read_user_version(conn)?;
    let objects = schema_objects(conn)?;

    if objects.is_empty() {
        return Ok(if user_version == 0 {
            SchemaState::Fresh
        } else {
            SchemaState::UnknownOrCorrupt
        });
    }

    if objects.contains_key(&("table".to_owned(), "relay_meta".to_owned())) {
        let Some(marker) = read_schema_marker(conn)? else {
            return Ok(SchemaState::UnknownOrCorrupt);
        };

        if marker.family != SCHEMA_FAMILY {
            return Ok(SchemaState::UnknownOrCorrupt);
        }
        if marker.version > SCHEMA_VERSION {
            return Ok(if user_version == marker.version {
                SchemaState::Higher {
                    found: marker.version,
                }
            } else {
                SchemaState::UnknownOrCorrupt
            });
        }
        if marker.version != SCHEMA_VERSION
            || user_version != SCHEMA_VERSION
            || marker.signature != SCHEMA_SIGNATURE
            || marker.relay_server_id.as_bytes() == &[0_u8; 16]
            || objects != reference_schema_objects(SCHEMA_V1_DDL)?
        {
            return Ok(SchemaState::UnknownOrCorrupt);
        }
        return Ok(SchemaState::Current {
            relay_server_id: marker.relay_server_id,
        });
    }

    if user_version == 1 && objects == reference_schema_objects(LEGACY_V1_DDL)? {
        return Ok(SchemaState::LegacyV1);
    }

    Ok(SchemaState::UnknownOrCorrupt)
}

fn ensure_schema_signature_bound() -> Result<(), SchemaError> {
    let computed = Sha256::digest(SCHEMA_V1_DDL.as_bytes());
    if computed.as_slice() == SCHEMA_SIGNATURE {
        Ok(())
    } else {
        Err(SchemaError::UnknownOrCorruptSchema)
    }
}

/// 对 fresh DB 原子创建 v1 schema；对 current DB 严格校验并返回持久 server id。
///
/// higher、精确 legacy v1、未知或损坏 schema 均 typed reject，且本函数在这些路径
/// 上不执行写操作。
pub fn migrate_or_validate(
    conn: &mut Connection,
    relay_server_id: RelayServerId,
) -> Result<RelayServerId, SchemaError> {
    match inspect(conn)? {
        SchemaState::Fresh => {
            let transaction = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            transaction.execute_batch(SCHEMA_V1_DDL)?;
            transaction.execute(
                "INSERT INTO relay_meta(
                    singleton, schema_family, schema_version, schema_signature, relay_server_id
                 ) VALUES (1, ?1, ?2, ?3, ?4)",
                params![
                    SCHEMA_FAMILY,
                    i64::from(SCHEMA_VERSION),
                    SCHEMA_SIGNATURE.as_slice(),
                    relay_server_id.as_bytes().as_slice(),
                ],
            )?;
            transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
            transaction.commit()?;

            match inspect(conn)? {
                SchemaState::Current {
                    relay_server_id: stored,
                } if stored == relay_server_id => Ok(stored),
                _ => Err(SchemaError::UnknownOrCorruptSchema),
            }
        }
        SchemaState::Current {
            relay_server_id: stored,
        } => Ok(stored),
        SchemaState::Higher { found } => Err(SchemaError::SchemaTooNew {
            found,
            supported: SCHEMA_VERSION,
        }),
        SchemaState::LegacyV1 => Err(SchemaError::LegacyV1ResetRequired),
        SchemaState::UnknownOrCorrupt => Err(SchemaError::UnknownOrCorruptSchema),
    }
}

fn read_pragmas(conn: &Connection) -> Result<PragmaReadback, rusqlite::Error> {
    let journal_mode =
        conn.pragma_query_value(None, "journal_mode", |row| row.get::<_, String>(0))?;
    let synchronous = conn.pragma_query_value(None, "synchronous", |row| row.get::<_, i64>(0))?;
    let foreign_keys =
        conn.pragma_query_value(None, "foreign_keys", |row| row.get::<_, i64>(0))? != 0;
    let busy_timeout = conn.pragma_query_value(None, "busy_timeout", |row| row.get::<_, i64>(0))?;
    let busy_timeout_ms = u64::try_from(busy_timeout)
        .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(0, busy_timeout))?;
    Ok(PragmaReadback {
        journal_mode,
        synchronous,
        foreign_keys,
        busy_timeout_ms,
    })
}

fn ensure_pragma(
    matches: bool,
    name: &'static str,
    expected: &str,
    actual: &str,
) -> Result<(), SchemaError> {
    if matches {
        Ok(())
    } else {
        Err(SchemaError::PragmaMismatch {
            name,
            expected: expected.to_owned(),
            actual: actual.to_owned(),
        })
    }
}

fn read_user_version(conn: &Connection) -> Result<u32, SchemaError> {
    let raw = conn.pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))?;
    u32::try_from(raw).map_err(|_| SchemaError::UnknownOrCorruptSchema)
}

fn read_schema_marker(conn: &Connection) -> Result<Option<SchemaMarker>, SchemaError> {
    let mut statement = match conn.prepare(
        "SELECT singleton, schema_family, schema_version, schema_signature, relay_server_id
         FROM relay_meta ORDER BY singleton LIMIT 2",
    ) {
        Ok(statement) => statement,
        Err(_) => return Ok(None),
    };
    let mut rows = match statement.query([]) {
        Ok(rows) => rows,
        Err(_) => return Ok(None),
    };
    let Some(row) = rows.next()? else {
        return Ok(None);
    };
    let decoded = (|| -> rusqlite::Result<RawSchemaMarker> {
        Ok((
            row.get(0)?,
            row.get(1)?,
            row.get(2)?,
            row.get(3)?,
            row.get(4)?,
        ))
    })();
    let Ok((singleton, family, version_raw, signature_raw, relay_server_id_raw)) = decoded else {
        return Ok(None);
    };
    if rows.next()?.is_some() || singleton != 1 {
        return Ok(None);
    }
    let Ok(version) = u32::try_from(version_raw) else {
        return Ok(None);
    };
    let Ok(signature) = <[u8; 32]>::try_from(signature_raw) else {
        return Ok(None);
    };
    let Ok(relay_server_id_bytes) = <[u8; 16]>::try_from(relay_server_id_raw) else {
        return Ok(None);
    };
    Ok(Some(SchemaMarker {
        family,
        version,
        signature,
        relay_server_id: RelayServerId::from_bytes(relay_server_id_bytes),
    }))
}

fn schema_objects(conn: &Connection) -> Result<BTreeMap<(String, String), String>, SchemaError> {
    let mut statement = conn.prepare(
        "SELECT type, name, sql
         FROM sqlite_schema
         WHERE name NOT LIKE 'sqlite_%' AND sql IS NOT NULL
         ORDER BY type, name",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
        ))
    })?;
    let mut objects = BTreeMap::new();
    for row in rows {
        let (kind, name, sql) = row?;
        if objects.insert((kind, name), normalize_sql(&sql)).is_some() {
            return Err(SchemaError::UnknownOrCorruptSchema);
        }
    }
    Ok(objects)
}

fn reference_schema_objects(ddl: &str) -> Result<BTreeMap<(String, String), String>, SchemaError> {
    let reference = Connection::open_in_memory()?;
    reference.execute_batch(ddl)?;
    schema_objects(&reference)
}

fn normalize_sql(sql: &str) -> String {
    // SQLite preserves the defining SQL but harmlessly varies keyword case and
    // whitespace around tokens. Canonicalize only unquoted tokens; quoted string
    // literals and identifiers remain byte-exact because their case/space can be
    // semantic (for example CHECK(status IN ('active', 'retired'))).
    let characters = sql.chars().collect::<Vec<_>>();
    let mut normalized = String::with_capacity(sql.len());
    let mut index = 0;
    let mut pending_space = false;
    while index < characters.len() {
        let character = characters[index];
        if character.is_ascii_whitespace() {
            pending_space = true;
            index += 1;
            continue;
        }

        if pending_space
            && normalized
                .chars()
                .next_back()
                .is_some_and(sql_token_character)
            && sql_token_character(character)
        {
            normalized.push(' ');
        }
        pending_space = false;

        match character {
            '\'' | '"' | '`' => {
                let quote = character;
                normalized.push(character);
                index += 1;
                while index < characters.len() {
                    let quoted = characters[index];
                    normalized.push(quoted);
                    index += 1;
                    if quoted == quote {
                        if index < characters.len() && characters[index] == quote {
                            normalized.push(characters[index]);
                            index += 1;
                        } else {
                            break;
                        }
                    }
                }
            }
            '[' => {
                normalized.push(character);
                index += 1;
                while index < characters.len() {
                    let quoted = characters[index];
                    normalized.push(quoted);
                    index += 1;
                    if quoted == ']' {
                        if index < characters.len() && characters[index] == ']' {
                            normalized.push(characters[index]);
                            index += 1;
                        } else {
                            break;
                        }
                    }
                }
            }
            _ => {
                normalized.extend(character.to_lowercase());
                index += 1;
            }
        }
    }
    normalized
}

fn sql_token_character(character: char) -> bool {
    character.is_alphanumeric() || matches!(character, '_' | '$')
}
