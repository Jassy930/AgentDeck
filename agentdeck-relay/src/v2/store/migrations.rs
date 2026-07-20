//! Relay v2 SQLite schema marker、连接配置与启动迁移。

use std::collections::BTreeMap;
use std::time::Duration;

use agentdeck_crypto::{
    ValidatedRelayReceiptSignerIdentityV1, ValidatedRelayReceiptVerifyKey,
    verify_relay_admin_purge_receipt,
};
use agentdeck_protocol::relay_v2::{
    MachineEnrollmentResponseV1, MachineRouteId, PublicKeyBytes,
    RelayAdminPurgeReceiptExpectationV1, RelayAdminPurgeReceiptV1, RelayReceiptKeyId,
    RelayReceiptVerifyKeyV1, RelayServerId, RootKeyId, TrustEpoch, enrollment_receipt_hash,
    purge_request_hash,
};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use sha2::{Digest, Sha256};
use thiserror::Error;

use super::model::retirement_terminal_is_canonical_and_bound;

pub const SCHEMA_FAMILY: &str = "agentdeck-relay-v2";
pub const SCHEMA_VERSION: u32 = 2;
const SCHEMA_V1_SIGNATURE: [u8; 32] = [
    0x0a, 0x66, 0x67, 0x20, 0x39, 0x4a, 0xfd, 0x28, 0xd4, 0x7d, 0x43, 0x43, 0x90, 0x60, 0xa2, 0x08,
    0x9c, 0x2d, 0x3f, 0xdc, 0x6b, 0x63, 0x42, 0x27, 0x86, 0x14, 0x44, 0x5c, 0x55, 0xaf, 0x54, 0x23,
];
pub const SCHEMA_SIGNATURE: [u8; 32] = [
    0xdc, 0x01, 0xdb, 0xdf, 0x24, 0x1d, 0x88, 0x3e, 0x18, 0x7f, 0xc0, 0x12, 0x17, 0x91, 0xfb, 0xfb,
    0x0f, 0x65, 0x44, 0xce, 0xe7, 0x5f, 0x2b, 0x6c, 0xed, 0x18, 0x88, 0x4d, 0xcb, 0x7b, 0x7f, 0x74,
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
    UpgradeableV1 {
        relay_server_id: RelayServerId,
    },
    Current {
        relay_server_id: RelayServerId,
        receipt_verify_key: RelayReceiptVerifyKeyV1,
    },
    Higher {
        found: u32,
    },
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

const SCHEMA_V2_DDL: &str = r#"
CREATE TABLE relay_meta (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    schema_family TEXT NOT NULL CHECK(schema_family = 'agentdeck-relay-v2'),
    schema_version INTEGER NOT NULL CHECK(schema_version = 2),
    schema_signature BLOB NOT NULL CHECK(typeof(schema_signature) = 'blob' AND length(schema_signature) = 32),
    relay_server_id BLOB NOT NULL UNIQUE CHECK(typeof(relay_server_id) = 'blob' AND length(relay_server_id) = 16),
    receipt_format_version INTEGER NOT NULL CHECK(receipt_format_version = 1),
    receipt_key_generation INTEGER NOT NULL CHECK(receipt_key_generation = 1),
    receipt_key_id BLOB NOT NULL CHECK(typeof(receipt_key_id) = 'blob' AND length(receipt_key_id) = 32),
    receipt_public_key BLOB NOT NULL CHECK(typeof(receipt_public_key) = 'blob' AND length(receipt_public_key) = 32)
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
    enrollment_binding_state TEXT NOT NULL CHECK(enrollment_binding_state IN ('bound', 'legacy_unbound')),
    enrollment_receipt_hash BLOB CHECK(
        enrollment_receipt_hash IS NULL
        OR (typeof(enrollment_receipt_hash) = 'blob' AND length(enrollment_receipt_hash) = 32)
    ),
    retirement_hash BLOB CHECK(retirement_hash IS NULL OR (typeof(retirement_hash) = 'blob' AND length(retirement_hash) = 32)),
    retirement_terminal_blob BLOB CHECK(
        retirement_terminal_blob IS NULL
        OR (typeof(retirement_terminal_blob) = 'blob' AND length(retirement_terminal_blob) BETWEEN 1 AND 4096)
    ),
    terminal_kind TEXT CHECK(terminal_kind IS NULL OR terminal_kind IN (
        'root_present_retirement', 'root_lost_admin_purge', 'legacy_admin_tombstone'
    )),
    admin_purge_request_hash BLOB CHECK(
        admin_purge_request_hash IS NULL
        OR (typeof(admin_purge_request_hash) = 'blob' AND length(admin_purge_request_hash) = 32)
    ),
    admin_purge_tombstone_hash BLOB CHECK(
        admin_purge_tombstone_hash IS NULL
        OR (typeof(admin_purge_tombstone_hash) = 'blob' AND length(admin_purge_tombstone_hash) = 32)
    ),
    admin_purge_receipt_hash BLOB CHECK(
        admin_purge_receipt_hash IS NULL
        OR (typeof(admin_purge_receipt_hash) = 'blob' AND length(admin_purge_receipt_hash) = 32)
    ),
    admin_purge_receipt_blob BLOB CHECK(
        admin_purge_receipt_blob IS NULL
        OR (typeof(admin_purge_receipt_blob) = 'blob' AND length(admin_purge_receipt_blob) BETWEEN 1 AND 65536)
    ),
    status TEXT NOT NULL CHECK(status IN ('active', 'retired')),
    CHECK(
        (enrollment_binding_state = 'bound' AND enrollment_receipt_hash IS NOT NULL)
        OR (enrollment_binding_state = 'legacy_unbound' AND enrollment_receipt_hash IS NULL)
    ),
    CHECK(
        (status = 'active'
            AND retirement_hash IS NULL AND retirement_terminal_blob IS NULL
            AND terminal_kind IS NULL
            AND admin_purge_request_hash IS NULL AND admin_purge_tombstone_hash IS NULL
            AND admin_purge_receipt_hash IS NULL AND admin_purge_receipt_blob IS NULL)
        OR
        (status = 'retired' AND terminal_kind = 'root_present_retirement'
            AND retirement_hash IS NOT NULL AND retirement_terminal_blob IS NOT NULL
            AND admin_purge_request_hash IS NULL AND admin_purge_tombstone_hash IS NULL
            AND admin_purge_receipt_hash IS NULL AND admin_purge_receipt_blob IS NULL)
        OR
        (status = 'retired' AND terminal_kind = 'legacy_admin_tombstone'
            AND retirement_hash IS NULL AND retirement_terminal_blob IS NULL
            AND admin_purge_request_hash IS NULL AND admin_purge_tombstone_hash IS NULL
            AND admin_purge_receipt_hash IS NULL AND admin_purge_receipt_blob IS NULL)
        OR
        (status = 'retired' AND terminal_kind = 'root_lost_admin_purge'
            AND enrollment_binding_state = 'bound'
            AND retirement_hash IS NULL AND retirement_terminal_blob IS NULL
            AND admin_purge_request_hash IS NOT NULL AND admin_purge_tombstone_hash IS NOT NULL
            AND admin_purge_receipt_hash IS NOT NULL AND admin_purge_receipt_blob IS NOT NULL)
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
            typeof(high_water_seq) = 'text' AND length(high_water_seq) = 20
            AND high_water_seq NOT GLOB '*[^0-9]*'
            AND high_water_seq <= '18446744073709551615'
        )
    ),
    oldest_seq TEXT CHECK(
        oldest_seq IS NULL
        OR (
            typeof(oldest_seq) = 'text' AND length(oldest_seq) = 20
            AND oldest_seq NOT GLOB '*[^0-9]*'
            AND oldest_seq <= '18446744073709551615'
            AND high_water_seq != '-1' AND oldest_seq <= high_water_seq
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
        typeof(stream_seq) = 'text' AND length(stream_seq) = 20
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
            typeof(start_cursor_seq) = 'text' AND length(start_cursor_seq) = 20
            AND start_cursor_seq NOT GLOB '*[^0-9]*'
            AND start_cursor_seq <= '18446744073709551615'
        )
    ),
    ack TEXT CHECK(
        ack IS NULL
        OR (
            typeof(ack) = 'text' AND length(ack) = 20
            AND ack NOT GLOB '*[^0-9]*' AND ack <= '18446744073709551615'
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
    machine_route BLOB CHECK(machine_route IS NULL OR (typeof(machine_route) = 'blob' AND length(machine_route) = 16)),
    CHECK(consumed_at IS NULL OR consumed_at <= expires_at),
    CHECK(
        (consumed_at IS NULL AND request_hash IS NULL AND response_blob IS NULL
            AND receipt_hash IS NULL AND machine_route IS NULL)
        OR
        (consumed_at IS NOT NULL AND request_hash IS NOT NULL AND response_blob IS NOT NULL
            AND receipt_hash IS NOT NULL AND machine_route IS NOT NULL)
    ),
    FOREIGN KEY(machine_route) REFERENCES machine_routes(machine_route) ON UPDATE RESTRICT ON DELETE CASCADE
);
CREATE INDEX idx_enrollment_codes_expiry ON enrollment_codes(expires_at, consumed_at);
CREATE UNIQUE INDEX idx_enrollment_codes_machine_route
    ON enrollment_codes(machine_route) WHERE machine_route IS NOT NULL;
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
        if marker.relay_server_id.as_bytes() == &[0_u8; 16] {
            return Ok(SchemaState::UnknownOrCorrupt);
        }
        if marker.version == 1 {
            return Ok(
                if user_version == 1
                    && marker.signature == SCHEMA_V1_SIGNATURE
                    && objects == reference_schema_objects(SCHEMA_V1_DDL)?
                {
                    validate_sqlite_integrity(conn)?;
                    validate_foreign_keys(conn)?;
                    audit_v1_enrollment_bindings(conn, marker.relay_server_id)?;
                    SchemaState::UpgradeableV1 {
                        relay_server_id: marker.relay_server_id,
                    }
                } else {
                    SchemaState::UnknownOrCorrupt
                },
            );
        }
        if marker.version != SCHEMA_VERSION
            || user_version != SCHEMA_VERSION
            || marker.signature != SCHEMA_SIGNATURE
            || objects != reference_schema_objects(SCHEMA_V2_DDL)?
        {
            return Ok(SchemaState::UnknownOrCorrupt);
        }
        let Some(receipt_verify_key) = read_receipt_verify_key(conn, marker.relay_server_id)?
        else {
            return Ok(SchemaState::UnknownOrCorrupt);
        };
        validate_v2_semantics(conn)?;
        return Ok(SchemaState::Current {
            relay_server_id: marker.relay_server_id,
            receipt_verify_key,
        });
    }

    if user_version == 1 && objects == reference_schema_objects(LEGACY_V1_DDL)? {
        return Ok(SchemaState::LegacyV1);
    }

    Ok(SchemaState::UnknownOrCorrupt)
}

fn ensure_schema_signature_bound() -> Result<(), SchemaError> {
    let v1 = Sha256::digest(SCHEMA_V1_DDL.as_bytes());
    let v2 = Sha256::digest(SCHEMA_V2_DDL.as_bytes());
    if v1.as_slice() == SCHEMA_V1_SIGNATURE && v2.as_slice() == SCHEMA_SIGNATURE {
        Ok(())
    } else {
        Err(SchemaError::UnknownOrCorruptSchema)
    }
}

/// 对 fresh DB 原子创建 v2 schema；对 exact v1 单次迁移；对 current v2 严格校验。
///
/// higher、精确 legacy v1、未知或损坏 schema 均 typed reject，且本函数在这些路径
/// 上不执行写操作。
pub fn migrate_or_validate(
    conn: &mut Connection,
    relay_server_id: RelayServerId,
    receipt_signer_identity: ValidatedRelayReceiptSignerIdentityV1,
) -> Result<RelayServerId, SchemaError> {
    match inspect(conn)? {
        SchemaState::Fresh => {
            let receipt_verify_key = expected_anchor(receipt_signer_identity, relay_server_id)?;
            let transaction = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            transaction.execute_batch(SCHEMA_V2_DDL)?;
            transaction.execute(
                "INSERT INTO relay_meta(
                    singleton, schema_family, schema_version, schema_signature, relay_server_id,
                    receipt_format_version, receipt_key_generation, receipt_key_id,
                    receipt_public_key
                 ) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    SCHEMA_FAMILY,
                    i64::from(SCHEMA_VERSION),
                    SCHEMA_SIGNATURE.as_slice(),
                    relay_server_id.as_bytes().as_slice(),
                    i64::from(receipt_verify_key.receipt_format_version),
                    i64::try_from(receipt_verify_key.key_generation)
                        .map_err(|_| SchemaError::UnknownOrCorruptSchema)?,
                    receipt_verify_key.key_id.as_bytes().as_slice(),
                    receipt_verify_key.public_key.0.as_slice(),
                ],
            )?;
            transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
            validate_v2_semantics(&transaction)?;
            transaction.commit()?;

            match inspect(conn)? {
                SchemaState::Current {
                    relay_server_id: stored,
                    receipt_verify_key: stored_key,
                } if stored == relay_server_id && stored_key == receipt_verify_key => Ok(stored),
                _ => Err(SchemaError::UnknownOrCorruptSchema),
            }
        }
        SchemaState::UpgradeableV1 {
            relay_server_id: stored,
        } => {
            let expected = expected_anchor(receipt_signer_identity, stored)?;
            migrate_v1_to_v2(conn, stored, &expected)?;
            match inspect(conn)? {
                SchemaState::Current {
                    relay_server_id,
                    receipt_verify_key,
                } if relay_server_id == stored && receipt_verify_key == expected => Ok(stored),
                _ => Err(SchemaError::UnknownOrCorruptSchema),
            }
        }
        SchemaState::Current {
            relay_server_id: stored,
            receipt_verify_key,
        } => {
            let expected = expected_anchor(receipt_signer_identity, stored)?;
            if receipt_verify_key == expected {
                Ok(stored)
            } else {
                Err(SchemaError::UnknownOrCorruptSchema)
            }
        }
        SchemaState::Higher { found } => Err(SchemaError::SchemaTooNew {
            found,
            supported: SCHEMA_VERSION,
        }),
        SchemaState::LegacyV1 => Err(SchemaError::LegacyV1ResetRequired),
        SchemaState::UnknownOrCorrupt => Err(SchemaError::UnknownOrCorruptSchema),
    }
}

fn expected_anchor(
    identity: ValidatedRelayReceiptSignerIdentityV1,
    relay_server_id: RelayServerId,
) -> Result<RelayReceiptVerifyKeyV1, SchemaError> {
    identity
        .bind_to_relay(relay_server_id)
        .map(|validated| validated.wire_anchor().clone())
        .map_err(|_| SchemaError::UnknownOrCorruptSchema)
}

fn migrate_v1_to_v2(
    conn: &mut Connection,
    relay_server_id: RelayServerId,
    receipt_verify_key: &RelayReceiptVerifyKeyV1,
) -> Result<(), SchemaError> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    validate_sqlite_integrity(&tx)?;
    validate_foreign_keys(&tx)?;
    audit_v1_enrollment_bindings(&tx, relay_server_id)?;

    tx.execute_batch(
        r#"
CREATE TEMP TABLE migration_relay_meta AS SELECT * FROM relay_meta;
CREATE TEMP TABLE migration_machine_routes AS SELECT * FROM machine_routes;
CREATE TEMP TABLE migration_device_grants AS SELECT * FROM device_grants;
CREATE TEMP TABLE migration_revocations AS SELECT * FROM revocations;
CREATE TEMP TABLE migration_streams AS SELECT * FROM streams;
CREATE TEMP TABLE migration_frames AS SELECT * FROM frames;
CREATE TEMP TABLE migration_subscriptions AS SELECT * FROM subscriptions;
CREATE TEMP TABLE migration_enrollment_codes AS SELECT * FROM enrollment_codes;
DROP TABLE subscriptions;
DROP TABLE frames;
DROP TABLE streams;
DROP TABLE revocations;
DROP TABLE device_grants;
DROP TABLE enrollment_codes;
DROP TABLE machine_routes;
DROP TABLE relay_meta;
"#,
    )?;
    tx.execute_batch(SCHEMA_V2_DDL)?;
    tx.execute(
        "INSERT INTO relay_meta(
            singleton, schema_family, schema_version, schema_signature, relay_server_id,
            receipt_format_version, receipt_key_generation, receipt_key_id, receipt_public_key
         ) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            SCHEMA_FAMILY,
            i64::from(SCHEMA_VERSION),
            SCHEMA_SIGNATURE.as_slice(),
            relay_server_id.as_bytes().as_slice(),
            i64::from(receipt_verify_key.receipt_format_version),
            i64::try_from(receipt_verify_key.key_generation)
                .map_err(|_| SchemaError::UnknownOrCorruptSchema)?,
            receipt_verify_key.key_id.as_bytes().as_slice(),
            receipt_verify_key.public_key.0.as_slice(),
        ],
    )?;
    tx.execute_batch(
        r#"
INSERT INTO machine_routes(
    machine_route, relay_server_id, root_key_id, root_pubkey, trust_epoch,
    highest_link_generation, link_cert_hash, data_cert_hash,
    enrollment_binding_state, enrollment_receipt_hash,
    retirement_hash, retirement_terminal_blob, terminal_kind,
    admin_purge_request_hash, admin_purge_tombstone_hash,
    admin_purge_receipt_hash, admin_purge_receipt_blob, status
)
SELECT machine_route, relay_server_id, root_key_id, root_pubkey, trust_epoch,
       highest_link_generation, link_cert_hash, data_cert_hash,
       'legacy_unbound', NULL,
       retirement_hash, retirement_terminal_blob,
       CASE
           WHEN status = 'active' THEN NULL
           WHEN retirement_hash IS NOT NULL THEN 'root_present_retirement'
           ELSE 'legacy_admin_tombstone'
       END,
       NULL, NULL, NULL, NULL, status
FROM migration_machine_routes;
INSERT INTO device_grants SELECT * FROM migration_device_grants;
INSERT INTO revocations SELECT * FROM migration_revocations;
INSERT INTO streams SELECT * FROM migration_streams;
INSERT INTO frames SELECT * FROM migration_frames;
INSERT INTO subscriptions SELECT * FROM migration_subscriptions;
INSERT INTO enrollment_codes(
    code_hash, expires_at, consumed_at, request_hash, response_blob, receipt_hash, machine_route
)
SELECT code_hash, expires_at, NULL, NULL, NULL, NULL, NULL
FROM migration_enrollment_codes WHERE consumed_at IS NULL;
"#,
    )?;
    backfill_v1_consumed_enrollments(&tx, relay_server_id)?;
    tx.execute_batch(
        r#"
DROP TABLE migration_subscriptions;
DROP TABLE migration_frames;
DROP TABLE migration_streams;
DROP TABLE migration_revocations;
DROP TABLE migration_device_grants;
DROP TABLE migration_enrollment_codes;
DROP TABLE migration_machine_routes;
DROP TABLE migration_relay_meta;
"#,
    )?;
    tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    validate_v2_semantics(&tx)?;
    tx.commit()?;
    Ok(())
}

fn audit_v1_enrollment_bindings(
    conn: &Connection,
    relay_server_id: RelayServerId,
) -> Result<(), SchemaError> {
    audit_root_present_retirement_terminals(conn)?;
    let mut statement = conn.prepare(
        "SELECT request_hash, response_blob, receipt_hash
         FROM enrollment_codes WHERE consumed_at IS NOT NULL ORDER BY code_hash",
    )?;
    let mut rows = statement.query([])?;
    let mut bound_routes = std::collections::BTreeSet::new();
    while let Some(row) = rows.next()? {
        let request_hash = array_from_blob::<32>(row.get(0)?)?;
        let response_blob = row.get::<_, Vec<u8>>(1)?;
        let receipt_hash = array_from_blob::<32>(row.get(2)?)?;
        let response = decode_and_validate_enrollment_response(
            conn,
            relay_server_id,
            request_hash,
            &response_blob,
            receipt_hash,
        )?;
        if !bound_routes.insert(*response.machine_route.as_bytes()) {
            return Err(SchemaError::UnknownOrCorruptSchema);
        }
    }
    Ok(())
}

fn backfill_v1_consumed_enrollments(
    tx: &Transaction<'_>,
    relay_server_id: RelayServerId,
) -> Result<(), SchemaError> {
    let mut statement = tx.prepare(
        "SELECT code_hash, expires_at, consumed_at, request_hash, response_blob, receipt_hash
         FROM migration_enrollment_codes WHERE consumed_at IS NOT NULL ORDER BY code_hash",
    )?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let code_hash = row.get::<_, Vec<u8>>(0)?;
        let expires_at = row.get::<_, i64>(1)?;
        let consumed_at = row.get::<_, i64>(2)?;
        let request_hash = array_from_blob::<32>(row.get(3)?)?;
        let response_blob = row.get::<_, Vec<u8>>(4)?;
        let receipt_hash = array_from_blob::<32>(row.get(5)?)?;
        let response = decode_and_validate_enrollment_response(
            tx,
            relay_server_id,
            request_hash,
            &response_blob,
            receipt_hash,
        )?;
        let changed = tx.execute(
            "UPDATE machine_routes
             SET enrollment_binding_state = 'bound', enrollment_receipt_hash = ?2
             WHERE machine_route = ?1 AND enrollment_binding_state = 'legacy_unbound'",
            params![
                response.machine_route.as_bytes().as_slice(),
                receipt_hash.as_slice()
            ],
        )?;
        if changed != 1 {
            return Err(SchemaError::UnknownOrCorruptSchema);
        }
        let status = tx.query_row(
            "SELECT status FROM machine_routes WHERE machine_route = ?1",
            params![response.machine_route.as_bytes().as_slice()],
            |row| row.get::<_, String>(0),
        )?;
        if status == "active" {
            tx.execute(
                "INSERT INTO enrollment_codes(
                    code_hash, expires_at, consumed_at, request_hash, response_blob,
                    receipt_hash, machine_route
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    code_hash,
                    expires_at,
                    consumed_at,
                    request_hash.as_slice(),
                    response_blob,
                    receipt_hash.as_slice(),
                    response.machine_route.as_bytes().as_slice(),
                ],
            )?;
        } else if status != "retired" {
            return Err(SchemaError::UnknownOrCorruptSchema);
        }
    }
    Ok(())
}

fn decode_and_validate_enrollment_response(
    conn: &Connection,
    relay_server_id: RelayServerId,
    request_hash: [u8; 32],
    response_blob: &[u8],
    receipt_hash: [u8; 32],
) -> Result<MachineEnrollmentResponseV1, SchemaError> {
    let response: MachineEnrollmentResponseV1 =
        serde_json::from_slice(response_blob).map_err(|_| SchemaError::UnknownOrCorruptSchema)?;
    let canonical =
        serde_json::to_vec(&response).map_err(|_| SchemaError::UnknownOrCorruptSchema)?;
    if canonical != response_blob
        || response.relay_server_id != relay_server_id
        || response.receipt_hash != receipt_hash
        || enrollment_receipt_hash(
            relay_server_id,
            response.machine_route,
            response.trust_epoch,
            request_hash,
        ) != receipt_hash
    {
        return Err(SchemaError::UnknownOrCorruptSchema);
    }
    let trust_epoch = conn
        .query_row(
            "SELECT trust_epoch FROM machine_routes WHERE machine_route = ?1",
            params![response.machine_route.as_bytes().as_slice()],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?
        .ok_or(SchemaError::UnknownOrCorruptSchema)?;
    if u64::from_be_bytes(array_from_blob::<8>(trust_epoch)?) != response.trust_epoch {
        return Err(SchemaError::UnknownOrCorruptSchema);
    }
    Ok(response)
}

fn validate_sqlite_integrity(conn: &Connection) -> Result<(), SchemaError> {
    let result = conn.query_row("PRAGMA integrity_check(1)", [], |row| {
        row.get::<_, String>(0)
    })?;
    if result == "ok" {
        Ok(())
    } else {
        Err(SchemaError::UnknownOrCorruptSchema)
    }
}

fn validate_foreign_keys(conn: &Connection) -> Result<(), SchemaError> {
    let mut statement = conn.prepare("PRAGMA foreign_key_check")?;
    if statement.query([])?.next()?.is_none() {
        Ok(())
    } else {
        Err(SchemaError::UnknownOrCorruptSchema)
    }
}

fn validate_v2_semantics(conn: &Connection) -> Result<(), SchemaError> {
    validate_sqlite_integrity(conn)?;
    validate_foreign_keys(conn)?;
    let invalid_machine = conn
        .query_row(
            "SELECT 1 FROM machine_routes AS m
             WHERE
                (m.status = 'active' AND m.enrollment_binding_state = 'bound' AND (
                    SELECT COUNT(*) FROM enrollment_codes AS e
                    WHERE e.machine_route = m.machine_route AND e.consumed_at IS NOT NULL
                      AND e.receipt_hash = m.enrollment_receipt_hash
                ) != 1)
                OR (m.status = 'active' AND m.enrollment_binding_state = 'legacy_unbound' AND (
                    SELECT COUNT(*) FROM enrollment_codes AS e
                    WHERE e.machine_route = m.machine_route
                ) != 0)
                OR (m.status = 'retired' AND (
                    SELECT COUNT(*) FROM enrollment_codes AS e
                    WHERE e.machine_route = m.machine_route
                ) != 0)
             LIMIT 1",
            [],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if invalid_machine {
        return Err(SchemaError::UnknownOrCorruptSchema);
    }
    let relay_server_id = read_schema_marker(conn)?
        .ok_or(SchemaError::UnknownOrCorruptSchema)?
        .relay_server_id;
    let mut statement = conn.prepare(
        "SELECT request_hash, response_blob, receipt_hash, machine_route
         FROM enrollment_codes WHERE consumed_at IS NOT NULL ORDER BY code_hash",
    )?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let request_hash = array_from_blob::<32>(row.get(0)?)?;
        let response_blob = row.get::<_, Vec<u8>>(1)?;
        let receipt_hash = array_from_blob::<32>(row.get(2)?)?;
        let stored_route = array_from_blob::<16>(row.get(3)?)?;
        let response = decode_and_validate_enrollment_response(
            conn,
            relay_server_id,
            request_hash,
            &response_blob,
            receipt_hash,
        )?;
        if response.machine_route != MachineRouteId::from_bytes(stored_route) {
            return Err(SchemaError::UnknownOrCorruptSchema);
        }
    }
    audit_root_present_retirement_terminals(conn)?;
    audit_v2_admin_purge_receipts(conn, relay_server_id)?;
    Ok(())
}

fn audit_root_present_retirement_terminals(conn: &Connection) -> Result<(), SchemaError> {
    let mut statement = conn.prepare(
        "SELECT machine_route, trust_epoch, retirement_hash, retirement_terminal_blob
         FROM machine_routes
         WHERE status = 'retired' AND retirement_hash IS NOT NULL
         ORDER BY machine_route",
    )?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let machine_route = MachineRouteId::from_bytes(array_from_blob::<16>(row.get(0)?)?);
        let trust_epoch = TrustEpoch::new(u64::from_be_bytes(array_from_blob::<8>(row.get(1)?)?));
        let retirement_hash = required_array_from_blob::<32>(row.get(2)?)?;
        let terminal_blob = row
            .get::<_, Option<Vec<u8>>>(3)?
            .ok_or(SchemaError::UnknownOrCorruptSchema)?;
        if !retirement_terminal_is_canonical_and_bound(
            machine_route,
            trust_epoch,
            retirement_hash,
            &terminal_blob,
        ) {
            return Err(SchemaError::UnknownOrCorruptSchema);
        }
    }
    Ok(())
}

/// `root_lost_admin_purge` 是唯一可作为 portable proof 的 terminal kind。启动时只信
/// `relay_meta` 中持久化的 verify anchor，并把 receipt 逐字段重新绑定到当前 row 与
/// 当前全库 readback；legacy admin tombstone 则必须保持无 signer-backed proof 材料。
fn audit_v2_admin_purge_receipts(
    conn: &Connection,
    relay_server_id: RelayServerId,
) -> Result<(), SchemaError> {
    let unsigned_portable_material = conn
        .query_row(
            "SELECT 1 FROM machine_routes
             WHERE (terminal_kind IS NULL OR terminal_kind <> 'root_lost_admin_purge')
               AND (admin_purge_request_hash IS NOT NULL
                    OR admin_purge_tombstone_hash IS NOT NULL
                    OR admin_purge_receipt_hash IS NOT NULL
                    OR admin_purge_receipt_blob IS NOT NULL)
             LIMIT 1",
            [],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if unsigned_portable_material {
        return Err(SchemaError::UnknownOrCorruptSchema);
    }

    let anchor = read_receipt_verify_key(conn, relay_server_id)?
        .ok_or(SchemaError::UnknownOrCorruptSchema)?;
    let verify_key = ValidatedRelayReceiptVerifyKey::new(anchor)
        .map_err(|_| SchemaError::UnknownOrCorruptSchema)?;
    let mut statement = conn.prepare(
        "SELECT machine_route, relay_server_id, root_key_id, root_pubkey, trust_epoch,
                enrollment_receipt_hash, retirement_hash, retirement_terminal_blob,
                admin_purge_request_hash, admin_purge_tombstone_hash,
                admin_purge_receipt_hash, admin_purge_receipt_blob
         FROM machine_routes
         WHERE status = 'retired' AND terminal_kind = 'root_lost_admin_purge'
         ORDER BY machine_route",
    )?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let machine_route = MachineRouteId::from_bytes(array_from_blob::<16>(row.get(0)?)?);
        let row_relay_server_id = RelayServerId::from_bytes(array_from_blob::<16>(row.get(1)?)?);
        let root_key_id = RootKeyId::from_bytes(array_from_blob::<16>(row.get(2)?)?);
        let root_pubkey = array_from_blob::<32>(row.get(3)?)?;
        let trust_epoch = TrustEpoch::new(u64::from_be_bytes(array_from_blob::<8>(row.get(4)?)?));
        let enrollment_receipt_hash = required_array_from_blob::<32>(row.get(5)?)?;
        let retirement_hash = row.get::<_, Option<Vec<u8>>>(6)?;
        let retirement_terminal_blob = row.get::<_, Option<Vec<u8>>>(7)?;
        let stored_request_hash = required_array_from_blob::<32>(row.get(8)?)?;
        let stored_tombstone_hash = required_array_from_blob::<32>(row.get(9)?)?;
        let stored_receipt_hash = required_array_from_blob::<32>(row.get(10)?)?;
        let receipt_blob = row
            .get::<_, Option<Vec<u8>>>(11)?
            .ok_or(SchemaError::UnknownOrCorruptSchema)?;
        if row_relay_server_id != relay_server_id
            || retirement_hash.is_some()
            || retirement_terminal_blob.is_some()
        {
            return Err(SchemaError::UnknownOrCorruptSchema);
        }

        let receipt: RelayAdminPurgeReceiptV1 = serde_json::from_slice(&receipt_blob)
            .map_err(|_| SchemaError::UnknownOrCorruptSchema)?;
        let canonical_blob =
            serde_json::to_vec(&receipt).map_err(|_| SchemaError::UnknownOrCorruptSchema)?;
        if canonical_blob != receipt_blob {
            return Err(SchemaError::UnknownOrCorruptSchema);
        }

        let root_fingerprint: [u8; 32] = Sha256::digest(root_pubkey).into();
        let expected_request_hash = purge_request_hash(machine_route, root_fingerprint)
            .map_err(|_| SchemaError::UnknownOrCorruptSchema)?;
        let expectation = RelayAdminPurgeReceiptExpectationV1 {
            relay_server_id,
            machine_route,
            root_key_id,
            root_fingerprint,
            trust_epoch,
            enrollment_receipt_hash,
            purge_request_hash: expected_request_hash,
        };
        verify_relay_admin_purge_receipt(&verify_key, &expectation, &receipt)
            .map_err(|_| SchemaError::UnknownOrCorruptSchema)?;
        let canonical_receipt_hash = receipt
            .canonical_sha256()
            .map_err(|_| SchemaError::UnknownOrCorruptSchema)?;
        if stored_request_hash != expected_request_hash
            || stored_request_hash != receipt.purge_request_hash
            || stored_tombstone_hash != receipt.tombstone_hash
            || stored_receipt_hash != canonical_receipt_hash
            || !admin_purge_descendants_are_zero(conn, machine_route)?
        {
            return Err(SchemaError::UnknownOrCorruptSchema);
        }
    }
    Ok(())
}

fn admin_purge_descendants_are_zero(
    conn: &Connection,
    machine_route: MachineRouteId,
) -> Result<bool, SchemaError> {
    let has_descendant = conn.query_row(
        "SELECT
            EXISTS(SELECT 1 FROM machine_routes
                   WHERE machine_route = ?1 AND status = 'active')
            OR EXISTS(SELECT 1 FROM enrollment_codes WHERE machine_route = ?1)
            OR EXISTS(SELECT 1 FROM device_grants WHERE machine_route = ?1)
            OR EXISTS(SELECT 1 FROM revocations WHERE machine_route = ?1)
            OR EXISTS(SELECT 1 FROM streams WHERE machine_route = ?1)
            OR EXISTS(SELECT 1 FROM subscriptions WHERE machine_route = ?1)
            OR EXISTS(
                SELECT 1 FROM frames AS f JOIN streams AS s
                  ON s.stream_route = f.stream_route AND s.generation = f.generation
                WHERE s.machine_route = ?1
            )",
        params![machine_route.as_bytes().as_slice()],
        |row| row.get::<_, bool>(0),
    )?;
    Ok(!has_descendant)
}

fn required_array_from_blob<const N: usize>(
    value: Option<Vec<u8>>,
) -> Result<[u8; N], SchemaError> {
    array_from_blob(value.ok_or(SchemaError::UnknownOrCorruptSchema)?)
}

fn array_from_blob<const N: usize>(value: Vec<u8>) -> Result<[u8; N], SchemaError> {
    value
        .try_into()
        .map_err(|_| SchemaError::UnknownOrCorruptSchema)
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

fn read_receipt_verify_key(
    conn: &Connection,
    relay_server_id: RelayServerId,
) -> Result<Option<RelayReceiptVerifyKeyV1>, SchemaError> {
    let raw = conn
        .query_row(
            "SELECT receipt_format_version, receipt_key_generation,
                    receipt_key_id, receipt_public_key
             FROM relay_meta WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                ))
            },
        )
        .optional()?;
    let Some((format_raw, generation_raw, key_id_raw, public_key_raw)) = raw else {
        return Ok(None);
    };
    let Ok(receipt_format_version) = u16::try_from(format_raw) else {
        return Ok(None);
    };
    let Ok(key_generation) = u64::try_from(generation_raw) else {
        return Ok(None);
    };
    let Ok(key_id) = <[u8; 32]>::try_from(key_id_raw) else {
        return Ok(None);
    };
    let Ok(public_key) = <[u8; 32]>::try_from(public_key_raw) else {
        return Ok(None);
    };
    let wire = RelayReceiptVerifyKeyV1 {
        receipt_format_version,
        relay_server_id,
        key_generation,
        key_id: RelayReceiptKeyId::from_bytes(key_id),
        public_key: PublicKeyBytes(public_key),
    };
    match ValidatedRelayReceiptVerifyKey::new(wire) {
        Ok(validated) => Ok(Some(validated.wire_anchor().clone())),
        Err(_) => Ok(None),
    }
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

#[cfg(test)]
mod schema_v2_tests {
    use std::ffi::OsString;
    use std::fs;
    use std::path::{Path, PathBuf};

    use agentdeck_crypto::{SigningKey, ValidatedRelayReceiptSignerIdentityV1};
    use agentdeck_protocol::relay_v2::frame::RetirementCommitted;
    use agentdeck_protocol::relay_v2::{
        MachineEnrollmentResponseV1, MachineRouteId, OpaqueRouteFrame, RELAY_PROTOCOL_VERSION,
        RelayFrameBody, TrustEpoch, encode,
    };
    use rusqlite::Connection;
    use tempfile::TempDir;

    use super::*;
    use crate::v2::store::{RelayStoreHandle, RelayV2StoreConfig, StoreError, sqlite};

    fn signer_identity(seed: u8) -> ValidatedRelayReceiptSignerIdentityV1 {
        ValidatedRelayReceiptSignerIdentityV1::from_signing_key(&SigningKey::from_seed(&[seed; 32]))
            .expect("valid receipt signer identity")
    }

    fn retirement_terminal(
        machine_route: MachineRouteId,
        trust_epoch: u64,
        retirement_hash: [u8; 32],
    ) -> Vec<u8> {
        encode(&OpaqueRouteFrame {
            version: RELAY_PROTOCOL_VERSION,
            body: RelayFrameBody::RetirementCommitted(RetirementCommitted {
                machine_route,
                trust_epoch: TrustEpoch::new(trust_epoch),
                retire_hash: retirement_hash,
            }),
        })
    }

    fn populate_v1_fixture(
        conn: &Connection,
        valid_response: bool,
    ) -> (RelayServerId, MachineRouteId) {
        conn.execute_batch(SCHEMA_V1_DDL)
            .expect("create exact v1 schema");
        let relay = RelayServerId::from_bytes([0x21; 16]);
        let route = MachineRouteId::from_bytes([0x22; 16]);
        conn.execute(
            "INSERT INTO relay_meta(
                singleton, schema_family, schema_version, schema_signature, relay_server_id
             ) VALUES (1, ?1, 1, ?2, ?3)",
            params![
                SCHEMA_FAMILY,
                SCHEMA_V1_SIGNATURE.as_slice(),
                relay.as_bytes().as_slice(),
            ],
        )
        .expect("insert v1 marker");
        conn.pragma_update(None, "user_version", 1)
            .expect("set v1 user version");
        conn.execute(
            "INSERT INTO machine_routes(
                machine_route, relay_server_id, root_key_id, root_pubkey, trust_epoch,
                highest_link_generation, link_cert_hash, data_cert_hash, status
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'active')",
            params![
                route.as_bytes().as_slice(),
                relay.as_bytes().as_slice(),
                [0x23_u8; 16].as_slice(),
                [0x24_u8; 32].as_slice(),
                1_u64.to_be_bytes().as_slice(),
                1_u64.to_be_bytes().as_slice(),
                [0x25_u8; 32].as_slice(),
                [0x26_u8; 32].as_slice(),
            ],
        )
        .expect("insert v1 machine");
        let request_hash = [0x27; 32];
        let receipt_hash = enrollment_receipt_hash(relay, route, 1, request_hash);
        let response = if valid_response {
            serde_json::to_vec(&MachineEnrollmentResponseV1 {
                relay_server_id: relay,
                machine_route: route,
                trust_epoch: 1,
                receipt_hash,
            })
            .expect("encode v1 response")
        } else {
            br#"{"relayServerId":"malformed"}"#.to_vec()
        };
        conn.execute(
            "INSERT INTO enrollment_codes(
                code_hash, expires_at, consumed_at, request_hash, response_blob, receipt_hash
             ) VALUES (?1, 100, 10, ?2, ?3, ?4)",
            params![
                [0x28_u8; 32].as_slice(),
                request_hash.as_slice(),
                response,
                receipt_hash.as_slice(),
            ],
        )
        .expect("insert v1 consumed enrollment");
        (relay, route)
    }

    fn v1_fixture(valid_response: bool) -> (Connection, RelayServerId, MachineRouteId) {
        let conn = Connection::open_in_memory().expect("open v1 fixture");
        let (relay, route) = populate_v1_fixture(&conn, valid_response);
        (conn, relay, route)
    }

    #[cfg(unix)]
    fn secure_v1_fixture_path(temp: &TempDir, file_name: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700))
            .expect("secure v1 fixture parent");
        temp.path().join(file_name)
    }

    #[cfg(unix)]
    fn secure_v1_fixture_database(path: &Path) {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .expect("secure v1 fixture database");
    }

    #[cfg(unix)]
    fn sidecar(path: &Path, suffix: &str) -> PathBuf {
        let mut value = path.as_os_str().to_os_string();
        value.push(suffix);
        PathBuf::from(value)
    }

    #[cfg(unix)]
    fn process_lock_path(path: &Path) -> PathBuf {
        let mut name = path
            .file_name()
            .expect("fixture database has a file name")
            .to_os_string();
        name.push(".agentdeck.lock");
        path.with_file_name(name)
    }

    #[cfg(unix)]
    fn directory_entries(path: &Path) -> Vec<OsString> {
        let mut entries = fs::read_dir(path)
            .expect("read fixture directory")
            .map(|entry| entry.expect("read fixture entry").file_name())
            .collect::<Vec<_>>();
        entries.sort();
        entries
    }

    #[cfg(unix)]
    #[derive(Debug, PartialEq, Eq)]
    struct SqliteArtifacts {
        database: Vec<u8>,
        wal: Option<Vec<u8>>,
        shm: Option<Vec<u8>>,
        directory_entries: Vec<OsString>,
    }

    #[cfg(unix)]
    fn sqlite_artifacts(path: &Path) -> SqliteArtifacts {
        SqliteArtifacts {
            database: fs::read(path).expect("read SQLite database"),
            wal: fs::read(sidecar(path, "-wal")).ok(),
            shm: fs::read(sidecar(path, "-shm")).ok(),
            directory_entries: directory_entries(path.parent().expect("database parent")),
        }
    }

    #[cfg(unix)]
    fn assert_production_open_rejected(config: &RelayV2StoreConfig) {
        match sqlite::open(config) {
            Ok((_conn, _lock)) => panic!("invalid v1 fixture must fail before RW open"),
            Err(error) => assert!(
                matches!(error, StoreError::UnknownOrCorruptSchema),
                "unexpected invalid v1 open error: {error:?}"
            ),
        }
    }

    fn read_v1_enrollment(conn: &Connection) -> (MachineEnrollmentResponseV1, [u8; 32], [u8; 32]) {
        let (response_blob, request_hash, receipt_hash) = conn
            .query_row(
                "SELECT response_blob, request_hash, receipt_hash
                 FROM enrollment_codes WHERE consumed_at IS NOT NULL",
                [],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                    ))
                },
            )
            .expect("read v1 consumed enrollment");
        (
            serde_json::from_slice(&response_blob).expect("decode v1 response"),
            request_hash.try_into().expect("request hash length"),
            receipt_hash.try_into().expect("receipt hash length"),
        )
    }

    fn write_v1_enrollment_response(
        conn: &Connection,
        response: &MachineEnrollmentResponseV1,
        receipt_hash: [u8; 32],
    ) {
        conn.execute(
            "UPDATE enrollment_codes SET response_blob = ?1, receipt_hash = ?2
             WHERE consumed_at IS NOT NULL",
            params![
                serde_json::to_vec(response).expect("encode v1 response"),
                receipt_hash.as_slice(),
            ],
        )
        .expect("rewrite v1 consumed enrollment");
    }

    fn assert_v1_migration_rejected_without_schema_rewrite(
        conn: &mut Connection,
        relay_server_id: RelayServerId,
    ) {
        let error = migrate_or_validate(
            conn,
            RelayServerId::from_bytes([0xff; 16]),
            signer_identity(0x41),
        )
        .expect_err("invalid v1 enrollment binding must fail migration");
        assert!(matches!(error, SchemaError::UnknownOrCorruptSchema));
        assert!(matches!(
            inspect(conn),
            Err(SchemaError::UnknownOrCorruptSchema)
        ));
        let marker = read_schema_marker(conn)
            .expect("read rejected v1 marker")
            .expect("rejected v1 marker remains present");
        assert_eq!(marker.family, SCHEMA_FAMILY);
        assert_eq!(marker.version, 1);
        assert_eq!(marker.signature, SCHEMA_V1_SIGNATURE);
        assert_eq!(marker.relay_server_id, relay_server_id);
        assert_eq!(
            schema_objects(conn).expect("read rejected v1 schema objects"),
            reference_schema_objects(SCHEMA_V1_DDL).expect("build exact v1 schema reference")
        );
        assert_eq!(
            conn.pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
                .expect("read rolled-back user version"),
            1
        );
    }

    #[test]
    fn schema_v2_exact_v1_migrates_once_and_binds_consumed_enrollment() {
        let (mut conn, relay, route) = v1_fixture(true);
        assert!(matches!(
            inspect(&conn).expect("inspect exact v1"),
            SchemaState::UpgradeableV1 { relay_server_id } if relay_server_id == relay
        ));
        let identity = signer_identity(0x41);
        assert_eq!(
            migrate_or_validate(&mut conn, RelayServerId::from_bytes([0xff; 16]), identity)
                .expect("migrate v1 exactly once"),
            relay
        );
        assert!(matches!(
            inspect(&conn).expect("inspect migrated v2"),
            SchemaState::Current { relay_server_id, .. } if relay_server_id == relay
        ));
        let binding: (String, Vec<u8>, Vec<u8>) = conn
            .query_row(
                "SELECT m.enrollment_binding_state, m.enrollment_receipt_hash, e.machine_route
                 FROM machine_routes AS m JOIN enrollment_codes AS e
                   ON e.machine_route = m.machine_route
                 WHERE m.machine_route = ?1",
                params![route.as_bytes().as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("read migrated binding");
        assert_eq!(binding.0, "bound");
        assert_eq!(binding.1.len(), 32);
        assert_eq!(binding.2, route.as_bytes().as_slice());

        migrate_or_validate(&mut conn, RelayServerId::from_bytes([0xee; 16]), identity)
            .expect("same identity reopen is exact current");
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM enrollment_codes", [], |row| row
                .get::<_, i64>(0))
                .expect("count enrollment after reopen"),
            1
        );
    }

    #[test]
    fn schema_v2_malformed_consumed_response_rolls_back_entire_migration() {
        let (mut conn, relay, _) = v1_fixture(false);
        assert_v1_migration_rejected_without_schema_rewrite(&mut conn, relay);
    }

    #[cfg(unix)]
    #[test]
    fn production_open_rejects_cold_malformed_v1_before_lock_or_sqlite_artifact_write() {
        let temp = TempDir::new().expect("tempdir");
        let path = secure_v1_fixture_path(&temp, "cold-invalid-v1.db");
        let conn = Connection::open(&path).expect("open cold v1 fixture");
        populate_v1_fixture(&conn, false);
        drop(conn);
        secure_v1_fixture_database(&path);

        let before_database = fs::read(&path).expect("read cold v1 database");
        let before_entries = directory_entries(temp.path());
        let wal = sidecar(&path, "-wal");
        let shm = sidecar(&path, "-shm");
        let lock = process_lock_path(&path);
        assert!(!wal.exists());
        assert!(!shm.exists());
        assert!(!lock.exists());

        assert_production_open_rejected(&RelayV2StoreConfig::new(
            path.clone(),
            signer_identity(0x41),
        ));

        assert_eq!(
            fs::read(&path).expect("read rejected cold v1 database"),
            before_database
        );
        assert_eq!(directory_entries(temp.path()), before_entries);
        assert!(!wal.exists());
        assert!(!shm.exists());
        assert!(!lock.exists());
    }

    #[cfg(unix)]
    #[test]
    fn production_open_rejects_misbound_v1_retirement_before_lock_with_zero_write() {
        for case in ["route", "epoch", "hash", "noncanonical", "invalid"] {
            let temp = TempDir::new().expect("tempdir");
            let path = secure_v1_fixture_path(&temp, &format!("retirement-{case}.db"));
            let conn = Connection::open(&path).expect("open v1 retirement fixture");
            let (_, route) = populate_v1_fixture(&conn, true);
            let retirement_hash = [0xa1; 32];
            let mut terminal = match case {
                "route" => {
                    retirement_terminal(MachineRouteId::from_bytes([0xa2; 16]), 1, retirement_hash)
                }
                "epoch" => retirement_terminal(route, 2, retirement_hash),
                "hash" => retirement_terminal(route, 1, [0xa3; 32]),
                "noncanonical" => retirement_terminal(route, 1, retirement_hash),
                "invalid" => vec![0xa4],
                _ => unreachable!(),
            };
            if case == "noncanonical" {
                terminal.push(0);
            }
            conn.execute(
                "UPDATE machine_routes
                 SET status = 'retired', retirement_hash = ?2, retirement_terminal_blob = ?3
                 WHERE machine_route = ?1",
                params![
                    route.as_bytes().as_slice(),
                    retirement_hash.as_slice(),
                    terminal,
                ],
            )
            .expect("write malformed v1 retirement fixture");
            drop(conn);
            secure_v1_fixture_database(&path);
            let lock = process_lock_path(&path);
            assert!(!lock.exists());
            let before = sqlite_artifacts(&path);

            assert_production_open_rejected(&RelayV2StoreConfig::new(
                path.clone(),
                signer_identity(0x41),
            ));

            assert_eq!(
                sqlite_artifacts(&path),
                before,
                "v1 retirement case: {case}"
            );
            assert!(!lock.exists());
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn production_open_rejects_cold_current_retirement_tamper_with_zero_write() {
        for case in ["route", "hash"] {
            let temp = TempDir::new().expect("tempdir");
            let path = secure_v1_fixture_path(&temp, &format!("current-retirement-{case}.db"));
            let conn = Connection::open(&path).expect("open current retirement fixture");
            let (_, route) = populate_v1_fixture(&conn, true);
            let retirement_hash = [0xb1; 32];
            let terminal = retirement_terminal(route, 1, retirement_hash);
            conn.execute(
                "UPDATE machine_routes
                 SET status = 'retired', retirement_hash = ?2, retirement_terminal_blob = ?3
                 WHERE machine_route = ?1",
                params![
                    route.as_bytes().as_slice(),
                    retirement_hash.as_slice(),
                    terminal,
                ],
            )
            .expect("write valid v1 retirement fixture");
            drop(conn);
            secure_v1_fixture_database(&path);
            let identity = signer_identity(0x41);
            let store = RelayStoreHandle::open(RelayV2StoreConfig::new(path.clone(), identity))
                .await
                .expect("migrate valid retirement fixture to current v2");
            store.shutdown().await.expect("shutdown migrated store");
            let lock = process_lock_path(&path);
            fs::remove_file(&lock).expect("remove successful-open lock artifact");

            let conn = Connection::open(&path).expect("open current tamper fixture");
            conn.pragma_update(None, "journal_mode", "DELETE")
                .expect("checkpoint current fixture");
            match case {
                "route" => {
                    let terminal = retirement_terminal(
                        MachineRouteId::from_bytes([0xb2; 16]),
                        1,
                        retirement_hash,
                    );
                    conn.execute(
                        "UPDATE machine_routes SET retirement_terminal_blob = ?2
                         WHERE machine_route = ?1",
                        params![route.as_bytes().as_slice(), terminal],
                    )
                    .expect("tamper current retirement route");
                }
                "hash" => {
                    conn.execute(
                        "UPDATE machine_routes SET retirement_hash = ?2 WHERE machine_route = ?1",
                        params![route.as_bytes().as_slice(), [0xb3_u8; 32].as_slice()],
                    )
                    .expect("tamper current retirement hash");
                }
                _ => unreachable!(),
            }
            drop(conn);
            assert!(!sidecar(&path, "-wal").exists());
            assert!(!sidecar(&path, "-shm").exists());
            let before = sqlite_artifacts(&path);

            assert_production_open_rejected(&RelayV2StoreConfig::new(path.clone(), identity));

            assert_eq!(
                sqlite_artifacts(&path),
                before,
                "current retirement case: {case}"
            );
            assert!(!lock.exists());
        }
    }

    #[cfg(unix)]
    #[test]
    fn production_open_rejects_hot_wal_noncanonical_v1_without_source_or_directory_write() {
        let temp = TempDir::new().expect("tempdir");
        let path = secure_v1_fixture_path(&temp, "hot-invalid-v1.db");
        let conn = Connection::open(&path).expect("open base v1 fixture");
        populate_v1_fixture(&conn, true);
        drop(conn);
        secure_v1_fixture_database(&path);

        let writer = Connection::open(&path).expect("open hot-WAL v1 writer");
        writer
            .pragma_update(None, "journal_mode", "WAL")
            .expect("enable hot-WAL v1 fixture");
        writer
            .pragma_update(None, "wal_autocheckpoint", 0)
            .expect("disable hot-WAL autocheckpoint");
        let mut response_blob = writer
            .query_row(
                "SELECT response_blob FROM enrollment_codes WHERE consumed_at IS NOT NULL",
                [],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .expect("read canonical hot-WAL response");
        response_blob.push(b' ');
        writer
            .execute(
                "UPDATE enrollment_codes SET response_blob = ?1 WHERE consumed_at IS NOT NULL",
                params![response_blob],
            )
            .expect("write noncanonical response only into hot WAL");

        let wal = sidecar(&path, "-wal");
        let shm = sidecar(&path, "-shm");
        let lock = process_lock_path(&path);
        let before_database = fs::read(&path).expect("read hot-WAL v1 database");
        let before_wal = fs::read(&wal).expect("read v1 WAL");
        let before_shm = fs::read(&shm).expect("read v1 SHM");
        let before_entries = directory_entries(temp.path());
        assert!(!lock.exists());

        assert_production_open_rejected(&RelayV2StoreConfig::new(
            path.clone(),
            signer_identity(0x41),
        ));

        assert_eq!(
            fs::read(&path).expect("read rejected hot-WAL database"),
            before_database
        );
        assert_eq!(fs::read(&wal).expect("read rejected WAL"), before_wal);
        assert_eq!(fs::read(&shm).expect("read rejected SHM"), before_shm);
        assert_eq!(directory_entries(temp.path()), before_entries);
        assert!(!lock.exists());
        drop(writer);
    }

    #[test]
    fn schema_v2_noncanonical_consumed_response_is_rejected_without_schema_rewrite() {
        let (mut conn, relay, _) = v1_fixture(true);
        let response_blob = conn
            .query_row(
                "SELECT response_blob FROM enrollment_codes WHERE consumed_at IS NOT NULL",
                [],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .expect("read canonical response");
        let mut noncanonical = response_blob;
        noncanonical.push(b' ');
        conn.execute(
            "UPDATE enrollment_codes SET response_blob = ?1 WHERE consumed_at IS NOT NULL",
            params![noncanonical],
        )
        .expect("write valid JSON with noncanonical whitespace");

        assert_v1_migration_rejected_without_schema_rewrite(&mut conn, relay);
    }

    #[test]
    fn schema_v2_route_epoch_and_receipt_mismatches_are_rejected_without_schema_rewrite() {
        for mismatch in ["route", "epoch", "receipt"] {
            let (mut conn, relay, route) = v1_fixture(true);
            let (mut response, request_hash, _) = read_v1_enrollment(&conn);
            let receipt_hash = match mismatch {
                "route" => {
                    response.machine_route = MachineRouteId::from_bytes([0x91; 16]);
                    enrollment_receipt_hash(
                        relay,
                        response.machine_route,
                        response.trust_epoch,
                        request_hash,
                    )
                }
                "epoch" => {
                    response.trust_epoch = 2;
                    enrollment_receipt_hash(relay, route, response.trust_epoch, request_hash)
                }
                "receipt" => [0x92; 32],
                _ => unreachable!(),
            };
            response.receipt_hash = receipt_hash;
            write_v1_enrollment_response(&conn, &response, receipt_hash);

            assert_v1_migration_rejected_without_schema_rewrite(&mut conn, relay);
        }
    }

    #[test]
    fn schema_v2_duplicate_consumed_route_is_rejected_without_schema_rewrite() {
        let (mut conn, relay, _) = v1_fixture(true);
        conn.execute(
            "INSERT INTO enrollment_codes(
                code_hash, expires_at, consumed_at, request_hash, response_blob, receipt_hash
             ) SELECT ?1, expires_at, consumed_at, request_hash, response_blob, receipt_hash
               FROM enrollment_codes WHERE consumed_at IS NOT NULL",
            params![[0x93_u8; 32].as_slice()],
        )
        .expect("insert duplicate consumed route fixture");

        assert_v1_migration_rejected_without_schema_rewrite(&mut conn, relay);
    }

    #[test]
    fn schema_v2_retired_consumed_binding_drops_replay_row_but_preserves_terminal_provenance() {
        let (mut conn, relay, route) = v1_fixture(true);
        let retirement_hash = [0x94_u8; 32];
        let retirement_terminal = retirement_terminal(route, 1, retirement_hash);
        conn.execute(
            "UPDATE machine_routes
             SET status = 'retired', retirement_hash = ?2, retirement_terminal_blob = ?3
             WHERE machine_route = ?1",
            params![
                route.as_bytes().as_slice(),
                retirement_hash.as_slice(),
                retirement_terminal.as_slice(),
            ],
        )
        .expect("retire v1 machine fixture");

        migrate_or_validate(
            &mut conn,
            RelayServerId::from_bytes([0xff; 16]),
            signer_identity(0x41),
        )
        .expect("migrate retired v1 machine");
        let readback: (String, String, i64, Vec<u8>, Vec<u8>, i64, i64) = conn
            .query_row(
                "SELECT enrollment_binding_state, terminal_kind,
                        enrollment_receipt_hash IS NOT NULL,
                        retirement_hash, retirement_terminal_blob,
                        (SELECT COUNT(*) FROM enrollment_codes),
                        (SELECT COUNT(*) FROM enrollment_codes WHERE code_hash = ?2)
                 FROM machine_routes WHERE machine_route = ?1",
                params![route.as_bytes().as_slice(), [0x28_u8; 32].as_slice()],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                    ))
                },
            )
            .expect("read migrated retired binding");
        assert_eq!(
            readback,
            (
                "bound".to_owned(),
                "root_present_retirement".to_owned(),
                1,
                retirement_hash.to_vec(),
                retirement_terminal,
                0,
                0,
            )
        );
        assert!(matches!(
            inspect(&conn).expect("inspect retired v2"),
            SchemaState::Current { relay_server_id, .. } if relay_server_id == relay
        ));
    }

    #[test]
    fn schema_v2_active_machine_without_consumed_binding_stays_legacy_unbound() {
        let (mut conn, relay, route) = v1_fixture(true);
        conn.execute(
            "UPDATE enrollment_codes
             SET consumed_at = NULL, request_hash = NULL, response_blob = NULL, receipt_hash = NULL",
            [],
        )
        .expect("convert consumed fixture into an unused code");

        migrate_or_validate(
            &mut conn,
            RelayServerId::from_bytes([0xff; 16]),
            signer_identity(0x41),
        )
        .expect("migrate legacy-unbound active machine");
        let readback: (String, i64, i64, i64) = conn
            .query_row(
                "SELECT enrollment_binding_state, enrollment_receipt_hash IS NULL,
                        (SELECT COUNT(*) FROM enrollment_codes WHERE machine_route = ?1),
                        (SELECT COUNT(*) FROM enrollment_codes WHERE machine_route IS NULL)
                 FROM machine_routes WHERE machine_route = ?1",
                params![route.as_bytes().as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .expect("read migrated legacy-unbound machine");
        assert_eq!(readback, ("legacy_unbound".to_owned(), 1, 0, 1));
        assert!(matches!(
            inspect(&conn).expect("inspect legacy-unbound v2"),
            SchemaState::Current { relay_server_id, .. } if relay_server_id == relay
        ));
    }
}
