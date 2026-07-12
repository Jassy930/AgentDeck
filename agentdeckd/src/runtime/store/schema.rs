//! Runtime SQLite schema v1 与只读识别标记。

use std::sync::OnceLock;

use sha2::{Digest, Sha256};

pub const RUNTIME_SCHEMA_FAMILY: &str = "agentdeck-runtime";
pub const RUNTIME_SCHEMA_VERSION: u32 = 1;
pub const RUNTIME_KEY_GENERATION: u32 = 1;
pub const EXPECTED_TABLES: [&str; 7] = [
    "commands",
    "conversations",
    "event_journal",
    "execution_fences",
    "execution_intents",
    "machine_enrollment_receipts",
    "runtime_meta",
];

pub fn schema_signature() -> [u8; 32] {
    static SIGNATURE: OnceLock<[u8; 32]> = OnceLock::new();
    *SIGNATURE.get_or_init(|| Sha256::digest(RUNTIME_DDL.as_bytes()).into())
}

pub const RUNTIME_DDL: &str = r#"
CREATE TABLE runtime_meta (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    schema_family TEXT NOT NULL CHECK(schema_family = 'agentdeck-runtime'),
    schema_version INTEGER NOT NULL CHECK(schema_version >= 1),
    schema_signature BLOB NOT NULL CHECK(typeof(schema_signature) = 'blob' AND length(schema_signature) = 32),
    database_id BLOB NOT NULL UNIQUE CHECK(typeof(database_id) = 'blob' AND length(database_id) = 16),
    key_generation INTEGER NOT NULL CHECK(key_generation BETWEEN 1 AND 4294967295),
    wrapped_key_bundle BLOB NOT NULL CHECK(typeof(wrapped_key_bundle) = 'blob' AND length(wrapped_key_bundle) = 112),
    catalog_high_water TEXT CHECK(
        catalog_high_water IS NULL OR (
            typeof(catalog_high_water) = 'text'
            AND length(catalog_high_water) = 20
            AND catalog_high_water NOT GLOB '*[^0-9]*'
            AND catalog_high_water <= '18446744073709551615'
        )
    )
);
CREATE TABLE conversations (
    conversation_id BLOB PRIMARY KEY CHECK(typeof(conversation_id) = 'blob' AND length(conversation_id) = 16),
    adapter_state_key BLOB NOT NULL UNIQUE CHECK(typeof(adapter_state_key) = 'blob' AND length(adapter_state_key) = 16),
    catalog_revision TEXT NOT NULL CHECK(
        typeof(catalog_revision) = 'text' AND length(catalog_revision) = 20
        AND catalog_revision NOT GLOB '*[^0-9]*'
        AND catalog_revision <= '18446744073709551615'
    ),
    command_high_water TEXT CHECK(
        command_high_water IS NULL OR (
            typeof(command_high_water) = 'text' AND length(command_high_water) = 20
            AND command_high_water NOT GLOB '*[^0-9]*'
            AND command_high_water <= '18446744073709551615'
        )
    ),
    event_high_water TEXT CHECK(
        event_high_water IS NULL OR (
            typeof(event_high_water) = 'text' AND length(event_high_water) = 20
            AND event_high_water NOT GLOB '*[^0-9]*'
            AND event_high_water <= '18446744073709551615'
        )
    ),
    lifecycle TEXT NOT NULL CHECK(lifecycle IN ('active', 'archived', 'recoveryBlocked')),
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= created_at_ms),
    sealed_descriptor BLOB NOT NULL CHECK(typeof(sealed_descriptor) = 'blob' AND length(sealed_descriptor) >= 40)
);
CREATE TABLE commands (
    conversation_id BLOB NOT NULL CHECK(typeof(conversation_id) = 'blob' AND length(conversation_id) = 16),
    command_seq TEXT NOT NULL CHECK(
        typeof(command_seq) = 'text' AND length(command_seq) = 20
        AND command_seq NOT GLOB '*[^0-9]*'
        AND command_seq <= '18446744073709551615'
    ),
    command_id BLOB NOT NULL UNIQUE CHECK(typeof(command_id) = 'blob' AND length(command_id) = 16),
    idempotency_token BLOB NOT NULL UNIQUE CHECK(typeof(idempotency_token) = 'blob' AND length(idempotency_token) = 32),
    payload_token BLOB NOT NULL CHECK(typeof(payload_token) = 'blob' AND length(payload_token) = 32),
    state TEXT NOT NULL CHECK(state IN (
        'accepted', 'started', 'completed', 'failed', 'interrupted',
        'expired', 'canceled', 'revokedBeforeStart'
    )),
    logical_payload_bytes INTEGER NOT NULL CHECK(logical_payload_bytes BETWEEN 0 AND 1048576),
    accepted_at_ms INTEGER NOT NULL CHECK(accepted_at_ms >= 0),
    expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms >= accepted_at_ms),
    retain_until_ms INTEGER NOT NULL CHECK(retain_until_ms >= expires_at_ms),
    started_at_ms INTEGER CHECK(started_at_ms IS NULL OR started_at_ms >= accepted_at_ms),
    terminal_at_ms INTEGER CHECK(terminal_at_ms IS NULL OR terminal_at_ms >= accepted_at_ms),
    sealed_command BLOB NOT NULL CHECK(typeof(sealed_command) = 'blob' AND length(sealed_command) >= 40),
    sealed_result BLOB CHECK(sealed_result IS NULL OR (typeof(sealed_result) = 'blob' AND length(sealed_result) >= 40)),
    PRIMARY KEY(conversation_id, command_seq),
    FOREIGN KEY(conversation_id) REFERENCES conversations(conversation_id) ON UPDATE RESTRICT ON DELETE RESTRICT
);
CREATE INDEX idx_commands_recovery ON commands(conversation_id, state, command_seq);
CREATE INDEX idx_commands_expiry ON commands(state, expires_at_ms);
CREATE INDEX idx_commands_retention ON commands(retain_until_ms);
CREATE TABLE execution_intents (
    command_id BLOB PRIMARY KEY CHECK(typeof(command_id) = 'blob' AND length(command_id) = 16),
    daemon_boot_id BLOB NOT NULL CHECK(typeof(daemon_boot_id) = 'blob' AND length(daemon_boot_id) = 16),
    execution_nonce_token BLOB NOT NULL CHECK(typeof(execution_nonce_token) = 'blob' AND length(execution_nonce_token) = 32),
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
    sealed_intent BLOB NOT NULL CHECK(typeof(sealed_intent) = 'blob' AND length(sealed_intent) >= 40),
    UNIQUE(command_id, daemon_boot_id, execution_nonce_token),
    UNIQUE(daemon_boot_id, execution_nonce_token),
    FOREIGN KEY(command_id) REFERENCES commands(command_id) ON UPDATE RESTRICT ON DELETE RESTRICT
);
CREATE TABLE execution_fences (
    command_id BLOB PRIMARY KEY CHECK(typeof(command_id) = 'blob' AND length(command_id) = 16),
    daemon_boot_id BLOB NOT NULL CHECK(typeof(daemon_boot_id) = 'blob' AND length(daemon_boot_id) = 16),
    execution_nonce_token BLOB NOT NULL CHECK(typeof(execution_nonce_token) = 'blob' AND length(execution_nonce_token) = 32),
    process_group_id INTEGER NOT NULL CHECK(process_group_id > 0),
    leader_pid INTEGER NOT NULL CHECK(leader_pid > 0),
    leader_start_time TEXT NOT NULL CHECK(
        typeof(leader_start_time) = 'text' AND length(leader_start_time) = 20
        AND leader_start_time NOT GLOB '*[^0-9]*'
        AND leader_start_time <= '18446744073709551615'
    ),
    release_authorized_at_ms INTEGER CHECK(release_authorized_at_ms IS NULL OR release_authorized_at_ms >= 0),
    sealed_fence BLOB NOT NULL CHECK(typeof(sealed_fence) = 'blob' AND length(sealed_fence) >= 40),
    FOREIGN KEY(command_id, daemon_boot_id, execution_nonce_token)
        REFERENCES execution_intents(command_id, daemon_boot_id, execution_nonce_token)
        ON UPDATE RESTRICT ON DELETE RESTRICT
);
CREATE TABLE event_journal (
    conversation_id BLOB NOT NULL CHECK(typeof(conversation_id) = 'blob' AND length(conversation_id) = 16),
    event_seq TEXT NOT NULL CHECK(
        typeof(event_seq) = 'text' AND length(event_seq) = 20
        AND event_seq NOT GLOB '*[^0-9]*'
        AND event_seq <= '18446744073709551615'
    ),
    event_id BLOB NOT NULL UNIQUE CHECK(typeof(event_id) = 'blob' AND length(event_id) = 16),
    command_id BLOB CHECK(command_id IS NULL OR (typeof(command_id) = 'blob' AND length(command_id) = 16)),
    logical_event_bytes INTEGER NOT NULL CHECK(logical_event_bytes BETWEEN 0 AND 67108864),
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
    sealed_event BLOB NOT NULL CHECK(typeof(sealed_event) = 'blob' AND length(sealed_event) >= 40),
    PRIMARY KEY(conversation_id, event_seq),
    FOREIGN KEY(conversation_id) REFERENCES conversations(conversation_id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    FOREIGN KEY(command_id) REFERENCES commands(command_id) ON UPDATE RESTRICT ON DELETE RESTRICT
);
CREATE INDEX idx_event_journal_retention ON event_journal(created_at_ms, conversation_id, event_seq);
CREATE TABLE machine_enrollment_receipts (
    relay_server_id BLOB NOT NULL CHECK(typeof(relay_server_id) = 'blob' AND length(relay_server_id) = 16),
    machine_route BLOB NOT NULL CHECK(typeof(machine_route) = 'blob' AND length(machine_route) = 16),
    root_fingerprint BLOB NOT NULL CHECK(typeof(root_fingerprint) = 'blob' AND length(root_fingerprint) = 32),
    PRIMARY KEY(relay_server_id, machine_route)
);
"#;
