//! Runtime SQLite physical schema 与稳定 crypto context。

use std::sync::OnceLock;

use sha2::{Digest, Sha256};

pub const RUNTIME_SCHEMA_FAMILY: &str = "agentdeck-runtime";
pub const RUNTIME_SCHEMA_VERSION: u32 = 3;
/// 行密文与 wrapped key bundle 的 AAD context 版本。
///
/// physical schema migration 只增表/增认证计数，不得让既有行重新加密或重新包装。
pub const RUNTIME_CRYPTO_CONTEXT_VERSION: u32 = 1;
pub const RUNTIME_KEY_GENERATION: u32 = 1;
pub const EXPECTED_TABLES_V1: [&str; 7] = [
    "commands",
    "conversations",
    "event_journal",
    "execution_fences",
    "execution_intents",
    "machine_enrollment_receipts",
    "runtime_meta",
];
pub const EXPECTED_TABLES_V2: [&str; 9] = [
    "claude_code_adapter_state",
    "codex_adapter_state",
    "commands",
    "conversations",
    "event_journal",
    "execution_fences",
    "execution_intents",
    "machine_enrollment_receipts",
    "runtime_meta",
];
pub const EXPECTED_TABLES: [&str; 10] = [
    "approval_ledger",
    "claude_code_adapter_state",
    "codex_adapter_state",
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
    *SIGNATURE.get_or_init(|| {
        let mut digest = Sha256::new();
        digest.update(RUNTIME_DDL_V1.as_bytes());
        digest.update(RUNTIME_MIGRATION_V2.as_bytes());
        digest.update(RUNTIME_MIGRATION_V3.as_bytes());
        digest.finalize().into()
    })
}

pub fn schema_signature_v2() -> [u8; 32] {
    static SIGNATURE: OnceLock<[u8; 32]> = OnceLock::new();
    *SIGNATURE.get_or_init(|| {
        let mut digest = Sha256::new();
        digest.update(RUNTIME_DDL_V1.as_bytes());
        digest.update(RUNTIME_MIGRATION_V2.as_bytes());
        digest.finalize().into()
    })
}

pub fn schema_signature_v1() -> [u8; 32] {
    static SIGNATURE: OnceLock<[u8; 32]> = OnceLock::new();
    *SIGNATURE.get_or_init(|| Sha256::digest(RUNTIME_DDL_V1.as_bytes()).into())
}

pub const RUNTIME_DDL_V1: &str = r#"
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
    ),
    conversation_count INTEGER NOT NULL CHECK(conversation_count >= 0),
    command_count INTEGER NOT NULL CHECK(command_count >= 0),
    event_count INTEGER NOT NULL CHECK(event_count >= 0),
    intent_count INTEGER NOT NULL CHECK(intent_count >= 0),
    fence_count INTEGER NOT NULL CHECK(fence_count >= 0),
    accepted_count INTEGER NOT NULL CHECK(accepted_count BETWEEN 0 AND 1024),
    accepted_payload_bytes INTEGER NOT NULL CHECK(accepted_payload_bytes BETWEEN 0 AND 268435456),
    started_without_fence_count INTEGER NOT NULL CHECK(started_without_fence_count >= 0),
    started_without_release_count INTEGER NOT NULL CHECK(started_without_release_count >= 0),
    started_released_count INTEGER NOT NULL CHECK(started_released_count >= 0),
    metadata_token BLOB NOT NULL CHECK(typeof(metadata_token) = 'blob' AND length(metadata_token) = 32)
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
    accepted_count INTEGER NOT NULL CHECK(accepted_count BETWEEN 0 AND 32),
    metadata_token BLOB NOT NULL CHECK(typeof(metadata_token) = 'blob' AND length(metadata_token) = 32),
    sealed_descriptor BLOB NOT NULL CHECK(typeof(sealed_descriptor) = 'blob' AND length(sealed_descriptor) >= 40)
);
CREATE UNIQUE INDEX idx_conversations_catalog_revision ON conversations(catalog_revision);
CREATE TABLE commands (
    conversation_id BLOB NOT NULL CHECK(typeof(conversation_id) = 'blob' AND length(conversation_id) = 16),
    command_seq TEXT NOT NULL CHECK(
        typeof(command_seq) = 'text' AND length(command_seq) = 20
        AND command_seq NOT GLOB '*[^0-9]*'
        AND command_seq <= '18446744073709551615'
    ),
    command_id BLOB NOT NULL UNIQUE CHECK(typeof(command_id) = 'blob' AND length(command_id) = 16),
    owner_token BLOB NOT NULL CHECK(typeof(owner_token) = 'blob' AND length(owner_token) = 32),
    idempotency_token BLOB NOT NULL UNIQUE CHECK(typeof(idempotency_token) = 'blob' AND length(idempotency_token) = 32),
    payload_token BLOB NOT NULL CHECK(typeof(payload_token) = 'blob' AND length(payload_token) = 32),
    terminal_token BLOB CHECK(terminal_token IS NULL OR (typeof(terminal_token) = 'blob' AND length(terminal_token) = 32)),
    turn_id BLOB UNIQUE CHECK(turn_id IS NULL OR (typeof(turn_id) = 'blob' AND length(turn_id) = 16)),
    started_event_id BLOB UNIQUE CHECK(started_event_id IS NULL OR (typeof(started_event_id) = 'blob' AND length(started_event_id) = 16)),
    terminal_event_id BLOB UNIQUE CHECK(terminal_event_id IS NULL OR (typeof(terminal_event_id) = 'blob' AND length(terminal_event_id) = 16)),
    state TEXT NOT NULL CHECK(state IN (
        'accepted', 'started', 'completed', 'failed', 'interrupted',
        'expired', 'canceled', 'revokedBeforeStart'
    )),
    logical_payload_bytes INTEGER NOT NULL CHECK(logical_payload_bytes BETWEEN 0 AND 1048576),
    accepted_at_ms INTEGER NOT NULL CHECK(accepted_at_ms >= 0),
    expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms >= accepted_at_ms),
    retain_until_ms INTEGER NOT NULL CHECK(retain_until_ms >= expires_at_ms),
    started_at_ms INTEGER CHECK(started_at_ms IS NULL OR started_at_ms >= accepted_at_ms),
    terminal_at_ms INTEGER CHECK(
        terminal_at_ms IS NULL OR (
            terminal_at_ms >= accepted_at_ms
            AND (started_at_ms IS NULL OR terminal_at_ms >= started_at_ms)
        )
    ),
    metadata_token BLOB NOT NULL CHECK(typeof(metadata_token) = 'blob' AND length(metadata_token) = 32),
    sealed_command BLOB NOT NULL CHECK(typeof(sealed_command) = 'blob' AND length(sealed_command) >= 40),
    sealed_result BLOB CHECK(sealed_result IS NULL OR (typeof(sealed_result) = 'blob' AND length(sealed_result) >= 40)),
    PRIMARY KEY(conversation_id, command_seq),
    FOREIGN KEY(conversation_id) REFERENCES conversations(conversation_id) ON UPDATE RESTRICT ON DELETE RESTRICT
);
CREATE INDEX idx_commands_recovery ON commands(conversation_id, state, command_seq);
CREATE INDEX idx_commands_expiry ON commands(state, expires_at_ms);
CREATE INDEX idx_commands_retention ON commands(retain_until_ms);
CREATE INDEX idx_commands_owner_state ON commands(owner_token, state, conversation_id, command_seq);
CREATE UNIQUE INDEX idx_commands_one_started ON commands(conversation_id) WHERE state = 'started';
CREATE TABLE execution_intents (
    command_id BLOB PRIMARY KEY CHECK(typeof(command_id) = 'blob' AND length(command_id) = 16),
    turn_id BLOB NOT NULL UNIQUE CHECK(typeof(turn_id) = 'blob' AND length(turn_id) = 16),
    started_event_id BLOB NOT NULL UNIQUE CHECK(typeof(started_event_id) = 'blob' AND length(started_event_id) = 16),
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
    release_token BLOB CHECK(
        (release_authorized_at_ms IS NULL AND release_token IS NULL)
        OR (
            release_authorized_at_ms IS NOT NULL
            AND typeof(release_token) = 'blob'
            AND length(release_token) = 32
        )
    ),
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
    metadata_token BLOB NOT NULL CHECK(typeof(metadata_token) = 'blob' AND length(metadata_token) = 32),
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

/// v1 -> v2 只增两个 adapter 私有表与其 authenticated ledger totals。
///
/// `ALTER TABLE` 使用固定 default 让 migration 可以在单事务里先扩 schema，再以
/// v1 ledger token 为 compare-and-swap 前提更新 v2 token；既有 wrapped key/ciphertext
/// 均保持逐字节不变。
pub const RUNTIME_MIGRATION_V2: &str = r#"
ALTER TABLE runtime_meta ADD COLUMN codex_adapter_state_count INTEGER NOT NULL DEFAULT 0
    CHECK(codex_adapter_state_count >= 0);
ALTER TABLE runtime_meta ADD COLUMN claude_code_adapter_state_count INTEGER NOT NULL DEFAULT 0
    CHECK(claude_code_adapter_state_count >= 0);
CREATE TABLE codex_adapter_state (
    state_key_token BLOB PRIMARY KEY
        CHECK(typeof(state_key_token) = 'blob' AND length(state_key_token) = 32),
    conversation_id BLOB NOT NULL UNIQUE
        CHECK(typeof(conversation_id) = 'blob' AND length(conversation_id) = 16),
    state_reference_token BLOB NOT NULL UNIQUE
        CHECK(typeof(state_reference_token) = 'blob' AND length(state_reference_token) = 32),
    sealed_state_reference BLOB NOT NULL
        CHECK(typeof(sealed_state_reference) = 'blob' AND length(sealed_state_reference) >= 40),
    FOREIGN KEY(conversation_id) REFERENCES conversations(conversation_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT
);
CREATE TABLE claude_code_adapter_state (
    state_key_token BLOB PRIMARY KEY
        CHECK(typeof(state_key_token) = 'blob' AND length(state_key_token) = 32),
    conversation_id BLOB NOT NULL UNIQUE
        CHECK(typeof(conversation_id) = 'blob' AND length(conversation_id) = 16),
    state_reference_token BLOB NOT NULL UNIQUE
        CHECK(typeof(state_reference_token) = 'blob' AND length(state_reference_token) = 32),
    sealed_state_reference BLOB NOT NULL
        CHECK(typeof(sealed_state_reference) = 'blob' AND length(sealed_state_reference) >= 40),
    FOREIGN KEY(conversation_id) REFERENCES conversations(conversation_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT
);
"#;

/// v2 -> v3 只增 approval ledger 与两个 authenticated ledger totals。
///
/// 新字段的固定零 default 让 v1/v2 migration 都可以在单事务内完成 CAS token
/// 升级；stable crypto context 仍为 v1，既有 wrapped key bundle 与密文不重写。
pub const RUNTIME_MIGRATION_V3: &str = r#"
ALTER TABLE runtime_meta ADD COLUMN approval_count INTEGER NOT NULL DEFAULT 0
    CHECK(approval_count BETWEEN 0 AND 32768);
ALTER TABLE runtime_meta ADD COLUMN active_approval_count INTEGER NOT NULL DEFAULT 0
    CHECK(active_approval_count BETWEEN 0 AND 1024
        AND active_approval_count <= approval_count);
CREATE TABLE approval_ledger (
    approval_id BLOB PRIMARY KEY
        CHECK(typeof(approval_id) = 'blob' AND length(approval_id) = 16),
    conversation_id BLOB NOT NULL
        CHECK(typeof(conversation_id) = 'blob' AND length(conversation_id) = 16),
    command_id BLOB NOT NULL
        CHECK(typeof(command_id) = 'blob' AND length(command_id) = 16),
    turn_id BLOB NOT NULL
        CHECK(typeof(turn_id) = 'blob' AND length(turn_id) = 16),
    request_token BLOB NOT NULL
        CHECK(typeof(request_token) = 'blob' AND length(request_token) = 32),
    decision_token BLOB
        CHECK(decision_token IS NULL OR (
            typeof(decision_token) = 'blob' AND length(decision_token) = 32
        )),
    claimant_token BLOB
        CHECK(claimant_token IS NULL OR (
            typeof(claimant_token) = 'blob' AND length(claimant_token) = 32
        )),
    state TEXT NOT NULL CHECK(state IN (
        'pending', 'claimed', 'applying', 'applied', 'deliveryFailed', 'expired'
    )),
    requested_at_ms INTEGER NOT NULL CHECK(requested_at_ms >= 0),
    deadline_at_ms INTEGER NOT NULL CHECK(deadline_at_ms >= requested_at_ms),
    claimed_at_ms INTEGER
        CHECK(claimed_at_ms IS NULL OR claimed_at_ms >= requested_at_ms),
    state_changed_at_ms INTEGER NOT NULL
        CHECK(state_changed_at_ms >= requested_at_ms),
    delivery_round INTEGER NOT NULL
        CHECK(delivery_round BETWEEN 0 AND 4294967295),
    attempts_in_round INTEGER NOT NULL
        CHECK(attempts_in_round BETWEEN 0 AND 8),
    round_started_at_ms INTEGER CHECK(round_started_at_ms IS NULL OR (
        claimed_at_ms IS NOT NULL AND round_started_at_ms >= claimed_at_ms
    )),
    last_attempt_at_ms INTEGER CHECK(last_attempt_at_ms IS NULL OR (
        round_started_at_ms IS NOT NULL AND last_attempt_at_ms >= round_started_at_ms
    )),
    state_version INTEGER NOT NULL CHECK(state_version >= 1),
    last_event_id BLOB NOT NULL UNIQUE
        CHECK(typeof(last_event_id) = 'blob' AND length(last_event_id) = 16),
    logical_request_bytes INTEGER NOT NULL
        CHECK(logical_request_bytes BETWEEN 1 AND 262144),
    logical_decision_bytes INTEGER NOT NULL
        CHECK(logical_decision_bytes BETWEEN 0 AND 65536),
    metadata_token BLOB NOT NULL
        CHECK(typeof(metadata_token) = 'blob' AND length(metadata_token) = 32),
    sealed_request BLOB NOT NULL
        CHECK(typeof(sealed_request) = 'blob'
            AND length(sealed_request) BETWEEN 40 AND 262184),
    sealed_decision BLOB CHECK(sealed_decision IS NULL OR (
        typeof(sealed_decision) = 'blob'
        AND length(sealed_decision) BETWEEN 40 AND 65576
    )),
    sealed_status_detail BLOB CHECK(sealed_status_detail IS NULL OR (
        typeof(sealed_status_detail) = 'blob'
        AND length(sealed_status_detail) BETWEEN 40 AND 65576
    )),
    CHECK(
        (
            decision_token IS NULL
            AND claimant_token IS NULL
            AND claimed_at_ms IS NULL
            AND logical_decision_bytes = 0
            AND sealed_decision IS NULL
        ) OR (
            decision_token IS NOT NULL
            AND claimant_token IS NOT NULL
            AND claimed_at_ms IS NOT NULL
            AND logical_decision_bytes > 0
            AND sealed_decision IS NOT NULL
        )
    ),
    CHECK(
        (
            delivery_round = 0
            AND attempts_in_round = 0
            AND round_started_at_ms IS NULL
            AND last_attempt_at_ms IS NULL
        ) OR (
            delivery_round >= 1
            AND claimed_at_ms IS NOT NULL
            AND round_started_at_ms IS NOT NULL
            AND (
                (attempts_in_round = 0 AND last_attempt_at_ms IS NULL)
                OR (attempts_in_round >= 1 AND last_attempt_at_ms IS NOT NULL)
            )
        )
    ),
    CHECK(
        (state = 'pending' AND decision_token IS NULL AND delivery_round = 0)
        OR (state = 'claimed' AND decision_token IS NOT NULL AND delivery_round = 0)
        OR (state = 'applying' AND decision_token IS NOT NULL AND delivery_round >= 1)
        OR (state IN ('applied', 'deliveryFailed')
            AND decision_token IS NOT NULL
            AND delivery_round >= 1
            AND attempts_in_round >= 1)
        OR state = 'expired'
    ),
    CHECK(claimed_at_ms IS NULL OR state_changed_at_ms >= claimed_at_ms),
    FOREIGN KEY(conversation_id) REFERENCES conversations(conversation_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    FOREIGN KEY(command_id) REFERENCES commands(command_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    FOREIGN KEY(turn_id) REFERENCES execution_intents(turn_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    FOREIGN KEY(last_event_id) REFERENCES event_journal(event_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT
);
CREATE INDEX idx_approval_active_turn
    ON approval_ledger(conversation_id, turn_id, state);
CREATE INDEX idx_approval_deadline
    ON approval_ledger(state, deadline_at_ms);
CREATE UNIQUE INDEX idx_approval_request_per_turn
    ON approval_ledger(turn_id, request_token);
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    #[test]
    fn approval_physical_schema_advances_to_v3_without_rotating_crypto_context() {
        assert_eq!(RUNTIME_SCHEMA_VERSION, 3);
        assert_eq!(RUNTIME_CRYPTO_CONTEXT_VERSION, 1);
        assert_eq!(EXPECTED_TABLES.len(), 10);
        assert!(EXPECTED_TABLES.contains(&"approval_ledger"));
    }

    fn v3_connection() -> Connection {
        let connection = Connection::open_in_memory().expect("open in-memory schema");
        connection
            .execute_batch(RUNTIME_DDL_V1)
            .expect("create v1 schema");
        connection
            .execute_batch(RUNTIME_MIGRATION_V2)
            .expect("apply v2 migration");
        connection
            .execute_batch(RUNTIME_MIGRATION_V3)
            .expect("apply v3 migration");
        connection
    }

    #[test]
    fn approval_schema_has_exact_meta_columns_indexes_and_foreign_keys() {
        let connection = v3_connection();
        let tables = connection
            .prepare(
                "SELECT name FROM sqlite_schema
                 WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
                 ORDER BY name",
            )
            .expect("prepare table manifest")
            .query_map([], |row| row.get::<_, String>(0))
            .expect("query table manifest")
            .collect::<Result<Vec<_>, _>>()
            .expect("collect table manifest");
        assert_eq!(tables, EXPECTED_TABLES);

        let meta_columns = connection
            .prepare("SELECT name FROM pragma_table_info('runtime_meta') ORDER BY cid")
            .expect("prepare meta columns")
            .query_map([], |row| row.get::<_, String>(0))
            .expect("query meta columns")
            .collect::<Result<Vec<_>, _>>()
            .expect("collect meta columns");
        assert_eq!(
            &meta_columns[meta_columns.len() - 2..],
            ["approval_count", "active_approval_count"]
        );

        let indexes = connection
            .prepare(
                "SELECT name FROM sqlite_schema
                 WHERE type = 'index' AND tbl_name = 'approval_ledger'
                   AND name NOT LIKE 'sqlite_%'
                 ORDER BY name",
            )
            .expect("prepare approval indexes")
            .query_map([], |row| row.get::<_, String>(0))
            .expect("query approval indexes")
            .collect::<Result<Vec<_>, _>>()
            .expect("collect approval indexes");
        assert_eq!(
            indexes,
            [
                "idx_approval_active_turn",
                "idx_approval_deadline",
                "idx_approval_request_per_turn"
            ]
        );

        let foreign_key_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM pragma_foreign_key_list('approval_ledger')",
                [],
                |row| row.get(0),
            )
            .expect("read approval foreign keys");
        assert_eq!(foreign_key_count, 4);
    }

    #[test]
    fn approval_schema_rejects_incoherent_winner_and_retry_state() {
        let connection = v3_connection();
        connection
            .pragma_update(None, "foreign_keys", false)
            .expect("disable foreign keys for isolated CHECK test");
        let pending = "INSERT INTO approval_ledger (
            approval_id, conversation_id, command_id, turn_id,
            request_token, decision_token, claimant_token, state,
            requested_at_ms, deadline_at_ms, claimed_at_ms, state_changed_at_ms,
            delivery_round, attempts_in_round, round_started_at_ms, last_attempt_at_ms,
            state_version, last_event_id, logical_request_bytes, logical_decision_bytes,
            metadata_token, sealed_request, sealed_decision, sealed_status_detail
        ) VALUES (
            ?1, ?2, ?3, ?4, ?5, NULL, NULL, 'pending',
            10, 20, NULL, 10, 0, 0, NULL, NULL, 1, ?6, 7, 0, ?7, ?8, NULL, NULL
        )";
        connection
            .execute(
                pending,
                rusqlite::params![
                    &[1_u8; 16][..],
                    &[2_u8; 16][..],
                    &[3_u8; 16][..],
                    &[4_u8; 16][..],
                    &[5_u8; 32][..],
                    &[6_u8; 16][..],
                    &[7_u8; 32][..],
                    &[8_u8; 40][..],
                ],
            )
            .expect("coherent pending row");

        let invalid = pending.replace("NULL, NULL, 'pending'", "zeroblob(32), NULL, 'pending'");
        assert!(
            connection
                .execute(
                    &invalid,
                    rusqlite::params![
                        &[9_u8; 16][..],
                        &[2_u8; 16][..],
                        &[3_u8; 16][..],
                        &[4_u8; 16][..],
                        &[5_u8; 32][..],
                        &[10_u8; 16][..],
                        &[7_u8; 32][..],
                        &[8_u8; 40][..],
                    ],
                )
                .is_err(),
            "pending row cannot carry only part of a winner tuple"
        );
    }
}
