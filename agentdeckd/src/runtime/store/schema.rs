//! Runtime SQLite physical schema 与稳定 crypto context。

use std::sync::OnceLock;

use sha2::{Digest, Sha256};

pub const RUNTIME_SCHEMA_FAMILY: &str = "agentdeck-runtime";
pub const RUNTIME_SCHEMA_VERSION: u32 = 4;
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
pub const EXPECTED_TABLES_V3: [&str; 10] = [
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
pub const EXPECTED_TABLES: [&str; 16] = [
    "approval_ledger",
    "catalog_journal",
    "claude_code_adapter_state",
    "codex_adapter_state",
    "commands",
    "conversations",
    "event_journal",
    "event_retention",
    "event_stream_index",
    "execution_fences",
    "execution_intents",
    "machine_enrollment_receipts",
    "publication_outbox",
    "publication_streams",
    "runtime_meta",
    "snapshots",
];

pub fn schema_signature() -> [u8; 32] {
    static SIGNATURE: OnceLock<[u8; 32]> = OnceLock::new();
    *SIGNATURE.get_or_init(|| {
        let mut digest = Sha256::new();
        digest.update(RUNTIME_DDL_V1.as_bytes());
        digest.update(RUNTIME_MIGRATION_V2.as_bytes());
        digest.update(RUNTIME_MIGRATION_V3.as_bytes());
        digest.update(RUNTIME_MIGRATION_V4.as_bytes());
        digest.finalize().into()
    })
}

pub fn schema_signature_v3() -> [u8; 32] {
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

/// v3 -> v4 增加有界 canonical replay window、catalog delta、snapshot 与
/// transport-neutral publication outbox。既有 `event_journal` 仍是不可裁剪的
/// authenticated audit，migration 不改写任何既有 ciphertext。
pub const RUNTIME_MIGRATION_V4: &str = r#"
ALTER TABLE runtime_meta ADD COLUMN audit_event_logical_bytes INTEGER NOT NULL DEFAULT 0
    CHECK(audit_event_logical_bytes >= 0);
ALTER TABLE runtime_meta ADD COLUMN event_stream_count INTEGER NOT NULL DEFAULT 0
    CHECK(event_stream_count BETWEEN 0 AND 131072);
ALTER TABLE runtime_meta ADD COLUMN event_stream_bytes INTEGER NOT NULL DEFAULT 0
    CHECK(event_stream_bytes BETWEEN 0 AND 536870912);
ALTER TABLE runtime_meta ADD COLUMN catalog_delta_count INTEGER NOT NULL DEFAULT 0
    CHECK(catalog_delta_count BETWEEN 0 AND 10000);
ALTER TABLE runtime_meta ADD COLUMN catalog_delta_bytes INTEGER NOT NULL DEFAULT 0
    CHECK(catalog_delta_bytes BETWEEN 0 AND 67108864);
ALTER TABLE runtime_meta ADD COLUMN catalog_retention_floor TEXT CHECK(
    catalog_retention_floor IS NULL OR (
        typeof(catalog_retention_floor) = 'text'
        AND length(catalog_retention_floor) = 20
        AND catalog_retention_floor NOT GLOB '*[^0-9]*'
        AND catalog_retention_floor <= '18446744073709551615'
    )
);
ALTER TABLE runtime_meta ADD COLUMN snapshot_count INTEGER NOT NULL DEFAULT 0
    CHECK(snapshot_count BETWEEN 0 AND 1024);
ALTER TABLE runtime_meta ADD COLUMN snapshot_bytes INTEGER NOT NULL DEFAULT 0
    CHECK(snapshot_bytes BETWEEN 0 AND 536870912);
ALTER TABLE runtime_meta ADD COLUMN publication_stream_count INTEGER NOT NULL DEFAULT 0
    CHECK(publication_stream_count BETWEEN 0 AND 1025);
ALTER TABLE runtime_meta ADD COLUMN publication_outbox_count INTEGER NOT NULL DEFAULT 0
    CHECK(publication_outbox_count BETWEEN 0 AND 10000);
ALTER TABLE runtime_meta ADD COLUMN publication_outbox_bytes INTEGER NOT NULL DEFAULT 0
    CHECK(publication_outbox_bytes BETWEEN 0 AND 536870912);

CREATE TABLE event_stream_index (
    conversation_id BLOB NOT NULL
        CHECK(typeof(conversation_id) = 'blob' AND length(conversation_id) = 16),
    event_seq TEXT NOT NULL CHECK(
        typeof(event_seq) = 'text' AND length(event_seq) = 20
        AND event_seq NOT GLOB '*[^0-9]*'
        AND event_seq <= '18446744073709551615'
    ),
    event_id BLOB NOT NULL UNIQUE
        CHECK(typeof(event_id) = 'blob' AND length(event_id) = 16),
    logical_event_bytes INTEGER NOT NULL
        CHECK(logical_event_bytes BETWEEN 0 AND 67108864),
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
    metadata_token BLOB NOT NULL
        CHECK(typeof(metadata_token) = 'blob' AND length(metadata_token) = 32),
    PRIMARY KEY(conversation_id, event_seq),
    FOREIGN KEY(conversation_id, event_seq)
        REFERENCES event_journal(conversation_id, event_seq)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    FOREIGN KEY(event_id) REFERENCES event_journal(event_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    FOREIGN KEY(conversation_id) REFERENCES conversations(conversation_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT
);
CREATE INDEX idx_event_stream_global_gc
    ON event_stream_index(created_at_ms, conversation_id, event_seq);

CREATE TABLE event_retention (
    conversation_id BLOB PRIMARY KEY
        CHECK(typeof(conversation_id) = 'blob' AND length(conversation_id) = 16),
    oldest_retained_event_seq TEXT CHECK(
        oldest_retained_event_seq IS NULL OR (
            typeof(oldest_retained_event_seq) = 'text'
            AND length(oldest_retained_event_seq) = 20
            AND oldest_retained_event_seq NOT GLOB '*[^0-9]*'
            AND oldest_retained_event_seq <= '18446744073709551615'
        )
    ),
    indexed_through_event_seq TEXT CHECK(
        indexed_through_event_seq IS NULL OR (
            typeof(indexed_through_event_seq) = 'text'
            AND length(indexed_through_event_seq) = 20
            AND indexed_through_event_seq NOT GLOB '*[^0-9]*'
            AND indexed_through_event_seq <= '18446744073709551615'
        )
    ),
    retained_event_count INTEGER NOT NULL
        CHECK(retained_event_count BETWEEN 0 AND 10000),
    retained_logical_bytes INTEGER NOT NULL
        CHECK(retained_logical_bytes BETWEEN 0 AND 67108864),
    range_digest BLOB NOT NULL
        CHECK(typeof(range_digest) = 'blob' AND length(range_digest) = 32),
    metadata_token BLOB NOT NULL
        CHECK(typeof(metadata_token) = 'blob' AND length(metadata_token) = 32),
    CHECK((retained_event_count = 0 AND oldest_retained_event_seq IS NULL)
       OR (retained_event_count > 0 AND oldest_retained_event_seq IS NOT NULL)),
    CHECK(oldest_retained_event_seq IS NULL
       OR indexed_through_event_seq IS NOT NULL),
    CHECK(oldest_retained_event_seq IS NULL
       OR oldest_retained_event_seq <= indexed_through_event_seq),
    FOREIGN KEY(conversation_id) REFERENCES conversations(conversation_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT
);

CREATE TABLE catalog_journal (
    catalog_revision TEXT PRIMARY KEY CHECK(
        typeof(catalog_revision) = 'text' AND length(catalog_revision) = 20
        AND catalog_revision NOT GLOB '*[^0-9]*'
        AND catalog_revision <= '18446744073709551615'
    ),
    conversation_id BLOB NOT NULL
        CHECK(typeof(conversation_id) = 'blob' AND length(conversation_id) = 16),
    change_kind TEXT NOT NULL CHECK(change_kind IN ('upserted', 'removed')),
    logical_delta_bytes INTEGER NOT NULL
        CHECK(logical_delta_bytes BETWEEN 1 AND 67108864),
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
    metadata_token BLOB NOT NULL
        CHECK(typeof(metadata_token) = 'blob' AND length(metadata_token) = 32),
    sealed_delta BLOB NOT NULL CHECK(
        typeof(sealed_delta) = 'blob' AND length(sealed_delta) BETWEEN 40 AND 67108904
    )
);
CREATE INDEX idx_catalog_journal_gc
    ON catalog_journal(created_at_ms, catalog_revision);

CREATE TABLE snapshots (
    snapshot_id BLOB PRIMARY KEY
        CHECK(typeof(snapshot_id) = 'blob' AND length(snapshot_id) = 16),
    target_scope TEXT NOT NULL CHECK(target_scope IN ('catalog', 'conversation')),
    conversation_id BLOB CHECK(
        conversation_id IS NULL OR
        (typeof(conversation_id) = 'blob' AND length(conversation_id) = 16)
    ),
    source_build_pin_id BLOB CHECK(
        source_build_pin_id IS NULL OR
        (typeof(source_build_pin_id) = 'blob' AND length(source_build_pin_id) = 16)
    ),
    base_cursor TEXT CHECK(
        base_cursor IS NULL OR (
            typeof(base_cursor) = 'text' AND length(base_cursor) = 20
            AND base_cursor NOT GLOB '*[^0-9]*'
            AND base_cursor <= '18446744073709551615'
        )
    ),
    build_state TEXT NOT NULL CHECK(build_state = 'ready'),
    item_count INTEGER NOT NULL CHECK(item_count BETWEEN 0 AND 10000),
    logical_snapshot_bytes INTEGER NOT NULL
        CHECK(logical_snapshot_bytes BETWEEN 1 AND 67108864),
    content_sha256 BLOB NOT NULL
        CHECK(typeof(content_sha256) = 'blob' AND length(content_sha256) = 32),
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
    metadata_token BLOB NOT NULL
        CHECK(typeof(metadata_token) = 'blob' AND length(metadata_token) = 32),
    sealed_snapshot BLOB NOT NULL CHECK(
        typeof(sealed_snapshot) = 'blob'
        AND length(sealed_snapshot) BETWEEN 40 AND 67108904
    ),
    CHECK((target_scope = 'catalog' AND conversation_id IS NULL
           AND source_build_pin_id IS NULL)
       OR (target_scope = 'conversation' AND conversation_id IS NOT NULL
           AND source_build_pin_id IS NOT NULL)),
    FOREIGN KEY(conversation_id) REFERENCES conversations(conversation_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT
);
CREATE UNIQUE INDEX idx_snapshots_ready_catalog
    ON snapshots(target_scope) WHERE target_scope = 'catalog';
CREATE UNIQUE INDEX idx_snapshots_ready_conversation
    ON snapshots(conversation_id) WHERE target_scope = 'conversation';
CREATE INDEX idx_snapshots_gc ON snapshots(created_at_ms, target_scope, conversation_id);

CREATE TABLE publication_streams (
    publication_stream_id BLOB PRIMARY KEY
        CHECK(typeof(publication_stream_id) = 'blob' AND length(publication_stream_id) = 16),
    scope TEXT NOT NULL CHECK(scope IN ('catalog', 'conversation')),
    conversation_id BLOB
        CHECK(conversation_id IS NULL OR (
            typeof(conversation_id) = 'blob' AND length(conversation_id) = 16
        )),
    stream_route BLOB NOT NULL
        CHECK(typeof(stream_route) = 'blob' AND length(stream_route) = 16),
    generation BLOB NOT NULL
        CHECK(typeof(generation) = 'blob' AND length(generation) = 16),
    counter_scope_token BLOB CHECK(
        counter_scope_token IS NULL OR (
            typeof(counter_scope_token) = 'blob' AND length(counter_scope_token) = 32
        )
    ),
    sender_counter_high_water TEXT CHECK(
        sender_counter_high_water IS NULL OR (
            typeof(sender_counter_high_water) = 'text'
            AND length(sender_counter_high_water) = 20
            AND sender_counter_high_water NOT GLOB '*[^0-9]*'
            AND sender_counter_high_water <= '18446744073709551615'
        )
    ),
    reserved_high_water TEXT CHECK(
        reserved_high_water IS NULL OR (
            typeof(reserved_high_water) = 'text' AND length(reserved_high_water) = 20
            AND reserved_high_water NOT GLOB '*[^0-9]*'
            AND reserved_high_water <= '18446744073709551615'
        )
    ),
    committed_high_water TEXT CHECK(
        committed_high_water IS NULL OR (
            typeof(committed_high_water) = 'text' AND length(committed_high_water) = 20
            AND committed_high_water NOT GLOB '*[^0-9]*'
            AND committed_high_water <= '18446744073709551615'
        )
    ),
    committed_inner_cursor TEXT CHECK(
        committed_inner_cursor IS NULL OR (
            typeof(committed_inner_cursor) = 'text'
            AND length(committed_inner_cursor) = 20
            AND committed_inner_cursor NOT GLOB '*[^0-9]*'
            AND committed_inner_cursor <= '18446744073709551615'
        )
    ),
    acknowledged_high_water TEXT CHECK(
        acknowledged_high_water IS NULL OR (
            typeof(acknowledged_high_water) = 'text'
            AND length(acknowledged_high_water) = 20
            AND acknowledged_high_water NOT GLOB '*[^0-9]*'
            AND acknowledged_high_water <= '18446744073709551615'
        )
    ),
    acknowledged_inner_cursor TEXT CHECK(
        acknowledged_inner_cursor IS NULL OR (
            typeof(acknowledged_inner_cursor) = 'text'
            AND length(acknowledged_inner_cursor) = 20
            AND acknowledged_inner_cursor NOT GLOB '*[^0-9]*'
            AND acknowledged_inner_cursor <= '18446744073709551615'
        )
    ),
    last_acknowledged_blob_hash BLOB CHECK(
        last_acknowledged_blob_hash IS NULL OR (
            typeof(last_acknowledged_blob_hash) = 'blob'
            AND length(last_acknowledged_blob_hash) = 32
        )
    ),
    last_committed_blob_hash BLOB CHECK(
        last_committed_blob_hash IS NULL OR (
            typeof(last_committed_blob_hash) = 'blob'
            AND length(last_committed_blob_hash) = 32
        )
    ),
    state TEXT NOT NULL CHECK(state IN ('active', 'needsSnapshot', 'retired')),
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= created_at_ms),
    metadata_token BLOB NOT NULL
        CHECK(typeof(metadata_token) = 'blob' AND length(metadata_token) = 32),
    CHECK((scope = 'catalog' AND conversation_id IS NULL)
       OR (scope = 'conversation' AND conversation_id IS NOT NULL)),
    CHECK(committed_high_water IS NULL OR reserved_high_water IS NOT NULL),
    CHECK(committed_high_water IS NULL OR committed_high_water <= reserved_high_water),
    CHECK(acknowledged_high_water IS NULL OR committed_high_water IS NOT NULL),
    CHECK(acknowledged_high_water IS NULL OR acknowledged_high_water <= committed_high_water),
    CHECK((committed_high_water IS NULL
           AND committed_inner_cursor IS NULL
           AND last_committed_blob_hash IS NULL)
       OR (committed_high_water IS NOT NULL
           AND last_committed_blob_hash IS NOT NULL)),
    CHECK((acknowledged_high_water IS NULL
           AND acknowledged_inner_cursor IS NULL
           AND last_acknowledged_blob_hash IS NULL)
       OR (acknowledged_high_water IS NOT NULL
           AND last_acknowledged_blob_hash IS NOT NULL)),
    CHECK((counter_scope_token IS NULL AND sender_counter_high_water IS NULL)
       OR (counter_scope_token IS NOT NULL AND sender_counter_high_water IS NOT NULL)),
    UNIQUE(publication_stream_id, generation),
    UNIQUE(stream_route, generation),
    UNIQUE(counter_scope_token),
    FOREIGN KEY(conversation_id) REFERENCES conversations(conversation_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT
);
CREATE UNIQUE INDEX idx_publication_active_catalog
    ON publication_streams(scope) WHERE scope = 'catalog' AND state = 'active';
CREATE UNIQUE INDEX idx_publication_active_conversation
    ON publication_streams(conversation_id)
    WHERE scope = 'conversation' AND state = 'active';

CREATE TABLE publication_outbox (
    publication_id BLOB PRIMARY KEY
        CHECK(typeof(publication_id) = 'blob' AND length(publication_id) = 16),
    publication_stream_id BLOB NOT NULL
        CHECK(typeof(publication_stream_id) = 'blob' AND length(publication_stream_id) = 16),
    generation BLOB NOT NULL
        CHECK(typeof(generation) = 'blob' AND length(generation) = 16),
    stream_seq TEXT NOT NULL CHECK(
        typeof(stream_seq) = 'text' AND length(stream_seq) = 20
        AND stream_seq NOT GLOB '*[^0-9]*'
        AND stream_seq <= '18446744073709551615'
    ),
    counter_scope_token BLOB NOT NULL
        CHECK(typeof(counter_scope_token) = 'blob' AND length(counter_scope_token) = 32),
    sender_counter TEXT NOT NULL CHECK(
        typeof(sender_counter) = 'text' AND length(sender_counter) = 20
        AND sender_counter NOT GLOB '*[^0-9]*'
        AND sender_counter <= '18446744073709551615'
    ),
    inner_after_seq TEXT CHECK(
        inner_after_seq IS NULL OR (
            typeof(inner_after_seq) = 'text' AND length(inner_after_seq) = 20
            AND inner_after_seq NOT GLOB '*[^0-9]*'
            AND inner_after_seq <= '18446744073709551615'
        )
    ),
    inner_through_seq TEXT CHECK(
        inner_through_seq IS NULL OR (
            typeof(inner_through_seq) = 'text' AND length(inner_through_seq) = 20
            AND inner_through_seq NOT GLOB '*[^0-9]*'
            AND inner_through_seq <= '18446744073709551615'
        )
    ),
    payload_kind TEXT NOT NULL CHECK(
        payload_kind IN ('event', 'catalog', 'snapshot', 'control')
    ),
    blob_sha256 BLOB NOT NULL
        CHECK(typeof(blob_sha256) = 'blob' AND length(blob_sha256) = 32),
    logical_blob_bytes INTEGER NOT NULL
        CHECK(logical_blob_bytes BETWEEN 1 AND 4194304),
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
    metadata_token BLOB NOT NULL
        CHECK(typeof(metadata_token) = 'blob' AND length(metadata_token) = 32),
    sealed_publication BLOB NOT NULL CHECK(
        typeof(sealed_publication) = 'blob'
        AND length(sealed_publication) BETWEEN 40 AND 4194344
    ),
    CHECK((inner_after_seq IS NULL AND inner_through_seq IS NULL)
       OR (inner_through_seq IS NOT NULL
           AND (inner_after_seq IS NULL OR inner_after_seq < inner_through_seq))),
    UNIQUE(publication_stream_id, generation, stream_seq),
    UNIQUE(counter_scope_token, sender_counter),
    FOREIGN KEY(publication_stream_id, generation)
        REFERENCES publication_streams(publication_stream_id, generation)
        ON UPDATE RESTRICT ON DELETE RESTRICT
);
CREATE INDEX idx_publication_pending
    ON publication_outbox(publication_stream_id, generation, stream_seq);
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    #[test]
    fn stream_schema_advances_to_v4_with_six_bounded_store_tables() {
        assert_eq!(RUNTIME_SCHEMA_VERSION, 4);
        assert_eq!(RUNTIME_CRYPTO_CONTEXT_VERSION, 1);
        for table in [
            "event_stream_index",
            "event_retention",
            "catalog_journal",
            "snapshots",
            "publication_streams",
            "publication_outbox",
        ] {
            assert!(EXPECTED_TABLES.contains(&table), "missing {table}");
        }
    }

    #[test]
    fn approval_physical_schema_remains_v3_compatible_without_rotating_crypto_context() {
        assert_eq!(RUNTIME_SCHEMA_VERSION, 4);
        assert_eq!(RUNTIME_CRYPTO_CONTEXT_VERSION, 1);
        assert_eq!(EXPECTED_TABLES_V3.len(), 10);
        assert!(EXPECTED_TABLES_V3.contains(&"approval_ledger"));
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
        assert_eq!(tables, EXPECTED_TABLES_V3);

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
    fn v4_schema_has_exact_stream_tables_and_bounds() {
        let connection = v3_connection();
        connection
            .execute_batch(RUNTIME_MIGRATION_V4)
            .expect("apply v4 migration");
        let tables = connection
            .prepare(
                "SELECT name FROM sqlite_schema
                 WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
                 ORDER BY name",
            )
            .expect("prepare v4 tables")
            .query_map([], |row| row.get::<_, String>(0))
            .expect("query v4 tables")
            .collect::<Result<Vec<_>, _>>()
            .expect("collect v4 tables");
        assert_eq!(tables, EXPECTED_TABLES);

        let event_indexes = connection
            .prepare("SELECT name FROM pragma_index_list('event_journal') ORDER BY name")
            .expect("prepare event journal indexes")
            .query_map([], |row| row.get::<_, String>(0))
            .expect("query event journal indexes")
            .collect::<Result<Vec<_>, _>>()
            .expect("collect event journal indexes");
        assert!(
            !event_indexes
                .iter()
                .any(|name| name == "idx_event_journal_stream_identity"),
            "v4 migration must not rebuild an index over the full immutable audit journal"
        );

        let meta_columns = connection
            .prepare("SELECT name FROM pragma_table_info('runtime_meta') ORDER BY cid")
            .expect("prepare v4 meta columns")
            .query_map([], |row| row.get::<_, String>(0))
            .expect("query v4 meta columns")
            .collect::<Result<Vec<_>, _>>()
            .expect("collect v4 meta columns");
        assert_eq!(
            &meta_columns[meta_columns.len() - 11..],
            [
                "audit_event_logical_bytes",
                "event_stream_count",
                "event_stream_bytes",
                "catalog_delta_count",
                "catalog_delta_bytes",
                "catalog_retention_floor",
                "snapshot_count",
                "snapshot_bytes",
                "publication_stream_count",
                "publication_outbox_count",
                "publication_outbox_bytes",
            ]
        );
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
