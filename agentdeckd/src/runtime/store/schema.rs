//! Runtime SQLite physical schema 与稳定 crypto context。

use std::sync::OnceLock;

use agentdeck_protocol::e2ee::KEY_UPDATE_SET_MAX_CANONICAL_BYTES;
use sha2::{Digest, Sha256};

use super::cipher::ROW_BLOB_V1_OVERHEAD_LEN;

pub const RUNTIME_SCHEMA_FAMILY: &str = "agentdeck-runtime";
pub const RUNTIME_SCHEMA_VERSION_V5: u32 = 5;
pub const RUNTIME_SCHEMA_VERSION_V6: u32 = 6;
pub const RUNTIME_SCHEMA_VERSION_V7: u32 = 7;
pub const RUNTIME_SCHEMA_VERSION_V8: u32 = 8;
pub const RUNTIME_SCHEMA_VERSION_V9: u32 = 9;
pub const RUNTIME_SCHEMA_VERSION_V10: u32 = 10;
pub const RUNTIME_SCHEMA_VERSION_V11: u32 = 11;
pub const RUNTIME_SCHEMA_VERSION_V12: u32 = 12;
pub const RUNTIME_SCHEMA_VERSION_V13: u32 = 13;
pub const RUNTIME_SCHEMA_VERSION_V14: u32 = 14;
pub const RUNTIME_SCHEMA_VERSION: u32 = RUNTIME_SCHEMA_VERSION_V14;
/// 协议允许的最大 canonical KeyUpdateSet；Store admission 与 physical CHECK 共用此事实源。
pub const RUNTIME_KEY_UPDATE_MAX_CANONICAL_BYTES: usize = KEY_UPDATE_SET_MAX_CANONICAL_BYTES;
/// ADKU codec 的最大明文；physical sealed-state CHECK 还必须加固定行密文开销。
pub const RUNTIME_KEY_UPDATE_MAX_PLAINTEXT_BYTES: usize = 1024 * 1024;
pub const RUNTIME_KEY_UPDATE_MAX_SEALED_STATE_BYTES: usize =
    RUNTIME_KEY_UPDATE_MAX_PLAINTEXT_BYTES + ROW_BLOB_V1_OVERHEAD_LEN;
/// 行密文与 wrapped key bundle 的 AAD context 版本。
///
/// physical schema migration 只增表/增认证计数，不得让既有行重新加密或重新包装。
pub const RUNTIME_CRYPTO_CONTEXT_VERSION: u32 = 1;
pub const RUNTIME_KEY_GENERATION: u32 = 1;
#[cfg_attr(not(test), allow(dead_code))]
pub const MAX_CONFIGURATION_BYTES: usize = 16 * 1024;
#[cfg_attr(not(test), allow(dead_code))]
pub const MAX_CONFIGURATION_REQUEST_BYTES: usize = 32 * 1024;
#[cfg_attr(not(test), allow(dead_code))]
pub const MAX_CONFIGURATION_VERSIONS_PER_CONVERSATION: u64 = 4_096;
#[cfg_attr(not(test), allow(dead_code))]
pub const MAX_CONFIGURATION_VERSIONS_GLOBAL: u64 = 65_536;
#[cfg_attr(not(test), allow(dead_code))]
pub const MAX_CONFIGURATION_SEALED_BYTES_GLOBAL: u64 = 64 * 1024 * 1024;
#[cfg_attr(not(test), allow(dead_code))]
pub const MAX_COMMAND_CONFIGURATION_PINS: u64 = 1_048_576;
#[cfg_attr(not(test), allow(dead_code))]
pub const MAX_METADATA_MUTATION_REQUEST_BYTES: usize = 16 * 1024;
#[cfg_attr(not(test), allow(dead_code))]
pub const MAX_METADATA_MUTATION_OUTCOME_BYTES: usize = 16 * 1024;
#[cfg_attr(not(test), allow(dead_code))]
pub const MAX_METADATA_MUTATIONS_PER_CONVERSATION: u64 = 4_096;
#[cfg_attr(not(test), allow(dead_code))]
pub const MAX_METADATA_MUTATIONS_GLOBAL: u64 = 65_536;
#[cfg_attr(not(test), allow(dead_code))]
pub const MAX_ACTIVE_METADATA_MUTATIONS: u64 = 1_024;
#[cfg_attr(not(test), allow(dead_code))]
pub const MAX_METADATA_MUTATION_CHARGED_BYTES_GLOBAL: u64 = 64 * 1024 * 1024;
pub const MAX_ADMIN_COMMAND_REQUEST_BYTES: usize = 16 * 1024;
pub const MAX_ADMIN_COMMAND_OUTCOME_BYTES: usize = 16 * 1024;
pub const MAX_ADMIN_COMMANDS: u64 = 65_536;
pub const MAX_PENDING_ADMIN_COMMANDS: u64 = 1_024;
pub const MAX_ADMIN_COMMAND_CHARGED_BYTES: u64 = 64 * 1024 * 1024;
pub const ADMIN_COMMAND_RETENTION_MS: u64 = 30 * 24 * 60 * 60 * 1_000;
#[cfg_attr(not(test), allow(dead_code))]
pub const RUNTIME_LEDGER_DOMAIN_V4: &[u8] = b"runtime.meta.ledger.v4";
#[cfg_attr(not(test), allow(dead_code))]
pub const RUNTIME_LEDGER_DOMAIN_V5: &[u8] = b"runtime.meta.ledger.v5";
#[cfg_attr(not(test), allow(dead_code))]
pub const RUNTIME_LEDGER_DOMAIN_V6: &[u8] = b"runtime.meta.ledger.v6";
#[cfg_attr(not(test), allow(dead_code))]
pub const RUNTIME_LEDGER_DOMAIN_V7: &[u8] = b"runtime.meta.ledger.v7";
#[cfg_attr(not(test), allow(dead_code))]
pub const RUNTIME_LEDGER_DOMAIN_V8: &[u8] = b"runtime.meta.ledger.v8";
#[cfg_attr(not(test), allow(dead_code))]
pub const RUNTIME_LEDGER_DOMAIN_V9: &[u8] = b"runtime.meta.ledger.v9";
#[cfg_attr(not(test), allow(dead_code))]
pub const RUNTIME_LEDGER_DOMAIN_V10: &[u8] = b"runtime.meta.ledger.v10";
#[cfg_attr(not(test), allow(dead_code))]
pub const RUNTIME_LEDGER_DOMAIN_V11: &[u8] = b"runtime.meta.ledger.v11";
#[cfg_attr(not(test), allow(dead_code))]
pub const RUNTIME_LEDGER_DOMAIN_V12: &[u8] = b"runtime.meta.ledger.v12";
#[cfg_attr(not(test), allow(dead_code))]
pub const RUNTIME_LEDGER_DOMAIN_V13: &[u8] = b"runtime.meta.ledger.v13";
#[cfg_attr(not(test), allow(dead_code))]
pub const RUNTIME_LEDGER_DOMAIN_V14: &[u8] = b"runtime.meta.ledger.v14";
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
pub const EXPECTED_TABLES_V4: [&str; 16] = [
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
pub const EXPECTED_TABLES_V5: [&str; 20] = [
    "approval_ledger",
    "catalog_journal",
    "claude_code_adapter_state",
    "codex_adapter_state",
    "command_configuration_pins",
    "commands",
    "configuration_journal",
    "conversation_state",
    "conversations",
    "event_journal",
    "event_retention",
    "event_stream_index",
    "execution_fences",
    "execution_intents",
    "machine_enrollment_receipts",
    "metadata_mutation_ledger",
    "publication_outbox",
    "publication_streams",
    "runtime_meta",
    "snapshots",
];
pub const EXPECTED_TABLES_V6: [&str; 22] = [
    "approval_ledger",
    "catalog_journal",
    "claude_code_adapter_state",
    "codex_adapter_state",
    "command_configuration_pins",
    "commands",
    "configuration_journal",
    "conversation_state",
    "conversations",
    "event_journal",
    "event_retention",
    "event_stream_index",
    "execution_fences",
    "execution_intents",
    "machine_enrollment_receipts",
    "metadata_mutation_ledger",
    "native_metadata_effect_fences",
    "native_projection_state",
    "publication_outbox",
    "publication_streams",
    "runtime_meta",
    "snapshots",
];
pub const EXPECTED_TABLES_V7: [&str; 23] = [
    "admin_commands",
    "approval_ledger",
    "catalog_journal",
    "claude_code_adapter_state",
    "codex_adapter_state",
    "command_configuration_pins",
    "commands",
    "configuration_journal",
    "conversation_state",
    "conversations",
    "event_journal",
    "event_retention",
    "event_stream_index",
    "execution_fences",
    "execution_intents",
    "machine_enrollment_receipts",
    "metadata_mutation_ledger",
    "native_metadata_effect_fences",
    "native_projection_state",
    "publication_outbox",
    "publication_streams",
    "runtime_meta",
    "snapshots",
];
pub const EXPECTED_TABLES_V8: [&str; 24] = [
    "admin_commands",
    "approval_ledger",
    "catalog_journal",
    "claude_code_adapter_state",
    "codex_adapter_state",
    "command_configuration_pins",
    "commands",
    "configuration_journal",
    "conversation_state",
    "conversations",
    "event_journal",
    "event_retention",
    "event_stream_index",
    "execution_fences",
    "execution_intents",
    "machine_enrollment_receipts",
    "machine_identity_state",
    "metadata_mutation_ledger",
    "native_metadata_effect_fences",
    "native_projection_state",
    "publication_outbox",
    "publication_streams",
    "runtime_meta",
    "snapshots",
];
pub const EXPECTED_TABLES_V9: [&str; 25] = [
    "admin_commands",
    "approval_ledger",
    "catalog_journal",
    "claude_code_adapter_state",
    "codex_adapter_state",
    "command_configuration_pins",
    "commands",
    "configuration_journal",
    "conversation_state",
    "conversations",
    "event_journal",
    "event_retention",
    "event_stream_index",
    "execution_fences",
    "execution_intents",
    "machine_enrollment_receipts",
    "machine_identity_state",
    "machine_remote_state",
    "metadata_mutation_ledger",
    "native_metadata_effect_fences",
    "native_projection_state",
    "publication_outbox",
    "publication_streams",
    "runtime_meta",
    "snapshots",
];
pub const EXPECTED_TABLES_V10: [&str; 30] = [
    "admin_commands",
    "approval_ledger",
    "catalog_journal",
    "claude_code_adapter_state",
    "codex_adapter_state",
    "command_configuration_pins",
    "commands",
    "configuration_journal",
    "conversation_state",
    "conversations",
    "event_journal",
    "event_retention",
    "event_stream_index",
    "execution_fences",
    "execution_intents",
    "machine_enrollment_receipts",
    "machine_identity_state",
    "machine_remote_state",
    "metadata_mutation_ledger",
    "native_metadata_effect_fences",
    "native_projection_state",
    "publication_outbox",
    "publication_streams",
    "remote_authorization_ledger",
    "remote_control_outbox",
    "remote_key_directory",
    "remote_pairing_receipts",
    "remote_pairings",
    "runtime_meta",
    "snapshots",
];
pub const EXPECTED_TABLES_V11: [&str; 32] = [
    "admin_commands",
    "approval_ledger",
    "catalog_journal",
    "claude_code_adapter_state",
    "codex_adapter_state",
    "command_configuration_pins",
    "commands",
    "configuration_journal",
    "conversation_state",
    "conversations",
    "event_journal",
    "event_retention",
    "event_stream_index",
    "execution_fences",
    "execution_intents",
    "machine_enrollment_receipts",
    "machine_identity_state",
    "machine_remote_state",
    "metadata_mutation_ledger",
    "native_metadata_effect_fences",
    "native_projection_state",
    "publication_outbox",
    "publication_streams",
    "remote_authorization_ledger",
    "remote_control_outbox",
    "remote_counter_states",
    "remote_key_directory",
    "remote_pairing_receipts",
    "remote_pairings",
    "remote_replay_states",
    "runtime_meta",
    "snapshots",
];
pub const EXPECTED_TABLES_V12: [&str; 35] = [
    "admin_commands",
    "approval_ledger",
    "catalog_journal",
    "claude_code_adapter_state",
    "codex_adapter_state",
    "command_configuration_pins",
    "commands",
    "configuration_journal",
    "conversation_state",
    "conversations",
    "event_journal",
    "event_retention",
    "event_stream_index",
    "execution_fences",
    "execution_intents",
    "machine_enrollment_receipts",
    "machine_identity_state",
    "machine_remote_state",
    "metadata_mutation_ledger",
    "native_metadata_effect_fences",
    "native_projection_state",
    "publication_outbox",
    "publication_streams",
    "remote_authorization_ledger",
    "remote_control_outbox",
    "remote_counter_guard_manifest",
    "remote_counter_states",
    "remote_key_directory",
    "remote_key_transitions",
    "remote_key_update_outbox",
    "remote_pairing_receipts",
    "remote_pairings",
    "remote_replay_states",
    "runtime_meta",
    "snapshots",
];
pub const EXPECTED_TABLES_V13: [&str; 35] = EXPECTED_TABLES_V12;
pub const EXPECTED_TABLES_V14: [&str; 35] = EXPECTED_TABLES_V13;
pub const EXPECTED_TABLES: [&str; 35] = EXPECTED_TABLES_V14;

pub fn schema_signature() -> [u8; 32] {
    schema_signature_v14()
}

pub fn schema_signature_v14() -> [u8; 32] {
    static SIGNATURE: OnceLock<[u8; 32]> = OnceLock::new();
    *SIGNATURE.get_or_init(|| {
        let mut digest = Sha256::new();
        digest.update(RUNTIME_DDL_V1.as_bytes());
        digest.update(RUNTIME_MIGRATION_V2.as_bytes());
        digest.update(RUNTIME_MIGRATION_V3.as_bytes());
        digest.update(RUNTIME_MIGRATION_V4.as_bytes());
        digest.update(RUNTIME_MIGRATION_V5.as_bytes());
        digest.update(RUNTIME_MIGRATION_V6.as_bytes());
        digest.update(RUNTIME_MIGRATION_V7.as_bytes());
        digest.update(RUNTIME_MIGRATION_V8.as_bytes());
        digest.update(RUNTIME_MIGRATION_V9.as_bytes());
        digest.update(RUNTIME_MIGRATION_V10.as_bytes());
        digest.update(RUNTIME_MIGRATION_V11.as_bytes());
        digest.update(RUNTIME_MIGRATION_V12.as_bytes());
        digest.update(RUNTIME_MIGRATION_V13.as_bytes());
        digest.update(RUNTIME_MIGRATION_V14.as_bytes());
        digest.finalize().into()
    })
}

pub fn schema_signature_v13() -> [u8; 32] {
    static SIGNATURE: OnceLock<[u8; 32]> = OnceLock::new();
    *SIGNATURE.get_or_init(|| {
        let mut digest = Sha256::new();
        digest.update(RUNTIME_DDL_V1.as_bytes());
        digest.update(RUNTIME_MIGRATION_V2.as_bytes());
        digest.update(RUNTIME_MIGRATION_V3.as_bytes());
        digest.update(RUNTIME_MIGRATION_V4.as_bytes());
        digest.update(RUNTIME_MIGRATION_V5.as_bytes());
        digest.update(RUNTIME_MIGRATION_V6.as_bytes());
        digest.update(RUNTIME_MIGRATION_V7.as_bytes());
        digest.update(RUNTIME_MIGRATION_V8.as_bytes());
        digest.update(RUNTIME_MIGRATION_V9.as_bytes());
        digest.update(RUNTIME_MIGRATION_V10.as_bytes());
        digest.update(RUNTIME_MIGRATION_V11.as_bytes());
        digest.update(RUNTIME_MIGRATION_V12.as_bytes());
        digest.update(RUNTIME_MIGRATION_V13.as_bytes());
        digest.finalize().into()
    })
}

pub fn schema_signature_v12() -> [u8; 32] {
    static SIGNATURE: OnceLock<[u8; 32]> = OnceLock::new();
    *SIGNATURE.get_or_init(|| {
        let mut digest = Sha256::new();
        digest.update(RUNTIME_DDL_V1.as_bytes());
        digest.update(RUNTIME_MIGRATION_V2.as_bytes());
        digest.update(RUNTIME_MIGRATION_V3.as_bytes());
        digest.update(RUNTIME_MIGRATION_V4.as_bytes());
        digest.update(RUNTIME_MIGRATION_V5.as_bytes());
        digest.update(RUNTIME_MIGRATION_V6.as_bytes());
        digest.update(RUNTIME_MIGRATION_V7.as_bytes());
        digest.update(RUNTIME_MIGRATION_V8.as_bytes());
        digest.update(RUNTIME_MIGRATION_V9.as_bytes());
        digest.update(RUNTIME_MIGRATION_V10.as_bytes());
        digest.update(RUNTIME_MIGRATION_V11.as_bytes());
        digest.update(RUNTIME_MIGRATION_V12.as_bytes());
        digest.finalize().into()
    })
}

pub fn schema_signature_v11() -> [u8; 32] {
    static SIGNATURE: OnceLock<[u8; 32]> = OnceLock::new();
    *SIGNATURE.get_or_init(|| {
        let mut digest = Sha256::new();
        digest.update(RUNTIME_DDL_V1.as_bytes());
        digest.update(RUNTIME_MIGRATION_V2.as_bytes());
        digest.update(RUNTIME_MIGRATION_V3.as_bytes());
        digest.update(RUNTIME_MIGRATION_V4.as_bytes());
        digest.update(RUNTIME_MIGRATION_V5.as_bytes());
        digest.update(RUNTIME_MIGRATION_V6.as_bytes());
        digest.update(RUNTIME_MIGRATION_V7.as_bytes());
        digest.update(RUNTIME_MIGRATION_V8.as_bytes());
        digest.update(RUNTIME_MIGRATION_V9.as_bytes());
        digest.update(RUNTIME_MIGRATION_V10.as_bytes());
        digest.update(RUNTIME_MIGRATION_V11.as_bytes());
        digest.finalize().into()
    })
}

pub fn schema_signature_v10() -> [u8; 32] {
    static SIGNATURE: OnceLock<[u8; 32]> = OnceLock::new();
    *SIGNATURE.get_or_init(|| {
        let mut digest = Sha256::new();
        digest.update(RUNTIME_DDL_V1.as_bytes());
        digest.update(RUNTIME_MIGRATION_V2.as_bytes());
        digest.update(RUNTIME_MIGRATION_V3.as_bytes());
        digest.update(RUNTIME_MIGRATION_V4.as_bytes());
        digest.update(RUNTIME_MIGRATION_V5.as_bytes());
        digest.update(RUNTIME_MIGRATION_V6.as_bytes());
        digest.update(RUNTIME_MIGRATION_V7.as_bytes());
        digest.update(RUNTIME_MIGRATION_V8.as_bytes());
        digest.update(RUNTIME_MIGRATION_V9.as_bytes());
        digest.update(RUNTIME_MIGRATION_V10.as_bytes());
        digest.finalize().into()
    })
}

pub fn schema_signature_v9() -> [u8; 32] {
    static SIGNATURE: OnceLock<[u8; 32]> = OnceLock::new();
    *SIGNATURE.get_or_init(|| {
        let mut digest = Sha256::new();
        digest.update(RUNTIME_DDL_V1.as_bytes());
        digest.update(RUNTIME_MIGRATION_V2.as_bytes());
        digest.update(RUNTIME_MIGRATION_V3.as_bytes());
        digest.update(RUNTIME_MIGRATION_V4.as_bytes());
        digest.update(RUNTIME_MIGRATION_V5.as_bytes());
        digest.update(RUNTIME_MIGRATION_V6.as_bytes());
        digest.update(RUNTIME_MIGRATION_V7.as_bytes());
        digest.update(RUNTIME_MIGRATION_V8.as_bytes());
        digest.update(RUNTIME_MIGRATION_V9.as_bytes());
        digest.finalize().into()
    })
}

pub fn schema_signature_v8() -> [u8; 32] {
    static SIGNATURE: OnceLock<[u8; 32]> = OnceLock::new();
    *SIGNATURE.get_or_init(|| {
        let mut digest = Sha256::new();
        digest.update(RUNTIME_DDL_V1.as_bytes());
        digest.update(RUNTIME_MIGRATION_V2.as_bytes());
        digest.update(RUNTIME_MIGRATION_V3.as_bytes());
        digest.update(RUNTIME_MIGRATION_V4.as_bytes());
        digest.update(RUNTIME_MIGRATION_V5.as_bytes());
        digest.update(RUNTIME_MIGRATION_V6.as_bytes());
        digest.update(RUNTIME_MIGRATION_V7.as_bytes());
        digest.update(RUNTIME_MIGRATION_V8.as_bytes());
        digest.finalize().into()
    })
}

pub fn schema_signature_v7() -> [u8; 32] {
    static SIGNATURE: OnceLock<[u8; 32]> = OnceLock::new();
    *SIGNATURE.get_or_init(|| {
        let mut digest = Sha256::new();
        digest.update(RUNTIME_DDL_V1.as_bytes());
        digest.update(RUNTIME_MIGRATION_V2.as_bytes());
        digest.update(RUNTIME_MIGRATION_V3.as_bytes());
        digest.update(RUNTIME_MIGRATION_V4.as_bytes());
        digest.update(RUNTIME_MIGRATION_V5.as_bytes());
        digest.update(RUNTIME_MIGRATION_V6.as_bytes());
        digest.update(RUNTIME_MIGRATION_V7.as_bytes());
        digest.finalize().into()
    })
}

pub fn schema_signature_v6() -> [u8; 32] {
    static SIGNATURE: OnceLock<[u8; 32]> = OnceLock::new();
    *SIGNATURE.get_or_init(|| {
        let mut digest = Sha256::new();
        digest.update(RUNTIME_DDL_V1.as_bytes());
        digest.update(RUNTIME_MIGRATION_V2.as_bytes());
        digest.update(RUNTIME_MIGRATION_V3.as_bytes());
        digest.update(RUNTIME_MIGRATION_V4.as_bytes());
        digest.update(RUNTIME_MIGRATION_V5.as_bytes());
        digest.update(RUNTIME_MIGRATION_V6.as_bytes());
        digest.finalize().into()
    })
}

pub fn schema_signature_v5() -> [u8; 32] {
    static SIGNATURE: OnceLock<[u8; 32]> = OnceLock::new();
    *SIGNATURE.get_or_init(|| {
        let mut digest = Sha256::new();
        digest.update(RUNTIME_DDL_V1.as_bytes());
        digest.update(RUNTIME_MIGRATION_V2.as_bytes());
        digest.update(RUNTIME_MIGRATION_V3.as_bytes());
        digest.update(RUNTIME_MIGRATION_V4.as_bytes());
        digest.update(RUNTIME_MIGRATION_V5.as_bytes());
        digest.finalize().into()
    })
}

pub fn schema_signature_v4() -> [u8; 32] {
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
    sealed_snapshot_sha256 BLOB NOT NULL
        CHECK(typeof(sealed_snapshot_sha256) = 'blob'
              AND length(sealed_snapshot_sha256) = 32),
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
    last_acknowledged_publication_id BLOB CHECK(
        last_acknowledged_publication_id IS NULL OR (
            typeof(last_acknowledged_publication_id) = 'blob'
            AND length(last_acknowledged_publication_id) = 16
        )
    ),
    last_acknowledged_request_digest BLOB CHECK(
        last_acknowledged_request_digest IS NULL OR (
            typeof(last_acknowledged_request_digest) = 'blob'
            AND length(last_acknowledged_request_digest) = 32
        )
    ),
    last_rotation_request_digest BLOB CHECK(
        last_rotation_request_digest IS NULL OR (
            typeof(last_rotation_request_digest) = 'blob'
            AND length(last_rotation_request_digest) = 32
        )
    ),
    rotation_serial TEXT NOT NULL CHECK(
        typeof(rotation_serial) = 'text' AND length(rotation_serial) = 20
        AND rotation_serial NOT GLOB '*[^0-9]*'
        AND rotation_serial <= '18446744073709551615'
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
    CHECK((last_acknowledged_publication_id IS NULL
           AND last_acknowledged_request_digest IS NULL)
       OR (last_acknowledged_publication_id IS NOT NULL
           AND last_acknowledged_request_digest IS NOT NULL)),
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

/// B1a 只冻结 additive v5 physical shape；B1b 才把 current production schema
/// version、migration dispatch 与 authenticated row materialization 原子切到 v5。
#[cfg_attr(not(test), allow(dead_code))]
pub const RUNTIME_MIGRATION_V5: &str = r#"
ALTER TABLE runtime_meta ADD COLUMN configuration_count INTEGER NOT NULL DEFAULT 0
    CHECK(configuration_count BETWEEN 0 AND 65536);
ALTER TABLE runtime_meta ADD COLUMN configuration_sealed_bytes INTEGER NOT NULL DEFAULT 0
    CHECK(configuration_sealed_bytes BETWEEN 0 AND 67108864)
    CHECK((configuration_count = 0 AND configuration_sealed_bytes = 0)
       OR (configuration_count > 0 AND configuration_sealed_bytes > 0));
ALTER TABLE runtime_meta ADD COLUMN command_configuration_pin_count INTEGER NOT NULL DEFAULT 0
    CHECK(command_configuration_pin_count BETWEEN 0 AND 1048576)
    CHECK(command_configuration_pin_count <= command_count);
ALTER TABLE runtime_meta ADD COLUMN metadata_mutation_count INTEGER NOT NULL DEFAULT 0
    CHECK(metadata_mutation_count BETWEEN 0 AND 65536);
ALTER TABLE runtime_meta ADD COLUMN active_metadata_mutation_count INTEGER NOT NULL DEFAULT 0
    CHECK(active_metadata_mutation_count BETWEEN 0 AND 1024)
    CHECK(active_metadata_mutation_count <= metadata_mutation_count);
ALTER TABLE runtime_meta ADD COLUMN metadata_mutation_charged_bytes INTEGER NOT NULL DEFAULT 0
    CHECK(metadata_mutation_charged_bytes BETWEEN 0 AND 67108864)
    CHECK((metadata_mutation_count = 0 AND metadata_mutation_charged_bytes = 0)
       OR (metadata_mutation_count > 0 AND metadata_mutation_charged_bytes > 0));

CREATE TABLE configuration_journal (
    conversation_id BLOB NOT NULL
        CHECK(typeof(conversation_id) = 'blob' AND length(conversation_id) = 16),
    configuration_revision TEXT NOT NULL CHECK(
        typeof(configuration_revision) = 'text'
        AND length(configuration_revision) = 20
        AND configuration_revision NOT GLOB '*[^0-9]*'
        AND configuration_revision > '00000000000000000000'
        AND configuration_revision <= '18446744073709551615'
    ),
    base_configuration_revision TEXT NOT NULL CHECK(
        typeof(base_configuration_revision) = 'text'
        AND length(base_configuration_revision) = 20
        AND base_configuration_revision NOT GLOB '*[^0-9]*'
        AND base_configuration_revision <= '18446744073709551615'
        AND base_configuration_revision < configuration_revision
    ),
    event_seq TEXT NOT NULL CHECK(
        typeof(event_seq) = 'text' AND length(event_seq) = 20
        AND event_seq NOT GLOB '*[^0-9]*'
        AND event_seq <= '18446744073709551615'
    ),
    owner_token BLOB NOT NULL
        CHECK(typeof(owner_token) = 'blob' AND length(owner_token) = 32),
    idempotency_token BLOB NOT NULL
        CHECK(typeof(idempotency_token) = 'blob' AND length(idempotency_token) = 32),
    request_token BLOB NOT NULL
        CHECK(typeof(request_token) = 'blob' AND length(request_token) = 32),
    logical_configuration_bytes INTEGER NOT NULL
        CHECK(logical_configuration_bytes BETWEEN 1 AND 16384),
    logical_request_bytes INTEGER NOT NULL
        CHECK(logical_request_bytes BETWEEN 1 AND 32768)
        CHECK(logical_configuration_bytes <= logical_request_bytes),
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
    metadata_token BLOB NOT NULL
        CHECK(typeof(metadata_token) = 'blob' AND length(metadata_token) = 32),
    sealed_request BLOB NOT NULL CHECK(
        typeof(sealed_request) = 'blob'
        AND length(sealed_request) BETWEEN 40 AND 32808
        AND length(sealed_request) = logical_request_bytes + 40
    ),
    PRIMARY KEY(conversation_id, configuration_revision),
    FOREIGN KEY(conversation_id) REFERENCES conversations(conversation_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    FOREIGN KEY(conversation_id, event_seq)
        REFERENCES event_journal(conversation_id, event_seq)
        ON UPDATE RESTRICT ON DELETE RESTRICT
);
CREATE UNIQUE INDEX idx_configuration_event
    ON configuration_journal(conversation_id, event_seq);
CREATE UNIQUE INDEX idx_configuration_idempotency
    ON configuration_journal(idempotency_token);

CREATE TABLE conversation_state (
    conversation_id BLOB PRIMARY KEY
        CHECK(typeof(conversation_id) = 'blob' AND length(conversation_id) = 16),
    current_configuration_revision TEXT CHECK(
        current_configuration_revision IS NULL OR (
            typeof(current_configuration_revision) = 'text'
            AND length(current_configuration_revision) = 20
            AND current_configuration_revision NOT GLOB '*[^0-9]*'
            AND current_configuration_revision <> '00000000000000000000'
            AND current_configuration_revision <= '18446744073709551615'
        )
    ),
    entry_revision TEXT NOT NULL CHECK(
        typeof(entry_revision) = 'text' AND length(entry_revision) = 20
        AND entry_revision NOT GLOB '*[^0-9]*'
        AND entry_revision <= '18446744073709551615'
    ),
    origin_kind TEXT NOT NULL CHECK(origin_kind IN ('managed', 'nativeProjected')),
    origin_namespace TEXT CHECK(
        origin_namespace IS NULL OR (
            typeof(origin_namespace) = 'text'
            AND length(CAST(origin_namespace AS BLOB)) BETWEEN 1 AND 64
            AND instr(origin_namespace, char(0)) = 0
        )
    ),
    legacy_command_high_water TEXT CHECK(
        legacy_command_high_water IS NULL OR (
            typeof(legacy_command_high_water) = 'text'
            AND length(legacy_command_high_water) = 20
            AND legacy_command_high_water NOT GLOB '*[^0-9]*'
            AND legacy_command_high_water <= '18446744073709551615'
        )
    ),
    metadata_token BLOB NOT NULL
        CHECK(typeof(metadata_token) = 'blob' AND length(metadata_token) = 32),
    CHECK((origin_kind = 'managed' AND origin_namespace IS NULL)
       OR (origin_kind = 'nativeProjected' AND origin_namespace IS NOT NULL)),
    FOREIGN KEY(conversation_id) REFERENCES conversations(conversation_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    FOREIGN KEY(conversation_id, current_configuration_revision)
        REFERENCES configuration_journal(conversation_id, configuration_revision)
        ON UPDATE RESTRICT ON DELETE RESTRICT
);
CREATE INDEX idx_conversation_state_origin
    ON conversation_state(origin_kind, origin_namespace);

CREATE TABLE command_configuration_pins (
    conversation_id BLOB NOT NULL
        CHECK(typeof(conversation_id) = 'blob' AND length(conversation_id) = 16),
    command_seq TEXT NOT NULL CHECK(
        typeof(command_seq) = 'text' AND length(command_seq) = 20
        AND command_seq NOT GLOB '*[^0-9]*'
        AND command_seq <= '18446744073709551615'
    ),
    configuration_revision TEXT NOT NULL CHECK(
        typeof(configuration_revision) = 'text'
        AND length(configuration_revision) = 20
        AND configuration_revision NOT GLOB '*[^0-9]*'
        AND configuration_revision > '00000000000000000000'
        AND configuration_revision <= '18446744073709551615'
    ),
    metadata_token BLOB NOT NULL
        CHECK(typeof(metadata_token) = 'blob' AND length(metadata_token) = 32),
    PRIMARY KEY(conversation_id, command_seq),
    FOREIGN KEY(conversation_id, command_seq)
        REFERENCES commands(conversation_id, command_seq)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    FOREIGN KEY(conversation_id, configuration_revision)
        REFERENCES configuration_journal(conversation_id, configuration_revision)
        ON UPDATE RESTRICT ON DELETE RESTRICT
);
CREATE INDEX idx_command_configuration_pins_configuration
    ON command_configuration_pins(conversation_id, configuration_revision);

CREATE TABLE metadata_mutation_ledger (
    conversation_id BLOB NOT NULL
        CHECK(typeof(conversation_id) = 'blob' AND length(conversation_id) = 16),
    owner_token BLOB NOT NULL
        CHECK(typeof(owner_token) = 'blob' AND length(owner_token) = 32),
    idempotency_token BLOB NOT NULL
        CHECK(typeof(idempotency_token) = 'blob' AND length(idempotency_token) = 32),
    request_token BLOB NOT NULL
        CHECK(typeof(request_token) = 'blob' AND length(request_token) = 32),
    expected_entry_revision TEXT NOT NULL CHECK(
        typeof(expected_entry_revision) = 'text'
        AND length(expected_entry_revision) = 20
        AND expected_entry_revision NOT GLOB '*[^0-9]*'
        AND expected_entry_revision <= '18446744073709551615'
    ),
    applied_entry_revision TEXT CHECK(
        applied_entry_revision IS NULL OR (
            typeof(applied_entry_revision) = 'text'
            AND length(applied_entry_revision) = 20
            AND applied_entry_revision NOT GLOB '*[^0-9]*'
            AND applied_entry_revision > '00000000000000000000'
            AND applied_entry_revision <= '18446744073709551615'
        )
    ),
    applied_catalog_revision TEXT CHECK(
        applied_catalog_revision IS NULL OR (
            typeof(applied_catalog_revision) = 'text'
            AND length(applied_catalog_revision) = 20
            AND applied_catalog_revision NOT GLOB '*[^0-9]*'
            AND applied_catalog_revision > '00000000000000000000'
            AND applied_catalog_revision <= '18446744073709551615'
        )
    ),
    state TEXT NOT NULL CHECK(state IN (
        'claimed', 'applying', 'applied', 'outcomeUnknown', 'failed'
    )),
    logical_request_bytes INTEGER NOT NULL
        CHECK(logical_request_bytes BETWEEN 1 AND 16384),
    logical_outcome_bytes INTEGER NOT NULL
        CHECK(logical_outcome_bytes BETWEEN 0 AND 16384),
    charged_outcome_bytes INTEGER NOT NULL
        CHECK(charged_outcome_bytes BETWEEN 40 AND 16424),
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
    state_changed_at_ms INTEGER NOT NULL CHECK(state_changed_at_ms >= created_at_ms),
    metadata_token BLOB NOT NULL
        CHECK(typeof(metadata_token) = 'blob' AND length(metadata_token) = 32),
    sealed_request BLOB NOT NULL CHECK(
        typeof(sealed_request) = 'blob'
        AND length(sealed_request) BETWEEN 40 AND 16424
        AND length(sealed_request) = logical_request_bytes + 40
    ),
    sealed_outcome BLOB CHECK(
        sealed_outcome IS NULL OR (
            typeof(sealed_outcome) = 'blob'
            AND length(sealed_outcome) BETWEEN 40 AND 16424
            AND length(sealed_outcome) = logical_outcome_bytes + 40
        )
    ),
    PRIMARY KEY(conversation_id, idempotency_token),
    CHECK((applied_entry_revision IS NULL AND applied_catalog_revision IS NULL)
       OR (applied_entry_revision IS NOT NULL AND applied_catalog_revision IS NOT NULL)),
    CHECK((state = 'applied'
           AND applied_entry_revision IS NOT NULL
           AND applied_catalog_revision IS NOT NULL)
       OR (state <> 'applied'
           AND applied_entry_revision IS NULL
           AND applied_catalog_revision IS NULL)),
    CHECK((sealed_outcome IS NULL AND logical_outcome_bytes = 0)
       OR (sealed_outcome IS NOT NULL AND logical_outcome_bytes BETWEEN 1 AND 16384)),
    CHECK((state IN ('claimed', 'applying', 'outcomeUnknown')
           AND sealed_outcome IS NULL
           AND logical_outcome_bytes = 0)
       OR state NOT IN ('claimed', 'applying', 'outcomeUnknown')),
    CHECK((state IN ('claimed', 'applying', 'outcomeUnknown')
           AND charged_outcome_bytes = 16424)
       OR (state IN ('applied', 'failed')
           AND sealed_outcome IS NOT NULL
           AND charged_outcome_bytes = length(sealed_outcome))),
    FOREIGN KEY(conversation_id) REFERENCES conversations(conversation_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT
);
CREATE INDEX idx_metadata_mutation_active
    ON metadata_mutation_ledger(conversation_id, state, state_changed_at_ms)
    WHERE state IN ('claimed', 'applying', 'outcomeUnknown');
CREATE UNIQUE INDEX idx_metadata_mutation_idempotency
    ON metadata_mutation_ledger(idempotency_token);
"#;

/// C-b1 additive v6 physical shape。
///
/// 只追加 authenticated totals 与两张空 sidecar；既有 v5 row、ciphertext、token、
/// metadata MAC、wrapped key bundle 与 crypto context 均不得改写。projection/fence
/// writer 与 streaming audit 属于后续 C-b2/C-c/C-e。
pub const RUNTIME_MIGRATION_V6: &str = r#"
ALTER TABLE runtime_meta ADD COLUMN native_projection_present_count INTEGER NOT NULL DEFAULT 0
    CHECK(native_projection_present_count BETWEEN 0 AND 1024);
ALTER TABLE runtime_meta ADD COLUMN native_projection_tombstone_count INTEGER NOT NULL DEFAULT 0
    CHECK(native_projection_tombstone_count BETWEEN 0 AND 8192);
ALTER TABLE runtime_meta ADD COLUMN native_projection_retired_count INTEGER NOT NULL DEFAULT 0
    CHECK(native_projection_retired_count BETWEEN 0 AND 8192)
    CHECK(native_projection_tombstone_count + native_projection_retired_count <= 8192);
ALTER TABLE runtime_meta ADD COLUMN native_projection_physical_count INTEGER NOT NULL DEFAULT 0
    CHECK(native_projection_physical_count BETWEEN 0 AND 9216)
    CHECK(native_projection_physical_count = native_projection_present_count
        + native_projection_tombstone_count + native_projection_retired_count)
    CHECK(native_projection_physical_count <= conversation_count)
    CHECK(conversation_count >= native_projection_tombstone_count + native_projection_retired_count)
    CHECK(conversation_count - native_projection_tombstone_count
        - native_projection_retired_count <= 1024);
ALTER TABLE runtime_meta ADD COLUMN native_projection_charged_bytes INTEGER NOT NULL DEFAULT 0
    CHECK(native_projection_charged_bytes BETWEEN 0 AND 16777216)
    CHECK((native_projection_present_count + native_projection_tombstone_count = 0
           AND native_projection_charged_bytes = 0)
       OR (native_projection_present_count + native_projection_tombstone_count > 0
           AND native_projection_charged_bytes > 0));
ALTER TABLE runtime_meta ADD COLUMN native_metadata_effect_fence_count INTEGER NOT NULL DEFAULT 0
    CHECK(native_metadata_effect_fence_count BETWEEN 0 AND 65536)
    CHECK(native_metadata_effect_fence_count <= metadata_mutation_count);
ALTER TABLE runtime_meta ADD COLUMN native_metadata_effect_unreleased_count INTEGER NOT NULL DEFAULT 0
    CHECK(native_metadata_effect_unreleased_count BETWEEN 0 AND 1024)
    CHECK(native_metadata_effect_unreleased_count <= native_metadata_effect_fence_count);
ALTER TABLE runtime_meta ADD COLUMN native_metadata_effect_released_count INTEGER NOT NULL DEFAULT 0
    CHECK(native_metadata_effect_released_count BETWEEN 0 AND 65536)
    CHECK(native_metadata_effect_unreleased_count + native_metadata_effect_released_count
        = native_metadata_effect_fence_count);

CREATE TABLE native_projection_state (
    conversation_id BLOB PRIMARY KEY
        CHECK(typeof(conversation_id) = 'blob' AND length(conversation_id) = 16),
    origin_namespace TEXT NOT NULL CHECK(
        typeof(origin_namespace) = 'text'
        AND length(CAST(origin_namespace AS BLOB)) BETWEEN 1 AND 64
        AND instr(origin_namespace, char(0)) = 0
    ),
    state_reference_token BLOB NOT NULL
        CHECK(typeof(state_reference_token) = 'blob' AND length(state_reference_token) = 32),
    projection_state TEXT NOT NULL
        CHECK(projection_state IN ('present', 'tombstone', 'retired')),
    scan_generation BLOB NOT NULL CHECK(
        typeof(scan_generation) = 'blob' AND length(scan_generation) = 16
        AND scan_generation <> X'00000000000000000000000000000000'
    ),
    observation_token BLOB NOT NULL
        CHECK(typeof(observation_token) = 'blob' AND length(observation_token) = 32),
    projection_catalog_revision TEXT NOT NULL CHECK(
        typeof(projection_catalog_revision) = 'text'
        AND length(projection_catalog_revision) = 20
        AND projection_catalog_revision NOT GLOB '*[^0-9]*'
        AND projection_catalog_revision <= '18446744073709551615'
    ),
    reconciled_at_ms INTEGER NOT NULL CHECK(reconciled_at_ms >= 0),
    state_changed_at_ms INTEGER NOT NULL CHECK(state_changed_at_ms >= 0),
    private_binding_retain_until_ms INTEGER CHECK(
        private_binding_retain_until_ms IS NULL OR private_binding_retain_until_ms >= 0
    ),
    charged_reference_bytes INTEGER NOT NULL
        CHECK(charged_reference_bytes BETWEEN 0 AND 563),
    metadata_token BLOB NOT NULL
        CHECK(typeof(metadata_token) = 'blob' AND length(metadata_token) = 32),
    UNIQUE(origin_namespace, state_reference_token),
    CHECK((projection_state = 'present'
           AND state_changed_at_ms <= reconciled_at_ms
           AND private_binding_retain_until_ms IS NULL
           AND charged_reference_bytes BETWEEN 60 AND 563)
       OR (projection_state = 'tombstone'
           AND state_changed_at_ms <= reconciled_at_ms
           AND state_changed_at_ms <= 9223372034262775807
           AND private_binding_retain_until_ms = state_changed_at_ms + 2592000000
           AND charged_reference_bytes BETWEEN 60 AND 563)
       OR (projection_state = 'retired'
           AND private_binding_retain_until_ms IS NOT NULL
           AND state_changed_at_ms >= private_binding_retain_until_ms
           AND charged_reference_bytes = 0)),
    FOREIGN KEY(conversation_id) REFERENCES conversation_state(conversation_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT
);
CREATE INDEX idx_native_projection_scan
    ON native_projection_state(
        origin_namespace, projection_state, scan_generation, conversation_id
    );
CREATE INDEX idx_native_projection_retention
    ON native_projection_state(
        private_binding_retain_until_ms, projection_state, conversation_id
    ) WHERE projection_state IN ('tombstone', 'retired');

CREATE TABLE native_metadata_effect_fences (
    conversation_id BLOB NOT NULL
        CHECK(typeof(conversation_id) = 'blob' AND length(conversation_id) = 16),
    idempotency_token BLOB NOT NULL
        CHECK(typeof(idempotency_token) = 'blob' AND length(idempotency_token) = 32),
    daemon_boot_id BLOB NOT NULL
        CHECK(typeof(daemon_boot_id) = 'blob' AND length(daemon_boot_id) = 16),
    effect_nonce_token BLOB NOT NULL
        CHECK(typeof(effect_nonce_token) = 'blob' AND length(effect_nonce_token) = 32),
    effect_spec_token BLOB NOT NULL
        CHECK(typeof(effect_spec_token) = 'blob' AND length(effect_spec_token) = 32),
    process_group_id INTEGER NOT NULL CHECK(process_group_id > 0),
    leader_pid INTEGER NOT NULL CHECK(leader_pid > 0),
    leader_start_time TEXT NOT NULL CHECK(
        typeof(leader_start_time) = 'text' AND length(leader_start_time) = 20
        AND leader_start_time NOT GLOB '*[^0-9]*'
        AND leader_start_time <= '18446744073709551615'
    ),
    release_authorized_at_ms INTEGER CHECK(
        release_authorized_at_ms IS NULL OR release_authorized_at_ms >= 0
    ),
    release_token_commitment BLOB CHECK(
        (release_authorized_at_ms IS NULL AND release_token_commitment IS NULL)
        OR (release_authorized_at_ms IS NOT NULL
            AND typeof(release_token_commitment) = 'blob'
            AND length(release_token_commitment) = 32)
    ),
    logical_fence_bytes INTEGER NOT NULL CHECK(logical_fence_bytes BETWEEN 126 AND 17532),
    metadata_token BLOB NOT NULL
        CHECK(typeof(metadata_token) = 'blob' AND length(metadata_token) = 32),
    sealed_fence BLOB NOT NULL CHECK(
        typeof(sealed_fence) = 'blob'
        AND length(sealed_fence) BETWEEN 166 AND 17572
        AND length(sealed_fence) = logical_fence_bytes + 40
    ),
    PRIMARY KEY(conversation_id, idempotency_token),
    UNIQUE(daemon_boot_id, effect_nonce_token),
    UNIQUE(daemon_boot_id, process_group_id, leader_start_time),
    FOREIGN KEY(conversation_id, idempotency_token)
        REFERENCES metadata_mutation_ledger(conversation_id, idempotency_token)
        ON UPDATE RESTRICT ON DELETE RESTRICT
);
"#;

/// P3.10-A1 additive v7 physical shape。
///
/// machine-wide admin idempotency 使用独立 ledger，不复用 conversation-scoped
/// `commands`。迁移只追加三项 authenticated totals 与一张空表；既有 row
/// ciphertext、metadata token、wrapped key bundle 与 crypto context 不得改写。
/// admin row 的 AEAD、token、准入、retention 与 streaming audit 属于 A2。
pub const RUNTIME_MIGRATION_V7: &str = r#"
ALTER TABLE runtime_meta ADD COLUMN admin_command_count INTEGER NOT NULL DEFAULT 0
    CHECK(admin_command_count BETWEEN 0 AND 65536);
ALTER TABLE runtime_meta ADD COLUMN admin_command_pending_count INTEGER NOT NULL DEFAULT 0
    CHECK(admin_command_pending_count BETWEEN 0 AND 1024)
    CHECK(admin_command_pending_count <= admin_command_count);
ALTER TABLE runtime_meta ADD COLUMN admin_command_charged_bytes INTEGER NOT NULL DEFAULT 0
    CHECK(admin_command_charged_bytes BETWEEN 0 AND 67108864)
    CHECK((admin_command_count = 0 AND admin_command_charged_bytes = 0)
       OR (admin_command_count > 0 AND admin_command_charged_bytes > 0));

CREATE TABLE admin_commands (
    idempotency_token BLOB PRIMARY KEY
        CHECK(typeof(idempotency_token) = 'blob' AND length(idempotency_token) = 32),
    command_kind TEXT NOT NULL CHECK(command_kind = 'stageUpgrade'),
    request_token BLOB NOT NULL
        CHECK(typeof(request_token) = 'blob' AND length(request_token) = 32),
    state TEXT NOT NULL CHECK(state IN ('pending', 'completed', 'failed')),
    sealed_request BLOB NOT NULL CHECK(
        typeof(sealed_request) = 'blob'
        AND length(sealed_request) BETWEEN 40 AND 16424
    ),
    sealed_outcome BLOB NOT NULL CHECK(
        typeof(sealed_outcome) = 'blob'
        AND length(sealed_outcome) BETWEEN 40 AND 16424
    ),
    created_at_ms INTEGER NOT NULL
        CHECK(created_at_ms BETWEEN 0 AND 9223372034262775807),
    state_changed_at_ms INTEGER NOT NULL CHECK(state_changed_at_ms >= created_at_ms),
    retain_until_ms INTEGER NOT NULL
        CHECK(retain_until_ms >= created_at_ms + 2592000000),
    charged_bytes INTEGER NOT NULL CHECK(
        charged_bytes BETWEEN 80 AND 32848
        AND charged_bytes = length(sealed_request) + length(sealed_outcome)
    ),
    metadata_token BLOB NOT NULL
        CHECK(typeof(metadata_token) = 'blob' AND length(metadata_token) = 32)
);
CREATE INDEX idx_admin_commands_retention
    ON admin_commands(retain_until_ms, idempotency_token);
CREATE INDEX idx_admin_commands_pending
    ON admin_commands(state_changed_at_ms, idempotency_token) WHERE state = 'pending';
"#;

/// P4.1-A additive v8 physical shape。
///
/// 只追加 authenticated singleton identity public binding 与 0/1 ledger count；
/// 既有 row、ciphertext、metadata token、wrapped key bundle 与 crypto context 均不改写。
pub const RUNTIME_MIGRATION_V8: &str = r#"
ALTER TABLE runtime_meta ADD COLUMN machine_identity_count INTEGER NOT NULL DEFAULT 0
    CHECK(machine_identity_count BETWEEN 0 AND 1);

CREATE TABLE machine_identity_state (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    identity_state TEXT NOT NULL CHECK(identity_state IN ('preparing', 'active')),
    database_id BLOB NOT NULL CHECK(typeof(database_id) = 'blob' AND length(database_id) = 16),
    root_key_id BLOB NOT NULL CHECK(
        typeof(root_key_id) = 'blob' AND length(root_key_id) = 16
        AND root_key_id <> X'00000000000000000000000000000000'
    ),
    trust_epoch TEXT NOT NULL CHECK(
        typeof(trust_epoch) = 'text' AND length(trust_epoch) = 20
        AND trust_epoch NOT GLOB '*[^0-9]*'
        AND trust_epoch > '00000000000000000000'
        AND trust_epoch <= '18446744073709551615'
    ),
    link_generation TEXT NOT NULL CHECK(
        typeof(link_generation) = 'text' AND length(link_generation) = 20
        AND link_generation NOT GLOB '*[^0-9]*'
        AND link_generation > '00000000000000000000'
        AND link_generation <= '18446744073709551615'
    ),
    data_generation TEXT NOT NULL CHECK(
        typeof(data_generation) = 'text' AND length(data_generation) = 20
        AND data_generation NOT GLOB '*[^0-9]*'
        AND data_generation > '00000000000000000000'
        AND data_generation <= '18446744073709551615'
    ),
    key_directory_revision TEXT NOT NULL CHECK(
        typeof(key_directory_revision) = 'text' AND length(key_directory_revision) = 20
        AND key_directory_revision NOT GLOB '*[^0-9]*'
        AND key_directory_revision <= '18446744073709551615'
    ),
    root_public_key BLOB NOT NULL
        CHECK(typeof(root_public_key) = 'blob' AND length(root_public_key) = 32
              AND root_public_key <> X'0000000000000000000000000000000000000000000000000000000000000000'),
    root_fingerprint BLOB NOT NULL
        CHECK(typeof(root_fingerprint) = 'blob' AND length(root_fingerprint) = 32),
    machine_hpke_public_key BLOB NOT NULL
        CHECK(typeof(machine_hpke_public_key) = 'blob' AND length(machine_hpke_public_key) = 32
              AND machine_hpke_public_key <> X'0000000000000000000000000000000000000000000000000000000000000000'),
    machine_hpke_fingerprint BLOB NOT NULL
        CHECK(typeof(machine_hpke_fingerprint) = 'blob' AND length(machine_hpke_fingerprint) = 32),
    link_sign_public_key BLOB NOT NULL
        CHECK(typeof(link_sign_public_key) = 'blob' AND length(link_sign_public_key) = 32
              AND link_sign_public_key <> X'0000000000000000000000000000000000000000000000000000000000000000'),
    link_sign_fingerprint BLOB NOT NULL
        CHECK(typeof(link_sign_fingerprint) = 'blob' AND length(link_sign_fingerprint) = 32),
    data_sign_public_key BLOB NOT NULL
        CHECK(typeof(data_sign_public_key) = 'blob' AND length(data_sign_public_key) = 32
              AND data_sign_public_key <> X'0000000000000000000000000000000000000000000000000000000000000000'),
    data_sign_fingerprint BLOB NOT NULL
        CHECK(typeof(data_sign_fingerprint) = 'blob' AND length(data_sign_fingerprint) = 32),
    metadata_token BLOB NOT NULL
        CHECK(typeof(metadata_token) = 'blob' AND length(metadata_token) = 32)
);
"#;

/// P4.2-A additive v9 physical shape。
///
/// 只追加 authenticated remote lifecycle singleton 与 0/1 ledger count；状态内容只允许存在于
/// 有界 sealed blob，既有 row、ciphertext、metadata token、wrapped key bundle 与 crypto context
/// 均不改写。
pub const RUNTIME_MIGRATION_V9: &str = r#"
ALTER TABLE runtime_meta ADD COLUMN machine_remote_state_count INTEGER NOT NULL DEFAULT 0
    CHECK(machine_remote_state_count BETWEEN 0 AND 1);

CREATE TABLE machine_remote_state (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    lifecycle TEXT NOT NULL CHECK(lifecycle IN (
        'enrollmentPrepared',
        'enrollmentResponseValidated',
        'active',
        'retirePending',
        'relayCommitted',
        'purgeReadbackAbsent',
        'localDeleted'
    )),
    reset_kind TEXT CHECK(reset_kind IS NULL OR reset_kind IN ('rootPresent', 'rootLost')),
    database_id BLOB NOT NULL CHECK(typeof(database_id) = 'blob' AND length(database_id) = 16),
    relay_server_id BLOB NOT NULL CHECK(
        typeof(relay_server_id) = 'blob' AND length(relay_server_id) = 16
        AND relay_server_id <> X'00000000000000000000000000000000'
    ),
    machine_route BLOB NOT NULL CHECK(
        typeof(machine_route) = 'blob' AND length(machine_route) = 16
        AND machine_route <> X'00000000000000000000000000000000'
    ),
    root_key_id BLOB NOT NULL CHECK(
        typeof(root_key_id) = 'blob' AND length(root_key_id) = 16
        AND root_key_id <> X'00000000000000000000000000000000'
    ),
    root_fingerprint BLOB NOT NULL
        CHECK(typeof(root_fingerprint) = 'blob' AND length(root_fingerprint) = 32
              AND root_fingerprint <> X'0000000000000000000000000000000000000000000000000000000000000000'),
    trust_epoch TEXT NOT NULL CHECK(
        typeof(trust_epoch) = 'text' AND length(trust_epoch) = 20
        AND trust_epoch NOT GLOB '*[^0-9]*'
        AND trust_epoch > '00000000000000000000'
        AND trust_epoch <= '18446744073709551615'
    ),
    request_hash BLOB NOT NULL
        CHECK(typeof(request_hash) = 'blob' AND length(request_hash) = 32
              AND request_hash <> X'0000000000000000000000000000000000000000000000000000000000000000'),
    response_hash BLOB CHECK(
        response_hash IS NULL
        OR (typeof(response_hash) = 'blob' AND length(response_hash) = 32
            AND response_hash <> X'0000000000000000000000000000000000000000000000000000000000000000')
    ),
    enrollment_receipt_hash BLOB CHECK(
        enrollment_receipt_hash IS NULL
        OR (typeof(enrollment_receipt_hash) = 'blob' AND length(enrollment_receipt_hash) = 32
            AND enrollment_receipt_hash <> X'0000000000000000000000000000000000000000000000000000000000000000')
    ),
    receipt_verify_key_hash BLOB NOT NULL
        CHECK(typeof(receipt_verify_key_hash) = 'blob' AND length(receipt_verify_key_hash) = 32
              AND receipt_verify_key_hash <> X'0000000000000000000000000000000000000000000000000000000000000000'),
    sealed_state BLOB NOT NULL CHECK(
        typeof(sealed_state) = 'blob' AND length(sealed_state) BETWEEN 40 AND 65576
    ),
    sealed_state_bytes INTEGER NOT NULL CHECK(
        typeof(sealed_state_bytes) = 'integer'
        AND sealed_state_bytes BETWEEN 40 AND 65576
        AND sealed_state_bytes = length(sealed_state)
    ),
    metadata_token BLOB NOT NULL
        CHECK(typeof(metadata_token) = 'blob' AND length(metadata_token) = 32),
    CHECK(
        (lifecycle IN ('enrollmentPrepared', 'enrollmentResponseValidated', 'active')
            AND reset_kind IS NULL)
        OR (lifecycle IN (
                'retirePending', 'relayCommitted', 'purgeReadbackAbsent', 'localDeleted'
            ) AND reset_kind IS NOT NULL AND reset_kind = 'rootPresent')
        OR (lifecycle IN ('purgeReadbackAbsent', 'localDeleted')
            AND reset_kind IS NOT NULL AND reset_kind = 'rootLost')
    ),
    CHECK(
        (lifecycle = 'enrollmentPrepared'
            AND response_hash IS NULL AND enrollment_receipt_hash IS NULL)
        OR (lifecycle = 'enrollmentResponseValidated'
            AND response_hash IS NOT NULL AND enrollment_receipt_hash IS NULL)
        OR (lifecycle IN (
                'active', 'retirePending', 'relayCommitted', 'purgeReadbackAbsent', 'localDeleted'
            ) AND response_hash IS NOT NULL AND enrollment_receipt_hash IS NOT NULL)
    )
);
"#;

/// P4.3-A additive v10 physical shape。
///
/// 只追加 authenticated pairing/auth/key-directory/control-outbox 表及对应 ledger totals；
/// 既有 row、ciphertext、metadata token、wrapped key bundle 与 crypto context 均不改写。
pub const RUNTIME_MIGRATION_V10: &str = r#"
ALTER TABLE runtime_meta ADD COLUMN remote_pairing_count INTEGER NOT NULL DEFAULT 0
    CHECK(remote_pairing_count BETWEEN 0 AND 8);
ALTER TABLE runtime_meta ADD COLUMN remote_pairing_sealed_bytes INTEGER NOT NULL DEFAULT 0
    CHECK(remote_pairing_sealed_bytes BETWEEN 0 AND 67108864);
ALTER TABLE runtime_meta ADD COLUMN remote_pairing_receipt_count INTEGER NOT NULL DEFAULT 0
    CHECK(remote_pairing_receipt_count BETWEEN 0 AND 65536);
ALTER TABLE runtime_meta ADD COLUMN remote_pairing_receipt_bytes INTEGER NOT NULL DEFAULT 0
    CHECK(remote_pairing_receipt_bytes BETWEEN 0 AND 67108864);

ALTER TABLE runtime_meta ADD COLUMN remote_authorization_count INTEGER NOT NULL DEFAULT 0
    CHECK(remote_authorization_count BETWEEN 0 AND 256);
ALTER TABLE runtime_meta ADD COLUMN remote_authorization_preparing_count INTEGER NOT NULL DEFAULT 0
    CHECK(remote_authorization_preparing_count BETWEEN 0 AND 256);
ALTER TABLE runtime_meta ADD COLUMN remote_authorization_active_count INTEGER NOT NULL DEFAULT 0
    CHECK(remote_authorization_active_count BETWEEN 0 AND 256);
ALTER TABLE runtime_meta ADD COLUMN remote_authorization_revoking_count INTEGER NOT NULL DEFAULT 0
    CHECK(remote_authorization_revoking_count BETWEEN 0 AND 256);
ALTER TABLE runtime_meta ADD COLUMN remote_authorization_revoked_count INTEGER NOT NULL DEFAULT 0
    CHECK(remote_authorization_revoked_count BETWEEN 0 AND 256);
ALTER TABLE runtime_meta ADD COLUMN remote_authorization_sealed_bytes INTEGER NOT NULL DEFAULT 0
    CHECK(remote_authorization_sealed_bytes BETWEEN 0 AND 67108864);

ALTER TABLE runtime_meta ADD COLUMN remote_key_directory_count INTEGER NOT NULL DEFAULT 0
    CHECK(remote_key_directory_count BETWEEN 0 AND 1);
ALTER TABLE runtime_meta ADD COLUMN remote_key_directory_sealed_bytes INTEGER NOT NULL DEFAULT 0
    CHECK(remote_key_directory_sealed_bytes BETWEEN 0 AND 67108864);

ALTER TABLE runtime_meta ADD COLUMN remote_control_outbox_count INTEGER NOT NULL DEFAULT 0
    CHECK(remote_control_outbox_count BETWEEN 0 AND 1024);
ALTER TABLE runtime_meta ADD COLUMN remote_control_outbox_pending_count INTEGER NOT NULL DEFAULT 0
    CHECK(remote_control_outbox_pending_count BETWEEN 0 AND 1024);
ALTER TABLE runtime_meta ADD COLUMN remote_control_outbox_acknowledged_count INTEGER NOT NULL DEFAULT 0
    CHECK(remote_control_outbox_acknowledged_count BETWEEN 0 AND 1024);
ALTER TABLE runtime_meta ADD COLUMN remote_control_outbox_sealed_bytes INTEGER NOT NULL DEFAULT 0
    CHECK(remote_control_outbox_sealed_bytes BETWEEN 0 AND 67108864);

CREATE TABLE remote_pairings (
    pairing_id BLOB PRIMARY KEY NOT NULL CHECK(
        typeof(pairing_id) = 'blob' AND length(pairing_id) = 16
        AND pairing_id <> X'00000000000000000000000000000000'
    ),
    machine_remote_singleton INTEGER NOT NULL DEFAULT 1
        CHECK(machine_remote_singleton = 1),
    lifecycle TEXT NOT NULL CHECK(lifecycle IN (
        'routeOpening', 'unused', 'preparing', 'awaitingLocalConfirmation',
        'grantPreparing', 'grantCommitted', 'orphanRevoking',
        'delivered', 'expired', 'canceled'
    )),
    database_id BLOB NOT NULL CHECK(typeof(database_id) = 'blob' AND length(database_id) = 16),
    relay_server_id BLOB NOT NULL CHECK(
        typeof(relay_server_id) = 'blob' AND length(relay_server_id) = 16
        AND relay_server_id <> X'00000000000000000000000000000000'
    ),
    machine_route BLOB NOT NULL CHECK(
        typeof(machine_route) = 'blob' AND length(machine_route) = 16
        AND machine_route <> X'00000000000000000000000000000000'
    ),
    pair_route BLOB NOT NULL UNIQUE CHECK(
        typeof(pair_route) = 'blob' AND length(pair_route) = 16
        AND pair_route <> X'00000000000000000000000000000000'
    ),
    expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms > 0),
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0 AND created_at_ms < expires_at_ms),
    state_changed_at_ms INTEGER NOT NULL CHECK(state_changed_at_ms >= created_at_ms),
    request_hash BLOB CHECK(
        request_hash IS NULL OR (typeof(request_hash) = 'blob' AND length(request_hash) = 32
            AND request_hash <> X'0000000000000000000000000000000000000000000000000000000000000000')
    ),
    device_sign_fingerprint BLOB CHECK(
        device_sign_fingerprint IS NULL OR (
            typeof(device_sign_fingerprint) = 'blob' AND length(device_sign_fingerprint) = 32
            AND device_sign_fingerprint <> X'0000000000000000000000000000000000000000000000000000000000000000'
        )
    ),
    grant_hash BLOB CHECK(
        grant_hash IS NULL OR (typeof(grant_hash) = 'blob' AND length(grant_hash) = 32
            AND grant_hash <> X'0000000000000000000000000000000000000000000000000000000000000000')
    ),
    response_hash BLOB CHECK(
        response_hash IS NULL OR (typeof(response_hash) = 'blob' AND length(response_hash) = 32
            AND response_hash <> X'0000000000000000000000000000000000000000000000000000000000000000')
    ),
    sealed_state BLOB NOT NULL CHECK(
        typeof(sealed_state) = 'blob' AND length(sealed_state) BETWEEN 40 AND 8388648
    ),
    sealed_state_bytes INTEGER NOT NULL CHECK(
        typeof(sealed_state_bytes) = 'integer' AND sealed_state_bytes = length(sealed_state)
    ),
    metadata_token BLOB NOT NULL CHECK(typeof(metadata_token) = 'blob' AND length(metadata_token) = 32),
    FOREIGN KEY(machine_remote_singleton) REFERENCES machine_remote_state(singleton)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CHECK((request_hash IS NULL AND device_sign_fingerprint IS NULL)
          OR (request_hash IS NOT NULL AND device_sign_fingerprint IS NOT NULL)),
    CHECK(grant_hash IS NULL OR request_hash IS NOT NULL),
    CHECK(response_hash IS NULL OR grant_hash IS NOT NULL),
    CHECK((lifecycle IN ('routeOpening', 'unused')
            AND request_hash IS NULL AND grant_hash IS NULL AND response_hash IS NULL)
          OR (lifecycle IN ('preparing', 'awaitingLocalConfirmation')
            AND request_hash IS NOT NULL AND grant_hash IS NULL AND response_hash IS NULL)
          OR (lifecycle IN ('grantPreparing', 'grantCommitted', 'orphanRevoking', 'delivered')
            AND request_hash IS NOT NULL AND grant_hash IS NOT NULL AND response_hash IS NOT NULL)
          OR lifecycle IN ('expired', 'canceled'))
);
CREATE INDEX idx_remote_pairings_recovery
    ON remote_pairings(lifecycle, expires_at_ms, pairing_id);

CREATE TABLE remote_pairing_receipts (
    pairing_id BLOB PRIMARY KEY NOT NULL CHECK(
        typeof(pairing_id) = 'blob' AND length(pairing_id) = 16
        AND pairing_id <> X'00000000000000000000000000000000'
    ),
    machine_remote_singleton INTEGER NOT NULL DEFAULT 1 CHECK(machine_remote_singleton = 1),
    database_id BLOB NOT NULL CHECK(typeof(database_id) = 'blob' AND length(database_id) = 16),
    relay_server_id BLOB NOT NULL CHECK(
        typeof(relay_server_id) = 'blob' AND length(relay_server_id) = 16
        AND relay_server_id <> X'00000000000000000000000000000000'
    ),
    machine_route BLOB NOT NULL CHECK(
        typeof(machine_route) = 'blob' AND length(machine_route) = 16
        AND machine_route <> X'00000000000000000000000000000000'
    ),
    pair_route BLOB NOT NULL UNIQUE CHECK(
        typeof(pair_route) = 'blob' AND length(pair_route) = 16
        AND pair_route <> X'00000000000000000000000000000000'
    ),
    idempotency_token BLOB NOT NULL CHECK(
        typeof(idempotency_token) = 'blob' AND length(idempotency_token) = 32
        AND idempotency_token <> X'0000000000000000000000000000000000000000000000000000000000000000'
    ),
    input_hash BLOB NOT NULL CHECK(
        typeof(input_hash) = 'blob' AND length(input_hash) = 32
        AND input_hash <> X'0000000000000000000000000000000000000000000000000000000000000000'
    ),
    action TEXT NOT NULL CHECK(action IN ('confirmed', 'canceled', 'expired')),
    request_hash BLOB CHECK(
        request_hash IS NULL OR (typeof(request_hash) = 'blob' AND length(request_hash) = 32
            AND request_hash <> X'0000000000000000000000000000000000000000000000000000000000000000')
    ),
    receipt_hash BLOB NOT NULL CHECK(
        typeof(receipt_hash) = 'blob' AND length(receipt_hash) = 32
        AND receipt_hash <> X'0000000000000000000000000000000000000000000000000000000000000000'
    ),
    canonical_receipt BLOB NOT NULL CHECK(
        typeof(canonical_receipt) = 'blob' AND length(canonical_receipt) BETWEEN 1 AND 65536
    ),
    receipt_bytes INTEGER NOT NULL CHECK(
        typeof(receipt_bytes) = 'integer' AND receipt_bytes = length(canonical_receipt)
    ),
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
    retain_until_ms INTEGER NOT NULL CHECK(
        retain_until_ms >= created_at_ms + 2592000000
        AND created_at_ms <= 9223372034262775807
    ),
    metadata_token BLOB NOT NULL CHECK(typeof(metadata_token) = 'blob' AND length(metadata_token) = 32),
    FOREIGN KEY(machine_remote_singleton) REFERENCES machine_remote_state(singleton)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CHECK(action <> 'confirmed' OR request_hash IS NOT NULL)
);
CREATE UNIQUE INDEX idx_remote_pairing_receipts_idempotency
    ON remote_pairing_receipts(idempotency_token);
CREATE INDEX idx_remote_pairing_receipts_retention
    ON remote_pairing_receipts(retain_until_ms, pairing_id);

CREATE TABLE remote_authorization_ledger (
    device_route BLOB NOT NULL CHECK(
        typeof(device_route) = 'blob' AND length(device_route) = 16
        AND device_route <> X'00000000000000000000000000000000'
    ),
    grant_serial TEXT NOT NULL CHECK(
        typeof(grant_serial) = 'text' AND length(grant_serial) = 20
        AND grant_serial NOT GLOB '*[^0-9]*'
        AND grant_serial > '00000000000000000000'
        AND grant_serial <= '18446744073709551615'
    ),
    machine_remote_singleton INTEGER NOT NULL DEFAULT 1 CHECK(machine_remote_singleton = 1),
    lifecycle TEXT NOT NULL CHECK(
        lifecycle IN ('grantPreparing', 'active', 'superseded', 'revoking', 'revoked')
    ),
    database_id BLOB NOT NULL CHECK(typeof(database_id) = 'blob' AND length(database_id) = 16),
    device_sign_fingerprint BLOB NOT NULL CHECK(
        typeof(device_sign_fingerprint) = 'blob' AND length(device_sign_fingerprint) = 32
        AND device_sign_fingerprint <> X'0000000000000000000000000000000000000000000000000000000000000000'
    ),
    grant_hash BLOB NOT NULL CHECK(
        typeof(grant_hash) = 'blob' AND length(grant_hash) = 32
        AND grant_hash <> X'0000000000000000000000000000000000000000000000000000000000000000'
    ),
    authorization_hash BLOB NOT NULL CHECK(
        typeof(authorization_hash) = 'blob' AND length(authorization_hash) = 32
        AND authorization_hash <> X'0000000000000000000000000000000000000000000000000000000000000000'
    ),
    key_directory_revision TEXT NOT NULL CHECK(
        typeof(key_directory_revision) = 'text' AND length(key_directory_revision) = 20
        AND key_directory_revision NOT GLOB '*[^0-9]*'
        AND key_directory_revision > '00000000000000000000'
        AND key_directory_revision <= '18446744073709551615'
    ),
    sealed_authorization BLOB NOT NULL CHECK(
        typeof(sealed_authorization) = 'blob' AND length(sealed_authorization) BETWEEN 40 AND 262184
    ),
    sealed_authorization_bytes INTEGER NOT NULL CHECK(
        typeof(sealed_authorization_bytes) = 'integer'
        AND sealed_authorization_bytes = length(sealed_authorization)
    ),
    revocation_hash BLOB CHECK(
        revocation_hash IS NULL OR (typeof(revocation_hash) = 'blob' AND length(revocation_hash) = 32
            AND revocation_hash <> X'0000000000000000000000000000000000000000000000000000000000000000')
    ),
    sealed_revocation BLOB CHECK(
        sealed_revocation IS NULL OR (typeof(sealed_revocation) = 'blob' AND length(sealed_revocation) BETWEEN 40 AND 65576)
    ),
    sealed_revocation_bytes INTEGER CHECK(
        (sealed_revocation IS NULL AND sealed_revocation_bytes IS NULL)
        OR (sealed_revocation IS NOT NULL AND typeof(sealed_revocation_bytes) = 'integer'
            AND sealed_revocation_bytes = length(sealed_revocation))
    ),
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
    state_changed_at_ms INTEGER NOT NULL CHECK(state_changed_at_ms >= created_at_ms),
    metadata_token BLOB NOT NULL CHECK(typeof(metadata_token) = 'blob' AND length(metadata_token) = 32),
    PRIMARY KEY(device_route, grant_serial),
    FOREIGN KEY(machine_remote_singleton) REFERENCES machine_remote_state(singleton)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CHECK((lifecycle IN ('grantPreparing', 'active', 'superseded')
            AND revocation_hash IS NULL AND sealed_revocation IS NULL)
          OR (lifecycle IN ('revoking', 'revoked')
            AND revocation_hash IS NOT NULL AND sealed_revocation IS NOT NULL))
);
CREATE UNIQUE INDEX idx_remote_authorization_current
    ON remote_authorization_ledger(device_route)
    WHERE lifecycle IN ('grantPreparing', 'active', 'revoking');
CREATE INDEX idx_remote_authorization_recovery
    ON remote_authorization_ledger(lifecycle, state_changed_at_ms, device_route, grant_serial);

CREATE TABLE remote_key_directory (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    machine_identity_singleton INTEGER NOT NULL DEFAULT 1 CHECK(machine_identity_singleton = 1),
    database_id BLOB NOT NULL CHECK(typeof(database_id) = 'blob' AND length(database_id) = 16),
    revision TEXT NOT NULL CHECK(
        typeof(revision) = 'text' AND length(revision) = 20
        AND revision NOT GLOB '*[^0-9]*'
        AND revision > '00000000000000000000'
        AND revision <= '18446744073709551615'
    ),
    directory_hash BLOB NOT NULL CHECK(
        typeof(directory_hash) = 'blob' AND length(directory_hash) = 32
        AND directory_hash <> X'0000000000000000000000000000000000000000000000000000000000000000'
    ),
    sealed_directory BLOB NOT NULL CHECK(
        typeof(sealed_directory) = 'blob' AND length(sealed_directory) BETWEEN 40 AND 67108864
    ),
    sealed_directory_bytes INTEGER NOT NULL CHECK(
        typeof(sealed_directory_bytes) = 'integer'
        AND sealed_directory_bytes = length(sealed_directory)
    ),
    metadata_token BLOB NOT NULL CHECK(typeof(metadata_token) = 'blob' AND length(metadata_token) = 32),
    FOREIGN KEY(machine_identity_singleton) REFERENCES machine_identity_state(singleton)
        ON UPDATE RESTRICT ON DELETE RESTRICT
);

CREATE TABLE remote_control_outbox (
    outbox_id BLOB PRIMARY KEY NOT NULL CHECK(
        typeof(outbox_id) = 'blob' AND length(outbox_id) = 16
        AND outbox_id <> X'00000000000000000000000000000000'
    ),
    operation_kind TEXT NOT NULL CHECK(operation_kind IN (
        'openPairRoute', 'closePairRoute', 'installGrant', 'revokeDevice'
    )),
    operation_key BLOB NOT NULL CHECK(
        typeof(operation_key) = 'blob' AND length(operation_key) = 32
        AND operation_key <> X'0000000000000000000000000000000000000000000000000000000000000000'
    ),
    lifecycle TEXT NOT NULL CHECK(lifecycle IN ('prepared', 'acknowledged')),
    database_id BLOB NOT NULL CHECK(typeof(database_id) = 'blob' AND length(database_id) = 16),
    pairing_id BLOB,
    device_route BLOB,
    grant_serial TEXT,
    frame_hash BLOB NOT NULL CHECK(
        typeof(frame_hash) = 'blob' AND length(frame_hash) = 32
        AND frame_hash <> X'0000000000000000000000000000000000000000000000000000000000000000'
    ),
    sealed_frame BLOB NOT NULL CHECK(
        typeof(sealed_frame) = 'blob' AND length(sealed_frame) BETWEEN 40 AND 4194344
    ),
    sealed_frame_bytes INTEGER NOT NULL CHECK(
        typeof(sealed_frame_bytes) = 'integer' AND sealed_frame_bytes = length(sealed_frame)
    ),
    terminal_hash BLOB CHECK(
        terminal_hash IS NULL OR (typeof(terminal_hash) = 'blob' AND length(terminal_hash) = 32
            AND terminal_hash <> X'0000000000000000000000000000000000000000000000000000000000000000')
    ),
    sealed_terminal BLOB CHECK(
        sealed_terminal IS NULL OR (typeof(sealed_terminal) = 'blob' AND length(sealed_terminal) BETWEEN 40 AND 4194344)
    ),
    sealed_terminal_bytes INTEGER CHECK(
        (sealed_terminal IS NULL AND sealed_terminal_bytes IS NULL)
        OR (sealed_terminal IS NOT NULL AND typeof(sealed_terminal_bytes) = 'integer'
            AND sealed_terminal_bytes = length(sealed_terminal))
    ),
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
    state_changed_at_ms INTEGER NOT NULL CHECK(state_changed_at_ms >= created_at_ms),
    metadata_token BLOB NOT NULL CHECK(typeof(metadata_token) = 'blob' AND length(metadata_token) = 32),
    UNIQUE(operation_kind, operation_key),
    FOREIGN KEY(pairing_id) REFERENCES remote_pairings(pairing_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    FOREIGN KEY(device_route, grant_serial)
        REFERENCES remote_authorization_ledger(device_route, grant_serial)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CHECK(pairing_id IS NULL OR (typeof(pairing_id) = 'blob' AND length(pairing_id) = 16)),
    CHECK(device_route IS NULL OR (typeof(device_route) = 'blob' AND length(device_route) = 16)),
    CHECK(grant_serial IS NULL OR (
        typeof(grant_serial) = 'text' AND length(grant_serial) = 20
        AND grant_serial NOT GLOB '*[^0-9]*'
        AND grant_serial > '00000000000000000000'
        AND grant_serial <= '18446744073709551615'
    )),
    CHECK((operation_kind IN ('openPairRoute', 'closePairRoute')
            AND pairing_id IS NOT NULL AND device_route IS NULL AND grant_serial IS NULL)
          OR (operation_kind IN ('installGrant', 'revokeDevice')
            AND device_route IS NOT NULL AND grant_serial IS NOT NULL)),
    CHECK((lifecycle = 'prepared' AND terminal_hash IS NULL AND sealed_terminal IS NULL)
          OR (lifecycle = 'acknowledged' AND terminal_hash IS NOT NULL AND sealed_terminal IS NOT NULL))
);
CREATE INDEX idx_remote_control_outbox_recovery
    ON remote_control_outbox(lifecycle, operation_kind, created_at_ms, outbox_id);
"#;

/// P4.5 additive v11 physical shape。
///
/// replay window 的完整 scope、counter→ciphertext hash map 与 retention pins 只进入
/// `sealed_state`；SQLite 仅暴露 blind-index scope token 和经过 metadata MAC 绑定的
/// GC 投影。CounterGuard 的 Runtime DB 侧状态在同一 physical bump 预留，避免发布
/// 接线随后再升 v12。既有 row/ciphertext、wrapped key bundle 与 crypto context 均不改写。
pub const RUNTIME_MIGRATION_V11: &str = r#"
ALTER TABLE runtime_meta ADD COLUMN remote_replay_scope_count INTEGER NOT NULL DEFAULT 0
    CHECK(remote_replay_scope_count BETWEEN 0 AND 4096);
ALTER TABLE runtime_meta ADD COLUMN remote_replay_retired_scope_count INTEGER NOT NULL DEFAULT 0
    CHECK(remote_replay_retired_scope_count BETWEEN 0 AND remote_replay_scope_count);
ALTER TABLE runtime_meta ADD COLUMN remote_replay_pin_count INTEGER NOT NULL DEFAULT 0
    CHECK(remote_replay_pin_count BETWEEN 0 AND 1048576);
ALTER TABLE runtime_meta ADD COLUMN remote_replay_sealed_bytes INTEGER NOT NULL DEFAULT 0
    CHECK(remote_replay_sealed_bytes BETWEEN 0 AND 1073741824)
    CHECK((remote_replay_scope_count = 0 AND remote_replay_sealed_bytes = 0)
       OR (remote_replay_scope_count > 0 AND remote_replay_sealed_bytes > 0));

ALTER TABLE runtime_meta ADD COLUMN remote_counter_state_count INTEGER NOT NULL DEFAULT 0
    CHECK(remote_counter_state_count BETWEEN 0 AND 4096);
ALTER TABLE runtime_meta ADD COLUMN remote_counter_state_sealed_bytes INTEGER NOT NULL DEFAULT 0
    CHECK(remote_counter_state_sealed_bytes BETWEEN 0 AND 1073741824)
    CHECK((remote_counter_state_count = 0 AND remote_counter_state_sealed_bytes = 0)
       OR (remote_counter_state_count > 0 AND remote_counter_state_sealed_bytes > 0));

CREATE TABLE remote_replay_states (
    scope_token BLOB PRIMARY KEY NOT NULL CHECK(
        typeof(scope_token) = 'blob' AND length(scope_token) = 32
        AND scope_token <> X'0000000000000000000000000000000000000000000000000000000000000000'
    ),
    database_id BLOB NOT NULL CHECK(typeof(database_id) = 'blob' AND length(database_id) = 16),
    retired_at_ms INTEGER CHECK(
        retired_at_ms IS NULL OR retired_at_ms BETWEEN 0 AND 9223372036764775807
    ),
    sealed_state BLOB NOT NULL CHECK(
        typeof(sealed_state) = 'blob' AND length(sealed_state) BETWEEN 40 AND 262184
    ),
    sealed_state_bytes INTEGER NOT NULL CHECK(
        typeof(sealed_state_bytes) = 'integer'
        AND sealed_state_bytes = length(sealed_state)
    ),
    metadata_token BLOB NOT NULL CHECK(
        typeof(metadata_token) = 'blob' AND length(metadata_token) = 32
    )
);
CREATE INDEX idx_remote_replay_retired
    ON remote_replay_states(retired_at_ms, scope_token) WHERE retired_at_ms IS NOT NULL;

CREATE TABLE remote_counter_states (
    scope_token BLOB PRIMARY KEY NOT NULL CHECK(
        typeof(scope_token) = 'blob' AND length(scope_token) = 32
        AND scope_token <> X'0000000000000000000000000000000000000000000000000000000000000000'
    ),
    database_id BLOB NOT NULL CHECK(typeof(database_id) = 'blob' AND length(database_id) = 16),
    purpose TEXT NOT NULL CHECK(purpose IN (
        'catalog', 'conversationDek', 'deviceCommandTx', 'deviceReplyTx'
    )),
    key_epoch TEXT NOT NULL CHECK(
        typeof(key_epoch) = 'text' AND length(key_epoch) = 20
        AND key_epoch NOT GLOB '*[^0-9]*'
        AND key_epoch > '00000000000000000000'
        AND key_epoch <= '18446744073709551615'
    ),
    reserved_end TEXT NOT NULL CHECK(
        typeof(reserved_end) = 'text' AND length(reserved_end) = 20
        AND reserved_end NOT GLOB '*[^0-9]*'
        AND reserved_end <= '18446744073709551615'
    ),
    reservation_id BLOB CHECK(
        reservation_id IS NULL OR (
            typeof(reservation_id) = 'blob' AND length(reservation_id) = 16
            AND reservation_id <> X'00000000000000000000000000000000'
        )
    ),
    db_anchor BLOB NOT NULL CHECK(
        typeof(db_anchor) = 'blob' AND length(db_anchor) = 32
        AND db_anchor <> X'0000000000000000000000000000000000000000000000000000000000000000'
    ),
    lifecycle TEXT NOT NULL CHECK(lifecycle IN ('active', 'retired')),
    sealed_state BLOB NOT NULL CHECK(
        typeof(sealed_state) = 'blob' AND length(sealed_state) BETWEEN 40 AND 262184
    ),
    sealed_state_bytes INTEGER NOT NULL CHECK(
        typeof(sealed_state_bytes) = 'integer'
        AND sealed_state_bytes = length(sealed_state)
    ),
    metadata_token BLOB NOT NULL CHECK(
        typeof(metadata_token) = 'blob' AND length(metadata_token) = 32
    )
);
CREATE INDEX idx_remote_counter_lifecycle
    ON remote_counter_states(lifecycle, purpose, key_epoch, scope_token);
"#;

/// P4.5 additive v12 key-transition substrate。
///
/// canonical recipient roster、per-stream committed cut 与 opaque update/ACK bytes 全部进入
/// StorageKEK 行密文；outer projection 只保留有界恢复索引，并由 metadata token 与 v12 ledger
/// 交叉认证。旧行密文继续使用 frozen crypto context v1，不因 physical bump 重写。
pub const RUNTIME_MIGRATION_V12: &str = r#"
ALTER TABLE runtime_meta ADD COLUMN remote_counter_guard_manifest_count INTEGER NOT NULL DEFAULT 0
    CHECK(remote_counter_guard_manifest_count BETWEEN 0 AND 4096);
ALTER TABLE runtime_meta ADD COLUMN remote_key_transition_count INTEGER NOT NULL DEFAULT 0
    CHECK(remote_key_transition_count BETWEEN 0 AND 4096);
ALTER TABLE runtime_meta ADD COLUMN remote_key_transition_active_count INTEGER NOT NULL DEFAULT 0
    CHECK(remote_key_transition_active_count BETWEEN 0 AND 1
          AND remote_key_transition_active_count <= remote_key_transition_count);
ALTER TABLE runtime_meta ADD COLUMN remote_key_transition_sealed_bytes INTEGER NOT NULL DEFAULT 0
    CHECK(remote_key_transition_sealed_bytes BETWEEN 0 AND 536870912)
    CHECK((remote_key_transition_count = 0 AND remote_key_transition_sealed_bytes = 0)
       OR (remote_key_transition_count > 0 AND remote_key_transition_sealed_bytes > 0));
ALTER TABLE runtime_meta ADD COLUMN remote_key_update_outbox_count INTEGER NOT NULL DEFAULT 0
    CHECK(remote_key_update_outbox_count BETWEEN 0 AND 65536);
ALTER TABLE runtime_meta ADD COLUMN remote_key_update_outbox_sealed_bytes INTEGER NOT NULL DEFAULT 0
    CHECK(remote_key_update_outbox_sealed_bytes BETWEEN 0 AND 536870912)
    CHECK((remote_key_update_outbox_count = 0 AND remote_key_update_outbox_sealed_bytes = 0)
       OR (remote_key_update_outbox_count > 0 AND remote_key_update_outbox_sealed_bytes > 0));

CREATE TABLE remote_counter_guard_manifest (
    scope_token BLOB PRIMARY KEY NOT NULL CHECK(
        typeof(scope_token) = 'blob' AND length(scope_token) = 32
        AND scope_token <> X'0000000000000000000000000000000000000000000000000000000000000000'
    ),
    database_id BLOB NOT NULL CHECK(typeof(database_id) = 'blob' AND length(database_id) = 16),
    phase TEXT NOT NULL CHECK(phase IN ('reserved', 'materialized')),
    metadata_token BLOB NOT NULL CHECK(typeof(metadata_token) = 'blob' AND length(metadata_token) = 32)
);

CREATE TABLE remote_key_transitions (
    operation_id BLOB PRIMARY KEY NOT NULL CHECK(
        typeof(operation_id) = 'blob' AND length(operation_id) = 16
        AND operation_id <> X'00000000000000000000000000000000'
    ),
    active_slot INTEGER NOT NULL DEFAULT 1 CHECK(active_slot = 1),
    database_id BLOB NOT NULL CHECK(typeof(database_id) = 'blob' AND length(database_id) = 16),
    operation_kind TEXT NOT NULL CHECK(operation_kind IN (
        'Add', 'Renew', 'Revoke', 'ActivateConversation', 'CounterRecovery'
    )),
    target_device_route BLOB CHECK(
        target_device_route IS NULL OR (typeof(target_device_route) = 'blob'
        AND length(target_device_route) = 16
        AND target_device_route <> X'00000000000000000000000000000000')
    ),
    target_grant_serial TEXT CHECK(
        target_grant_serial IS NULL OR (typeof(target_grant_serial) = 'text'
        AND length(target_grant_serial) = 20
        AND target_grant_serial NOT GLOB '*[^0-9]*'
        AND target_grant_serial > '00000000000000000000'
        AND target_grant_serial <= '18446744073709551615')
    ),
    target_conversation_id BLOB CHECK(
        target_conversation_id IS NULL OR (typeof(target_conversation_id) = 'blob'
        AND length(target_conversation_id) = 16
        AND target_conversation_id <> X'00000000000000000000000000000000')
    ),
    target_stream_route BLOB CHECK(
        target_stream_route IS NULL OR (typeof(target_stream_route) = 'blob'
        AND length(target_stream_route) = 16
        AND target_stream_route <> X'00000000000000000000000000000000')
    ),
    from_revision TEXT NOT NULL CHECK(
        typeof(from_revision) = 'text' AND length(from_revision) = 20
        AND from_revision NOT GLOB '*[^0-9]*'
        AND from_revision <= '18446744073709551615'
    ),
    to_revision TEXT NOT NULL CHECK(
        typeof(to_revision) = 'text' AND length(to_revision) = 20
        AND to_revision NOT GLOB '*[^0-9]*'
        AND to_revision > '00000000000000000000'
        AND to_revision <= '18446744073709551615'
    ),
    phase TEXT NOT NULL CHECK(phase IN (
        'DrainingOld', 'RotatedPreparingUpdates', 'UpdatesFrozen',
        'BarriersFrozen', 'BarriersCommitted', 'Complete'
    )),
    terminal_kind TEXT CHECK(terminal_kind IS NULL OR terminal_kind IN ('Completed', 'Cancelled')),
    recipient_count INTEGER NOT NULL CHECK(recipient_count BETWEEN 0 AND 256),
    stream_count INTEGER NOT NULL CHECK(stream_count BETWEEN 0 AND 1025),
    update_count INTEGER NOT NULL CHECK(update_count BETWEEN 0 AND recipient_count),
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms BETWEEN 0 AND 9223372034262775807),
    state_changed_at_ms INTEGER NOT NULL CHECK(state_changed_at_ms >= created_at_ms),
    terminal_at_ms INTEGER CHECK(
        terminal_at_ms IS NULL OR terminal_at_ms BETWEEN state_changed_at_ms AND 9223372034262775807
    ),
    retain_until_ms INTEGER CHECK(
        retain_until_ms IS NULL OR retain_until_ms BETWEEN terminal_at_ms AND 9223372036854775807
    ),
    sealed_state BLOB NOT NULL CHECK(
        typeof(sealed_state) = 'blob' AND length(sealed_state) BETWEEN 40 AND 524328
    ),
    sealed_state_bytes INTEGER NOT NULL CHECK(
        typeof(sealed_state_bytes) = 'integer' AND sealed_state_bytes = length(sealed_state)
    ),
    metadata_token BLOB NOT NULL CHECK(typeof(metadata_token) = 'blob' AND length(metadata_token) = 32),
    CHECK((operation_kind IN ('Add', 'Renew', 'Revoke')
              AND target_device_route IS NOT NULL AND target_grant_serial IS NOT NULL
              AND target_conversation_id IS NULL AND target_stream_route IS NULL)
          OR (operation_kind = 'ActivateConversation'
              AND target_device_route IS NULL AND target_grant_serial IS NULL
              AND target_conversation_id IS NOT NULL AND target_stream_route IS NOT NULL)
          OR (operation_kind = 'CounterRecovery'
              AND ((target_device_route IS NOT NULL AND target_grant_serial IS NOT NULL
                    AND target_conversation_id IS NULL AND target_stream_route IS NULL)
                OR (target_device_route IS NULL AND target_grant_serial IS NULL
                    AND target_conversation_id IS NOT NULL AND target_stream_route IS NOT NULL)))),
    CHECK((phase = 'Complete' AND terminal_kind IS NOT NULL
              AND terminal_at_ms IS NOT NULL AND retain_until_ms IS NOT NULL)
          OR (phase <> 'Complete' AND terminal_kind IS NULL
              AND terminal_at_ms IS NULL AND retain_until_ms IS NULL)),
    CHECK((phase IN ('DrainingOld', 'RotatedPreparingUpdates') AND update_count = 0)
          OR phase NOT IN ('DrainingOld', 'RotatedPreparingUpdates')),
    CHECK((phase IN ('DrainingOld', 'RotatedPreparingUpdates', 'UpdatesFrozen') AND stream_count = 0)
          OR phase NOT IN ('DrainingOld', 'RotatedPreparingUpdates', 'UpdatesFrozen'))
);
CREATE UNIQUE INDEX idx_remote_key_transition_active
    ON remote_key_transitions(active_slot) WHERE phase <> 'Complete';
CREATE INDEX idx_remote_key_transition_recovery
    ON remote_key_transitions(phase, state_changed_at_ms, operation_id);
CREATE INDEX idx_remote_key_transition_retention
    ON remote_key_transitions(retain_until_ms, operation_id) WHERE phase = 'Complete';

CREATE TABLE remote_key_update_outbox (
    operation_id BLOB NOT NULL CHECK(
        typeof(operation_id) = 'blob' AND length(operation_id) = 16
        AND operation_id <> X'00000000000000000000000000000000'
    ),
    device_route BLOB NOT NULL CHECK(
        typeof(device_route) = 'blob' AND length(device_route) = 16
        AND device_route <> X'00000000000000000000000000000000'
    ),
    grant_serial TEXT NOT NULL CHECK(
        typeof(grant_serial) = 'text' AND length(grant_serial) = 20
        AND grant_serial NOT GLOB '*[^0-9]*'
        AND grant_serial > '00000000000000000000'
        AND grant_serial <= '18446744073709551615'
    ),
    database_id BLOB NOT NULL CHECK(typeof(database_id) = 'blob' AND length(database_id) = 16),
    key_revision TEXT NOT NULL CHECK(
        typeof(key_revision) = 'text' AND length(key_revision) = 20
        AND key_revision NOT GLOB '*[^0-9]*'
        AND key_revision > '00000000000000000000'
        AND key_revision <= '18446744073709551615'
    ),
    lifecycle TEXT NOT NULL CHECK(lifecycle IN ('Frozen', 'Acked', 'Cancelled')),
    update_hash BLOB NOT NULL CHECK(
        typeof(update_hash) = 'blob' AND length(update_hash) = 32
        AND update_hash <> X'0000000000000000000000000000000000000000000000000000000000000000'
    ),
    canonical_update_bytes INTEGER NOT NULL CHECK(canonical_update_bytes BETWEEN 1 AND 262144),
    ack_hash BLOB CHECK(
        ack_hash IS NULL OR (typeof(ack_hash) = 'blob' AND length(ack_hash) = 32
            AND ack_hash <> X'0000000000000000000000000000000000000000000000000000000000000000')
    ),
    applied_ack_count INTEGER NOT NULL CHECK(applied_ack_count BETWEEN 0 AND 1025),
    applied_ack_set_hash BLOB CHECK(
        applied_ack_set_hash IS NULL OR (
            typeof(applied_ack_set_hash) = 'blob' AND length(applied_ack_set_hash) = 32
            AND applied_ack_set_hash <>
                X'0000000000000000000000000000000000000000000000000000000000000000'
        )
    ),
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms BETWEEN 0 AND 9223372036854775807),
    state_changed_at_ms INTEGER NOT NULL CHECK(state_changed_at_ms >= created_at_ms),
    sealed_state BLOB NOT NULL CHECK(
        typeof(sealed_state) = 'blob' AND length(sealed_state) BETWEEN 40 AND 524328
    ),
    sealed_state_bytes INTEGER NOT NULL CHECK(
        typeof(sealed_state_bytes) = 'integer' AND sealed_state_bytes = length(sealed_state)
    ),
    metadata_token BLOB NOT NULL CHECK(typeof(metadata_token) = 'blob' AND length(metadata_token) = 32),
    PRIMARY KEY(operation_id, device_route, grant_serial),
    FOREIGN KEY(operation_id) REFERENCES remote_key_transitions(operation_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CHECK((lifecycle = 'Acked' AND ack_hash IS NOT NULL)
          OR (lifecycle IN ('Frozen', 'Cancelled') AND ack_hash IS NULL)),
    CHECK((applied_ack_count = 0 AND applied_ack_set_hash IS NULL)
          OR (lifecycle = 'Acked' AND applied_ack_count > 0
              AND applied_ack_set_hash IS NOT NULL))
);
CREATE INDEX idx_remote_key_update_recovery
    ON remote_key_update_outbox(operation_id, lifecycle, device_route, grant_serial);
"#;

/// P4.5 v13 generation-rollover physical shape。
///
/// v4-v12 的 publication CHECK 将 outer 与 inner cursor 的 NULL 形态错误地绑定在
/// 一起，无法表达 authenticated rotation baseline `(BeforeFirst, H)`。v13 在同一
/// transaction 内重建 parent/outbox 两张表，逐列复制 opaque ciphertext、hash、token
/// 与 wrapped key 相关字节；只放宽由 rotation lineage 表达的 inner baseline，不新增
/// canonical state，也不重写任何行密文。
pub const RUNTIME_MIGRATION_V13: &str = r#"
PRAGMA defer_foreign_keys = ON;

ALTER TABLE publication_outbox RENAME TO publication_outbox_v12;
ALTER TABLE publication_streams RENAME TO publication_streams_v12;
DROP INDEX idx_publication_pending;
DROP INDEX idx_publication_active_catalog;
DROP INDEX idx_publication_active_conversation;

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
    last_acknowledged_publication_id BLOB CHECK(
        last_acknowledged_publication_id IS NULL OR (
            typeof(last_acknowledged_publication_id) = 'blob'
            AND length(last_acknowledged_publication_id) = 16
        )
    ),
    last_acknowledged_request_digest BLOB CHECK(
        last_acknowledged_request_digest IS NULL OR (
            typeof(last_acknowledged_request_digest) = 'blob'
            AND length(last_acknowledged_request_digest) = 32
        )
    ),
    last_rotation_request_digest BLOB CHECK(
        last_rotation_request_digest IS NULL OR (
            typeof(last_rotation_request_digest) = 'blob'
            AND length(last_rotation_request_digest) = 32
        )
    ),
    rotation_serial TEXT NOT NULL CHECK(
        typeof(rotation_serial) = 'text' AND length(rotation_serial) = 20
        AND rotation_serial NOT GLOB '*[^0-9]*'
        AND rotation_serial <= '18446744073709551615'
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
           AND last_committed_blob_hash IS NULL
           AND (committed_inner_cursor IS NULL OR (
               rotation_serial > '00000000000000000000'
               AND last_rotation_request_digest IS NOT NULL
               AND acknowledged_high_water IS NULL
               AND acknowledged_inner_cursor IS committed_inner_cursor)))
       OR (committed_high_water IS NOT NULL
           AND last_committed_blob_hash IS NOT NULL)),
    CHECK((acknowledged_high_water IS NULL
           AND last_acknowledged_blob_hash IS NULL
           AND (acknowledged_inner_cursor IS NULL OR (
               rotation_serial > '00000000000000000000'
               AND last_rotation_request_digest IS NOT NULL
               AND committed_inner_cursor IS acknowledged_inner_cursor)))
       OR (acknowledged_high_water IS NOT NULL
           AND last_acknowledged_blob_hash IS NOT NULL)),
    CHECK((counter_scope_token IS NULL AND sender_counter_high_water IS NULL)
       OR (counter_scope_token IS NOT NULL AND sender_counter_high_water IS NOT NULL)),
    CHECK((last_acknowledged_publication_id IS NULL
           AND last_acknowledged_request_digest IS NULL)
       OR (last_acknowledged_publication_id IS NOT NULL
           AND last_acknowledged_request_digest IS NOT NULL)),
    UNIQUE(publication_stream_id, generation),
    UNIQUE(stream_route, generation),
    UNIQUE(counter_scope_token),
    FOREIGN KEY(conversation_id) REFERENCES conversations(conversation_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT
);

INSERT INTO publication_streams (
    publication_stream_id, scope, conversation_id, stream_route, generation,
    counter_scope_token, sender_counter_high_water, reserved_high_water,
    committed_high_water, committed_inner_cursor, acknowledged_high_water,
    acknowledged_inner_cursor, last_acknowledged_blob_hash,
    last_acknowledged_publication_id, last_acknowledged_request_digest,
    last_rotation_request_digest, rotation_serial, last_committed_blob_hash,
    state, created_at_ms, updated_at_ms, metadata_token
)
SELECT publication_stream_id, scope, conversation_id, stream_route, generation,
       counter_scope_token, sender_counter_high_water, reserved_high_water,
       committed_high_water, committed_inner_cursor, acknowledged_high_water,
       acknowledged_inner_cursor, last_acknowledged_blob_hash,
       last_acknowledged_publication_id, last_acknowledged_request_digest,
       last_rotation_request_digest, rotation_serial, last_committed_blob_hash,
       state, created_at_ms, updated_at_ms, metadata_token
FROM publication_streams_v12;

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

INSERT INTO publication_outbox (
    publication_id, publication_stream_id, generation, stream_seq,
    counter_scope_token, sender_counter, inner_after_seq, inner_through_seq,
    payload_kind, blob_sha256, logical_blob_bytes, created_at_ms,
    metadata_token, sealed_publication
)
SELECT publication_id, publication_stream_id, generation, stream_seq,
       counter_scope_token, sender_counter, inner_after_seq, inner_through_seq,
       payload_kind, blob_sha256, logical_blob_bytes, created_at_ms,
       metadata_token, sealed_publication
FROM publication_outbox_v12;

CREATE INDEX idx_publication_pending
    ON publication_outbox(publication_stream_id, generation, stream_seq);

DROP TABLE publication_outbox_v12;
DROP TABLE publication_streams_v12;
"#;

/// P4.5 v14 key-update capacity shape。
///
/// 最大合法 `KeyUpdateSetV1` 为 277,297 bytes；v12/v13 的 256 KiB CHECK 会在
/// Store admission 之后拒绝协议合法值。完整 ACK、1,025 个 applied ACK 与 1,025 个
/// snapshot flush marker 的 ADKU plaintext 也会超过旧 512 KiB。迁移只重建 outbox
/// 的物理 CHECK，逐列复制既有 opaque ciphertext/hash/token，crypto context 保持 v1。
pub const RUNTIME_MIGRATION_V14: &str = r#"
PRAGMA defer_foreign_keys = ON;

ALTER TABLE remote_key_update_outbox RENAME TO remote_key_update_outbox_v13;
DROP INDEX idx_remote_key_update_recovery;

CREATE TABLE remote_key_update_outbox (
    operation_id BLOB NOT NULL CHECK(
        typeof(operation_id) = 'blob' AND length(operation_id) = 16
        AND operation_id <> X'00000000000000000000000000000000'
    ),
    device_route BLOB NOT NULL CHECK(
        typeof(device_route) = 'blob' AND length(device_route) = 16
        AND device_route <> X'00000000000000000000000000000000'
    ),
    grant_serial TEXT NOT NULL CHECK(
        typeof(grant_serial) = 'text' AND length(grant_serial) = 20
        AND grant_serial NOT GLOB '*[^0-9]*'
        AND grant_serial > '00000000000000000000'
        AND grant_serial <= '18446744073709551615'
    ),
    database_id BLOB NOT NULL CHECK(typeof(database_id) = 'blob' AND length(database_id) = 16),
    key_revision TEXT NOT NULL CHECK(
        typeof(key_revision) = 'text' AND length(key_revision) = 20
        AND key_revision NOT GLOB '*[^0-9]*'
        AND key_revision > '00000000000000000000'
        AND key_revision <= '18446744073709551615'
    ),
    lifecycle TEXT NOT NULL CHECK(lifecycle IN ('Frozen', 'Acked', 'Cancelled')),
    update_hash BLOB NOT NULL CHECK(
        typeof(update_hash) = 'blob' AND length(update_hash) = 32
        AND update_hash <> X'0000000000000000000000000000000000000000000000000000000000000000'
    ),
    canonical_update_bytes INTEGER NOT NULL CHECK(canonical_update_bytes BETWEEN 1 AND 393216),
    ack_hash BLOB CHECK(
        ack_hash IS NULL OR (typeof(ack_hash) = 'blob' AND length(ack_hash) = 32
            AND ack_hash <> X'0000000000000000000000000000000000000000000000000000000000000000')
    ),
    applied_ack_count INTEGER NOT NULL CHECK(applied_ack_count BETWEEN 0 AND 1025),
    applied_ack_set_hash BLOB CHECK(
        applied_ack_set_hash IS NULL OR (
            typeof(applied_ack_set_hash) = 'blob' AND length(applied_ack_set_hash) = 32
            AND applied_ack_set_hash <>
                X'0000000000000000000000000000000000000000000000000000000000000000'
        )
    ),
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms BETWEEN 0 AND 9223372036854775807),
    state_changed_at_ms INTEGER NOT NULL CHECK(state_changed_at_ms >= created_at_ms),
    sealed_state BLOB NOT NULL CHECK(
        typeof(sealed_state) = 'blob' AND length(sealed_state) BETWEEN 40 AND 1048616
    ),
    sealed_state_bytes INTEGER NOT NULL CHECK(
        typeof(sealed_state_bytes) = 'integer' AND sealed_state_bytes = length(sealed_state)
    ),
    metadata_token BLOB NOT NULL CHECK(typeof(metadata_token) = 'blob' AND length(metadata_token) = 32),
    PRIMARY KEY(operation_id, device_route, grant_serial),
    FOREIGN KEY(operation_id) REFERENCES remote_key_transitions(operation_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CHECK((lifecycle = 'Acked' AND ack_hash IS NOT NULL)
          OR (lifecycle IN ('Frozen', 'Cancelled') AND ack_hash IS NULL)),
    CHECK((applied_ack_count = 0 AND applied_ack_set_hash IS NULL)
          OR (lifecycle = 'Acked' AND applied_ack_count > 0
              AND applied_ack_set_hash IS NOT NULL))
);

INSERT INTO remote_key_update_outbox (
    operation_id, device_route, grant_serial, database_id,
    key_revision, lifecycle, update_hash, canonical_update_bytes,
    ack_hash, applied_ack_count, applied_ack_set_hash,
    created_at_ms, state_changed_at_ms, sealed_state,
    sealed_state_bytes, metadata_token
)
SELECT operation_id, device_route, grant_serial, database_id,
       key_revision, lifecycle, update_hash, canonical_update_bytes,
       ack_hash, applied_ack_count, applied_ack_set_hash,
       created_at_ms, state_changed_at_ms, sealed_state,
       sealed_state_bytes, metadata_token
FROM remote_key_update_outbox_v13;

DROP TABLE remote_key_update_outbox_v13;

CREATE INDEX idx_remote_key_update_recovery
    ON remote_key_update_outbox(operation_id, lifecycle, device_route, grant_serial);
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::{Connection, params};

    const V4_SCHEMA_SIGNATURE_GOLDEN: [u8; 32] = [
        0x79, 0x20, 0x35, 0x80, 0xf3, 0x37, 0x1f, 0x06, 0x01, 0xf6, 0xf5, 0x24, 0x1f, 0x63, 0x4e,
        0x05, 0xef, 0x12, 0xfa, 0x4f, 0x7d, 0x47, 0xa1, 0xd1, 0x45, 0x17, 0x87, 0x78, 0xe8, 0x8f,
        0xc7, 0x11,
    ];
    const V5_SCHEMA_SIGNATURE_GOLDEN: [u8; 32] = [
        0x00, 0xa4, 0xd5, 0x3a, 0x7a, 0x2a, 0x0f, 0xf2, 0xbe, 0x36, 0x89, 0xdf, 0xc3, 0xdd, 0xcb,
        0x5a, 0x8c, 0x47, 0x4f, 0x25, 0x55, 0x22, 0xae, 0xbe, 0xb6, 0x28, 0x72, 0x00, 0x04, 0xe2,
        0x43, 0x68,
    ];

    #[derive(Debug, PartialEq, Eq)]
    struct TableColumn {
        name: String,
        column_type: String,
        not_null: bool,
        default_value: Option<String>,
        primary_key_ordinal: i64,
    }

    #[derive(Debug, PartialEq, Eq)]
    struct IndexShape {
        unique: bool,
        partial: bool,
        columns: Vec<String>,
        sql: String,
    }

    #[derive(Debug, PartialEq, Eq)]
    struct ForeignKeyColumn {
        id: i64,
        seq: i64,
        target_table: String,
        source_column: String,
        target_column: String,
        on_update: String,
        on_delete: String,
    }

    fn table_names(connection: &Connection) -> Vec<String> {
        connection
            .prepare(
                "SELECT name FROM sqlite_schema
                 WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
                 ORDER BY name",
            )
            .expect("prepare table manifest")
            .query_map([], |row| row.get::<_, String>(0))
            .expect("query table manifest")
            .collect::<Result<Vec<_>, _>>()
            .expect("collect table manifest")
    }

    fn table_columns(connection: &Connection, table: &str) -> Vec<String> {
        connection
            .prepare(&format!(
                "SELECT name FROM pragma_table_info('{table}') ORDER BY cid"
            ))
            .expect("prepare table columns")
            .query_map([], |row| row.get::<_, String>(0))
            .expect("query table columns")
            .collect::<Result<Vec<_>, _>>()
            .expect("collect table columns")
    }

    fn table_column_details(connection: &Connection, table: &str) -> Vec<TableColumn> {
        connection
            .prepare(&format!(
                "SELECT name, type, \"notnull\", dflt_value, pk
                 FROM pragma_table_info('{table}') ORDER BY cid"
            ))
            .expect("prepare table column details")
            .query_map([], |row| {
                Ok(TableColumn {
                    name: row.get(0)?,
                    column_type: row.get(1)?,
                    not_null: row.get::<_, i64>(2)? != 0,
                    default_value: row.get(3)?,
                    primary_key_ordinal: row.get(4)?,
                })
            })
            .expect("query table column details")
            .collect::<Result<Vec<_>, _>>()
            .expect("collect table column details")
    }

    fn explicit_indexes(connection: &Connection, table: &str) -> Vec<String> {
        connection
            .prepare(
                "SELECT name FROM sqlite_schema
                 WHERE type = 'index' AND tbl_name = ?1
                   AND name NOT LIKE 'sqlite_%'
                 ORDER BY name",
            )
            .expect("prepare table indexes")
            .query_map([table], |row| row.get::<_, String>(0))
            .expect("query table indexes")
            .collect::<Result<Vec<_>, _>>()
            .expect("collect table indexes")
    }

    fn index_shape(connection: &Connection, table: &str, index: &str) -> IndexShape {
        let (unique, partial): (i64, i64) = connection
            .query_row(
                &format!(
                    "SELECT \"unique\", partial FROM pragma_index_list('{table}') WHERE name = ?1"
                ),
                [index],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("read index flags");
        let columns = connection
            .prepare(&format!(
                "SELECT name FROM pragma_index_info('{index}') ORDER BY seqno"
            ))
            .expect("prepare index columns")
            .query_map([], |row| row.get::<_, String>(0))
            .expect("query index columns")
            .collect::<Result<Vec<_>, _>>()
            .expect("collect index columns");
        let sql = connection
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE type = 'index' AND name = ?1",
                [index],
                |row| row.get::<_, String>(0),
            )
            .expect("read index SQL");
        IndexShape {
            unique: unique != 0,
            partial: partial != 0,
            columns,
            sql,
        }
    }

    fn foreign_key_columns(connection: &Connection, table: &str) -> Vec<ForeignKeyColumn> {
        let mut columns = connection
            .prepare(&format!("SELECT id, seq, \"table\", \"from\", \"to\", on_update, on_delete FROM pragma_foreign_key_list('{table}')"))
            .expect("prepare foreign keys")
            .query_map([], |row| {
                Ok(ForeignKeyColumn {
                    id: row.get(0)?,
                    seq: row.get(1)?,
                    target_table: row.get(2)?,
                    source_column: row.get(3)?,
                    target_column: row.get(4)?,
                    on_update: row.get(5)?,
                    on_delete: row.get(6)?,
                })
            })
            .expect("query foreign keys")
            .collect::<Result<Vec<_>, _>>()
            .expect("collect foreign keys");
        columns.sort_by(|left, right| {
            (
                left.target_table.as_str(),
                left.id,
                left.seq,
                left.source_column.as_str(),
            )
                .cmp(&(
                    right.target_table.as_str(),
                    right.id,
                    right.seq,
                    right.source_column.as_str(),
                ))
        });
        columns
    }

    fn table_sql(connection: &Connection, table: &str) -> String {
        connection
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = ?1",
                [table],
                |row| row.get(0),
            )
            .expect("read table SQL")
    }

    fn check_upper_bound(sql: &str, marker: &str) -> usize {
        let tail = sql
            .split_once(marker)
            .unwrap_or_else(|| panic!("missing CHECK marker: {marker}"))
            .1;
        let digits = tail
            .split(|character: char| !character.is_ascii_digit())
            .next()
            .expect("CHECK upper bound digits");
        digits.parse().expect("numeric CHECK upper bound")
    }

    #[test]
    fn stream_schema_advances_to_v4_with_six_bounded_store_tables() {
        assert_eq!(RUNTIME_SCHEMA_VERSION, RUNTIME_SCHEMA_VERSION_V14);
        assert_eq!(RUNTIME_CRYPTO_CONTEXT_VERSION, 1);
        for table in [
            "event_stream_index",
            "event_retention",
            "catalog_journal",
            "snapshots",
            "publication_streams",
            "publication_outbox",
        ] {
            assert!(EXPECTED_TABLES_V4.contains(&table), "missing {table}");
        }
    }

    #[test]
    fn approval_physical_schema_remains_v3_compatible_without_rotating_crypto_context() {
        assert_eq!(RUNTIME_SCHEMA_VERSION, RUNTIME_SCHEMA_VERSION_V14);
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

    fn v4_connection() -> Connection {
        let connection = v3_connection();
        connection
            .execute_batch(RUNTIME_MIGRATION_V4)
            .expect("apply v4 migration");
        connection
    }

    fn v5_structural_connection() -> Connection {
        let connection = v4_connection();
        connection
            .execute_batch(RUNTIME_MIGRATION_V5)
            .expect("apply v5 structural migration");
        connection
    }

    fn v6_structural_connection() -> Connection {
        let connection = v5_structural_connection();
        connection
            .execute_batch(RUNTIME_MIGRATION_V6)
            .expect("apply v6 structural migration");
        connection
    }

    fn v7_structural_connection() -> Connection {
        let connection = v6_structural_connection();
        connection
            .execute_batch(RUNTIME_MIGRATION_V7)
            .expect("apply v7 structural migration");
        connection
    }

    fn v8_structural_connection() -> Connection {
        let connection = v7_structural_connection();
        connection
            .execute_batch(RUNTIME_MIGRATION_V8)
            .expect("apply v8 structural migration");
        connection
    }

    fn v9_structural_connection() -> Connection {
        let connection = v8_structural_connection();
        connection
            .execute_batch(RUNTIME_MIGRATION_V9)
            .expect("apply v9 structural migration");
        connection
    }

    fn v10_structural_connection() -> Connection {
        let connection = v9_structural_connection();
        connection
            .execute_batch(RUNTIME_MIGRATION_V10)
            .expect("apply v10 structural migration");
        connection
    }

    fn v11_structural_connection() -> Connection {
        let connection = v10_structural_connection();
        connection
            .execute_batch(RUNTIME_MIGRATION_V11)
            .expect("apply v11 structural migration");
        connection
    }

    fn v12_structural_connection() -> Connection {
        let connection = v11_structural_connection();
        connection
            .execute_batch(RUNTIME_MIGRATION_V12)
            .expect("apply v12 structural migration");
        connection
    }

    fn v13_structural_connection() -> Connection {
        let connection = v12_structural_connection();
        connection
            .execute_batch(RUNTIME_MIGRATION_V13)
            .expect("apply v13 structural migration");
        connection
    }

    fn v14_structural_connection() -> Connection {
        let connection = v13_structural_connection();
        connection
            .execute_batch(RUNTIME_MIGRATION_V14)
            .expect("apply v14 structural migration");
        connection
    }

    fn insert_v13_rotation_baseline(
        connection: &Connection,
        identity_byte: u8,
        committed_inner_cursor: Option<&str>,
        acknowledged_inner_cursor: Option<&str>,
        rotation_serial: &str,
        last_rotation_request_digest: Option<&[u8]>,
    ) -> rusqlite::Result<usize> {
        let publication_stream_id = [identity_byte; 16];
        let stream_route = [identity_byte.wrapping_add(1); 16];
        let generation = [identity_byte.wrapping_add(2); 16];
        let metadata_token = [identity_byte.wrapping_add(3); 32];
        connection.execute(
            "INSERT INTO publication_streams (
                 publication_stream_id, scope, conversation_id, stream_route, generation,
                 committed_inner_cursor, acknowledged_inner_cursor,
                 last_rotation_request_digest, rotation_serial, state,
                 created_at_ms, updated_at_ms, metadata_token
             ) VALUES (?1, 'catalog', NULL, ?2, ?3, ?4, ?5, ?6, ?7,
                       'retired', 0, 0, ?8)",
            params![
                &publication_stream_id[..],
                &stream_route[..],
                &generation[..],
                committed_inner_cursor,
                acknowledged_inner_cursor,
                last_rotation_request_digest,
                rotation_serial,
                &metadata_token[..],
            ],
        )
    }

    #[test]
    fn v6_adds_projection_and_effect_fence_sidecars_without_rotating_crypto_context() {
        assert_eq!(RUNTIME_SCHEMA_VERSION, RUNTIME_SCHEMA_VERSION_V14);
        assert_eq!(RUNTIME_SCHEMA_VERSION_V6, 6);
        assert_eq!(RUNTIME_CRYPTO_CONTEXT_VERSION, 1);
        assert_eq!(EXPECTED_TABLES_V5.len(), 20);
        assert_eq!(EXPECTED_TABLES_V6.len(), 22);
        assert_ne!(EXPECTED_TABLES.as_slice(), EXPECTED_TABLES_V6.as_slice());
        assert_ne!(schema_signature(), schema_signature_v6());
        assert_eq!(RUNTIME_LEDGER_DOMAIN_V6, b"runtime.meta.ledger.v6");

        let connection = v6_structural_connection();
        assert_eq!(table_names(&connection), EXPECTED_TABLES_V6);
        assert!(EXPECTED_TABLES_V6.contains(&"native_projection_state"));
        assert!(EXPECTED_TABLES_V6.contains(&"native_metadata_effect_fences"));
        assert_eq!(
            &table_columns(&connection, "runtime_meta")
                [table_columns(&connection, "runtime_meta").len() - 8..],
            [
                "native_projection_present_count",
                "native_projection_tombstone_count",
                "native_projection_retired_count",
                "native_projection_physical_count",
                "native_projection_charged_bytes",
                "native_metadata_effect_fence_count",
                "native_metadata_effect_unreleased_count",
                "native_metadata_effect_released_count",
            ]
        );
    }

    #[test]
    fn v7_adds_machine_wide_admin_command_ledger_without_rotating_crypto_context() {
        assert_eq!(RUNTIME_SCHEMA_VERSION, RUNTIME_SCHEMA_VERSION_V14);
        assert_eq!(RUNTIME_SCHEMA_VERSION_V7, 7);
        assert_eq!(RUNTIME_CRYPTO_CONTEXT_VERSION, 1);
        assert_eq!(EXPECTED_TABLES_V7.len(), 23);
        assert_ne!(EXPECTED_TABLES.as_slice(), EXPECTED_TABLES_V7.as_slice());
        assert_ne!(schema_signature(), schema_signature_v7());
        assert_ne!(schema_signature_v6(), schema_signature_v7());
        assert_eq!(RUNTIME_LEDGER_DOMAIN_V7, b"runtime.meta.ledger.v7");

        let connection = v7_structural_connection();
        assert_eq!(table_names(&connection), EXPECTED_TABLES_V7);
        assert_eq!(
            &table_columns(&connection, "runtime_meta")
                [table_columns(&connection, "runtime_meta").len() - 3..],
            [
                "admin_command_count",
                "admin_command_pending_count",
                "admin_command_charged_bytes",
            ]
        );
        assert_eq!(
            table_columns(&connection, "admin_commands"),
            [
                "idempotency_token",
                "command_kind",
                "request_token",
                "state",
                "sealed_request",
                "sealed_outcome",
                "created_at_ms",
                "state_changed_at_ms",
                "retain_until_ms",
                "charged_bytes",
                "metadata_token",
            ]
        );
        assert_eq!(
            explicit_indexes(&connection, "admin_commands"),
            ["idx_admin_commands_pending", "idx_admin_commands_retention"]
        );
        assert_eq!(
            index_shape(
                &connection,
                "admin_commands",
                "idx_admin_commands_retention"
            ),
            IndexShape {
                unique: false,
                partial: false,
                columns: vec!["retain_until_ms".to_owned(), "idempotency_token".to_owned()],
                sql: "CREATE INDEX idx_admin_commands_retention\n    ON admin_commands(retain_until_ms, idempotency_token)".to_owned(),
            }
        );
        let pending = index_shape(&connection, "admin_commands", "idx_admin_commands_pending");
        assert!(!pending.unique);
        assert!(pending.partial);
        assert_eq!(
            pending.columns,
            ["state_changed_at_ms", "idempotency_token"]
        );
        assert!(pending.sql.ends_with("WHERE state = 'pending'"));
    }

    #[test]
    fn v8_adds_authenticated_machine_identity_singleton_without_rotating_crypto_context() {
        assert_eq!(RUNTIME_SCHEMA_VERSION_V8, 8);
        assert_eq!(RUNTIME_CRYPTO_CONTEXT_VERSION, 1);
        assert_eq!(EXPECTED_TABLES_V8.len(), 24);
        assert_ne!(EXPECTED_TABLES.as_slice(), EXPECTED_TABLES_V8.as_slice());
        assert_ne!(schema_signature(), schema_signature_v8());
        assert_ne!(schema_signature_v7(), schema_signature_v8());
        assert_eq!(RUNTIME_LEDGER_DOMAIN_V8, b"runtime.meta.ledger.v8");

        let connection = v8_structural_connection();
        assert_eq!(table_names(&connection), EXPECTED_TABLES_V8);
        assert_eq!(
            table_columns(&connection, "runtime_meta")
                .last()
                .map(String::as_str),
            Some("machine_identity_count")
        );
        assert_eq!(
            table_columns(&connection, "machine_identity_state"),
            [
                "singleton",
                "identity_state",
                "database_id",
                "root_key_id",
                "trust_epoch",
                "link_generation",
                "data_generation",
                "key_directory_revision",
                "root_public_key",
                "root_fingerprint",
                "machine_hpke_public_key",
                "machine_hpke_fingerprint",
                "link_sign_public_key",
                "link_sign_fingerprint",
                "data_sign_public_key",
                "data_sign_fingerprint",
                "metadata_token",
            ]
        );
        assert!(
            explicit_indexes(&connection, "machine_identity_state").is_empty(),
            "singleton identity row needs no secondary index"
        );
        assert!(
            foreign_key_columns(&connection, "machine_identity_state").is_empty(),
            "database binding is authenticated and checked by the v8 full audit"
        );
        let sql = table_sql(&connection, "machine_identity_state");
        for forbidden in [
            "private",
            "seed",
            "ikm",
            "storage_kek",
            "counter_guard",
            "certificate",
        ] {
            assert!(
                !sql.to_ascii_lowercase().contains(forbidden),
                "v8 identity row must not contain {forbidden} material"
            );
        }
    }

    #[test]
    fn v9_adds_bounded_authenticated_machine_remote_singleton_without_rotating_crypto_context() {
        assert_eq!(RUNTIME_SCHEMA_VERSION_V9, 9);
        assert_eq!(RUNTIME_CRYPTO_CONTEXT_VERSION, 1);
        assert_eq!(EXPECTED_TABLES_V8.len(), 24);
        assert_eq!(EXPECTED_TABLES_V9.len(), 25);
        assert_ne!(EXPECTED_TABLES.as_slice(), EXPECTED_TABLES_V9.as_slice());
        assert_ne!(schema_signature(), schema_signature_v9());
        assert_ne!(schema_signature_v8(), schema_signature_v9());
        assert_eq!(RUNTIME_LEDGER_DOMAIN_V9, b"runtime.meta.ledger.v9");

        let connection = v9_structural_connection();
        assert_eq!(table_names(&connection), EXPECTED_TABLES_V9);
        assert_eq!(
            table_columns(&connection, "runtime_meta")
                .last()
                .map(String::as_str),
            Some("machine_remote_state_count")
        );
        assert_eq!(
            table_columns(&connection, "machine_remote_state"),
            [
                "singleton",
                "lifecycle",
                "reset_kind",
                "database_id",
                "relay_server_id",
                "machine_route",
                "root_key_id",
                "root_fingerprint",
                "trust_epoch",
                "request_hash",
                "response_hash",
                "enrollment_receipt_hash",
                "receipt_verify_key_hash",
                "sealed_state",
                "sealed_state_bytes",
                "metadata_token",
            ]
        );
        assert!(
            explicit_indexes(&connection, "machine_remote_state").is_empty(),
            "singleton remote row needs no secondary index"
        );
        assert!(foreign_key_columns(&connection, "machine_remote_state").is_empty());
        let sql = table_sql(&connection, "machine_remote_state");
        for forbidden in [
            "enrollment_code",
            "origin",
            "pinset",
            "certificate",
            "purge_proof",
            "private_key",
        ] {
            assert!(
                !sql.to_ascii_lowercase().contains(forbidden),
                "v9 remote row must not persist plaintext {forbidden}"
            );
        }
    }

    #[test]
    fn v10_adds_five_bounded_remote_security_tables_without_rotating_crypto_context() {
        assert_eq!(RUNTIME_SCHEMA_VERSION_V10, 10);
        assert_eq!(RUNTIME_CRYPTO_CONTEXT_VERSION, 1);
        assert_eq!(EXPECTED_TABLES_V9.len(), 25);
        assert_eq!(EXPECTED_TABLES_V10.len(), 30);
        assert_ne!(EXPECTED_TABLES.as_slice(), EXPECTED_TABLES_V10.as_slice());
        assert_ne!(schema_signature(), schema_signature_v10());
        assert_ne!(schema_signature_v9(), schema_signature_v10());
        assert_eq!(RUNTIME_LEDGER_DOMAIN_V10, b"runtime.meta.ledger.v10");

        let connection = v10_structural_connection();
        assert_eq!(table_names(&connection), EXPECTED_TABLES_V10);
        assert_eq!(
            &table_columns(&connection, "runtime_meta")
                [table_columns(&connection, "runtime_meta").len() - 16..],
            [
                "remote_pairing_count",
                "remote_pairing_sealed_bytes",
                "remote_pairing_receipt_count",
                "remote_pairing_receipt_bytes",
                "remote_authorization_count",
                "remote_authorization_preparing_count",
                "remote_authorization_active_count",
                "remote_authorization_revoking_count",
                "remote_authorization_revoked_count",
                "remote_authorization_sealed_bytes",
                "remote_key_directory_count",
                "remote_key_directory_sealed_bytes",
                "remote_control_outbox_count",
                "remote_control_outbox_pending_count",
                "remote_control_outbox_acknowledged_count",
                "remote_control_outbox_sealed_bytes",
            ]
        );
        for table in [
            "remote_pairings",
            "remote_pairing_receipts",
            "remote_authorization_ledger",
            "remote_key_directory",
            "remote_control_outbox",
        ] {
            let sql = table_sql(&connection, table).to_ascii_lowercase();
            assert!(
                sql.contains("metadata_token"),
                "{table} must be row-authenticated"
            );
            assert!(
                sql.contains("database_id"),
                "{table} must bind the runtime database"
            );
        }
        assert!(!table_sql(&connection, "remote_pairings").contains("receiptTombstone"));
        assert!(!table_sql(&connection, "remote_pairings").contains("sealed_receipt"));
        assert!(table_sql(&connection, "remote_pairings").contains("orphanRevoking"));
        assert!(table_sql(&connection, "remote_pairing_receipts").contains("2592000000"));
        let receipt_columns = table_columns(&connection, "remote_pairing_receipts");
        assert!(receipt_columns.contains(&"idempotency_token".to_owned()));
        assert!(receipt_columns.contains(&"input_hash".to_owned()));
        assert!(!receipt_columns.contains(&"owner".to_owned()));
        assert!(!receipt_columns.contains(&"idempotency_key".to_owned()));
        let authorization_sql = table_sql(&connection, "remote_authorization_ledger");
        assert!(authorization_sql.contains("'superseded'"));
        assert!(
            authorization_sql.contains("lifecycle IN ('grantPreparing', 'active', 'superseded')")
        );
        let authorization_columns = table_columns(&connection, "remote_authorization_ledger");
        assert!(authorization_columns.contains(&"sealed_authorization".to_owned()));
        assert!(!authorization_columns.contains(&"device_sign_public_key".to_owned()));
        assert!(!authorization_columns.contains(&"device_hpke_public_key".to_owned()));
        assert_eq!(
            explicit_indexes(&connection, "remote_pairings"),
            ["idx_remote_pairings_recovery"]
        );
        assert_eq!(
            explicit_indexes(&connection, "remote_pairing_receipts"),
            [
                "idx_remote_pairing_receipts_idempotency",
                "idx_remote_pairing_receipts_retention",
            ]
        );
        assert_eq!(
            explicit_indexes(&connection, "remote_authorization_ledger"),
            [
                "idx_remote_authorization_current",
                "idx_remote_authorization_recovery",
            ]
        );
        let current_authorization = index_shape(
            &connection,
            "remote_authorization_ledger",
            "idx_remote_authorization_current",
        );
        assert!(current_authorization.unique);
        assert!(current_authorization.partial);
        assert_eq!(current_authorization.columns, ["device_route"]);
        assert!(
            current_authorization
                .sql
                .contains("WHERE lifecycle IN ('grantPreparing', 'active', 'revoking')")
        );
        assert!(!current_authorization.sql.contains("superseded"));
        assert!(!current_authorization.sql.contains("revoked"));
        let outbox_fks = foreign_key_columns(&connection, "remote_control_outbox");
        assert_eq!(outbox_fks.len(), 3);
        assert!(
            outbox_fks.iter().all(|foreign| {
                foreign.on_update == "RESTRICT" && foreign.on_delete == "RESTRICT"
            })
        );
        assert!(outbox_fks.iter().any(|foreign| {
            foreign.target_table == "remote_pairings" && foreign.source_column == "pairing_id"
        }));
        assert_eq!(
            outbox_fks
                .iter()
                .filter(|foreign| foreign.target_table == "remote_authorization_ledger")
                .count(),
            2
        );
    }

    #[test]
    fn v11_adds_authenticated_replay_and_counter_state_without_rotating_crypto_context() {
        assert_eq!(RUNTIME_SCHEMA_VERSION_V11, 11);
        assert_eq!(RUNTIME_CRYPTO_CONTEXT_VERSION, 1);
        assert_eq!(EXPECTED_TABLES_V10.len(), 30);
        assert_eq!(EXPECTED_TABLES_V11.len(), 32);
        assert_ne!(EXPECTED_TABLES.as_slice(), EXPECTED_TABLES_V11.as_slice());
        assert_ne!(schema_signature(), schema_signature_v11());
        assert_ne!(schema_signature_v10(), schema_signature_v11());
        assert_eq!(RUNTIME_LEDGER_DOMAIN_V11, b"runtime.meta.ledger.v11");

        let connection = v11_structural_connection();
        assert_eq!(table_names(&connection), EXPECTED_TABLES_V11);
        assert_eq!(
            &table_columns(&connection, "runtime_meta")
                [table_columns(&connection, "runtime_meta").len() - 6..],
            [
                "remote_replay_scope_count",
                "remote_replay_retired_scope_count",
                "remote_replay_pin_count",
                "remote_replay_sealed_bytes",
                "remote_counter_state_count",
                "remote_counter_state_sealed_bytes",
            ]
        );
        assert_eq!(
            table_columns(&connection, "remote_replay_states"),
            [
                "scope_token",
                "database_id",
                "retired_at_ms",
                "sealed_state",
                "sealed_state_bytes",
                "metadata_token",
            ]
        );
        assert_eq!(
            table_columns(&connection, "remote_counter_states"),
            [
                "scope_token",
                "database_id",
                "purpose",
                "key_epoch",
                "reserved_end",
                "reservation_id",
                "db_anchor",
                "lifecycle",
                "sealed_state",
                "sealed_state_bytes",
                "metadata_token",
            ]
        );
        for table in ["remote_replay_states", "remote_counter_states"] {
            let sql = table_sql(&connection, table).to_ascii_lowercase();
            assert!(sql.contains("database_id"));
            assert!(sql.contains("sealed_state"));
            assert!(sql.contains("metadata_token"));
        }
        assert_eq!(
            explicit_indexes(&connection, "remote_replay_states"),
            ["idx_remote_replay_retired"]
        );
        assert_eq!(
            explicit_indexes(&connection, "remote_counter_states"),
            ["idx_remote_counter_lifecycle"]
        );
    }

    #[test]
    fn v12_adds_authenticated_key_transition_and_update_outbox_without_rotating_crypto_context() {
        assert_eq!(RUNTIME_SCHEMA_VERSION, RUNTIME_SCHEMA_VERSION_V14);
        assert_eq!(RUNTIME_SCHEMA_VERSION_V12, 12);
        assert_eq!(RUNTIME_CRYPTO_CONTEXT_VERSION, 1);
        assert_eq!(EXPECTED_TABLES_V11.len(), 32);
        assert_eq!(EXPECTED_TABLES_V12.len(), 35);
        assert_eq!(EXPECTED_TABLES_V13, EXPECTED_TABLES_V12);
        assert_ne!(EXPECTED_TABLES.as_slice(), EXPECTED_TABLES_V11.as_slice());
        assert_ne!(schema_signature(), schema_signature_v12());
        assert_ne!(schema_signature_v11(), schema_signature_v12());
        assert_eq!(RUNTIME_LEDGER_DOMAIN_V12, b"runtime.meta.ledger.v12");

        let connection = v12_structural_connection();
        assert_eq!(table_names(&connection), EXPECTED_TABLES_V12);
        assert_eq!(
            &table_columns(&connection, "runtime_meta")
                [table_columns(&connection, "runtime_meta").len() - 6..],
            [
                "remote_counter_guard_manifest_count",
                "remote_key_transition_count",
                "remote_key_transition_active_count",
                "remote_key_transition_sealed_bytes",
                "remote_key_update_outbox_count",
                "remote_key_update_outbox_sealed_bytes",
            ]
        );
        let manifest_sql =
            table_sql(&connection, "remote_counter_guard_manifest").to_ascii_lowercase();
        assert_eq!(
            table_columns(&connection, "remote_counter_guard_manifest"),
            ["scope_token", "database_id", "phase", "metadata_token"]
        );
        assert!(manifest_sql.contains("scope_token"));
        assert!(manifest_sql.contains("database_id"));
        assert!(manifest_sql.contains("phase"));
        assert!(manifest_sql.contains("'reserved'"));
        assert!(manifest_sql.contains("'materialized'"));
        assert!(manifest_sql.contains("metadata_token"));
        for table in ["remote_key_transitions", "remote_key_update_outbox"] {
            let sql = table_sql(&connection, table).to_ascii_lowercase();
            assert!(sql.contains("database_id"));
            assert!(sql.contains("sealed_state"));
            assert!(sql.contains("metadata_token"));
        }
        let active = index_shape(
            &connection,
            "remote_key_transitions",
            "idx_remote_key_transition_active",
        );
        assert!(active.unique);
        assert!(active.partial);
        assert_eq!(active.columns, ["active_slot"]);
        assert!(active.sql.contains("WHERE phase <> 'Complete'"));
        assert_eq!(
            foreign_key_columns(&connection, "remote_key_update_outbox")
                .iter()
                .filter(|foreign| foreign.target_table == "remote_key_transitions")
                .count(),
            1
        );
    }

    #[test]
    fn v13_rebuilds_publication_tables_and_only_accepts_authenticated_inner_baseline() {
        assert_eq!(RUNTIME_SCHEMA_VERSION, RUNTIME_SCHEMA_VERSION_V14);
        assert_eq!(RUNTIME_SCHEMA_VERSION_V13, 13);
        assert_eq!(RUNTIME_CRYPTO_CONTEXT_VERSION, 1);
        assert_eq!(EXPECTED_TABLES_V13, EXPECTED_TABLES_V12);
        assert_eq!(EXPECTED_TABLES_V14, EXPECTED_TABLES_V13);
        assert_eq!(EXPECTED_TABLES, EXPECTED_TABLES_V14);
        assert_ne!(schema_signature(), schema_signature_v13());
        assert_ne!(schema_signature_v12(), schema_signature_v13());
        assert_eq!(RUNTIME_LEDGER_DOMAIN_V13, b"runtime.meta.ledger.v13");

        let connection = v13_structural_connection();
        assert_eq!(table_names(&connection), EXPECTED_TABLES_V13);
        assert_eq!(
            explicit_indexes(&connection, "publication_streams"),
            [
                "idx_publication_active_catalog",
                "idx_publication_active_conversation",
            ]
        );
        assert_eq!(
            explicit_indexes(&connection, "publication_outbox"),
            ["idx_publication_pending"]
        );
        assert_eq!(
            foreign_key_columns(&connection, "publication_outbox")
                .iter()
                .filter(|foreign| foreign.target_table == "publication_streams")
                .count(),
            2
        );
        let legacy_table_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema
                 WHERE name IN ('publication_streams_v12', 'publication_outbox_v12')",
                [],
                |row| row.get(0),
            )
            .expect("count temporary v12 tables");
        assert_eq!(legacy_table_count, 0);
        let foreign_key_violation_count: i64 = connection
            .query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
                row.get(0)
            })
            .expect("count foreign-key violations");
        assert_eq!(foreign_key_violation_count, 0);

        let inner_h = "00000000000000000042";
        let inner_before_h = "00000000000000000041";
        let rotation_serial = "00000000000000000001";
        let zero_rotation_serial = "00000000000000000000";
        let rotation_digest = [0xA5_u8; 32];
        insert_v13_rotation_baseline(
            &connection,
            1,
            Some(inner_h),
            Some(inner_h),
            rotation_serial,
            Some(&rotation_digest),
        )
        .expect("accept authenticated (BeforeFirst, H) baseline");

        for (identity_byte, committed, acknowledged, serial, digest) in [
            (
                10,
                Some(inner_h),
                Some(inner_h),
                zero_rotation_serial,
                Some(rotation_digest.as_slice()),
            ),
            (11, Some(inner_h), Some(inner_h), rotation_serial, None),
            (
                12,
                Some(inner_h),
                Some(inner_before_h),
                rotation_serial,
                Some(rotation_digest.as_slice()),
            ),
            (
                13,
                None,
                Some(inner_h),
                rotation_serial,
                Some(rotation_digest.as_slice()),
            ),
        ] {
            assert!(
                insert_v13_rotation_baseline(
                    &connection,
                    identity_byte,
                    committed,
                    acknowledged,
                    serial,
                    digest,
                )
                .is_err(),
                "invalid inner baseline {identity_byte} must fail closed"
            );
        }
    }

    #[test]
    fn v14_rebuilds_key_update_outbox_with_protocol_and_codec_capacity() {
        assert_eq!(RUNTIME_SCHEMA_VERSION, RUNTIME_SCHEMA_VERSION_V14);
        assert_eq!(RUNTIME_SCHEMA_VERSION_V14, 14);
        assert_eq!(RUNTIME_CRYPTO_CONTEXT_VERSION, 1);
        assert_eq!(EXPECTED_TABLES_V14, EXPECTED_TABLES_V13);
        assert_eq!(EXPECTED_TABLES, EXPECTED_TABLES_V14);
        assert_eq!(schema_signature(), schema_signature_v14());
        assert_ne!(schema_signature_v13(), schema_signature_v14());
        assert_eq!(RUNTIME_LEDGER_DOMAIN_V14, b"runtime.meta.ledger.v14");

        let connection = v14_structural_connection();
        assert_eq!(table_names(&connection), EXPECTED_TABLES_V14);
        let update_sql = table_sql(&connection, "remote_key_update_outbox");
        assert_eq!(
            check_upper_bound(&update_sql, "canonical_update_bytes BETWEEN 1 AND "),
            RUNTIME_KEY_UPDATE_MAX_CANONICAL_BYTES,
            "SQLite canonical admission must track the protocol KeyUpdateSet cap"
        );
        assert_eq!(
            check_upper_bound(&update_sql, "length(sealed_state) BETWEEN 40 AND "),
            RUNTIME_KEY_UPDATE_MAX_SEALED_STATE_BYTES,
            "SQLite sealed-state admission must track codec plaintext plus row overhead"
        );
        assert_eq!(
            explicit_indexes(&connection, "remote_key_update_outbox"),
            ["idx_remote_key_update_recovery"]
        );
        assert_eq!(
            foreign_key_columns(&connection, "remote_key_update_outbox")
                .iter()
                .filter(|foreign| foreign.target_table == "remote_key_transitions")
                .count(),
            1
        );
        let legacy_table_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema
                 WHERE name = 'remote_key_update_outbox_v13'",
                [],
                |row| row.get(0),
            )
            .expect("count temporary v13 key-update table");
        assert_eq!(legacy_table_count, 0);
        let foreign_key_violation_count: i64 = connection
            .query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
                row.get(0)
            })
            .expect("count v14 foreign-key violations");
        assert_eq!(foreign_key_violation_count, 0);
    }

    #[test]
    fn v10_close_ack_must_remove_outbox_before_secret_row_and_keeps_receipt_tombstone() {
        let mut connection = v10_structural_connection();
        connection
            .pragma_update(None, "foreign_keys", true)
            .expect("enable foreign keys");
        let transaction = connection
            .transaction()
            .expect("begin close ACK transaction");
        transaction
            .execute(
                "INSERT INTO machine_remote_state (
                     singleton, lifecycle, reset_kind, database_id, relay_server_id, machine_route,
                     root_key_id, root_fingerprint, trust_epoch, request_hash, response_hash,
                     enrollment_receipt_hash, receipt_verify_key_hash, sealed_state,
                     sealed_state_bytes, metadata_token
                 ) VALUES (1, 'enrollmentPrepared', NULL, ?1, ?2, ?3, ?4, ?5,
                           '00000000000000000001', ?6, NULL, NULL, ?7, ?8, 40, ?9)",
                params![
                    &[1_u8; 16],
                    &[2_u8; 16],
                    &[3_u8; 16],
                    &[4_u8; 16],
                    &[5_u8; 32],
                    &[6_u8; 32],
                    &[7_u8; 32],
                    &[8_u8; 40],
                    &[9_u8; 32],
                ],
            )
            .expect("insert machine parent");
        transaction
            .execute(
                "INSERT INTO remote_pairings (
                     pairing_id, lifecycle, database_id, relay_server_id, machine_route,
                     pair_route, expires_at_ms, created_at_ms, state_changed_at_ms,
                     request_hash, device_sign_fingerprint, grant_hash, response_hash,
                     sealed_state, sealed_state_bytes, metadata_token
                 ) VALUES (?1, 'canceled', ?2, ?3, ?4, ?5, 301000, 1000, 1000,
                           NULL, NULL, NULL, NULL, ?6, 40, ?7)",
                params![
                    &[10_u8; 16],
                    &[1_u8; 16],
                    &[2_u8; 16],
                    &[3_u8; 16],
                    &[11_u8; 16],
                    &[12_u8; 40],
                    &[13_u8; 32],
                ],
            )
            .expect("insert terminal pairing secret row");
        transaction
            .execute(
                "INSERT INTO remote_control_outbox (
                     outbox_id, operation_kind, operation_key, lifecycle, database_id,
                     pairing_id, device_route, grant_serial, frame_hash, sealed_frame,
                     sealed_frame_bytes, terminal_hash, sealed_terminal,
                     sealed_terminal_bytes, created_at_ms, state_changed_at_ms, metadata_token
                 ) VALUES (?1, 'closePairRoute', ?2, 'prepared', ?3, ?4, NULL, NULL,
                           ?5, ?6, 40, NULL, NULL, NULL, 1000, 1000, ?7)",
                params![
                    &[14_u8; 16],
                    &[15_u8; 32],
                    &[1_u8; 16],
                    &[10_u8; 16],
                    &[16_u8; 32],
                    &[17_u8; 40],
                    &[18_u8; 32],
                ],
            )
            .expect("insert close outbox");
        assert!(
            transaction
                .execute(
                    "DELETE FROM remote_pairings WHERE pairing_id = ?1",
                    params![&[10_u8; 16]],
                )
                .is_err(),
            "RESTRICT must prevent scrubbing the secret row before close outbox resolution"
        );
        transaction
            .execute(
                "INSERT INTO remote_pairing_receipts (
                     pairing_id, database_id, relay_server_id, machine_route, pair_route,
                     idempotency_token, input_hash, action, request_hash, receipt_hash,
                     canonical_receipt, receipt_bytes, created_at_ms, retain_until_ms,
                     metadata_token
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'canceled', NULL, ?8, X'01', 1,
                           1000, 2592001000, ?9)",
                params![
                    &[10_u8; 16],
                    &[1_u8; 16],
                    &[2_u8; 16],
                    &[3_u8; 16],
                    &[11_u8; 16],
                    &[21_u8; 32],
                    &[22_u8; 32],
                    &[19_u8; 32],
                    &[20_u8; 32],
                ],
            )
            .expect("insert canonical receipt tombstone");
        transaction
            .execute(
                "DELETE FROM remote_control_outbox WHERE outbox_id = ?1",
                params![&[14_u8; 16]],
            )
            .expect("remove acknowledged close outbox first");
        transaction
            .execute(
                "DELETE FROM remote_pairings WHERE pairing_id = ?1",
                params![&[10_u8; 16]],
            )
            .expect("scrub pairing secret after close outbox removal");
        transaction.commit().expect("commit close ACK ordering");
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM remote_pairing_receipts", [], |row| {
                    row.get::<_, i64>(0)
                })
                .expect("count receipt tombstones"),
            1
        );
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM remote_pairings", [], |row| {
                    row.get::<_, i64>(0)
                })
                .expect("count pairing secret rows"),
            0
        );
    }

    #[test]
    fn v9_machine_remote_state_enforces_lifecycle_hash_and_reset_combinations() {
        let connection = v9_structural_connection();
        let database_id = [0x11_u8; 16];
        let relay_server_id = [0x12_u8; 16];
        let machine_route = [0x13_u8; 16];
        let root_key_id = [0x14_u8; 16];
        let root_fingerprint = [0x15_u8; 32];
        let request_hash = [0x16_u8; 32];
        let response_hash = [0x17_u8; 32];
        let receipt_hash = [0x18_u8; 32];
        let verify_key_hash = [0x19_u8; 32];
        let sealed_state = [0x1A_u8; 40];
        let metadata_token = [0x1B_u8; 32];
        let insert = |lifecycle: &str,
                      reset_kind: Option<&str>,
                      response_present: bool,
                      receipt_present: bool| {
            connection.execute(
                "INSERT INTO machine_remote_state (
                     singleton, lifecycle, reset_kind, database_id, relay_server_id,
                     machine_route, root_key_id, root_fingerprint, trust_epoch,
                     request_hash, response_hash, enrollment_receipt_hash,
                     receipt_verify_key_hash, sealed_state, sealed_state_bytes, metadata_token
                 ) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, 40, ?14)",
                params![
                    lifecycle,
                    reset_kind,
                    &database_id[..],
                    &relay_server_id[..],
                    &machine_route[..],
                    &root_key_id[..],
                    &root_fingerprint[..],
                    "00000000000000000001",
                    &request_hash[..],
                    response_present.then_some(&response_hash[..]),
                    receipt_present.then_some(&receipt_hash[..]),
                    &verify_key_hash[..],
                    &sealed_state[..],
                    &metadata_token[..],
                ],
            )
        };

        for (lifecycle, reset_kind, response_present, receipt_present) in [
            ("enrollmentPrepared", None, false, false),
            ("enrollmentResponseValidated", None, true, false),
            ("active", None, true, true),
            ("retirePending", Some("rootPresent"), true, true),
            ("relayCommitted", Some("rootPresent"), true, true),
            ("purgeReadbackAbsent", Some("rootLost"), true, true),
            ("localDeleted", Some("rootPresent"), true, true),
        ] {
            insert(lifecycle, reset_kind, response_present, receipt_present)
                .unwrap_or_else(|error| panic!("valid {lifecycle}/{reset_kind:?}: {error}"));
            connection
                .execute("DELETE FROM machine_remote_state", [])
                .expect("clear valid remote state");
        }

        for (lifecycle, reset_kind, response_present, receipt_present) in [
            ("enrollmentPrepared", Some("rootPresent"), false, false),
            ("enrollmentPrepared", None, true, false),
            ("enrollmentResponseValidated", None, false, false),
            ("active", None, true, false),
            ("retirePending", Some("rootLost"), true, true),
            ("relayCommitted", None, true, true),
        ] {
            assert!(
                insert(lifecycle, reset_kind, response_present, receipt_present).is_err(),
                "invalid {lifecycle}/{reset_kind:?} combination must be rejected"
            );
        }

        insert("active", None, true, true).expect("insert active hash constraint fixture");
        for column in [
            "root_fingerprint",
            "request_hash",
            "response_hash",
            "enrollment_receipt_hash",
            "receipt_verify_key_hash",
        ] {
            assert!(
                connection
                    .execute(
                        &format!(
                            "UPDATE machine_remote_state SET {column} = zeroblob(32) WHERE singleton = 1"
                        ),
                        [],
                    )
                    .is_err(),
                "all-zero {column} must be rejected"
            );
        }
        assert!(
            connection
                .execute(
                    "UPDATE machine_remote_state SET sealed_state_bytes = 40.5 WHERE singleton = 1",
                    [],
                )
                .is_err(),
            "sealed_state_bytes must remain an integer"
        );
    }

    #[test]
    fn v6_sidecars_have_frozen_columns_indexes_and_foreign_keys() {
        let connection = v6_structural_connection();
        assert_eq!(
            table_columns(&connection, "native_projection_state"),
            [
                "conversation_id",
                "origin_namespace",
                "state_reference_token",
                "projection_state",
                "scan_generation",
                "observation_token",
                "projection_catalog_revision",
                "reconciled_at_ms",
                "state_changed_at_ms",
                "private_binding_retain_until_ms",
                "charged_reference_bytes",
                "metadata_token",
            ]
        );
        assert_eq!(
            table_columns(&connection, "native_metadata_effect_fences"),
            [
                "conversation_id",
                "idempotency_token",
                "daemon_boot_id",
                "effect_nonce_token",
                "effect_spec_token",
                "process_group_id",
                "leader_pid",
                "leader_start_time",
                "release_authorized_at_ms",
                "release_token_commitment",
                "logical_fence_bytes",
                "metadata_token",
                "sealed_fence",
            ]
        );
        assert_eq!(
            explicit_indexes(&connection, "native_projection_state"),
            [
                "idx_native_projection_retention",
                "idx_native_projection_scan"
            ]
        );
        assert!(
            explicit_indexes(&connection, "native_metadata_effect_fences").is_empty(),
            "effect-fence recovery joins by its composite primary key"
        );

        let projection_fks = foreign_key_columns(&connection, "native_projection_state");
        assert_composite_foreign_key(
            &projection_fks,
            "conversation_state",
            &[("conversation_id", "conversation_id")],
        );
        let fence_fks = foreign_key_columns(&connection, "native_metadata_effect_fences");
        assert_composite_foreign_key(
            &fence_fks,
            "metadata_mutation_ledger",
            &[
                ("conversation_id", "conversation_id"),
                ("idempotency_token", "idempotency_token"),
            ],
        );
        for foreign_key in projection_fks.iter().chain(fence_fks.iter()) {
            assert_eq!(foreign_key.on_update, "RESTRICT");
            assert_eq!(foreign_key.on_delete, "RESTRICT");
        }
    }

    #[test]
    fn v5_sidecar_freeze_remains_stable_without_changing_the_v4_surface() {
        assert_eq!(RUNTIME_SCHEMA_VERSION_V5, 5);
        assert_eq!(EXPECTED_TABLES_V4.len(), 16);
        assert_eq!(EXPECTED_TABLES_V5.len(), 20);
        assert_eq!(schema_signature_v4(), V4_SCHEMA_SIGNATURE_GOLDEN);
        assert_eq!(schema_signature_v5(), V5_SCHEMA_SIGNATURE_GOLDEN);
        let mut expected_v5 = Sha256::new();
        for migration in [
            RUNTIME_DDL_V1,
            RUNTIME_MIGRATION_V2,
            RUNTIME_MIGRATION_V3,
            RUNTIME_MIGRATION_V4,
            RUNTIME_MIGRATION_V5,
        ] {
            expected_v5.update(migration.as_bytes());
        }
        assert_eq!(
            schema_signature_v5(),
            <[u8; 32]>::from(expected_v5.finalize())
        );
        assert_ne!(schema_signature_v4(), schema_signature_v5());
        assert_eq!(RUNTIME_LEDGER_DOMAIN_V4, b"runtime.meta.ledger.v4");
        assert_eq!(RUNTIME_LEDGER_DOMAIN_V5, b"runtime.meta.ledger.v5");
        assert_eq!(MAX_CONFIGURATION_BYTES, 16 * 1024);
        assert_eq!(MAX_CONFIGURATION_REQUEST_BYTES, 32 * 1024);
        assert_eq!(MAX_CONFIGURATION_VERSIONS_PER_CONVERSATION, 4_096);
        assert_eq!(MAX_CONFIGURATION_VERSIONS_GLOBAL, 65_536);
        assert_eq!(MAX_CONFIGURATION_SEALED_BYTES_GLOBAL, 64 * 1024 * 1024);
        assert_eq!(MAX_COMMAND_CONFIGURATION_PINS, 1_048_576);
        assert_eq!(MAX_METADATA_MUTATION_REQUEST_BYTES, 16 * 1024);
        assert_eq!(MAX_METADATA_MUTATION_OUTCOME_BYTES, 16 * 1024);
        assert_eq!(MAX_METADATA_MUTATIONS_PER_CONVERSATION, 4_096);
        assert_eq!(MAX_METADATA_MUTATIONS_GLOBAL, 65_536);
        assert_eq!(MAX_ACTIVE_METADATA_MUTATIONS, 1_024);
        assert_eq!(MAX_METADATA_MUTATION_CHARGED_BYTES_GLOBAL, 64 * 1024 * 1024);
    }

    #[test]
    fn v5_schema_has_exact_sidecar_manifest_columns_and_indexes() {
        let connection = v5_structural_connection();
        assert_eq!(table_names(&connection), EXPECTED_TABLES_V5);
        assert_eq!(
            &table_columns(&connection, "runtime_meta")
                [table_columns(&connection, "runtime_meta").len() - 6..],
            [
                "configuration_count",
                "configuration_sealed_bytes",
                "command_configuration_pin_count",
                "metadata_mutation_count",
                "active_metadata_mutation_count",
                "metadata_mutation_charged_bytes",
            ]
        );
        let meta_columns = table_column_details(&connection, "runtime_meta");
        for column in &meta_columns[meta_columns.len() - 6..] {
            assert_eq!(column.column_type, "INTEGER", "{} type", column.name);
            assert!(column.not_null, "{} must be NOT NULL", column.name);
            assert_eq!(
                column.default_value.as_deref(),
                Some("0"),
                "{} default",
                column.name
            );
        }
        assert_eq!(
            table_columns(&connection, "conversation_state"),
            [
                "conversation_id",
                "current_configuration_revision",
                "entry_revision",
                "origin_kind",
                "origin_namespace",
                "legacy_command_high_water",
                "metadata_token",
            ]
        );
        assert_eq!(
            table_columns(&connection, "configuration_journal"),
            [
                "conversation_id",
                "configuration_revision",
                "base_configuration_revision",
                "event_seq",
                "owner_token",
                "idempotency_token",
                "request_token",
                "logical_configuration_bytes",
                "logical_request_bytes",
                "created_at_ms",
                "metadata_token",
                "sealed_request",
            ]
        );
        assert_eq!(
            table_columns(&connection, "command_configuration_pins"),
            [
                "conversation_id",
                "command_seq",
                "configuration_revision",
                "metadata_token",
            ]
        );
        assert_eq!(
            table_columns(&connection, "metadata_mutation_ledger"),
            [
                "conversation_id",
                "owner_token",
                "idempotency_token",
                "request_token",
                "expected_entry_revision",
                "applied_entry_revision",
                "applied_catalog_revision",
                "state",
                "logical_request_bytes",
                "logical_outcome_bytes",
                "charged_outcome_bytes",
                "created_at_ms",
                "state_changed_at_ms",
                "metadata_token",
                "sealed_request",
                "sealed_outcome",
            ]
        );
        assert_eq!(
            explicit_indexes(&connection, "conversation_state"),
            ["idx_conversation_state_origin"]
        );
        assert_eq!(
            explicit_indexes(&connection, "configuration_journal"),
            ["idx_configuration_event", "idx_configuration_idempotency"]
        );
        assert_eq!(
            explicit_indexes(&connection, "command_configuration_pins"),
            ["idx_command_configuration_pins_configuration"]
        );
        assert_eq!(
            explicit_indexes(&connection, "metadata_mutation_ledger"),
            [
                "idx_metadata_mutation_active",
                "idx_metadata_mutation_idempotency"
            ]
        );

        for (table, expected_primary_key) in [
            ("conversation_state", vec![("conversation_id", 1)]),
            (
                "configuration_journal",
                vec![("conversation_id", 1), ("configuration_revision", 2)],
            ),
            (
                "command_configuration_pins",
                vec![("conversation_id", 1), ("command_seq", 2)],
            ),
            (
                "metadata_mutation_ledger",
                vec![("conversation_id", 1), ("idempotency_token", 2)],
            ),
        ] {
            let actual = table_column_details(&connection, table)
                .into_iter()
                .filter(|column| column.primary_key_ordinal > 0)
                .map(|column| (column.name, column.primary_key_ordinal))
                .collect::<Vec<_>>();
            let expected = expected_primary_key
                .into_iter()
                .map(|(name, ordinal)| (name.to_owned(), ordinal))
                .collect::<Vec<_>>();
            assert_eq!(actual, expected, "{table} primary key");
        }

        assert_eq!(
            index_shape(&connection, "conversation_state", "idx_conversation_state_origin"),
            IndexShape {
                unique: false,
                partial: false,
                columns: vec!["origin_kind".to_owned(), "origin_namespace".to_owned()],
                sql: "CREATE INDEX idx_conversation_state_origin\n    ON conversation_state(origin_kind, origin_namespace)".to_owned(),
            }
        );
        for (name, columns) in [
            (
                "idx_configuration_event",
                vec!["conversation_id".to_owned(), "event_seq".to_owned()],
            ),
            (
                "idx_configuration_idempotency",
                vec!["idempotency_token".to_owned()],
            ),
        ] {
            let shape = index_shape(&connection, "configuration_journal", name);
            assert!(shape.unique, "{name} must be UNIQUE");
            assert!(!shape.partial, "{name} must cover every row");
            assert_eq!(shape.columns, columns, "{name} columns");
        }
        let pin_index = index_shape(
            &connection,
            "command_configuration_pins",
            "idx_command_configuration_pins_configuration",
        );
        assert!(!pin_index.unique);
        assert!(!pin_index.partial);
        assert_eq!(
            pin_index.columns,
            ["conversation_id", "configuration_revision"]
        );
        let metadata_idempotency = index_shape(
            &connection,
            "metadata_mutation_ledger",
            "idx_metadata_mutation_idempotency",
        );
        assert!(metadata_idempotency.unique);
        assert!(!metadata_idempotency.partial);
        assert_eq!(metadata_idempotency.columns, ["idempotency_token"]);
        let metadata_active = index_shape(
            &connection,
            "metadata_mutation_ledger",
            "idx_metadata_mutation_active",
        );
        assert!(!metadata_active.unique);
        assert!(metadata_active.partial);
        assert_eq!(
            metadata_active.columns,
            ["conversation_id", "state", "state_changed_at_ms"]
        );
        assert!(
            metadata_active
                .sql
                .contains("WHERE state IN ('claimed', 'applying', 'outcomeUnknown')")
        );
    }

    #[test]
    fn v5_schema_uses_same_conversation_composite_foreign_keys() {
        let connection = v5_structural_connection();
        let configuration_fks = foreign_key_columns(&connection, "configuration_journal");
        assert_eq!(configuration_fks.len(), 3);
        assert_composite_foreign_key(
            &configuration_fks,
            "conversations",
            &[("conversation_id", "conversation_id")],
        );
        assert_composite_foreign_key(
            &configuration_fks,
            "event_journal",
            &[
                ("conversation_id", "conversation_id"),
                ("event_seq", "event_seq"),
            ],
        );

        let state_fks = foreign_key_columns(&connection, "conversation_state");
        assert_eq!(state_fks.len(), 3);
        assert_composite_foreign_key(
            &state_fks,
            "conversations",
            &[("conversation_id", "conversation_id")],
        );
        assert_composite_foreign_key(
            &state_fks,
            "configuration_journal",
            &[
                ("conversation_id", "conversation_id"),
                ("current_configuration_revision", "configuration_revision"),
            ],
        );
        let pin_fks = foreign_key_columns(&connection, "command_configuration_pins");
        assert_eq!(pin_fks.len(), 4);
        assert_composite_foreign_key(
            &pin_fks,
            "commands",
            &[
                ("conversation_id", "conversation_id"),
                ("command_seq", "command_seq"),
            ],
        );
        assert_composite_foreign_key(
            &pin_fks,
            "configuration_journal",
            &[
                ("conversation_id", "conversation_id"),
                ("configuration_revision", "configuration_revision"),
            ],
        );

        let metadata_fks = foreign_key_columns(&connection, "metadata_mutation_ledger");
        assert_eq!(metadata_fks.len(), 1);
        assert_composite_foreign_key(
            &metadata_fks,
            "conversations",
            &[("conversation_id", "conversation_id")],
        );

        for table in [
            "conversation_state",
            "configuration_journal",
            "command_configuration_pins",
            "metadata_mutation_ledger",
        ] {
            for column in foreign_key_columns(&connection, table) {
                assert_eq!(column.on_update, "RESTRICT", "{table} update action");
                assert_eq!(column.on_delete, "RESTRICT", "{table} delete action");
            }
        }
    }

    fn assert_composite_foreign_key(
        columns: &[ForeignKeyColumn],
        target_table: &str,
        expected_columns: &[(&str, &str)],
    ) {
        let candidates = columns
            .iter()
            .filter(|column| column.target_table == target_table)
            .collect::<Vec<_>>();
        assert_eq!(
            candidates.len(),
            expected_columns.len(),
            "{target_table} FK"
        );
        let id = candidates[0].id;
        for (seq, (source, target)) in expected_columns.iter().enumerate() {
            let column = candidates
                .iter()
                .find(|column| column.id == id && column.seq == seq as i64)
                .expect("composite FK column");
            assert_eq!(column.source_column, *source);
            assert_eq!(column.target_column, *target);
        }
    }

    const SEQ_ZERO: &str = "00000000000000000000";
    const SEQ_ONE: &str = "00000000000000000001";

    fn insert_conversation(
        connection: &Connection,
        conversation_seed: u8,
        catalog_revision: &str,
        command_high_water: Option<&str>,
        event_high_water: Option<&str>,
    ) {
        connection
            .execute(
                "INSERT INTO conversations (
                     conversation_id, adapter_state_key, catalog_revision,
                     command_high_water, event_high_water, lifecycle,
                     created_at_ms, updated_at_ms, accepted_count,
                     metadata_token, sealed_descriptor
                 ) VALUES (?1, ?2, ?3, ?4, ?5, 'active', 1, 1, 0, ?6, ?7)",
                params![
                    &[conversation_seed; 16][..],
                    &[conversation_seed.wrapping_add(0x40); 16][..],
                    catalog_revision,
                    command_high_water,
                    event_high_water,
                    &[conversation_seed.wrapping_add(0x50); 32][..],
                    &[conversation_seed.wrapping_add(0x60); 40][..],
                ],
            )
            .expect("insert conversation fixture");
    }

    fn insert_event(
        connection: &Connection,
        conversation_seed: u8,
        event_seed: u8,
        event_seq: &str,
    ) {
        connection
            .execute(
                "INSERT INTO event_journal (
                     conversation_id, event_seq, event_id, command_id,
                     logical_event_bytes, created_at_ms, metadata_token, sealed_event
                 ) VALUES (?1, ?2, ?3, NULL, 1, 2, ?4, ?5)",
                params![
                    &[conversation_seed; 16][..],
                    event_seq,
                    &[event_seed; 16][..],
                    &[event_seed.wrapping_add(1); 32][..],
                    &[event_seed.wrapping_add(2); 40][..],
                ],
            )
            .expect("insert event fixture");
    }

    fn insert_command(connection: &Connection, conversation_seed: u8, command_seed: u8) {
        connection
            .execute(
                "INSERT INTO commands (
                     conversation_id, command_seq, command_id, owner_token,
                     idempotency_token, payload_token, terminal_token, turn_id,
                     started_event_id, terminal_event_id, state, logical_payload_bytes,
                     accepted_at_ms, expires_at_ms, retain_until_ms, started_at_ms,
                     terminal_at_ms, metadata_token, sealed_command, sealed_result
                 ) VALUES (
                     ?1, ?2, ?3, ?4, ?5, ?6, NULL, NULL, NULL, NULL,
                     'accepted', 1, 2, 3, 4, NULL, NULL, ?7, ?8, NULL
                 )",
                params![
                    &[conversation_seed; 16][..],
                    SEQ_ZERO,
                    &[command_seed; 16][..],
                    &[command_seed.wrapping_add(1); 32][..],
                    &[command_seed.wrapping_add(2); 32][..],
                    &[command_seed.wrapping_add(3); 32][..],
                    &[command_seed.wrapping_add(4); 32][..],
                    &[command_seed.wrapping_add(5); 40][..],
                ],
            )
            .expect("insert command fixture");
    }

    fn insert_configuration(
        connection: &Connection,
        conversation_seed: u8,
        token_seed: u8,
        event_seq: &str,
    ) -> rusqlite::Result<usize> {
        connection.execute(
            "INSERT INTO configuration_journal (
                 conversation_id, configuration_revision, base_configuration_revision,
                 event_seq, owner_token, idempotency_token, request_token,
                 logical_configuration_bytes, logical_request_bytes, created_at_ms,
                 metadata_token, sealed_request
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, 2, 3, ?8, ?9)",
            params![
                &[conversation_seed; 16][..],
                SEQ_ONE,
                SEQ_ZERO,
                event_seq,
                &[token_seed; 32][..],
                &[token_seed.wrapping_add(1); 32][..],
                &[token_seed.wrapping_add(2); 32][..],
                &[token_seed.wrapping_add(3); 32][..],
                &[token_seed.wrapping_add(4); 42][..],
            ],
        )
    }

    fn insert_state(
        connection: &Connection,
        conversation_seed: u8,
        current_revision: Option<&str>,
        origin_kind: &str,
        origin_namespace: Option<&str>,
        legacy_high_water: Option<&rusqlite::types::Value>,
    ) -> rusqlite::Result<usize> {
        connection.execute(
            "INSERT INTO conversation_state (
                 conversation_id, current_configuration_revision, entry_revision,
                 origin_kind, origin_namespace, legacy_command_high_water, metadata_token
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                &[conversation_seed; 16][..],
                current_revision,
                SEQ_ZERO,
                origin_kind,
                origin_namespace,
                legacy_high_water,
                &[conversation_seed.wrapping_add(0x70); 32][..],
            ],
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn insert_metadata_mutation(
        connection: &Connection,
        conversation_seed: u8,
        token_seed: u8,
        state: &str,
        applied_entry_revision: Option<&str>,
        applied_catalog_revision: Option<&str>,
        logical_outcome_bytes: i64,
        charged_outcome_bytes: i64,
        sealed_outcome: Option<&[u8]>,
        created_at_ms: i64,
        state_changed_at_ms: i64,
    ) -> rusqlite::Result<usize> {
        connection.execute(
            "INSERT INTO metadata_mutation_ledger (
                 conversation_id, owner_token, idempotency_token, request_token,
                 expected_entry_revision, applied_entry_revision,
                 applied_catalog_revision, state, logical_request_bytes,
                 logical_outcome_bytes, charged_outcome_bytes, created_at_ms,
                 state_changed_at_ms, metadata_token, sealed_request, sealed_outcome
             ) VALUES (
                 ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 1, ?9, ?10, ?11, ?12,
                 ?13, ?14, ?15
             )",
            params![
                &[conversation_seed; 16][..],
                &[token_seed; 32][..],
                &[token_seed.wrapping_add(1); 32][..],
                &[token_seed.wrapping_add(2); 32][..],
                SEQ_ZERO,
                applied_entry_revision,
                applied_catalog_revision,
                state,
                logical_outcome_bytes,
                charged_outcome_bytes,
                created_at_ms,
                state_changed_at_ms,
                &[token_seed.wrapping_add(3); 32][..],
                &[token_seed.wrapping_add(4); 41][..],
                sealed_outcome,
            ],
        )
    }

    #[test]
    fn v5_schema_locks_nullable_head_origin_caps_and_metadata_charging() {
        let connection = v5_structural_connection();
        let state_sql = table_sql(&connection, "conversation_state");
        assert!(state_sql.contains("current_configuration_revision TEXT CHECK"));
        assert!(state_sql.contains("current_configuration_revision <> '00000000000000000000'"));
        assert!(state_sql.contains("origin_kind IN ('managed', 'nativeProjected')"));
        assert!(state_sql.contains("origin_kind = 'managed' AND origin_namespace IS NULL"));
        assert!(state_sql.contains("length(CAST(origin_namespace AS BLOB)) BETWEEN 1 AND 64"));

        let configuration_sql = table_sql(&connection, "configuration_journal");
        assert!(configuration_sql.contains("logical_configuration_bytes BETWEEN 1 AND 16384"));
        assert!(configuration_sql.contains("logical_request_bytes BETWEEN 1 AND 32768"));
        assert!(configuration_sql.contains("length(sealed_request) BETWEEN 40 AND 32808"));
        assert!(configuration_sql.contains("length(sealed_request) = logical_request_bytes + 40"));
        assert!(!configuration_sql.contains("event_id"));
        assert!(!configuration_sql.contains("sealed_event"));

        let metadata_sql = table_sql(&connection, "metadata_mutation_ledger");
        assert!(metadata_sql.contains("state IN (\n        'claimed', 'applying', 'applied', 'outcomeUnknown', 'failed'\n    )"));
        assert!(metadata_sql.contains("charged_outcome_bytes BETWEEN 40 AND 16424"));
        assert!(metadata_sql.contains("length(sealed_request) = logical_request_bytes + 40"));
        assert!(metadata_sql.contains("length(sealed_outcome) = logical_outcome_bytes + 40"));
        assert!(metadata_sql.contains("state IN ('claimed', 'applying', 'outcomeUnknown')"));
        assert!(metadata_sql.contains("charged_outcome_bytes = 16424"));
        assert!(metadata_sql.contains("charged_outcome_bytes = length(sealed_outcome)"));

        let meta_sql = table_sql(&connection, "runtime_meta");
        for check in [
            "configuration_count BETWEEN 0 AND 65536",
            "configuration_sealed_bytes BETWEEN 0 AND 67108864",
            "command_configuration_pin_count BETWEEN 0 AND 1048576",
            "metadata_mutation_count BETWEEN 0 AND 65536",
            "active_metadata_mutation_count BETWEEN 0 AND 1024",
            "metadata_mutation_charged_bytes BETWEEN 0 AND 67108864",
        ] {
            assert!(meta_sql.contains(check), "missing CHECK: {check}");
        }
        assert!(meta_sql.contains("command_configuration_pin_count <= command_count"));
        assert!(meta_sql.contains("active_metadata_mutation_count <= metadata_mutation_count"));
    }

    #[test]
    fn v5_state_distinguishes_null_before_first_from_real_sequence_zero() {
        let connection = v5_structural_connection();
        connection
            .pragma_update(None, "foreign_keys", true)
            .expect("enable sidecar foreign keys");

        insert_conversation(&connection, 0x11, SEQ_ZERO, None, None);
        assert_eq!(
            insert_state(&connection, 0x11, None, "managed", None, None)
                .expect("fresh v5 state uses NULL heads"),
            1
        );

        insert_conversation(&connection, 0x12, SEQ_ONE, Some(SEQ_ZERO), None);
        insert_command(&connection, 0x12, 0x32);
        let sequence_zero = rusqlite::types::Value::Text(SEQ_ZERO.to_owned());
        assert_eq!(
            insert_state(
                &connection,
                0x12,
                None,
                "managed",
                None,
                Some(&sequence_zero),
            )
            .expect("legacy cutoff preserves real sequence zero"),
            1
        );
        insert_conversation(&connection, 0x16, "00000000000000000005", None, None);
        assert!(
            insert_state(
                &connection,
                0x16,
                None,
                "nativeProjected",
                Some("bad\0namespace"),
                None,
            )
            .is_err(),
            "opaque native namespace rejects embedded NUL"
        );

        insert_conversation(&connection, 0x13, "00000000000000000002", None, None);
        let integer_zero = rusqlite::types::Value::Integer(0);
        assert!(
            insert_state(
                &connection,
                0x13,
                None,
                "managed",
                None,
                Some(&integer_zero),
            )
            .is_err(),
            "integer zero cannot impersonate the nullable BeforeFirst sentinel"
        );

        insert_conversation(&connection, 0x14, "00000000000000000003", None, None);
        assert!(
            insert_state(&connection, 0x14, Some(SEQ_ZERO), "managed", None, None,).is_err(),
            "rev0 must be represented by NULL, never a non-null zero revision"
        );

        insert_conversation(&connection, 0x15, "00000000000000000004", None, None);
        assert!(
            insert_state(&connection, 0x15, None, "nativeProjected", None, None,).is_err(),
            "native projection requires a namespace"
        );
        assert_eq!(
            insert_state(
                &connection,
                0x15,
                None,
                "nativeProjected",
                Some("opaque.adapter"),
                None,
            )
            .expect("opaque native namespace is vendor-neutral"),
            1
        );
    }

    #[test]
    fn v5_configuration_and_pin_checks_bind_the_same_conversation() {
        let check_only = v5_structural_connection();
        assert!(
            check_only
                .execute(
                    "INSERT INTO command_configuration_pins (
                         conversation_id, command_seq, configuration_revision, metadata_token
                     ) VALUES (?1, ?2, ?3, ?4)",
                    params![&[0x20_u8; 16][..], SEQ_ZERO, SEQ_ZERO, &[0x60_u8; 32][..]],
                )
                .is_err(),
            "pin's own CHECK rejects revision zero even without FK enforcement"
        );

        let connection = v5_structural_connection();
        connection
            .pragma_update(None, "foreign_keys", true)
            .expect("enable sidecar foreign keys");
        insert_conversation(&connection, 0x21, SEQ_ZERO, Some(SEQ_ZERO), Some(SEQ_ZERO));
        insert_event(&connection, 0x21, 0x41, SEQ_ZERO);
        insert_command(&connection, 0x21, 0x42);
        assert_eq!(
            insert_configuration(&connection, 0x21, 0x51, SEQ_ZERO)
                .expect("configuration references the exact event row"),
            1
        );
        assert_eq!(
            insert_state(&connection, 0x21, Some(SEQ_ONE), "managed", None, None,)
                .expect("non-zero current head references exact configuration"),
            1
        );
        assert_eq!(
            connection
                .execute(
                    "INSERT INTO command_configuration_pins (
                         conversation_id, command_seq, configuration_revision, metadata_token
                     ) VALUES (?1, ?2, ?3, ?4)",
                    params![&[0x21_u8; 16][..], SEQ_ZERO, SEQ_ONE, &[0x61_u8; 32][..]],
                )
                .expect("pin exact command to exact same-conversation configuration"),
            1
        );

        insert_conversation(&connection, 0x22, SEQ_ONE, Some(SEQ_ZERO), Some(SEQ_ZERO));
        insert_event(&connection, 0x22, 0x43, SEQ_ZERO);
        insert_command(&connection, 0x22, 0x44);
        assert!(
            connection
                .execute(
                    "INSERT INTO command_configuration_pins (
                         conversation_id, command_seq, configuration_revision, metadata_token
                     ) VALUES (?1, ?2, ?3, ?4)",
                    params![&[0x22_u8; 16][..], SEQ_ZERO, SEQ_ONE, &[0x63_u8; 32][..]],
                )
                .is_err(),
            "a command cannot point at another conversation's revision"
        );
        assert!(
            connection
                .execute(
                    "INSERT INTO configuration_journal (
                         conversation_id, configuration_revision, base_configuration_revision,
                         event_seq, owner_token, idempotency_token, request_token,
                         logical_configuration_bytes, logical_request_bytes, created_at_ms,
                         metadata_token, sealed_request
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, 1, 1, ?8, ?9)",
                    params![
                        &[0x22_u8; 16][..],
                        SEQ_ZERO,
                        SEQ_ZERO,
                        SEQ_ZERO,
                        &[0x71_u8; 32][..],
                        &[0x72_u8; 32][..],
                        &[0x73_u8; 32][..],
                        &[0x74_u8; 32][..],
                        &[0x75_u8; 41][..],
                    ],
                )
                .is_err(),
            "configuration revision zero is invalid"
        );
        assert!(
            connection
                .execute(
                    "DELETE FROM configuration_journal
                     WHERE conversation_id = ?1 AND configuration_revision = ?2",
                    params![&[0x21_u8; 16][..], SEQ_ONE],
                )
                .is_err(),
            "current heads and command pins make configuration append-only"
        );
    }

    #[test]
    fn v5_metadata_states_charge_reserve_before_side_effects_and_exact_outcomes_after() {
        let connection = v5_structural_connection();
        connection
            .pragma_update(None, "foreign_keys", true)
            .expect("enable sidecar foreign keys");
        insert_conversation(&connection, 0x31, SEQ_ZERO, None, None);

        for (offset, state) in ["claimed", "applying", "outcomeUnknown"]
            .into_iter()
            .enumerate()
        {
            assert_eq!(
                insert_metadata_mutation(
                    &connection,
                    0x31,
                    0x40 + offset as u8 * 8,
                    state,
                    None,
                    None,
                    0,
                    16_424,
                    None,
                    1,
                    1,
                )
                .expect("active mutation reserves terminal outcome capacity"),
                1
            );
        }
        assert!(
            insert_metadata_mutation(
                &connection,
                0x31,
                0x60,
                "claimed",
                None,
                None,
                0,
                40,
                None,
                1,
                1,
            )
            .is_err(),
            "active mutation cannot under-reserve terminal outcome capacity"
        );
        assert!(
            insert_metadata_mutation(
                &connection,
                0x31,
                0x68,
                "outcomeUnknown",
                None,
                None,
                1,
                16_424,
                Some(&[0x69; 41]),
                1,
                1,
            )
            .is_err(),
            "active state cannot masquerade a terminal outcome"
        );
        assert_eq!(
            insert_metadata_mutation(
                &connection,
                0x31,
                0x70,
                "applied",
                Some(SEQ_ONE),
                Some(SEQ_ONE),
                1,
                41,
                Some(&[0x71; 41]),
                1,
                2,
            )
            .expect("applied mutation charges exact sealed outcome"),
            1
        );
        assert!(
            insert_metadata_mutation(
                &connection,
                0x31,
                0x78,
                "applied",
                None,
                None,
                1,
                41,
                Some(&[0x79; 41]),
                1,
                2,
            )
            .is_err(),
            "applied state requires exact entry and catalog revisions"
        );
        assert_eq!(
            insert_metadata_mutation(
                &connection,
                0x31,
                0x80,
                "failed",
                None,
                None,
                1,
                41,
                Some(&[0x81; 41]),
                1,
                2,
            )
            .expect("failed mutation charges exact sealed outcome"),
            1
        );
        assert!(
            insert_metadata_mutation(
                &connection,
                0x31,
                0x88,
                "failed",
                Some(SEQ_ONE),
                Some(SEQ_ONE),
                1,
                41,
                Some(&[0x89; 41]),
                2,
                1,
            )
            .is_err(),
            "failed state cannot carry applied revisions or move time backwards"
        );
        assert!(
            insert_metadata_mutation(
                &connection,
                0x32,
                0x90,
                "claimed",
                None,
                None,
                0,
                16_424,
                None,
                1,
                1,
            )
            .is_err(),
            "metadata ledger requires an authenticated conversation"
        );
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
        assert_eq!(tables, EXPECTED_TABLES_V4);

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
        let snapshot_columns = connection
            .prepare("SELECT name FROM pragma_table_info('snapshots') ORDER BY cid")
            .expect("prepare snapshot columns")
            .query_map([], |row| row.get::<_, String>(0))
            .expect("query snapshot columns")
            .collect::<Result<Vec<_>, _>>()
            .expect("collect snapshot columns");
        assert_eq!(
            &snapshot_columns[snapshot_columns.len() - 5..],
            [
                "content_sha256",
                "sealed_snapshot_sha256",
                "created_at_ms",
                "metadata_token",
                "sealed_snapshot",
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
