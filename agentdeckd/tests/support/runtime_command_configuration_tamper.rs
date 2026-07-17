//! Command configuration pin 的 current-v5 篡改测试支撑。
//!
//! 所有 SQLite 读取都发生在 tamper 前：先用 production `RuntimeKeyBundle`
//! 解包密钥并自证现有 pin/runtime ledger token，随后只执行一次定向写入。
//! tamper 后的 artifact oracle 只允许有界 filesystem handle 读取，不再打开 SQLite。

use std::fs::OpenOptions;
use std::io::{ErrorKind, Read};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use agentdeckd::runtime::store::cipher::{KeyWrapAad, RuntimeKeyBundle};
use agentdeckd::runtime::store::{
    RUNTIME_CRYPTO_CONTEXT_VERSION, RUNTIME_SCHEMA_FAMILY, RuntimeId,
};
use agentdeckd::security::StorageKek;
use rusqlite::{Connection, params};

const COMMAND_PIN_METADATA_DOMAIN: &[u8] = b"command.configuration.pin.metadata.v1";
const RUNTIME_LEDGER_DOMAIN_V5: &[u8] = b"runtime.meta.ledger.v5";
const MAX_ARTIFACT_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StoreArtifacts {
    main: Option<Vec<u8>>,
    wal: Option<Vec<u8>>,
    shm: Option<Vec<u8>>,
}

impl StoreArtifacts {
    pub(crate) fn read(database: &Path) -> Self {
        Self {
            main: read_optional(database),
            wal: read_optional(&artifact_path(database, "-wal")),
            shm: read_optional(&artifact_path(database, "-shm")),
        }
    }

    pub(crate) fn assert_main_and_wal_unchanged(&self, baseline: &Self, label: &str) {
        assert_eq!(self.main, baseline.main, "{label}: main DB drifted");
        assert_eq!(self.wal, baseline.wal, "{label}: WAL drifted");
    }
}

fn artifact_path(database: &Path, suffix: &str) -> PathBuf {
    PathBuf::from(format!("{}{suffix}", database.display()))
}

fn read_optional(path: &Path) -> Option<Vec<u8>> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::NotFound => return None,
        Err(error) => panic!("open runtime artifact {}: {error}", path.display()),
    };
    let metadata = file
        .metadata()
        .unwrap_or_else(|error| panic!("inspect runtime artifact {}: {error}", path.display()));
    assert!(
        metadata.file_type().is_file(),
        "runtime artifact must be a regular file: {}",
        path.display()
    );
    assert!(
        metadata.len() <= MAX_ARTIFACT_BYTES,
        "runtime artifact {} has {} bytes, exceeding the {MAX_ARTIFACT_BYTES}-byte test oracle cap",
        path.display(),
        metadata.len()
    );
    let mut bytes = Vec::with_capacity(
        usize::try_from(metadata.len()).expect("bounded artifact length fits usize"),
    );
    file.take(MAX_ARTIFACT_BYTES + 1)
        .read_to_end(&mut bytes)
        .unwrap_or_else(|error| panic!("read runtime artifact {}: {error}", path.display()));
    assert!(
        u64::try_from(bytes.len()).expect("artifact bytes fit u64") <= MAX_ARTIFACT_BYTES,
        "runtime artifact {} grew beyond the {MAX_ARTIFACT_BYTES}-byte test oracle cap",
        path.display()
    );
    Some(bytes)
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum TargetPinCorruption {
    TokenBitFlip,
    RevisionSwapToTwo,
    Delete,
    CopyToken {
        source_conversation_id: RuntimeId,
        source_command_seq: u64,
    },
}

#[derive(Debug)]
struct Ledger {
    catalog_high_water: Option<String>,
    conversation_count: u64,
    command_count: u64,
    event_count: u64,
    intent_count: u64,
    fence_count: u64,
    codex_adapter_state_count: u64,
    claude_code_adapter_state_count: u64,
    approval_count: u64,
    active_approval_count: u64,
    audit_event_logical_bytes: u64,
    event_stream_count: u64,
    event_stream_bytes: u64,
    catalog_delta_count: u64,
    catalog_delta_bytes: u64,
    catalog_retention_floor: Option<String>,
    snapshot_count: u64,
    snapshot_bytes: u64,
    publication_stream_count: u64,
    publication_outbox_count: u64,
    publication_outbox_bytes: u64,
    configuration_count: u64,
    configuration_sealed_bytes: u64,
    command_configuration_pin_count: u64,
    metadata_mutation_count: u64,
    active_metadata_mutation_count: u64,
    metadata_mutation_charged_bytes: u64,
    accepted_count: u64,
    accepted_payload_bytes: u64,
    started_without_fence_count: u64,
    started_without_release_count: u64,
    started_released_count: u64,
}

struct VerifiedTamperContext {
    connection: Connection,
    key_bundle: RuntimeKeyBundle,
    database_id: [u8; 16],
    ledger: Ledger,
    ledger_token: Vec<u8>,
}

impl VerifiedTamperContext {
    fn load(database: &Path, storage_kek: &StorageKek) -> Self {
        let connection = Connection::open(database).expect("open command pin tamper connection");
        connection
            .pragma_update(None, "wal_autocheckpoint", 0_i64)
            .expect("disable tamper connection WAL autocheckpoint");
        assert_eq!(
            connection
                .query_row("PRAGMA wal_autocheckpoint", [], |row| row.get::<_, i64>(0))
                .expect("read back tamper connection WAL autocheckpoint"),
            0,
            "tamper connection must never checkpoint the target WAL before artifact capture"
        );
        let (database_id, key_generation, wrapped_key_bundle): (Vec<u8>, i64, Vec<u8>) = connection
            .query_row(
                "SELECT database_id, key_generation, wrapped_key_bundle
                 FROM runtime_meta WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("read command pin crypto material");
        let database_id: [u8; 16] = database_id
            .try_into()
            .expect("runtime database id is exactly 16 bytes");
        let key_bundle = RuntimeKeyBundle::unwrap(
            storage_kek,
            &KeyWrapAad {
                schema_family: RUNTIME_SCHEMA_FAMILY.as_bytes(),
                schema_version: RUNTIME_CRYPTO_CONTEXT_VERSION,
                database_id: &database_id,
            },
            &wrapped_key_bundle,
        )
        .expect("unwrap command pin RuntimeKeyBundle");
        assert_eq!(
            u32::try_from(key_generation).expect("nonnegative key generation"),
            key_bundle.generation(),
            "unwrapped key generation must match runtime_meta"
        );
        let (ledger, ledger_token) = read_ledger(&connection);
        assert_eq!(
            ledger_token,
            ledger_metadata_token(&key_bundle, database_id, &ledger),
            "test helper must reproduce the existing production v5 ledger token"
        );

        let mut statement = connection
            .prepare(
                "SELECT conversation_id, command_seq, configuration_revision, metadata_token
                 FROM command_configuration_pins ORDER BY conversation_id, command_seq",
            )
            .expect("prepare existing command pin proof");
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                ))
            })
            .expect("query existing command pin proof");
        let mut pin_count = 0_u64;
        for row in rows {
            let (conversation_id, command_seq, revision, token) =
                row.expect("read existing command pin proof");
            let conversation_id: [u8; 16] = conversation_id
                .try_into()
                .expect("pin conversation id is exactly 16 bytes");
            assert_eq!(
                token,
                pin_metadata_token(&key_bundle, conversation_id, &command_seq, &revision),
                "test helper must reproduce every existing production pin token"
            );
            pin_count += 1;
        }
        drop(statement);
        assert_eq!(
            pin_count, ledger.command_configuration_pin_count,
            "baseline physical pin rows must match authenticated ledger"
        );
        Self {
            connection,
            key_bundle,
            database_id,
            ledger,
            ledger_token,
        }
    }
}

pub(crate) fn corrupt_target_pin(
    database: &Path,
    storage_kek: &StorageKek,
    target_conversation_id: RuntimeId,
    target_command_seq: u64,
    corruption: TargetPinCorruption,
) {
    let context = VerifiedTamperContext::load(database, storage_kek);
    let target_seq = encode_sequence(target_command_seq);
    match corruption {
        TargetPinCorruption::TokenBitFlip => {
            let mut token: Vec<u8> = context
                .connection
                .query_row(
                    "SELECT metadata_token FROM command_configuration_pins
                     WHERE conversation_id = ?1 AND command_seq = ?2",
                    params![&target_conversation_id.as_bytes()[..], &target_seq],
                    |row| row.get(0),
                )
                .expect("read target token before bit flip");
            *token
                .last_mut()
                .expect("authenticated pin token is non-empty") ^= 1;
            assert_eq!(
                context
                    .connection
                    .execute(
                        "UPDATE command_configuration_pins SET metadata_token = ?1
                         WHERE conversation_id = ?2 AND command_seq = ?3",
                        params![token, &target_conversation_id.as_bytes()[..], &target_seq],
                    )
                    .expect("flip target command pin token"),
                1
            );
        }
        TargetPinCorruption::RevisionSwapToTwo => {
            assert_eq!(
                context
                    .connection
                    .execute(
                        "UPDATE command_configuration_pins
                         SET configuration_revision = '00000000000000000002'
                         WHERE conversation_id = ?1 AND command_seq = ?2",
                        params![&target_conversation_id.as_bytes()[..], &target_seq],
                    )
                    .expect("swap target pin revision while retaining old token"),
                1
            );
        }
        TargetPinCorruption::Delete => {
            assert_eq!(
                context
                    .connection
                    .execute(
                        "DELETE FROM command_configuration_pins
                         WHERE conversation_id = ?1 AND command_seq = ?2",
                        params![&target_conversation_id.as_bytes()[..], &target_seq],
                    )
                    .expect("delete fresh target command pin"),
                1
            );
        }
        TargetPinCorruption::CopyToken {
            source_conversation_id,
            source_command_seq,
        } => {
            let source_token: Vec<u8> = context
                .connection
                .query_row(
                    "SELECT metadata_token FROM command_configuration_pins
                     WHERE conversation_id = ?1 AND command_seq = ?2",
                    params![
                        &source_conversation_id.as_bytes()[..],
                        encode_sequence(source_command_seq)
                    ],
                    |row| row.get(0),
                )
                .expect("read source command pin token before tamper");
            assert_eq!(
                context
                    .connection
                    .execute(
                        "UPDATE command_configuration_pins SET metadata_token = ?1
                         WHERE conversation_id = ?2 AND command_seq = ?3",
                        params![
                            source_token,
                            &target_conversation_id.as_bytes()[..],
                            &target_seq
                        ],
                    )
                    .expect("copy source token onto target pin"),
                1
            );
        }
    }
}

pub(crate) fn insert_authenticated_orphan_pin(
    database: &Path,
    storage_kek: &StorageKek,
    conversation_id: RuntimeId,
    command_seq: u64,
    configuration_revision: u64,
) {
    let context = VerifiedTamperContext::load(database, storage_kek);
    let command_seq = encode_sequence(command_seq);
    let revision = encode_sequence(configuration_revision);
    let token = pin_metadata_token(
        &context.key_bundle,
        *conversation_id.as_bytes(),
        &command_seq,
        &revision,
    );
    context
        .connection
        .execute_batch("PRAGMA foreign_keys = OFF")
        .expect("disable FK for authenticated orphan fixture");
    assert_eq!(
        context
            .connection
            .execute(
                "INSERT INTO command_configuration_pins (
                     conversation_id, command_seq, configuration_revision, metadata_token
                 ) VALUES (?1, ?2, ?3, ?4)",
                params![
                    &conversation_id.as_bytes()[..],
                    &command_seq,
                    &revision,
                    &token[..]
                ],
            )
            .expect("insert MAC-valid FK-off orphan pin"),
        1
    );
}

pub(crate) fn diverge_authenticated_pin_ledger(database: &Path, storage_kek: &StorageKek) {
    let mut context = VerifiedTamperContext::load(database, storage_kek);
    context.ledger.command_configuration_pin_count = context
        .ledger
        .command_configuration_pin_count
        .checked_sub(1)
        .expect("fixture has at least one command pin");
    let next_token =
        ledger_metadata_token(&context.key_bundle, context.database_id, &context.ledger);
    assert_eq!(
        context
            .connection
            .execute(
                "UPDATE runtime_meta
                 SET command_configuration_pin_count = ?1, metadata_token = ?2
                 WHERE singleton = 1 AND metadata_token = ?3",
                params![
                    i64::try_from(context.ledger.command_configuration_pin_count)
                        .expect("pin count fits SQLite integer"),
                    &next_token[..],
                    &context.ledger_token
                ],
            )
            .expect("write authenticated pin ledger divergence"),
        1
    );
}

fn pin_metadata_token(
    key_bundle: &RuntimeKeyBundle,
    conversation_id: [u8; 16],
    command_seq: &str,
    configuration_revision: &str,
) -> [u8; 32] {
    let mut message = Vec::with_capacity(128);
    for field in [
        &conversation_id[..],
        command_seq.as_bytes(),
        configuration_revision.as_bytes(),
    ] {
        message.extend_from_slice(&(field.len() as u64).to_be_bytes());
        message.extend_from_slice(field);
    }
    *key_bundle
        .blind_index(COMMAND_PIN_METADATA_DOMAIN, &message)
        .expect("compute command pin metadata token")
        .as_bytes()
}

fn encode_sequence(value: u64) -> String {
    format!("{value:020}")
}

fn read_ledger(connection: &Connection) -> (Ledger, Vec<u8>) {
    connection
        .query_row(
            "SELECT catalog_high_water,
                    conversation_count, command_count, event_count, intent_count, fence_count,
                    codex_adapter_state_count, claude_code_adapter_state_count,
                    approval_count, active_approval_count,
                    audit_event_logical_bytes, event_stream_count, event_stream_bytes,
                    catalog_delta_count, catalog_delta_bytes, catalog_retention_floor,
                    snapshot_count, snapshot_bytes, publication_stream_count,
                    publication_outbox_count, publication_outbox_bytes,
                    configuration_count, configuration_sealed_bytes,
                    command_configuration_pin_count, metadata_mutation_count,
                    active_metadata_mutation_count, metadata_mutation_charged_bytes,
                    accepted_count, accepted_payload_bytes, started_without_fence_count,
                    started_without_release_count, started_released_count, metadata_token
             FROM runtime_meta WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    Ledger {
                        catalog_high_water: row.get(0)?,
                        conversation_count: nonnegative(row.get(1)?, 1)?,
                        command_count: nonnegative(row.get(2)?, 2)?,
                        event_count: nonnegative(row.get(3)?, 3)?,
                        intent_count: nonnegative(row.get(4)?, 4)?,
                        fence_count: nonnegative(row.get(5)?, 5)?,
                        codex_adapter_state_count: nonnegative(row.get(6)?, 6)?,
                        claude_code_adapter_state_count: nonnegative(row.get(7)?, 7)?,
                        approval_count: nonnegative(row.get(8)?, 8)?,
                        active_approval_count: nonnegative(row.get(9)?, 9)?,
                        audit_event_logical_bytes: nonnegative(row.get(10)?, 10)?,
                        event_stream_count: nonnegative(row.get(11)?, 11)?,
                        event_stream_bytes: nonnegative(row.get(12)?, 12)?,
                        catalog_delta_count: nonnegative(row.get(13)?, 13)?,
                        catalog_delta_bytes: nonnegative(row.get(14)?, 14)?,
                        catalog_retention_floor: row.get(15)?,
                        snapshot_count: nonnegative(row.get(16)?, 16)?,
                        snapshot_bytes: nonnegative(row.get(17)?, 17)?,
                        publication_stream_count: nonnegative(row.get(18)?, 18)?,
                        publication_outbox_count: nonnegative(row.get(19)?, 19)?,
                        publication_outbox_bytes: nonnegative(row.get(20)?, 20)?,
                        configuration_count: nonnegative(row.get(21)?, 21)?,
                        configuration_sealed_bytes: nonnegative(row.get(22)?, 22)?,
                        command_configuration_pin_count: nonnegative(row.get(23)?, 23)?,
                        metadata_mutation_count: nonnegative(row.get(24)?, 24)?,
                        active_metadata_mutation_count: nonnegative(row.get(25)?, 25)?,
                        metadata_mutation_charged_bytes: nonnegative(row.get(26)?, 26)?,
                        accepted_count: nonnegative(row.get(27)?, 27)?,
                        accepted_payload_bytes: nonnegative(row.get(28)?, 28)?,
                        started_without_fence_count: nonnegative(row.get(29)?, 29)?,
                        started_without_release_count: nonnegative(row.get(30)?, 30)?,
                        started_released_count: nonnegative(row.get(31)?, 31)?,
                    },
                    row.get(32)?,
                ))
            },
        )
        .expect("read current-v5 authenticated runtime ledger")
}

fn nonnegative(value: i64, column: usize) -> rusqlite::Result<u64> {
    u64::try_from(value).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(column, value))
}

fn ledger_metadata_token(
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    ledger: &Ledger,
) -> Vec<u8> {
    let mut message = Vec::with_capacity(304);
    message.extend_from_slice(&database_id);
    encode_optional_sequence(&mut message, ledger.catalog_high_water.as_deref());
    for value in [
        ledger.conversation_count,
        ledger.command_count,
        ledger.event_count,
        ledger.intent_count,
        ledger.fence_count,
        ledger.codex_adapter_state_count,
        ledger.claude_code_adapter_state_count,
        ledger.approval_count,
        ledger.active_approval_count,
        ledger.audit_event_logical_bytes,
        ledger.event_stream_count,
        ledger.event_stream_bytes,
        ledger.catalog_delta_count,
        ledger.catalog_delta_bytes,
    ] {
        message.extend_from_slice(&value.to_be_bytes());
    }
    encode_optional_sequence(&mut message, ledger.catalog_retention_floor.as_deref());
    for value in [
        ledger.snapshot_count,
        ledger.snapshot_bytes,
        ledger.publication_stream_count,
        ledger.publication_outbox_count,
        ledger.publication_outbox_bytes,
        ledger.accepted_count,
        ledger.accepted_payload_bytes,
        ledger.started_without_fence_count,
        ledger.started_without_release_count,
        ledger.started_released_count,
        ledger.configuration_count,
        ledger.configuration_sealed_bytes,
        ledger.command_configuration_pin_count,
        ledger.metadata_mutation_count,
        ledger.active_metadata_mutation_count,
        ledger.metadata_mutation_charged_bytes,
    ] {
        message.extend_from_slice(&value.to_be_bytes());
    }
    key_bundle
        .blind_index(RUNTIME_LEDGER_DOMAIN_V5, &message)
        .expect("compute current-v5 runtime ledger token")
        .as_bytes()
        .to_vec()
}

fn encode_optional_sequence(message: &mut Vec<u8>, value: Option<&str>) {
    match value {
        None => message.push(0),
        Some(value) => {
            message.push(1);
            message.extend_from_slice(value.as_bytes());
        }
    }
}
