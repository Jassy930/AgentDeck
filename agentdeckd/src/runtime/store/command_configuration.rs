//! Accepted command 与 exact configuration revision 的 authenticated sidecar。
//!
//! `commands.sealed_command` 保持既有 ADC1 三字段物理形状；新命令的 expected
//! revision 由 v2 payload token 与本表 pin 共同绑定。迁移前命令只有在 frozen
//! legacy cutoff 内缺 pin 时才解释为 revision 0。

use rusqlite::{Connection, OptionalExtension, Transaction, params};
use zeroize::Zeroizing;

use crate::runtime::model::RuntimeStoreError;

use super::cipher::RuntimeKeyBundle;
use super::configuration::load_conversation_state;
use super::identity::{RuntimeId, RuntimeIdKind};
use super::schema::MAX_COMMAND_CONFIGURATION_PINS;
use super::sequence::{SequenceScope, decode_sequence, encode_sequence};
use super::sqlite::RuntimeLedger;

const COMMAND_PIN_METADATA_DOMAIN: &[u8] = b"command.configuration.pin.metadata.v1";
const COMMAND_PAYLOAD_DOMAIN_V1: &[u8] = b"command.payload.prompt.v1";
const COMMAND_PAYLOAD_DOMAIN_V2: &[u8] = b"command.payload.prompt.v2";
const COMMAND_PAYLOAD_MAGIC_V2: &[u8; 4] = b"ADP2";

fn append_u32_field(message: &mut Vec<u8>, value: &[u8]) -> Result<(), RuntimeStoreError> {
    let length = u32::try_from(value.len()).map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
    message.extend_from_slice(&length.to_be_bytes());
    message.extend_from_slice(value);
    Ok(())
}

fn append_u64_field(message: &mut Vec<u8>, value: &[u8]) {
    message.extend_from_slice(&(value.len() as u64).to_be_bytes());
    message.extend_from_slice(value);
}

pub(super) fn command_payload_token(
    key_bundle: &RuntimeKeyBundle,
    configuration_revision: u64,
    payload: &[u8],
) -> Result<[u8; 32], RuntimeStoreError> {
    if configuration_revision == 0 {
        return Ok(*key_bundle
            .blind_index(COMMAND_PAYLOAD_DOMAIN_V1, payload)?
            .as_bytes());
    }
    let revision = encode_sequence(configuration_revision);
    let mut request = Zeroizing::new(Vec::with_capacity(
        COMMAND_PAYLOAD_MAGIC_V2.len() + 2 * 4 + revision.len() + payload.len(),
    ));
    request.extend_from_slice(COMMAND_PAYLOAD_MAGIC_V2);
    append_u32_field(&mut request, revision.as_bytes())?;
    append_u32_field(&mut request, payload)?;
    Ok(*key_bundle
        .blind_index(COMMAND_PAYLOAD_DOMAIN_V2, request.as_ref())?
        .as_bytes())
}

fn pin_metadata_token(
    key_bundle: &RuntimeKeyBundle,
    conversation_id: RuntimeId,
    command_seq: &str,
    configuration_revision: &str,
) -> Result<[u8; 32], RuntimeStoreError> {
    let mut message = Zeroizing::new(Vec::with_capacity(128));
    for field in [
        &conversation_id.as_bytes()[..],
        command_seq.as_bytes(),
        configuration_revision.as_bytes(),
    ] {
        append_u64_field(&mut message, field);
    }
    Ok(*key_bundle
        .blind_index(COMMAND_PIN_METADATA_DOMAIN, message.as_ref())?
        .as_bytes())
}

pub(super) fn validate_fresh_admission(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    conversation_id: RuntimeId,
    expected_configuration_revision: u64,
) -> Result<u64, RuntimeStoreError> {
    // 先区分“conversation 不存在”和“已存在 conversation 的 authenticated
    // sidecar 缺失/损坏”。后者必须继续 fail-close，不能退化成 not-found。
    super::journal::load_conversation(connection, key_bundle, database_id, conversation_id)?;
    let state = load_conversation_state(connection, key_bundle, conversation_id)?;
    let current = state.current_revision()?;
    if current == 0 {
        return Err(RuntimeStoreError::ConfigurationRequired);
    }
    let authenticated = super::configuration::load_authenticated_configuration_revision(
        connection,
        key_bundle,
        database_id,
        conversation_id,
        current,
    )?;
    if authenticated.configuration_revision != current {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    // current head 必须先完成 AEAD/MAC/event/append-only 认证，随后才允许把
    // caller 的 stale/future revision 映射成普通 CAS conflict。否则损坏可被
    // 一个不匹配的 expected revision 掩盖。
    if expected_configuration_revision != current {
        return Err(RuntimeStoreError::ConfigurationConflict {
            current_configuration_revision: current,
        });
    }
    Ok(current)
}

pub(super) fn ensure_pin_capacity(ledger: &RuntimeLedger) -> Result<(), RuntimeStoreError> {
    if ledger.command_configuration_pin_count >= MAX_COMMAND_CONFIGURATION_PINS {
        return Err(RuntimeStoreError::CommandConfigurationPinLimit);
    }
    Ok(())
}

pub(super) fn insert_pin(
    transaction: &Transaction<'_>,
    key_bundle: &RuntimeKeyBundle,
    conversation_id: RuntimeId,
    command_seq: u64,
    configuration_revision: u64,
) -> Result<(), RuntimeStoreError> {
    if configuration_revision == 0 {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let command_seq = encode_sequence(command_seq);
    let configuration_revision = encode_sequence(configuration_revision);
    let token = pin_metadata_token(
        key_bundle,
        conversation_id,
        &command_seq,
        &configuration_revision,
    )?;
    transaction.execute(
        "INSERT INTO command_configuration_pins (
             conversation_id, command_seq, configuration_revision, metadata_token
         ) VALUES (?1, ?2, ?3, ?4)",
        params![
            &conversation_id.as_bytes()[..],
            &command_seq,
            &configuration_revision,
            &token[..],
        ],
    )?;
    Ok(())
}

fn schema_version(connection: &Connection) -> Result<u32, RuntimeStoreError> {
    connection
        .query_row(
            "SELECT schema_version FROM runtime_meta WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)
}

pub(super) fn load_revision(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    conversation_id: RuntimeId,
    command_seq: u64,
) -> Result<u64, RuntimeStoreError> {
    let version = schema_version(connection)?;
    if version < 5 {
        let sidecar_exists: i64 = connection.query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM sqlite_schema
                 WHERE type = 'table' AND name = 'command_configuration_pins'
             )",
            [],
            |row| row.get(0),
        )?;
        return if sidecar_exists == 0 {
            Ok(0)
        } else {
            Err(RuntimeStoreError::UnknownOrCorruptSchema)
        };
    }
    if version != 5 {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }

    let state = load_conversation_state(connection, key_bundle, conversation_id)?;
    let cutoff = state.legacy_command_high_water()?;
    let command_seq_encoded = encode_sequence(command_seq);
    let raw = connection
        .query_row(
            "SELECT configuration_revision, metadata_token,
                    EXISTS(
                        SELECT 1 FROM configuration_journal AS configuration
                        WHERE configuration.conversation_id = pin.conversation_id
                          AND configuration.configuration_revision = pin.configuration_revision
                    )
             FROM command_configuration_pins AS pin
             WHERE conversation_id = ?1 AND command_seq = ?2",
            params![&conversation_id.as_bytes()[..], &command_seq_encoded],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .optional()?;
    let Some((revision_encoded, token, configuration_exists)) = raw else {
        return if cutoff.is_some_and(|legacy| command_seq <= legacy) {
            Ok(0)
        } else {
            Err(RuntimeStoreError::UnknownOrCorruptSchema)
        };
    };
    if cutoff.is_some_and(|legacy| command_seq <= legacy) || configuration_exists != 1 {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let revision = decode_sequence(SequenceScope::ConfigurationRevision, &revision_encoded)?;
    if revision == 0 || revision > state.current_revision()? {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let expected = pin_metadata_token(
        key_bundle,
        conversation_id,
        &command_seq_encoded,
        &revision_encoded,
    )?;
    if token.as_slice() != expected {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(revision)
}

pub(super) fn validate_v5_integrity(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    ledger: &RuntimeLedger,
) -> Result<u64, RuntimeStoreError> {
    let mut conversation_statement = connection
        .prepare("SELECT conversation_id FROM conversation_state ORDER BY conversation_id")?;
    let conversation_rows = conversation_statement.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
    let mut authenticated_pin_count = 0_u64;
    for raw_conversation_id in conversation_rows {
        let conversation_id = RuntimeId::from_bytes(
            RuntimeIdKind::Conversation,
            raw_conversation_id?
                .try_into()
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
        )?;
        let state = load_conversation_state(connection, key_bundle, conversation_id)?;
        let current = state.current_revision()?;
        let cutoff = state.legacy_command_high_water()?;
        let mut command_statement = connection.prepare(
            "SELECT command.command_seq, pin.configuration_revision, pin.metadata_token,
                    CASE WHEN pin.configuration_revision IS NULL THEN 0 ELSE EXISTS(
                        SELECT 1 FROM configuration_journal AS configuration
                        WHERE configuration.conversation_id = command.conversation_id
                          AND configuration.configuration_revision = pin.configuration_revision
                    ) END
             FROM commands AS command
             LEFT JOIN command_configuration_pins AS pin
               ON pin.conversation_id = command.conversation_id
              AND pin.command_seq = command.command_seq
             WHERE command.conversation_id = ?1
             ORDER BY command.command_seq",
        )?;
        let command_rows =
            command_statement.query_map([&conversation_id.as_bytes()[..]], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<Vec<u8>>>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            })?;
        for command_row in command_rows {
            let (command_seq_encoded, revision, token, configuration_exists) = command_row?;
            let command_seq = decode_sequence(SequenceScope::CommandSeq, &command_seq_encoded)?;
            let legacy = cutoff.is_some_and(|value| command_seq <= value);
            match (revision, token) {
                (None, None) if legacy => {}
                (Some(revision_encoded), Some(token)) if !legacy => {
                    let revision =
                        decode_sequence(SequenceScope::ConfigurationRevision, &revision_encoded)?;
                    if revision == 0 || revision > current || configuration_exists != 1 {
                        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
                    }
                    let expected = pin_metadata_token(
                        key_bundle,
                        conversation_id,
                        &command_seq_encoded,
                        &revision_encoded,
                    )?;
                    if token.as_slice() != expected {
                        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
                    }
                    authenticated_pin_count = authenticated_pin_count
                        .checked_add(1)
                        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
                }
                _ => return Err(RuntimeStoreError::UnknownOrCorruptSchema),
            }
        }
    }
    let physical_pin_count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM command_configuration_pins",
        [],
        |row| row.get(0),
    )?;
    let physical_pin_count =
        u64::try_from(physical_pin_count).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    if physical_pin_count != authenticated_pin_count
        || ledger.command_configuration_pin_count != authenticated_pin_count
        || authenticated_pin_count > MAX_COMMAND_CONFIGURATION_PINS
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(authenticated_pin_count)
}
