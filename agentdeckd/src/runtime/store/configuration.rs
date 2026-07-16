//! Runtime v5 configuration sidecar 的初始状态、迁移物化与完整性门禁。
//!
//! B1b 只允许 `conversation_state` 出现非空数据；configuration/pin/metadata
//! writer 分别由后续 B2/B3/B4 接入。在这些 writer 落地前，任一对应物理行都
//! 必须 fail-close，不能把未认证的手写 fixture 当作合法状态。

use rusqlite::{Connection, Transaction, params};

use crate::runtime::model::{MAX_RUNTIME_CONVERSATIONS, RuntimeStoreError};

use super::cipher::RuntimeKeyBundle;
use super::sequence::{SequenceScope, decode_sequence, encode_sequence};
use super::sqlite::RuntimeLedger;

const CONVERSATION_STATE_DOMAIN: &[u8] = b"conversation.state.metadata.v1";
const V5_SCHEMA_FIXED_PROJECTION_BYTES: u64 = 2 * 1024 * 1024;
const V5_STATE_ROW_PROJECTION_BYTES: u64 = 1024;

fn append_field(message: &mut Vec<u8>, value: &[u8]) {
    message.extend_from_slice(&(value.len() as u64).to_be_bytes());
    message.extend_from_slice(value);
}

fn append_optional_field(message: &mut Vec<u8>, value: Option<&[u8]>) {
    match value {
        None => message.push(0),
        Some(value) => {
            message.push(1);
            append_field(message, value);
        }
    }
}

fn conversation_state_metadata_token(
    key_bundle: &RuntimeKeyBundle,
    conversation_id: &[u8; 16],
    current_configuration_revision: Option<&str>,
    entry_revision: &str,
    origin_kind: &str,
    origin_namespace: Option<&str>,
    legacy_command_high_water: Option<&str>,
) -> Result<[u8; 32], RuntimeStoreError> {
    let mut message = Vec::with_capacity(192);
    append_field(&mut message, conversation_id);
    append_optional_field(
        &mut message,
        current_configuration_revision.map(str::as_bytes),
    );
    append_field(&mut message, entry_revision.as_bytes());
    append_field(&mut message, origin_kind.as_bytes());
    append_optional_field(&mut message, origin_namespace.map(str::as_bytes));
    append_optional_field(&mut message, legacy_command_high_water.map(str::as_bytes));
    let token = key_bundle.blind_index(CONVERSATION_STATE_DOMAIN, &message)?;
    Ok(*token.as_bytes())
}

pub(super) fn migration_projection_bytes(
    conversation_count: u64,
) -> Result<u64, RuntimeStoreError> {
    if conversation_count > MAX_RUNTIME_CONVERSATIONS {
        return Err(RuntimeStoreError::ConversationLimit);
    }
    V5_SCHEMA_FIXED_PROJECTION_BYTES
        .checked_add(
            conversation_count
                .checked_mul(V5_STATE_ROW_PROJECTION_BYTES)
                .ok_or(RuntimeStoreError::CapacityArithmeticOverflow {
                    field: "v5 conversation state projection bytes",
                })?,
        )
        .ok_or(RuntimeStoreError::CapacityArithmeticOverflow {
            field: "v5 migration projection bytes",
        })
}

pub(super) fn insert_fresh_managed_state(
    transaction: &Transaction<'_>,
    key_bundle: &RuntimeKeyBundle,
    conversation_id: &[u8; 16],
) -> Result<(), RuntimeStoreError> {
    insert_managed_state(transaction, key_bundle, conversation_id, None)
}

fn insert_managed_state(
    transaction: &Transaction<'_>,
    key_bundle: &RuntimeKeyBundle,
    conversation_id: &[u8; 16],
    legacy_command_high_water: Option<&str>,
) -> Result<(), RuntimeStoreError> {
    if let Some(cutoff) = legacy_command_high_water {
        decode_sequence(SequenceScope::CommandSeq, cutoff)?;
    }
    let entry_revision = encode_sequence(0);
    let metadata_token = conversation_state_metadata_token(
        key_bundle,
        conversation_id,
        None,
        &entry_revision,
        "managed",
        None,
        legacy_command_high_water,
    )?;
    transaction.execute(
        "INSERT INTO conversation_state (
             conversation_id, current_configuration_revision, entry_revision,
             origin_kind, origin_namespace, legacy_command_high_water, metadata_token
         ) VALUES (?1, NULL, ?2, 'managed', NULL, ?3, ?4)",
        params![
            &conversation_id[..],
            entry_revision,
            legacy_command_high_water,
            &metadata_token[..],
        ],
    )?;
    Ok(())
}

pub(super) fn materialize_legacy_v4_states(
    transaction: &Transaction<'_>,
    key_bundle: &RuntimeKeyBundle,
    ledger: &RuntimeLedger,
) -> Result<(), RuntimeStoreError> {
    migration_projection_bytes(ledger.conversation_count)?;
    let rows = transaction
        .prepare(
            "SELECT conversation_id, command_high_water
             FROM conversations ORDER BY conversation_id",
        )?
        .query_map([], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Option<String>>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    if u64::try_from(rows.len()).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
        != ledger.conversation_count
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    for (conversation_id, legacy_command_high_water) in rows {
        let conversation_id: [u8; 16] = conversation_id
            .try_into()
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
        insert_managed_state(
            transaction,
            key_bundle,
            &conversation_id,
            legacy_command_high_water.as_deref(),
        )?;
    }
    Ok(())
}

fn v5_totals_are_zero(ledger: &RuntimeLedger) -> bool {
    ledger.configuration_count == 0
        && ledger.configuration_sealed_bytes == 0
        && ledger.command_configuration_pin_count == 0
        && ledger.metadata_mutation_count == 0
        && ledger.active_metadata_mutation_count == 0
        && ledger.metadata_mutation_charged_bytes == 0
}

pub(super) fn validate_v5_integrity(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    ledger: &RuntimeLedger,
) -> Result<(), RuntimeStoreError> {
    let version: u32 = connection
        .query_row(
            "SELECT schema_version FROM runtime_meta WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    if version < 5 {
        return if v5_totals_are_zero(ledger) {
            Ok(())
        } else {
            Err(RuntimeStoreError::UnknownOrCorruptSchema)
        };
    }
    if version != 5 || !v5_totals_are_zero(ledger) {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }

    let rows = connection
        .prepare(
            "SELECT conversation_id, current_configuration_revision, entry_revision,
                    origin_kind, origin_namespace, legacy_command_high_water, metadata_token
             FROM conversation_state ORDER BY conversation_id",
        )?
        .query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, Vec<u8>>(6)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    if u64::try_from(rows.len()).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
        != ledger.conversation_count
        || ledger.conversation_count > MAX_RUNTIME_CONVERSATIONS
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    for (conversation_id, current, entry, origin, namespace, cutoff, token) in rows {
        let conversation_id: [u8; 16] = conversation_id
            .try_into()
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
        if let Some(current) = current.as_deref()
            && decode_sequence(SequenceScope::CommandSeq, current)? == 0
        {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        decode_sequence(SequenceScope::CommandSeq, &entry)?;
        if let Some(cutoff) = cutoff.as_deref() {
            decode_sequence(SequenceScope::CommandSeq, cutoff)?;
        }
        if !matches!(
            (origin.as_str(), namespace.as_deref()),
            ("managed", None) | ("nativeProjected", Some(_))
        ) {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        let expected = conversation_state_metadata_token(
            key_bundle,
            &conversation_id,
            current.as_deref(),
            &entry,
            &origin,
            namespace.as_deref(),
            cutoff.as_deref(),
        )?;
        if token.as_slice() != expected {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
    }
    let missing_states: i64 = connection.query_row(
        "SELECT COUNT(*) FROM conversations AS c
         LEFT JOIN conversation_state AS s USING (conversation_id)
         WHERE s.conversation_id IS NULL",
        [],
        |row| row.get(0),
    )?;
    let physical: (i64, i64, i64, i64, i64, i64) = connection.query_row(
        "SELECT
             (SELECT COUNT(*) FROM configuration_journal),
             (SELECT COALESCE(SUM(length(sealed_request)), 0) FROM configuration_journal),
             (SELECT COUNT(*) FROM command_configuration_pins),
             (SELECT COUNT(*) FROM metadata_mutation_ledger),
             (SELECT COUNT(*) FROM metadata_mutation_ledger
                WHERE state IN ('claimed', 'applying', 'outcomeUnknown')),
             (SELECT COALESCE(SUM(length(sealed_request) + charged_outcome_bytes), 0)
                FROM metadata_mutation_ledger)",
        [],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
            ))
        },
    )?;
    if missing_states != 0 || physical != (0, 0, 0, 0, 0, 0) {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(())
}
