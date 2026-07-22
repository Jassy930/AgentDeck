//! Counter state 与 publication outbox 的 open/recovery 全库审计。

use rusqlite::OptionalExtension;

use crate::runtime::model::RuntimeStoreError;

use super::super::cipher::RuntimeKeyBundle;
use super::super::sqlite::RuntimeLedger;
use super::{
    CounterState, RawCounterRow, RemoteCounterRecordKind, authenticate_raw, canonical_sequence,
    fixed,
};

/// open/recovery 全库审计入口。除 outer metadata、AEAD 与 canonical codec 外，
/// Frozen counter head 还必须逐轴对应同一 exact publication outbox row。
pub(in super::super) fn validate_full_integrity(
    connection: &rusqlite::Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    ledger: &RuntimeLedger,
) -> Result<(), RuntimeStoreError> {
    let mut statement = connection.prepare(
        "SELECT scope_token, database_id, purpose, key_epoch, reserved_end,
                reservation_id, db_anchor, lifecycle, sealed_state,
                sealed_state_bytes, metadata_token
         FROM remote_counter_states ORDER BY scope_token",
    )?;
    let mut rows = statement.query([])?;
    let mut count = 0_u64;
    let mut sealed_total = 0_u64;
    while let Some(row) = rows.next()? {
        let raw: RawCounterRow = (
            row.get(0)?,
            row.get(1)?,
            row.get(2)?,
            row.get(3)?,
            row.get(4)?,
            row.get(5)?,
            row.get(6)?,
            row.get(7)?,
            row.get(8)?,
            row.get(9)?,
            row.get(10)?,
        );
        let authenticated = authenticate_raw(key_bundle, database_id, raw)?;
        if authenticated.state.record.kind == RemoteCounterRecordKind::Frozen {
            validate_frozen_outbox_projection(connection, &authenticated.state)?;
        } else if authenticated.state.record.kind == RemoteCounterRecordKind::RecoveryStaged {
            let recovery = authenticated
                .state
                .recovery
                .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
            super::super::key_transition::validate_counter_recovery_transition_binding(
                connection,
                key_bundle,
                database_id,
                recovery.operation_id,
                recovery.from_revision,
                recovery.to_revision,
            )?;
        }
        count = count
            .checked_add(1)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        sealed_total = sealed_total
            .checked_add(authenticated.sealed_bytes)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    }
    if count != ledger.remote_counter_state_count
        || sealed_total != ledger.remote_counter_state_sealed_bytes
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(())
}

fn validate_frozen_outbox_projection(
    connection: &rusqlite::Connection,
    state: &CounterState,
) -> Result<(), RuntimeStoreError> {
    type RawOutbox = (Vec<u8>, Vec<u8>, String, Vec<u8>, String, Vec<u8>);
    let publication_id = state
        .record
        .publication_id
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let raw: Option<RawOutbox> = connection
        .query_row(
            "SELECT publication_stream_id, generation, stream_seq,
                    counter_scope_token, sender_counter, blob_sha256
             FROM publication_outbox WHERE publication_id = ?1",
            [&publication_id[..]],
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
        )
        .optional()?;
    // delivery ACK 会合法删除 outbox；counter anchor 仍由 canonical row + ledger
    // 独立认证。只要 exact row 仍存在，就必须逐轴一致，不能接受混接备份。
    let Some(raw) = raw else {
        return Ok(());
    };
    if fixed::<16>(raw.0)?
        != state
            .publication_stream_id
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?
        || fixed::<16>(raw.1)?
            != state
                .generation
                .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?
        || canonical_sequence(&raw.2, true)?
            != state
                .stream_seq
                .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?
        || fixed::<32>(raw.3)? != state.record.scope_token
        || canonical_sequence(&raw.4, true)?
            != state
                .sender_counter
                .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?
        || fixed::<32>(raw.5)?
            != state
                .blob_sha256
                .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(())
}
