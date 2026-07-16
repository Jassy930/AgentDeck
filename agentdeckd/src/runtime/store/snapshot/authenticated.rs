//! Runtime v4 snapshot authenticated metadata and exact-reference read boundary。

use std::collections::HashMap;

use rusqlite::{Connection, DatabaseName, OptionalExtension, params};
use sha2::{Digest, Sha256};

use agentdeck_protocol::runtime::sync::StreamCursor;

use crate::runtime::model::RuntimeStoreError;

use super::super::cipher::{
    ROW_BLOB_V1_OVERHEAD_LEN, RuntimeKeyBundle, RuntimeReadCryptoCapability,
};
use super::super::identity::{RuntimeId, RuntimeIdKind};
use super::super::sequence::{SequenceScope, decode_sequence};
use super::super::sqlite::RuntimeLedger;
use super::super::stream::optional_field;
use super::{
    CatalogSnapshotRowMetadata, ConversationSnapshotRowMetadata, MAX_DIRECTORY_ROWS,
    MAX_SNAPSHOT_BYTES, MAX_SNAPSHOT_BYTES_GLOBAL, MAX_SNAPSHOT_ITEMS, ReadySnapshotReference,
    SNAPSHOT_TOKEN_DOMAIN, StoredCatalogSnapshot, StoredConversationSnapshot,
    catalog_materialization_peak_bound, load_snapshot_row_read,
    open_snapshot_payload_read_in_place, snapshot_token,
};

const SNAPSHOT_CIPHERTEXT_DIGEST_BUFFER_BYTES: usize = 16 * 1024;

/// SubscriptionBarrier 只认证 snapshot metadata directory；不读取或解密最多
/// 64 MiB 的 `sealed_snapshot`。必须枚举完整目录并与 authenticated ledger 精确
/// 对账后，才能选择请求 target 的 ready base。
pub(in crate::runtime::store) fn authenticate_directory(
    transaction: &rusqlite::Transaction<'_>,
    key_bundle: &RuntimeKeyBundle,
    ledger: &RuntimeLedger,
    requested_target: crate::runtime::events::RuntimeStreamTarget,
) -> Result<Option<ReadySnapshotReference>, RuntimeStoreError> {
    use crate::runtime::events::RuntimeStreamTarget;

    let mut statement = transaction.prepare(
        "SELECT snapshot_id, target_scope, conversation_id, source_build_pin_id,
                    base_cursor, build_state, item_count, logical_snapshot_bytes,
                    content_sha256, sealed_snapshot_sha256, created_at_ms, metadata_token
             FROM snapshots
             ORDER BY snapshot_id",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, Vec<u8>>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, Option<Vec<u8>>>(2)?,
            row.get::<_, Option<Vec<u8>>>(3)?,
            row.get::<_, Option<String>>(4)?,
            row.get::<_, String>(5)?,
            row.get::<_, i64>(6)?,
            row.get::<_, i64>(7)?,
            row.get::<_, Vec<u8>>(8)?,
            row.get::<_, Vec<u8>>(9)?,
            row.get::<_, i64>(10)?,
            row.get::<_, Vec<u8>>(11)?,
        ))
    })?;

    let mut directory = HashMap::new();
    let mut conversation_bases = Vec::new();
    let mut checked_count = 0_u64;
    let mut checked_bytes = 0_u64;
    for row in rows {
        let raw = row.map_err(snapshot_directory_row_error)?;
        let snapshot_id: [u8; 16] = raw
            .0
            .as_slice()
            .try_into()
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
        if snapshot_id == [0; 16] || raw.5 != "ready" {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        let source_build_pin_id = raw
            .3
            .as_deref()
            .map(|bytes| {
                <[u8; 16]>::try_from(bytes).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)
            })
            .transpose()?;
        let (target, sequence_scope) = match raw.1.as_str() {
            "catalog" if raw.2.is_none() && source_build_pin_id.is_none() => {
                (RuntimeStreamTarget::Catalog, SequenceScope::CatalogRevision)
            }
            "conversation" if raw.2.is_some() && source_build_pin_id.is_some() => {
                let conversation_bytes: [u8; 16] = raw
                    .2
                    .as_deref()
                    .expect("guarded above")
                    .try_into()
                    .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
                let conversation_id =
                    RuntimeId::from_bytes(RuntimeIdKind::Conversation, conversation_bytes)
                        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
                if source_build_pin_id == Some([0; 16]) {
                    return Err(RuntimeStoreError::UnknownOrCorruptSchema);
                }
                (
                    RuntimeStreamTarget::Conversation(conversation_id),
                    SequenceScope::EventSeq,
                )
            }
            _ => return Err(RuntimeStoreError::UnknownOrCorruptSchema),
        };
        let item_count =
            u64::try_from(raw.6).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
        let logical_bytes =
            u64::try_from(raw.7).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
        if item_count > MAX_SNAPSHOT_ITEMS
            || matches!(target, RuntimeStreamTarget::Conversation(_)) && item_count == 0
            || logical_bytes == 0
            || logical_bytes > MAX_SNAPSHOT_BYTES as u64
        {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        let content_sha256: [u8; 32] = raw
            .8
            .as_slice()
            .try_into()
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
        let sealed_snapshot_sha256: [u8; 32] = raw
            .9
            .as_slice()
            .try_into()
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
        let created_at_ms =
            u64::try_from(raw.10).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
        let expected = snapshot_token(
            key_bundle,
            &raw.1,
            raw.2.as_deref(),
            &snapshot_id,
            source_build_pin_id.as_ref().map(<[u8; 16]>::as_slice),
            raw.4.as_deref(),
            item_count,
            logical_bytes,
            &content_sha256,
            &sealed_snapshot_sha256,
            created_at_ms,
        )?;
        if raw.11.as_slice() != expected {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        let base = raw
            .4
            .as_deref()
            .map(|value| decode_sequence(sequence_scope, value))
            .transpose()
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
        match target {
            RuntimeStreamTarget::Catalog => {
                let catalog_high_water = ledger
                    .catalog_high_water
                    .as_deref()
                    .map(|value| decode_sequence(SequenceScope::CatalogRevision, value))
                    .transpose()
                    .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
                if base > catalog_high_water || item_count > ledger.conversation_count {
                    return Err(RuntimeStoreError::UnknownOrCorruptSchema);
                }
            }
            RuntimeStreamTarget::Conversation(conversation_id) => {
                conversation_bases.push((conversation_id, base));
            }
        }
        let reference = ReadySnapshotReference {
            snapshot_id,
            target,
            base: StreamCursor::from_high_water(base),
            item_count,
            logical_bytes,
            content_sha256,
        };
        if directory.insert(target, reference).is_some() {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        checked_count = checked_count
            .checked_add(1)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        checked_bytes = checked_bytes
            .checked_add(logical_bytes)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        if checked_count > MAX_DIRECTORY_ROWS || checked_bytes > MAX_SNAPSHOT_BYTES_GLOBAL {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
    }
    drop(statement);
    if checked_count != ledger.snapshot_count || checked_bytes != ledger.snapshot_bytes {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    if !conversation_bases.is_empty() {
        let conversation_ids = conversation_bases
            .iter()
            .map(|(conversation_id, _)| *conversation_id)
            .collect::<Vec<_>>();
        let parent_event_high_waters =
            super::super::journal::load_authenticated_conversation_event_high_waters(
                transaction,
                key_bundle,
                &conversation_ids,
            )
            .map_err(snapshot_parent_error)?;
        for (conversation_id, base) in conversation_bases {
            let parent_event_high_water = parent_event_high_waters
                .get(&conversation_id)
                .copied()
                .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
            if base > parent_event_high_water {
                return Err(RuntimeStoreError::UnknownOrCorruptSchema);
            }
        }
    }
    Ok(directory.get(&requested_target).cloned())
}

fn snapshot_directory_row_error(error: rusqlite::Error) -> RuntimeStoreError {
    match error {
        rusqlite::Error::FromSqlConversionFailure(..)
        | rusqlite::Error::IntegralValueOutOfRange(..)
        | rusqlite::Error::Utf8Error(_)
        | rusqlite::Error::InvalidColumnType(..) => RuntimeStoreError::UnknownOrCorruptSchema,
        error => RuntimeStoreError::Sqlite(error),
    }
}

pub(super) fn snapshot_parent_error(error: RuntimeStoreError) -> RuntimeStoreError {
    match error {
        RuntimeStoreError::Sqlite(error) => snapshot_directory_row_error(error),
        _ => RuntimeStoreError::UnknownOrCorruptSchema,
    }
}

pub(in crate::runtime::store) fn load_conversation_snapshot_read(
    connection: &Connection,
    read_crypto: &super::super::cipher::RuntimeReadCryptoCapability,
    database_id: [u8; 16],
    conversation_id: RuntimeId,
) -> Result<Option<StoredConversationSnapshot>, RuntimeStoreError> {
    if conversation_id.kind() != RuntimeIdKind::Conversation {
        return Err(RuntimeStoreError::IdKindMismatch {
            expected: RuntimeIdKind::Conversation,
            actual: conversation_id.kind(),
        });
    }
    let exists: i64 = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM conversations WHERE conversation_id = ?1)",
        [&conversation_id.as_bytes()[..]],
        |row| row.get(0),
    )?;
    if exists == 0 {
        return Err(RuntimeStoreError::ConversationNotFound);
    }
    load_snapshot_row_read(connection, read_crypto, database_id, conversation_id)
}

pub(in crate::runtime::store) fn load_conversation_snapshot_reference_read(
    connection: &Connection,
    read_crypto: &super::super::cipher::RuntimeReadCryptoCapability,
    database_id: [u8; 16],
    reference: &ReadySnapshotReference,
) -> Result<StoredConversationSnapshot, RuntimeStoreError> {
    let crate::runtime::events::RuntimeStreamTarget::Conversation(conversation_id) =
        reference.target
    else {
        return Err(RuntimeStoreError::InvalidConfig(
            "catalog snapshot reference cannot load a conversation snapshot",
        ));
    };
    let exact_exists: i64 = connection.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM snapshots
             WHERE snapshot_id = ?1 AND target_scope = 'conversation'
               AND conversation_id = ?2 AND build_state = 'ready'
         )",
        params![&reference.snapshot_id[..], &conversation_id.as_bytes()[..]],
        |row| row.get(0),
    )?;
    if exact_exists != 1 {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let snapshot = load_snapshot_row_read(connection, read_crypto, database_id, conversation_id)?
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let logical_bytes = u64::try_from(snapshot.payload.len())
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    if snapshot.snapshot_id != reference.snapshot_id
        || snapshot.conversation_id != conversation_id
        || StreamCursor::from_high_water(snapshot.base_event_seq) != reference.base
        || snapshot.item_count != reference.item_count
        || logical_bytes != reference.logical_bytes
        || snapshot.content_sha256 != reference.content_sha256
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(snapshot)
}

pub(super) fn checked_snapshot_blob_len(raw_len: i64) -> Result<usize, RuntimeStoreError> {
    let sealed_blob_len =
        usize::try_from(raw_len).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let maximum_blob_len = MAX_SNAPSHOT_BYTES
        .checked_add(ROW_BLOB_V1_OVERHEAD_LEN)
        .ok_or(RuntimeStoreError::PayloadTooLarge)?;
    if sealed_blob_len > maximum_blob_len {
        return Err(super::super::cipher::CipherError::InputTooLarge.into());
    }
    if sealed_blob_len < ROW_BLOB_V1_OVERHEAD_LEN {
        return Err(super::super::cipher::CipherError::InvalidEncoding.into());
    }
    Ok(sealed_blob_len)
}

pub(super) fn snapshot_ciphertext_sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// Retention 只允许使用 byte-identical ready snapshot。通过 SQLite incremental
/// BLOB API 和固定 16 KiB buffer 重算 ciphertext digest，禁止为了裁剪授权全量
/// materialize 最多 64 MiB 的 sealed snapshot。
fn verify_snapshot_ciphertext_identity(
    connection: &Connection,
    snapshot_id: &[u8; 16],
    expected_len: usize,
    expected_sha256: &[u8; 32],
) -> Result<(), RuntimeStoreError> {
    let (row_id, stored_len): (i64, i64) = connection
        .query_row(
            "SELECT rowid, length(sealed_snapshot) FROM snapshots WHERE snapshot_id = ?1",
            [&snapshot_id[..]],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => RuntimeStoreError::UnknownOrCorruptSchema,
            other => RuntimeStoreError::Sqlite(other),
        })?;
    if checked_snapshot_blob_len(stored_len)? != expected_len {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let blob = connection.blob_open(
        DatabaseName::Main,
        "snapshots",
        "sealed_snapshot",
        row_id,
        true,
    )?;
    if blob.len() != expected_len {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; SNAPSHOT_CIPHERTEXT_DIGEST_BUFFER_BYTES];
    let mut offset = 0_usize;
    while offset < expected_len {
        let chunk_len = buffer.len().min(expected_len - offset);
        blob.read_at_exact(&mut buffer[..chunk_len], offset)?;
        digest.update(&buffer[..chunk_len]);
        offset = offset
            .checked_add(chunk_len)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    }
    if <[u8; 32]>::from(digest.finalize()) != *expected_sha256 {
        return Err(super::super::cipher::CipherError::AuthenticationFailed.into());
    }
    Ok(())
}

pub(super) fn load_conversation_snapshot_metadata(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    conversation_id: RuntimeId,
) -> Result<Option<ConversationSnapshotRowMetadata>, RuntimeStoreError> {
    let raw = connection
        .query_row(
            "SELECT snapshot_id, source_build_pin_id, base_cursor, item_count,
                    logical_snapshot_bytes, content_sha256, sealed_snapshot_sha256,
                    created_at_ms, metadata_token, length(sealed_snapshot)
             FROM snapshots
             WHERE target_scope = 'conversation' AND conversation_id = ?1
               AND build_state = 'ready'",
            [&conversation_id.as_bytes()[..]],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, Vec<u8>>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, Vec<u8>>(8)?,
                    row.get::<_, i64>(9)?,
                ))
            },
        )
        .optional()?;
    let Some(raw) = raw else {
        return Ok(None);
    };
    let sealed_blob_len = checked_snapshot_blob_len(raw.9)?;
    let snapshot_id: [u8; 16] = raw
        .0
        .as_slice()
        .try_into()
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let source_build_pin_id: [u8; 16] = raw
        .1
        .as_slice()
        .try_into()
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    if snapshot_id == [0; 16] || source_build_pin_id == [0; 16] {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let item_count = u64::try_from(raw.3).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let logical_bytes =
        u64::try_from(raw.4).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    if item_count == 0
        || item_count > MAX_SNAPSHOT_ITEMS
        || logical_bytes == 0
        || logical_bytes > MAX_SNAPSHOT_BYTES as u64
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let expected_blob_len = usize::try_from(logical_bytes)
        .ok()
        .and_then(|bytes| bytes.checked_add(ROW_BLOB_V1_OVERHEAD_LEN))
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    if sealed_blob_len != expected_blob_len {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let content_sha256: [u8; 32] = raw
        .5
        .as_slice()
        .try_into()
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let sealed_snapshot_sha256: [u8; 32] = raw
        .6
        .as_slice()
        .try_into()
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let created_at_ms =
        u64::try_from(raw.7).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let expected = snapshot_token(
        key_bundle,
        "conversation",
        Some(conversation_id.as_bytes()),
        &snapshot_id,
        Some(&source_build_pin_id),
        raw.2.as_deref(),
        item_count,
        logical_bytes,
        &content_sha256,
        &sealed_snapshot_sha256,
        created_at_ms,
    )?;
    if raw.8.as_slice() != expected {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let base_event_seq = raw
        .2
        .as_deref()
        .map(|value| decode_sequence(SequenceScope::EventSeq, value))
        .transpose()?;
    Ok(Some(ConversationSnapshotRowMetadata {
        snapshot_id,
        source_build_pin_id,
        base_event_seq,
        item_count,
        logical_bytes,
        content_sha256,
        sealed_snapshot_sha256,
        created_at_ms,
        sealed_blob_len,
    }))
}

pub(super) fn load_catalog_snapshot_metadata(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
) -> Result<Option<CatalogSnapshotRowMetadata>, RuntimeStoreError> {
    let raw = connection
        .query_row(
            "SELECT snapshot_id, source_build_pin_id, base_cursor, item_count,
                    logical_snapshot_bytes, content_sha256, sealed_snapshot_sha256,
                    created_at_ms, metadata_token, length(sealed_snapshot)
             FROM snapshots
             WHERE target_scope = 'catalog' AND conversation_id IS NULL
               AND build_state = 'ready'",
            [],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Option<Vec<u8>>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, Vec<u8>>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, Vec<u8>>(8)?,
                    row.get::<_, i64>(9)?,
                ))
            },
        )
        .optional()?;
    let Some(raw) = raw else {
        return Ok(None);
    };
    let sealed_blob_len = checked_snapshot_blob_len(raw.9)?;
    let snapshot_id: [u8; 16] = raw
        .0
        .as_slice()
        .try_into()
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    if snapshot_id == [0; 16] || raw.1.is_some() {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let item_count = u64::try_from(raw.3).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let logical_bytes =
        u64::try_from(raw.4).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    if item_count > MAX_SNAPSHOT_ITEMS
        || logical_bytes == 0
        || logical_bytes > MAX_SNAPSHOT_BYTES as u64
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let expected_blob_len = usize::try_from(logical_bytes)
        .ok()
        .and_then(|bytes| bytes.checked_add(ROW_BLOB_V1_OVERHEAD_LEN))
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    if sealed_blob_len != expected_blob_len {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let content_sha256: [u8; 32] = raw
        .5
        .as_slice()
        .try_into()
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let sealed_snapshot_sha256: [u8; 32] = raw
        .6
        .as_slice()
        .try_into()
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let created_at_ms =
        u64::try_from(raw.7).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let expected = snapshot_token(
        key_bundle,
        "catalog",
        None,
        &snapshot_id,
        None,
        raw.2.as_deref(),
        item_count,
        logical_bytes,
        &content_sha256,
        &sealed_snapshot_sha256,
        created_at_ms,
    )?;
    if raw.8.as_slice() != expected {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let base_catalog_revision = raw
        .2
        .as_deref()
        .map(|value| decode_sequence(SequenceScope::CatalogRevision, value))
        .transpose()?;
    Ok(Some(CatalogSnapshotRowMetadata {
        snapshot_id,
        base_catalog_revision,
        item_count,
        logical_bytes,
        content_sha256,
        sealed_snapshot_sha256,
        created_at_ms,
        sealed_blob_len,
    }))
}

pub(in crate::runtime::store) fn load_catalog_snapshot_reference_read(
    connection: &Connection,
    read_crypto: &RuntimeReadCryptoCapability,
    database_id: [u8; 16],
    reference: &ReadySnapshotReference,
) -> Result<StoredCatalogSnapshot, RuntimeStoreError> {
    if reference.target != crate::runtime::events::RuntimeStreamTarget::Catalog
        || reference.snapshot_id == [0; 16]
    {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }
    let raw = connection
        .query_row(
            "SELECT source_build_pin_id, base_cursor, item_count,
                    logical_snapshot_bytes, content_sha256, sealed_snapshot_sha256,
                    created_at_ms, metadata_token, sealed_snapshot
             FROM snapshots
             WHERE snapshot_id = ?1 AND target_scope = 'catalog'
               AND conversation_id IS NULL AND build_state = 'ready'",
            [&reference.snapshot_id[..]],
            |row| {
                Ok((
                    row.get::<_, Option<Vec<u8>>>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, Vec<u8>>(7)?,
                    row.get::<_, Vec<u8>>(8)?,
                ))
            },
        )
        .map_err(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => RuntimeStoreError::InvalidStateTransition,
            other => RuntimeStoreError::Sqlite(other),
        })?;
    if raw.0.is_some() {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let item_count = u64::try_from(raw.2).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let logical_bytes =
        u64::try_from(raw.3).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let content_sha256: [u8; 32] = raw
        .4
        .as_slice()
        .try_into()
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let sealed_snapshot_sha256: [u8; 32] = raw
        .5
        .as_slice()
        .try_into()
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let created_at_ms =
        u64::try_from(raw.6).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let base_catalog_revision = raw
        .1
        .as_deref()
        .map(|value| decode_sequence(SequenceScope::CatalogRevision, value))
        .transpose()?;
    let base = StreamCursor::from_high_water(base_catalog_revision);
    if base != reference.base
        || item_count != reference.item_count
        || logical_bytes != reference.logical_bytes
        || content_sha256 != reference.content_sha256
        || item_count > MAX_SNAPSHOT_ITEMS
        || logical_bytes == 0
        || logical_bytes > MAX_SNAPSHOT_BYTES as u64
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let base_field = optional_field(raw.1.as_deref().map(str::as_bytes));
    let conversation = optional_field(None);
    let source = optional_field(None);
    if !super::super::stream::verify_metadata_mac(
        read_crypto,
        SNAPSHOT_TOKEN_DOMAIN,
        &[
            b"catalog",
            &conversation,
            &reference.snapshot_id,
            &source,
            &base_field,
            b"ready",
            &item_count.to_be_bytes(),
            &logical_bytes.to_be_bytes(),
            &content_sha256,
            &sealed_snapshot_sha256,
            &created_at_ms.to_be_bytes(),
        ],
        &raw.7,
    )? {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let expected_sealed_len = usize::try_from(logical_bytes)
        .ok()
        .and_then(|bytes| bytes.checked_add(ROW_BLOB_V1_OVERHEAD_LEN))
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let mut payload = raw.8;
    if payload.len() != expected_sealed_len {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    if snapshot_ciphertext_sha256(&payload) != sealed_snapshot_sha256 {
        return Err(super::super::cipher::CipherError::AuthenticationFailed.into());
    }
    open_snapshot_payload_read_in_place(
        read_crypto,
        database_id,
        &reference.snapshot_id,
        &mut payload,
    )?;
    if payload.len()
        != usize::try_from(logical_bytes).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
        || <[u8; 32]>::from(Sha256::digest(payload.as_slice())) != content_sha256
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    catalog_materialization_peak_bound(logical_bytes, item_count)?;
    // 威胁场景：合法 v1 baseline 转为 v2 entry 后再与旧 plaintext 做 canonical
    // 比较，必然因 adapterStateKey/entryRevision 形状不同而误报损坏。canonical
    // 校验必须针对认证后实际解出的原始格式，随后才在内存转换。
    let persisted = super::decode_persisted_catalog_baseline(&payload)?;
    let canonical = match &persisted {
        super::PersistedCatalogBaseline::Current(baseline) => {
            canonical_json_matches(baseline, &payload)?
        }
        super::PersistedCatalogBaseline::Legacy(baseline) => {
            canonical_json_matches(baseline, &payload)?
        }
    };
    let baseline = persisted.into_current();
    if baseline.version != 1
        || baseline.base_catalog_cursor != base
        || u64::try_from(baseline.entries.len())
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
            != item_count
        || !canonical
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(StoredCatalogSnapshot {
        snapshot_id: reference.snapshot_id,
        base_catalog_revision,
        item_count,
        content_sha256,
        created_at_ms,
        payload,
        memory_lease: None,
    })
}

/// 不分配第二份 canonical payload 的逐字节比较 writer。
///
/// 威胁场景：64 MiB catalog plaintext 在 read-pool 内若为 canonical 校验再
/// `to_vec` 一次，会与 raw + decoded baseline 三份共驻并越过 128 MiB 上限。
struct CanonicalJsonCompare<'a> {
    expected: &'a [u8],
    position: usize,
}

impl std::io::Write for CanonicalJsonCompare<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let end = self.position.checked_add(bytes.len()).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "canonical length overflow")
        })?;
        if self.expected.get(self.position..end) != Some(bytes) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "catalog baseline is not canonical",
            ));
        }
        self.position = end;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn canonical_json_matches<T: serde::Serialize>(
    value: &T,
    expected: &[u8],
) -> Result<bool, RuntimeStoreError> {
    let mut writer = CanonicalJsonCompare {
        expected,
        position: 0,
    };
    match serde_json::to_writer(&mut writer, value) {
        Ok(()) => Ok(writer.position == expected.len()),
        Err(error) if error.is_io() => Ok(false),
        Err(_) => Err(RuntimeStoreError::UnknownOrCorruptSchema),
    }
}

pub(in crate::runtime::store) fn authenticated_conversation_snapshot_covers(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    conversation_id: RuntimeId,
    victim: u64,
) -> Result<bool, RuntimeStoreError> {
    let Some(snapshot) =
        load_conversation_snapshot_metadata(connection, key_bundle, conversation_id)?
    else {
        return Ok(false);
    };
    if snapshot.base_event_seq.is_none_or(|base| base < victim) {
        return Ok(false);
    }
    verify_snapshot_ciphertext_identity(
        connection,
        &snapshot.snapshot_id,
        snapshot.sealed_blob_len,
        &snapshot.sealed_snapshot_sha256,
    )?;
    Ok(true)
}

pub(in crate::runtime::store) fn authenticated_catalog_snapshot_covers(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    victim: u64,
) -> Result<bool, RuntimeStoreError> {
    let Some(snapshot) = load_catalog_snapshot_metadata(connection, key_bundle)? else {
        return Ok(false);
    };
    if snapshot
        .base_catalog_revision
        .is_none_or(|base| base < victim)
    {
        return Ok(false);
    }
    verify_snapshot_ciphertext_identity(
        connection,
        &snapshot.snapshot_id,
        snapshot.sealed_blob_len,
        &snapshot.sealed_snapshot_sha256,
    )?;
    Ok(true)
}
