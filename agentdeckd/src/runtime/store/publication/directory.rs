//! Publication stream 与 outbox directory 的完整认证扫描。

use std::collections::HashMap;

use super::*;

/// SubscriptionBarrier 先认证完整 publication stream directory，再选择请求 target
/// 的唯一 active stream。目录枚举不按 scope/state 过滤；历史 NeedsSnapshot/Retired
/// row 也必须通过 metadata token 与 parent 认证。
pub(in crate::runtime::store) fn authenticate_directory(
    transaction: &Transaction<'_>,
    key_bundle: &RuntimeKeyBundle,
    ledger: &RuntimeLedger,
    requested_scope: PublicationScope,
) -> Result<Option<PublicationStreamRecord>, RuntimeStoreError> {
    let streams = authenticate_directory_records(transaction, key_bundle, ledger)?;
    let mut active = None;
    for stream in streams {
        if stream.state == PublicationStreamState::Active
            && stream.scope == requested_scope
            && active.replace(stream).is_some()
        {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
    }
    Ok(active)
}

/// Dispatcher restart 枚举必须先认证完整 stream/outbox directory 与 ledger，不能用
/// 未认证的 `SELECT DISTINCT publication_stream_id` 作为恢复信任根。NeedsSnapshot/
/// Retired stream 只要仍有 `reserved > acknowledged` 的 frozen row，也必须继续返回：
/// `committed > acknowledged` 表示 Relay COMMIT 已落库、daemon local ACK 尚待精确修复，
/// 恢复只能删本地 outbox，绝不能重新触达 transport。
pub(in crate::runtime::store) fn load_pending_publication_stream_ids(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
) -> Result<Vec<[u8; 16]>, RuntimeStoreError> {
    let ledger = super::super::sqlite::load_runtime_ledger(connection, key_bundle, database_id)?;
    Ok(
        authenticate_directory_records(connection, key_bundle, &ledger)?
            .into_iter()
            .filter(|stream| stream.reserved_high_water > stream.acknowledged_high_water)
            .map(|stream| stream.publication_stream_id)
            .collect(),
    )
}

pub(in crate::runtime::store) fn authenticate_directory_records(
    transaction: &Connection,
    key_bundle: &RuntimeKeyBundle,
    ledger: &RuntimeLedger,
) -> Result<Vec<PublicationStreamRecord>, RuntimeStoreError> {
    let mut statement = transaction.prepare(
        "SELECT publication_stream_id FROM publication_streams
         ORDER BY publication_stream_id",
    )?;
    let rows = statement.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
    let mut ids = Vec::new();
    for row in rows {
        let id = row.map_err(publication_directory_row_error)?;
        ids.push(fixed::<16>(&id)?);
        if ids.len() > 1_025 {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
    }
    drop(statement);

    let checked_count =
        u64::try_from(ids.len()).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    if checked_count != ledger.publication_stream_count {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }

    let mut streams_by_id = HashMap::new();
    for publication_stream_id in ids {
        let stream = load_stream(transaction, key_bundle, publication_stream_id)
            .map_err(publication_directory_entry_error)?;
        if stream.publication_stream_id == [0; 16]
            || stream.stream_route == [0; 16]
            || stream.generation == [0; 16]
        {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        if let PublicationScope::Conversation(conversation_id) = stream.scope {
            super::super::journal::load_authenticated_conversation_event_high_water(
                transaction,
                key_bundle,
                conversation_id,
            )
            .map_err(publication_directory_entry_error)?;
        }
        if streams_by_id
            .insert(stream.publication_stream_id, stream)
            .is_some()
        {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
    }

    let mut outbox_by_stream = HashMap::new();
    for (publication_stream_id, stream) in &streams_by_id {
        outbox_by_stream.insert(
            *publication_stream_id,
            PublicationOutboxAccumulator::new(stream)?,
        );
    }

    let mut statement = transaction.prepare(
        "SELECT publication_id, publication_stream_id, generation, stream_seq,
                counter_scope_token, sender_counter, inner_after_seq, inner_through_seq,
                payload_kind, blob_sha256, logical_blob_bytes, created_at_ms,
                metadata_token
         FROM publication_outbox
         ORDER BY publication_stream_id, generation, stream_seq",
    )?;
    let rows = statement.query_map([], OutboxDirectoryRow::read)?;
    let mut outbox_count = 0_u64;
    let mut outbox_bytes = 0_u64;
    for row in rows {
        let row = row
            .map_err(publication_directory_row_error)?
            .authenticate(key_bundle)
            .map_err(publication_directory_entry_error)?;
        let parent = streams_by_id
            .get(&row.publication_stream_id)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        if parent.generation != row.generation
            || parent.counter_scope_token != Some(row.counter_scope_token)
            || row.created_at_ms < parent.created_at_ms
            || row.created_at_ms > parent.updated_at_ms
        {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        outbox_by_stream
            .get_mut(&row.publication_stream_id)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?
            .push(parent, &row)?;
        outbox_count = outbox_count
            .checked_add(1)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        outbox_bytes = outbox_bytes
            .checked_add(row.logical_blob_bytes)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        if outbox_count > MAX_PUBLICATION_ROWS_GLOBAL || outbox_bytes > MAX_PUBLICATION_BYTES_GLOBAL
        {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
    }
    drop(statement);
    if outbox_count != ledger.publication_outbox_count
        || outbox_bytes != ledger.publication_outbox_bytes
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }

    let mut streams = Vec::with_capacity(streams_by_id.len());
    let mut active_by_target = HashMap::new();
    for stream in streams_by_id.into_values() {
        outbox_by_stream
            .remove(&stream.publication_stream_id)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?
            .finish(&stream)?;
        authenticate_rotation_inner_baseline(transaction, key_bundle, &stream)?;
        if stream.state == PublicationStreamState::Active
            && active_by_target.insert(stream.scope, ()).is_some()
        {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        streams.push(stream);
    }
    streams.sort_unstable_by_key(|stream| stream.publication_stream_id);
    Ok(streams)
}

struct OutboxDirectoryRow {
    publication_stream_id: [u8; 16],
    generation: [u8; 16],
    stream_seq: u64,
    counter_scope_token: [u8; 32],
    sender_counter: u64,
    inner_after: Option<u64>,
    inner_through: Option<u64>,
    payload_kind: PublicationPayloadKind,
    blob_sha256: [u8; 32],
    logical_blob_bytes: u64,
    created_at_ms: u64,
}

struct PublicationOutboxAccumulator {
    expected_outer: Option<u64>,
    expected_inner: Option<u64>,
    last_outer: Option<u64>,
    previous_sender_counter: Option<u64>,
    committed_hash: Option<[u8; 32]>,
    committed_inner: Option<Option<u64>>,
    row_count: u64,
    logical_bytes: u64,
}

impl PublicationOutboxAccumulator {
    fn new(stream: &PublicationStreamRecord) -> Result<Self, RuntimeStoreError> {
        let expected_outer = stream
            .acknowledged_high_water
            .map_or(Some(0), |value| value.checked_add(1));
        Ok(Self {
            expected_outer,
            expected_inner: stream.acknowledged_inner_cursor,
            last_outer: stream.acknowledged_high_water,
            previous_sender_counter: None,
            committed_hash: None,
            committed_inner: None,
            row_count: 0,
            logical_bytes: 0,
        })
    }

    fn push(
        &mut self,
        stream: &PublicationStreamRecord,
        row: &OutboxDirectoryRow,
    ) -> Result<(), RuntimeStoreError> {
        if Some(row.stream_seq) != self.expected_outer
            || self
                .previous_sender_counter
                .is_some_and(|previous| row.sender_counter <= previous)
        {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        match row.inner_through {
            Some(through) if row.inner_after == self.expected_inner => {
                self.expected_inner = Some(through);
            }
            None if row.inner_after.is_none()
                && row.payload_kind == PublicationPayloadKind::Control => {}
            _ => return Err(RuntimeStoreError::UnknownOrCorruptSchema),
        }
        self.row_count = self
            .row_count
            .checked_add(1)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        self.logical_bytes = self
            .logical_bytes
            .checked_add(row.logical_blob_bytes)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        if self.row_count > MAX_PUBLICATION_ROWS_PER_STREAM
            || self.logical_bytes > MAX_PUBLICATION_BYTES_PER_STREAM
        {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        self.previous_sender_counter = Some(row.sender_counter);
        self.last_outer = Some(row.stream_seq);
        if stream.committed_high_water == Some(row.stream_seq) {
            self.committed_hash = Some(row.blob_sha256);
            self.committed_inner = Some(self.expected_inner);
        }
        self.expected_outer = row.stream_seq.checked_add(1);
        Ok(())
    }

    fn finish(self, stream: &PublicationStreamRecord) -> Result<(), RuntimeStoreError> {
        if stream.reserved_high_water != self.last_outer
            || self
                .previous_sender_counter
                .is_some_and(|counter| Some(counter) != stream.sender_counter_high_water)
            || stream.committed_high_water.is_none()
                && stream.committed_inner_cursor != stream.acknowledged_inner_cursor
            || stream
                .acknowledged_inner_cursor
                .zip(stream.committed_inner_cursor)
                .is_some_and(|(acknowledged, committed)| acknowledged > committed)
        {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }

        if stream.committed_high_water > stream.acknowledged_high_water {
            if self.committed_hash != stream.last_committed_blob_hash
                || self.committed_inner != Some(stream.committed_inner_cursor)
            {
                return Err(RuntimeStoreError::UnknownOrCorruptSchema);
            }
        } else if stream.committed_high_water == stream.acknowledged_high_water {
            if stream.committed_high_water.is_some()
                && (stream.last_committed_blob_hash != stream.last_acknowledged_blob_hash
                    || stream.committed_inner_cursor != stream.acknowledged_inner_cursor)
            {
                return Err(RuntimeStoreError::UnknownOrCorruptSchema);
            }
        } else {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        Ok(())
    }
}

/// Generation rotation 后，outer 从 BeforeFirst 重新开始，但 inner 必须保留旧
/// generation 已 COMMIT+ACK 的 H。该非对称 cut 只能由 authenticated rotation
/// lineage 与覆盖 H 的 ready snapshot 共同证明；否则 open/recovery 必须 fail-close。
/// 一旦新 generation ACK 了首帧，常规 outbox/hash 链继续承担完整性证明。
fn authenticate_rotation_inner_baseline(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    stream: &PublicationStreamRecord,
) -> Result<(), RuntimeStoreError> {
    let Some(inner_baseline) = stream.acknowledged_inner_cursor else {
        return Ok(());
    };
    if stream.acknowledged_high_water.is_some() {
        return Ok(());
    }
    if stream.rotation_serial == 0
        || stream.last_rotation_request_digest.is_none()
        || stream.committed_inner_cursor.is_none()
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let covered = match stream.scope {
        PublicationScope::Catalog => super::super::snapshot::authenticated_catalog_snapshot_covers(
            connection,
            key_bundle,
            inner_baseline,
        )?,
        PublicationScope::Conversation(conversation_id) => {
            super::super::snapshot::authenticated_conversation_snapshot_covers(
                connection,
                key_bundle,
                conversation_id,
                inner_baseline,
            )?
        }
    };
    if !covered {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(())
}

struct RawOutboxDirectoryRow {
    publication_id: Vec<u8>,
    publication_stream_id: Vec<u8>,
    generation: Vec<u8>,
    stream_seq: String,
    counter_scope_token: Vec<u8>,
    sender_counter: String,
    inner_after: Option<String>,
    inner_through: Option<String>,
    payload_kind: String,
    blob_sha256: Vec<u8>,
    logical_blob_bytes: i64,
    created_at_ms: i64,
    metadata_token: Vec<u8>,
}

impl OutboxDirectoryRow {
    fn read(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawOutboxDirectoryRow> {
        Ok(RawOutboxDirectoryRow {
            publication_id: row.get(0)?,
            publication_stream_id: row.get(1)?,
            generation: row.get(2)?,
            stream_seq: row.get(3)?,
            counter_scope_token: row.get(4)?,
            sender_counter: row.get(5)?,
            inner_after: row.get(6)?,
            inner_through: row.get(7)?,
            payload_kind: row.get(8)?,
            blob_sha256: row.get(9)?,
            logical_blob_bytes: row.get(10)?,
            created_at_ms: row.get(11)?,
            metadata_token: row.get(12)?,
        })
    }
}

impl RawOutboxDirectoryRow {
    fn authenticate(
        self,
        key_bundle: &RuntimeKeyBundle,
    ) -> Result<OutboxDirectoryRow, RuntimeStoreError> {
        let publication_id = fixed::<16>(&self.publication_id)?;
        let publication_stream_id = fixed::<16>(&self.publication_stream_id)?;
        let generation = fixed::<16>(&self.generation)?;
        let counter_scope_token = fixed::<32>(&self.counter_scope_token)?;
        let blob_sha256 = fixed::<32>(&self.blob_sha256)?;
        if publication_id == [0; 16]
            || publication_stream_id == [0; 16]
            || generation == [0; 16]
            || counter_scope_token == [0; 32]
        {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        let stream_seq = decode_sequence(SequenceScope::EventSeq, &self.stream_seq)?;
        let sender_counter = decode_sequence(SequenceScope::EventSeq, &self.sender_counter)?;
        let inner_after = decode_optional(&self.inner_after)?;
        let inner_through = decode_optional(&self.inner_through)?;
        let payload_kind = parse_payload_kind(&self.payload_kind)?;
        validate_inner_range(inner_after, inner_through, payload_kind)?;
        let logical_blob_bytes = u64::try_from(self.logical_blob_bytes)
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
        if !(1..=u64::try_from(MAX_PUBLICATION_BLOB_BYTES)
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?)
            .contains(&logical_blob_bytes)
        {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        let created_at_ms = u64::try_from(self.created_at_ms)
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
        let expected = outbox_token(
            key_bundle,
            publication_id,
            publication_stream_id,
            generation,
            &self.stream_seq,
            counter_scope_token,
            sender_counter,
            self.inner_after.as_deref(),
            self.inner_through.as_deref(),
            payload_kind,
            blob_sha256,
            logical_blob_bytes,
            created_at_ms,
        )?;
        if self.metadata_token.as_slice() != expected {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        Ok(OutboxDirectoryRow {
            publication_stream_id,
            generation,
            stream_seq,
            counter_scope_token,
            sender_counter,
            inner_after,
            inner_through,
            payload_kind,
            blob_sha256,
            logical_blob_bytes,
            created_at_ms,
        })
    }
}

fn publication_directory_row_error(error: rusqlite::Error) -> RuntimeStoreError {
    match error {
        rusqlite::Error::FromSqlConversionFailure(..)
        | rusqlite::Error::IntegralValueOutOfRange(..)
        | rusqlite::Error::Utf8Error(_)
        | rusqlite::Error::InvalidColumnType(..) => RuntimeStoreError::UnknownOrCorruptSchema,
        error => RuntimeStoreError::Sqlite(error),
    }
}

fn publication_directory_entry_error(error: RuntimeStoreError) -> RuntimeStoreError {
    match error {
        RuntimeStoreError::Sqlite(error) => publication_directory_row_error(error),
        _ => RuntimeStoreError::UnknownOrCorruptSchema,
    }
}
