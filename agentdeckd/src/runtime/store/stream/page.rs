use agentdeck_protocol::runtime::{CatalogDelta, RuntimeEvent};
use rusqlite::{Connection, OptionalExtension, params};

use crate::runtime::model::{MAX_RUNTIME_EVENT_BYTES, RuntimeStoreError};
use crate::runtime::read_pool::{
    MAX_RUNTIME_READ_PAGE_BYTES, MAX_RUNTIME_READ_PAGE_ROWS, ReadMemoryLease,
};

use super::super::{RuntimeId, catalog, cipher, journal, sequence, sqlite};
use super::{
    EVENT_STREAM_INDEX_TOKEN_DOMAIN, PersistedRuntimeEvent, RuntimeBackfillPin,
    RuntimeBackfillTarget, SequenceScope, decode_persisted_runtime_event, decode_sequence,
    runtime_event_id, verify_metadata_mac,
};

#[derive(Debug)]
pub struct RuntimeEventBackfillPage {
    pub events: Vec<RuntimeEvent>,
    pub next_after: u64,
    pub through: u64,
    pub complete: bool,
    completion: RuntimeBackfillPageCompletion,
    pub(crate) memory_lease: Option<ReadMemoryLease>,
}

#[derive(Debug, PartialEq)]
pub struct RuntimeCatalogBackfillPage {
    pub deltas: Vec<CatalogDelta>,
    pub next_after: u64,
    pub through: u64,
    pub complete: bool,
    completion: RuntimeBackfillPageCompletion,
    pub(crate) memory_lease: Option<ReadMemoryLease>,
}

pub(in super::super) struct RuntimeSnapshotEventPage {
    pub(in super::super) events: Vec<RuntimeEvent>,
    pub(in super::super) next_after: u64,
    pub(in super::super) complete: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in super::super) struct RuntimeBackfillReadPlan {
    pin: RuntimeBackfillPin,
    requested_after: Option<u64>,
    first: u64,
}

/// backfill page 的 opaque completion capability。load 只返回并认证此 capability；
/// reply pump 收到对应 transport flush ACK 后，调用方才可显式提交它。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeBackfillPageCompletion {
    plan: RuntimeBackfillReadPlan,
    next_after: u64,
    complete: bool,
}

impl RuntimeEventBackfillPage {
    #[must_use]
    pub const fn completion(&self) -> &RuntimeBackfillPageCompletion {
        &self.completion
    }
}

impl RuntimeCatalogBackfillPage {
    #[must_use]
    pub const fn completion(&self) -> &RuntimeBackfillPageCompletion {
        &self.completion
    }
}

#[cfg(test)]
pub(in super::super) fn load_event_backfill_page(
    state: &sqlite::RuntimeSqlite,
    pin: &RuntimeBackfillPin,
    requested_after: Option<u64>,
    now_ms: u64,
) -> Result<RuntimeEventBackfillPage, RuntimeStoreError> {
    let plan = prepare_backfill_page(state, pin, requested_after, now_ms)?;
    let read_crypto = state.key_bundle.read_only_capability();
    let page = read_event_backfill_page(&state.connection, &read_crypto, state.database_id, &plan)?;
    validate_backfill_page(state, page.completion(), now_ms)?;
    Ok(page)
}

pub(in super::super) fn prepare_backfill_page(
    state: &sqlite::RuntimeSqlite,
    pin: &RuntimeBackfillPin,
    requested_after: Option<u64>,
    now_ms: u64,
) -> Result<RuntimeBackfillReadPlan, RuntimeStoreError> {
    validate_active_pin(state, pin, requested_after, now_ms)?;
    let first = requested_after
        .map_or(Some(0), |value| value.checked_add(1))
        .ok_or(RuntimeStoreError::InvalidBackfillPin)?;
    Ok(RuntimeBackfillReadPlan {
        pin: pin.clone(),
        requested_after,
        first,
    })
}

pub(in super::super) fn read_event_backfill_page(
    connection: &Connection,
    read_crypto: &cipher::RuntimeReadCryptoCapability,
    database_id: [u8; 16],
    plan: &RuntimeBackfillReadPlan,
) -> Result<RuntimeEventBackfillPage, RuntimeStoreError> {
    read_event_backfill_page_with_mode(
        connection,
        read_crypto,
        database_id,
        plan,
        EventPageReadMode::Regular,
    )
}

/// 只供 worker 在 authenticated 首 row 确实超过 8 MiB page cap 后使用。
///
/// 威胁场景：合法的单条 canonical RuntimeEvent 可能大于 8 MiB、但仍在 64 MiB
/// item hard cap 内；若 snapshot/backfill 永远只走普通 page，它会永久无法 replay。
/// 此入口强制只读这一 row，且拒绝把普通小页或多 row 聚合升级成 128 MiB 路径。
pub(in super::super) fn read_oversized_event_backfill_page(
    connection: &Connection,
    read_crypto: &cipher::RuntimeReadCryptoCapability,
    database_id: [u8; 16],
    plan: &RuntimeBackfillReadPlan,
) -> Result<RuntimeEventBackfillPage, RuntimeStoreError> {
    read_event_backfill_page_with_mode(
        connection,
        read_crypto,
        database_id,
        plan,
        EventPageReadMode::OversizedSingle,
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EventPageReadMode {
    Regular,
    OversizedSingle,
}

fn read_event_backfill_page_with_mode(
    connection: &Connection,
    read_crypto: &cipher::RuntimeReadCryptoCapability,
    database_id: [u8; 16],
    plan: &RuntimeBackfillReadPlan,
    mode: EventPageReadMode,
) -> Result<RuntimeEventBackfillPage, RuntimeStoreError> {
    debug_assert_eq!(MAX_RUNTIME_READ_PAGE_ROWS, 64);
    let RuntimeBackfillTarget::Conversation(conversation_id) = plan.pin.target else {
        return Err(RuntimeStoreError::InvalidBackfillPin);
    };
    let first = sequence::encode_sequence(plan.first);
    let through = sequence::encode_sequence(plan.pin.through);
    let mut compact = Vec::new();
    let mut total_bytes = 0_u64;
    let mut statement = connection.prepare(
        "SELECT event_seq, event_id, logical_event_bytes, created_at_ms, metadata_token
         FROM event_stream_index
         WHERE conversation_id = ?1 AND event_seq BETWEEN ?2 AND ?3
         ORDER BY event_seq LIMIT 64",
    )?;
    let rows = statement.query_map(
        params![&conversation_id.as_bytes()[..], &first, &through],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Vec<u8>>(4)?,
            ))
        },
    )?;
    for row in rows {
        let row = row?;
        let logical_bytes =
            u64::try_from(row.2).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
        let created_at_ms =
            u64::try_from(row.3).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
        // 威胁场景：攻击者若只篡改 replay membership 的 size/time/token，仍可让
        // journal ciphertext 本身认证通过，并借伪造 size 绕过 8 MiB page cap。
        if !verify_metadata_mac(
            read_crypto,
            EVENT_STREAM_INDEX_TOKEN_DOMAIN,
            &[
                conversation_id.as_bytes(),
                row.0.as_bytes(),
                &row.1,
                &logical_bytes.to_be_bytes(),
                &created_at_ms.to_be_bytes(),
            ],
            &row.4,
        )? {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        match mode {
            EventPageReadMode::Regular => {
                if logical_bytes > u64::from(MAX_RUNTIME_READ_PAGE_BYTES) {
                    if compact.is_empty() {
                        return Err(RuntimeStoreError::BackfillNeedSnapshot);
                    }
                    break;
                }
                if !compact.is_empty()
                    && total_bytes
                        .checked_add(logical_bytes)
                        .ok_or(RuntimeStoreError::PayloadTooLarge)?
                        > u64::from(MAX_RUNTIME_READ_PAGE_BYTES)
                {
                    break;
                }
            }
            EventPageReadMode::OversizedSingle => {
                if !compact.is_empty()
                    || logical_bytes <= u64::from(MAX_RUNTIME_READ_PAGE_BYTES)
                    || logical_bytes
                        > u64::try_from(MAX_RUNTIME_EVENT_BYTES)
                            .map_err(|_| RuntimeStoreError::PayloadTooLarge)?
                {
                    return Err(RuntimeStoreError::UnknownOrCorruptSchema);
                }
            }
        }
        total_bytes = total_bytes
            .checked_add(logical_bytes)
            .ok_or(RuntimeStoreError::PayloadTooLarge)?;
        compact.push((row.0, row.1, logical_bytes, created_at_ms));
        if mode == EventPageReadMode::OversizedSingle {
            break;
        }
    }
    drop(statement);
    if compact.is_empty() {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let mut events = Vec::new();
    events
        .try_reserve_exact(compact.len())
        .map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
    let mut expected = decode_sequence(SequenceScope::EventSeq, &first)?;
    for (event_seq, event_id, logical_bytes, created_at_ms) in compact {
        let actual = decode_sequence(SequenceScope::EventSeq, &event_seq)?;
        if actual != expected {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        let event = journal::load_event_read(
            connection,
            read_crypto,
            database_id,
            runtime_event_id(&event_id)?,
        )?;
        if event.conversation_id != conversation_id
            || event.event_seq != actual
            || event.event_id.as_bytes() != event_id.as_slice()
            || event.created_at_ms != created_at_ms
            || u64::try_from(event.payload.len())
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
                != logical_bytes
        {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        let PersistedRuntimeEvent::Canonical(event) = decode_persisted_runtime_event(&event)?
        else {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        };
        events.push(*event);
        expected = expected
            .checked_add(1)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    }
    let next_after = expected
        .checked_sub(1)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let complete = next_after == plan.pin.through;
    Ok(RuntimeEventBackfillPage {
        events,
        next_after,
        through: plan.pin.through,
        complete,
        completion: RuntimeBackfillPageCompletion {
            plan: plan.clone(),
            next_after,
            complete,
        },
        memory_lease: None,
    })
}

/// Snapshot reducer 专用只读页。exact build pin 在 worker 进入/退出 read-pool
/// 前后另行认证；这里复用同一 64-row/8-MiB canonical decoder，但不生成可被
/// reply pump 误提交的 backfill completion capability。
pub(in super::super) fn read_snapshot_event_page(
    connection: &Connection,
    read_crypto: &cipher::RuntimeReadCryptoCapability,
    database_id: [u8; 16],
    conversation_id: RuntimeId,
    through: u64,
    after: Option<u64>,
) -> Result<RuntimeSnapshotEventPage, RuntimeStoreError> {
    read_snapshot_event_page_with_mode(
        connection,
        read_crypto,
        database_id,
        conversation_id,
        through,
        after,
        EventPageReadMode::Regular,
    )
}

pub(in super::super) fn read_oversized_snapshot_event_page(
    connection: &Connection,
    read_crypto: &cipher::RuntimeReadCryptoCapability,
    database_id: [u8; 16],
    conversation_id: RuntimeId,
    through: u64,
    after: Option<u64>,
) -> Result<RuntimeSnapshotEventPage, RuntimeStoreError> {
    read_snapshot_event_page_with_mode(
        connection,
        read_crypto,
        database_id,
        conversation_id,
        through,
        after,
        EventPageReadMode::OversizedSingle,
    )
}

fn read_snapshot_event_page_with_mode(
    connection: &Connection,
    read_crypto: &cipher::RuntimeReadCryptoCapability,
    database_id: [u8; 16],
    conversation_id: RuntimeId,
    through: u64,
    after: Option<u64>,
    mode: EventPageReadMode,
) -> Result<RuntimeSnapshotEventPage, RuntimeStoreError> {
    let first = after
        .map_or(Some(0), |value| value.checked_add(1))
        .ok_or(RuntimeStoreError::BackfillCursorAhead)?;
    let plan = RuntimeBackfillReadPlan {
        pin: RuntimeBackfillPin {
            pin_id: [0; 16],
            target: RuntimeBackfillTarget::Conversation(conversation_id),
            after,
            through,
            expires_at_ms: u64::MAX,
        },
        requested_after: after,
        first,
    };
    let page =
        read_event_backfill_page_with_mode(connection, read_crypto, database_id, &plan, mode)?;
    Ok(RuntimeSnapshotEventPage {
        events: page.events,
        next_after: page.next_after,
        complete: page.complete,
    })
}

#[cfg(test)]
#[allow(dead_code)]
pub(in super::super) fn load_catalog_backfill_page(
    state: &sqlite::RuntimeSqlite,
    pin: &RuntimeBackfillPin,
    requested_after: Option<u64>,
    now_ms: u64,
) -> Result<RuntimeCatalogBackfillPage, RuntimeStoreError> {
    let plan = prepare_backfill_page(state, pin, requested_after, now_ms)?;
    let read_crypto = state.key_bundle.read_only_capability();
    let page =
        read_catalog_backfill_page(&state.connection, &read_crypto, state.database_id, &plan)?;
    validate_backfill_page(state, page.completion(), now_ms)?;
    Ok(page)
}

pub(in super::super) fn read_catalog_backfill_page(
    connection: &Connection,
    read_crypto: &cipher::RuntimeReadCryptoCapability,
    database_id: [u8; 16],
    plan: &RuntimeBackfillReadPlan,
) -> Result<RuntimeCatalogBackfillPage, RuntimeStoreError> {
    debug_assert_eq!(MAX_RUNTIME_READ_PAGE_ROWS, 64);
    if plan.pin.target != RuntimeBackfillTarget::Catalog {
        return Err(RuntimeStoreError::InvalidBackfillPin);
    }
    let first_value = plan.first;
    let first = sequence::encode_sequence(first_value);
    let through = sequence::encode_sequence(plan.pin.through);
    let mut revisions = Vec::new();
    let mut total_bytes = 0_u64;
    let mut statement = connection.prepare(
        "SELECT catalog_revision, logical_delta_bytes
         FROM catalog_journal
         WHERE catalog_revision BETWEEN ?1 AND ?2
         ORDER BY catalog_revision LIMIT 64",
    )?;
    let rows = statement.query_map(params![&first, &through], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
    })?;
    for row in rows {
        let (revision, logical_bytes) = row?;
        let logical_bytes =
            u64::try_from(logical_bytes).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
        if logical_bytes > u64::from(MAX_RUNTIME_READ_PAGE_BYTES) {
            return Err(RuntimeStoreError::BackfillNeedSnapshot);
        }
        if !revisions.is_empty()
            && total_bytes
                .checked_add(logical_bytes)
                .ok_or(RuntimeStoreError::PayloadTooLarge)?
                > u64::from(MAX_RUNTIME_READ_PAGE_BYTES)
        {
            break;
        }
        total_bytes = total_bytes
            .checked_add(logical_bytes)
            .ok_or(RuntimeStoreError::PayloadTooLarge)?;
        revisions.push(revision);
    }
    drop(statement);
    if revisions.is_empty() {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let mut deltas = Vec::new();
    deltas
        .try_reserve_exact(revisions.len())
        .map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
    let mut expected = first_value;
    for revision in revisions {
        let actual = decode_sequence(SequenceScope::CatalogRevision, &revision)?;
        if actual != expected {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        deltas.push(catalog::load_delta(
            connection,
            read_crypto,
            database_id,
            &revision,
        )?);
        expected = expected
            .checked_add(1)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    }
    let next_after = expected
        .checked_sub(1)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let complete = next_after == plan.pin.through;
    Ok(RuntimeCatalogBackfillPage {
        deltas,
        next_after,
        through: plan.pin.through,
        complete,
        completion: RuntimeBackfillPageCompletion {
            plan: plan.clone(),
            next_after,
            complete,
        },
        memory_lease: None,
    })
}

pub(in super::super) fn validate_backfill_page(
    state: &sqlite::RuntimeSqlite,
    completion: &RuntimeBackfillPageCompletion,
    now_ms: u64,
) -> Result<(), RuntimeStoreError> {
    // writer/GC 可在 read transaction 期间 revoke pin；必须在把 page 交给调用方前
    // 重新验证。revoked page 直接丢弃并要求 snapshot，绝不把过期 range 冒充 live。
    let plan = &completion.plan;
    validate_active_pin(state, &plan.pin, plan.requested_after, now_ms)?;
    if completion.next_after < plan.first || completion.next_after > plan.pin.through {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    if completion.complete != (completion.next_after == plan.pin.through) {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(())
}

pub(in super::super) fn complete_backfill_page(
    state: &sqlite::RuntimeSqlite,
    completion: &RuntimeBackfillPageCompletion,
    now_ms: u64,
) -> Result<(), RuntimeStoreError> {
    validate_backfill_page(state, completion, now_ms)?;
    advance_or_release_pin(
        state,
        &completion.plan.pin,
        completion.next_after,
        completion.complete,
    )
}

pub(in super::super) fn release_backfill_pin(
    state: &sqlite::RuntimeSqlite,
    pin_id: [u8; 16],
) -> Result<(), RuntimeStoreError> {
    state.connection.execute(
        "DELETE FROM temp.active_stream_pins WHERE pin_id = ?1",
        [&pin_id[..]],
    )?;
    Ok(())
}

fn validate_active_pin(
    state: &sqlite::RuntimeSqlite,
    pin: &RuntimeBackfillPin,
    requested_after: Option<u64>,
    now_ms: u64,
) -> Result<(), RuntimeStoreError> {
    let raw = state
        .connection
        .query_row(
            "SELECT scope, target_id, through_seq, next_after_seq, expires_at_ms, state
             FROM temp.active_stream_pins WHERE pin_id = ?1",
            [&pin.pin_id[..]],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<Vec<u8>>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, String>(5)?,
                ))
            },
        )
        .optional()?
        .ok_or(RuntimeStoreError::InvalidBackfillPin)?;
    let expected_target: (&str, Option<[u8; 16]>) = match pin.target {
        RuntimeBackfillTarget::Catalog => ("catalog", None),
        RuntimeBackfillTarget::Conversation(conversation_id) => {
            ("event", Some(*conversation_id.as_bytes()))
        }
    };
    let stored_after = raw
        .3
        .as_deref()
        .map(|value| decode_sequence(sequence_scope(pin.target), value))
        .transpose()?;
    let stored_expiry =
        u64::try_from(raw.4).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    if raw.5 == "revoked" {
        return Err(RuntimeStoreError::BackfillNeedSnapshot);
    }
    if raw.5 != "active"
        || raw.0 != expected_target.0
        || raw.1.as_deref() != expected_target.1.as_ref().map(<[u8; 16]>::as_slice)
        || decode_sequence(sequence_scope(pin.target), &raw.2)? != pin.through
        || stored_expiry != pin.expires_at_ms
        || requested_after != stored_after
    {
        return Err(RuntimeStoreError::InvalidBackfillPin);
    }
    super::validate_pin_clock_lower_bound(now_ms, stored_expiry)?;
    if now_ms >= stored_expiry {
        state.connection.execute(
            "DELETE FROM temp.active_stream_pins WHERE pin_id = ?1",
            [&pin.pin_id[..]],
        )?;
        return Err(RuntimeStoreError::InvalidBackfillPin);
    }
    Ok(())
}

fn advance_or_release_pin(
    state: &sqlite::RuntimeSqlite,
    pin: &RuntimeBackfillPin,
    next_after: u64,
    complete: bool,
) -> Result<(), RuntimeStoreError> {
    let changed = if complete {
        state.connection.execute(
            "DELETE FROM temp.active_stream_pins WHERE pin_id = ?1 AND state = 'active'",
            [&pin.pin_id[..]],
        )?
    } else {
        state.connection.execute(
            "UPDATE temp.active_stream_pins SET next_after_seq = ?1
             WHERE pin_id = ?2 AND state = 'active'",
            params![sequence::encode_sequence(next_after), &pin.pin_id[..]],
        )?
    };
    if changed != 1 {
        return Err(RuntimeStoreError::InvalidBackfillPin);
    }
    Ok(())
}

const fn sequence_scope(target: RuntimeBackfillTarget) -> SequenceScope {
    match target {
        RuntimeBackfillTarget::Catalog => SequenceScope::CatalogRevision,
        RuntimeBackfillTarget::Conversation(_) => SequenceScope::EventSeq,
    }
}
