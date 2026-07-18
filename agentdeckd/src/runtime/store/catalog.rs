//! Runtime v4 authenticated catalog delta journal。

use std::path::PathBuf;

use agentdeck_protocol::AgentKind;
use agentdeck_protocol::runtime::identity::ConversationId;
use agentdeck_protocol::runtime::{CatalogChange, CatalogDelta, ConversationEntry};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};

use crate::runtime::model::{ConversationLifecycle, RuntimeStoreError};

use super::cipher::{ROW_BLOB_V1_OVERHEAD_LEN, RuntimeKeyBundle};
use super::identity::{RuntimeId, RuntimeIdKind};
use super::sequence::{SequenceScope, decode_sequence, encode_sequence};
use super::sqlite::RuntimeLedger;
use super::stream::{
    metadata_mac, open_v4_row, open_v4_row_read, seal_v4_row, sqlite_u64, verify_metadata_mac,
};

pub(crate) const MAX_CATALOG_DELTAS: u64 = 10_000;
pub(crate) const MAX_CATALOG_DELTA_BYTES: u64 = 64 * 1024 * 1024;
const MAX_CATALOG_DELTA_ITEM_BYTES: usize = 64 * 1024 * 1024;
const CATALOG_TOKEN_DOMAIN: &[u8] = b"catalog.journal.v1";

/// Runtime DB v4 中由 Runtime v1 写入的 catalog entry。它只用于认证后的
/// daemon-private payload 兼容读取；旧 adapter handle 在转换时丢弃，绝不重新进入 v2 wire。
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct LegacyConversationEntryV4 {
    pub(super) conversation_id: ConversationId,
    pub(super) adapter_state_key: String,
    pub(super) agent_kind: AgentKind,
    #[serde(default)]
    pub(super) title: Option<String>,
    #[serde(default)]
    pub(super) cwd: Option<PathBuf>,
    pub(super) last_active_ms: u64,
    pub(super) archived: bool,
}

impl LegacyConversationEntryV4 {
    pub(super) fn into_current(self) -> ConversationEntry {
        let Self {
            conversation_id,
            adapter_state_key,
            agent_kind,
            title,
            cwd,
            last_active_ms,
            archived,
        } = self;
        drop(adapter_state_key);
        ConversationEntry {
            conversation_id,
            agent_kind,
            title,
            cwd,
            last_active_ms,
            archived,
            // P3.9-C0-A1 只迁移 wire 形态；真实 metadata revision 由 v5 migration 建立。
            entry_revision: 0,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LegacyCatalogDeltaV4 {
    catalog_revision: u64,
    changes: Vec<LegacyCatalogChangeV4>,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
enum LegacyCatalogChangeV4 {
    Upserted { entry: LegacyConversationEntryV4 },
    Removed { conversation_id: ConversationId },
}

impl LegacyCatalogDeltaV4 {
    fn into_current(self) -> CatalogDelta {
        CatalogDelta {
            catalog_revision: self.catalog_revision,
            changes: self
                .changes
                .into_iter()
                .map(|change| match change {
                    LegacyCatalogChangeV4::Upserted { entry } => CatalogChange::Upserted {
                        entry: entry.into_current(),
                    },
                    LegacyCatalogChangeV4::Removed { conversation_id } => {
                        CatalogChange::Removed { conversation_id }
                    }
                })
                .collect(),
        }
    }
}

fn decode_persisted_catalog_delta(
    payload: &[u8],
) -> Result<(CatalogDelta, bool), RuntimeStoreError> {
    if let Ok(delta) = serde_json::from_slice::<CatalogDelta>(payload) {
        return Ok((delta, false));
    }
    let legacy = serde_json::from_slice::<LegacyCatalogDeltaV4>(payload)
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    Ok((legacy.into_current(), true))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct AuthenticatedCatalogDeltaRange {
    pub(super) count: u64,
    pub(super) logical_bytes: u64,
}

/// 只读取并认证 refresh 所需区间的 delta metadata，不 materialize sealed/plaintext
/// payload。威胁场景：旧 catalog cursor cache 已占住 build budget 时，若先打开完整
/// snapshot/delta 再决定 overload，会让两个合法请求把瞬时 retained memory 推过全局
/// 128 MiB 上界。
pub(super) fn summarize_authenticated_delta_range(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    first: u64,
    through: u64,
) -> Result<AuthenticatedCatalogDeltaRange, RuntimeStoreError> {
    let expected_count = through
        .checked_sub(first)
        .and_then(|count| count.checked_add(1))
        .ok_or(RuntimeStoreError::InvalidStateTransition)?;
    if expected_count > MAX_CATALOG_DELTAS {
        return Err(RuntimeStoreError::BackfillNeedSnapshot);
    }
    let first_encoded = encode_sequence(first);
    let through_encoded = encode_sequence(through);
    let mut statement = connection.prepare(
        "SELECT catalog_revision, conversation_id, change_kind, logical_delta_bytes,
                created_at_ms, metadata_token, length(sealed_delta)
         FROM catalog_journal
         WHERE catalog_revision >= ?1 AND catalog_revision <= ?2
         ORDER BY catalog_revision",
    )?;
    let rows = statement.query_map(params![first_encoded, through_encoded], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, Vec<u8>>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, i64>(4)?,
            row.get::<_, Vec<u8>>(5)?,
            row.get::<_, i64>(6)?,
        ))
    })?;
    let mut count = 0_u64;
    let mut logical_bytes = 0_u64;
    for row in rows {
        let (revision, conversation_id, change_kind, row_bytes, created_at_ms, token, blob_len) =
            row?;
        let expected_revision = first
            .checked_add(count)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        if decode_sequence(SequenceScope::CatalogRevision, &revision)? != expected_revision
            || !matches!(change_kind.as_str(), "upserted" | "removed")
        {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        runtime_conversation_id(&conversation_id)?;
        let row_bytes =
            u64::try_from(row_bytes).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
        let created_at_ms =
            u64::try_from(created_at_ms).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
        if row_bytes == 0 || row_bytes > MAX_CATALOG_DELTA_ITEM_BYTES as u64 {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        let expected_blob_len = usize::try_from(row_bytes)
            .ok()
            .and_then(|bytes| bytes.checked_add(ROW_BLOB_V1_OVERHEAD_LEN))
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        if usize::try_from(blob_len).ok() != Some(expected_blob_len) {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        let expected_token = catalog_token(
            key_bundle,
            &revision,
            &conversation_id,
            change_kind.as_bytes(),
            row_bytes,
            created_at_ms,
        )?;
        if token.as_slice() != expected_token {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        count = count
            .checked_add(1)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        logical_bytes = logical_bytes
            .checked_add(row_bytes)
            .ok_or(RuntimeStoreError::PayloadTooLarge)?;
    }
    if count != expected_count {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(AuthenticatedCatalogDeltaRange {
        count,
        logical_bytes,
    })
}

/// `runtime_meta.catalog_high_water` 的推进与 delta 冻结共享同一 transaction。
/// v1/v2/v3 migration 的 high-water 不推进，因此不会伪造历史 delta。
pub(super) fn reconcile_catalog_journal(
    transaction: &Transaction<'_>,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    previous: &RuntimeLedger,
    requested: &RuntimeLedger,
    mutation_now_ms: Option<u64>,
) -> Result<RuntimeLedger, RuntimeStoreError> {
    if requested.catalog_high_water == previous.catalog_high_water {
        return Ok(requested.clone());
    }
    let requested_high_water = requested
        .catalog_high_water
        .as_deref()
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let requested_high_water_value =
        decode_sequence(SequenceScope::CatalogRevision, requested_high_water)?;
    let previous_value = previous
        .catalog_high_water
        .as_deref()
        .map(|value| decode_sequence(SequenceScope::CatalogRevision, value))
        .transpose()?;
    let expected_first = previous_value
        .map_or(Some(0), |value| value.checked_add(1))
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;

    let mut rows = Vec::new();
    let mut statement = transaction.prepare(
        "SELECT conversation_id, catalog_revision
         FROM conversations
         WHERE (?1 IS NULL OR catalog_revision > ?1) AND catalog_revision <= ?2
         ORDER BY catalog_revision",
    )?;
    let mapped = statement.query_map(
        params![previous.catalog_high_water.as_deref(), requested_high_water],
        |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?)),
    )?;
    for row in mapped {
        rows.push(row?);
        if rows.len() > 1_024 {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
    }
    drop(statement);

    let expected_count = requested_high_water_value
        .checked_sub(expected_first)
        .and_then(|value| value.checked_add(1))
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    if u64::try_from(rows.len()).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
        != expected_count
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }

    let mut trim_now_ms = 0_u64;
    for (offset, (conversation_id, revision)) in rows.into_iter().enumerate() {
        let revision_value = decode_sequence(SequenceScope::CatalogRevision, &revision)?;
        if revision_value
            != expected_first
                .checked_add(
                    u64::try_from(offset).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
                )
                .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?
        {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        let conversation_id = runtime_conversation_id(&conversation_id)?;
        let conversation = super::journal::load_conversation(
            transaction,
            key_bundle,
            database_id,
            conversation_id,
        )?;
        if conversation.catalog_revision != revision_value {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        let delta_created_at_ms = mutation_now_ms.unwrap_or(conversation.updated_at_ms);
        trim_now_ms = trim_now_ms.max(delta_created_at_ms);
        let entry_revision = super::configuration::load_conversation_state(
            transaction,
            key_bundle,
            conversation_id,
        )?
        .entry_revision()?;
        let delta = CatalogDelta {
            catalog_revision: revision_value,
            changes: vec![CatalogChange::Upserted {
                entry: ConversationEntry {
                    conversation_id: ConversationId::new(
                        conversation.conversation_id.to_canonical_string(),
                    ),
                    agent_kind: conversation.descriptor.agent_kind,
                    title: conversation.descriptor.title.clone(),
                    cwd: Some(conversation.descriptor.cwd.clone()),
                    last_active_ms: conversation.updated_at_ms,
                    archived: conversation.lifecycle == ConversationLifecycle::Archived,
                    entry_revision,
                },
            }],
        };
        let plaintext =
            serde_json::to_vec(&delta).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
        if plaintext.is_empty() || plaintext.len() > MAX_CATALOG_DELTA_ITEM_BYTES {
            return Err(RuntimeStoreError::PayloadTooLarge);
        }
        let logical_bytes =
            u64::try_from(plaintext.len()).map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
        let sealed = seal_v4_row(
            key_bundle,
            database_id,
            b"catalog_journal",
            revision.as_bytes(),
            b"sealed_delta",
            &plaintext,
            MAX_CATALOG_DELTA_ITEM_BYTES,
        )?;
        let token = catalog_token(
            key_bundle,
            &revision,
            conversation_id.as_bytes(),
            b"upserted",
            logical_bytes,
            delta_created_at_ms,
        )?;
        transaction.execute(
            "INSERT INTO catalog_journal (
                 catalog_revision, conversation_id, change_kind, logical_delta_bytes,
                 created_at_ms, metadata_token, sealed_delta
             ) VALUES (?1, ?2, 'upserted', ?3, ?4, ?5, ?6)",
            params![
                &revision,
                &conversation_id.as_bytes()[..],
                sqlite_u64(logical_bytes)?,
                sqlite_u64(delta_created_at_ms)?,
                &token[..],
                sealed,
            ],
        )?;
    }

    let mut floor = previous.catalog_retention_floor.clone();
    trim_catalog_window(transaction, key_bundle, &mut floor, trim_now_ms)?;
    let (count, bytes): (i64, i64) = transaction.query_row(
        "SELECT COUNT(*), COALESCE(SUM(logical_delta_bytes), 0) FROM catalog_journal",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let mut next = requested.clone();
    next.catalog_delta_count =
        u64::try_from(count).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    next.catalog_delta_bytes =
        u64::try_from(bytes).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    next.catalog_retention_floor = floor;
    Ok(next)
}

fn trim_catalog_window(
    transaction: &Transaction<'_>,
    key_bundle: &RuntimeKeyBundle,
    floor: &mut Option<String>,
    now_ms: u64,
) -> Result<(), RuntimeStoreError> {
    trim_catalog_window_with_limits(
        transaction,
        key_bundle,
        floor,
        now_ms,
        MAX_CATALOG_DELTAS,
        MAX_CATALOG_DELTA_BYTES,
    )
}

fn trim_catalog_window_with_limits(
    transaction: &Transaction<'_>,
    key_bundle: &RuntimeKeyBundle,
    floor: &mut Option<String>,
    now_ms: u64,
    max_deltas: u64,
    max_bytes: u64,
) -> Result<(), RuntimeStoreError> {
    loop {
        let (count, bytes): (i64, i64) = transaction.query_row(
            "SELECT COUNT(*), COALESCE(SUM(logical_delta_bytes), 0) FROM catalog_journal",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let count = u64::try_from(count).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
        let bytes = u64::try_from(bytes).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
        if count <= max_deltas && bytes <= max_bytes {
            break;
        }
        let victim: String = transaction
            .query_row(
                "SELECT catalog_revision FROM catalog_journal
                 ORDER BY catalog_revision LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()?
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        super::retention::authorize_trim(
            transaction,
            key_bundle,
            super::retention::RetentionTarget::Catalog,
            &victim,
            now_ms,
        )?;
        if transaction.execute(
            "DELETE FROM catalog_journal WHERE catalog_revision = ?1",
            [&victim],
        )? != 1
        {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
    }
    *floor = transaction.query_row(
        "SELECT MIN(catalog_revision) FROM catalog_journal",
        [],
        |row| row.get(0),
    )?;
    Ok(())
}

pub(super) fn validate_integrity(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    ledger: &RuntimeLedger,
) -> Result<(), RuntimeStoreError> {
    let mut expected_revision = ledger
        .catalog_retention_floor
        .as_deref()
        .map(|value| decode_sequence(SequenceScope::CatalogRevision, value))
        .transpose()?;
    let mut count = 0_u64;
    let mut bytes = 0_u64;
    let mut first = None;
    let mut last = None;
    let mut statement = connection.prepare(
        "SELECT catalog_revision, conversation_id, change_kind, logical_delta_bytes,
                created_at_ms, metadata_token, sealed_delta
         FROM catalog_journal ORDER BY catalog_revision",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, Vec<u8>>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, i64>(4)?,
            row.get::<_, Vec<u8>>(5)?,
            row.get::<_, Vec<u8>>(6)?,
        ))
    })?;
    for row in rows {
        let (revision, conversation_id, change_kind, logical_bytes, created_at, token, sealed) =
            row?;
        let revision_value = decode_sequence(SequenceScope::CatalogRevision, &revision)?;
        if Some(revision_value) != expected_revision {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        expected_revision = revision_value.checked_add(1);
        if first.is_none() {
            first = Some(revision.clone());
        }
        let logical_bytes =
            u64::try_from(logical_bytes).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
        let created_at =
            u64::try_from(created_at).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
        let expected = catalog_token(
            key_bundle,
            &revision,
            &conversation_id,
            change_kind.as_bytes(),
            logical_bytes,
            created_at,
        )?;
        if token.as_slice() != expected {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        let plaintext = open_v4_row(
            key_bundle,
            database_id,
            b"catalog_journal",
            revision.as_bytes(),
            b"sealed_delta",
            &sealed,
            MAX_CATALOG_DELTA_ITEM_BYTES,
        )?;
        if plaintext.expose_secret().len()
            != usize::try_from(logical_bytes)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
        {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        let (delta, _) = decode_persisted_catalog_delta(plaintext.expose_secret())?;
        if delta.catalog_revision != revision_value || delta.changes.len() != 1 {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        let encoded_id = runtime_conversation_id(&conversation_id)?.to_canonical_string();
        let matches = match &delta.changes[0] {
            CatalogChange::Upserted { entry } => {
                change_kind == "upserted" && entry.conversation_id.as_str() == encoded_id
            }
            CatalogChange::Removed { conversation_id } => {
                change_kind == "removed" && conversation_id.as_str() == encoded_id
            }
        };
        if !matches {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        count = count
            .checked_add(1)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        bytes = bytes
            .checked_add(logical_bytes)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        last = Some(revision);
    }
    if count != ledger.catalog_delta_count || bytes != ledger.catalog_delta_bytes {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    if count == 0 {
        if ledger.catalog_retention_floor.is_some() || first.is_some() || last.is_some() {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
    } else if ledger.catalog_retention_floor.as_ref() != first.as_ref()
        || ledger.catalog_high_water.as_ref() != last.as_ref()
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(())
}

pub(super) fn load_delta(
    connection: &Connection,
    read_crypto: &super::cipher::RuntimeReadCryptoCapability,
    database_id: [u8; 16],
    revision: &str,
) -> Result<CatalogDelta, RuntimeStoreError> {
    load_delta_with_created_at(connection, read_crypto, database_id, revision)
        .map(|(delta, _)| delta)
}

pub(super) fn load_delta_with_created_at(
    connection: &Connection,
    read_crypto: &super::cipher::RuntimeReadCryptoCapability,
    database_id: [u8; 16],
    revision: &str,
) -> Result<(CatalogDelta, u64), RuntimeStoreError> {
    let raw = connection
        .query_row(
            "SELECT conversation_id, change_kind, logical_delta_bytes, created_at_ms,
                    metadata_token, sealed_delta
             FROM catalog_journal WHERE catalog_revision = ?1",
            [revision],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                ))
            },
        )
        .map_err(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => RuntimeStoreError::UnknownOrCorruptSchema,
            other => RuntimeStoreError::Sqlite(other),
        })?;
    let logical_bytes =
        u64::try_from(raw.2).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let created_at_ms =
        u64::try_from(raw.3).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    if !verify_metadata_mac(
        read_crypto,
        CATALOG_TOKEN_DOMAIN,
        &[
            revision.as_bytes(),
            &raw.0,
            raw.1.as_bytes(),
            &logical_bytes.to_be_bytes(),
            &created_at_ms.to_be_bytes(),
        ],
        &raw.4,
    )? {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let plaintext = open_v4_row_read(
        read_crypto,
        database_id,
        b"catalog_journal",
        revision.as_bytes(),
        b"sealed_delta",
        &raw.5,
        MAX_CATALOG_DELTA_ITEM_BYTES,
    )?;
    if plaintext.expose_secret().len()
        != usize::try_from(logical_bytes).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let (delta, _) = decode_persisted_catalog_delta(plaintext.expose_secret())?;
    let revision_value = decode_sequence(SequenceScope::CatalogRevision, revision)?;
    if delta.catalog_revision != revision_value || delta.changes.len() != 1 {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let encoded_id = runtime_conversation_id(&raw.0)?.to_canonical_string();
    let matches = match &delta.changes[0] {
        CatalogChange::Upserted { entry } => {
            raw.1 == "upserted" && entry.conversation_id.as_str() == encoded_id
        }
        CatalogChange::Removed { conversation_id } => {
            raw.1 == "removed" && conversation_id.as_str() == encoded_id
        }
    };
    if !matches {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok((delta, created_at_ms))
}

fn catalog_token(
    key_bundle: &RuntimeKeyBundle,
    revision: &str,
    conversation_id: &[u8],
    change_kind: &[u8],
    logical_bytes: u64,
    created_at_ms: u64,
) -> Result<[u8; 32], RuntimeStoreError> {
    metadata_mac(
        key_bundle,
        CATALOG_TOKEN_DOMAIN,
        &[
            revision.as_bytes(),
            conversation_id,
            change_kind,
            &logical_bytes.to_be_bytes(),
            &created_at_ms.to_be_bytes(),
        ],
    )
}

fn runtime_conversation_id(bytes: &[u8]) -> Result<RuntimeId, RuntimeStoreError> {
    let bytes: [u8; 16] = bytes
        .try_into()
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    Ok(RuntimeId::from_bytes(RuntimeIdKind::Conversation, bytes)?)
}

#[allow(dead_code)]
fn canonical_floor(value: u64) -> String {
    encode_sequence(value)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use agentdeck_protocol::AgentKind;
    use rusqlite::{TransactionBehavior, params};

    use super::*;
    use crate::runtime::model::{ConversationDescriptor, NewConversation, RuntimeStoreConfig};
    use crate::runtime::store::identity::{RuntimeId, RuntimeIdKind};
    use crate::security::{MemoryKeyStore, load_or_create_storage_kek};

    static NEXT_ROOT: AtomicU64 = AtomicU64::new(1);

    #[test]
    fn legacy_runtime_v1_catalog_delta_dual_decodes_without_rewrite() {
        // 威胁场景：DB schema 仍是 v4、但 sealed catalog payload 来自 Runtime v1；
        // 新 daemon 必须丢弃 private handle 并返回 v2 entry，不能改写原 ciphertext。
        let legacy = LegacyCatalogDeltaV4 {
            catalog_revision: 7,
            changes: vec![LegacyCatalogChangeV4::Upserted {
                entry: LegacyConversationEntryV4 {
                    conversation_id: ConversationId::new("conversation-legacy"),
                    adapter_state_key: "adapter-private".into(),
                    agent_kind: AgentKind::Codex,
                    title: Some("legacy title".into()),
                    cwd: Some(PathBuf::from("/tmp/legacy")),
                    last_active_ms: 9,
                    archived: false,
                },
            }],
        };
        let payload = serde_json::to_vec(&legacy).expect("encode canonical v1 catalog delta");
        let (decoded, was_legacy) =
            decode_persisted_catalog_delta(&payload).expect("dual decode v1 catalog delta");
        assert!(was_legacy);
        let [CatalogChange::Upserted { entry }] = decoded.changes.as_slice() else {
            panic!("legacy upsert must remain one upsert")
        };
        assert_eq!(entry.entry_revision, 0);
        assert!(
            !serde_json::to_string(&decoded)
                .unwrap()
                .contains("adapterStateKey")
        );
    }

    #[test]
    fn catalog_gc_preserves_pin_and_rows_without_durable_replacement() {
        let root = std::env::temp_dir().join(format!(
            "agentdeck-catalog-pin-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).expect("create catalog pin root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
                .expect("secure catalog pin root");
        }
        let config = RuntimeStoreConfig::new(root.join("runtime.db"));
        let keys = MemoryKeyStore::new();
        let kek =
            load_or_create_storage_kek(&keys, &root.join("key-state.db")).expect("create test KEK");
        let mut state = super::super::sqlite::open(&config, kek).expect("open test store");
        for seed in [0x21_u8, 0x22] {
            let input = NewConversation {
                conversation_id: RuntimeId::from_bytes(RuntimeIdKind::Conversation, [seed; 16])
                    .expect("conversation id"),
                adapter_state_key: RuntimeId::from_bytes(
                    RuntimeIdKind::AdapterState,
                    [seed.wrapping_add(0x40); 16],
                )
                .expect("adapter id"),
                descriptor: ConversationDescriptor {
                    agent_kind: AgentKind::Codex,
                    title: Some(format!("catalog-{seed}")),
                    cwd: PathBuf::from("/tmp/catalog-pin"),
                },
            };
            let descriptor =
                super::super::journal::canonical_conversation_descriptor(&input.descriptor)
                    .expect("canonical descriptor");
            let mut effects = crate::runtime::events::CommandStreamEffects::default();
            super::super::journal::create_conversation(
                &mut state,
                &config,
                input,
                descriptor,
                &mut effects,
            )
            .expect("create catalog row");
        }
        let initial_ledger = super::super::sqlite::load_runtime_ledger(
            &state.connection,
            state.key_bundle.as_ref(),
            state.database_id,
        )
        .expect("load first-delta catalog ledger");
        assert_eq!(
            initial_ledger.catalog_retention_floor,
            Some(encode_sequence(0)),
            "the first retained catalog delta establishes oldest-retained revision zero"
        );
        let pin_id = [0x61; 16];
        state
            .connection
            .execute(
                "INSERT INTO temp.active_stream_pins (
                     pin_id, scope, target_id, first_seq, through_seq,
                     next_after_seq, expires_at_ms, state
                 ) VALUES (?1, 'catalog', NULL, ?2, ?3, NULL, 999999, 'active')",
                params![&pin_id[..], encode_sequence(0), encode_sequence(1)],
            )
            .expect("insert catalog pin");
        let transaction = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("catalog GC transaction");
        let mut floor = None;
        assert!(matches!(
            trim_catalog_window_with_limits(
                &transaction,
                state.key_bundle.as_ref(),
                &mut floor,
                10,
                1,
                MAX_CATALOG_DELTA_BYTES,
            ),
            Err(RuntimeStoreError::WorkerBusy {
                lane: crate::runtime::model::RuntimeStoreLane::Normal,
            })
        ));
        drop(transaction);
        assert_eq!(floor, None);
        let state_text: String = state
            .connection
            .query_row(
                "SELECT state FROM temp.active_stream_pins WHERE pin_id = ?1",
                [&pin_id[..]],
                |row| row.get(0),
            )
            .expect("active pin");
        assert_eq!(state_text, "active");
        let revisions: Vec<String> = state
            .connection
            .prepare("SELECT catalog_revision FROM catalog_journal ORDER BY catalog_revision")
            .expect("prepare retained catalog rows")
            .query_map([], |row| row.get(0))
            .expect("query retained catalog rows")
            .collect::<Result<_, _>>()
            .expect("collect retained catalog rows");
        assert_eq!(revisions, [encode_sequence(0), encode_sequence(1)]);

        state
            .connection
            .execute(
                "DELETE FROM temp.active_stream_pins WHERE pin_id = ?1",
                [&pin_id[..]],
            )
            .expect("release catalog pin");

        let publication_stream_id = [0x71; 16];
        let publication_generation = [0x72; 16];
        super::super::publication::create_publication_stream(
            &mut state,
            &config,
            publication_stream_id,
            super::super::publication::PublicationScope::Catalog,
            [0x73; 16],
            publication_generation,
            10,
        )
        .expect("create still-unfrozen catalog publication stream");

        let transaction = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("uncovered catalog GC transaction");
        assert!(matches!(
            trim_catalog_window_with_limits(
                &transaction,
                state.key_bundle.as_ref(),
                &mut floor,
                10,
                1,
                MAX_CATALOG_DELTA_BYTES,
            ),
            Err(RuntimeStoreError::PublicationNeedsSnapshot)
        ));
        drop(transaction);
        let retained_count: i64 = state
            .connection
            .query_row("SELECT COUNT(*) FROM catalog_journal", [], |row| row.get(0))
            .expect("count catalog rows after rejected trim");
        assert_eq!(retained_count, 2);

        super::super::publication::freeze_publication(
            &mut state,
            &config,
            super::super::publication::FreezePublicationRequest {
                publication_id: [0x74; 16],
                publication_stream_id,
                generation: publication_generation,
                counter_scope_token: [0x75; 32],
                sender_counter: 1,
                inner_after: None,
                inner_through: Some(0),
                payload_kind: super::super::publication::PublicationPayloadKind::Catalog,
                blob: b"exact-catalog-victim-zero".to_vec(),
            },
            11,
        )
        .expect("freeze exact replacement for catalog victim zero");
        let transaction = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("covered catalog GC transaction");
        assert!(matches!(
            trim_catalog_window_with_limits(
                &transaction,
                state.key_bundle.as_ref(),
                &mut floor,
                11,
                1,
                MAX_CATALOG_DELTA_BYTES,
            ),
            Err(RuntimeStoreError::PublicationNeedsSnapshot)
        ));
        drop(transaction);
        let retained_count: i64 = state
            .connection
            .query_row("SELECT COUNT(*) FROM catalog_journal", [], |row| row.get(0))
            .expect("count catalog rows after outbox-only rejected trim");
        assert_eq!(retained_count, 2);
        drop(state);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn catalog_backfill_accepts_cursor_immediately_before_oldest_retained_revision() {
        let root = std::env::temp_dir().join(format!(
            "agentdeck-catalog-floor-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).expect("create catalog floor root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
                .expect("secure catalog floor root");
        }
        let config = RuntimeStoreConfig::new(root.join("runtime.db"));
        let keys = MemoryKeyStore::new();
        let kek =
            load_or_create_storage_kek(&keys, &root.join("key-state.db")).expect("create test KEK");
        let mut state = super::super::sqlite::open(&config, kek).expect("open test store");
        for seed in 0x30_u8..=0x36 {
            let input = NewConversation {
                conversation_id: RuntimeId::from_bytes(RuntimeIdKind::Conversation, [seed; 16])
                    .expect("conversation id"),
                adapter_state_key: RuntimeId::from_bytes(
                    RuntimeIdKind::AdapterState,
                    [seed.wrapping_add(0x40); 16],
                )
                .expect("adapter id"),
                descriptor: ConversationDescriptor {
                    agent_kind: AgentKind::Codex,
                    title: Some(format!("catalog-floor-{seed}")),
                    cwd: PathBuf::from("/tmp/catalog-floor"),
                },
            };
            let descriptor =
                super::super::journal::canonical_conversation_descriptor(&input.descriptor)
                    .expect("canonical descriptor");
            let mut effects = crate::runtime::events::CommandStreamEffects::default();
            super::super::journal::create_conversation(
                &mut state,
                &config,
                input,
                descriptor,
                &mut effects,
            )
            .expect("create catalog row");
        }

        let publication_stream_id = [0x37; 16];
        let publication_generation = [0x38; 16];
        super::super::publication::create_publication_stream(
            &mut state,
            &config,
            publication_stream_id,
            super::super::publication::PublicationScope::Catalog,
            [0x39; 16],
            publication_generation,
            10,
        )
        .expect("create catalog replacement stream");
        super::super::publication::freeze_publication(
            &mut state,
            &config,
            super::super::publication::FreezePublicationRequest {
                publication_id: [0x3a; 16],
                publication_stream_id,
                generation: publication_generation,
                counter_scope_token: [0x3b; 32],
                sender_counter: 1,
                inner_after: None,
                inner_through: Some(4),
                payload_kind: super::super::publication::PublicationPayloadKind::Catalog,
                blob: b"catalog-retention-boundary-replacement".to_vec(),
            },
            11,
        )
        .expect("freeze replacement for catalog revisions zero through four");

        super::super::snapshot::refresh_catalog_snapshot(
            &mut state,
            &config,
            None,
            agentdeck_protocol::runtime::StreamCursor::At(6),
        )
        .expect("ready catalog snapshot covers revisions zero through six");
        let previous = super::super::sqlite::load_runtime_ledger(
            &state.connection,
            state.key_bundle.as_ref(),
            state.database_id,
        )
        .expect("load catalog ledger before trim");
        assert_eq!(previous.catalog_high_water, Some(encode_sequence(6)));
        let key_bundle = std::sync::Arc::clone(&state.key_bundle);
        let database_id = state.database_id;
        let transaction = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("catalog floor transaction");
        let mut floor = previous.catalog_retention_floor.clone();
        trim_catalog_window_with_limits(
            &transaction,
            key_bundle.as_ref(),
            &mut floor,
            11,
            2,
            MAX_CATALOG_DELTA_BYTES,
        )
        .expect("retain catalog revisions five and six");
        assert_eq!(floor, Some(encode_sequence(5)));
        let (count, bytes): (i64, i64) = transaction
            .query_row(
                "SELECT COUNT(*), COALESCE(SUM(logical_delta_bytes), 0)
                 FROM catalog_journal",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("measure retained catalog window");
        let mut next = previous.clone();
        next.catalog_delta_count = u64::try_from(count).expect("catalog count");
        next.catalog_delta_bytes = u64::try_from(bytes).expect("catalog bytes");
        next.catalog_retention_floor = floor;
        let _pending_targets = super::super::sqlite::update_runtime_ledger(
            &transaction,
            key_bundle.as_ref(),
            database_id,
            &previous,
            &next,
        )
        .expect("authenticate retained catalog floor");
        transaction.commit().expect("commit retained catalog floor");

        let plan = super::super::stream::acquire_backfill_pin(
            &state,
            super::super::stream::RuntimeBackfillTarget::Catalog,
            Some(4),
            100,
        )
        .expect("cursor four can backfill from oldest retained revision five");
        let super::super::stream::RuntimeBackfillPlan::Pinned(pin) = plan else {
            panic!("revisions five and six form a non-empty retained page");
        };
        let page = super::super::stream::load_catalog_backfill_page(&state, &pin, Some(4), 100)
            .expect("load catalog backfill at retention boundary");
        assert!(page.complete);
        assert_eq!(page.next_after, 6);
        assert_eq!(
            page.deltas
                .iter()
                .map(|delta| delta.catalog_revision)
                .collect::<Vec<_>>(),
            [5, 6]
        );
        super::super::stream::complete_backfill_page(&state, page.completion(), 100)
            .expect("ACK retained catalog page");

        drop(state);
        let _ = fs::remove_dir_all(root);
    }
}
