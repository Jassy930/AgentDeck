//! 已排序 frozen baseline 的 page 切片与 DTO 构造。

use agentdeck_protocol::runtime::catalog::{CatalogSnapshot, MAX_CATALOG_PAGE_ROWS};
use agentdeck_protocol::runtime::{ConversationEntry, StreamCursor};

use super::CatalogSnapshotProviderError;
use super::cache::actual_page_retained_bound;
use super::cursor::{CursorClaims, CursorMacKey, encode_cursor};
use crate::runtime::store::{ReadySnapshotReference, StoredCatalogSnapshot};

pub(super) fn construct_page(
    cursor_key: &CursorMacKey,
    reference: &ReadySnapshotReference,
    selected: &[ConversationEntry],
    has_more: bool,
    issued_at_ms: u64,
    expires_at_ms: u64,
    binding: [u8; 32],
) -> Result<(CatalogSnapshot, Vec<u8>, usize), CatalogSnapshotProviderError> {
    let page_entries = selected.to_vec();
    let next_page_cursor = if has_more {
        let next_key = page_entries
            .last()
            .ok_or(CatalogSnapshotProviderError::InvalidCursor)?
            .conversation_id
            .as_str()
            .to_owned();
        Some(encode_cursor(
            cursor_key,
            &CursorClaims {
                snapshot: reference.clone(),
                next_key,
                issued_at_ms,
                expires_at_ms,
                principal_binding: binding,
            },
        )?)
    } else {
        None
    };
    let cursor_bytes = next_page_cursor
        .as_ref()
        .map_or(0, |value| value.as_str().len());
    let snapshot = CatalogSnapshot::new(reference.base, page_entries, next_page_cursor)?;
    let payload =
        serde_json::to_vec(&snapshot).map_err(|_| CatalogSnapshotProviderError::InvalidCursor)?;
    let page_bytes =
        actual_page_retained_bound(snapshot.entries(), payload.capacity(), cursor_bytes)?;
    Ok((snapshot, payload, page_bytes))
}

pub(super) fn page_range(
    entries: &[ConversationEntry],
    after: Option<&str>,
) -> Result<(usize, usize), CatalogSnapshotProviderError> {
    let start = match after {
        None => 0,
        Some(after) => entries
            .binary_search_by(|entry| entry.conversation_id.as_str().cmp(after))
            .map_err(|_| CatalogSnapshotProviderError::InvalidCursor)?
            .checked_add(1)
            .ok_or(CatalogSnapshotProviderError::InvalidCursor)?,
    };
    let end = start
        .saturating_add(MAX_CATALOG_PAGE_ROWS)
        .min(entries.len());
    Ok((start, end))
}

pub(super) fn validate_stored(
    stored: &StoredCatalogSnapshot,
    reference: &ReadySnapshotReference,
) -> Result<(), CatalogSnapshotProviderError> {
    if stored.snapshot_id != reference.snapshot_id
        || StreamCursor::from_high_water(stored.base_catalog_revision) != reference.base
        || stored.item_count != reference.item_count
        || stored.content_sha256 != reference.content_sha256
    {
        return Err(CatalogSnapshotProviderError::InvalidCursor);
    }
    Ok(())
}
