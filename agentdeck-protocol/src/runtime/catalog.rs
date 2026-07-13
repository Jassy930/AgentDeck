//! Runtime v1 会话目录（design §8.1 / §9.1 / §9.5）。
//!
//! common catalog 只保存中立 `adapter_state_key` handle；vendor resume reference
//! 只存在于各 adapter 私有 namespace，**永不进入 catalog bytes 或客户端 wire**。
//! `catalog_revision` 是独立于 `event_seq` 的 canonical revision。

use crate::runtime::identity::{AdapterStateKey, CatalogPageCursor, ConversationId};
use crate::runtime::sync::StreamCursor;
use crate::trunk::AgentKind;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Catalog 每页最多 500 rows（design §9.5）。
pub const MAX_CATALOG_PAGE_ROWS: usize = 500;
/// 冻结 catalog page 的最大 encoded 大小（64 MiB）。
pub const MAX_CATALOG_PAGE_BYTES: usize = 64 * 1024 * 1024;

/// catalog 校验失败。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CatalogError {
    #[error("catalog page exceeds {MAX_CATALOG_PAGE_ROWS} rows")]
    PageTooLarge,
    #[error("catalog page exceeds {MAX_CATALOG_PAGE_BYTES} encoded bytes")]
    EncodedTooLarge,
}

/// 一个会话目录条目（中立业务内容）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConversationEntry {
    pub conversation_id: ConversationId,
    pub adapter_state_key: AdapterStateKey,
    pub agent_kind: AgentKind,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub cwd: Option<PathBuf>,
    /// epoch 毫秒，仅用于排序。
    pub last_active_ms: u64,
    pub archived: bool,
}

/// 分页 catalog snapshot；构造时校验每页 ≤ 500 rows。
#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CatalogSnapshot {
    pub base_catalog_cursor: StreamCursor,
    entries: Vec<ConversationEntry>,
    #[schemars(with = "crate::runtime::schema::RequiredNullable<CatalogPageCursor>")]
    next_page_cursor: Option<CatalogPageCursor>,
}

impl CatalogSnapshot {
    pub fn new(
        base_catalog_cursor: StreamCursor,
        entries: Vec<ConversationEntry>,
        next_page_cursor: Option<CatalogPageCursor>,
    ) -> Result<Self, CatalogError> {
        if entries.len() > MAX_CATALOG_PAGE_ROWS {
            return Err(CatalogError::PageTooLarge);
        }
        let snapshot = Self {
            base_catalog_cursor,
            entries,
            next_page_cursor,
        };
        if serde_json::to_vec(&snapshot)
            .map_err(|_| CatalogError::EncodedTooLarge)?
            .len()
            > MAX_CATALOG_PAGE_BYTES
        {
            return Err(CatalogError::EncodedTooLarge);
        }
        Ok(snapshot)
    }

    pub fn entries(&self) -> &[ConversationEntry] {
        &self.entries
    }

    pub fn next_page_cursor(&self) -> Option<&CatalogPageCursor> {
        self.next_page_cursor.as_ref()
    }
}

impl<'de> Deserialize<'de> for CatalogSnapshot {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire {
            base_catalog_cursor: StreamCursor,
            entries: Vec<ConversationEntry>,
            #[serde(deserialize_with = "deserialize_required_optional_page_cursor")]
            next_page_cursor: Option<CatalogPageCursor>,
        }
        let w = Wire::deserialize(deserializer)?;
        CatalogSnapshot::new(w.base_catalog_cursor, w.entries, w.next_page_cursor)
            .map_err(serde::de::Error::custom)
    }
}

fn deserialize_required_optional_page_cursor<'de, D>(
    deserializer: D,
) -> Result<Option<CatalogPageCursor>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<CatalogPageCursor>::deserialize(deserializer)
}

/// catalog 增量。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CatalogDelta {
    pub catalog_revision: u64,
    pub changes: Vec<CatalogChange>,
}

/// catalog 单条变化。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub enum CatalogChange {
    Upserted { entry: ConversationEntry },
    Removed { conversation_id: ConversationId },
}
