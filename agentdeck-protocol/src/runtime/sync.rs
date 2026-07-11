//! Runtime v1 订阅、cursor、snapshot barrier（design §9.1 / §9.2 / RC-16）。

use crate::capabilities::SessionCapabilities;
use crate::runtime::identity::{ConversationId, ItemId, StreamGeneration};
use crate::trunk::AgentItem;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// 两层 sequence 的外层订阅 cursor（design §9.1）。
///
/// 统一使用 `BeforeFirst | At(u64)`，**绝不把 SQLite `-1` 编进 unsigned wire**：
/// `Subscribe(BeforeFirst)` 表示从 frame 0 开始。wire 表示：
/// `BeforeFirst → "beforeFirst"`，`At(n) → { "at": n }`。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum StreamCursor {
    BeforeFirst,
    At(u64),
}

impl StreamCursor {
    /// 下一帧的 streamSeq：`next(BeforeFirst)=0`、`next(At(n))=n+1`（design §9.1）。
    ///
    /// 注意：streamSeq 接近 `u64::MAX` 时上层必须以新随机 route/generation 建 stream
    /// 并做 signed barrier，禁止整数 wrap；本 helper 只承载正常推进语义。
    pub fn next(&self) -> u64 {
        match self {
            StreamCursor::BeforeFirst => 0,
            StreamCursor::At(n) => n + 1,
        }
    }
}

/// 首次订阅/backfill 完成 barrier（design §9.2）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeSyncComplete {
    pub stream_generation: StreamGeneration,
    pub stream_cursor: StreamCursor,
    pub event_seq: u64,
    pub key_directory_revision: u64,
}

/// snapshot barrier 内的一项：capabilities 或 agent item。
///
/// 未派生 `PartialEq`：内嵌的中立 trunk 类型（`SessionCapabilities`/`AgentItem`）
/// 本身未派生 `PartialEq`，本 task 不改动 trunk；契约测试以 wire round-trip 覆盖。
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub enum SnapshotItem {
    Capabilities { capabilities: SessionCapabilities },
    Item { item_id: ItemId, item: AgentItem },
}

impl SnapshotItem {
    fn is_capabilities(&self) -> bool {
        matches!(self, SnapshotItem::Capabilities { .. })
    }
}

/// snapshot 构造/wire 校验失败（RC-16 能力先行不变量）。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SnapshotError {
    #[error("snapshot must contain SessionCapabilities")]
    CapabilitiesMissing,
    #[error("snapshot must deliver SessionCapabilities before any AgentItem")]
    CapabilitiesNotFirst,
    #[error("snapshot must contain SessionCapabilities exactly once")]
    DuplicateCapabilities,
}

/// 首次订阅 canonical snapshot（design §9.2）。
///
/// RC-16：snapshot 必须先交付 `SessionCapabilities`，再交付任何 `AgentItem`。
/// `new()` 与 wire 反序列化都强制该不变量（空 conversation 也必须先带 capabilities）。
#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConversationSnapshot {
    pub conversation_id: ConversationId,
    pub base_event_seq: u64,
    items: Vec<SnapshotItem>,
}

impl ConversationSnapshot {
    /// 构造并校验 capabilities-before-items 不变量。
    pub fn new(
        conversation_id: ConversationId,
        base_event_seq: u64,
        items: Vec<SnapshotItem>,
    ) -> Result<Self, SnapshotError> {
        Self::validate_items(&items)?;
        Ok(Self {
            conversation_id,
            base_event_seq,
            items,
        })
    }

    pub fn items(&self) -> &[SnapshotItem] {
        &self.items
    }

    fn validate_items(items: &[SnapshotItem]) -> Result<(), SnapshotError> {
        let first = items.first().ok_or(SnapshotError::CapabilitiesMissing)?;
        if !first.is_capabilities() {
            // 缺失还是不在首位：若完全没有 capabilities 报 missing，否则报 not-first。
            if items.iter().any(SnapshotItem::is_capabilities) {
                return Err(SnapshotError::CapabilitiesNotFirst);
            }
            return Err(SnapshotError::CapabilitiesMissing);
        }
        let extra = items.iter().skip(1).filter(|i| i.is_capabilities()).count();
        if extra > 0 {
            return Err(SnapshotError::DuplicateCapabilities);
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for ConversationSnapshot {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire {
            conversation_id: ConversationId,
            base_event_seq: u64,
            items: Vec<SnapshotItem>,
        }
        let w = Wire::deserialize(deserializer)?;
        ConversationSnapshot::new(w.conversation_id, w.base_event_seq, w.items)
            .map_err(serde::de::Error::custom)
    }
}

/// backfill 批次（design §9.4）：daemon journal 有完整区间时定向下发缺失事件。
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BackfillChunk {
    pub conversation_id: ConversationId,
    pub events: Vec<crate::runtime::event::RuntimeEvent>,
}
