//! Runtime v2 订阅、cursor、snapshot barrier 与定向 backfill。

use crate::capabilities::SessionCapabilities;
use crate::runtime::catalog::CatalogDelta;
use crate::runtime::configuration::ConversationConfigurationState;
use crate::runtime::event::RuntimeEvent;
use crate::runtime::identity::{CommandId, ConversationId, EntityId, ItemId, StreamGeneration};
use crate::trunk::AgentItem;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// 单个 backfill reply 最多包含 512 条 canonical entry。
pub const MAX_BACKFILL_ENTRIES: usize = 512;
/// 单个 backfill wire payload 最大 64 MiB。
pub const MAX_BACKFILL_BYTES: usize = 64 * 1024 * 1024;

/// zero-based stream/canonical sequence cursor。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum StreamCursor {
    BeforeFirst,
    At(u64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum StreamCursorError {
    #[error("stream cursor is exhausted")]
    Exhausted,
}

impl StreamCursor {
    /// `BeforeFirst -> 0`、`At(n) -> n+1`；到 `u64::MAX` 时 typed fail，不 wrap。
    pub fn checked_next(self) -> Result<u64, StreamCursorError> {
        match self {
            StreamCursor::BeforeFirst => Ok(0),
            StreamCursor::At(value) => value.checked_add(1).ok_or(StreamCursorError::Exhausted),
        }
    }

    /// 兼容旧调用名；语义改为 checked。
    pub fn next(self) -> Result<u64, StreamCursorError> {
        self.checked_next()
    }

    pub fn from_high_water(value: Option<u64>) -> Self {
        value.map_or(StreamCursor::BeforeFirst, StreamCursor::At)
    }

    pub fn high_water(self) -> Option<u64> {
        match self {
            StreamCursor::BeforeFirst => None,
            StreamCursor::At(value) => Some(value),
        }
    }
}

/// Runtime 内层 canonical cursor；tag 阻止 catalog/event 混用。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "scope", rename_all = "camelCase", deny_unknown_fields)]
pub enum RuntimeInnerCursor {
    Catalog {
        cursor: StreamCursor,
    },
    Conversation {
        #[serde(rename = "conversationId")]
        conversation_id: ConversationId,
        cursor: StreamCursor,
    },
}

/// Unsubscribe 的显式目标；不携带无意义 cursor。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "scope", rename_all = "camelCase", deny_unknown_fields)]
pub enum RuntimeSubscriptionTarget {
    Catalog,
    Conversation {
        #[serde(rename = "conversationId")]
        conversation_id: ConversationId,
    },
}

/// Subscribe/Unsubscribe typed receipt。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "status", rename_all = "camelCase", deny_unknown_fields)]
pub enum SubscriptionReceipt {
    Subscribed {
        #[serde(rename = "streamGeneration")]
        stream_generation: StreamGeneration,
    },
    Unsubscribed,
}

/// 首次订阅/backfill 完成的设备定向 barrier。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeSyncComplete {
    pub stream_generation: StreamGeneration,
    pub stream_cursor: StreamCursor,
    pub inner_cursor: RuntimeInnerCursor,
    pub key_directory_revision: u64,
}

/// snapshot barrier 内的一项。
#[derive(Debug, Clone, JsonSchema)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub enum SnapshotItem {
    Capabilities {
        #[serde(rename = "commandId")]
        command_id: (),
        #[serde(rename = "itemId")]
        item_id: (),
        #[serde(rename = "entityId")]
        entity_id: (),
        capabilities: SessionCapabilities,
    },
    Item {
        #[serde(rename = "itemId")]
        item_id: ItemId,
        #[serde(rename = "entityId")]
        entity_id: EntityId,
        #[serde(
            rename = "commandId",
            deserialize_with = "deserialize_required_optional_command_id"
        )]
        #[schemars(with = "crate::runtime::schema::RequiredNullable<CommandId>")]
        command_id: Option<CommandId>,
        item: AgentItem,
    },
}

impl Serialize for SnapshotItem {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.validate().map_err(serde::ser::Error::custom)?;
        #[derive(Serialize)]
        #[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
        enum Wire<'a> {
            Capabilities {
                #[serde(rename = "commandId")]
                command_id: (),
                #[serde(rename = "itemId")]
                item_id: (),
                #[serde(rename = "entityId")]
                entity_id: (),
                capabilities: &'a SessionCapabilities,
            },
            Item {
                #[serde(rename = "itemId")]
                item_id: &'a ItemId,
                #[serde(rename = "entityId")]
                entity_id: &'a EntityId,
                #[serde(rename = "commandId")]
                command_id: &'a Option<CommandId>,
                item: &'a AgentItem,
            },
        }
        match self {
            Self::Capabilities { capabilities, .. } => Wire::Capabilities {
                command_id: (),
                item_id: (),
                entity_id: (),
                capabilities,
            }
            .serialize(serializer),
            Self::Item {
                item_id,
                entity_id,
                command_id,
                item,
            } => Wire::Item {
                item_id,
                entity_id,
                command_id,
                item,
            }
            .serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for SnapshotItem {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
        enum Wire {
            Capabilities {
                #[serde(rename = "commandId")]
                command_id: (),
                #[serde(rename = "itemId")]
                item_id: (),
                #[serde(rename = "entityId")]
                entity_id: (),
                capabilities: SessionCapabilities,
            },
            Item {
                #[serde(rename = "itemId")]
                item_id: ItemId,
                #[serde(rename = "entityId")]
                entity_id: EntityId,
                #[serde(
                    rename = "commandId",
                    deserialize_with = "deserialize_required_optional_command_id"
                )]
                command_id: Option<CommandId>,
                item: AgentItem,
            },
        }
        match Wire::deserialize(deserializer)? {
            Wire::Capabilities {
                command_id,
                item_id,
                entity_id,
                capabilities,
            } => Ok(Self::Capabilities {
                command_id,
                item_id,
                entity_id,
                capabilities,
            }),
            Wire::Item {
                item_id,
                entity_id,
                command_id,
                item,
            } => {
                let value = Self::Item {
                    item_id,
                    entity_id,
                    command_id,
                    item,
                };
                value.validate().map_err(serde::de::Error::custom)?;
                Ok(value)
            }
        }
    }
}

impl SnapshotItem {
    pub fn capabilities(capabilities: SessionCapabilities) -> Self {
        Self::Capabilities {
            command_id: (),
            item_id: (),
            entity_id: (),
            capabilities,
        }
    }

    /// 返回会话快照中的中立 AgentItem，供共享投影层消费。
    ///
    /// capability barrier 不是内容项，因此返回 `None`。调用方仍不能取得
    /// vendor 私有 identity 或 adapter state。
    pub fn agent_item(&self) -> Option<&AgentItem> {
        match self {
            Self::Capabilities { .. } => None,
            Self::Item { item, .. } => Some(item),
        }
    }

    fn is_capabilities(&self) -> bool {
        matches!(self, SnapshotItem::Capabilities { .. })
    }

    fn validate(&self) -> Result<(), SnapshotError> {
        match self {
            SnapshotItem::Capabilities { .. } => Ok(()),
            SnapshotItem::Item {
                command_id, item, ..
            } if matches!(item, AgentItem::UserMessage { .. }) && command_id.is_none() => {
                Err(SnapshotError::InvalidIdentity)
            }
            SnapshotItem::Item { .. } => Ok(()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SnapshotError {
    #[error("snapshot must contain SessionCapabilities")]
    CapabilitiesMissing,
    #[error("snapshot must deliver SessionCapabilities before any AgentItem")]
    CapabilitiesNotFirst,
    #[error("snapshot must contain SessionCapabilities exactly once")]
    DuplicateCapabilities,
    #[error("snapshot item identity matrix is invalid")]
    InvalidIdentity,
    #[error("snapshot configuration agent kind does not match SessionCapabilities")]
    ConfigurationAgentMismatch,
}

/// 首次订阅 canonical snapshot。空 high-water 必须是 `BeforeFirst`。
#[derive(Debug, Clone, JsonSchema)]
#[schemars(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConversationSnapshot {
    pub conversation_id: ConversationId,
    pub base_event_cursor: StreamCursor,
    pub configuration_state: ConversationConfigurationState,
    items: Vec<SnapshotItem>,
}

impl ConversationSnapshot {
    pub fn new(
        conversation_id: ConversationId,
        base_event_cursor: StreamCursor,
        configuration_state: ConversationConfigurationState,
        items: Vec<SnapshotItem>,
    ) -> Result<Self, SnapshotError> {
        Self::validate(&configuration_state, &items)?;
        Ok(Self {
            conversation_id,
            base_event_cursor,
            configuration_state,
            items,
        })
    }

    pub fn items(&self) -> &[SnapshotItem] {
        &self.items
    }

    fn validate(
        configuration_state: &ConversationConfigurationState,
        items: &[SnapshotItem],
    ) -> Result<(), SnapshotError> {
        Self::validate_items(items)?;
        if let Some(configuration) = configuration_state.configuration() {
            let SnapshotItem::Capabilities { capabilities, .. } = &items[0] else {
                unreachable!("validate_items guarantees a capabilities-first snapshot");
            };
            if configuration.agent_kind() != capabilities.agent_kind {
                return Err(SnapshotError::ConfigurationAgentMismatch);
            }
        }
        Ok(())
    }

    fn validate_items(items: &[SnapshotItem]) -> Result<(), SnapshotError> {
        for item in items {
            item.validate()?;
        }
        let first = items.first().ok_or(SnapshotError::CapabilitiesMissing)?;
        if !first.is_capabilities() {
            return if items.iter().any(SnapshotItem::is_capabilities) {
                Err(SnapshotError::CapabilitiesNotFirst)
            } else {
                Err(SnapshotError::CapabilitiesMissing)
            };
        }
        if items.iter().skip(1).any(SnapshotItem::is_capabilities) {
            return Err(SnapshotError::DuplicateCapabilities);
        }
        Ok(())
    }
}

impl Serialize for ConversationSnapshot {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        Self::validate(&self.configuration_state, &self.items)
            .map_err(serde::ser::Error::custom)?;
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire<'a> {
            conversation_id: &'a ConversationId,
            base_event_cursor: StreamCursor,
            configuration_state: &'a ConversationConfigurationState,
            items: &'a [SnapshotItem],
        }
        Wire {
            conversation_id: &self.conversation_id,
            base_event_cursor: self.base_event_cursor,
            configuration_state: &self.configuration_state,
            items: &self.items,
        }
        .serialize(serializer)
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
            base_event_cursor: StreamCursor,
            configuration_state: ConversationConfigurationState,
            items: Vec<SnapshotItem>,
        }
        let wire = Wire::deserialize(deserializer)?;
        Self::new(
            wire.conversation_id,
            wire.base_event_cursor,
            wire.configuration_state,
            wire.items,
        )
        .map_err(serde::de::Error::custom)
    }
}

/// 客户端 inner HWM 后的定向 backfill 请求。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "scope", rename_all = "camelCase", deny_unknown_fields)]
pub enum BackfillRequest {
    Catalog {
        after: StreamCursor,
    },
    Conversation {
        #[serde(rename = "conversationId")]
        conversation_id: ConversationId,
        after: StreamCursor,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BackfillError {
    #[error("backfill range must be non-empty and increasing")]
    InvalidRange,
    #[error("backfill chunk entries are not contiguous or scoped")]
    InvalidEntries,
    #[error("backfill chunk exceeds 512 entries or 64 MiB")]
    TooLarge,
}

/// `after` exclusive、`through` inclusive 的非空连续范围。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BackfillRange {
    after: StreamCursor,
    through: StreamCursor,
}

impl BackfillRange {
    pub fn new(after: StreamCursor, through: StreamCursor) -> Result<Self, BackfillError> {
        let first = after
            .checked_next()
            .map_err(|_| BackfillError::InvalidRange)?;
        let Some(last) = through.high_water() else {
            return Err(BackfillError::InvalidRange);
        };
        if first > last {
            return Err(BackfillError::InvalidRange);
        }
        let count = last
            .checked_sub(first)
            .and_then(|value| value.checked_add(1))
            .ok_or(BackfillError::InvalidRange)?;
        if count > MAX_BACKFILL_ENTRIES as u64 {
            return Err(BackfillError::TooLarge);
        }
        Ok(Self { after, through })
    }

    pub fn after(self) -> StreamCursor {
        self.after
    }

    pub fn through(self) -> StreamCursor {
        self.through
    }

    fn expected_len(self) -> Result<usize, BackfillError> {
        let first = self
            .after
            .checked_next()
            .map_err(|_| BackfillError::InvalidRange)?;
        let last = self
            .through
            .high_water()
            .ok_or(BackfillError::InvalidRange)?;
        usize::try_from(last - first + 1).map_err(|_| BackfillError::TooLarge)
    }
}

impl<'de> Deserialize<'de> for BackfillRange {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire {
            after: StreamCursor,
            through: StreamCursor,
        }
        let wire = Wire::deserialize(deserializer)?;
        Self::new(wire.after, wire.through).map_err(serde::de::Error::custom)
    }
}

/// 定向 backfill chunk；conversation variant 的 capabilities 在 events 前应用。
#[derive(Debug, Clone, JsonSchema)]
#[serde(tag = "scope", rename_all = "camelCase", deny_unknown_fields)]
pub enum BackfillChunk {
    Catalog {
        range: BackfillRange,
        deltas: Vec<CatalogDelta>,
    },
    Conversation {
        #[serde(rename = "conversationId")]
        conversation_id: ConversationId,
        #[serde(rename = "capabilitiesPreamble")]
        capabilities_preamble: SessionCapabilities,
        range: BackfillRange,
        events: Vec<RuntimeEvent>,
    },
}

#[derive(Serialize)]
#[serde(tag = "scope", rename_all = "camelCase", deny_unknown_fields)]
enum BackfillChunkWire<'a> {
    Catalog {
        range: &'a BackfillRange,
        deltas: &'a [CatalogDelta],
    },
    Conversation {
        #[serde(rename = "conversationId")]
        conversation_id: &'a ConversationId,
        #[serde(rename = "capabilitiesPreamble")]
        capabilities_preamble: &'a SessionCapabilities,
        range: &'a BackfillRange,
        events: &'a [RuntimeEvent],
    },
}

impl BackfillChunk {
    pub fn catalog(range: BackfillRange, deltas: Vec<CatalogDelta>) -> Result<Self, BackfillError> {
        let chunk = Self::Catalog { range, deltas };
        chunk.validate()?;
        Ok(chunk)
    }

    pub fn conversation(
        conversation_id: ConversationId,
        capabilities_preamble: SessionCapabilities,
        range: BackfillRange,
        events: Vec<RuntimeEvent>,
    ) -> Result<Self, BackfillError> {
        let chunk = Self::Conversation {
            conversation_id,
            capabilities_preamble,
            range,
            events,
        };
        chunk.validate()?;
        Ok(chunk)
    }

    fn wire(&self) -> BackfillChunkWire<'_> {
        match self {
            Self::Catalog { range, deltas } => BackfillChunkWire::Catalog { range, deltas },
            Self::Conversation {
                conversation_id,
                capabilities_preamble,
                range,
                events,
            } => BackfillChunkWire::Conversation {
                conversation_id,
                capabilities_preamble,
                range,
                events,
            },
        }
    }

    fn validate(&self) -> Result<(), BackfillError> {
        match self {
            BackfillChunk::Catalog { range, deltas } => {
                if deltas.len() != range.expected_len()? || deltas.is_empty() {
                    return Err(BackfillError::InvalidEntries);
                }
                let mut expected = range
                    .after()
                    .checked_next()
                    .map_err(|_| BackfillError::InvalidRange)?;
                for delta in deltas {
                    if delta.catalog_revision != expected {
                        return Err(BackfillError::InvalidEntries);
                    }
                    expected = expected.checked_add(1).unwrap_or(expected);
                }
            }
            BackfillChunk::Conversation {
                conversation_id,
                range,
                events,
                ..
            } => {
                if events.len() != range.expected_len()? || events.is_empty() {
                    return Err(BackfillError::InvalidEntries);
                }
                let mut expected = range
                    .after()
                    .checked_next()
                    .map_err(|_| BackfillError::InvalidRange)?;
                for event in events {
                    if &event.conversation_id != conversation_id || event.event_seq != expected {
                        return Err(BackfillError::InvalidEntries);
                    }
                    event
                        .validate()
                        .map_err(|_| BackfillError::InvalidEntries)?;
                    expected = expected.checked_add(1).unwrap_or(expected);
                }
            }
        }
        let encoded = serde_json::to_vec(&self.wire()).map_err(|_| BackfillError::TooLarge)?;
        if encoded.len() > MAX_BACKFILL_BYTES {
            return Err(BackfillError::TooLarge);
        }
        Ok(())
    }
}

impl Serialize for BackfillChunk {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.validate().map_err(serde::ser::Error::custom)?;
        self.wire().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for BackfillChunk {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(tag = "scope", rename_all = "camelCase", deny_unknown_fields)]
        enum Wire {
            Catalog {
                range: BackfillRange,
                deltas: Vec<CatalogDelta>,
            },
            Conversation {
                #[serde(rename = "conversationId")]
                conversation_id: ConversationId,
                #[serde(rename = "capabilitiesPreamble")]
                capabilities_preamble: SessionCapabilities,
                range: BackfillRange,
                events: Vec<RuntimeEvent>,
            },
        }
        let chunk = match Wire::deserialize(deserializer)? {
            Wire::Catalog { range, deltas } => Self::Catalog { range, deltas },
            Wire::Conversation {
                conversation_id,
                capabilities_preamble,
                range,
                events,
            } => Self::Conversation {
                conversation_id,
                capabilities_preamble,
                range,
                events,
            },
        };
        chunk.validate().map_err(serde::de::Error::custom)?;
        Ok(chunk)
    }
}

fn deserialize_required_optional_command_id<'de, D>(
    deserializer: D,
) -> Result<Option<CommandId>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<CommandId>::deserialize(deserializer)
}
