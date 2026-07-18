//! Authenticated conversation snapshot materialization.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use agentdeck_protocol::runtime::identity::ConversationId;
use agentdeck_protocol::runtime::{
    ConversationConfigurationState, ConversationSnapshot, RuntimeEvent, RuntimeEventBody,
    SnapshotItem, StreamCursor, VendorConfigurationSnapshot,
};
use agentdeck_protocol::{
    AgentItem, AgentItemMeta, AgentKind, SessionCapabilities, VendorCapabilities,
};
use serde::ser::SerializeSeq;
use serde::{Deserialize, Serialize, Serializer};
use tokio::sync::OwnedSemaphorePermit;

use crate::agent::MAX_CANONICAL_NATIVE_HISTORY_ITEMS;
use crate::runtime::AgentRouter;
use crate::runtime::events::{
    RuntimeStreamTarget, SnapshotBarrierSource, SnapshotBuildPinCleanup,
    SnapshotMaterializationSource,
};
use crate::runtime::model::RuntimeStoreError;
use crate::runtime::store::cipher::CipherError;
use crate::runtime::store::{
    AuthenticatedConversationSnapshotContext, MAX_CONFIGURATION_CANONICAL_BYTES,
    PreparedConversationSnapshotWrite, ReadySnapshotReference, RuntimeId, RuntimeSnapshotBuildPin,
    RuntimeStoreHandle, SnapshotOrigin, StoredConversationSnapshot,
};

const MAX_CONVERSATION_SNAPSHOT_ITEMS: usize = 10_000;
const MAX_CONVERSATION_SNAPSHOT_BYTES: usize = 64 * 1024 * 1024;
pub(crate) const SNAPSHOT_BUILD_MEMORY_BYTES: usize = 128 * 1024 * 1024;
const MAX_JSON_CONTAINER_DEPTH: usize = 128;

/// 可跨 caller future 与已经入队的 blocking Store command 共享的 build budget。
///
/// 威胁场景：caller 在 worker 已接管大 snapshot payload 后被 deadline/disconnect
/// 取消；若 permit 只属于 caller，释放后第二次 build 会与仍在执行的第一条 Store
/// command 同时占用同一份 128 MiB 额度。最后一个 owner drop 前不得归还 permit。
#[derive(Clone)]
pub(crate) struct SharedSnapshotBuildPermit {
    permit: Arc<Mutex<OwnedSemaphorePermit>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SharedSnapshotBuildPermitError {
    Poisoned,
    Insufficient,
}

impl SharedSnapshotBuildPermit {
    pub(crate) fn new(permit: OwnedSemaphorePermit) -> Self {
        Self {
            permit: Arc::new(Mutex::new(permit)),
        }
    }

    pub(crate) fn merge(
        &self,
        additional: OwnedSemaphorePermit,
    ) -> Result<(), SharedSnapshotBuildPermitError> {
        self.permit
            .lock()
            .map_err(|_| SharedSnapshotBuildPermitError::Poisoned)?
            .merge(additional);
        Ok(())
    }

    pub(crate) fn split(
        &self,
        permits: usize,
    ) -> Result<OwnedSemaphorePermit, SharedSnapshotBuildPermitError> {
        self.permit
            .lock()
            .map_err(|_| SharedSnapshotBuildPermitError::Poisoned)?
            .split(permits)
            .ok_or(SharedSnapshotBuildPermitError::Insufficient)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SnapshotMaterializationError {
    #[error("runtime snapshot store operation failed: {0}")]
    Store(#[from] RuntimeStoreError),
    #[error("runtime snapshot payload is schema-incompatible")]
    SchemaIncompatible,
    #[error("runtime snapshot adapter capability is unavailable")]
    FeatureUnavailable,
    #[error("runtime snapshot payload exceeds its item or byte limit")]
    PayloadTooLarge,
    #[error("runtime snapshot state is no longer valid")]
    InvalidState,
}

impl SnapshotMaterializationError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Store(error) => error.code(),
            Self::SchemaIncompatible => "daemon.runtime.schema_incompatible",
            Self::FeatureUnavailable => "daemon.runtime.feature_unavailable",
            Self::PayloadTooLarge => "daemon.payload.item_too_large",
            Self::InvalidState => "daemon.runtime.invalid_state",
        }
    }
}

fn map_ready_store_error(error: RuntimeStoreError) -> SnapshotMaterializationError {
    match error {
        RuntimeStoreError::Cipher(
            CipherError::InvalidGeneration
            | CipherError::InvalidEncoding
            | CipherError::UnsupportedVersion { .. }
            | CipherError::GenerationMismatch { .. }
            | CipherError::InputTooLarge
            | CipherError::AuthenticationFailed,
        )
        | RuntimeStoreError::UnknownOrCorruptSchema
        | RuntimeStoreError::SchemaInspectionRaced
        | RuntimeStoreError::SchemaTooNew { .. } => {
            SnapshotMaterializationError::SchemaIncompatible
        }
        error => SnapshotMaterializationError::Store(error),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SnapshotBuildBinding {
    pin_id: [u8; 16],
    conversation_id: RuntimeId,
    base_event_cursor: StreamCursor,
}

#[derive(Clone)]
struct SnapshotAssemblyContext {
    conversation_id: RuntimeId,
    base_event_cursor: StreamCursor,
    configuration_state: ConversationConfigurationState,
    capabilities: SessionCapabilities,
    binding: SnapshotBuildBinding,
}

#[derive(Default)]
struct BuildSerializationProbe {
    counted_canonical_bytes: usize,
    estimated_peak_bytes: usize,
    full_payload_allocation_bytes: usize,
}

impl BuildSerializationProbe {
    #[cfg(test)]
    const fn counted_canonical_bytes(&self) -> usize {
        self.counted_canonical_bytes
    }

    #[cfg(test)]
    const fn estimated_peak_bytes(&self) -> usize {
        self.estimated_peak_bytes
    }

    #[cfg(test)]
    const fn full_payload_allocation_bytes(&self) -> usize {
        self.full_payload_allocation_bytes
    }
}

struct RetainedByteCounter {
    bytes: usize,
}

impl RetainedByteCounter {
    const fn new(initial: usize) -> Self {
        Self { bytes: initial }
    }

    fn add(&mut self, bytes: usize) -> Result<(), SnapshotMaterializationError> {
        self.bytes = self
            .bytes
            .checked_add(bytes)
            .ok_or(SnapshotMaterializationError::PayloadTooLarge)?;
        Ok(())
    }

    fn add_capacity<T>(&mut self, capacity: usize) -> Result<(), SnapshotMaterializationError> {
        self.add(
            capacity
                .checked_mul(std::mem::size_of::<T>())
                .ok_or(SnapshotMaterializationError::PayloadTooLarge)?,
        )
    }
}

fn snapshot_identity_validation_scratch_bytes() -> Result<usize, SnapshotMaterializationError> {
    MAX_CONVERSATION_SNAPSHOT_ITEMS
        .checked_next_power_of_two()
        .and_then(|slots| slots.checked_mul(2))
        .and_then(|slots| {
            slots.checked_mul(std::mem::size_of::<&str>() + 2 * std::mem::size_of::<usize>())
        })
        .ok_or(SnapshotMaterializationError::PayloadTooLarge)
}

fn snapshot_estimator_fixed_bytes() -> Result<usize, SnapshotMaterializationError> {
    std::mem::size_of::<RetainedByteCounter>()
        .checked_add(std::mem::size_of::<BoundedCanonicalCounter>())
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<BuildSerializationProbe>()))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<JsonRetainedScanner<'static>>()))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<CanonicalCompareWriter<'static>>()))
        .and_then(|bytes| {
            bytes.checked_add(
                MAX_JSON_CONTAINER_DEPTH.checked_mul(8 * std::mem::size_of::<usize>())?,
            )
        })
        .ok_or(SnapshotMaterializationError::PayloadTooLarge)
}

fn estimate_typed_snapshot_retained_bytes(
    snapshot: &ConversationSnapshot,
) -> Result<usize, SnapshotMaterializationError> {
    let mut retained = RetainedByteCounter::new(
        std::mem::size_of::<ConversationSnapshot>()
            .checked_add(snapshot_estimator_fixed_bytes()?)
            .and_then(|bytes| bytes.checked_add(snapshot_identity_validation_scratch_bytes().ok()?))
            .ok_or(SnapshotMaterializationError::PayloadTooLarge)?,
    );
    retained.add(snapshot.conversation_id.0.capacity())?;
    estimate_configuration_state_nested(&snapshot.configuration_state, &mut retained)?;
    retained
        .add_capacity::<SnapshotItem>(allocation_capacity_upper_bound(snapshot.items().len())?)?;
    for item in snapshot.items() {
        estimate_snapshot_item_nested(item, &mut retained)?;
    }
    Ok(retained.bytes)
}

fn estimate_configuration_state_nested(
    state: &ConversationConfigurationState,
    retained: &mut RetainedByteCounter,
) -> Result<(), SnapshotMaterializationError> {
    let Some(configuration) = state.configuration() else {
        return Ok(());
    };
    match configuration.vendor_control() {
        VendorConfigurationSnapshot::Codex(_) => Ok(()),
        VendorConfigurationSnapshot::ClaudeCode(configuration) => {
            for value in [
                configuration.model(),
                configuration.effort(),
                configuration.output_style(),
            ]
            .into_iter()
            .flatten()
            {
                retained.add(allocation_capacity_upper_bound(value.len())?)?;
            }
            Ok(())
        }
    }
}

fn configuration_state_nested_retained_bytes(
    state: &ConversationConfigurationState,
) -> Result<usize, SnapshotMaterializationError> {
    let mut retained = RetainedByteCounter::new(0);
    estimate_configuration_state_nested(state, &mut retained)?;
    Ok(retained.bytes)
}

fn estimate_snapshot_item_nested(
    item: &SnapshotItem,
    retained: &mut RetainedByteCounter,
) -> Result<(), SnapshotMaterializationError> {
    match item {
        SnapshotItem::Capabilities { capabilities, .. } => {
            estimate_capabilities_nested(capabilities, retained)
        }
        SnapshotItem::Item {
            item_id,
            entity_id,
            command_id,
            item,
        } => {
            retained.add(item_id.0.capacity())?;
            retained.add(entity_id.0.capacity())?;
            if let Some(command_id) = command_id {
                retained.add(command_id.0.capacity())?;
            }
            estimate_agent_item_nested(item, retained)
        }
    }
}

fn estimate_capabilities_nested(
    capabilities: &SessionCapabilities,
    retained: &mut RetainedByteCounter,
) -> Result<(), SnapshotMaterializationError> {
    retained.add(capabilities.agent_version.capacity())?;
    retained.add(
        capabilities
            .features
            .len()
            .checked_mul(std::mem::size_of::<usize>() * 8)
            .ok_or(SnapshotMaterializationError::PayloadTooLarge)?,
    )?;
    match &capabilities.vendor {
        VendorCapabilities::Codex(vendor) => {
            retained.add_capacity::<agentdeck_protocol::vendor::codex::CodexSandboxMode>(
                vendor.sandbox_modes.capacity(),
            )?;
            retained.add_capacity::<agentdeck_protocol::vendor::codex::CodexReasoningEffort>(
                vendor.reasoning_effort_levels.capacity(),
            )
        }
        VendorCapabilities::ClaudeCode(vendor) => {
            retained
                .add_capacity::<agentdeck_protocol::vendor::claude_code::ClaudeCodePermissionMode>(
                    vendor.permission_modes.capacity(),
                )?;
            estimate_string_vec_nested(&vendor.output_styles, retained)?;
            estimate_string_vec_nested(&vendor.hooks_supported, retained)?;
            retained.add(vendor.cli_version.capacity())
        }
    }
}

fn estimate_string_vec_nested(
    values: &Vec<String>,
    retained: &mut RetainedByteCounter,
) -> Result<(), SnapshotMaterializationError> {
    retained.add_capacity::<String>(values.capacity())?;
    for value in values {
        retained.add(value.capacity())?;
    }
    Ok(())
}

fn estimate_agent_item_nested(
    item: &AgentItem,
    retained: &mut RetainedByteCounter,
) -> Result<(), SnapshotMaterializationError> {
    match item {
        AgentItem::UserMessage { text, meta }
        | AgentItem::AssistantMessage { text, meta }
        | AgentItem::Reasoning { text, meta } => {
            retained.add(text.capacity())?;
            estimate_agent_item_meta_nested(meta, retained)
        }
        AgentItem::Shell { command, meta, .. } => {
            retained.add(command.capacity())?;
            estimate_agent_item_meta_nested(meta, retained)
        }
        AgentItem::Diff { files, meta } => {
            retained.add_capacity::<agentdeck_protocol::DiffFile>(files.capacity())?;
            for file in files {
                retained.add(file.path.capacity())?;
                if let Some(patch) = &file.patch {
                    retained.add(patch.capacity())?;
                }
            }
            estimate_agent_item_meta_nested(meta, retained)
        }
        AgentItem::Plan { steps, meta } => {
            retained.add_capacity::<agentdeck_protocol::PlanStep>(steps.capacity())?;
            for step in steps {
                retained.add(step.title.capacity())?;
                if let Some(detail) = &step.detail {
                    retained.add(detail.capacity())?;
                }
            }
            estimate_agent_item_meta_nested(meta, retained)
        }
        AgentItem::ImageReference {
            saved_path,
            original_path,
            meta,
        } => {
            if let Some(path) = saved_path {
                retained.add(path.capacity())?;
            }
            if let Some(path) = original_path {
                retained.add(path.capacity())?;
            }
            estimate_agent_item_meta_nested(meta, retained)
        }
        AgentItem::ToolCall {
            name,
            args,
            result,
            meta,
        } => {
            retained.add(name.capacity())?;
            estimate_json_value_nested(args, 0, retained)?;
            if let Some(result) = result {
                estimate_json_value_nested(result, 0, retained)?;
            }
            estimate_agent_item_meta_nested(meta, retained)
        }
        AgentItem::Raw {
            raw_kind,
            raw_payload,
            meta,
        } => {
            retained.add(raw_kind.capacity())?;
            retained.add(raw_payload.capacity())?;
            estimate_agent_item_meta_nested(meta, retained)
        }
    }
}

fn estimate_agent_item_meta_nested(
    meta: &AgentItemMeta,
    retained: &mut RetainedByteCounter,
) -> Result<(), SnapshotMaterializationError> {
    retained.add(json_btree_map_retained_bytes(meta.vendor_extensions.len())?)?;
    for (key, value) in &meta.vendor_extensions {
        retained.add(key.capacity())?;
        estimate_json_value_nested(value, 0, retained)?;
    }
    Ok(())
}

fn estimate_json_value_nested(
    value: &serde_json::Value,
    depth: usize,
    retained: &mut RetainedByteCounter,
) -> Result<(), SnapshotMaterializationError> {
    if depth > MAX_JSON_CONTAINER_DEPTH {
        return Err(SnapshotMaterializationError::SchemaIncompatible);
    }
    match value {
        serde_json::Value::String(value) => retained.add(value.capacity()),
        serde_json::Value::Array(values) => {
            retained.add_capacity::<serde_json::Value>(values.capacity())?;
            for value in values {
                estimate_json_value_nested(value, depth + 1, retained)?;
            }
            Ok(())
        }
        serde_json::Value::Object(values) => {
            retained.add(json_btree_map_retained_bytes(values.len())?)?;
            for (key, value) in values {
                retained.add(key.capacity())?;
                estimate_json_value_nested(value, depth + 1, retained)?;
            }
            Ok(())
        }
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {
            Ok(())
        }
    }
}

fn json_btree_map_retained_bytes(entries: usize) -> Result<usize, SnapshotMaterializationError> {
    if entries == 0 {
        return Ok(0);
    }
    // std/serde_json 默认 BTreeMap 的 B=6：每个 node 预留 11 个 key/value
    // slot，internal node 另有 12 条 edge。按“每个 entry 独占一个 internal
    // node”计费虽保守，但覆盖大量 singleton object 的最坏放大，以及 split
    // 后未满 leaf/internal node；key 的实际 heap capacity 另行逐项计入。
    let node_bytes = 4_usize
        .checked_mul(std::mem::size_of::<usize>())
        .and_then(|header| {
            std::mem::size_of::<String>()
                .checked_add(std::mem::size_of::<serde_json::Value>())
                .and_then(|slot| slot.checked_mul(11))
                .and_then(|slots| header.checked_add(slots))
        })
        .and_then(|leaf| leaf.checked_add(12 * std::mem::size_of::<usize>()))
        .ok_or(SnapshotMaterializationError::PayloadTooLarge)?;
    entries
        .checked_mul(node_bytes)
        .ok_or(SnapshotMaterializationError::PayloadTooLarge)
}

/// Ready reference 尚未打开 payload，无法运行内容感知 scanner；这里按 JSON 中
/// 最紧凑 object entry 与未满 BTreeMap node 的最坏比例取 256 倍，并复用本模块
/// 的 identity/estimator 固定成本。大 payload 会保守占满全池，随后仍由 exact
/// scanner 决定是否可接受。
pub(crate) fn conversation_snapshot_reference_peak_bound(
    logical_bytes: u64,
    item_count: u64,
) -> Result<usize, SnapshotMaterializationError> {
    const MAX_DYNAMIC_EXPANSION: usize = 256;
    let logical = usize::try_from(logical_bytes)
        .map_err(|_| SnapshotMaterializationError::PayloadTooLarge)?;
    let items =
        usize::try_from(item_count).map_err(|_| SnapshotMaterializationError::PayloadTooLarge)?;
    if logical > MAX_CONVERSATION_SNAPSHOT_BYTES || items > MAX_CONVERSATION_SNAPSHOT_ITEMS {
        return Err(SnapshotMaterializationError::PayloadTooLarge);
    }
    let fixed = snapshot_identity_validation_scratch_bytes()?
        .checked_add(snapshot_estimator_fixed_bytes()?)
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<ConversationSnapshot>()))
        .and_then(|bytes| bytes.checked_add(MAX_CONFIGURATION_CANONICAL_BYTES))
        .ok_or(SnapshotMaterializationError::PayloadTooLarge)?;
    Ok(logical
        .checked_mul(MAX_DYNAMIC_EXPANSION)
        .and_then(|bytes| {
            items
                .checked_mul(std::mem::size_of::<SnapshotItem>() * 2 + 256)
                .and_then(|item_bytes| bytes.checked_add(item_bytes))
        })
        .and_then(|bytes| bytes.checked_add(fixed))
        .unwrap_or(SNAPSHOT_BUILD_MEMORY_BYTES)
        .min(SNAPSHOT_BUILD_MEMORY_BYTES))
}

/// Build reducer 的唯一 retained-memory estimator。它直接复用本模块对
/// AgentItem/serde_json/capabilities 的深度估算，避免 subscription 层形成第二套
/// 容器放大规则。
pub(crate) struct ConversationSnapshotBudgetEstimator {
    nested: RetainedByteCounter,
    observed_item_events: usize,
}

impl ConversationSnapshotBudgetEstimator {
    pub(crate) fn bootstrap_bound() -> Result<usize, SnapshotMaterializationError> {
        conversation_snapshot_reference_peak_bound(0, 1)
    }

    pub(crate) fn new(
        capabilities: &SessionCapabilities,
        configuration_state: &ConversationConfigurationState,
    ) -> Result<Self, SnapshotMaterializationError> {
        let mut nested = RetainedByteCounter::new(
            snapshot_identity_validation_scratch_bytes()?
                .checked_add(snapshot_estimator_fixed_bytes()?)
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<ConversationSnapshot>()))
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<SessionCapabilities>()))
                .and_then(|bytes| bytes.checked_add(4096))
                .ok_or(SnapshotMaterializationError::PayloadTooLarge)?,
        );
        estimate_capabilities_nested(capabilities, &mut nested)?;
        estimate_configuration_state_nested(configuration_state, &mut nested)?;
        Ok(Self {
            nested,
            observed_item_events: 0,
        })
    }

    pub(crate) fn current_bound(&self) -> Result<usize, SnapshotMaterializationError> {
        self.reducer_retained_bound()
    }

    /// 必须在 page 的 RuntimeEvent allocations 移入 StableItemReducer 前调用。
    /// 重复 item update 会被保守重复计费；这只降低并发，不会低估 retained memory。
    pub(crate) fn observe_event_page(
        &mut self,
        events: &[RuntimeEvent],
    ) -> Result<usize, SnapshotMaterializationError> {
        for event in events {
            let RuntimeEventBody::Item { item } = &event.body else {
                continue;
            };
            let (Some(item_id), Some(entity_id)) = (&event.item_id, &event.entity_id) else {
                return Err(SnapshotMaterializationError::SchemaIncompatible);
            };
            // item/entity allocation 被移入 SnapshotItem；StableItemReducer 还各克隆
            // 一份 key 给两个 position map。
            self.nested.add(item_id.0.capacity())?;
            self.nested.add(item_id.0.capacity())?;
            self.nested.add(entity_id.0.capacity())?;
            self.nested.add(entity_id.0.capacity())?;
            if let Some(command_id) = &event.command_id {
                self.nested.add(command_id.0.capacity())?;
            }
            estimate_agent_item_nested(item, &mut self.nested)?;
            self.observed_item_events = self
                .observed_item_events
                .checked_add(1)
                .ok_or(SnapshotMaterializationError::PayloadTooLarge)?;
        }
        self.reducer_retained_bound()
    }

    fn reducer_retained_bound(&self) -> Result<usize, SnapshotMaterializationError> {
        let item_capacity = allocation_capacity_upper_bound(self.observed_item_events)?;
        let item_vector = item_capacity
            .checked_mul(std::mem::size_of::<SnapshotItem>())
            .ok_or(SnapshotMaterializationError::PayloadTooLarge)?;
        let map_capacity = allocation_capacity_upper_bound(self.observed_item_events)?;
        let map_tables = map_capacity
            .checked_mul(std::mem::size_of::<(String, usize)>() + 2 * std::mem::size_of::<usize>())
            .and_then(|bytes| bytes.checked_mul(2))
            .and_then(|bytes| {
                bytes.checked_add(
                    2 * std::mem::size_of::<std::collections::HashMap<String, usize>>(),
                )
            })
            .ok_or(SnapshotMaterializationError::PayloadTooLarge)?;
        let retained = self
            .nested
            .bytes
            .checked_add(item_vector)
            .and_then(|bytes| bytes.checked_add(map_tables))
            .ok_or(SnapshotMaterializationError::PayloadTooLarge)?;
        if retained > SNAPSHOT_BUILD_MEMORY_BYTES {
            Err(SnapshotMaterializationError::PayloadTooLarge)
        } else {
            Ok(retained)
        }
    }

    /// `items` 已由前述 page charge 覆盖。这里只计算从 reducer Vec 过渡到最终
    /// ConversationSnapshot Vec 的重叠，以及 typed DTO + canonical payload 峰值，
    /// 返回需要补足的总 charge。
    pub(crate) fn final_build_peak(
        &self,
        input: &SnapshotBuildInput,
        items: &Vec<SnapshotItem>,
    ) -> Result<usize, SnapshotMaterializationError> {
        if items.len() >= MAX_CONVERSATION_SNAPSHOT_ITEMS {
            return Err(SnapshotMaterializationError::PayloadTooLarge);
        }
        let capabilities = input
            .capabilities()
            .ok_or(SnapshotMaterializationError::InvalidState)?;
        let configuration_state = input
            .configuration_state()
            .ok_or(SnapshotMaterializationError::InvalidState)?;
        let conversation_id = input.conversation_id().to_canonical_string();
        let final_item_count = items
            .len()
            .checked_add(1)
            .ok_or(SnapshotMaterializationError::PayloadTooLarge)?;
        let mut typed = RetainedByteCounter::new(
            std::mem::size_of::<ConversationSnapshot>()
                .checked_add(snapshot_estimator_fixed_bytes()?)
                .and_then(|bytes| {
                    bytes.checked_add(snapshot_identity_validation_scratch_bytes().ok()?)
                })
                .ok_or(SnapshotMaterializationError::PayloadTooLarge)?,
        );
        typed.add(conversation_id.capacity())?;
        typed.add_capacity::<SnapshotItem>(allocation_capacity_upper_bound(final_item_count)?)?;
        estimate_capabilities_nested(capabilities, &mut typed)?;
        estimate_configuration_state_nested(configuration_state, &mut typed)?;
        for item in items {
            estimate_snapshot_item_nested(item, &mut typed)?;
        }

        let view = BorrowedBuildSnapshot {
            conversation_id: &conversation_id,
            base_event_cursor: input.base_event_cursor(),
            configuration_state,
            items: BorrowedBuildItems {
                capabilities,
                items,
            },
        };
        let mut counter = BoundedCanonicalCounter::new();
        if serde_json::to_writer(&mut counter, &view).is_err() {
            return if counter.exceeded {
                Err(SnapshotMaterializationError::PayloadTooLarge)
            } else {
                Err(SnapshotMaterializationError::SchemaIncompatible)
            };
        }
        let old_vector_bytes = items
            .capacity()
            .checked_mul(std::mem::size_of::<SnapshotItem>())
            .ok_or(SnapshotMaterializationError::PayloadTooLarge)?;
        let transition_peak = typed
            .bytes
            .checked_add(old_vector_bytes)
            .ok_or(SnapshotMaterializationError::PayloadTooLarge)?;
        let payload_capacity = counter
            .bytes
            .checked_add(crate::runtime::store::cipher::ROW_BLOB_V1_OVERHEAD_LEN)
            .ok_or(SnapshotMaterializationError::PayloadTooLarge)?;
        let serialization_peak = typed
            .bytes
            .checked_add(std::mem::size_of::<Vec<u8>>())
            .and_then(|bytes| bytes.checked_add(payload_capacity))
            .ok_or(SnapshotMaterializationError::PayloadTooLarge)?;
        let peak = transition_peak.max(serialization_peak);
        if peak > SNAPSHOT_BUILD_MEMORY_BYTES {
            Err(SnapshotMaterializationError::PayloadTooLarge)
        } else {
            Ok(peak)
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BorrowedBuildSnapshot<'a> {
    conversation_id: &'a str,
    base_event_cursor: StreamCursor,
    configuration_state: &'a ConversationConfigurationState,
    items: BorrowedBuildItems<'a>,
}

struct BorrowedBuildItems<'a> {
    capabilities: &'a SessionCapabilities,
    items: &'a [SnapshotItem],
}

impl Serialize for BorrowedBuildItems<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        #[derive(Serialize)]
        #[serde(tag = "kind", rename_all = "camelCase")]
        enum First<'a> {
            Capabilities {
                #[serde(rename = "commandId")]
                command_id: (),
                #[serde(rename = "itemId")]
                item_id: (),
                #[serde(rename = "entityId")]
                entity_id: (),
                capabilities: &'a SessionCapabilities,
            },
        }
        let mut sequence = serializer.serialize_seq(Some(self.items.len() + 1))?;
        sequence.serialize_element(&First::Capabilities {
            command_id: (),
            item_id: (),
            entity_id: (),
            capabilities: self.capabilities,
        })?;
        for item in self.items {
            sequence.serialize_element(item)?;
        }
        sequence.end()
    }
}

struct BoundedCanonicalCounter {
    bytes: usize,
    exceeded: bool,
}

impl BoundedCanonicalCounter {
    const fn new() -> Self {
        Self {
            bytes: 0,
            exceeded: false,
        }
    }
}

impl std::io::Write for BoundedCanonicalCounter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let Some(next) = self.bytes.checked_add(bytes.len()) else {
            self.exceeded = true;
            return Err(std::io::Error::new(
                std::io::ErrorKind::OutOfMemory,
                "snapshot canonical length overflow",
            ));
        };
        if next > MAX_CONVERSATION_SNAPSHOT_BYTES {
            self.exceeded = true;
            return Err(std::io::Error::new(
                std::io::ErrorKind::OutOfMemory,
                "snapshot canonical payload exceeds limit",
            ));
        }
        self.bytes = next;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn serialize_build_snapshot(
    snapshot: &ConversationSnapshot,
    mut probe: Option<&mut BuildSerializationProbe>,
) -> Result<Vec<u8>, SnapshotMaterializationError> {
    let typed_retained_bytes = estimate_typed_snapshot_retained_bytes(snapshot)?;
    let mut counter = BoundedCanonicalCounter::new();
    if serde_json::to_writer(&mut counter, snapshot).is_err() {
        return if counter.exceeded {
            Err(SnapshotMaterializationError::PayloadTooLarge)
        } else {
            Err(SnapshotMaterializationError::SchemaIncompatible)
        };
    }
    if let Some(probe) = probe.as_mut() {
        probe.counted_canonical_bytes = counter.bytes;
    }
    let payload_capacity = counter
        .bytes
        .checked_add(crate::runtime::store::cipher::ROW_BLOB_V1_OVERHEAD_LEN)
        .ok_or(SnapshotMaterializationError::PayloadTooLarge)?;
    let estimated_peak_bytes = typed_retained_bytes
        .checked_add(std::mem::size_of::<Vec<u8>>())
        .and_then(|bytes| bytes.checked_add(payload_capacity))
        .ok_or(SnapshotMaterializationError::PayloadTooLarge)?;
    if let Some(probe) = probe.as_mut() {
        probe.estimated_peak_bytes = estimated_peak_bytes;
    }
    if estimated_peak_bytes > SNAPSHOT_BUILD_MEMORY_BYTES {
        return Err(SnapshotMaterializationError::PayloadTooLarge);
    }

    let mut payload = Vec::with_capacity(payload_capacity);
    let actual_peak_bytes = typed_retained_bytes
        .checked_add(std::mem::size_of::<Vec<u8>>())
        .and_then(|bytes| bytes.checked_add(payload.capacity()))
        .ok_or(SnapshotMaterializationError::PayloadTooLarge)?;
    if let Some(probe) = probe.as_mut() {
        probe.estimated_peak_bytes = actual_peak_bytes;
        probe.full_payload_allocation_bytes = payload.capacity();
    }
    if actual_peak_bytes > SNAPSHOT_BUILD_MEMORY_BYTES {
        return Err(SnapshotMaterializationError::PayloadTooLarge);
    }
    serde_json::to_writer(&mut payload, snapshot)
        .map_err(|_| SnapshotMaterializationError::SchemaIncompatible)?;
    if payload.len() != counter.bytes {
        return Err(SnapshotMaterializationError::SchemaIncompatible);
    }
    let post_encode_peak_bytes = typed_retained_bytes
        .checked_add(std::mem::size_of::<Vec<u8>>())
        .and_then(|bytes| bytes.checked_add(payload.capacity()))
        .ok_or(SnapshotMaterializationError::PayloadTooLarge)?;
    if post_encode_peak_bytes > SNAPSHOT_BUILD_MEMORY_BYTES {
        return Err(SnapshotMaterializationError::PayloadTooLarge);
    }
    Ok(payload)
}

pub struct AssembledConversationSnapshot {
    item_count: u64,
    canonical_payload: Vec<u8>,
    binding: SnapshotBuildBinding,
}

impl std::fmt::Debug for AssembledConversationSnapshot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AssembledConversationSnapshot")
            .field("item_count", &self.item_count)
            .field("canonical_payload_bytes", &self.canonical_payload.len())
            .finish()
    }
}

impl AssembledConversationSnapshot {
    #[must_use]
    pub const fn item_count(&self) -> u64 {
        self.item_count
    }

    #[must_use]
    pub fn canonical_payload(&self) -> &[u8] {
        &self.canonical_payload
    }

    #[cfg(test)]
    fn retained_memory_observation(&self) -> SnapshotHandoffRetentionObservation {
        SnapshotHandoffRetentionObservation {
            raw_payload_bytes: self.canonical_payload.capacity(),
            small_metadata_bytes: std::mem::size_of::<Self>(),
            decoded_dto_bytes: 0,
            has_memory_lease: false,
        }
    }
}

fn assemble_snapshot(
    context: SnapshotAssemblyContext,
    agent_items: Vec<SnapshotItem>,
) -> Result<AssembledConversationSnapshot, SnapshotMaterializationError> {
    if agent_items.len() >= MAX_CONVERSATION_SNAPSHOT_ITEMS {
        return Err(SnapshotMaterializationError::PayloadTooLarge);
    }
    validate_unique_agent_item_ids(&agent_items)?;
    if agent_items
        .iter()
        .any(|item| matches!(item, SnapshotItem::Capabilities { .. }))
    {
        return Err(SnapshotMaterializationError::SchemaIncompatible);
    }

    let item_count = agent_items
        .len()
        .checked_add(1)
        .and_then(|value| u64::try_from(value).ok())
        .ok_or(SnapshotMaterializationError::PayloadTooLarge)?;
    let mut items = Vec::with_capacity(agent_items.len() + 1);
    items.push(SnapshotItem::capabilities(context.capabilities));
    items.extend(agent_items);
    let snapshot = ConversationSnapshot::new(
        ConversationId::new(context.conversation_id.to_canonical_string()),
        context.base_event_cursor,
        context.configuration_state,
        items,
    )
    .map_err(|_| SnapshotMaterializationError::SchemaIncompatible)?;
    let canonical_payload = serialize_build_snapshot(&snapshot, None)?;
    Ok(AssembledConversationSnapshot {
        item_count,
        canonical_payload,
        binding: context.binding,
    })
}

#[cfg(test)]
fn decode_ready_snapshot(
    payload: &[u8],
) -> Result<ConversationSnapshot, SnapshotMaterializationError> {
    Ok(decode_ready_snapshot_with_capacity(payload, payload.len())?.snapshot)
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LegacyConversationSnapshotV4 {
    conversation_id: ConversationId,
    base_event_cursor: StreamCursor,
    items: Vec<SnapshotItem>,
}

impl LegacyConversationSnapshotV4 {
    fn into_current(
        self,
        configuration_state: ConversationConfigurationState,
    ) -> Result<ConversationSnapshot, SnapshotMaterializationError> {
        ConversationSnapshot::new(
            self.conversation_id,
            self.base_event_cursor,
            configuration_state,
            self.items,
        )
        .map_err(|_| SnapshotMaterializationError::SchemaIncompatible)
    }
}

struct DecodedReadySnapshot {
    snapshot: ConversationSnapshot,
    legacy_v4: bool,
}

#[cfg(test)]
fn decode_ready_snapshot_with_capacity(
    payload: &[u8],
    raw_capacity: usize,
) -> Result<DecodedReadySnapshot, SnapshotMaterializationError> {
    let configuration_state = ConversationConfigurationState::new(0, None)
        .map_err(|_| SnapshotMaterializationError::SchemaIncompatible)?;
    decode_ready_snapshot_with_configuration(payload, raw_capacity, &configuration_state)
}

fn decode_ready_snapshot_with_configuration(
    payload: &[u8],
    raw_capacity: usize,
    legacy_configuration_state: &ConversationConfigurationState,
) -> Result<DecodedReadySnapshot, SnapshotMaterializationError> {
    if payload.len() > MAX_CONVERSATION_SNAPSHOT_BYTES {
        return Err(SnapshotMaterializationError::PayloadTooLarge);
    }
    let retained = observe_json_retained_budget_with_capacity(payload, raw_capacity)?;
    let expected_nested = configuration_state_nested_retained_bytes(legacy_configuration_state)?;
    let retained_with_expected = retained
        .total_retained_bytes()
        .checked_add(std::mem::size_of::<ConversationConfigurationState>())
        .and_then(|bytes| bytes.checked_add(expected_nested))
        .ok_or(SnapshotMaterializationError::PayloadTooLarge)?;
    if retained_with_expected > SNAPSHOT_BUILD_MEMORY_BYTES {
        return Err(SnapshotMaterializationError::PayloadTooLarge);
    }
    if let Ok(snapshot) = serde_json::from_slice::<ConversationSnapshot>(payload) {
        let comparison = compare_canonical_snapshot(payload, &snapshot)?;
        debug_assert_eq!(comparison.bytes_compared, payload.len());
        return Ok(DecodedReadySnapshot {
            snapshot,
            legacy_v4: false,
        });
    }

    let legacy = serde_json::from_slice::<LegacyConversationSnapshotV4>(payload)
        .map_err(|_| SnapshotMaterializationError::SchemaIncompatible)?;
    if retained_with_expected
        .checked_add(expected_nested)
        .ok_or(SnapshotMaterializationError::PayloadTooLarge)?
        > SNAPSHOT_BUILD_MEMORY_BYTES
    {
        return Err(SnapshotMaterializationError::PayloadTooLarge);
    }
    let comparison = compare_canonical_value(payload, &legacy)?;
    debug_assert_eq!(comparison.bytes_compared, payload.len());
    Ok(DecodedReadySnapshot {
        snapshot: legacy.into_current(legacy_configuration_state.clone())?,
        legacy_v4: true,
    })
}

#[derive(Clone, Copy, Debug)]
struct JsonRetainedBudgetObservation {
    raw_bytes: usize,
    decoded_and_validation_bytes: usize,
}

impl JsonRetainedBudgetObservation {
    #[cfg(test)]
    const fn raw_bytes(self) -> usize {
        self.raw_bytes
    }

    const fn total_retained_bytes(self) -> usize {
        self.raw_bytes + self.decoded_and_validation_bytes
    }
}

#[cfg(test)]
fn observe_json_retained_budget(
    payload: &[u8],
) -> Result<JsonRetainedBudgetObservation, SnapshotMaterializationError> {
    observe_json_retained_budget_with_capacity(payload, payload.len())
}

fn observe_json_retained_budget_with_capacity(
    payload: &[u8],
    raw_capacity: usize,
) -> Result<JsonRetainedBudgetObservation, SnapshotMaterializationError> {
    if raw_capacity < payload.len() {
        return Err(SnapshotMaterializationError::SchemaIncompatible);
    }
    let mut scanner = JsonRetainedScanner::new(payload);
    let decoded_dom_bytes = scanner.scan()?;
    let identity_validation_bytes = snapshot_identity_validation_scratch_bytes()?;
    let decoded_and_validation_bytes = decoded_dom_bytes
        .checked_add(std::mem::size_of::<ConversationSnapshot>())
        .and_then(|bytes| bytes.checked_add(identity_validation_bytes))
        .and_then(|bytes| bytes.checked_add(snapshot_estimator_fixed_bytes().ok()?))
        .ok_or(SnapshotMaterializationError::PayloadTooLarge)?;
    let _total_retained_bytes = raw_capacity
        .checked_add(decoded_and_validation_bytes)
        .ok_or(SnapshotMaterializationError::PayloadTooLarge)?;
    Ok(JsonRetainedBudgetObservation {
        raw_bytes: raw_capacity,
        decoded_and_validation_bytes,
    })
}

#[derive(Clone, Copy)]
enum JsonRetainedShape {
    FixedDto,
    DynamicValue,
    Sequence(JsonSequenceKind),
}

#[derive(Clone, Copy)]
enum JsonSequenceKind {
    SnapshotItems,
    Features,
    CodexSandboxModes,
    CodexReasoningEfforts,
    ClaudeCodePermissionModes,
    Strings,
    DiffFiles,
    PlanSteps,
}

fn fixed_json_field_shape(key: &[u8]) -> JsonRetainedShape {
    match key {
        b"items" => JsonRetainedShape::Sequence(JsonSequenceKind::SnapshotItems),
        b"features" => JsonRetainedShape::Sequence(JsonSequenceKind::Features),
        b"sandboxModes" => JsonRetainedShape::Sequence(JsonSequenceKind::CodexSandboxModes),
        b"reasoningEffortLevels" => {
            JsonRetainedShape::Sequence(JsonSequenceKind::CodexReasoningEfforts)
        }
        b"permissionModes" => {
            JsonRetainedShape::Sequence(JsonSequenceKind::ClaudeCodePermissionModes)
        }
        b"outputStyles" | b"hooksSupported" => {
            JsonRetainedShape::Sequence(JsonSequenceKind::Strings)
        }
        b"files" => JsonRetainedShape::Sequence(JsonSequenceKind::DiffFiles),
        b"steps" => JsonRetainedShape::Sequence(JsonSequenceKind::PlanSteps),
        b"args" | b"result" | b"vendorExtensions" => JsonRetainedShape::DynamicValue,
        _ => JsonRetainedShape::FixedDto,
    }
}

fn sequence_retained_bytes(
    kind: JsonSequenceKind,
    elements: usize,
) -> Result<usize, SnapshotMaterializationError> {
    if matches!(kind, JsonSequenceKind::Features) {
        return elements
            .checked_mul(std::mem::size_of::<usize>() * 8)
            .ok_or(SnapshotMaterializationError::PayloadTooLarge);
    }
    let capacity = allocation_capacity_upper_bound(elements)?;
    let element_bytes = match kind {
        JsonSequenceKind::SnapshotItems => std::mem::size_of::<SnapshotItem>(),
        JsonSequenceKind::CodexSandboxModes => {
            std::mem::size_of::<agentdeck_protocol::vendor::codex::CodexSandboxMode>()
        }
        JsonSequenceKind::CodexReasoningEfforts => {
            std::mem::size_of::<agentdeck_protocol::vendor::codex::CodexReasoningEffort>()
        }
        JsonSequenceKind::ClaudeCodePermissionModes => {
            std::mem::size_of::<agentdeck_protocol::vendor::claude_code::ClaudeCodePermissionMode>()
        }
        JsonSequenceKind::Strings => std::mem::size_of::<String>(),
        JsonSequenceKind::DiffFiles => std::mem::size_of::<agentdeck_protocol::DiffFile>(),
        JsonSequenceKind::PlanSteps => std::mem::size_of::<agentdeck_protocol::PlanStep>(),
        JsonSequenceKind::Features => unreachable!("features handled above"),
    };
    capacity
        .checked_mul(element_bytes)
        .ok_or(SnapshotMaterializationError::PayloadTooLarge)
}

#[derive(Clone, Copy)]
struct ScannedJsonString {
    decoded_content_bytes: usize,
    content_start: usize,
    content_end: usize,
    escaped: bool,
}

impl ScannedJsonString {
    fn unescaped_bytes<'a>(&self, payload: &'a [u8]) -> Option<&'a [u8]> {
        (!self.escaped).then(|| &payload[self.content_start..self.content_end])
    }
}

struct JsonRetainedScanner<'a> {
    payload: &'a [u8],
    position: usize,
    decoded_bytes: usize,
}

impl<'a> JsonRetainedScanner<'a> {
    const fn new(payload: &'a [u8]) -> Self {
        Self {
            payload,
            position: 0,
            decoded_bytes: 0,
        }
    }

    fn scan(&mut self) -> Result<usize, SnapshotMaterializationError> {
        self.skip_whitespace();
        self.scan_value(0, JsonRetainedShape::FixedDto)?;
        self.skip_whitespace();
        if self.position != self.payload.len() {
            return Err(SnapshotMaterializationError::SchemaIncompatible);
        }
        Ok(self.decoded_bytes)
    }

    fn scan_value(
        &mut self,
        depth: usize,
        shape: JsonRetainedShape,
    ) -> Result<(), SnapshotMaterializationError> {
        match self.current() {
            Some(b'{') => self.scan_object(depth + 1, shape),
            Some(b'[') => self.scan_array(depth + 1, shape),
            Some(b'"') => {
                let string = self.scan_string()?;
                self.add_string_capacity(string.decoded_content_bytes)
            }
            Some(b't') => self.scan_literal(b"true"),
            Some(b'f') => self.scan_literal(b"false"),
            Some(b'n') => self.scan_literal(b"null"),
            Some(b'-' | b'0'..=b'9') => self.scan_number(),
            _ => Err(SnapshotMaterializationError::SchemaIncompatible),
        }
    }

    fn scan_array(
        &mut self,
        depth: usize,
        shape: JsonRetainedShape,
    ) -> Result<(), SnapshotMaterializationError> {
        self.ensure_depth(depth)?;
        self.position += 1;
        self.skip_whitespace();
        let mut elements = 0_usize;
        if self.consume(b']') {
            return Ok(());
        }
        let element_shape = match shape {
            JsonRetainedShape::DynamicValue => JsonRetainedShape::DynamicValue,
            JsonRetainedShape::FixedDto | JsonRetainedShape::Sequence(_) => {
                JsonRetainedShape::FixedDto
            }
        };
        loop {
            self.scan_value(depth, element_shape)?;
            elements = elements
                .checked_add(1)
                .ok_or(SnapshotMaterializationError::PayloadTooLarge)?;
            self.skip_whitespace();
            if self.consume(b']') {
                break;
            }
            if !self.consume(b',') {
                return Err(SnapshotMaterializationError::SchemaIncompatible);
            }
            self.skip_whitespace();
        }
        let retained_bytes = match shape {
            JsonRetainedShape::DynamicValue | JsonRetainedShape::FixedDto => {
                allocation_capacity_upper_bound(elements)?
                    .checked_mul(std::mem::size_of::<serde_json::Value>())
                    .ok_or(SnapshotMaterializationError::PayloadTooLarge)?
            }
            JsonRetainedShape::Sequence(kind) => sequence_retained_bytes(kind, elements)?,
        };
        self.add_decoded(retained_bytes)
    }

    fn scan_object(
        &mut self,
        depth: usize,
        shape: JsonRetainedShape,
    ) -> Result<(), SnapshotMaterializationError> {
        self.ensure_depth(depth)?;
        self.position += 1;
        self.skip_whitespace();
        let mut entries = 0_usize;
        if self.consume(b'}') {
            return Ok(());
        }
        loop {
            if self.current() != Some(b'"') {
                return Err(SnapshotMaterializationError::SchemaIncompatible);
            }
            let key = self.scan_string()?;
            self.skip_whitespace();
            if !self.consume(b':') {
                return Err(SnapshotMaterializationError::SchemaIncompatible);
            }
            self.skip_whitespace();
            let child_shape = match shape {
                JsonRetainedShape::DynamicValue => {
                    self.add_string_capacity(key.decoded_content_bytes)?;
                    JsonRetainedShape::DynamicValue
                }
                JsonRetainedShape::FixedDto | JsonRetainedShape::Sequence(_) => {
                    let key = key
                        .unescaped_bytes(self.payload)
                        .ok_or(SnapshotMaterializationError::SchemaIncompatible)?;
                    fixed_json_field_shape(key)
                }
            };
            self.scan_value(depth, child_shape)?;
            entries = entries
                .checked_add(1)
                .ok_or(SnapshotMaterializationError::PayloadTooLarge)?;
            self.skip_whitespace();
            if self.consume(b'}') {
                break;
            }
            if !self.consume(b',') {
                return Err(SnapshotMaterializationError::SchemaIncompatible);
            }
            self.skip_whitespace();
        }
        if matches!(shape, JsonRetainedShape::DynamicValue) {
            self.add_decoded(json_btree_map_retained_bytes(entries)?)?;
        }
        Ok(())
    }

    fn scan_string(&mut self) -> Result<ScannedJsonString, SnapshotMaterializationError> {
        if !self.consume(b'"') {
            return Err(SnapshotMaterializationError::SchemaIncompatible);
        }
        let content_start = self.position;
        let mut escaped = false;
        loop {
            let Some(byte) = self.current() else {
                return Err(SnapshotMaterializationError::SchemaIncompatible);
            };
            match byte {
                b'"' => {
                    let content_end = self.position;
                    let content_bytes = self
                        .position
                        .checked_sub(content_start)
                        .ok_or(SnapshotMaterializationError::SchemaIncompatible)?;
                    self.position += 1;
                    let decoded_content_bytes = if escaped {
                        let string_start = content_start
                            .checked_sub(1)
                            .ok_or(SnapshotMaterializationError::SchemaIncompatible)?;
                        serde_json::from_slice::<String>(&self.payload[string_start..self.position])
                            .map_err(|_| SnapshotMaterializationError::SchemaIncompatible)?
                            .len()
                    } else {
                        content_bytes
                    };
                    return Ok(ScannedJsonString {
                        decoded_content_bytes,
                        content_start,
                        content_end,
                        escaped,
                    });
                }
                b'\\' => {
                    escaped = true;
                    self.position += 1;
                    let Some(escape) = self.current() else {
                        return Err(SnapshotMaterializationError::SchemaIncompatible);
                    };
                    self.position += 1;
                    match escape {
                        b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => {}
                        b'u' => {
                            for _ in 0..4 {
                                let Some(hex) = self.current() else {
                                    return Err(SnapshotMaterializationError::SchemaIncompatible);
                                };
                                if !hex.is_ascii_hexdigit() {
                                    return Err(SnapshotMaterializationError::SchemaIncompatible);
                                }
                                self.position += 1;
                            }
                        }
                        _ => return Err(SnapshotMaterializationError::SchemaIncompatible),
                    }
                }
                0x00..=0x1f => return Err(SnapshotMaterializationError::SchemaIncompatible),
                _ => self.position += 1,
            }
        }
    }

    fn scan_number(&mut self) -> Result<(), SnapshotMaterializationError> {
        self.consume(b'-');
        match self.current() {
            Some(b'0') => self.position += 1,
            Some(b'1'..=b'9') => {
                self.position += 1;
                while matches!(self.current(), Some(b'0'..=b'9')) {
                    self.position += 1;
                }
            }
            _ => return Err(SnapshotMaterializationError::SchemaIncompatible),
        }
        if self.consume(b'.') {
            if !matches!(self.current(), Some(b'0'..=b'9')) {
                return Err(SnapshotMaterializationError::SchemaIncompatible);
            }
            while matches!(self.current(), Some(b'0'..=b'9')) {
                self.position += 1;
            }
        }
        if matches!(self.current(), Some(b'e' | b'E')) {
            self.position += 1;
            if matches!(self.current(), Some(b'+' | b'-')) {
                self.position += 1;
            }
            if !matches!(self.current(), Some(b'0'..=b'9')) {
                return Err(SnapshotMaterializationError::SchemaIncompatible);
            }
            while matches!(self.current(), Some(b'0'..=b'9')) {
                self.position += 1;
            }
        }
        Ok(())
    }

    fn scan_literal(&mut self, literal: &[u8]) -> Result<(), SnapshotMaterializationError> {
        let end = self
            .position
            .checked_add(literal.len())
            .ok_or(SnapshotMaterializationError::PayloadTooLarge)?;
        if self.payload.get(self.position..end) != Some(literal) {
            return Err(SnapshotMaterializationError::SchemaIncompatible);
        }
        self.position = end;
        Ok(())
    }

    fn add_string_capacity(
        &mut self,
        content_bytes: usize,
    ) -> Result<(), SnapshotMaterializationError> {
        self.add_decoded(content_bytes)
    }

    fn add_decoded(&mut self, bytes: usize) -> Result<(), SnapshotMaterializationError> {
        self.decoded_bytes = self
            .decoded_bytes
            .checked_add(bytes)
            .ok_or(SnapshotMaterializationError::PayloadTooLarge)?;
        Ok(())
    }

    fn ensure_depth(&self, depth: usize) -> Result<(), SnapshotMaterializationError> {
        if depth > MAX_JSON_CONTAINER_DEPTH {
            Err(SnapshotMaterializationError::SchemaIncompatible)
        } else {
            Ok(())
        }
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.current(), Some(b' ' | b'\n' | b'\r' | b'\t')) {
            self.position += 1;
        }
    }

    fn consume(&mut self, expected: u8) -> bool {
        if self.current() == Some(expected) {
            self.position += 1;
            true
        } else {
            false
        }
    }

    fn current(&self) -> Option<u8> {
        self.payload.get(self.position).copied()
    }
}

fn allocation_capacity_upper_bound(elements: usize) -> Result<usize, SnapshotMaterializationError> {
    if elements == 0 {
        return Ok(0);
    }
    elements
        .max(4)
        .checked_next_power_of_two()
        .ok_or(SnapshotMaterializationError::PayloadTooLarge)
}

struct CanonicalComparison {
    bytes_compared: usize,
}

impl CanonicalComparison {
    #[cfg(test)]
    const fn bytes_compared(&self) -> usize {
        self.bytes_compared
    }

    #[cfg(test)]
    const fn peak_buffered_bytes(&self) -> usize {
        0
    }
}

struct CanonicalCompareWriter<'a> {
    expected: &'a [u8],
    position: usize,
}

impl std::io::Write for CanonicalCompareWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let end = self.position.checked_add(bytes.len()).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "canonical length overflow")
        })?;
        if self.expected.get(self.position..end) != Some(bytes) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "snapshot is not canonical",
            ));
        }
        self.position = end;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn compare_canonical_snapshot(
    expected: &[u8],
    snapshot: &ConversationSnapshot,
) -> Result<CanonicalComparison, SnapshotMaterializationError> {
    compare_canonical_value(expected, snapshot)
}

fn compare_canonical_value<T: Serialize>(
    expected: &[u8],
    value: &T,
) -> Result<CanonicalComparison, SnapshotMaterializationError> {
    let mut writer = CanonicalCompareWriter {
        expected,
        position: 0,
    };
    serde_json::to_writer(&mut writer, value)
        .map_err(|_| SnapshotMaterializationError::SchemaIncompatible)?;
    if writer.position != expected.len() {
        return Err(SnapshotMaterializationError::SchemaIncompatible);
    }
    Ok(CanonicalComparison {
        bytes_compared: writer.position,
    })
}

fn validate_ready_snapshot(
    context: &AuthenticatedConversationSnapshotContext,
    reference: &ReadySnapshotReference,
    expected_configuration_state: &ConversationConfigurationState,
    snapshot: &ConversationSnapshot,
) -> Result<(), SnapshotMaterializationError> {
    let RuntimeStreamTarget::Conversation(reference_conversation_id) = reference.target else {
        return Err(SnapshotMaterializationError::SchemaIncompatible);
    };
    let expected_conversation_id = context.conversation_id.to_canonical_string();
    let item_count = u64::try_from(snapshot.items().len())
        .map_err(|_| SnapshotMaterializationError::PayloadTooLarge)?;
    if reference_conversation_id != context.conversation_id
        || snapshot.conversation_id.as_str() != expected_conversation_id
        || snapshot.base_event_cursor != reference.base
        || reference.base.high_water() > context.event_high_water
        || item_count != reference.item_count
        || &snapshot.configuration_state != expected_configuration_state
    {
        return Err(SnapshotMaterializationError::SchemaIncompatible);
    }
    if snapshot.items().len() > MAX_CONVERSATION_SNAPSHOT_ITEMS {
        return Err(SnapshotMaterializationError::PayloadTooLarge);
    }
    let Some(SnapshotItem::Capabilities { capabilities, .. }) = snapshot.items().first() else {
        return Err(SnapshotMaterializationError::SchemaIncompatible);
    };
    if capabilities.agent_kind != context.agent_kind {
        return Err(SnapshotMaterializationError::SchemaIncompatible);
    }
    validate_unique_agent_item_ids(snapshot.items())
}

fn validate_unique_agent_item_ids(
    items: &[SnapshotItem],
) -> Result<(), SnapshotMaterializationError> {
    let mut item_ids = HashSet::with_capacity(items.len());
    let mut entity_ids = HashSet::with_capacity(items.len());
    for item in items {
        match item {
            SnapshotItem::Capabilities { .. } => {}
            SnapshotItem::Item {
                item_id, entity_id, ..
            } => {
                if !item_ids.insert(item_id.as_str()) || !entity_ids.insert(entity_id.as_str()) {
                    return Err(SnapshotMaterializationError::SchemaIncompatible);
                }
            }
        }
    }
    Ok(())
}

/// Ready row 的 decoded DTO 与 exact opaque payload 一起持有。`stored` 内嵌的
/// read-pool memory lease 在本 wrapper drop 前不会释放，避免 decoded state 尚存活时
/// 让第二个 128 MiB snapshot read 绕过全池预算。
pub struct MaterializedConversationSnapshot {
    stored: StoredConversationSnapshot,
    wire_payload: Option<Vec<u8>>,
}

impl std::fmt::Debug for MaterializedConversationSnapshot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MaterializedConversationSnapshot")
            .field("conversation_id", &self.stored.conversation_id)
            .field("snapshot_id", &self.stored.snapshot_id)
            .field("item_count", &self.stored.item_count)
            .field("canonical_payload_bytes", &self.canonical_payload().len())
            .finish()
    }
}

impl MaterializedConversationSnapshot {
    #[must_use]
    pub const fn item_count(&self) -> u64 {
        self.stored.item_count
    }

    #[must_use]
    pub fn canonical_payload(&self) -> &[u8] {
        self.wire_payload
            .as_deref()
            .unwrap_or(self.stored.payload.as_slice())
    }

    /// 把 authenticated ready row、可选 legacy→v2 wire 产物与 read-pool lease
    /// 一起移交给 egress。三者都必须活到 transport flush 完成。
    pub(crate) fn into_parts(self) -> (StoredConversationSnapshot, Option<Vec<u8>>) {
        (self.stored, self.wire_payload)
    }

    #[cfg(test)]
    fn retained_memory_observation(&self) -> SnapshotHandoffRetentionObservation {
        SnapshotHandoffRetentionObservation {
            raw_payload_bytes: self
                .stored
                .payload
                .capacity()
                .saturating_add(self.wire_payload.as_ref().map_or(0, Vec::capacity)),
            small_metadata_bytes: std::mem::size_of::<Self>(),
            decoded_dto_bytes: 0,
            has_memory_lease: self.stored.memory_lease.is_some(),
        }
    }
}

#[cfg(test)]
struct SnapshotHandoffRetentionObservation {
    raw_payload_bytes: usize,
    small_metadata_bytes: usize,
    decoded_dto_bytes: usize,
    has_memory_lease: bool,
}

#[cfg(test)]
impl SnapshotHandoffRetentionObservation {
    const fn raw_payload_bytes(&self) -> usize {
        self.raw_payload_bytes
    }

    const fn small_metadata_bytes(&self) -> usize {
        self.small_metadata_bytes
    }

    const fn decoded_dto_bytes(&self) -> usize {
        self.decoded_dto_bytes
    }

    const fn has_memory_lease(&self) -> bool {
        self.has_memory_lease
    }
}

/// S3 的数据源中立 build handoff。故意不实现 `Clone`：exact TEMP pin 由单一
/// BuildInput 线性保留，直到后续 store snapshot 成功消费或调用方显式释放。
pub struct SnapshotBuildInput {
    pin: Option<RuntimeSnapshotBuildPin>,
    cleanup: Option<SnapshotBuildPinCleanup>,
    conversation_id: RuntimeId,
    agent_kind: AgentKind,
    base_event_cursor: StreamCursor,
    configuration_state: Option<ConversationConfigurationState>,
    capabilities: Option<SessionCapabilities>,
}

impl std::fmt::Debug for SnapshotBuildInput {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SnapshotBuildInput")
            .field("conversation_id", &self.conversation_id)
            .field("agent_kind", &self.agent_kind)
            .field("base_event_cursor", &self.base_event_cursor)
            .finish_non_exhaustive()
    }
}

impl SnapshotBuildInput {
    #[must_use]
    pub const fn conversation_id(&self) -> RuntimeId {
        self.conversation_id
    }

    #[must_use]
    pub const fn agent_kind(&self) -> AgentKind {
        self.agent_kind
    }

    #[must_use]
    pub const fn base_event_cursor(&self) -> StreamCursor {
        self.base_event_cursor
    }

    #[must_use]
    pub fn capabilities(&self) -> Option<&SessionCapabilities> {
        self.capabilities.as_ref()
    }

    #[must_use]
    pub fn configuration_state(&self) -> Option<&ConversationConfigurationState> {
        self.configuration_state.as_ref()
    }

    pub(crate) fn replay_pin(
        &self,
    ) -> Result<RuntimeSnapshotBuildPin, SnapshotMaterializationError> {
        self.pin
            .clone()
            .ok_or(SnapshotMaterializationError::InvalidState)
    }

    fn binding(&self) -> Result<SnapshotBuildBinding, SnapshotMaterializationError> {
        let pin = self
            .pin
            .as_ref()
            .ok_or(SnapshotMaterializationError::InvalidState)?;
        Ok(SnapshotBuildBinding {
            pin_id: pin.build_binding_id(),
            conversation_id: self.conversation_id,
            base_event_cursor: self.base_event_cursor,
        })
    }

    /// 只有 exact binding 完全一致时才移动 pin。mismatch 返回前不会消费 pin，
    /// 调用方仍可显式 release 当前 BuildInput。
    pub fn bind_assembled_snapshot(
        &mut self,
        assembled: AssembledConversationSnapshot,
    ) -> Result<PreparedConversationSnapshotWrite, SnapshotMaterializationError> {
        if assembled.binding != self.binding()? {
            return Err(SnapshotMaterializationError::SchemaIncompatible);
        }
        let cleanup = self
            .cleanup
            .take()
            .ok_or(SnapshotMaterializationError::InvalidState)?;
        let pin = self
            .pin
            .take()
            .ok_or(SnapshotMaterializationError::InvalidState)?;
        Ok(PreparedConversationSnapshotWrite::new(
            pin,
            assembled.item_count,
            assembled.canonical_payload,
            cleanup,
        ))
    }
}

/// NativeProjected conversation 的线性 dynamic handoff。它持有与 barrier H 绑定的
/// TEMP pin 与 cleanup，但故意没有 `bind_assembled_snapshot`，因此调用链无法把 native
/// transcript 正文写入 durable snapshot store。
pub struct DynamicSnapshotInput {
    pin: Option<RuntimeSnapshotBuildPin>,
    cleanup: Option<SnapshotBuildPinCleanup>,
    conversation_id: RuntimeId,
    adapter_state_key: RuntimeId,
    agent_kind: AgentKind,
    catalog_revision: u64,
    base_event_cursor: StreamCursor,
    configuration_state: Option<ConversationConfigurationState>,
    capabilities: Option<SessionCapabilities>,
}

impl std::fmt::Debug for DynamicSnapshotInput {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DynamicSnapshotInput")
            .field("conversation_id", &self.conversation_id)
            .field("agent_kind", &self.agent_kind)
            .field("base_event_cursor", &self.base_event_cursor)
            .finish_non_exhaustive()
    }
}

impl DynamicSnapshotInput {
    #[must_use]
    pub const fn conversation_id(&self) -> RuntimeId {
        self.conversation_id
    }

    #[must_use]
    pub const fn adapter_state_key(&self) -> RuntimeId {
        self.adapter_state_key
    }

    #[must_use]
    pub const fn agent_kind(&self) -> AgentKind {
        self.agent_kind
    }

    #[must_use]
    pub const fn base_event_cursor(&self) -> StreamCursor {
        self.base_event_cursor
    }

    pub(crate) fn matches_revalidated_context(
        &self,
        context: &AuthenticatedConversationSnapshotContext,
    ) -> bool {
        context.origin == SnapshotOrigin::NativeProjected
            && context.conversation_id == self.conversation_id
            && context.adapter_state_key == self.adapter_state_key
            && context.agent_kind == self.agent_kind
            && context.catalog_revision == self.catalog_revision
            && context.command_high_water.is_none()
            && context.event_high_water == self.base_event_cursor.high_water()
    }

    #[must_use]
    pub fn capabilities(&self) -> Option<&SessionCapabilities> {
        self.capabilities.as_ref()
    }

    #[must_use]
    pub fn configuration_state(&self) -> Option<&ConversationConfigurationState> {
        self.configuration_state.as_ref()
    }

    pub(crate) fn replay_pin(
        &self,
    ) -> Result<RuntimeSnapshotBuildPin, SnapshotMaterializationError> {
        self.pin
            .clone()
            .ok_or(SnapshotMaterializationError::InvalidState)
    }
}

/// 组装 seam 只消费 capabilities 与 cursor-selected configuration，exact pin ownership 仍由 BuildInput 持有，
/// 直到成功 bind 或显式 release。这样 raw 分配时不会与原 input 的 typed
/// capabilities 同时驻留；item/entity/command identity 原样进入 DTO。
pub fn assemble_build_snapshot(
    input: &mut SnapshotBuildInput,
    agent_items: Vec<SnapshotItem>,
) -> Result<AssembledConversationSnapshot, SnapshotMaterializationError> {
    let binding = input.binding()?;
    if input.capabilities.is_none() || input.configuration_state.is_none() {
        return Err(SnapshotMaterializationError::InvalidState);
    }
    let capabilities = input
        .capabilities
        .take()
        .ok_or(SnapshotMaterializationError::InvalidState)?;
    let configuration_state = input
        .configuration_state
        .take()
        .ok_or(SnapshotMaterializationError::InvalidState)?;
    assemble_snapshot(
        SnapshotAssemblyContext {
            conversation_id: input.conversation_id,
            base_event_cursor: input.base_event_cursor,
            configuration_state,
            capabilities,
            binding,
        },
        agent_items,
    )
}

pub(crate) struct AssembledDynamicSnapshot {
    snapshot: ConversationSnapshot,
    canonical_payload: Vec<u8>,
}

impl AssembledDynamicSnapshot {
    pub(crate) fn into_parts(self) -> (ConversationSnapshot, Vec<u8>) {
        (self.snapshot, self.canonical_payload)
    }
}

/// NativeProjected 的 ephemeral assembly。10,000 限额只计算原生正文 item；
/// mandatory Capabilities 另占一项，不改变 durable Ready/Build 的 10,000 total cap。
pub(crate) fn assemble_dynamic_snapshot(
    input: &mut DynamicSnapshotInput,
    agent_items: Vec<SnapshotItem>,
) -> Result<AssembledDynamicSnapshot, SnapshotMaterializationError> {
    if agent_items.len() > MAX_CANONICAL_NATIVE_HISTORY_ITEMS
        || input.capabilities.is_none()
        || input.configuration_state.is_none()
    {
        return Err(if agent_items.len() > MAX_CANONICAL_NATIVE_HISTORY_ITEMS {
            SnapshotMaterializationError::PayloadTooLarge
        } else {
            SnapshotMaterializationError::InvalidState
        });
    }
    let pin = input.replay_pin()?;
    if pin.conversation_id() != input.conversation_id
        || pin.base_event_seq() != input.base_event_cursor.high_water()
    {
        return Err(SnapshotMaterializationError::InvalidState);
    }
    validate_unique_agent_item_ids(&agent_items)?;
    let capabilities = input
        .capabilities
        .take()
        .ok_or(SnapshotMaterializationError::InvalidState)?;
    let configuration_state = input
        .configuration_state
        .take()
        .ok_or(SnapshotMaterializationError::InvalidState)?;
    let mut items = Vec::with_capacity(
        agent_items
            .len()
            .checked_add(1)
            .ok_or(SnapshotMaterializationError::PayloadTooLarge)?,
    );
    items.push(SnapshotItem::capabilities(capabilities));
    items.extend(agent_items);
    let snapshot = ConversationSnapshot::new(
        ConversationId::new(input.conversation_id.to_canonical_string()),
        input.base_event_cursor,
        configuration_state,
        items,
    )
    .map_err(|_| SnapshotMaterializationError::SchemaIncompatible)?;
    let canonical_payload = serialize_build_snapshot(&snapshot, None)?;
    Ok(AssembledDynamicSnapshot {
        snapshot,
        canonical_payload,
    })
}

#[derive(Debug)]
#[allow(
    clippy::large_enum_variant,
    reason = "416-byte linear BuildInput avoids a separate heap allocation and exact memory-accounting branch"
)]
pub enum SnapshotMaterialization {
    Ready(MaterializedConversationSnapshot),
    Build(SnapshotBuildInput),
    Dynamic(DynamicSnapshotInput),
}

pub struct SnapshotMaterializer {
    store: RuntimeStoreHandle,
    router: std::sync::Arc<AgentRouter>,
}

impl SnapshotMaterializer {
    #[must_use]
    pub fn new(store: RuntimeStoreHandle, router: std::sync::Arc<AgentRouter>) -> Self {
        Self { store, router }
    }

    /// Production registration handoff 的唯一正常入口。source 已经线性持有 capture
    /// 时建立的同一 cleanup guard，materializer 不会重建 pin ownership。
    pub async fn materialize(
        &self,
        source: SnapshotMaterializationSource,
    ) -> Result<SnapshotMaterialization, SnapshotMaterializationError> {
        let (source, cleanup) = source.into_parts();
        match (source, cleanup) {
            (SnapshotBarrierSource::Ready(reference), None) => {
                self.materialize_ready(reference).await
            }
            (SnapshotBarrierSource::Build(pin), Some(cleanup)) => {
                self.prepare_build(pin, cleanup).await
            }
            (SnapshotBarrierSource::Dynamic(pin), Some(cleanup)) => {
                self.prepare_dynamic(pin, cleanup).await
            }
            (SnapshotBarrierSource::Build(pin), None) => Err(self
                .release_pin_after_error(pin, None, SnapshotMaterializationError::InvalidState)
                .await),
            (SnapshotBarrierSource::Dynamic(pin), None) => Err(self
                .release_pin_after_error(pin, None, SnapshotMaterializationError::InvalidState)
                .await),
            (SnapshotBarrierSource::Ready(_), Some(_)) => {
                Err(SnapshotMaterializationError::InvalidState)
            }
        }
    }

    pub async fn release_build_input(
        &self,
        mut input: SnapshotBuildInput,
    ) -> Result<(), SnapshotMaterializationError> {
        let pin = input
            .pin
            .take()
            .ok_or(SnapshotMaterializationError::InvalidState)?;
        let mut cleanup = input
            .cleanup
            .take()
            .ok_or(SnapshotMaterializationError::InvalidState)?;
        match self.store.release_snapshot_build_pin(pin).await {
            Ok(()) => {
                cleanup.disarm();
                Ok(())
            }
            Err(error) => Err(SnapshotMaterializationError::Store(error)),
        }
    }

    pub async fn release_dynamic_input(
        &self,
        mut input: DynamicSnapshotInput,
    ) -> Result<(), SnapshotMaterializationError> {
        let pin = input
            .pin
            .take()
            .ok_or(SnapshotMaterializationError::InvalidState)?;
        let mut cleanup = input
            .cleanup
            .take()
            .ok_or(SnapshotMaterializationError::InvalidState)?;
        match self.store.release_snapshot_build_pin(pin).await {
            Ok(()) => {
                cleanup.disarm();
                Ok(())
            }
            Err(error) => Err(SnapshotMaterializationError::Store(error)),
        }
    }

    async fn materialize_ready(
        &self,
        reference: ReadySnapshotReference,
    ) -> Result<SnapshotMaterialization, SnapshotMaterializationError> {
        let RuntimeStreamTarget::Conversation(conversation_id) = reference.target else {
            return Err(SnapshotMaterializationError::SchemaIncompatible);
        };

        // 顺序是安全边界：先完成小型 authenticated parent read，再申请 exact
        // snapshot 的整池 128 MiB lease。绝不能反过来持有 lease 后申请第二次 read。
        let context = self
            .store
            .load_authenticated_conversation_snapshot_context(conversation_id)
            .await
            .map_err(map_ready_store_error)?;
        if context.origin != SnapshotOrigin::Managed
            || reference.base.high_water() > context.event_high_water
        {
            return Err(SnapshotMaterializationError::SchemaIncompatible);
        }
        // configuration selector 的错误来源必须保留：row AEAD/generation 故障继续
        // 是 crypto failure；只有已解码 ready DTO 与 selector 不一致才是 schema。
        let expected_configuration_state = self
            .store
            .load_configuration_state_at_event_cursor(conversation_id, reference.base.high_water())
            .await
            .map_err(SnapshotMaterializationError::Store)?;
        let validation_reference = reference.clone();
        let mut stored = self
            .store
            .load_conversation_snapshot_by_reference(reference)
            .await
            .map_err(map_ready_store_error)?;
        let decoded = decode_ready_snapshot_with_configuration(
            &stored.payload,
            stored.payload.capacity(),
            &expected_configuration_state,
        )?;
        validate_ready_snapshot(
            &context,
            &validation_reference,
            &expected_configuration_state,
            &decoded.snapshot,
        )?;
        drop(expected_configuration_state);
        let wire_payload = if decoded.legacy_v4 {
            // 威胁场景：升级后若把已认证的 v1 JSON 原样交给 v2 client，缺失的
            // configurationState 会让 client 拒绝或误用默认策略。先释放旧 raw
            // allocation，再按现有 64/128 MiB 门禁生成唯一的 v2 wire；DB 不改写。
            drop(std::mem::take(&mut stored.payload));
            Some(serialize_build_snapshot(&decoded.snapshot, None)?)
        } else {
            None
        };
        drop(decoded.snapshot);
        Ok(SnapshotMaterialization::Ready(
            MaterializedConversationSnapshot {
                stored,
                wire_payload,
            },
        ))
    }

    async fn prepare_build(
        &self,
        pin: RuntimeSnapshotBuildPin,
        cleanup: SnapshotBuildPinCleanup,
    ) -> Result<SnapshotMaterialization, SnapshotMaterializationError> {
        let mut cleanup = Some(cleanup);
        let context = match self
            .store
            .prepare_authenticated_snapshot_build_context(pin.clone())
            .await
        {
            Ok(context) => context,
            Err(error) => {
                return Err(self
                    .release_pin_after_error(
                        pin,
                        cleanup.take(),
                        SnapshotMaterializationError::Store(error),
                    )
                    .await);
            }
        };
        if context.origin != SnapshotOrigin::Managed {
            return Err(self
                .release_pin_after_error(
                    pin,
                    cleanup.take(),
                    SnapshotMaterializationError::InvalidState,
                )
                .await);
        }
        let configuration_state = match self
            .store
            .load_configuration_state_at_event_cursor(context.conversation_id, pin.base_event_seq())
            .await
        {
            Ok(configuration_state) => configuration_state,
            Err(error) => {
                return Err(self
                    .release_pin_after_error(
                        pin,
                        cleanup.take(),
                        SnapshotMaterializationError::Store(error),
                    )
                    .await);
            }
        };
        let Some(capabilities) = self.router.capabilities(context.agent_kind) else {
            return Err(self
                .release_pin_after_error(
                    pin,
                    cleanup.take(),
                    SnapshotMaterializationError::FeatureUnavailable,
                )
                .await);
        };
        if capabilities.agent_kind != context.agent_kind {
            return Err(self
                .release_pin_after_error(
                    pin,
                    cleanup.take(),
                    SnapshotMaterializationError::FeatureUnavailable,
                )
                .await);
        }

        Ok(SnapshotMaterialization::Build(SnapshotBuildInput {
            conversation_id: context.conversation_id,
            agent_kind: context.agent_kind,
            base_event_cursor: StreamCursor::from_high_water(pin.base_event_seq()),
            configuration_state: Some(configuration_state),
            capabilities: Some(capabilities),
            pin: Some(pin),
            cleanup,
        }))
    }

    async fn prepare_dynamic(
        &self,
        pin: RuntimeSnapshotBuildPin,
        cleanup: SnapshotBuildPinCleanup,
    ) -> Result<SnapshotMaterialization, SnapshotMaterializationError> {
        let mut cleanup = Some(cleanup);
        let context = match self
            .store
            .prepare_authenticated_snapshot_build_context(pin.clone())
            .await
        {
            Ok(context) => context,
            Err(error) => {
                return Err(self
                    .release_pin_after_error(
                        pin,
                        cleanup.take(),
                        SnapshotMaterializationError::Store(error),
                    )
                    .await);
            }
        };
        if context.origin != SnapshotOrigin::NativeProjected || context.command_high_water.is_some()
        {
            return Err(self
                .release_pin_after_error(
                    pin,
                    cleanup.take(),
                    SnapshotMaterializationError::InvalidState,
                )
                .await);
        }
        let configuration_state = match self
            .store
            .load_configuration_state_at_event_cursor(context.conversation_id, pin.base_event_seq())
            .await
        {
            Ok(configuration_state) => configuration_state,
            Err(error) => {
                return Err(self
                    .release_pin_after_error(
                        pin,
                        cleanup.take(),
                        SnapshotMaterializationError::Store(error),
                    )
                    .await);
            }
        };
        let Some(capabilities) = self.router.capabilities(context.agent_kind) else {
            return Err(self
                .release_pin_after_error(
                    pin,
                    cleanup.take(),
                    SnapshotMaterializationError::FeatureUnavailable,
                )
                .await);
        };
        if capabilities.agent_kind != context.agent_kind {
            return Err(self
                .release_pin_after_error(
                    pin,
                    cleanup.take(),
                    SnapshotMaterializationError::FeatureUnavailable,
                )
                .await);
        }
        Ok(SnapshotMaterialization::Dynamic(DynamicSnapshotInput {
            pin: Some(pin.clone()),
            cleanup,
            conversation_id: context.conversation_id,
            adapter_state_key: context.adapter_state_key,
            agent_kind: context.agent_kind,
            catalog_revision: context.catalog_revision,
            base_event_cursor: StreamCursor::from_high_water(pin.base_event_seq()),
            configuration_state: Some(configuration_state),
            capabilities: Some(capabilities),
        }))
    }

    async fn release_pin_after_error(
        &self,
        pin: RuntimeSnapshotBuildPin,
        cleanup: Option<SnapshotBuildPinCleanup>,
        error: SnapshotMaterializationError,
    ) -> SnapshotMaterializationError {
        let mut cleanup = cleanup;
        match self.store.release_snapshot_build_pin(pin).await {
            Ok(()) => {
                if let Some(cleanup) = &mut cleanup {
                    cleanup.disarm();
                }
                error
            }
            Err(cleanup_error) => SnapshotMaterializationError::Store(cleanup_error),
        }
    }
}

#[cfg(test)]
#[path = "snapshot/tests.rs"]
mod tests;
