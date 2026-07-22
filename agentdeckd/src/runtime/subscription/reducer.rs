//! Durable RuntimeEvent → conversation snapshot reducer source。
//!
//! 这里只消费 canonical RuntimeEvent 的稳定 item/entity/command identity；vendor
//! history 没有这些身份时 fail-close，不能用临时序号伪造可重放 snapshot。

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use agentdeck_protocol::runtime::identity::{CommandId, EntityId, ItemId};
use agentdeck_protocol::runtime::{
    ConversationSnapshot, RuntimeEventBody, SnapshotItem, StreamCursor,
};
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard, OwnedSemaphorePermit, Semaphore};

use crate::agent::{
    CanonicalNativeHistoryRead, NativeHistoryReadError, NativeItemKey, NativeTurnKey,
};
use crate::runtime::AgentRouter;
use crate::runtime::events::{SnapshotBarrierSource, SnapshotMaterializationSource};
use crate::runtime::model::RuntimeStoreError;
use crate::runtime::snapshot::{
    ConversationSnapshotBudgetEstimator, DynamicSnapshotInput, SNAPSHOT_BUILD_MEMORY_BYTES,
    SharedSnapshotBuildPermit, SnapshotMaterialization, SnapshotMaterializationError,
    SnapshotMaterializer, assemble_build_snapshot, assemble_dynamic_snapshot,
    conversation_snapshot_reference_peak_bound,
};
use crate::runtime::store::{
    NativeHistoryIdentityError, RuntimeId, RuntimeStoreHandle, StoredConversationSnapshot,
};

#[derive(Debug, thiserror::Error)]
pub(super) enum SnapshotReducerError {
    #[error(transparent)]
    Materialize(#[from] SnapshotMaterializationError),
    #[error("snapshot build memory budget is closed")]
    BudgetClosed,
    #[error("snapshot store failed: {0}")]
    Store(#[from] RuntimeStoreError),
    #[error("snapshot payload is not canonical Runtime DTO")]
    Decode,
    #[error("native history read failed")]
    NativeRead,
    #[error("native history identity derivation failed")]
    Identity,
}

pub(super) struct ReducedConversationSnapshot {
    snapshot: ConversationSnapshot,
    payload: ReducedSnapshotPayload,
    history_command_ids: Option<Vec<RuntimeId>>,
    memory_permit: SharedSnapshotBuildPermit,
}

pub(super) enum ReducedSnapshotPayload {
    Durable {
        stored: StoredConversationSnapshot,
        wire_payload: Option<Vec<u8>>,
    },
    Dynamic {
        canonical_payload: Vec<u8>,
        input: Box<DynamicSnapshotInput>,
    },
    Transition {
        canonical_payload: Vec<u8>,
        input: Box<crate::runtime::snapshot::SnapshotBuildInput>,
    },
}

impl ReducedSnapshotPayload {
    pub(super) fn canonical_payload(&self) -> &[u8] {
        match self {
            Self::Durable {
                stored,
                wire_payload,
            } => wire_payload.as_deref().unwrap_or(stored.payload.as_slice()),
            Self::Dynamic {
                canonical_payload, ..
            }
            | Self::Transition {
                canonical_payload, ..
            } => canonical_payload,
        }
    }

    pub(super) async fn release_after_flush(
        self,
        store: &RuntimeStoreHandle,
        router: Arc<AgentRouter>,
    ) -> Result<(), SnapshotReducerError> {
        match self {
            Self::Dynamic { input, .. } => {
                SnapshotMaterializer::new(store.clone(), router)
                    .release_dynamic_input(*input)
                    .await?;
            }
            Self::Transition { input, .. } => {
                SnapshotMaterializer::new(store.clone(), router)
                    .release_build_input(*input)
                    .await?;
            }
            Self::Durable { .. } => {}
        }
        Ok(())
    }
}

impl ReducedConversationSnapshot {
    pub(super) fn into_parts(
        self,
    ) -> (
        ConversationSnapshot,
        ReducedSnapshotPayload,
        Option<Vec<RuntimeId>>,
        SharedSnapshotBuildPermit,
    ) {
        (
            self.snapshot,
            self.payload,
            self.history_command_ids,
            self.memory_permit,
        )
    }
}

pub(super) async fn materialize(
    store: &RuntimeStoreHandle,
    router: Arc<AgentRouter>,
    source: SnapshotMaterializationSource,
    build_budget: Arc<Semaphore>,
    build_gate: Arc<AsyncMutex<()>>,
) -> Result<ReducedConversationSnapshot, SnapshotReducerError> {
    let build_source = matches!(
        source.source(),
        SnapshotBarrierSource::Build(_)
            | SnapshotBarrierSource::TransitionBuild(_)
            | SnapshotBarrierSource::Dynamic(_)
    );
    // 威胁场景：Build 已持 bootstrap permit 时，Ready 若先把整池申请排进公平
    // semaphore，Build 后续 upgrade 会永远排在无法满足的 Ready 后面。所有初始
    // reservation 因此都先过 gate；Ready 取得完整 permit 后立即释放，Build 则持有
    // gate 直到 grow/materialize/store 全部完成。
    let initial_bytes = match source.source() {
        SnapshotBarrierSource::Ready(reference) => conversation_snapshot_reference_peak_bound(
            reference.logical_bytes,
            reference.item_count,
        )?,
        SnapshotBarrierSource::Build(_)
        | SnapshotBarrierSource::TransitionBuild(_)
        | SnapshotBarrierSource::Dynamic(_) => {
            ConversationSnapshotBudgetEstimator::bootstrap_bound()?
        }
    };
    let (mut memory, _build_guard) =
        reserve_initial_snapshot_memory(build_budget, build_gate, initial_bytes, build_source)
            .await?;
    let materializer = SnapshotMaterializer::new(store.clone(), router.clone());
    match materializer.materialize(source).await? {
        SnapshotMaterialization::Ready(snapshot) => {
            let (stored, wire_payload) = snapshot.into_parts();
            let canonical_payload = wire_payload.as_deref().unwrap_or(stored.payload.as_slice());
            let decoded = serde_json::from_slice(canonical_payload)
                .map_err(|_| SnapshotReducerError::Decode)?;
            Ok(ReducedConversationSnapshot {
                snapshot: decoded,
                payload: ReducedSnapshotPayload::Durable {
                    stored,
                    wire_payload,
                },
                history_command_ids: None,
                memory_permit: memory.into_permit()?,
            })
        }
        SnapshotMaterialization::Build(mut input) => {
            let capabilities = input.capabilities().ok_or(SnapshotReducerError::Decode)?;
            let configuration_state = input
                .configuration_state()
                .ok_or(SnapshotReducerError::Decode)?;
            let mut estimator =
                ConversationSnapshotBudgetEstimator::new(capabilities, configuration_state)?;
            memory.grow_to(estimator.current_bound()?).await?;
            let items = load_stable_items(store, &input, &mut memory, &mut estimator).await?;
            memory
                .grow_to(estimator.final_build_peak(&input, &items)?)
                .await?;
            let assembled = assemble_build_snapshot(&mut input, items)?;
            let write = input.bind_assembled_snapshot(assembled)?;
            let memory_permit = memory.into_permit()?;
            let stored = store
                .store_conversation_snapshot_guarded(write, memory_permit.clone())
                .await
                .map_err(|error| SnapshotReducerError::Store(error.into_error()))?;
            let decoded = serde_json::from_slice(&stored.payload)
                .map_err(|_| SnapshotReducerError::Decode)?;
            Ok(ReducedConversationSnapshot {
                snapshot: decoded,
                payload: ReducedSnapshotPayload::Durable {
                    stored,
                    wire_payload: None,
                },
                history_command_ids: None,
                memory_permit,
            })
        }
        SnapshotMaterialization::TransitionBuild(mut input) => {
            let capabilities = input.capabilities().ok_or(SnapshotReducerError::Decode)?;
            let configuration_state = input
                .configuration_state()
                .ok_or(SnapshotReducerError::Decode)?;
            let mut estimator =
                ConversationSnapshotBudgetEstimator::new(capabilities, configuration_state)?;
            memory.grow_to(estimator.current_bound()?).await?;
            let items = load_stable_items(store, &input, &mut memory, &mut estimator).await?;
            memory
                .grow_to(estimator.final_build_peak(&input, &items)?)
                .await?;
            let assembled = assemble_build_snapshot(&mut input, items)?;
            let (snapshot, canonical_payload) = input.bind_assembled_transition_read(assembled)?;
            Ok(ReducedConversationSnapshot {
                snapshot,
                payload: ReducedSnapshotPayload::Transition {
                    canonical_payload,
                    input: Box::new(input),
                },
                history_command_ids: None,
                memory_permit: memory.into_permit()?,
            })
        }
        SnapshotMaterialization::Dynamic(mut input) => {
            // Native reader 可继续运行到 spawn_blocking 完成，即使外层 subscription
            // future 因 disconnect/TTL 被取消。先占满共享 128 MiB 池，再把一个共享
            // permit clone 移入独立 owner task，取消时不会提前放开第二个大 build。
            // 主 permit 还会随 reduced result 持有到 pump 的 receipt replace 与 wire
            // flush 之后；所以后续 Dynamic 即使取得 build gate，也无法完成 bootstrap
            // reservation、更不可能在前一份 receipt set 线性化之前进入 native reader。
            memory.grow_to(SNAPSHOT_BUILD_MEMORY_BYTES).await?;
            let memory_permit = memory.into_permit()?;
            let reader_permit = memory_permit.clone();
            let reader = router.clone();
            let adapter_state_key = input.adapter_state_key();
            let agent_kind = input.agent_kind();
            let read_task = tokio::spawn(async move {
                let _reader_permit = reader_permit;
                reader
                    .read_native_history(adapter_state_key, agent_kind)
                    .await
            });
            let read = read_task
                .await
                .map_err(|_| SnapshotReducerError::NativeRead)?
                .map_err(map_native_history_read_error)?;

            // Filesystem read 在 SQLite transaction 外执行；返回后必须重新认证 exact
            // projection-only witness。正常 tombstone/reappear/config/command 漂移都丢弃
            // 本次 read，绝不发布 payload 或替换 history receipt set。
            let revalidated = store
                .load_authenticated_conversation_snapshot_context(input.conversation_id())
                .await?;
            if !input.matches_revalidated_context(&revalidated) {
                return Err(SnapshotMaterializationError::InvalidState.into());
            }

            let (items, command_ids) =
                project_native_history(store, input.conversation_id(), read)?;
            let assembled = assemble_dynamic_snapshot(&mut input, items)?;
            let (snapshot, canonical_payload) = assembled.into_parts();
            Ok(ReducedConversationSnapshot {
                snapshot,
                payload: ReducedSnapshotPayload::Dynamic {
                    canonical_payload,
                    input: Box::new(input),
                },
                history_command_ids: Some(command_ids),
                memory_permit,
            })
        }
    }
}

fn map_native_history_read_error(error: NativeHistoryReadError) -> SnapshotReducerError {
    match error {
        NativeHistoryReadError::Unavailable => {
            SnapshotMaterializationError::FeatureUnavailable.into()
        }
        NativeHistoryReadError::PayloadTooLarge => {
            SnapshotMaterializationError::PayloadTooLarge.into()
        }
        NativeHistoryReadError::InvalidSource => {
            SnapshotMaterializationError::SchemaIncompatible.into()
        }
        NativeHistoryReadError::ReadUnavailable => SnapshotReducerError::NativeRead,
    }
}

fn project_native_history(
    store: &RuntimeStoreHandle,
    conversation_id: RuntimeId,
    read: CanonicalNativeHistoryRead,
) -> Result<(Vec<SnapshotItem>, Vec<RuntimeId>), SnapshotReducerError> {
    project_native_history_with(
        read,
        |turn_key| {
            store
                .derive_native_history_command_id(conversation_id, turn_key.derivation_material())
                .map_err(map_native_identity_error)
        },
        |item_key| {
            store
                .derive_native_history_item_ids(conversation_id, item_key.derivation_material())
                .map_err(map_native_identity_error)
        },
    )
}

fn map_native_identity_error(_error: NativeHistoryIdentityError) -> SnapshotReducerError {
    SnapshotReducerError::Identity
}

fn project_native_history_with(
    read: CanonicalNativeHistoryRead,
    mut derive_command: impl FnMut(&NativeTurnKey) -> Result<RuntimeId, SnapshotReducerError>,
    mut derive_item: impl FnMut(&NativeItemKey) -> Result<([u8; 16], [u8; 16]), SnapshotReducerError>,
) -> Result<(Vec<SnapshotItem>, Vec<RuntimeId>), SnapshotReducerError> {
    let (_agent_kind, native_items, _source_bytes) = read.into_parts();
    let mut items = Vec::with_capacity(native_items.len());
    let mut commands_by_turn = HashMap::<NativeTurnKey, RuntimeId>::new();
    let mut command_ids = Vec::new();
    let mut all_identity_bytes = HashSet::<[u8; 16]>::with_capacity(
        native_items
            .len()
            .checked_mul(3)
            .ok_or(SnapshotReducerError::Identity)?,
    );

    for native in native_items {
        let (turn_key, item_key, item) = native.into_parts();
        let command_id = if let Some(command_id) = commands_by_turn.get(&turn_key).copied() {
            command_id
        } else {
            let command_id = derive_command(&turn_key)?;
            if !all_identity_bytes.insert(*command_id.as_bytes()) {
                return Err(SnapshotReducerError::Identity);
            }
            commands_by_turn.insert(turn_key, command_id);
            command_ids.push(command_id);
            command_id
        };
        let (item_id, entity_id) = derive_item(&item_key)?;
        if item_id == entity_id
            || !all_identity_bytes.insert(item_id)
            || !all_identity_bytes.insert(entity_id)
        {
            return Err(SnapshotReducerError::Identity);
        }
        items.push(SnapshotItem::Item {
            item_id: ItemId::new(uuid::Uuid::from_bytes(item_id).hyphenated().to_string()),
            entity_id: EntityId::new(uuid::Uuid::from_bytes(entity_id).hyphenated().to_string()),
            command_id: Some(CommandId::new(command_id.to_canonical_string())),
            item,
        });
    }
    if command_ids.len() > crate::runtime::history_receipt::MAX_HISTORY_COMMAND_IDS_PER_CONVERSATION
    {
        return Err(SnapshotMaterializationError::PayloadTooLarge.into());
    }
    Ok((items, command_ids))
}

async fn reserve_initial_snapshot_memory(
    build_budget: Arc<Semaphore>,
    build_gate: Arc<AsyncMutex<()>>,
    initial_bytes: usize,
    retain_gate: bool,
) -> Result<(SnapshotMemoryLease, Option<OwnedMutexGuard<()>>), SnapshotReducerError> {
    let guard = build_gate.lock_owned().await;
    let memory = SnapshotMemoryLease::reserve(build_budget, initial_bytes).await?;
    let retained_guard = retain_gate.then_some(guard);
    Ok((memory, retained_guard))
}

async fn load_stable_items(
    store: &RuntimeStoreHandle,
    input: &crate::runtime::snapshot::SnapshotBuildInput,
    memory: &mut SnapshotMemoryLease,
    estimator: &mut ConversationSnapshotBudgetEstimator,
) -> Result<Vec<SnapshotItem>, SnapshotReducerError> {
    let StreamCursor::At(through) = input.base_event_cursor() else {
        return Ok(Vec::new());
    };
    let pin = input.replay_pin()?;
    if pin.base_event_seq() != Some(through) {
        return Err(SnapshotReducerError::Decode);
    }
    // 威胁场景：一个接近 64 MiB/10,000-event 上限的真实会话若先累计完整
    // RuntimeEvent Vec 再生成 SnapshotItem，会让 raw DTO 与 reducer state 同时
    // 常驻并越过 128 MiB build 上限；因此这里只保留一页 read-pool lease。
    let mut reducer = StableItemReducer::default();
    let mut after = None;
    loop {
        let (events, next_after, complete, lease) = store
            .load_snapshot_event_page(pin.clone(), after)
            .await
            .map_err(SnapshotMaterializationError::Store)?;
        // 页仍由 read-pool lease 计费；在把 nested allocations 移入长期 reducer
        // 之前，先把它们的 conservative retained 上界加入共享 build budget。
        memory
            .grow_to(estimator.observe_event_page(&events)?)
            .await?;
        reducer.extend(events)?;
        // 本页的 nested allocations 已经移动进 reducer；页 Vec 与 read-pool
        // retained lease 在读取下一页前一并释放。
        drop(lease);
        after = Some(next_after);
        if complete {
            break;
        }
    }
    Ok(reducer.into_items())
}

struct SnapshotMemoryLease {
    budget: Arc<Semaphore>,
    permit: Option<OwnedSemaphorePermit>,
    bytes: usize,
}

impl SnapshotMemoryLease {
    async fn reserve(budget: Arc<Semaphore>, bytes: usize) -> Result<Self, SnapshotReducerError> {
        let permits = u32::try_from(bytes).map_err(|_| SnapshotReducerError::Decode)?;
        let permit = budget
            .clone()
            .acquire_many_owned(permits)
            .await
            .map_err(|_| SnapshotReducerError::BudgetClosed)?;
        Ok(Self {
            budget,
            permit: Some(permit),
            bytes,
        })
    }

    async fn grow_to(&mut self, target: usize) -> Result<(), SnapshotReducerError> {
        if target <= self.bytes {
            return Ok(());
        }
        let additional = target - self.bytes;
        let permits = u32::try_from(additional).map_err(|_| SnapshotReducerError::Decode)?;
        let permit = self
            .budget
            .clone()
            .acquire_many_owned(permits)
            .await
            .map_err(|_| SnapshotReducerError::BudgetClosed)?;
        self.permit
            .as_mut()
            .ok_or(SnapshotReducerError::BudgetClosed)?
            .merge(permit);
        self.bytes = target;
        Ok(())
    }

    fn into_permit(mut self) -> Result<SharedSnapshotBuildPermit, SnapshotReducerError> {
        self.permit
            .take()
            .map(SharedSnapshotBuildPermit::new)
            .ok_or(SnapshotReducerError::BudgetClosed)
    }
}

#[cfg(test)]
fn reduce_stable_items(
    events: impl IntoIterator<Item = agentdeck_protocol::runtime::RuntimeEvent>,
) -> Result<Vec<SnapshotItem>, SnapshotReducerError> {
    let mut reducer = StableItemReducer::default();
    reducer.extend(events)?;
    Ok(reducer.into_items())
}

#[derive(Default)]
struct StableItemReducer {
    items: Vec<SnapshotItem>,
    item_positions: HashMap<String, usize>,
    entity_positions: HashMap<String, usize>,
}

impl StableItemReducer {
    fn extend(
        &mut self,
        events: impl IntoIterator<Item = agentdeck_protocol::runtime::RuntimeEvent>,
    ) -> Result<(), SnapshotReducerError> {
        for event in events {
            if let RuntimeEventBody::Item { item } = event.body {
                let (Some(item_id), Some(entity_id)) = (event.item_id, event.entity_id) else {
                    return Err(SnapshotReducerError::Decode);
                };
                let item_key = item_id.as_str().to_owned();
                let entity_key = entity_id.as_str().to_owned();
                let next = SnapshotItem::Item {
                    item_id,
                    entity_id,
                    command_id: event.command_id,
                    item,
                };
                match (
                    self.item_positions.get(&item_key).copied(),
                    self.entity_positions.get(&entity_key).copied(),
                ) {
                    (None, None) => {
                        let position = self.items.len();
                        self.item_positions.insert(item_key, position);
                        self.entity_positions.insert(entity_key, position);
                        self.items.push(next);
                    }
                    (Some(item_position), Some(entity_position))
                        if item_position == entity_position =>
                    {
                        let SnapshotItem::Item {
                            command_id: previous_command,
                            ..
                        } = &self.items[item_position]
                        else {
                            return Err(SnapshotReducerError::Decode);
                        };
                        let SnapshotItem::Item {
                            command_id: next_command,
                            ..
                        } = &next
                        else {
                            return Err(SnapshotReducerError::Decode);
                        };
                        if previous_command != next_command {
                            return Err(SnapshotReducerError::Decode);
                        }
                        // 同一稳定 UI 实体的后续 event 是 deterministic final-state
                        // update；保留首次出现的位置，只替换最终内容。
                        self.items[item_position] = next;
                    }
                    _ => return Err(SnapshotReducerError::Decode),
                }
            }
        }
        Ok(())
    }

    fn into_items(self) -> Vec<SnapshotItem> {
        self.items
    }
}

#[cfg(test)]
mod tests {
    use std::future::{Future, poll_fn};
    use std::task::Poll;

    use agentdeck_protocol::runtime::identity::{
        CommandId, ConversationId, EntityId, EventId, ItemId,
    };
    use agentdeck_protocol::runtime::{RuntimeEvent, RuntimeEventBody};
    use agentdeck_protocol::{AgentItem, AgentItemMeta, AgentKind};

    use super::*;

    fn item_event(
        sequence: u64,
        item_id: &str,
        entity_id: &str,
        command_id: &str,
        text: &str,
    ) -> RuntimeEvent {
        RuntimeEvent::new(
            ConversationId::new("conversation-1"),
            EventId::new(format!("event-{sequence}")),
            sequence,
            Some(CommandId::new(command_id)),
            Some(ItemId::new(item_id)),
            Some(EntityId::new(entity_id)),
            RuntimeEventBody::Item {
                item: AgentItem::UserMessage {
                    text: text.to_owned(),
                    meta: AgentItemMeta::default(),
                },
            },
        )
        .expect("valid item event")
    }

    fn native_item(
        turn_seed: u8,
        item_seed: u8,
        text: &str,
    ) -> crate::agent::CanonicalNativeHistoryItem {
        crate::agent::CanonicalNativeHistoryItem::new(
            crate::agent::NativeTurnKey::from_verified_bytes([turn_seed; 32])
                .expect("nonzero native turn key"),
            crate::agent::NativeItemKey::from_verified_bytes([item_seed; 32])
                .expect("nonzero native item key"),
            AgentItem::AssistantMessage {
                text: text.to_owned(),
                meta: AgentItemMeta::default(),
            },
        )
        .expect("modeled native item")
    }

    fn native_read(
        items: Vec<crate::agent::CanonicalNativeHistoryItem>,
    ) -> CanonicalNativeHistoryRead {
        CanonicalNativeHistoryRead::new(AgentKind::ClaudeCode, items, 1)
            .expect("bounded native read")
    }

    fn deterministic_command(turn_key: &NativeTurnKey) -> Result<RuntimeId, SnapshotReducerError> {
        let seed = turn_key.derivation_material()[0];
        RuntimeId::from_bytes(
            crate::runtime::store::RuntimeIdKind::Command,
            [seed.wrapping_add(0x40); 16],
        )
        .map_err(|_| SnapshotReducerError::Identity)
    }

    fn deterministic_item(
        item_key: &NativeItemKey,
    ) -> Result<([u8; 16], [u8; 16]), SnapshotReducerError> {
        let seed = item_key.derivation_material()[0];
        Ok(([seed; 16], [seed.wrapping_add(0x20); 16]))
    }

    #[test]
    fn stable_identity_updates_reduce_to_the_latest_state_in_first_seen_order() {
        let reduced = reduce_stable_items([
            item_event(0, "item-a", "entity-a", "command-a", "old"),
            item_event(1, "item-b", "entity-b", "command-b", "second"),
            item_event(2, "item-a", "entity-a", "command-a", "new"),
        ])
        .expect("reduce stable updates");
        assert_eq!(reduced.len(), 2);
        let SnapshotItem::Item { item, .. } = &reduced[0] else {
            panic!("first item")
        };
        assert!(matches!(
            item,
            AgentItem::UserMessage { text, .. } if text == "new"
        ));
    }

    #[test]
    fn stable_identity_rejects_entity_alias_and_command_rebinding() {
        assert!(matches!(
            reduce_stable_items([
                item_event(0, "item-a", "entity-a", "command-a", "one"),
                item_event(1, "item-b", "entity-a", "command-b", "two"),
            ]),
            Err(SnapshotReducerError::Decode)
        ));
        assert!(matches!(
            reduce_stable_items([
                item_event(0, "item-a", "entity-a", "command-a", "one"),
                item_event(1, "item-a", "entity-a", "command-b", "two"),
            ]),
            Err(SnapshotReducerError::Decode)
        ));
    }

    #[test]
    fn native_identity_is_turn_shared_append_stable_and_cross_domain_unique() {
        let initial = native_read(vec![native_item(1, 11, "one"), native_item(1, 12, "two")]);
        let (first_items, first_commands) =
            project_native_history_with(initial, deterministic_command, deterministic_item)
                .expect("project initial native history");
        assert_eq!(first_commands.len(), 1);
        let first_wire = first_items
            .iter()
            .map(|item| match item {
                SnapshotItem::Item {
                    item_id,
                    entity_id,
                    command_id,
                    ..
                } => (
                    item_id.as_str().to_owned(),
                    entity_id.as_str().to_owned(),
                    command_id
                        .as_ref()
                        .expect("history command identity")
                        .as_str()
                        .to_owned(),
                ),
                SnapshotItem::Capabilities { .. } => panic!("native projection excludes caps"),
            })
            .collect::<Vec<_>>();
        assert_eq!(first_wire[0].2, first_wire[1].2);
        assert_ne!(first_wire[0].0, first_wire[1].0);
        assert_ne!(first_wire[0].1, first_wire[1].1);

        let appended = native_read(vec![
            native_item(1, 11, "one"),
            native_item(1, 12, "two"),
            native_item(2, 13, "three"),
        ]);
        let (appended_items, appended_commands) =
            project_native_history_with(appended, deterministic_command, deterministic_item)
                .expect("project appended native history");
        assert_eq!(appended_commands.len(), 2);
        for (before, after) in first_wire.iter().zip(appended_items.iter()) {
            let SnapshotItem::Item {
                item_id,
                entity_id,
                command_id,
                ..
            } = after
            else {
                panic!("appended native item")
            };
            assert_eq!(before.0, item_id.as_str());
            assert_eq!(before.1, entity_id.as_str());
            assert_eq!(
                before.2,
                command_id.as_ref().expect("history command").as_str()
            );
        }
    }

    #[test]
    fn native_identity_collision_or_cross_domain_alias_fails_the_whole_read() {
        let cross_domain = project_native_history_with(
            native_read(vec![native_item(1, 2, "alias")]),
            |_| {
                RuntimeId::from_bytes(crate::runtime::store::RuntimeIdKind::Command, [0x51; 16])
                    .map_err(|_| SnapshotReducerError::Identity)
            },
            |_| Ok(([0x51; 16], [0x52; 16])),
        );
        assert!(matches!(cross_domain, Err(SnapshotReducerError::Identity)));

        let item_alias = project_native_history_with(
            native_read(vec![
                native_item(1, 2, "first"),
                native_item(1, 3, "second"),
            ]),
            deterministic_command,
            |_| Ok(([0x61; 16], [0x62; 16])),
        );
        assert!(matches!(item_alias, Err(SnapshotReducerError::Identity)));

        let intra_item_alias = project_native_history_with(
            native_read(vec![native_item(1, 2, "same pair")]),
            deterministic_command,
            |_| Ok(([0x71; 16], [0x71; 16])),
        );
        assert!(matches!(
            intra_item_alias,
            Err(SnapshotReducerError::Identity)
        ));
    }

    #[test]
    fn small_snapshot_bound_is_variable_but_large_dynamic_payload_uses_full_pool() {
        let small = conversation_snapshot_reference_peak_bound(1_024, 2)
            .expect("small ready reference bound");
        assert!(small >= ConversationSnapshotBudgetEstimator::bootstrap_bound().unwrap());
        assert!(small < SNAPSHOT_BUILD_MEMORY_BYTES);
        assert_eq!(
            conversation_snapshot_reference_peak_bound(768 * 1024, 2)
                .expect("large ready reference bound"),
            SNAPSHOT_BUILD_MEMORY_BYTES
        );
    }

    #[tokio::test]
    async fn ready_full_reservation_cannot_block_inflight_build_budget_upgrade() {
        let budget = Arc::new(Semaphore::new(SNAPSHOT_BUILD_MEMORY_BYTES));
        let gate = Arc::new(AsyncMutex::new(()));
        let bootstrap = ConversationSnapshotBudgetEstimator::bootstrap_bound()
            .expect("bootstrap reservation bound");
        assert!(bootstrap < SNAPSHOT_BUILD_MEMORY_BYTES);

        let (mut build_memory, build_guard) =
            reserve_initial_snapshot_memory(budget.clone(), gate.clone(), bootstrap, true)
                .await
                .expect("reserve Build bootstrap while holding the upgrade gate");
        let build_guard = build_guard.expect("Build must retain the gate through upgrade");

        let mut ready_reservation = Box::pin(reserve_initial_snapshot_memory(
            budget.clone(),
            gate.clone(),
            SNAPSHOT_BUILD_MEMORY_BYTES,
            false,
        ));
        poll_fn(|context| {
            assert!(
                ready_reservation.as_mut().poll(context).is_pending(),
                "Ready must wait at the gate while Build can still need an upgrade"
            );
            Poll::Ready(())
        })
        .await;

        let mut upgrade = Box::pin(build_memory.grow_to(SNAPSHOT_BUILD_MEMORY_BYTES));
        poll_fn(|context| match upgrade.as_mut().poll(context) {
            Poll::Ready(result) => Poll::Ready(result),
            Poll::Pending => panic!(
                "Ready queued its full reservation ahead of the in-flight Build budget upgrade"
            ),
        })
        .await
        .expect("Build upgrade must consume the remaining permits immediately");
        drop(upgrade);
        assert_eq!(budget.available_permits(), 0);

        drop(build_guard);
        drop(build_memory);
        let (ready_memory, ready_guard) = ready_reservation
            .await
            .expect("Ready reserves the full pool after Build completes");
        assert!(
            ready_guard.is_none(),
            "Ready must release the gate immediately after its complete reservation"
        );
        assert!(
            gate.try_lock().is_ok(),
            "Ready must not retain the gate while its snapshot remains in flight"
        );
        assert_eq!(budget.available_permits(), 0);
        drop(ready_memory);
        assert_eq!(budget.available_permits(), SNAPSHOT_BUILD_MEMORY_BYTES);
    }
}
