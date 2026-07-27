//! Store-owned execution Item canonical builder。
//!
//! 威胁场景：若 adapter 或调用方能提交 raw `RuntimeEvent`/bytes，恶意或失控的
//! adapter 可伪造 command、turn、item/entity identity，或把原始错误文本写入 durable
//! audit，导致跨设备重放串到另一条执行并泄漏 vendor/private diagnostic。

use std::fmt;
use std::io::{self, Write};

use agentdeck_protocol::AgentItem;
use agentdeck_protocol::runtime::identity::{CommandId, ConversationId, EntityId, EventId, ItemId};
use agentdeck_protocol::runtime::{RuntimeEvent, RuntimeEventBody};

use crate::runtime::model::{EventRecord, MAX_RUNTIME_EVENT_BYTES, RuntimeStoreError};

use super::{RuntimeId, RuntimeIdKind};

/// RuntimeCore 提交 execution Item 的唯一 release 输入。body 完全私有，只能由
/// typed constructors 建立；调用方不能提交 raw RuntimeEvent、bytes 或 ProtocolError。
#[derive(Clone)]
pub struct AppendExecutionEvent {
    conversation_id: RuntimeId,
    command_id: RuntimeId,
    turn_id: RuntimeId,
    event_id: RuntimeId,
    body: ExecutionEventBody,
}

impl AppendExecutionEvent {
    #[must_use]
    pub fn item(
        conversation_id: RuntimeId,
        command_id: RuntimeId,
        turn_id: RuntimeId,
        event_id: RuntimeId,
        item_id: ItemId,
        entity_id: EntityId,
        item: AgentItem,
    ) -> Self {
        Self {
            conversation_id,
            command_id,
            turn_id,
            event_id,
            body: ExecutionEventBody::Item {
                item_id,
                entity_id,
                item,
            },
        }
    }

    fn into_parts(
        self,
    ) -> (
        RuntimeId,
        RuntimeId,
        RuntimeId,
        RuntimeId,
        ExecutionEventBody,
    ) {
        (
            self.conversation_id,
            self.command_id,
            self.turn_id,
            self.event_id,
            self.body,
        )
    }
}

impl fmt::Debug for AppendExecutionEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AppendExecutionEvent")
            .field("identity", &"[REDACTED]")
            .field("body", &self.body)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AppendExecutionEventOutcome {
    Appended { event: EventRecord },
    Replayed { event: EventRecord },
}

/// 一条 execution event 必须绑定的 daemon-owned durable identity。
///
/// `turn_id` 不进入当前 Runtime `Item` wire body，但会随准备结果保留，供
/// journal transaction 与当前 Started row 做 exact match；调用方不能从 adapter
/// payload 恢复或替换它。
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct ExecutionEventIdentity {
    conversation_id: RuntimeId,
    command_id: RuntimeId,
    turn_id: RuntimeId,
    event_id: RuntimeId,
    event_seq: u64,
}

impl ExecutionEventIdentity {
    pub(super) fn new(
        conversation_id: RuntimeId,
        command_id: RuntimeId,
        turn_id: RuntimeId,
        event_id: RuntimeId,
        event_seq: u64,
    ) -> Result<Self, RuntimeStoreError> {
        ensure_id_kind(conversation_id, RuntimeIdKind::Conversation)?;
        ensure_id_kind(command_id, RuntimeIdKind::Command)?;
        ensure_id_kind(turn_id, RuntimeIdKind::Turn)?;
        ensure_id_kind(event_id, RuntimeIdKind::Event)?;
        Ok(Self {
            conversation_id,
            command_id,
            turn_id,
            event_id,
            event_seq,
        })
    }
}

impl fmt::Debug for ExecutionEventIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecutionEventIdentity")
            .field("conversation_id", &"[REDACTED]")
            .field("command_id", &"[REDACTED]")
            .field("turn_id", &"[REDACTED]")
            .field("event_id", &"[REDACTED]")
            .field("event_seq", &self.event_seq)
            .finish()
    }
}

/// Store 唯一接受的 execution event typed body；没有 raw bytes/RuntimeEvent 入口。
#[derive(Clone)]
enum ExecutionEventBody {
    Item {
        item_id: ItemId,
        entity_id: EntityId,
        item: AgentItem,
    },
}

impl fmt::Debug for ExecutionEventBody {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self {
            Self::Item { .. } => "Item",
        };
        formatter
            .debug_struct("ExecutionEventBody")
            .field("kind", &kind)
            .field("payload", &"[REDACTED]")
            .finish()
    }
}

/// 已绑定 daemon identity 且通过协议上限检查的 canonical RuntimeEvent bytes。
pub(super) struct CanonicalExecutionEvent {
    identity: ExecutionEventIdentity,
    canonical_bytes: Vec<u8>,
}

impl CanonicalExecutionEvent {
    pub(super) fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    /// 以 journal 已认证的 Started row 与待写 event identity 复核完整 binding。
    /// Item/entity identity 已在私有 builder 内一次性移入 canonical RuntimeEvent；这里不再
    /// 保留第二份 String，避免 identity-heavy Item 绕过 normal lane 的 retained-byte 计费。
    pub(super) fn validate_exact_binding(
        &self,
        expected_identity: ExecutionEventIdentity,
    ) -> Result<(), RuntimeStoreError> {
        if self.identity == expected_identity {
            Ok(())
        } else {
            Err(RuntimeStoreError::InvalidStateTransition)
        }
    }
}

impl fmt::Debug for CanonicalExecutionEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CanonicalExecutionEvent")
            .field("identity", &self.identity)
            .field("canonical_bytes", &self.canonical_bytes.len())
            .finish()
    }
}

/// worker admission 后流入 journal 的 Store-owned template。它只保留 canonical bytes
/// 与 daemon identity；原始 AgentItem 已释放，不会让 64 MiB event 在队列中双份驻留。
pub(super) struct PreparedExecutionEvent {
    conversation_id: RuntimeId,
    command_id: RuntimeId,
    turn_id: RuntimeId,
    event_id: RuntimeId,
    template: CanonicalExecutionEvent,
    event_seq_value_offset: usize,
}

const MAX_EVENT_SEQ_DECIMAL_BYTES: usize = 20;

impl PreparedExecutionEvent {
    pub(super) fn from_input(input: AppendExecutionEvent) -> Result<Self, RuntimeStoreError> {
        let (conversation_id, command_id, turn_id, event_id, body) = input.into_parts();
        let identity =
            ExecutionEventIdentity::new(conversation_id, command_id, turn_id, event_id, 0)?;
        let mut template = build_execution_event(identity, body)?;
        let event_seq_value_offset =
            locate_template_event_seq(template.canonical_bytes(), conversation_id, event_id)?;
        // The template contains the one-byte decimal value `0`. Reserve the
        // remaining space for any u64 sequence while the single build permit
        // is held, so the queued retained-capacity charge also covers the
        // allocation used by the worker's in-place finalization.
        template
            .canonical_bytes
            .try_reserve_exact(MAX_EVENT_SEQ_DECIMAL_BYTES - 1)
            .map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
        Ok(Self {
            conversation_id,
            command_id,
            turn_id,
            event_id,
            template,
            event_seq_value_offset,
        })
    }

    pub(super) const fn conversation_id(&self) -> RuntimeId {
        self.conversation_id
    }

    pub(super) const fn command_id(&self) -> RuntimeId {
        self.command_id
    }

    pub(super) const fn turn_id(&self) -> RuntimeId {
        self.turn_id
    }

    pub(super) const fn event_id(&self) -> RuntimeId {
        self.event_id
    }

    pub(super) fn retained_capacity(&self) -> usize {
        self.template.canonical_bytes.capacity()
    }

    pub(super) fn canonical_len_for_seq(&self, event_seq: u64) -> Result<usize, RuntimeStoreError> {
        let sequence_len = event_seq.to_string().len();
        let final_len = self
            .template
            .canonical_bytes()
            .len()
            .checked_sub(1)
            .and_then(|length| length.checked_add(sequence_len))
            .ok_or(RuntimeStoreError::PayloadTooLarge)?;
        if final_len > MAX_RUNTIME_EVENT_BYTES {
            Err(RuntimeStoreError::PayloadTooLarge)
        } else {
            Ok(final_len)
        }
    }

    pub(super) fn into_canonical_bytes_for_seq(
        self,
        event_seq: u64,
    ) -> Result<Vec<u8>, RuntimeStoreError> {
        let expected_identity = ExecutionEventIdentity::new(
            self.conversation_id,
            self.command_id,
            self.turn_id,
            self.event_id,
            0,
        )?;
        self.template.validate_exact_binding(expected_identity)?;
        let sequence = event_seq.to_string();
        let final_len = self.canonical_len_for_seq(event_seq)?;
        let mut canonical = self.template.canonical_bytes;
        if canonical.capacity() < final_len {
            return Err(RuntimeStoreError::InvalidConfig(
                "execution event template lost its reserved sequence capacity",
            ));
        }
        let template_len = canonical.len();
        canonical.resize(final_len, 0);
        canonical.copy_within(
            self.event_seq_value_offset + 1..template_len,
            self.event_seq_value_offset + sequence.len(),
        );
        canonical[self.event_seq_value_offset..self.event_seq_value_offset + sequence.len()]
            .copy_from_slice(sequence.as_bytes());
        Ok(canonical)
    }
}

fn locate_template_event_seq(
    template: &[u8],
    conversation_id: RuntimeId,
    event_id: RuntimeId,
) -> Result<usize, RuntimeStoreError> {
    let prefix = format!(
        "{{\"conversationId\":\"{}\",\"eventId\":\"{}\",\"eventSeq\":",
        conversation_id.to_canonical_string(),
        event_id.to_canonical_string()
    );
    let offset = prefix.len();
    if !template.starts_with(prefix.as_bytes())
        || template.get(offset..offset + 2) != Some(b"0,".as_slice())
    {
        return Err(RuntimeStoreError::InvalidConfig(
            "execution event template has an invalid top-level eventSeq",
        ));
    }
    Ok(offset)
}

impl fmt::Debug for PreparedExecutionEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedExecutionEvent")
            .field("identity", &"[REDACTED]")
            .field("template_bytes", &self.template.canonical_bytes.len())
            .finish()
    }
}

fn build_execution_event(
    identity: ExecutionEventIdentity,
    body: ExecutionEventBody,
) -> Result<CanonicalExecutionEvent, RuntimeStoreError> {
    // 防止通过手工 struct literal 或未来重构绕过 constructor 的 kind 校验。
    ensure_id_kind(identity.conversation_id, RuntimeIdKind::Conversation)?;
    ensure_id_kind(identity.command_id, RuntimeIdKind::Command)?;
    ensure_id_kind(identity.turn_id, RuntimeIdKind::Turn)?;
    ensure_id_kind(identity.event_id, RuntimeIdKind::Event)?;

    let (item_id, entity_id, runtime_body) = match body {
        ExecutionEventBody::Item {
            item_id,
            entity_id,
            item,
        } => {
            validate_durable_item(&item_id, &entity_id, &item)?;
            (
                Some(item_id),
                Some(entity_id),
                RuntimeEventBody::Item { item },
            )
        }
    };

    let runtime_event = RuntimeEvent::new(
        ConversationId::new(identity.conversation_id.to_canonical_string()),
        EventId::new(identity.event_id.to_canonical_string()),
        identity.event_seq,
        Some(CommandId::new(identity.command_id.to_canonical_string())),
        item_id,
        entity_id,
        runtime_body,
    )
    .map_err(|_| RuntimeStoreError::InvalidConfig("execution event identity is invalid"))?;
    let canonical_bytes = encode_bounded(&runtime_event)?;
    let prepared = CanonicalExecutionEvent {
        identity,
        canonical_bytes,
    };
    prepared.validate_exact_binding(identity)?;
    Ok(prepared)
}

pub(super) fn validate_durable_item(
    item_id: &ItemId,
    entity_id: &EntityId,
    item: &AgentItem,
) -> Result<(), RuntimeStoreError> {
    if item_id.as_str().is_empty() || entity_id.as_str().is_empty() {
        return Err(RuntimeStoreError::InvalidConfig(
            "execution item identity must not be empty",
        ));
    }
    // 威胁场景：未经建模的 vendor frame 可能携带 session/thread identity、token 或私有
    // diagnostic；若作为 Raw 落盘，会绕过 adapter canonical boundary 并进入跨设备回放。
    if matches!(item, AgentItem::Raw { .. }) {
        Err(RuntimeStoreError::InvalidConfig(
            "raw agent items are not durable runtime events",
        ))
    } else {
        Ok(())
    }
}

fn ensure_id_kind(id: RuntimeId, expected: RuntimeIdKind) -> Result<(), RuntimeStoreError> {
    if id.kind() == expected {
        Ok(())
    } else {
        Err(RuntimeStoreError::IdKindMismatch {
            expected,
            actual: id.kind(),
        })
    }
}

fn encode_bounded(event: &RuntimeEvent) -> Result<Vec<u8>, RuntimeStoreError> {
    let mut output = BoundedEventBuffer::new(MAX_RUNTIME_EVENT_BYTES);
    match serde_json::to_writer(&mut output, event) {
        Ok(()) if !output.bytes.is_empty() => Ok(output.bytes),
        Ok(()) => Err(RuntimeStoreError::InvalidConfig(
            "execution event encoding produced an empty payload",
        )),
        Err(_) if output.overflowed => Err(RuntimeStoreError::PayloadTooLarge),
        Err(_) => Err(RuntimeStoreError::InvalidConfig(
            "execution event encoding failed",
        )),
    }
}

struct BoundedEventBuffer {
    bytes: Vec<u8>,
    limit: usize,
    overflowed: bool,
}

impl BoundedEventBuffer {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
            overflowed: false,
        }
    }
}

impl Write for BoundedEventBuffer {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        let remaining = self.limit.saturating_sub(self.bytes.len());
        if input.len() > remaining {
            self.overflowed = true;
            return Err(io::Error::new(
                io::ErrorKind::FileTooLarge,
                "runtime event exceeds protocol limit",
            ));
        }
        self.bytes.extend_from_slice(input);
        Ok(input.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use agentdeck_protocol::AgentItemMeta;

    use super::*;

    fn id(kind: RuntimeIdKind, seed: u8) -> RuntimeId {
        RuntimeId::from_bytes(kind, [seed; 16]).expect("non-zero runtime id")
    }

    fn identity() -> ExecutionEventIdentity {
        ExecutionEventIdentity::new(
            id(RuntimeIdKind::Conversation, 1),
            id(RuntimeIdKind::Command, 2),
            id(RuntimeIdKind::Turn, 3),
            id(RuntimeIdKind::Event, 4),
            7,
        )
        .expect("valid execution event identity")
    }

    fn assistant_item(text: String) -> AgentItem {
        AgentItem::AssistantMessage {
            text,
            meta: AgentItemMeta::default(),
        }
    }

    #[test]
    fn item_bytes_are_canonical_and_exactly_bound() {
        let identity = identity();
        let item_id = ItemId::new("item-stable");
        let entity_id = EntityId::new("entity-stable");
        let prepared = build_execution_event(
            identity,
            ExecutionEventBody::Item {
                item_id: item_id.clone(),
                entity_id: entity_id.clone(),
                item: assistant_item("hello".to_owned()),
            },
        )
        .expect("build canonical item event");

        let expected = format!(
            concat!(
                "{{\"conversationId\":\"{}\",\"eventId\":\"{}\",\"eventSeq\":7,",
                "\"commandId\":\"{}\",\"itemId\":\"item-stable\",",
                "\"entityId\":\"entity-stable\",\"body\":{{\"kind\":\"item\",",
                "\"item\":{{\"kind\":\"assistantMessage\",\"text\":\"hello\",",
                "\"meta\":{{\"vendorExtensions\":{{}}}}}}}}}}"
            ),
            identity.conversation_id.to_canonical_string(),
            identity.event_id.to_canonical_string(),
            identity.command_id.to_canonical_string(),
        );
        assert_eq!(prepared.canonical_bytes(), expected.as_bytes());
        let decoded: RuntimeEvent =
            serde_json::from_slice(prepared.canonical_bytes()).expect("decode canonical item");
        assert_eq!(
            serde_json::to_vec(&decoded).expect("re-encode canonical item"),
            prepared.canonical_bytes()
        );
        prepared
            .validate_exact_binding(identity)
            .expect("exact command/turn/item/entity binding");

        let wrong_turn = ExecutionEventIdentity::new(
            identity.conversation_id,
            identity.command_id,
            id(RuntimeIdKind::Turn, 9),
            identity.event_id,
            identity.event_seq,
        )
        .expect("different valid turn identity");
        assert!(matches!(
            prepared.validate_exact_binding(wrong_turn),
            Err(RuntimeStoreError::InvalidStateTransition)
        ));
    }

    #[test]
    fn debug_output_redacts_identity_and_item_payload() {
        let identity = identity();
        let secret = "adapter-private-secret";
        let body = ExecutionEventBody::Item {
            item_id: ItemId::new("secret-item-id"),
            entity_id: EntityId::new("secret-entity-id"),
            item: assistant_item(secret.to_owned()),
        };
        let body_debug = format!("{body:?}");
        assert!(!body_debug.contains(secret));
        assert!(!body_debug.contains("secret-item-id"));
        let prepared = build_execution_event(identity, body).expect("build redaction fixture");
        let prepared_debug = format!("{prepared:?}");
        assert!(!prepared_debug.contains(secret));
        assert!(!prepared_debug.contains("secret-item-id"));
        assert!(!prepared_debug.contains(&identity.turn_id.to_canonical_string()));
        assert!(prepared_debug.contains("canonical_bytes"));
    }

    #[test]
    fn large_item_is_allowed_at_the_runtime_protocol_limit() {
        let identity = identity();
        let item_id = ItemId::new("limit-item");
        let entity_id = EntityId::new("limit-entity");
        let empty = build_execution_event(
            identity,
            ExecutionEventBody::Item {
                item_id: item_id.clone(),
                entity_id: entity_id.clone(),
                item: assistant_item(String::new()),
            },
        )
        .expect("measure canonical item overhead");
        let text_bytes = MAX_RUNTIME_EVENT_BYTES
            .checked_sub(empty.canonical_bytes().len())
            .expect("protocol limit exceeds fixed event overhead");
        drop(empty);

        let at_limit = build_execution_event(
            identity,
            ExecutionEventBody::Item {
                item_id,
                entity_id,
                item: assistant_item("x".repeat(text_bytes)),
            },
        )
        .expect("an item exactly at the protocol limit remains valid");
        assert_eq!(at_limit.canonical_bytes().len(), MAX_RUNTIME_EVENT_BYTES);

        let above_limit = build_execution_event(
            identity,
            ExecutionEventBody::Item {
                item_id: ItemId::new("limit-item"),
                entity_id: EntityId::new("limit-entity"),
                item: assistant_item("x".repeat(text_bytes + 1)),
            },
        )
        .expect_err("one byte above the public runtime event limit must fail");
        assert!(matches!(above_limit, RuntimeStoreError::PayloadTooLarge));
    }

    #[test]
    fn raw_vendor_frames_are_rejected_before_durable_encoding() {
        let error = build_execution_event(
            identity(),
            ExecutionEventBody::Item {
                item_id: ItemId::new("raw-item"),
                entity_id: EntityId::new("raw-entity"),
                item: AgentItem::Raw {
                    raw_kind: "vendor.private".to_owned(),
                    raw_payload: r#"{"session_id":"private","token":"secret"}"#.to_owned(),
                    meta: AgentItemMeta::default(),
                },
            },
        )
        .expect_err("raw vendor frames cannot enter the durable runtime journal");
        assert!(matches!(error, RuntimeStoreError::InvalidConfig(_)));
    }

    #[test]
    fn identity_constructor_rejects_cross_namespace_ids() {
        let error = ExecutionEventIdentity::new(
            id(RuntimeIdKind::Conversation, 1),
            id(RuntimeIdKind::Turn, 2),
            id(RuntimeIdKind::Turn, 3),
            id(RuntimeIdKind::Event, 4),
            0,
        )
        .expect_err("turn id cannot impersonate command id");
        assert!(matches!(
            error,
            RuntimeStoreError::IdKindMismatch {
                expected: RuntimeIdKind::Command,
                actual: RuntimeIdKind::Turn,
            }
        ));
    }

    #[test]
    fn nested_vendor_event_seq_cannot_confuse_the_trusted_top_level_offset() {
        let identity = identity();
        let mut meta = AgentItemMeta::default();
        meta.vendor_extensions.insert(
            "nested".to_owned(),
            serde_json::json!({"eventSeq": 0, "z": 1}),
        );
        let input = AppendExecutionEvent::item(
            identity.conversation_id,
            identity.command_id,
            identity.turn_id,
            identity.event_id,
            ItemId::new("nested-item"),
            EntityId::new("nested-entity"),
            AgentItem::AssistantMessage {
                text: "nested marker".to_owned(),
                meta,
            },
        );
        let prepared = PreparedExecutionEvent::from_input(input).expect("prepare nested item");
        let encoded = prepared
            .into_canonical_bytes_for_seq(42)
            .expect("rewrite only top-level eventSeq");
        let decoded: RuntimeEvent =
            serde_json::from_slice(&encoded).expect("decode rewritten item");
        assert_eq!(decoded.event_seq, 42);
        let RuntimeEventBody::Item {
            item: AgentItem::AssistantMessage { meta, .. },
        } = decoded.body
        else {
            panic!("expected assistant item");
        };
        assert_eq!(
            meta.vendor_extensions["nested"]["eventSeq"],
            serde_json::json!(0)
        );
    }

    #[test]
    fn sequence_finalization_reuses_the_charged_template_allocation() {
        for event_seq in [0, 9, 10, u64::MAX] {
            let identity = identity();
            let prepared = PreparedExecutionEvent::from_input(AppendExecutionEvent::item(
                identity.conversation_id,
                identity.command_id,
                identity.turn_id,
                identity.event_id,
                ItemId::new("stable-item"),
                EntityId::new("stable-entity"),
                assistant_item("real sequence sample".to_owned()),
            ))
            .expect("prepare sequence sample");
            let retained_capacity = prepared.retained_capacity();
            let original_pointer = prepared.template.canonical_bytes.as_ptr();
            let expected_len = prepared
                .canonical_len_for_seq(event_seq)
                .expect("measure finalized sequence");

            let finalized = prepared
                .into_canonical_bytes_for_seq(event_seq)
                .expect("finalize sequence in place");
            assert_eq!(finalized.as_ptr(), original_pointer);
            assert_eq!(finalized.capacity(), retained_capacity);
            assert_eq!(finalized.len(), expected_len);
            let decoded: RuntimeEvent =
                serde_json::from_slice(&finalized).expect("decode finalized sequence");
            assert_eq!(decoded.event_seq, event_seq);
            assert_eq!(
                serde_json::to_vec(&decoded).expect("re-encode finalized sequence"),
                finalized
            );
        }
    }

    #[test]
    fn maximum_sequence_obeys_the_exact_protocol_byte_boundary() {
        let identity = identity();
        let empty = PreparedExecutionEvent::from_input(AppendExecutionEvent::item(
            identity.conversation_id,
            identity.command_id,
            identity.turn_id,
            identity.event_id,
            ItemId::new("limit-item"),
            EntityId::new("limit-entity"),
            assistant_item(String::new()),
        ))
        .expect("measure maximum-sequence overhead");
        let fixed_len = empty
            .canonical_len_for_seq(u64::MAX)
            .expect("empty event is within the protocol limit");
        let text_bytes = MAX_RUNTIME_EVENT_BYTES
            .checked_sub(fixed_len)
            .expect("protocol limit exceeds fixed event overhead");

        let at_limit = PreparedExecutionEvent::from_input(AppendExecutionEvent::item(
            identity.conversation_id,
            identity.command_id,
            identity.turn_id,
            identity.event_id,
            ItemId::new("limit-item"),
            EntityId::new("limit-entity"),
            assistant_item("x".repeat(text_bytes)),
        ))
        .expect("prepare exact-limit item");
        assert_eq!(
            at_limit
                .canonical_len_for_seq(u64::MAX)
                .expect("exact limit remains valid"),
            MAX_RUNTIME_EVENT_BYTES
        );
        assert_eq!(
            at_limit
                .into_canonical_bytes_for_seq(u64::MAX)
                .expect("finalize exact-limit item")
                .len(),
            MAX_RUNTIME_EVENT_BYTES
        );

        let above_limit = PreparedExecutionEvent::from_input(AppendExecutionEvent::item(
            identity.conversation_id,
            identity.command_id,
            identity.turn_id,
            identity.event_id,
            ItemId::new("limit-item"),
            EntityId::new("limit-entity"),
            assistant_item("x".repeat(text_bytes + 1)),
        ))
        .expect("template still fits before the maximum sequence is applied");
        assert!(matches!(
            above_limit.canonical_len_for_seq(u64::MAX),
            Err(RuntimeStoreError::PayloadTooLarge)
        ));
    }
}
