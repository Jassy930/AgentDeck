use std::collections::{BTreeMap, BTreeSet};

use agentdeck_protocol::runtime::identity::{
    ConversationId, EntityId, EventId, ItemId, StreamGeneration, TransferId,
};
use agentdeck_protocol::runtime::{
    BackfillChunk, BackfillRange, MAX_ACTIVE_TRANSFERS, MAX_JSON_PART_BYTES,
    MAX_JSON_TRANSFER_PARTS, MAX_PART_BYTES, MAX_TRANSFER_BYTES, MAX_TRANSFER_PARTS, RuntimeEvent,
    RuntimeEventBody, RuntimeTransferChannel, StreamCursor, TRANSFER_TTL_MS, TransferEnvelope,
    TransferError,
};
use agentdeck_protocol::{
    AgentItem, AgentItemMeta, AgentKind, SessionCapabilities, VendorCapabilities,
};
use agentdeckd::runtime::transfer::{
    MAX_GLOBAL_REASSEMBLY_BYTES, TransferBinding, TransferCarrierProfile, TransferCommit,
    TransferConnectionId, TransferLimits, TransferMetrics, TransferReducer, TransferReducerError,
    TransferStateError, TransferStateMachine, TransferTarget, capabilities_digest,
    checked_reassembly_projection, validate_declared_transfer,
};
use sha2::{Digest, Sha256};

const CONNECTION_A: TransferConnectionId = TransferConnectionId::new(1);
const CONNECTION_B: TransferConnectionId = TransferConnectionId::new(2);

#[derive(Clone, Debug, Default)]
struct TestReducer {
    cursors: BTreeMap<TransferTarget, StreamCursor>,
    applied_batches: u64,
    reject_next: bool,
}

impl TransferReducer for TestReducer {
    fn cursor(&self, target: &TransferTarget) -> StreamCursor {
        self.cursors
            .get(target)
            .copied()
            .unwrap_or(StreamCursor::BeforeFirst)
    }

    fn apply(&mut self, payload: &BackfillChunk) -> Result<(), TransferReducerError> {
        if self.reject_next {
            return Err(TransferReducerError::Rejected);
        }
        let (target, range) = match payload {
            BackfillChunk::Catalog { range, deltas } => {
                assert!(!deltas.is_empty());
                (TransferTarget::Catalog, *range)
            }
            BackfillChunk::Conversation {
                conversation_id,
                range,
                events,
                ..
            } => {
                assert!(!events.is_empty());
                (
                    TransferTarget::Conversation(conversation_id.clone()),
                    *range,
                )
            }
        };
        self.cursors.insert(target, range.through());
        self.applied_batches = self
            .applied_batches
            .checked_add(1)
            .ok_or(TransferReducerError::Rejected)?;
        Ok(())
    }
}

fn capabilities() -> SessionCapabilities {
    SessionCapabilities {
        agent_kind: AgentKind::Codex,
        agent_version: "transfer-test".to_owned(),
        features: BTreeSet::new(),
        vendor: VendorCapabilities::Codex(Default::default()),
    }
}

fn hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn generation(value: &str) -> StreamGeneration {
    StreamGeneration::new(value)
}

fn conversation(value: &str) -> ConversationId {
    ConversationId::new(value)
}

fn target(conversation_id: &ConversationId) -> TransferTarget {
    TransferTarget::Conversation(conversation_id.clone())
}

fn conversation_payload(
    conversation_id: &ConversationId,
    capabilities: &SessionCapabilities,
    after: StreamCursor,
    count: u64,
) -> (Vec<u8>, BackfillRange) {
    assert!(count > 0);
    let first = after.checked_next().expect("non-exhausted test cursor");
    let through = StreamCursor::At(first.checked_add(count - 1).expect("test range"));
    let range = BackfillRange::new(after, through).expect("valid test range");
    let events = (first..=through.high_water().expect("through high water"))
        .map(|event_seq| {
            RuntimeEvent::new(
                conversation_id.clone(),
                EventId::new(format!("event-{event_seq}")),
                event_seq,
                None,
                None,
                None,
                RuntimeEventBody::Capabilities {
                    capabilities: capabilities.clone(),
                },
            )
            .expect("valid canonical event")
        })
        .collect();
    let chunk =
        BackfillChunk::conversation(conversation_id.clone(), capabilities.clone(), range, events)
            .expect("valid canonical conversation chunk");
    (serde_json::to_vec(&chunk).expect("canonical JSON"), range)
}

fn binding(
    conversation_id: &ConversationId,
    stream_generation: &StreamGeneration,
    range: BackfillRange,
    capabilities: &SessionCapabilities,
) -> TransferBinding {
    binding_with_profile(
        conversation_id,
        stream_generation,
        range,
        capabilities,
        TransferCarrierProfile::JsonUds,
    )
}

fn binding_with_profile(
    conversation_id: &ConversationId,
    stream_generation: &StreamGeneration,
    range: BackfillRange,
    capabilities: &SessionCapabilities,
    carrier_profile: TransferCarrierProfile,
) -> TransferBinding {
    TransferBinding::Conversation {
        carrier_profile,
        channel: RuntimeTransferChannel::Stream,
        target: conversation_id.clone(),
        stream_generation: stream_generation.clone(),
        range,
        capabilities_sha256: capabilities_digest(capabilities).expect("capabilities digest"),
    }
}

fn split(transfer_id: &str, payload: &[u8], part_count: u32) -> Vec<TransferEnvelope> {
    assert!(part_count > 0);
    let chunk = payload.len().div_ceil(part_count as usize).max(1);
    (0..part_count)
        .map(|part_index| {
            let start = (part_index as usize).saturating_mul(chunk);
            let end = start.saturating_add(chunk).min(payload.len());
            let part = if start < payload.len() {
                payload[start..end].to_vec()
            } else {
                Vec::new()
            };
            TransferEnvelope::new(
                TransferId::new(transfer_id),
                part_index,
                part_count,
                hash(payload),
                payload.len() as u64,
                part,
            )
            .expect("valid transfer part")
        })
        .collect()
}

fn machine() -> (
    TransferStateMachine<TestReducer>,
    ConversationId,
    StreamGeneration,
    SessionCapabilities,
) {
    let conversation_id = conversation("conversation-a");
    let stream_generation = generation("generation-a");
    let capabilities = capabilities();
    let mut machine = TransferStateMachine::new();
    machine
        .connect(CONNECTION_A, TestReducer::default())
        .expect("connect transfer state");
    machine
        .set_generation(
            CONNECTION_A,
            target(&conversation_id),
            stream_generation.clone(),
        )
        .expect("install generation");
    (machine, conversation_id, stream_generation, capabilities)
}

fn assert_empty(metrics: TransferMetrics) {
    assert_eq!(metrics.active_transfers, 0);
    assert_eq!(metrics.reassembly_bytes, 0);
}

#[test]
fn transfer_does_not_advance_inner_cursor_before_complete_hash() {
    let (mut machine, conversation_id, stream_generation, capabilities) = machine();
    let (payload, range) = conversation_payload(
        &conversation_id,
        &capabilities,
        StreamCursor::BeforeFirst,
        1,
    );
    let parts = split("cursor-before-complete", &payload, 2);

    assert!(matches!(
        machine
            .accept(
                CONNECTION_A,
                binding(&conversation_id, &stream_generation, range, &capabilities),
                parts[0].clone(),
                10,
            )
            .expect("first part"),
        TransferCommit::InProgress {
            received_parts: 1,
            part_count: 2
        }
    ));
    let reducer = machine.reducer(CONNECTION_A).expect("connected reducer");
    assert_eq!(
        reducer.cursor(&target(&conversation_id)),
        StreamCursor::BeforeFirst
    );
    assert_eq!(reducer.applied_batches, 0);
}

#[test]
fn complete_transfer_advances_inner_cursor_once_after_range_validation() {
    let (mut machine, conversation_id, stream_generation, capabilities) = machine();
    let (payload, range) = conversation_payload(
        &conversation_id,
        &capabilities,
        StreamCursor::BeforeFirst,
        2,
    );
    let parts = split("complete-once", &payload, 2);
    let transfer_binding = binding(&conversation_id, &stream_generation, range, &capabilities);

    machine
        .accept(CONNECTION_A, transfer_binding.clone(), parts[0].clone(), 10)
        .expect("first part");
    assert_eq!(
        machine
            .accept(CONNECTION_A, transfer_binding, parts[1].clone(), 11)
            .expect("completed transfer"),
        TransferCommit::Applied {
            through: range.through()
        }
    );
    let reducer = machine.reducer(CONNECTION_A).expect("connected reducer");
    assert_eq!(reducer.cursor(&target(&conversation_id)), range.through());
    assert_eq!(reducer.applied_batches, 1);

    let mut rejecting = TransferStateMachine::new();
    rejecting
        .connect(
            CONNECTION_B,
            TestReducer {
                reject_next: true,
                ..TestReducer::default()
            },
        )
        .expect("connect rejecting reducer");
    rejecting
        .set_generation(
            CONNECTION_B,
            target(&conversation_id),
            stream_generation.clone(),
        )
        .expect("set rejecting generation");
    let rejecting_part = split("rejecting-clone", &payload, 1).remove(0);
    assert_eq!(
        rejecting
            .accept(
                CONNECTION_B,
                binding(&conversation_id, &stream_generation, range, &capabilities),
                rejecting_part,
                12,
            )
            .expect_err("clone reducer failure must not swap"),
        TransferStateError::ReducerRejected
    );
    let original = rejecting
        .reducer(CONNECTION_B)
        .expect("original reducer retained");
    assert_eq!(
        original.cursor(&target(&conversation_id)),
        StreamCursor::BeforeFirst
    );
    assert_eq!(original.applied_batches, 0);
    assert!(original.reject_next);

    let mut wrong_range = TransferStateMachine::new();
    wrong_range
        .connect(CONNECTION_B, TestReducer::default())
        .expect("connect range reducer");
    wrong_range
        .set_generation(
            CONNECTION_B,
            target(&conversation_id),
            stream_generation.clone(),
        )
        .expect("set range generation");
    let (skipped_payload, skipped_range) =
        conversation_payload(&conversation_id, &capabilities, StreamCursor::At(0), 1);
    let skipped_part = split("skipped-range", &skipped_payload, 1).remove(0);
    assert_eq!(
        wrong_range
            .accept(
                CONNECTION_B,
                binding(
                    &conversation_id,
                    &stream_generation,
                    skipped_range,
                    &capabilities,
                ),
                skipped_part,
                13,
            )
            .expect_err("range cannot skip the reducer cursor"),
        TransferStateError::RangeMismatch
    );
    assert_eq!(
        wrong_range
            .reducer(CONNECTION_B)
            .expect("range reducer retained")
            .cursor(&target(&conversation_id)),
        StreamCursor::BeforeFirst
    );
}

#[test]
fn out_of_order_parts_commit_only_after_full_hash() {
    let (mut machine, conversation_id, stream_generation, capabilities) = machine();
    let (payload, range) = conversation_payload(
        &conversation_id,
        &capabilities,
        StreamCursor::BeforeFirst,
        3,
    );
    let parts = split("out-of-order", &payload, 3);
    let transfer_binding = binding(&conversation_id, &stream_generation, range, &capabilities);

    for (arrival, index) in [2, 0].into_iter().enumerate() {
        assert!(matches!(
            machine
                .accept(
                    CONNECTION_A,
                    transfer_binding.clone(),
                    parts[index].clone(),
                    20 + arrival as u64,
                )
                .expect("out-of-order partial"),
            TransferCommit::InProgress { .. }
        ));
        assert_eq!(
            machine
                .reducer(CONNECTION_A)
                .expect("connected reducer")
                .applied_batches,
            0
        );
    }
    assert!(matches!(
        machine
            .accept(CONNECTION_A, transfer_binding, parts[1].clone(), 23)
            .expect("final missing part"),
        TransferCommit::Applied { .. }
    ));
    assert_eq!(
        machine
            .reducer(CONNECTION_A)
            .expect("connected reducer")
            .applied_batches,
        1
    );
}

#[test]
fn duplicate_same_part_is_idempotent_without_double_accounting() {
    let (mut machine, conversation_id, stream_generation, capabilities) = machine();
    let (payload, range) = conversation_payload(
        &conversation_id,
        &capabilities,
        StreamCursor::BeforeFirst,
        1,
    );
    let parts = split("duplicate-same", &payload, 2);
    let transfer_binding = binding(&conversation_id, &stream_generation, range, &capabilities);

    machine
        .accept(CONNECTION_A, transfer_binding.clone(), parts[0].clone(), 1)
        .expect("first part");
    let before = machine.metrics();
    assert!(matches!(
        machine
            .accept(CONNECTION_A, transfer_binding, parts[0].clone(), 2)
            .expect("duplicate same part"),
        TransferCommit::InProgress {
            received_parts: 1,
            ..
        }
    ));
    assert_eq!(machine.metrics(), before);
}

#[test]
fn duplicate_conflict_aborts_transfer_and_releases_memory() {
    let (mut machine, conversation_id, stream_generation, capabilities) = machine();
    let (payload, range) = conversation_payload(
        &conversation_id,
        &capabilities,
        StreamCursor::BeforeFirst,
        1,
    );
    let parts = split("duplicate-conflict", &payload, 2);
    let transfer_binding = binding(&conversation_id, &stream_generation, range, &capabilities);
    machine
        .accept(CONNECTION_A, transfer_binding.clone(), parts[0].clone(), 1)
        .expect("first part");
    let mut conflict = parts[0].clone();
    conflict.part[0] ^= 0xff;

    assert_eq!(
        machine
            .accept(CONNECTION_A, transfer_binding, conflict, 2)
            .expect_err("conflicting duplicate must abort"),
        TransferStateError::Transfer(TransferError::HashMismatch)
    );
    assert_empty(machine.metrics());
}

#[test]
fn metadata_conflict_aborts_transfer_and_releases_memory() {
    let (mut machine, conversation_id, stream_generation, capabilities) = machine();
    let (payload, range) = conversation_payload(
        &conversation_id,
        &capabilities,
        StreamCursor::BeforeFirst,
        1,
    );
    let parts = split("metadata-conflict", &payload, 2);
    machine
        .accept(
            CONNECTION_A,
            binding(&conversation_id, &stream_generation, range, &capabilities),
            parts[0].clone(),
            1,
        )
        .expect("first part");
    let conflicting_range =
        BackfillRange::new(StreamCursor::At(0), StreamCursor::At(1)).expect("alternate range");

    assert_eq!(
        machine
            .accept(
                CONNECTION_A,
                binding(
                    &conversation_id,
                    &stream_generation,
                    conflicting_range,
                    &capabilities,
                ),
                parts[1].clone(),
                2,
            )
            .expect_err("binding conflict must abort"),
        TransferStateError::Transfer(TransferError::HashMismatch)
    );
    assert_empty(machine.metrics());
}

#[test]
fn hash_or_length_mismatch_never_mutates_reducer() {
    let (mut machine, conversation_id, stream_generation, capabilities) = machine();
    let (payload, range) = conversation_payload(
        &conversation_id,
        &capabilities,
        StreamCursor::BeforeFirst,
        1,
    );
    let transfer_binding = binding(&conversation_id, &stream_generation, range, &capabilities);
    let wrong_hash = TransferEnvelope::new(
        TransferId::new("wrong-hash"),
        0,
        1,
        [0x5a; 32],
        payload.len() as u64,
        payload.clone(),
    )
    .expect("structurally valid wrong hash");
    assert_eq!(
        machine
            .accept(CONNECTION_A, transfer_binding.clone(), wrong_hash, 1)
            .expect_err("wrong hash"),
        TransferStateError::Transfer(TransferError::HashMismatch)
    );

    let mut length_parts = split("wrong-length", &payload, 2);
    for part in &mut length_parts {
        part.total_bytes = part.total_bytes.checked_add(1).expect("test length");
    }
    machine
        .accept(
            CONNECTION_A,
            transfer_binding.clone(),
            length_parts[0].clone(),
            2,
        )
        .expect("first length-mismatch part");
    assert_eq!(
        machine
            .accept(
                CONNECTION_A,
                transfer_binding.clone(),
                length_parts[1].clone(),
                3,
            )
            .expect_err("declared length mismatch"),
        TransferStateError::Transfer(TransferError::HashMismatch)
    );

    let invalid_dto = b"not a Runtime BackfillChunk DTO".to_vec();
    let invalid = TransferEnvelope::new(
        TransferId::new("invalid-strict-dto"),
        0,
        1,
        hash(&invalid_dto),
        invalid_dto.len() as u64,
        invalid_dto,
    )
    .expect("valid transfer wrapper");
    assert_eq!(
        machine
            .accept(CONNECTION_A, transfer_binding, invalid, 4)
            .expect_err("invalid strict DTO payload"),
        TransferStateError::StrictDtoDecode
    );
    let valid = split("capabilities-mismatch", &payload, 1).remove(0);
    let mut other_capabilities = capabilities.clone();
    other_capabilities.agent_version = "unexpected-capability-set".to_owned();
    assert_eq!(
        machine
            .accept(
                CONNECTION_A,
                binding(
                    &conversation_id,
                    &stream_generation,
                    range,
                    &other_capabilities,
                ),
                valid,
                5,
            )
            .expect_err("capabilities preamble must match the frozen binding"),
        TransferStateError::BindingMismatch
    );
    let reducer = machine.reducer(CONNECTION_A).expect("connected reducer");
    assert_eq!(reducer.applied_batches, 0);
    assert_eq!(
        reducer.cursor(&target(&conversation_id)),
        StreamCursor::BeforeFirst
    );
    assert_empty(machine.metrics());
}

#[test]
fn carrier_specific_part_limits_and_oversize_payload_fail_before_allocation() {
    assert_eq!(MAX_TRANSFER_PARTS, 64);
    assert_eq!(MAX_JSON_TRANSFER_PARTS, 94);
    assert_eq!(MAX_TRANSFER_BYTES, 64 * 1024 * 1024);
    assert_eq!(
        validate_declared_transfer(
            TransferCarrierProfile::JsonUds,
            MAX_JSON_TRANSFER_PARTS + 1,
            0,
            0,
        ),
        Err(TransferError::TooLarge)
    );
    assert_eq!(
        validate_declared_transfer(
            TransferCarrierProfile::RemoteCompact,
            1,
            MAX_TRANSFER_BYTES + 1,
            0,
        ),
        Err(TransferError::TooLarge)
    );
    assert_eq!(
        TransferEnvelope::new(TransferId::new("sixty-five"), 0, 65, [0; 32], 0, Vec::new(),)
            .expect_err("65 parts"),
        TransferError::TooLarge
    );

    let (mut machine, conversation_id, stream_generation, capabilities) = machine();
    let (payload, range) = conversation_payload(
        &conversation_id,
        &capabilities,
        StreamCursor::BeforeFirst,
        1,
    );
    let parts = split("oversize-aborts-existing", &payload, 2);
    let transfer_binding = binding(&conversation_id, &stream_generation, range, &capabilities);
    machine
        .accept(CONNECTION_A, transfer_binding.clone(), parts[0].clone(), 0)
        .expect("valid partial before oversized metadata");
    let mut oversized = parts[1].clone();
    oversized.part_count = MAX_JSON_TRANSFER_PARTS + 1;
    assert_eq!(
        machine
            .accept(CONNECTION_A, transfer_binding, oversized, 1)
            .expect_err("oversized continuation aborts the active transfer"),
        TransferStateError::Transfer(TransferError::TooLarge)
    );
    assert_empty(machine.metrics());
}

#[test]
fn carrier_profiles_enforce_json_boundary_and_exact_representability() {
    assert_eq!(
        TransferCarrierProfile::JsonUds.max_part_bytes(),
        MAX_JSON_PART_BYTES
    );
    assert_eq!(
        TransferCarrierProfile::RemoteCompact.max_part_bytes(),
        MAX_PART_BYTES
    );
    assert_eq!(
        TransferCarrierProfile::JsonUds.max_part_count(),
        MAX_JSON_TRANSFER_PARTS
    );
    assert_eq!(
        TransferCarrierProfile::RemoteCompact.max_part_count(),
        MAX_TRANSFER_PARTS
    );
    assert_eq!(
        validate_declared_transfer(
            TransferCarrierProfile::JsonUds,
            1,
            MAX_JSON_PART_BYTES as u64,
            MAX_JSON_PART_BYTES as u64,
        ),
        Ok(())
    );

    let json_unrepresentable = MAX_JSON_PART_BYTES as u64 + 1;
    assert_eq!(
        validate_declared_transfer(
            TransferCarrierProfile::JsonUds,
            1,
            json_unrepresentable,
            json_unrepresentable,
        ),
        Err(TransferError::TooLarge)
    );
    assert_eq!(
        validate_declared_transfer(
            TransferCarrierProfile::RemoteCompact,
            1,
            json_unrepresentable,
            json_unrepresentable,
        ),
        Ok(()),
        "同一声明只能在 3.5 MiB compact carrier 中表示"
    );

    let impossible_json_total = u64::try_from(MAX_TRANSFER_PARTS as usize * MAX_JSON_PART_BYTES)
        .expect("JSON representability fits u64")
        + 1;
    assert_eq!(
        validate_declared_transfer(
            TransferCarrierProfile::JsonUds,
            MAX_TRANSFER_PARTS,
            impossible_json_total,
            0,
        ),
        Err(TransferError::TooLarge),
        "64 个合法 JSON part 永远无法组成该 totalBytes"
    );
    assert_eq!(
        validate_declared_transfer(
            TransferCarrierProfile::RemoteCompact,
            MAX_TRANSFER_PARTS,
            impossible_json_total,
            0,
        ),
        Ok(())
    );
    assert_eq!(
        validate_declared_transfer(
            TransferCarrierProfile::JsonUds,
            MAX_JSON_TRANSFER_PARTS,
            MAX_TRANSFER_BYTES,
            0,
        ),
        Ok(()),
        "94 个 JSON part 必须覆盖完整 64 MiB transfer"
    );
}

#[test]
fn active_transfer_cannot_switch_carrier_profile_and_releases_accounting() {
    let (mut machine, conversation_id, stream_generation, capabilities) = machine();
    let (payload, range) = conversation_payload(
        &conversation_id,
        &capabilities,
        StreamCursor::BeforeFirst,
        1,
    );
    let parts = split("carrier-profile-switch", &payload, 2);
    let json_binding = binding_with_profile(
        &conversation_id,
        &stream_generation,
        range,
        &capabilities,
        TransferCarrierProfile::JsonUds,
    );
    machine
        .accept(CONNECTION_A, json_binding, parts[0].clone(), 1)
        .expect("start JSON/UDS transfer");
    assert_eq!(machine.metrics().active_transfers, 1);

    let remote_binding = binding_with_profile(
        &conversation_id,
        &stream_generation,
        range,
        &capabilities,
        TransferCarrierProfile::RemoteCompact,
    );
    assert_eq!(
        machine
            .accept(CONNECTION_A, remote_binding, parts[1].clone(), 2)
            .expect_err("carrier profile is immutable after the first part"),
        TransferStateError::Transfer(TransferError::HashMismatch)
    );
    assert_empty(machine.metrics());
    assert_eq!(
        machine
            .reducer(CONNECTION_A)
            .expect("connected reducer")
            .applied_batches,
        0
    );
}

#[test]
fn transfer_expires_at_exact_ttl_boundary() {
    let (mut state_machine, conversation_id, stream_generation, capabilities) = machine();
    let (payload, range) = conversation_payload(
        &conversation_id,
        &capabilities,
        StreamCursor::BeforeFirst,
        1,
    );
    let parts = split("ttl-boundary", &payload, 2);
    let transfer_binding = binding(&conversation_id, &stream_generation, range, &capabilities);
    state_machine
        .accept(
            CONNECTION_A,
            transfer_binding.clone(),
            parts[0].clone(),
            5_000,
        )
        .expect("first part");
    let retained = state_machine.metrics();
    assert_eq!(
        state_machine
            .expire(4_999)
            .expect_err("clock regression must fail closed"),
        TransferStateError::ClockRegressed {
            previous_ms: 5_000,
            observed_ms: 4_999,
        }
    );
    assert_eq!(state_machine.metrics(), retained);

    assert_eq!(
        state_machine
            .accept(
                CONNECTION_A,
                transfer_binding.clone(),
                parts[1].clone(),
                5_000 + TRANSFER_TTL_MS,
            )
            .expect_err("exact TTL boundary expires"),
        TransferStateError::Transfer(TransferError::Expired)
    );
    assert_empty(state_machine.metrics());
    let overflow = split("deadline-overflow", &payload, 1).remove(0);
    assert_eq!(
        state_machine
            .accept(
                CONNECTION_A,
                transfer_binding,
                overflow,
                u64::MAX - TRANSFER_TTL_MS + 1,
            )
            .expect_err("absolute deadline must not wrap"),
        TransferStateError::TimeOutOfRange
    );
    assert_empty(state_machine.metrics());

    let (mut timer_machine, timer_conversation, timer_generation, timer_capabilities) = machine();
    let (timer_payload, timer_range) = conversation_payload(
        &timer_conversation,
        &timer_capabilities,
        StreamCursor::BeforeFirst,
        1,
    );
    let timer_parts = split("ttl-timer", &timer_payload, 2);
    timer_machine
        .accept(
            CONNECTION_A,
            binding(
                &timer_conversation,
                &timer_generation,
                timer_range,
                &timer_capabilities,
            ),
            timer_parts[0].clone(),
            7_000,
        )
        .expect("partial before deterministic timer");
    timer_machine
        .expire(7_000 + TRANSFER_TTL_MS)
        .expect("timer expiry accounting");
    assert_empty(timer_machine.metrics());
}

#[test]
fn active_transfer_count_blocks_zero_byte_metadata_dos() {
    let (mut machine, conversation_id, stream_generation, capabilities) = machine();
    let range =
        BackfillRange::new(StreamCursor::BeforeFirst, StreamCursor::At(0)).expect("test range");
    let transfer_binding = binding(&conversation_id, &stream_generation, range, &capabilities);
    for index in 0..MAX_ACTIVE_TRANSFERS {
        let empty = TransferEnvelope::new(
            TransferId::new(format!("empty-{index}")),
            0,
            2,
            hash(&[]),
            0,
            Vec::new(),
        )
        .expect("zero-byte partial");
        machine
            .accept(CONNECTION_A, transfer_binding.clone(), empty, 0)
            .expect("within active count cap");
    }
    assert_eq!(machine.metrics().active_transfers, MAX_ACTIVE_TRANSFERS);
    assert_eq!(machine.metrics().reassembly_bytes, 0);
    let overflow = TransferEnvelope::new(
        TransferId::new("empty-overflow"),
        0,
        2,
        hash(&[]),
        0,
        Vec::new(),
    )
    .expect("zero-byte overflow candidate");
    assert_eq!(
        machine
            .accept(CONNECTION_A, transfer_binding, overflow, 0)
            .expect_err("active cap must count zero-byte transfer"),
        TransferStateError::Transfer(TransferError::ReassemblyFull)
    );
}

#[test]
fn reassembly_global_and_connection_caps_use_checked_arithmetic() {
    assert_eq!(MAX_GLOBAL_REASSEMBLY_BYTES, 512 * 1024 * 1024);
    assert_eq!(
        checked_reassembly_projection(u64::MAX, 1, u64::MAX),
        Err(TransferError::ReassemblyFull)
    );

    let limits = TransferLimits {
        max_reassembly_bytes_per_connection: 8,
        max_reassembly_bytes_global: 10,
        ..TransferLimits::default()
    };
    let release_conversation = conversation("budget-release-conversation");
    let release_generation = generation("budget-release-generation");
    let release_capabilities = capabilities();
    let release_range =
        BackfillRange::new(StreamCursor::BeforeFirst, StreamCursor::At(0)).expect("test range");
    let release_binding = binding(
        &release_conversation,
        &release_generation,
        release_range,
        &release_capabilities,
    );
    let mut release_machine =
        TransferStateMachine::with_limits(limits).expect("valid release limits");
    release_machine
        .connect(CONNECTION_A, TestReducer::default())
        .expect("connect release state");
    release_machine
        .set_generation(
            CONNECTION_A,
            target(&release_conversation),
            release_generation,
        )
        .expect("set release generation");
    let over_connection_parts = split("same-transfer-over-cap", &[0x33; 12], 2);
    release_machine
        .accept(
            CONNECTION_A,
            release_binding.clone(),
            over_connection_parts[0].clone(),
            0,
        )
        .expect("first part below cap");
    assert_eq!(release_machine.metrics().reassembly_bytes, 6);
    assert_eq!(
        release_machine
            .accept(
                CONNECTION_A,
                release_binding,
                over_connection_parts[1].clone(),
                1,
            )
            .expect_err("same transfer continuation exceeds connection cap"),
        TransferStateError::Transfer(TransferError::ReassemblyFull)
    );
    assert_empty(release_machine.metrics());

    let global_release_limits = TransferLimits {
        max_reassembly_bytes_per_connection: 10,
        max_reassembly_bytes_global: 12,
        ..TransferLimits::default()
    };
    let mut global_release_machine = TransferStateMachine::with_limits(global_release_limits)
        .expect("valid global release limits");
    for connection in [CONNECTION_A, CONNECTION_B] {
        global_release_machine
            .connect(connection, TestReducer::default())
            .expect("connect global release state");
        global_release_machine
            .set_generation(
                connection,
                target(&release_conversation),
                generation("budget-release-generation"),
            )
            .expect("set global release generation");
    }
    let global_a_parts = split("global-resident", &[0x55; 12], 2);
    global_release_machine
        .accept(
            CONNECTION_A,
            binding(
                &release_conversation,
                &generation("budget-release-generation"),
                release_range,
                &release_capabilities,
            ),
            global_a_parts[0].clone(),
            0,
        )
        .expect("resident global bytes");
    let global_b_parts = split("global-same-transfer-over-cap", &[0x66; 8], 2);
    let global_b_binding = binding(
        &release_conversation,
        &generation("budget-release-generation"),
        release_range,
        &release_capabilities,
    );
    global_release_machine
        .accept(
            CONNECTION_B,
            global_b_binding.clone(),
            global_b_parts[0].clone(),
            0,
        )
        .expect("partial below global cap");
    assert_eq!(global_release_machine.metrics().reassembly_bytes, 10);
    assert_eq!(
        global_release_machine
            .accept(CONNECTION_B, global_b_binding, global_b_parts[1].clone(), 1,)
            .expect_err("same transfer continuation exceeds global cap"),
        TransferStateError::Transfer(TransferError::ReassemblyFull)
    );
    assert_eq!(global_release_machine.metrics().reassembly_bytes, 6);
    assert_eq!(global_release_machine.metrics().active_transfers, 1);

    let mut machine = TransferStateMachine::with_limits(limits).expect("valid scaled limits");
    let conversation_id = conversation("budget-conversation");
    let stream_generation = generation("budget-generation");
    let capabilities = capabilities();
    let range =
        BackfillRange::new(StreamCursor::BeforeFirst, StreamCursor::At(0)).expect("test range");
    let transfer_binding = binding(&conversation_id, &stream_generation, range, &capabilities);
    for connection in [CONNECTION_A, CONNECTION_B] {
        machine
            .connect(connection, TestReducer::default())
            .expect("connect budget state");
        machine
            .set_generation(
                connection,
                target(&conversation_id),
                stream_generation.clone(),
            )
            .expect("set budget generation");
    }

    let partial = |id: &str, bytes: usize| {
        let payload = vec![0x44; bytes.checked_mul(2).expect("small test payload")];
        TransferEnvelope::new(
            TransferId::new(id),
            0,
            2,
            hash(&payload),
            payload.len() as u64,
            payload[..bytes].to_vec(),
        )
        .expect("valid budget partial")
    };
    machine
        .accept(
            CONNECTION_A,
            transfer_binding.clone(),
            partial("connection-a-six", 6),
            0,
        )
        .expect("six bytes on connection A");
    assert_eq!(
        machine
            .accept(
                CONNECTION_A,
                transfer_binding.clone(),
                partial("connection-a-three", 3),
                0,
            )
            .expect_err("connection cap"),
        TransferStateError::Transfer(TransferError::ReassemblyFull)
    );
    machine
        .accept(
            CONNECTION_B,
            transfer_binding.clone(),
            partial("connection-b-four", 4),
            0,
        )
        .expect("global cap exact boundary");
    assert_eq!(machine.metrics().reassembly_bytes, 10);
    assert_eq!(
        machine
            .accept(
                CONNECTION_B,
                transfer_binding,
                partial("global-overflow", 1),
                0,
            )
            .expect_err("global cap"),
        TransferStateError::Transfer(TransferError::ReassemblyFull)
    );
    assert_eq!(machine.metrics().reassembly_bytes, 10);

    let assembly_limits = TransferLimits {
        max_reassembly_bytes_per_connection: 10,
        max_reassembly_bytes_global: 20,
        ..TransferLimits::default()
    };
    let mut assembly_machine =
        TransferStateMachine::with_limits(assembly_limits).expect("assembly limits");
    assembly_machine
        .connect(CONNECTION_A, TestReducer::default())
        .expect("connect assembly state");
    assembly_machine
        .set_generation(
            CONNECTION_A,
            target(&conversation_id),
            stream_generation.clone(),
        )
        .expect("set assembly generation");
    let assembly_payload = b"123456";
    let assembly_parts = split("assembly-peak", assembly_payload, 2);
    assembly_machine
        .accept(
            CONNECTION_A,
            binding(&conversation_id, &stream_generation, range, &capabilities),
            assembly_parts[0].clone(),
            0,
        )
        .expect("first assembly part");
    assert_eq!(
        assembly_machine
            .accept(
                CONNECTION_A,
                binding(&conversation_id, &stream_generation, range, &capabilities,),
                assembly_parts[1].clone(),
                0,
            )
            .expect_err("parts plus assembly exceed connection peak"),
        TransferStateError::Transfer(TransferError::ReassemblyFull)
    );
    assert_empty(assembly_machine.metrics());
}

#[test]
fn completed_transfer_retry_cannot_apply_twice() {
    let (mut machine, conversation_id, stream_generation, capabilities) = machine();
    let (payload, range) = conversation_payload(
        &conversation_id,
        &capabilities,
        StreamCursor::BeforeFirst,
        1,
    );
    let part = split("completed-retry", &payload, 1).remove(0);
    let transfer_binding = binding(&conversation_id, &stream_generation, range, &capabilities);
    assert!(matches!(
        machine
            .accept(CONNECTION_A, transfer_binding.clone(), part.clone(), 1)
            .expect("first complete"),
        TransferCommit::Applied { .. }
    ));
    assert_eq!(
        machine
            .accept(CONNECTION_A, transfer_binding, part, 2)
            .expect("completed retry"),
        TransferCommit::AlreadyApplied
    );
    assert_eq!(
        machine
            .reducer(CONNECTION_A)
            .expect("connected reducer")
            .applied_batches,
        1
    );
    assert_eq!(machine.metrics().completed_tombstones, 1);
}

#[test]
fn disconnect_releases_every_partial_transfer_budget() {
    let (mut machine, conversation_id, stream_generation, capabilities) = machine();
    let (payload, range) = conversation_payload(
        &conversation_id,
        &capabilities,
        StreamCursor::BeforeFirst,
        1,
    );
    let transfer_binding = binding(&conversation_id, &stream_generation, range, &capabilities);
    for index in 0..3 {
        let parts = split(&format!("disconnect-{index}"), &payload, 2);
        machine
            .accept(CONNECTION_A, transfer_binding.clone(), parts[0].clone(), 1)
            .expect("partial before disconnect");
    }
    assert!(machine.metrics().reassembly_bytes > 0);
    machine
        .disconnect(CONNECTION_A)
        .expect("disconnect cleanup must preserve accounting");
    assert_empty(machine.metrics());
    assert!(machine.reducer(CONNECTION_A).is_none());
}

#[test]
fn stale_subscription_generation_cannot_commit_completed_transfer() {
    let (mut machine, conversation_id, stream_generation, capabilities) = machine();
    let (payload, range) = conversation_payload(
        &conversation_id,
        &capabilities,
        StreamCursor::BeforeFirst,
        1,
    );
    let parts = split("stale-generation", &payload, 2);
    let stale_binding = binding(&conversation_id, &stream_generation, range, &capabilities);
    machine
        .accept(CONNECTION_A, stale_binding.clone(), parts[0].clone(), 1)
        .expect("first part on old generation");
    machine
        .set_generation(
            CONNECTION_A,
            target(&conversation_id),
            generation("generation-b"),
        )
        .expect("rotate generation and release stale partial");
    assert_empty(machine.metrics());

    let current_binding = binding(
        &conversation_id,
        &generation("generation-b"),
        range,
        &capabilities,
    );
    machine
        .accept(CONNECTION_A, current_binding.clone(), parts[0].clone(), 2)
        .expect("same transfer id starts on current generation");
    let retained = machine.metrics();

    assert_eq!(
        machine
            .accept(CONNECTION_A, stale_binding, parts[1].clone(), 3)
            .expect_err("stale generation"),
        TransferStateError::StaleGeneration
    );
    assert_eq!(
        machine.metrics(),
        retained,
        "stale generation must not abort a current-generation transfer that reused the id"
    );
    assert!(matches!(
        machine
            .accept(CONNECTION_A, current_binding, parts[1].clone(), 4)
            .expect("current generation completes"),
        TransferCommit::Applied { .. }
    ));
    let reducer = machine.reducer(CONNECTION_A).expect("connected reducer");
    assert_eq!(reducer.applied_batches, 1);
    assert_eq!(reducer.cursor(&target(&conversation_id)), range.through());
}

#[test]
fn single_item_over_64mib_fails_without_truncation() {
    let conversation_id = conversation("oversize-item-conversation");
    let marker = "actual-runtime-item-must-survive-encoding";
    let item_event = RuntimeEvent::new(
        conversation_id.clone(),
        EventId::new("oversize-item-event"),
        0,
        None,
        Some(ItemId::new("oversize-item")),
        Some(EntityId::new("oversize-entity")),
        RuntimeEventBody::Item {
            item: AgentItem::AssistantMessage {
                text: marker.to_owned(),
                meta: AgentItemMeta::default(),
            },
        },
    )
    .expect("valid real Runtime item");
    let range =
        BackfillRange::new(StreamCursor::BeforeFirst, StreamCursor::At(0)).expect("single item");
    let chunk =
        BackfillChunk::conversation(conversation_id, capabilities(), range, vec![item_event])
            .expect("valid real BackfillChunk");
    let encoded = serde_json::to_vec(&chunk).expect("encode real Runtime item");
    assert!(
        encoded
            .windows(marker.len())
            .any(|window| window == marker.as_bytes()),
        "real encoder must preserve the complete item payload"
    );
    let too_large = MAX_TRANSFER_BYTES
        .checked_add(1)
        .expect("constant below u64 max");
    assert_eq!(
        TransferEnvelope::new(
            TransferId::new("single-item-over-limit"),
            0,
            1,
            hash(&encoded),
            too_large,
            encoded,
        )
        .expect_err("real protocol envelope rejects oversize metadata before reassembly"),
        TransferError::TooLarge,
    );
    assert_eq!(too_large, 67_108_865);
}
