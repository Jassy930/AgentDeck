#![cfg(unix)]

use agentdeck_cli::remote::transfer_state::{
    DurableLiveTransferStateV1, DurableTransferBindingIdentityV1, DurableTransferBootstrapError,
    DurableTransferOutcomeV1, DurableTransferStateError, MAX_DURABLE_TRANSFER_RECORD_BYTES,
};
use agentdeck_protocol::e2ee::{E2EE_FORMAT_VERSION, KeyId, KeyPurpose, StreamBindingV1};
use agentdeck_protocol::relay_v2::{
    DeviceRouteId, GrantSerial, KeyDirectoryRevision, MachineRouteId, RELAY_PROTOCOL_VERSION,
    StreamGenerationId, StreamRouteId, TrustEpoch,
};
use agentdeck_protocol::runtime::identity::{ConversationId, EventId, TransferId};
use agentdeck_protocol::runtime::{
    DurableStreamTransferIdentity, DurableStreamTransferSource, MAX_ACTIVE_TRANSFERS,
    MAX_PART_BYTES, RUNTIME_PROTOCOL_VERSION, RuntimeInnerCursor, RuntimeTransferCarrierV1,
    RuntimeTransferChannel, StreamCursor, TRANSFER_TTL_MS, TransferEnvelope,
};

const START_MS: u64 = 10_000;

fn canonical_id(seed: u64) -> String {
    format!("11111111-1111-4111-8111-{seed:012x}")
}

fn catalog_binding(route: u8, generation: u8) -> StreamBindingV1 {
    StreamBindingV1 {
        format_version: E2EE_FORMAT_VERSION,
        runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
        relay_protocol_version: RELAY_PROTOCOL_VERSION,
        machine_route: MachineRouteId::from_bytes([0x11; 16]),
        device_route: DeviceRouteId::from_bytes([0x22; 16]),
        grant_serial: GrantSerial::new(7),
        root_trust_epoch: TrustEpoch::new(3),
        stream_route: StreamRouteId::from_bytes([route; 16]),
        stream_generation: StreamGenerationId::from_bytes([generation; 16]),
        stream_cursor: StreamCursor::At(4),
        inner_cursor: RuntimeInnerCursor::Catalog {
            cursor: StreamCursor::At(6),
        },
        key_directory_revision: KeyDirectoryRevision::new(9),
        key_id: KeyId {
            purpose: KeyPurpose::Catalog,
            epoch: 5,
        },
    }
}

fn conversation_binding(conversation_id: &str, route: u8, generation: u8) -> StreamBindingV1 {
    let mut binding = catalog_binding(route, generation);
    binding.inner_cursor = RuntimeInnerCursor::Conversation {
        conversation_id: ConversationId::new(conversation_id),
        cursor: StreamCursor::At(12),
    };
    binding.key_id = KeyId {
        purpose: KeyPurpose::ConversationDek,
        epoch: 8,
    };
    binding
}

fn indexed_conversation_binding(index: u64) -> StreamBindingV1 {
    let mut binding = conversation_binding(&canonical_id(0x1_000 + index), 0x35, 0x45);
    let mut route = [0x35; 16];
    route[8..].copy_from_slice(&index.to_be_bytes());
    binding.stream_route = StreamRouteId::from_bytes(route);
    let mut generation = [0x45; 16];
    generation[8..].copy_from_slice(&index.to_be_bytes());
    binding.stream_generation = StreamGenerationId::from_bytes(generation);
    binding
}

fn bootstrap_marker_record(index: u64) -> Vec<u8> {
    let binding = indexed_conversation_binding(index);
    DurableLiveTransferStateV1::empty()
        .abort_exact_binding(
            &binding,
            None,
            DurableTransferBootstrapError::PayloadRejected,
            START_MS,
        )
        .expect("construct one canonical bootstrap marker")
        .record_bytes()[0]
        .clone()
}

fn carrier(
    identity: DurableStreamTransferIdentity,
    part_index: u32,
    part: Vec<u8>,
) -> RuntimeTransferCarrierV1 {
    RuntimeTransferCarrierV1::new(
        identity.message_id(),
        RuntimeTransferChannel::Stream,
        TransferEnvelope::new(
            identity.transfer_id(),
            part_index,
            identity.part_count(),
            identity.total_sha256(),
            identity.total_bytes(),
            part,
        )
        .expect("bounded transfer fixture"),
    )
}

fn split_catalog(
    first_revision: u64,
    through_revision: u64,
) -> (
    DurableStreamTransferIdentity,
    Vec<u8>,
    RuntimeTransferCarrierV1,
    RuntimeTransferCarrierV1,
) {
    let payload = vec![0x5a; MAX_PART_BYTES + 1];
    let identity =
        DurableStreamTransferIdentity::for_catalog(first_revision, through_revision, &payload)
            .expect("bounded multi-revision catalog identity");
    let first = carrier(identity, 0, payload[..MAX_PART_BYTES].to_vec());
    let final_part = carrier(identity, 1, payload[MAX_PART_BYTES..].to_vec());
    (identity, payload, first, final_part)
}

fn state_after(
    transition: agentdeck_cli::remote::transfer_state::DurableTransferTransitionV1,
) -> DurableLiveTransferStateV1 {
    transition.into_state()
}

#[test]
fn two_part_multi_revision_catalog_is_restart_durable_and_returns_authenticated_range() {
    let binding = catalog_binding(0x31, 0x41);
    let (_identity, payload, first, final_part) = split_catalog(7, 9);
    let first = DurableLiveTransferStateV1::empty()
        .accept_part(&binding, first, START_MS)
        .expect("buffer first part");
    assert_eq!(
        first.outcome(),
        &DurableTransferOutcomeV1::Buffered {
            received_parts: 1,
            part_count: 2,
        }
    );
    assert_eq!(first.state().active_count(), 1);
    assert_eq!(first.state().buffered_bytes(), MAX_PART_BYTES as u64);

    let records = first.record_bytes().to_vec();
    assert_eq!(
        records.len(),
        2,
        "active header and part are separate records"
    );
    assert!(
        records
            .iter()
            .all(|record| record.len() <= MAX_DURABLE_TRANSFER_RECORD_BYTES),
        "every record remains a single bounded persistence field"
    );
    let restarted =
        DurableLiveTransferStateV1::from_record_bytes(&records).expect("strict restart readback");
    assert_eq!(restarted.canonical_record_bytes().unwrap(), records);
    let mut reordered = records.clone();
    reordered.reverse();
    assert_eq!(
        DurableLiveTransferStateV1::from_record_bytes(&reordered).unwrap_err(),
        DurableTransferStateError::InvalidRecord
    );

    let complete = restarted
        .accept_part(&binding, final_part, START_MS + 1)
        .expect("complete after restart");
    match complete.outcome() {
        DurableTransferOutcomeV1::Complete {
            payload: assembled,
            source:
                DurableStreamTransferSource::Catalog {
                    first_revision,
                    through_revision,
                },
        } => {
            assert_eq!(assembled, &payload);
            assert_eq!((*first_revision, *through_revision), (7, 9));
        }
        other => panic!("expected complete catalog range, got {other:?}"),
    }
    assert_eq!(complete.state().active_count(), 0);
    assert_eq!(complete.state().completed_count(), 1);
    assert_eq!(complete.state().buffered_bytes(), 0);
}

#[test]
fn event_completion_binds_conversation_event_and_sequence_axes() {
    let conversation = canonical_id(0x51);
    let event = canonical_id(0x52);
    let binding = conversation_binding(&conversation, 0x32, 0x42);
    let payload = b"canonical-event".to_vec();
    let identity = DurableStreamTransferIdentity::for_event(
        &ConversationId::new(&conversation),
        &EventId::new(&event),
        13,
        &payload,
    )
    .expect("event identity");
    let complete = DurableLiveTransferStateV1::empty()
        .accept_part(&binding, carrier(identity, 0, payload.clone()), START_MS)
        .expect("complete event");
    match complete.outcome() {
        DurableTransferOutcomeV1::Complete {
            payload: assembled,
            source:
                DurableStreamTransferSource::Event {
                    conversation_id,
                    event_id,
                    event_seq,
                },
        } => {
            assert_eq!(assembled, &payload);
            assert_eq!(conversation_id.to_string(), conversation);
            assert_eq!(event_id.to_string(), event);
            assert_eq!(*event_seq, 13);
        }
        other => panic!("expected complete event axes, got {other:?}"),
    }
}

#[test]
fn duplicate_same_is_idempotent_but_conflict_aborts_to_needs_bootstrap() {
    let binding = catalog_binding(0x33, 0x43);
    let (_identity, _payload, first, _) = split_catalog(1, 2);
    let buffered = DurableLiveTransferStateV1::empty()
        .accept_part(&binding, first.clone(), START_MS)
        .unwrap();
    let repeated = state_after(buffered)
        .accept_part(&binding, first.clone(), START_MS + 1)
        .unwrap();
    assert_eq!(
        repeated.outcome(),
        &DurableTransferOutcomeV1::Buffered {
            received_parts: 1,
            part_count: 2,
        }
    );
    assert_eq!(repeated.state().active_count(), 1);

    let mut conflicting = first;
    conflicting.transfer.part[0] ^= 0xff;
    let aborted = state_after(repeated)
        .accept_part(&binding, conflicting, START_MS + 2)
        .unwrap();
    assert_eq!(
        aborted.outcome(),
        &DurableTransferOutcomeV1::NeedsBootstrap {
            error: DurableTransferBootstrapError::ConflictingDuplicate,
        }
    );
    assert_eq!(aborted.state().active_count(), 0);
    assert_eq!(aborted.state().buffered_bytes(), 0);
    assert_eq!(aborted.state().marker_count(), 1);
}

#[test]
fn ttl_is_absolute_and_clock_rollback_fails_closed_without_extending_expiry() {
    let binding = catalog_binding(0x34, 0x44);
    let (_identity, _payload, first, _) = split_catalog(3, 4);
    let buffered = DurableLiveTransferStateV1::empty()
        .accept_part(&binding, first.clone(), START_MS)
        .unwrap();
    let before_expiry = state_after(buffered)
        .accept_part(&binding, first.clone(), START_MS + TRANSFER_TTL_MS - 1)
        .unwrap();
    assert!(matches!(
        before_expiry.outcome(),
        DurableTransferOutcomeV1::Buffered { .. }
    ));
    let at_expiry = state_after(before_expiry)
        .accept_part(&binding, first.clone(), START_MS + TRANSFER_TTL_MS)
        .unwrap();
    assert_eq!(
        at_expiry.outcome(),
        &DurableTransferOutcomeV1::NeedsBootstrap {
            error: DurableTransferBootstrapError::Expired,
        }
    );

    let fresh = DurableLiveTransferStateV1::empty()
        .accept_part(&binding, first, START_MS)
        .unwrap();
    assert_eq!(
        state_after(fresh)
            .accept_part(
                &binding,
                carrier(
                    DurableStreamTransferIdentity::from_catalog_metadata(
                        3,
                        4,
                        (MAX_PART_BYTES + 1) as u64,
                        [0x77; 32],
                    )
                    .unwrap(),
                    0,
                    vec![0x77],
                ),
                START_MS - 1,
            )
            .unwrap_err(),
        DurableTransferStateError::ClockRollback
    );
}

#[test]
fn earliest_active_expiry_is_absolute_read_only_and_deterministic() {
    let conversation_a = canonical_id(0x71);
    let conversation_b = canonical_id(0x72);
    let binding_a = conversation_binding(&conversation_a, 0x34, 0x44);
    let binding_b = conversation_binding(&conversation_b, 0x35, 0x45);
    let identity_a = DurableStreamTransferIdentity::from_event_metadata(
        &ConversationId::new(&conversation_a),
        &EventId::new(canonical_id(0x73)),
        1,
        (MAX_PART_BYTES + 1) as u64,
        [0x71; 32],
    )
    .unwrap();
    let identity_b = DurableStreamTransferIdentity::from_event_metadata(
        &ConversationId::new(&conversation_b),
        &EventId::new(canonical_id(0x74)),
        2,
        (MAX_PART_BYTES + 1) as u64,
        [0x72; 32],
    )
    .unwrap();
    let part_a = carrier(identity_a, 0, vec![0x71]);
    let part_b = carrier(identity_b, 0, vec![0x72]);

    let state_ba = DurableLiveTransferStateV1::empty()
        .accept_part(&binding_b, part_b.clone(), START_MS)
        .unwrap()
        .into_state()
        .accept_part(&binding_a, part_a.clone(), START_MS)
        .unwrap()
        .into_state();
    let state_ab = DurableLiveTransferStateV1::empty()
        .accept_part(&binding_a, part_a.clone(), START_MS)
        .unwrap()
        .into_state()
        .accept_part(&binding_b, part_b, START_MS)
        .unwrap()
        .into_state();
    let expected_binding =
        DurableTransferBindingIdentityV1::from_stream_binding(&binding_a).unwrap();
    let expected = Some((expected_binding, START_MS + TRANSFER_TTL_MS));
    assert_eq!(state_ba.earliest_active_expiry(), expected);
    assert_eq!(state_ab.earliest_active_expiry(), expected);
    assert_eq!(
        state_ab
            .clone()
            .expire_due_active(START_MS - 1)
            .unwrap_err(),
        DurableTransferStateError::ClockRollback
    );
    assert_eq!(
        state_ba.canonical_record_bytes().unwrap(),
        state_ab.canonical_record_bytes().unwrap(),
        "equal-expiry selection and canonical records must not depend on insertion order"
    );

    let records_before_query = state_ba.canonical_record_bytes().unwrap();
    assert_eq!(state_ba.earliest_active_expiry(), expected);
    assert_eq!(
        state_ba.canonical_record_bytes().unwrap(),
        records_before_query
    );

    let (before_expiry, expired_binding) = state_ba
        .expire_due_active(START_MS + TRANSFER_TTL_MS - 1)
        .unwrap();
    assert_eq!(expired_binding, None);
    assert_eq!(
        before_expiry.canonical_record_bytes().unwrap(),
        records_before_query
    );

    let repeated = before_expiry
        .accept_part(&binding_a, part_a, START_MS + TRANSFER_TTL_MS - 1)
        .unwrap();
    assert!(matches!(
        repeated.outcome(),
        DurableTransferOutcomeV1::Buffered { .. }
    ));
    assert_eq!(repeated.state().earliest_active_expiry(), expected);

    let (expired_a, expired_binding) = repeated
        .into_state()
        .expire_due_active(START_MS + TRANSFER_TTL_MS)
        .unwrap();
    assert_eq!(expired_binding, Some(expected_binding));
    assert_eq!(expired_a.active_count(), 1);
    assert_eq!(expired_a.marker_count(), 1);
    let expected_binding_b =
        DurableTransferBindingIdentityV1::from_stream_binding(&binding_b).unwrap();
    assert_eq!(
        expired_a.earliest_active_expiry(),
        Some((expected_binding_b, START_MS + TRANSFER_TTL_MS))
    );
    let (expired_b, expired_binding) = expired_a
        .expire_due_active(START_MS + TRANSFER_TTL_MS)
        .unwrap();
    assert_eq!(expired_binding, Some(expected_binding_b));
    assert_eq!(expired_b.active_count(), 0);
    assert_eq!(expired_b.marker_count(), 2);
    let records = expired_b.canonical_record_bytes().unwrap();
    let restarted = DurableLiveTransferStateV1::from_record_bytes(&records).unwrap();
    assert_eq!(restarted.earliest_active_expiry(), None);
    assert_eq!(restarted.marker_count(), 2);
}

#[test]
fn accepting_new_transfer_housekeeps_expired_active_bindings_first() {
    let expired_conversation = canonical_id(0x75);
    let fresh_conversation = canonical_id(0x76);
    let expired_binding = conversation_binding(&expired_conversation, 0x36, 0x46);
    let fresh_binding = conversation_binding(&fresh_conversation, 0x37, 0x47);
    let expired_identity = DurableStreamTransferIdentity::from_event_metadata(
        &ConversationId::new(&expired_conversation),
        &EventId::new(canonical_id(0x77)),
        1,
        (MAX_PART_BYTES + 1) as u64,
        [0x75; 32],
    )
    .unwrap();
    let fresh_identity = DurableStreamTransferIdentity::from_event_metadata(
        &ConversationId::new(&fresh_conversation),
        &EventId::new(canonical_id(0x78)),
        2,
        (MAX_PART_BYTES + 1) as u64,
        [0x76; 32],
    )
    .unwrap();
    let expired_part = carrier(expired_identity, 0, vec![0x75]);
    let state = DurableLiveTransferStateV1::empty()
        .accept_part(&expired_binding, expired_part.clone(), START_MS)
        .unwrap()
        .into_state();

    let accepted = state
        .accept_part(
            &fresh_binding,
            carrier(fresh_identity, 0, vec![0x76]),
            START_MS + TRANSFER_TTL_MS,
        )
        .unwrap();
    assert_eq!(
        accepted.outcome(),
        &DurableTransferOutcomeV1::Buffered {
            received_parts: 1,
            part_count: 2,
        }
    );
    assert_eq!(accepted.state().active_count(), 1);
    assert_eq!(accepted.state().marker_count(), 1);
    assert_eq!(
        accepted.state().earliest_active_expiry(),
        Some((
            DurableTransferBindingIdentityV1::from_stream_binding(&fresh_binding).unwrap(),
            START_MS + 2 * TRANSFER_TTL_MS,
        ))
    );

    let expired = accepted
        .into_state()
        .accept_part(&expired_binding, expired_part, START_MS + TRANSFER_TTL_MS)
        .unwrap();
    assert_eq!(
        expired.outcome(),
        &DurableTransferOutcomeV1::NeedsBootstrap {
            error: DurableTransferBootstrapError::Expired,
        }
    );
    assert_eq!(expired.state().active_count(), 1);
    assert_eq!(expired.state().marker_count(), 1);
    let records = expired.record_bytes();
    assert_eq!(
        DurableLiveTransferStateV1::from_record_bytes(records)
            .unwrap()
            .canonical_record_bytes()
            .unwrap(),
        records
    );
}

#[test]
fn sixty_four_active_is_the_hard_limit_and_sixty_fifth_needs_bootstrap() {
    let binding = catalog_binding(0x35, 0x45);
    let mut state = DurableLiveTransferStateV1::empty();
    for index in 0..MAX_ACTIVE_TRANSFERS {
        let mut digest = [0_u8; 32];
        digest[..8].copy_from_slice(&(index as u64 + 1).to_be_bytes());
        let identity = DurableStreamTransferIdentity::from_catalog_metadata(
            5,
            6,
            (MAX_PART_BYTES + 1) as u64,
            digest,
        )
        .unwrap();
        let transition = state
            .accept_part(&binding, carrier(identity, 0, vec![index as u8]), START_MS)
            .unwrap();
        assert!(matches!(
            transition.outcome(),
            DurableTransferOutcomeV1::Buffered { .. }
        ));
        state = transition.into_state();
    }
    assert_eq!(state.active_count(), MAX_ACTIVE_TRANSFERS);

    let overflow = DurableStreamTransferIdentity::from_catalog_metadata(
        5,
        6,
        (MAX_PART_BYTES + 1) as u64,
        [0xff; 32],
    )
    .unwrap();
    let rejected = state
        .accept_part(&binding, carrier(overflow, 0, vec![0xff]), START_MS)
        .unwrap();
    assert_eq!(
        rejected.outcome(),
        &DurableTransferOutcomeV1::NeedsBootstrap {
            error: DurableTransferBootstrapError::ActiveLimit,
        }
    );
    assert_eq!(rejected.state().active_count(), 0);
}

#[test]
fn sixty_fifth_distinct_binding_marker_is_not_rejected_by_the_active_limit() {
    let mut state = DurableLiveTransferStateV1::empty();
    for index in 0..65 {
        let binding = indexed_conversation_binding(index);
        state = state
            .abort_exact_binding(
                &binding,
                None,
                DurableTransferBootstrapError::PayloadRejected,
                START_MS,
            )
            .expect("each distinct binding may persist its terminal marker")
            .into_state();
    }

    assert_eq!(state.active_count(), 0);
    assert_eq!(state.marker_count(), 65);
    let records = state.canonical_record_bytes().unwrap();
    let restarted = DurableLiveTransferStateV1::from_record_bytes(&records)
        .expect("the sixty-fifth marker remains restart durable");
    assert_eq!(restarted.active_count(), 0);
    assert_eq!(restarted.marker_count(), 65);
    assert_eq!(restarted.canonical_record_bytes().unwrap(), records);
}

#[test]
fn marker_collection_accepts_4096_and_rejects_4097() {
    const MAX_MARKERS: u64 = 4_096;

    let records = (0..MAX_MARKERS)
        .map(bootstrap_marker_record)
        .collect::<Vec<_>>();
    let accepted = DurableLiveTransferStateV1::from_record_bytes(&records)
        .expect("the complete durable binding marker collection must be accepted");
    assert_eq!(accepted.active_count(), 0);
    assert_eq!(accepted.marker_count(), MAX_MARKERS as usize);
    assert_eq!(accepted.canonical_record_bytes().unwrap(), records);

    let mut overflow = records;
    overflow.push(bootstrap_marker_record(MAX_MARKERS));
    assert_eq!(
        DurableLiveTransferStateV1::from_record_bytes(&overflow).unwrap_err(),
        DurableTransferStateError::TooLarge
    );
}

#[test]
fn scaled_reassembly_budget_counts_durable_parts_and_candidate_payload_together() {
    let binding = catalog_binding(0x36, 0x46);
    let identity = DurableStreamTransferIdentity::from_catalog_metadata(
        7,
        8,
        (MAX_PART_BYTES + 1) as u64,
        [0x66; 32],
    )
    .unwrap();
    let state = DurableLiveTransferStateV1::empty_with_buffer_budget(10).unwrap();
    let first = state
        .accept_part(&binding, carrier(identity, 0, vec![0x66; 6]), START_MS)
        .unwrap();
    assert_eq!(first.state().buffered_bytes(), 6);

    let other = DurableStreamTransferIdentity::from_catalog_metadata(
        9,
        10,
        (MAX_PART_BYTES + 1) as u64,
        [0x67; 32],
    )
    .unwrap();
    let full = state_after(first)
        .accept_part(&binding, carrier(other, 0, vec![0x67; 5]), START_MS + 1)
        .unwrap();
    assert_eq!(
        full.outcome(),
        &DurableTransferOutcomeV1::NeedsBootstrap {
            error: DurableTransferBootstrapError::ReassemblyFull,
        }
    );
    assert_eq!(full.state().buffered_bytes(), 0);
}

#[test]
fn final_part_budget_includes_durable_part_and_second_assembly_copy() {
    let binding = catalog_binding(0x3e, 0x4e);
    let payload = vec![0x6a; 6];
    let identity = DurableStreamTransferIdentity::for_catalog(23, 23, &payload).unwrap();
    let rejected = DurableLiveTransferStateV1::empty_with_buffer_budget(11)
        .unwrap()
        .accept_part(&binding, carrier(identity, 0, payload), START_MS)
        .unwrap();
    assert_eq!(
        rejected.outcome(),
        &DurableTransferOutcomeV1::NeedsBootstrap {
            error: DurableTransferBootstrapError::ReassemblyFull,
        }
    );
    assert_eq!(rejected.state().buffered_bytes(), 0);
}

#[test]
fn completed_tombstone_deduplicates_without_reemitting_payload() {
    let binding = catalog_binding(0x37, 0x47);
    let payload = b"one-part".to_vec();
    let identity = DurableStreamTransferIdentity::for_catalog(11, 11, &payload).unwrap();
    let frame = carrier(identity, 0, payload);
    let complete = DurableLiveTransferStateV1::empty()
        .accept_part(&binding, frame.clone(), START_MS)
        .unwrap();
    assert!(matches!(
        complete.outcome(),
        DurableTransferOutcomeV1::Complete { .. }
    ));
    let duplicate = state_after(complete)
        .accept_part(&binding, frame, START_MS + 1)
        .unwrap();
    assert_eq!(
        duplicate.outcome(),
        &DurableTransferOutcomeV1::AlreadyComplete
    );
    assert_eq!(duplicate.state().completed_count(), 1);
}

#[test]
fn completed_tombstone_is_binding_scoped_absolute_ttl_and_capped_at_256() {
    let binding = catalog_binding(0x3f, 0x4f);
    let payload = b"ttl-tombstone".to_vec();
    let identity = DurableStreamTransferIdentity::for_catalog(24, 24, &payload).unwrap();
    let frame = carrier(identity, 0, payload);
    let complete = DurableLiveTransferStateV1::empty()
        .accept_part(&binding, frame.clone(), START_MS)
        .unwrap();
    let duplicate = state_after(complete)
        .accept_part(&binding, frame.clone(), START_MS + TRANSFER_TTL_MS - 1)
        .unwrap();
    assert_eq!(
        duplicate.outcome(),
        &DurableTransferOutcomeV1::AlreadyComplete
    );
    let expired = state_after(duplicate)
        .accept_part(&binding, frame.clone(), START_MS + TRANSFER_TTL_MS)
        .unwrap();
    assert!(matches!(
        expired.outcome(),
        DurableTransferOutcomeV1::Complete { .. }
    ));

    let other_binding = catalog_binding(0x40, 0x50);
    let other = state_after(expired)
        .accept_part(&other_binding, frame, START_MS + TRANSFER_TTL_MS + 1)
        .unwrap();
    assert!(matches!(
        other.outcome(),
        DurableTransferOutcomeV1::Complete { .. }
    ));
    assert_eq!(other.state().completed_count(), 2);

    let mut state = DurableLiveTransferStateV1::empty();
    let mut first_frame = None;
    let mut latest_frame = None;
    for index in 0_u16..=256 {
        let payload = index.to_be_bytes().to_vec();
        let identity = DurableStreamTransferIdentity::for_catalog(25, 25, &payload).unwrap();
        let frame = carrier(identity, 0, payload);
        first_frame.get_or_insert_with(|| frame.clone());
        latest_frame = Some(frame.clone());
        state = state
            .accept_part(&binding, frame, START_MS + u64::from(index))
            .unwrap()
            .into_state();
    }
    assert_eq!(state.completed_count(), 256);
    let evicted = state
        .accept_part(
            &binding,
            first_frame.expect("first tombstone fixture"),
            START_MS + 257,
        )
        .unwrap();
    assert!(matches!(
        evicted.outcome(),
        DurableTransferOutcomeV1::Complete { .. }
    ));
    assert_eq!(evicted.state().completed_count(), 256);
    let latest = state_after(evicted)
        .accept_part(
            &binding,
            latest_frame.expect("latest tombstone fixture"),
            START_MS + 258,
        )
        .unwrap();
    assert_eq!(latest.outcome(), &DurableTransferOutcomeV1::AlreadyComplete);
}

#[test]
fn exact_expiry_cleanup_purges_tombstone_before_advancing_clock_watermark() {
    let binding = catalog_binding(0x41, 0x51);
    let payload = b"cleanup-expired-tombstone".to_vec();
    let identity = DurableStreamTransferIdentity::for_catalog(26, 26, &payload).unwrap();
    let completed = DurableLiveTransferStateV1::empty()
        .accept_part(&binding, carrier(identity, 0, payload), START_MS)
        .unwrap()
        .into_state();
    assert_eq!(completed.completed_count(), 1);

    let cleaned = completed
        .cleanup_exact_binding(&binding, START_MS + TRANSFER_TTL_MS)
        .expect("exact-expiry cleanup purges completed tombstone first");
    assert_eq!(cleaned.completed_count(), 0);
    assert!(cleaned.canonical_record_bytes().unwrap().is_empty());
}

#[test]
fn wrong_target_stale_binding_message_and_channel_fail_closed() {
    let conversation = canonical_id(0x61);
    let event = canonical_id(0x62);
    let event_payload = b"event".to_vec();
    let event_identity = DurableStreamTransferIdentity::for_event(
        &ConversationId::new(&conversation),
        &EventId::new(event),
        1,
        &event_payload,
    )
    .unwrap();
    let wrong_target = DurableLiveTransferStateV1::empty()
        .accept_part(
            &catalog_binding(0x38, 0x48),
            carrier(event_identity, 0, event_payload),
            START_MS,
        )
        .unwrap();
    assert_eq!(
        wrong_target.outcome(),
        &DurableTransferOutcomeV1::NeedsBootstrap {
            error: DurableTransferBootstrapError::TargetMismatch,
        }
    );

    let old_binding = catalog_binding(0x39, 0x49);
    let replacement = catalog_binding(0x3a, 0x4a);
    let (_identity, _payload, first, final_part) = split_catalog(12, 13);
    let buffered = DurableLiveTransferStateV1::empty()
        .accept_part(&old_binding, first, START_MS)
        .unwrap();
    let stale = state_after(buffered)
        .accept_part(&replacement, final_part, START_MS + 1)
        .unwrap();
    assert_eq!(
        stale.outcome(),
        &DurableTransferOutcomeV1::NeedsBootstrap {
            error: DurableTransferBootstrapError::StaleBinding,
        }
    );
    assert_eq!(stale.state().active_count(), 0);

    let payload = b"metadata".to_vec();
    let identity = DurableStreamTransferIdentity::for_catalog(14, 14, &payload).unwrap();
    let mut wrong_message = carrier(identity, 0, payload.clone());
    wrong_message.message_id = agentdeck_protocol::runtime::identity::MessageId::new("wrong");
    let wrong_message = DurableLiveTransferStateV1::empty()
        .accept_part(&old_binding, wrong_message, START_MS)
        .unwrap();
    assert_eq!(
        wrong_message.outcome(),
        &DurableTransferOutcomeV1::NeedsBootstrap {
            error: DurableTransferBootstrapError::MetadataMismatch,
        }
    );

    let mut wrong_channel = carrier(identity, 0, payload);
    wrong_channel.channel = RuntimeTransferChannel::Reply;
    let wrong_channel = DurableLiveTransferStateV1::empty()
        .accept_part(&old_binding, wrong_channel, START_MS)
        .unwrap();
    assert_eq!(
        wrong_channel.outcome(),
        &DurableTransferOutcomeV1::NeedsBootstrap {
            error: DurableTransferBootstrapError::MetadataMismatch,
        }
    );
}

#[test]
fn length_and_hash_failures_abort_active_bytes_to_bootstrap_marker() {
    let binding = catalog_binding(0x3b, 0x4b);
    let identity = DurableStreamTransferIdentity::from_catalog_metadata(
        15,
        16,
        (MAX_PART_BYTES + 1) as u64,
        [0x99; 32],
    )
    .unwrap();
    let first = DurableLiveTransferStateV1::empty()
        .accept_part(&binding, carrier(identity, 0, vec![0x99]), START_MS)
        .unwrap();
    let length = state_after(first)
        .accept_part(&binding, carrier(identity, 1, vec![0x99]), START_MS + 1)
        .unwrap();
    assert_eq!(
        length.outcome(),
        &DurableTransferOutcomeV1::NeedsBootstrap {
            error: DurableTransferBootstrapError::LengthMismatch,
        }
    );
    assert_eq!(length.state().buffered_bytes(), 0);

    let payload = vec![0x21; MAX_PART_BYTES + 1];
    let hash_identity = DurableStreamTransferIdentity::from_catalog_metadata(
        17,
        18,
        payload.len() as u64,
        [0x22; 32],
    )
    .unwrap();
    let first = DurableLiveTransferStateV1::empty()
        .accept_part(
            &binding,
            carrier(hash_identity, 0, payload[..MAX_PART_BYTES].to_vec()),
            START_MS,
        )
        .unwrap();
    let hash = state_after(first)
        .accept_part(
            &binding,
            carrier(hash_identity, 1, payload[MAX_PART_BYTES..].to_vec()),
            START_MS + 1,
        )
        .unwrap();
    assert_eq!(
        hash.outcome(),
        &DurableTransferOutcomeV1::NeedsBootstrap {
            error: DurableTransferBootstrapError::HashMismatch,
        }
    );
}

#[test]
fn explicit_abort_marks_bootstrap_and_exact_teardown_cleans_active_and_marker() {
    let binding = catalog_binding(0x3c, 0x4c);
    let (identity, _payload, first, _) = split_catalog(19, 20);
    let buffered = DurableLiveTransferStateV1::empty()
        .accept_part(&binding, first, START_MS)
        .unwrap();
    let aborted = state_after(buffered)
        .abort_exact_binding(
            &binding,
            Some(&identity.transfer_id()),
            DurableTransferBootstrapError::PayloadRejected,
            START_MS + 1,
        )
        .unwrap();
    assert_eq!(
        aborted.outcome(),
        &DurableTransferOutcomeV1::NeedsBootstrap {
            error: DurableTransferBootstrapError::PayloadRejected,
        }
    );
    assert_eq!(aborted.state().active_count(), 0);
    assert_eq!(aborted.state().marker_count(), 1);

    let blocked = state_after(aborted)
        .accept_part(&binding, carrier(identity, 0, vec![0x11]), START_MS + 2)
        .unwrap();
    assert!(matches!(
        blocked.outcome(),
        DurableTransferOutcomeV1::NeedsBootstrap { .. }
    ));
    let cleaned = state_after(blocked)
        .cleanup_exact_binding(&binding, START_MS + 3)
        .unwrap();
    assert_eq!(cleaned.active_count(), 0);
    assert_eq!(cleaned.marker_count(), 0);
    assert!(cleaned.canonical_record_bytes().unwrap().is_empty());
}

#[test]
fn malformed_record_and_wrong_transfer_id_fail_close_on_restart() {
    let binding = catalog_binding(0x3d, 0x4d);
    let (_identity, _payload, first, _) = split_catalog(21, 22);
    let transition = DurableLiveTransferStateV1::empty()
        .accept_part(&binding, first, START_MS)
        .unwrap();
    let mut records = transition.record_bytes().to_vec();
    records[0].push(0);
    assert_eq!(
        DurableLiveTransferStateV1::from_record_bytes(&records).unwrap_err(),
        DurableTransferStateError::InvalidRecord
    );

    let invalid = TransferId::new("not-adrt-shared");
    assert!(DurableStreamTransferIdentity::parse_transfer_id(&invalid).is_err());
}
