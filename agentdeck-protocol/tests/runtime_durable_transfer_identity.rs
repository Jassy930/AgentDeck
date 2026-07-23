use agentdeck_protocol::runtime::identity::{ConversationId, EventId, MessageId, TransferId};
use agentdeck_protocol::runtime::{
    DurableStreamTransferIdentity, DurableStreamTransferIdentityError, DurableStreamTransferSource,
    MAX_DURABLE_CATALOG_REVISIONS, MAX_PART_BYTES, MAX_TRANSFER_BYTES, RUNTIME_PROTOCOL_VERSION,
    RuntimeTransferCarrierV1, RuntimeTransferChannel, TransferEnvelope,
};

const ZERO_SHA256: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[test]
fn catalog_multi_revision_identity_and_message_id_are_exact_and_round_trip() {
    let identity = DurableStreamTransferIdentity::for_catalog(7, 9, b"catalog-range")
        .expect("three-revision catalog publication");

    assert_eq!(
        identity.transfer_id().as_str(),
        "adrt-shared-v1:c:7:9:13:74b9185a4008025f022200e26de1150b6c4c79b4a4860aaa32b38bac21c8544f"
    );
    assert_eq!(
        identity.message_id().as_str(),
        "shared-transfer-d65b6dde1618e82637b6f53015b12d739362731c55bab31863903f49ca9eb96e"
    );
    assert_eq!(
        identity.source(),
        DurableStreamTransferSource::Catalog {
            first_revision: 7,
            through_revision: 9,
        }
    );
    assert_eq!(
        DurableStreamTransferIdentity::parse_transfer_id(&identity.transfer_id()),
        Ok(identity)
    );
}

#[test]
fn event_identity_binds_canonical_ids_sequence_bytes_and_message_id() {
    let conversation = ConversationId::new("11111111-1111-4111-8111-111111111111");
    let event = EventId::new("22222222-2222-4222-8222-222222222222");
    let identity =
        DurableStreamTransferIdentity::for_event(&conversation, &event, 42, b"event-payload")
            .expect("canonical event source");

    assert_eq!(
        identity.transfer_id().as_str(),
        "adrt-shared-v1:e:11111111-1111-4111-8111-111111111111:22222222-2222-4222-8222-222222222222:42:13:f484a64a69d92ecf6c00aa2a387a7cdcee3bcf3c5944659d1fd381f4c40852f3"
    );
    assert_eq!(
        identity.message_id().as_str(),
        "shared-transfer-5e0f0dd07d8215097666057bd791c0bc4f500ccb73c83c115bc9be0bedcd31ae"
    );
    let DurableStreamTransferSource::Event {
        conversation_id,
        event_id,
        event_seq,
    } = identity.source()
    else {
        panic!("event source");
    };
    assert_eq!(conversation_id.to_string(), conversation.as_str());
    assert_eq!(event_id.to_string(), event.as_str());
    assert_eq!(event_seq, 42);
    assert_eq!(
        DurableStreamTransferIdentity::parse_transfer_id(&identity.transfer_id()),
        Ok(identity)
    );
}

#[test]
fn compact_part_count_is_derived_exactly_from_authenticated_total_bytes() {
    let identity = |total_bytes| {
        DurableStreamTransferIdentity::from_catalog_metadata(1, 1, total_bytes, [0; 32])
            .expect("bounded catalog metadata")
    };
    assert_eq!(identity(0).part_count(), 1);
    assert_eq!(identity(MAX_PART_BYTES as u64).part_count(), 1);
    assert_eq!(identity(MAX_PART_BYTES as u64 + 1).part_count(), 2);
    assert_eq!(identity(MAX_TRANSFER_BYTES).part_count(), 19);
    assert_eq!(
        DurableStreamTransferIdentity::from_catalog_metadata(1, 1, MAX_TRANSFER_BYTES + 1, [0; 32],),
        Err(DurableStreamTransferIdentityError::TooLarge)
    );
}

#[test]
fn parser_rejects_non_canonical_leading_zero_and_overwide_catalog_identities() {
    let invalid = [
        format!("adrt-shared-v1:c:07:9:0:{ZERO_SHA256}"),
        format!("adrt-shared-v1:c:7:09:0:{ZERO_SHA256}"),
        format!("adrt-shared-v1:c:7:9:00:{ZERO_SHA256}"),
        format!("adrt-shared-v1:c:9:7:0:{ZERO_SHA256}"),
        format!("adrt-shared-v1:c:0:500:0:{ZERO_SHA256}"),
        format!(
            "adrt-shared-v1:c:7:9:0:{}",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_ascii_uppercase()
        ),
        format!(
            "adrt-shared-v1:e:11111111-1111-4111-8111-111111111111:22222222-2222-4222-8222-222222222222:042:0:{ZERO_SHA256}"
        ),
        format!(
            "adrt-shared-v1:e:11111111-1111-4111-8111-11111111111A:22222222-2222-4222-8222-222222222222:42:0:{ZERO_SHA256}"
        ),
        format!(
            "adrt-shared-v1:e:00000000-0000-0000-0000-000000000000:22222222-2222-4222-8222-222222222222:42:0:{ZERO_SHA256}"
        ),
    ];
    for value in invalid {
        assert!(
            DurableStreamTransferIdentity::parse_transfer_id(&TransferId::new(value)).is_err(),
            "non-canonical identity must fail close"
        );
    }

    assert_eq!(MAX_DURABLE_CATALOG_REVISIONS, 500);
    assert!(DurableStreamTransferIdentity::for_catalog(7, 506, b"max-range").is_ok());
    assert!(
        DurableStreamTransferIdentity::for_catalog(
            u64::MAX - (MAX_DURABLE_CATALOG_REVISIONS - 1),
            u64::MAX,
            b"max-extreme-range",
        )
        .is_ok()
    );
    assert_eq!(
        DurableStreamTransferIdentity::for_catalog(7, 507, b"too-wide"),
        Err(DurableStreamTransferIdentityError::TooLarge)
    );
    assert_eq!(
        DurableStreamTransferIdentity::from_catalog_metadata(0, u64::MAX, 0, [0; 32]),
        Err(DurableStreamTransferIdentityError::TooLarge)
    );
    assert_eq!(
        DurableStreamTransferIdentity::parse_transfer_id(&TransferId::new("x".repeat(1025))),
        Err(DurableStreamTransferIdentityError::InvalidIdentity)
    );
    assert_eq!(
        DurableStreamTransferIdentity::for_event(
            &ConversationId::new("11111111-1111-4111-8111-11111111111A"),
            &EventId::new("22222222-2222-4222-8222-222222222222"),
            42,
            b"event",
        ),
        Err(DurableStreamTransferIdentityError::InvalidSource)
    );
}

#[test]
fn compact_carrier_metadata_must_match_the_identity_exactly() {
    let payload = b"authenticated-transfer";
    let identity =
        DurableStreamTransferIdentity::for_catalog(9, 9, payload).expect("single catalog revision");
    let transfer = TransferEnvelope::new(
        identity.transfer_id(),
        0,
        identity.part_count(),
        identity.total_sha256(),
        identity.total_bytes(),
        payload.to_vec(),
    )
    .expect("bounded compact transfer");
    let carrier = RuntimeTransferCarrierV1::new(
        identity.message_id(),
        RuntimeTransferChannel::Stream,
        transfer,
    );
    assert_eq!(identity.validate_carrier(&carrier), Ok(()));

    let mut mismatches = Vec::new();
    let mut changed = carrier.clone();
    changed.runtime_version = RUNTIME_PROTOCOL_VERSION + 1;
    mismatches.push(changed);
    let mut changed = carrier.clone();
    changed.channel = RuntimeTransferChannel::Reply;
    mismatches.push(changed);
    let mut changed = carrier.clone();
    changed.message_id = MessageId::new("different-message");
    mismatches.push(changed);
    let mut changed = carrier.clone();
    changed.transfer.transfer_id = TransferId::new("different-transfer");
    mismatches.push(changed);
    let mut changed = carrier.clone();
    changed.transfer.part_count += 1;
    mismatches.push(changed);
    let mut changed = carrier.clone();
    changed.transfer.total_bytes += 1;
    mismatches.push(changed);
    let mut changed = carrier;
    changed.transfer.total_sha256[0] ^= 0xff;
    mismatches.push(changed);

    for changed in mismatches {
        assert_eq!(
            identity.validate_carrier(&changed),
            Err(DurableStreamTransferIdentityError::MetadataMismatch)
        );
    }
}
