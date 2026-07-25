//! P4.6 bounded KeySync 持久协调状态契约。

use agentdeck_cli::remote::key_sync::{
    DurableKeySyncStateV1, FrozenKeySyncSendV1, KEY_SYNC_MAX_SEND_BYTES, KEY_SYNC_WINDOW_MS,
    KeySyncCoordinationStatus, KeySyncError, KeySyncInstallOutcome,
    SignedHigherRevisionObservationV1,
};
use agentdeck_crypto::sha256;
use agentdeck_protocol::e2ee::{
    DirectoryCurrentV1, E2EE_FORMAT_VERSION, KeyId, KeyPurpose, KeySyncRequestV1, KeyUpdateSetV1,
    KeyUpdateV1, SignedSealedBlobV1, UnsignedSealedBlobV1,
};
use agentdeck_protocol::relay_v2::frame::{SealedBlob, Send};
use agentdeck_protocol::relay_v2::{
    DeviceRouteId, Ed25519Signature, GrantSerial, KeyDirectoryRevision, MachineRouteId,
    OpaqueRouteFrame, RELAY_PROTOCOL_VERSION, RelayFrameBody, RequestRouteId, StreamGenerationId,
    StreamRouteId, TrustEpoch, encode,
};
use agentdeck_protocol::runtime::RUNTIME_PROTOCOL_VERSION;

const STARTED_AT_MS: u64 = 1_000_000;

fn observation() -> SignedHigherRevisionObservationV1 {
    SignedHigherRevisionObservationV1::new(
        MachineRouteId::from_bytes([0x11; 16]),
        DeviceRouteId::from_bytes([0x22; 16]),
        GrantSerial::new(7),
        TrustEpoch::new(3),
        KeyDirectoryRevision::new(11),
        KeyDirectoryRevision::new(14),
        KeyId {
            purpose: KeyPurpose::ConversationDek,
            epoch: 5,
        },
        Some(StreamRouteId::from_bytes([0x33; 16])),
        StreamRouteId::from_bytes([0x33; 16]),
        StreamGenerationId::from_bytes([0x34; 16]),
        17,
        23,
        [0x44; 32],
        [0x55; 32],
    )
    .expect("valid signed higher-revision observation")
}

fn catalog_observation() -> SignedHigherRevisionObservationV1 {
    SignedHigherRevisionObservationV1::new(
        MachineRouteId::from_bytes([0x81; 16]),
        DeviceRouteId::from_bytes([0x82; 16]),
        GrantSerial::new(9),
        TrustEpoch::new(4),
        KeyDirectoryRevision::new(21),
        KeyDirectoryRevision::new(22),
        KeyId {
            purpose: KeyPurpose::Catalog,
            epoch: 8,
        },
        None,
        StreamRouteId::from_bytes([0x83; 16]),
        StreamGenerationId::from_bytes([0x84; 16]),
        29,
        31,
        [0x85; 32],
        [0x86; 32],
    )
    .expect("valid Catalog observation with independent publication route")
}

fn observation_with_outer_axes(
    base: &SignedHigherRevisionObservationV1,
    publication_stream_route: StreamRouteId,
    publication_stream_generation: StreamGenerationId,
    publication_stream_seq: u64,
    sender_counter: u64,
) -> SignedHigherRevisionObservationV1 {
    let key_slot_stream_route = base
        .key_slot_stream_route()
        .map(|_| publication_stream_route);
    SignedHigherRevisionObservationV1::new(
        base.machine_route(),
        base.device_route(),
        base.grant_serial(),
        base.root_trust_epoch(),
        base.known_key_directory_revision(),
        base.observed_key_directory_revision(),
        base.observed_key_id(),
        key_slot_stream_route,
        publication_stream_route,
        publication_stream_generation,
        publication_stream_seq,
        sender_counter,
        base.signed_frame_sha256(),
        base.ciphertext_sha256(),
    )
    .expect("valid alternate outer stream axes")
}

fn observation_with_hashes(
    base: &SignedHigherRevisionObservationV1,
    signed_frame_sha256: [u8; 32],
    ciphertext_sha256: [u8; 32],
) -> SignedHigherRevisionObservationV1 {
    SignedHigherRevisionObservationV1::new(
        base.machine_route(),
        base.device_route(),
        base.grant_serial(),
        base.root_trust_epoch(),
        base.known_key_directory_revision(),
        base.observed_key_directory_revision(),
        base.observed_key_id(),
        base.key_slot_stream_route(),
        base.publication_stream_route(),
        base.publication_stream_generation(),
        base.publication_stream_seq(),
        base.sender_counter(),
        signed_frame_sha256,
        ciphertext_sha256,
    )
    .expect("valid alternate observation hashes")
}

fn signed_command_blob(request_revision: KeyDirectoryRevision, seed: u8) -> SignedSealedBlobV1 {
    UnsignedSealedBlobV1::new(
        KeyId {
            purpose: KeyPurpose::DeviceCommandTx,
            epoch: 4,
        },
        4,
        request_revision.value(),
        [seed; 12],
        vec![seed; 16],
    )
    .attach_signature(Ed25519Signature([seed; 64]))
}

fn frozen_attempt(
    observation: &SignedHigherRevisionObservationV1,
    attempt: u8,
    request_route_seed: u8,
) -> FrozenKeySyncSendV1 {
    let request = observation
        .request_for_attempt(attempt)
        .expect("bounded KeySync request");
    frozen_request(request, request_route_seed)
}

fn frozen_request(request: KeySyncRequestV1, request_route_seed: u8) -> FrozenKeySyncSendV1 {
    let frame = OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::Send(Send {
            device_route: request.device_route,
            request_route: RequestRouteId::from_bytes([request_route_seed; 16]),
            sealed_blob: SealedBlob(
                signed_command_blob(request.requested_key_directory_revision, request_route_seed)
                    .to_wire_bytes(),
            ),
        }),
    };
    FrozenKeySyncSendV1::new(request, encode(&frame)).expect("freeze exact Relay Send")
}

fn directory_current(observation: &SignedHigherRevisionObservationV1) -> DirectoryCurrentV1 {
    DirectoryCurrentV1 {
        format_version: E2EE_FORMAT_VERSION,
        runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
        relay_protocol_version: RELAY_PROTOCOL_VERSION,
        machine_route: observation.machine_route(),
        device_route: observation.device_route(),
        grant_serial: observation.grant_serial(),
        root_trust_epoch: observation.root_trust_epoch(),
        current_key_directory_revision: observation.known_key_directory_revision(),
        requested_key_directory_revision: observation.requested_key_directory_revision(),
    }
}

fn update_set_for_request(request: &KeySyncRequestV1) -> KeyUpdateSetV1 {
    KeyUpdateSetV1 {
        key_directory_revision: request.requested_key_directory_revision,
        device_route: request.device_route,
        updates: vec![KeyUpdateV1 {
            key_directory_revision: request.requested_key_directory_revision,
            key_id: KeyId {
                purpose: request.key_id.purpose,
                epoch: request.key_id.epoch - 1,
            },
            device_route: request.device_route,
            stream_route: request.stream_route,
            enc: vec![0x61; 32],
            wrapped_key: vec![0x62; 48],
            signature: Ed25519Signature([0x63; 64]),
        }],
    }
}

fn matching_update_set(observation: &SignedHigherRevisionObservationV1) -> KeyUpdateSetV1 {
    update_set_for_request(
        &observation
            .request_for_attempt(1)
            .expect("valid first KeySync request"),
    )
}

fn initial_state() -> DurableKeySyncStateV1 {
    let observation = observation();
    let first = frozen_attempt(&observation, 1, 0x71);
    DurableKeySyncStateV1::start(observation, STARTED_AT_MS, first).expect("start bounded KeySync")
}

fn resolved_catalog_state() -> DurableKeySyncStateV1 {
    let observation = catalog_observation();
    let state = DurableKeySyncStateV1::start(
        observation.clone(),
        STARTED_AT_MS,
        frozen_attempt(&observation, 1, 0x87),
    )
    .expect("start one-revision Catalog KeySync");
    let update_set = update_set_for_request(active_send(&state).request());
    let update_hash = update_set
        .canonical_sha256()
        .expect("resolved Catalog update hash");
    state
        .into_update_set_handoff(
            STARTED_AT_MS + 1_000,
            RequestRouteId::from_bytes([0x87; 16]),
            update_set,
        )
        .expect("Catalog UpdateSet handoff")
        .after_durable_install(STARTED_AT_MS + 2_000, update_hash)
        .expect("durably resolve Catalog KeySync")
        .into_state()
}

fn active_send(state: &DurableKeySyncStateV1) -> &FrozenKeySyncSendV1 {
    state.active_send().expect("fixture has an active probe")
}

#[test]
fn canonical_state_roundtrip_freezes_absolute_budget_and_exact_send() {
    let state = initial_state();
    assert_eq!(
        state.observation().observed_key_directory_revision(),
        KeyDirectoryRevision::new(14)
    );
    assert_eq!(
        active_send(&state)
            .request()
            .requested_key_directory_revision,
        KeyDirectoryRevision::new(12),
        "KeySync walks exact next revision instead of skipping to the observation"
    );
    assert_eq!(state.started_at_ms(), STARTED_AT_MS);
    assert_eq!(state.deadline_at_ms(), STARTED_AT_MS + KEY_SYNC_WINDOW_MS);
    assert_eq!(state.last_observed_at_ms(), STARTED_AT_MS);
    assert_eq!(state.attempt(), 1);
    assert_eq!(state.attempt_count(), 1);
    assert_eq!(
        active_send(&state).exact_send_sha256(),
        sha256(active_send(&state).exact_send_bytes())
    );
    assert_eq!(
        active_send(&state).request_sha256(),
        sha256(
            &active_send(&state)
                .request()
                .canonical_bytes()
                .expect("canonical request")
        )
    );

    let canonical = state.canonical_bytes().expect("canonical durable state");
    let reopened =
        DurableKeySyncStateV1::from_canonical_bytes(&canonical).expect("restart readback");
    assert_eq!(reopened, state);
    assert_eq!(
        reopened.canonical_bytes().expect("re-encode durable state"),
        canonical
    );

    let mut tampered = canonical;
    *tampered.last_mut().expect("non-empty state") ^= 0x01;
    assert_eq!(
        DurableKeySyncStateV1::from_canonical_bytes(&tampered),
        Err(KeySyncError::InvalidCanonical)
    );
}

#[test]
fn catalog_without_key_slot_still_binds_publication_identity_durably() {
    let observation = catalog_observation();
    assert_eq!(observation.key_slot_stream_route(), None);
    assert_eq!(
        observation.publication_stream_route(),
        StreamRouteId::from_bytes([0x83; 16])
    );
    assert_eq!(
        observation.publication_stream_generation(),
        StreamGenerationId::from_bytes([0x84; 16])
    );
    assert_eq!(observation.publication_stream_seq(), 29);
    assert_eq!(observation.sender_counter(), 31);

    let first = frozen_attempt(&observation, 1, 0x87);
    let state = DurableKeySyncStateV1::start(observation.clone(), STARTED_AT_MS, first)
        .expect("start Catalog KeySync");
    let canonical = state.canonical_bytes().expect("persist Catalog KeySync");
    let mut reopened =
        DurableKeySyncStateV1::from_canonical_bytes(&canonical).expect("reopen Catalog KeySync");
    assert_eq!(reopened.observation(), &observation);
    assert_eq!(reopened.observation().key_slot_stream_route(), None);
    assert_eq!(
        reopened.observation().publication_stream_route(),
        StreamRouteId::from_bytes([0x83; 16])
    );
    assert_eq!(
        reopened.observation().publication_stream_generation(),
        StreamGenerationId::from_bytes([0x84; 16])
    );
    assert_eq!(reopened.observation().publication_stream_seq(), 29);
    assert_eq!(reopened.observation().sender_counter(), 31);

    let different_publication = observation_with_outer_axes(
        &observation,
        StreamRouteId::from_bytes([0x88; 16]),
        observation.publication_stream_generation(),
        observation.publication_stream_seq(),
        observation.sender_counter(),
    );
    assert_eq!(different_publication.key_slot_stream_route(), None);
    assert_eq!(
        reopened.observe_again(&different_publication, STARTED_AT_MS + 1_000),
        Err(KeySyncError::ObservationConflict)
    );
}

#[test]
fn durable_installs_walk_11_to_14_without_resetting_one_budget() {
    let state = initial_state();
    let retained_observation = state.observation().clone();
    let first_request = active_send(&state).request().clone();
    assert_eq!(first_request.known_key_directory_revision.value(), 11);
    assert_eq!(first_request.requested_key_directory_revision.value(), 12);
    assert_eq!(first_request.attempt, 1);

    let first_update = update_set_for_request(&first_request);
    let first_update_hash = first_update
        .canonical_sha256()
        .expect("first update set hash");
    let first_handoff = state
        .into_update_set_handoff(
            STARTED_AT_MS + 1_000,
            RequestRouteId::from_bytes([0x71; 16]),
            first_update,
        )
        .expect("first update handoff");
    let first_outcome = first_handoff
        .after_durable_install(STARTED_AT_MS + 2_000, first_update_hash)
        .expect("durably install revision 12");
    assert!(matches!(&first_outcome, KeySyncInstallOutcome::Continue(_)));
    assert_eq!(first_outcome.public_code(), None);
    let state = first_outcome.into_state();
    assert_eq!(state.status(), KeySyncCoordinationStatus::AwaitingProbe);
    assert_eq!(state.current_known_key_directory_revision().value(), 12);
    assert_eq!(state.attempt_count(), 1);
    assert_eq!(state.started_at_ms(), STARTED_AT_MS);
    assert_eq!(state.deadline_at_ms(), STARTED_AT_MS + KEY_SYNC_WINDOW_MS);
    assert_eq!(state.observation(), &retained_observation);
    let first_ack = state
        .latest_completed_ack_basis()
        .expect("first durable ACK basis");
    assert_eq!(first_ack.attempt(), 1);
    assert_eq!(
        first_ack.source_request_route(),
        RequestRouteId::from_bytes([0x71; 16])
    );
    assert_eq!(first_ack.key_directory_revision().value(), 12);
    assert_eq!(first_ack.update_set_sha256(), first_update_hash);

    let canonical = state
        .canonical_bytes()
        .expect("persist continuation after revision 12");
    let mut state = DurableKeySyncStateV1::from_canonical_bytes(&canonical)
        .expect("restart continuation after revision 12");
    let second_request = state.next_request().expect("request revision 13");
    assert_eq!(second_request.known_key_directory_revision.value(), 12);
    assert_eq!(second_request.requested_key_directory_revision.value(), 13);
    assert_eq!(second_request.attempt, 2);
    state
        .freeze_next_probe(
            STARTED_AT_MS + 3_000,
            frozen_request(second_request.clone(), 0x72),
        )
        .expect("freeze second probe");
    let current_after_first_install = DirectoryCurrentV1 {
        format_version: E2EE_FORMAT_VERSION,
        runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
        relay_protocol_version: RELAY_PROTOCOL_VERSION,
        machine_route: retained_observation.machine_route(),
        device_route: retained_observation.device_route(),
        grant_serial: retained_observation.grant_serial(),
        root_trust_epoch: retained_observation.root_trust_epoch(),
        current_key_directory_revision: second_request.known_key_directory_revision,
        requested_key_directory_revision: second_request.requested_key_directory_revision,
    };
    let retry_second_request = state
        .next_retry_request_after_directory_current(
            STARTED_AT_MS + 3_500,
            RequestRouteId::from_bytes([0x72; 16]),
            &current_after_first_install,
        )
        .expect("derive retry from the installed intermediate revision");
    assert_eq!(
        retry_second_request.known_key_directory_revision.value(),
        12
    );
    assert_eq!(
        retry_second_request
            .requested_key_directory_revision
            .value(),
        13
    );
    assert_eq!(retry_second_request.attempt, 3);

    let second_update = update_set_for_request(&second_request);
    let second_update_hash = second_update
        .canonical_sha256()
        .expect("second update set hash");
    let second_handoff = state
        .into_update_set_handoff(
            STARTED_AT_MS + 4_000,
            RequestRouteId::from_bytes([0x72; 16]),
            second_update,
        )
        .expect("second update handoff");
    assert_eq!(second_handoff.started_at_ms(), STARTED_AT_MS);
    assert_eq!(
        second_handoff.deadline_at_ms(),
        STARTED_AT_MS + KEY_SYNC_WINDOW_MS
    );
    assert_eq!(second_handoff.attempt_count(), 2);
    let second_outcome = second_handoff
        .after_durable_install(STARTED_AT_MS + 5_000, second_update_hash)
        .expect("durably install revision 13");
    assert!(matches!(
        &second_outcome,
        KeySyncInstallOutcome::Continue(_)
    ));
    let state = second_outcome.into_state();
    assert_eq!(state.current_known_key_directory_revision().value(), 13);
    assert_eq!(state.attempt_count(), 2);
    let second_ack = state
        .latest_completed_ack_basis()
        .expect("second durable ACK basis");
    assert_eq!(second_ack.attempt(), 2);
    assert_eq!(
        second_ack.source_request_route(),
        RequestRouteId::from_bytes([0x72; 16])
    );
    assert_eq!(second_ack.key_directory_revision().value(), 13);
    assert_eq!(second_ack.update_set_sha256(), second_update_hash);

    let canonical = state
        .canonical_bytes()
        .expect("persist continuation after revision 13");
    let mut state = DurableKeySyncStateV1::from_canonical_bytes(&canonical)
        .expect("restart continuation after revision 13");
    let third_request = state.next_request().expect("request revision 14");
    assert_eq!(third_request.known_key_directory_revision.value(), 13);
    assert_eq!(third_request.requested_key_directory_revision.value(), 14);
    assert_eq!(third_request.attempt, 3);
    state
        .freeze_next_probe(
            STARTED_AT_MS + 6_000,
            frozen_request(third_request.clone(), 0x73),
        )
        .expect("freeze third probe");

    let third_update = update_set_for_request(&third_request);
    let third_update_hash = third_update
        .canonical_sha256()
        .expect("third update set hash");
    let third_outcome = state
        .into_update_set_handoff(
            STARTED_AT_MS + 7_000,
            RequestRouteId::from_bytes([0x73; 16]),
            third_update,
        )
        .expect("third update handoff")
        .after_durable_install(STARTED_AT_MS + 8_000, third_update_hash)
        .expect("durably install revision 14");
    assert!(matches!(&third_outcome, KeySyncInstallOutcome::Resolved(_)));
    assert_eq!(third_outcome.public_code(), None);
    let resolved = third_outcome.into_state();
    assert_eq!(resolved.status(), KeySyncCoordinationStatus::Resolved);
    assert_eq!(resolved.current_known_key_directory_revision().value(), 14);
    assert_eq!(resolved.attempt_count(), 3);
    assert_eq!(resolved.started_at_ms(), STARTED_AT_MS);
    assert_eq!(
        resolved.deadline_at_ms(),
        STARTED_AT_MS + KEY_SYNC_WINDOW_MS
    );
    assert_eq!(resolved.observation(), &retained_observation);
    let third_ack = resolved
        .latest_completed_ack_basis()
        .expect("third durable ACK basis");
    assert_eq!(third_ack.attempt(), 3);
    assert_eq!(
        third_ack.source_request_route(),
        RequestRouteId::from_bytes([0x73; 16])
    );
    assert_eq!(third_ack.key_directory_revision().value(), 14);
    assert_eq!(third_ack.update_set_sha256(), third_update_hash);
    assert_eq!(resolved.active_send(), None);
    assert_eq!(resolved.next_request(), Err(KeySyncError::ResponseConflict));
}

#[test]
fn same_observation_reuses_exact_send_and_different_signed_hash_conflicts() {
    let mut state = initial_state();
    let exact_before = active_send(&state).exact_send_bytes().to_vec();
    let hash_before = active_send(&state).exact_send_sha256();
    let same = state.observation().clone();
    let retry = state
        .observe_again(&same, STARTED_AT_MS + 5_000)
        .expect("same signed observation exact retry");
    assert_eq!(retry.exact_send_bytes(), exact_before);
    assert_eq!(retry.exact_send_sha256(), hash_before);
    assert_eq!(state.attempt(), 1, "transport retry does not spend attempt");
    assert_eq!(state.last_observed_at_ms(), STARTED_AT_MS + 5_000);

    let conflicting = observation_with_hashes(&same, [0x99; 32], same.ciphertext_sha256());
    assert_eq!(
        state.observe_again(&conflicting, STARTED_AT_MS + 6_000),
        Err(KeySyncError::ObservationConflict)
    );
    assert_eq!(active_send(&state).exact_send_bytes(), exact_before);

    let conflicting_ciphertext =
        observation_with_hashes(&same, same.signed_frame_sha256(), [0x98; 32]);
    assert_eq!(
        state.observe_again(&conflicting_ciphertext, STARTED_AT_MS + 6_500),
        Err(KeySyncError::ObservationConflict)
    );

    for different_outer_axes in [
        observation_with_outer_axes(
            &same,
            StreamRouteId::from_bytes([0x35; 16]),
            same.publication_stream_generation(),
            same.publication_stream_seq(),
            same.sender_counter(),
        ),
        observation_with_outer_axes(
            &same,
            same.publication_stream_route(),
            StreamGenerationId::from_bytes([0x36; 16]),
            same.publication_stream_seq(),
            same.sender_counter(),
        ),
        observation_with_outer_axes(
            &same,
            same.publication_stream_route(),
            same.publication_stream_generation(),
            same.publication_stream_seq() + 1,
            same.sender_counter(),
        ),
        observation_with_outer_axes(
            &same,
            same.publication_stream_route(),
            same.publication_stream_generation(),
            same.publication_stream_seq(),
            same.sender_counter() + 1,
        ),
    ] {
        assert_eq!(
            state.observe_again(&different_outer_axes, STARTED_AT_MS + 7_000),
            Err(KeySyncError::ObservationConflict)
        );
    }
}

#[test]
fn directory_current_can_be_validated_before_reserving_the_next_counter() {
    let state = initial_state();
    let status = directory_current(state.observation());
    let before = state
        .canonical_bytes()
        .expect("state before read-only DirectoryCurrent validation");

    let next = state
        .next_retry_request_after_directory_current(
            STARTED_AT_MS + 1_000,
            RequestRouteId::from_bytes([0x71; 16]),
            &status,
        )
        .expect("validate DirectoryCurrent before sealing");
    assert_eq!(next.known_key_directory_revision.value(), 11);
    assert_eq!(next.requested_key_directory_revision.value(), 12);
    assert_eq!(next.attempt, 2);
    assert_eq!(
        state
            .canonical_bytes()
            .expect("state after read-only DirectoryCurrent validation"),
        before,
        "validation must not consume an attempt or mutate durable state"
    );

    assert_eq!(
        state.next_retry_request_after_directory_current(
            STARTED_AT_MS + 1_000,
            RequestRouteId::from_bytes([0x70; 16]),
            &status,
        ),
        Err(KeySyncError::ResponseConflict)
    );
    assert_eq!(state.attempt(), 1);
}

#[test]
fn resolved_state_can_only_be_superseded_by_a_new_authenticated_revision_cycle() {
    let resolved = resolved_catalog_state();
    assert_eq!(resolved.status(), KeySyncCoordinationStatus::Resolved);
    let prior_ack = resolved
        .latest_completed_ack_basis()
        .expect("resolved cycle has a durable ACK basis");
    let before = resolved
        .canonical_bytes()
        .expect("resolved state before supersession validation");
    let next_observation = SignedHigherRevisionObservationV1::new(
        resolved.observation().machine_route(),
        resolved.observation().device_route(),
        resolved.observation().grant_serial(),
        resolved.observation().root_trust_epoch(),
        KeyDirectoryRevision::new(22),
        KeyDirectoryRevision::new(23),
        KeyId {
            purpose: KeyPurpose::Catalog,
            epoch: 9,
        },
        None,
        StreamRouteId::from_bytes([0x83; 16]),
        StreamGenerationId::from_bytes([0x84; 16]),
        30,
        32,
        [0x91; 32],
        [0x92; 32],
    )
    .expect("new signed higher-revision observation");
    let next_request = resolved
        .next_cycle_request(&next_observation, STARTED_AT_MS + 40_000)
        .expect("expired resolved window does not reset the new cycle budget");
    assert_eq!(next_request.known_key_directory_revision.value(), 22);
    assert_eq!(next_request.requested_key_directory_revision.value(), 23);
    assert_eq!(next_request.attempt, 1);
    assert_eq!(
        resolved
            .canonical_bytes()
            .expect("resolved state after read-only supersession validation"),
        before
    );

    let next = resolved
        .start_next_cycle(
            next_observation.clone(),
            STARTED_AT_MS + 40_000,
            frozen_request(next_request, 0x93),
        )
        .expect("start a fresh bounded cycle after authenticated supersession");
    assert_eq!(next.status(), KeySyncCoordinationStatus::Active);
    assert_eq!(next.attempt(), 1);
    assert_eq!(next.started_at_ms(), STARTED_AT_MS + 40_000);
    assert_eq!(next.observation(), &next_observation);
    assert_eq!(
        next.latest_completed_ack_basis(),
        Some(prior_ack),
        "new active cycle retains the old ACK basis across the CAS/send crash gap"
    );
    let reopened = DurableKeySyncStateV1::from_canonical_bytes(
        &next
            .canonical_bytes()
            .expect("encode superseding cycle with retained ACK"),
    )
    .expect("restart preserves retained ACK basis");
    assert_eq!(reopened, next);
    assert_eq!(reopened.latest_completed_ack_basis(), Some(prior_ack));

    let advance_next_request = resolved
        .next_cycle_request(&next_observation, STARTED_AT_MS + 40_000)
        .expect("typed notice next-cycle request");
    let advance_next = resolved
        .start_next_cycle_after_directory_advance(
            next_observation.clone(),
            STARTED_AT_MS + 40_000,
            frozen_request(advance_next_request, 0x94),
        )
        .expect("typed DirectoryRevisionAdvance starts without predecessor ACK retention");
    assert_eq!(advance_next.status(), KeySyncCoordinationStatus::Active);
    assert_eq!(advance_next.attempt(), 1);
    assert_eq!(advance_next.latest_completed_ack_basis(), None);
    let reopened_advance = DurableKeySyncStateV1::from_canonical_bytes(
        &advance_next
            .canonical_bytes()
            .expect("encode typed-notice superseding cycle"),
    )
    .expect("restart preserves absence of predecessor ACK basis");
    assert_eq!(reopened_advance, advance_next);
    assert_eq!(reopened_advance.latest_completed_ack_basis(), None);

    let wrong_known = SignedHigherRevisionObservationV1::new(
        resolved.observation().machine_route(),
        resolved.observation().device_route(),
        resolved.observation().grant_serial(),
        resolved.observation().root_trust_epoch(),
        KeyDirectoryRevision::new(21),
        KeyDirectoryRevision::new(23),
        KeyId {
            purpose: KeyPurpose::Catalog,
            epoch: 9,
        },
        None,
        StreamRouteId::from_bytes([0x83; 16]),
        StreamGenerationId::from_bytes([0x84; 16]),
        30,
        32,
        [0x93; 32],
        [0x94; 32],
    )
    .expect("structurally valid stale-known observation");
    assert_eq!(
        resolved.next_cycle_request(&wrong_known, STARTED_AT_MS + 40_000),
        Err(KeySyncError::ObservationConflict)
    );
    assert_eq!(
        resolved.next_cycle_request(&next_observation, STARTED_AT_MS + 1_999),
        Err(KeySyncError::ClockRollback)
    );
}

#[test]
fn retained_ack_extension_is_canonical_and_rejects_malformed_truncated_or_trailing_bytes() {
    let resolved = resolved_catalog_state();
    let next_observation = SignedHigherRevisionObservationV1::new(
        resolved.observation().machine_route(),
        resolved.observation().device_route(),
        resolved.observation().grant_serial(),
        resolved.observation().root_trust_epoch(),
        KeyDirectoryRevision::new(22),
        KeyDirectoryRevision::new(23),
        KeyId {
            purpose: KeyPurpose::Catalog,
            epoch: 9,
        },
        None,
        StreamRouteId::from_bytes([0x83; 16]),
        StreamGenerationId::from_bytes([0x84; 16]),
        30,
        32,
        [0x91; 32],
        [0x92; 32],
    )
    .expect("new signed higher-revision observation");
    let next_request = resolved
        .next_cycle_request(&next_observation, STARTED_AT_MS + 40_000)
        .expect("next-cycle request");
    let next = resolved
        .start_next_cycle(
            next_observation,
            STARTED_AT_MS + 40_000,
            frozen_request(next_request, 0x93),
        )
        .expect("active next cycle with retained ACK basis");
    let canonical = next
        .canonical_bytes()
        .expect("canonical retained ACK extension");
    let extension_offset = canonical
        .windows(4)
        .position(|window| window == b"AKA1")
        .expect("AKA1 extension magic");
    assert_eq!(
        canonical
            .windows(4)
            .filter(|window| *window == b"AKA1")
            .count(),
        1
    );
    let reopened = DurableKeySyncStateV1::from_canonical_bytes(&canonical)
        .expect("canonical retained extension roundtrip");
    assert_eq!(reopened, next);
    assert_eq!(
        reopened
            .canonical_bytes()
            .expect("retained extension canonical re-encode"),
        canonical
    );

    let set_body_len = |bytes: &mut Vec<u8>| {
        let body_len = u32::try_from(bytes.len() - 12).expect("bounded ADKS body");
        bytes[8..12].copy_from_slice(&body_len.to_be_bytes());
    };

    let mut malformed_magic = canonical.clone();
    malformed_magic[extension_offset] ^= 0x01;
    assert_eq!(
        DurableKeySyncStateV1::from_canonical_bytes(&malformed_magic),
        Err(KeySyncError::InvalidCanonical)
    );

    let mut truncated = canonical.clone();
    truncated.pop();
    set_body_len(&mut truncated);
    assert_eq!(
        DurableKeySyncStateV1::from_canonical_bytes(&truncated),
        Err(KeySyncError::InvalidCanonical)
    );

    let mut trailing = canonical;
    trailing.push(0x00);
    set_body_len(&mut trailing);
    assert_eq!(
        DurableKeySyncStateV1::from_canonical_bytes(&trailing),
        Err(KeySyncError::InvalidCanonical)
    );
}

#[test]
fn directory_current_spends_one_attempt_and_fourth_attempt_is_rejected() {
    let mut state = initial_state();
    let status = directory_current(state.observation());
    let second = frozen_attempt(state.observation(), 2, 0x72);
    state
        .retry_after_directory_current(
            STARTED_AT_MS + 1_000,
            RequestRouteId::from_bytes([0x71; 16]),
            &status,
            second,
        )
        .expect("second bounded attempt");
    assert_eq!(state.attempt(), 2);

    let third = frozen_attempt(state.observation(), 3, 0x73);
    state
        .retry_after_directory_current(
            STARTED_AT_MS + 2_000,
            RequestRouteId::from_bytes([0x72; 16]),
            &status,
            third,
        )
        .expect("third bounded attempt");
    assert_eq!(state.attempt(), 3);
    assert_eq!(state.attempt_count(), 3);

    let still_third = frozen_attempt(state.observation(), 3, 0x74);
    assert_eq!(
        state.retry_after_directory_current(
            STARTED_AT_MS + 3_000,
            RequestRouteId::from_bytes([0x73; 16]),
            &status,
            still_third,
        ),
        Err(KeySyncError::Exhausted)
    );
    assert_eq!(
        KeySyncError::Exhausted.public_code(),
        Some("remote.crypto.key_epoch_missing")
    );
    assert_eq!(KeySyncError::ClockRollback.public_code(), None);
    assert_eq!(state.attempt(), 3);
}

#[test]
fn restart_does_not_reset_deadline_or_attempt_budget() {
    let mut state = initial_state();
    let status = directory_current(state.observation());
    let second = frozen_attempt(state.observation(), 2, 0x72);
    state
        .retry_after_directory_current(
            STARTED_AT_MS + 10_000,
            RequestRouteId::from_bytes([0x71; 16]),
            &status,
            second,
        )
        .expect("second attempt before restart");
    let encoded = state.canonical_bytes().expect("persist second attempt");
    let mut reopened =
        DurableKeySyncStateV1::from_canonical_bytes(&encoded).expect("restart state readback");
    assert_eq!(reopened.attempt(), 2);
    assert_eq!(reopened.deadline_at_ms(), STARTED_AT_MS + 30_000);

    let third = frozen_attempt(reopened.observation(), 3, 0x73);
    assert_eq!(
        reopened.retry_after_directory_current(
            STARTED_AT_MS + KEY_SYNC_WINDOW_MS,
            RequestRouteId::from_bytes([0x72; 16]),
            &status,
            third,
        ),
        Err(KeySyncError::Exhausted)
    );
    assert_eq!(reopened.attempt(), 2);
}

#[test]
fn persisted_clock_rollback_is_fail_closed_without_mutating_state() {
    let mut state = initial_state();
    let same = state.observation().clone();
    state
        .observe_again(&same, STARTED_AT_MS + 8_000)
        .expect("advance durable clock watermark");
    let before = state.canonical_bytes().expect("state before rollback");
    assert_eq!(
        state.observe_again(&same, STARTED_AT_MS + 7_999),
        Err(KeySyncError::ClockRollback)
    );
    assert_eq!(
        state
            .canonical_bytes()
            .expect("state after rejected rollback"),
        before
    );
}

#[test]
fn directory_current_must_bind_current_request_and_new_request_route() {
    let mut state = initial_state();
    let status = directory_current(state.observation());
    let second = frozen_attempt(state.observation(), 2, 0x72);
    assert_eq!(
        state.retry_after_directory_current(
            STARTED_AT_MS + 1_000,
            RequestRouteId::from_bytes([0x70; 16]),
            &status,
            second,
        ),
        Err(KeySyncError::ResponseConflict)
    );

    let reused_route = frozen_attempt(state.observation(), 2, 0x71);
    assert_eq!(
        state.retry_after_directory_current(
            STARTED_AT_MS + 1_000,
            RequestRouteId::from_bytes([0x71; 16]),
            &status,
            reused_route,
        ),
        Err(KeySyncError::ResponseConflict)
    );
    assert_eq!(state.attempt(), 1);
}

#[test]
fn matching_update_set_yields_terminal_handoff_with_exact_request_evidence() {
    let state = initial_state();
    let retained_observation = state.observation().clone();
    let expected_send = active_send(&state).exact_send_bytes().to_vec();
    let expected_send_hash = active_send(&state).exact_send_sha256();
    let expected_request_hash = active_send(&state).request_sha256();
    let update_set = matching_update_set(state.observation());
    let expected_update_hash = update_set.canonical_sha256().expect("update set hash");
    let handoff = state
        .into_update_set_handoff(
            STARTED_AT_MS + 1_000,
            RequestRouteId::from_bytes([0x71; 16]),
            update_set,
        )
        .expect("terminal UpdateSet handoff");

    assert_eq!(
        handoff.request_route(),
        RequestRouteId::from_bytes([0x71; 16])
    );
    assert_eq!(
        handoff.requested_key_directory_revision(),
        KeyDirectoryRevision::new(12)
    );
    assert_eq!(handoff.request_sha256(), expected_request_hash);
    assert_eq!(
        sha256(
            &handoff
                .request()
                .canonical_bytes()
                .expect("terminal request canonical bytes")
        ),
        expected_request_hash
    );
    assert_eq!(handoff.exact_send_sha256(), expected_send_hash);
    assert_eq!(handoff.exact_send_bytes(), expected_send);
    assert_eq!(handoff.update_set_sha256(), expected_update_hash);
    assert_eq!(handoff.retained_observation(), &retained_observation);
    assert_eq!(
        handoff
            .update_set()
            .canonical_sha256()
            .expect("handoff update hash"),
        expected_update_hash
    );
}

#[test]
fn invalid_update_set_non_send_and_oversize_send_fail_closed() {
    let state = initial_state();
    let mut wrong_update = matching_update_set(state.observation());
    wrong_update.key_directory_revision = KeyDirectoryRevision::new(13);
    wrong_update.updates[0].key_directory_revision = KeyDirectoryRevision::new(13);
    assert_eq!(
        state.clone().into_update_set_handoff(
            STARTED_AT_MS + 1_000,
            RequestRouteId::from_bytes([0x71; 16]),
            wrong_update,
        ),
        Err(KeySyncError::ResponseConflict)
    );

    let request = state
        .observation()
        .request_for_attempt(1)
        .expect("valid first request");
    let non_send = OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::Ping(agentdeck_protocol::relay_v2::frame::Ping { nonce: 1 }),
    };
    assert_eq!(
        FrozenKeySyncSendV1::new(request.clone(), encode(&non_send)),
        Err(KeySyncError::InvalidCanonical)
    );
    let wrong_revision = OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::Send(Send {
            device_route: request.device_route,
            request_route: RequestRouteId::from_bytes([0x75; 16]),
            sealed_blob: SealedBlob(
                signed_command_blob(request.known_key_directory_revision, 0x75).to_wire_bytes(),
            ),
        }),
    };
    assert_eq!(
        FrozenKeySyncSendV1::new(request.clone(), encode(&wrong_revision)),
        Err(KeySyncError::InvalidCanonical),
        "probe header must advertise exact requested revision while using the old command key"
    );
    assert_eq!(
        FrozenKeySyncSendV1::new(request, vec![0; KEY_SYNC_MAX_SEND_BYTES + 1]),
        Err(KeySyncError::TooLarge)
    );
}
