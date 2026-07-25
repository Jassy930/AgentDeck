use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};

use agentdeck_crypto::{
    DeviceKeyRecoveryOpenAuthority, HpkePrivateKey, SigningKey, open_device_key_recovery_reply,
};
use agentdeck_protocol::e2ee::{
    DeviceKeyRecoveryReplyV1, DirectoryCurrentV1, E2EE_FORMAT_VERSION, KeyControlRequestV1, KeyId,
    KeyPurpose, KeySyncRequestV1, KeyUpdateAckV1, KeyUpdateSetV1, KeyUpdateV1,
    MachineDataSignerBindingV1, OuterContextV1, SealedPayloadKind, SignedSealedBlobV1,
    StreamAppliedAckV1, UnsignedSealedBlobV1,
};
use agentdeck_protocol::relay_v2::auth::Ed25519Signature;
use agentdeck_protocol::relay_v2::frame::{AcceptedRef, RouteAccepted};
use agentdeck_protocol::relay_v2::{
    DeviceRouteId, GrantSerial, KeyDirectoryRevision, MachineRouteId, OpaqueRouteFrame,
    RELAY_PROTOCOL_VERSION, RelayFrameBody, RequestRouteId, StreamCursor, StreamGenerationId,
    StreamRouteId, TrustEpoch,
};
use agentdeck_protocol::runtime::identity::{ConversationId, MessageId};
use agentdeck_protocol::runtime::sync::RuntimeInnerCursor;
use agentdeck_protocol::runtime::{
    RUNTIME_PROTOCOL_VERSION, RuntimeEnvelope, RuntimeMessage, RuntimeRequest,
    RuntimeTransferCarrierV1,
};
use async_trait::async_trait;
use tokio::sync::Mutex;

use super::bootstrap::machine_pairing_anchor_for_test;
use super::dispatch::test_support::{
    ActiveRemoteDispatchFixture, SignedRuntimeSendFixture, active_remote_dispatch_for_test,
    active_remote_dispatch_with_pending_transition_for_test,
};
use super::dispatch::{RemoteDispatchError, RemoteIngressRoute};
use super::key_control::{
    AuthenticatedKeyControlIngress, AuthenticatedKeyControlIngressHandler,
    BusinessIngressAdmission, KeyControlIngressError, KeyControlIngressOutcome,
    StoreBackedKeyControlIngressHandler,
};
use super::link::{
    DirectedReplyRoute, DirectedReplySeal, DirectedReplySealer, PreCoreIngressOutcome,
    RemoteLinkError, RemoteLinkIngressMode, RemoteLinkOwner, RemoteReplyPump,
    RemoteStreamPublisher, route_ingress_before_core, route_ingress_before_core_with_mode,
};
use super::replay::{ReplayDecision, ReplayError};
use super::transport::tests::machine_data_authority_for_transition_test;
use super::transport::{BusinessTransportEvent, active_pairing_transport_for_test};
use crate::remote::counter::CounterScope;
use crate::remote::directed_reply::DeviceReplyTxSealer;
use crate::runtime::model::MachineEnrollmentState;
use crate::runtime::store::key_transition::{
    FrozenKeyUpdate, KeyTransitionOperation, KeyTransitionRecipient, KeyTransitionStreamCut,
    KeyTransitionStreamScope, KeyUpdateLifecycle, TransitionSnapshotRequest,
};
use crate::runtime::store::publication::{
    FreezeSignedPublicationRequest, FrozenPublication, PublicationPayloadKind, PublicationScope,
};
use crate::runtime::store::remote_counter::{
    ActiveSenderCounterBinding, CounterRecoveryDisposition, CounterRecoveryStageRequest,
    CounterRecoveryStageTarget, RemoteCounterRecordKind, RemoteCounterReservation,
    RemoteCounterRetirementRequest,
};
use crate::runtime::store::{
    CurrentRemoteAuthorizationProof, RemoteReplyAuthorization, RuntimeId, RuntimeIdKind,
    matching_bootstrap_update_for_test,
};
use crate::security::MemoryKeyStore;

const MACHINE: MachineRouteId = MachineRouteId::from_bytes([0x32; 16]);
const DEVICE: DeviceRouteId = DeviceRouteId::from_bytes([0xd1; 16]);

#[derive(Default)]
struct RecordingHandler {
    transition_fenced: AtomicBool,
    controls: Mutex<Vec<KeyControlRequestV1>>,
}

#[async_trait]
impl AuthenticatedKeyControlIngressHandler for RecordingHandler {
    async fn authorize_business_ingress(
        &self,
        _authorization: &CurrentRemoteAuthorizationProof,
        _envelope: &RuntimeEnvelope,
    ) -> Result<BusinessIngressAdmission, KeyControlIngressError> {
        if self.transition_fenced.load(Ordering::SeqCst) {
            Err(KeyControlIngressError::TransitionFenced)
        } else {
            Ok(BusinessIngressAdmission::BusinessReady)
        }
    }

    async fn consume(
        &self,
        ingress: AuthenticatedKeyControlIngress,
    ) -> Result<KeyControlIngressOutcome, KeyControlIngressError> {
        self.controls.lock().await.push(ingress.control().clone());
        Ok(KeyControlIngressOutcome::Consumed)
    }
}

#[derive(Clone)]
struct KeyUpdateSealCall {
    route: DirectedReplyRoute,
    update_set: KeyUpdateSetV1,
}

#[derive(Default)]
struct RecordingKeyUpdateSealer {
    calls: StdMutex<Vec<KeyUpdateSealCall>>,
    directory_current_calls: StdMutex<Vec<(DirectedReplyRoute, DirectoryCurrentV1)>>,
}

struct ReadyNoopPublisher;

#[async_trait]
impl RemoteStreamPublisher for ReadyNoopPublisher {
    fn admission_ready(&self) -> bool {
        true
    }

    async fn prepare_subscription(
        &self,
        _target: crate::runtime::events::RuntimeStreamTarget,
    ) -> Result<(), RemoteLinkError> {
        Ok(())
    }

    async fn publish_exact(&self, _runtime_bytes: Arc<[u8]>) -> Result<(), RemoteLinkError> {
        Err(RemoteLinkError::StreamPublishFailed)
    }

    async fn publish_transfer_exact(
        &self,
        _carrier: RuntimeTransferCarrierV1,
    ) -> Result<(), RemoteLinkError> {
        Err(RemoteLinkError::StreamPublishFailed)
    }
}

#[async_trait]
impl DirectedReplySealer for RecordingKeyUpdateSealer {
    fn admission_ready(&self) -> bool {
        true
    }

    async fn seal_exact(
        &self,
        _authorization: &RemoteReplyAuthorization,
        _route: DirectedReplyRoute,
        _runtime_bytes: Arc<[u8]>,
    ) -> Result<DirectedReplySeal, RemoteLinkError> {
        panic!("KeySync must use the typed key-update sealer path")
    }

    async fn seal_key_update_exact(
        &self,
        authorization: &RemoteReplyAuthorization,
        route: DirectedReplyRoute,
        update_set: KeyUpdateSetV1,
    ) -> Result<SignedSealedBlobV1, RemoteLinkError> {
        self.calls
            .lock()
            .expect("record KeySync sealer call")
            .push(KeyUpdateSealCall { route, update_set });
        Ok(UnsignedSealedBlobV1::new(
            KeyId {
                purpose: KeyPurpose::DeviceReplyTx,
                epoch: authorization.reply_key_epoch(),
            },
            authorization.reply_key_epoch(),
            authorization.key_directory_revision().value(),
            [0x91; 12],
            vec![0x92; 16],
        )
        .attach_signature(Ed25519Signature([0x94; 64])))
    }

    async fn seal_directory_current_exact(
        &self,
        authorization: &RemoteReplyAuthorization,
        route: DirectedReplyRoute,
        status: DirectoryCurrentV1,
    ) -> Result<SignedSealedBlobV1, RemoteLinkError> {
        self.directory_current_calls
            .lock()
            .expect("record DirectoryCurrent sealer call")
            .push((route, status));
        Ok(UnsignedSealedBlobV1::new(
            KeyId {
                purpose: KeyPurpose::DeviceReplyTx,
                epoch: authorization.reply_key_epoch(),
            },
            authorization.reply_key_epoch(),
            authorization.key_directory_revision().value(),
            [0x95; 12],
            vec![0x96; 16],
        )
        .attach_signature(Ed25519Signature([0x97; 64])))
    }
}

async fn active_authority(
    fixture: &ActiveRemoteDispatchFixture,
) -> (GrantSerial, TrustEpoch, KeyDirectoryRevision) {
    let active = fixture
        .store()
        .load_active_remote_ingress(MACHINE, DEVICE)
        .await
        .expect("load authenticated key-control authority");
    (
        active.grant_serial(),
        active.trust_epoch(),
        active.key_directory_revision(),
    )
}

async fn controls(fixture: &ActiveRemoteDispatchFixture) -> [KeyControlRequestV1; 3] {
    let (grant_serial, trust_epoch, revision) = active_authority(fixture).await;
    let requested = revision
        .value()
        .checked_add(1)
        .expect("fixture revision has room");
    let stream_route = StreamRouteId::from_bytes([0x31; 16]);
    let generation = StreamGenerationId::from_bytes([0x32; 16]);
    [
        KeyControlRequestV1::key_sync(KeySyncRequestV1 {
            format_version: E2EE_FORMAT_VERSION,
            runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
            relay_protocol_version: RELAY_PROTOCOL_VERSION,
            machine_route: MACHINE,
            device_route: DEVICE,
            grant_serial,
            root_trust_epoch: trust_epoch,
            known_key_directory_revision: revision,
            requested_key_directory_revision: KeyDirectoryRevision::new(requested),
            key_id: KeyId {
                purpose: KeyPurpose::ConversationDek,
                epoch: 2,
            },
            stream_route: Some(stream_route),
            attempt: 1,
        }),
        KeyControlRequestV1::key_update_ack(KeyUpdateAckV1 {
            format_version: E2EE_FORMAT_VERSION,
            runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
            relay_protocol_version: RELAY_PROTOCOL_VERSION,
            machine_route: MACHINE,
            device_route: DEVICE,
            grant_serial,
            root_trust_epoch: trust_epoch,
            key_directory_revision: revision,
            update_set_sha256: [0x41; 32],
        }),
        KeyControlRequestV1::stream_applied_ack(StreamAppliedAckV1 {
            format_version: E2EE_FORMAT_VERSION,
            runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
            relay_protocol_version: RELAY_PROTOCOL_VERSION,
            machine_route: MACHINE,
            device_route: DEVICE,
            grant_serial,
            root_trust_epoch: trust_epoch,
            stream_route,
            stream_generation: generation,
            applied_stream_seq: 9,
            inner_cursor: RuntimeInnerCursor::Conversation {
                conversation_id: ConversationId::new("key-control-ingress"),
                cursor: StreamCursor::At(8),
            },
            key_directory_revision: revision,
            key_epoch: 2,
            epoch_barrier_sha256: [0x42; 32],
        }),
    ]
}

async fn admit_route(
    fixture: &ActiveRemoteDispatchFixture,
    send: &SignedRuntimeSendFixture,
) -> Result<RemoteIngressRoute, RemoteLinkError> {
    let verified = fixture
        .dispatcher()
        .verify_send(send.send().clone())
        .await
        .expect("authenticated ingress verifies");
    let current = fixture
        .dispatcher()
        .recheck_current(verified)
        .await
        .expect("authenticated ingress remains current");
    Ok(fixture
        .dispatcher()
        .admit_replay(current)
        .await?
        .into_route()?
        .ok_or(RemoteDispatchError::ReplayRejected)?)
}

async fn admitted_route_error(
    fixture: &ActiveRemoteDispatchFixture,
    send: &SignedRuntimeSendFixture,
) -> RemoteDispatchError {
    let verified = fixture
        .dispatcher()
        .verify_send(send.send().clone())
        .await
        .expect("DeviceSign and replay tuple verify before inner decode");
    let current = fixture
        .dispatcher()
        .recheck_current(verified)
        .await
        .expect("authorization remains exact-current before replay admission");
    let admitted = fixture
        .dispatcher()
        .admit_replay(current)
        .await
        .expect("fresh tuple is durably admitted before inner decode");
    match admitted.into_route() {
        Err(error) => error,
        Ok(_) => panic!("malformed inner payload must not produce a pre-Core route"),
    }
}

async fn consume_store_control(
    fixture: &ActiveRemoteDispatchFixture,
    handler: &StoreBackedKeyControlIngressHandler,
    control: KeyControlRequestV1,
    request_route: RequestRouteId,
    counter: u64,
) -> Result<KeyControlIngressOutcome, RemoteLinkError> {
    let send = fixture.signed_key_control_send_for_test(request_route, control, counter, false);
    let route = admit_route(fixture, &send).await?;
    match route_ingress_before_core(route, handler, &Arc::downgrade(&fixture.core_arc())).await? {
        PreCoreIngressOutcome::KeyControl(outcome) => Ok(outcome),
        PreCoreIngressOutcome::Business(_) => panic!("key-control must not enter RuntimeCore"),
    }
}

#[tokio::test]
async fn verified_next_revision_reconnect_probe_routes_only_to_key_control_before_core() {
    let fixture = active_remote_dispatch_for_test(MACHINE, DEVICE).await;
    let (grant_serial, trust_epoch, current_revision) = active_authority(&fixture).await;
    let requested_revision = KeyDirectoryRevision::new(
        current_revision
            .value()
            .checked_add(1)
            .expect("probe revision has room"),
    );
    let control = KeyControlRequestV1::key_sync(KeySyncRequestV1 {
        format_version: E2EE_FORMAT_VERSION,
        runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
        relay_protocol_version: RELAY_PROTOCOL_VERSION,
        machine_route: MACHINE,
        device_route: DEVICE,
        grant_serial,
        root_trust_epoch: trust_epoch,
        known_key_directory_revision: current_revision,
        requested_key_directory_revision: requested_revision,
        key_id: KeyId {
            purpose: KeyPurpose::Catalog,
            epoch: 1,
        },
        stream_route: None,
        attempt: 1,
    });
    let send = fixture.signed_key_control_probe_with_revision_for_test(
        RequestRouteId::from_bytes([0x4f; 16]),
        control,
        9,
        requested_revision.value(),
    );
    let verified = fixture
        .dispatcher()
        .verify_send(send.send().clone())
        .await
        .expect("old command secret authenticates the next-revision recovery probe");
    let current = fixture
        .dispatcher()
        .recheck_current(verified)
        .await
        .expect("probe authority remains current");
    let admitted = fixture
        .dispatcher()
        .admit_replay(current)
        .await
        .expect("probe tuple is durably admitted");
    assert_eq!(
        admitted.decision(),
        ReplayDecision::KeySyncRequired {
            local_revision: current_revision,
            observed_revision: requested_revision,
        }
    );
    assert!(
        matches!(
            admitted.into_route(),
            Ok(Some(RemoteIngressRoute::KeyControl(_)))
        ),
        "a verified next-revision probe may reach only the pre-Core KeySync handler"
    );
    assert_eq!(fixture.core().remote_registration_calls_for_test(), 0);
    fixture.shutdown().await;
}

#[tokio::test]
async fn daemon_still_at_known_revision_returns_typed_directory_current_under_old_reply_key() {
    let fixture = active_remote_dispatch_for_test(MACHINE, DEVICE).await;
    let (grant_serial, trust_epoch, current_revision) = active_authority(&fixture).await;
    let requested_revision = current_revision.next().expect("fixture revision has room");
    let request_route = RequestRouteId::from_bytes([0x4e; 16]);
    let control = KeyControlRequestV1::key_sync(KeySyncRequestV1 {
        format_version: E2EE_FORMAT_VERSION,
        runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
        relay_protocol_version: RELAY_PROTOCOL_VERSION,
        machine_route: MACHINE,
        device_route: DEVICE,
        grant_serial,
        root_trust_epoch: trust_epoch,
        known_key_directory_revision: current_revision,
        requested_key_directory_revision: requested_revision,
        key_id: KeyId {
            purpose: KeyPurpose::Catalog,
            epoch: 1,
        },
        stream_route: None,
        attempt: 1,
    });
    let send = fixture.signed_key_control_probe_with_revision_for_test(
        request_route,
        control,
        8,
        requested_revision.value(),
    );
    let verified = fixture
        .dispatcher()
        .verify_send(send.send().clone())
        .await
        .expect("old command secret authenticates the next-revision probe");
    let current = fixture
        .dispatcher()
        .recheck_current(verified)
        .await
        .expect("known revision remains current");
    let route = fixture
        .dispatcher()
        .admit_replay(current)
        .await
        .expect("probe tuple is durably admitted")
        .into_route()
        .expect("next-revision KeySync payload decrypts")
        .expect("next-revision KeySync has a pre-Core route");
    let handler = StoreBackedKeyControlIngressHandler::new(fixture.store());
    let outcome = route_ingress_before_core(route, &handler, &Arc::downgrade(&fixture.core_arc()))
        .await
        .expect("daemon current status is consumed before Core");
    let PreCoreIngressOutcome::KeyControl(KeyControlIngressOutcome::DirectedReply(reply)) = outcome
    else {
        panic!("KeySync must return a typed directed status")
    };
    let status = reply
        .directory_current()
        .expect("daemon local r returns DirectoryCurrent(r)")
        .clone();
    assert_eq!(status.current_key_directory_revision, current_revision);
    assert_eq!(status.requested_key_directory_revision, requested_revision);
    assert_eq!(reply.route().request_route, request_route);
    assert_eq!(fixture.core().remote_registration_calls_for_test(), 0);

    let (mut transport, _pairing_lane, harness) = active_pairing_transport_for_test(MACHINE);
    let business = transport
        .take_business_lane()
        .expect("take DirectoryCurrent business lane");
    let sealer = Arc::new(RecordingKeyUpdateSealer::default());
    let mut pump = RemoteReplyPump::new(business, sealer.clone());
    pump.forward_key_control(*reply)
        .await
        .expect("DirectoryCurrent seals under the current DeviceReplyTx key");
    {
        let calls = sealer
            .directory_current_calls
            .lock()
            .expect("read DirectoryCurrent sealer calls");
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0.request_route, request_route);
        assert_eq!(calls[0].1, status);
    }
    assert_eq!(harness.sent_count(), 1);
    transport.shutdown().await;
    fixture.shutdown().await;
}

#[tokio::test]
async fn production_remote_link_actor_routes_key_sync_required_to_directory_current_before_core() {
    let fixture = active_remote_dispatch_for_test(MACHINE, DEVICE).await;
    let (grant_serial, trust_epoch, current_revision) = active_authority(&fixture).await;
    let requested_revision = current_revision.next().expect("fixture revision has room");
    let request_route = RequestRouteId::from_bytes([0x4d; 16]);
    let control = KeyControlRequestV1::key_sync(KeySyncRequestV1 {
        format_version: E2EE_FORMAT_VERSION,
        runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
        relay_protocol_version: RELAY_PROTOCOL_VERSION,
        machine_route: MACHINE,
        device_route: DEVICE,
        grant_serial,
        root_trust_epoch: trust_epoch,
        known_key_directory_revision: current_revision,
        requested_key_directory_revision: requested_revision,
        key_id: KeyId {
            purpose: KeyPurpose::Catalog,
            epoch: 1,
        },
        stream_route: None,
        attempt: 1,
    });
    let send = fixture.signed_key_control_probe_with_revision_for_test(
        request_route,
        control.clone(),
        7,
        requested_revision.value(),
    );
    let (mut transport, _pairing_lane, harness) = active_pairing_transport_for_test(MACHINE);
    let business = transport
        .take_business_lane()
        .expect("take production KeySync actor lane");
    let sealer = Arc::new(RecordingKeyUpdateSealer::default());
    let handler = Arc::new(StoreBackedKeyControlIngressHandler::new(fixture.store()));
    let mut owner = RemoteLinkOwner::start_with_key_control_handler(
        MACHINE,
        fixture.store(),
        business,
        Arc::downgrade(&fixture.core_arc()),
        sealer.clone(),
        Arc::new(ReadyNoopPublisher),
        handler,
    )
    .expect("start production-shaped RemoteLink actor");
    harness
        .push_frame(OpaqueRouteFrame {
            version: RELAY_PROTOCOL_VERSION,
            body: RelayFrameBody::Send(send.send().clone()),
        })
        .await;
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while harness.sent_count() != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("production actor must not pre-reject KeySyncRequired");
    {
        let calls = sealer
            .directory_current_calls
            .lock()
            .expect("read actor DirectoryCurrent call");
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0.request_route, request_route);
        assert_eq!(calls[0].1.current_key_directory_revision, current_revision);
        assert_eq!(
            calls[0].1.requested_key_directory_revision,
            requested_revision
        );
    }
    assert_eq!(fixture.core().remote_registration_calls_for_test(), 0);

    let higher_revision_business = fixture.signed_runtime_send_with_revision_for_test(
        RequestRouteId::from_bytes([0x4c; 16]),
        MessageId::new("higher-revision-business-stays-before-core"),
        RuntimeRequest::DescribeAgents,
        8,
        requested_revision.value(),
    );
    harness
        .push_frame(OpaqueRouteFrame {
            version: RELAY_PROTOCOL_VERSION,
            body: RelayFrameBody::Send(higher_revision_business.send().clone()),
        })
        .await;
    let follow_up_route = RequestRouteId::from_bytes([0x4b; 16]);
    let follow_up = fixture.signed_key_control_probe_with_revision_for_test(
        follow_up_route,
        control,
        9,
        requested_revision.value(),
    );
    harness
        .push_frame(OpaqueRouteFrame {
            version: RELAY_PROTOCOL_VERSION,
            body: RelayFrameBody::Send(follow_up.send().clone()),
        })
        .await;
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while harness.sent_count() != 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("actor processes a later KeySync after rejecting higher-revision business");
    {
        let calls = sealer
            .directory_current_calls
            .lock()
            .expect("read post-rejection DirectoryCurrent calls");
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[1].0.request_route, follow_up_route);
    }
    assert_eq!(
        fixture.core().remote_registration_calls_for_test(),
        0,
        "higher-revision business must not enter RuntimeCore"
    );
    owner.shutdown().await.expect("shutdown KeySync actor");
    transport.shutdown().await;
    fixture.shutdown().await;
}

#[tokio::test]
async fn all_authenticated_key_control_variants_are_consumed_before_runtime_core() {
    let fixture = active_remote_dispatch_for_test(MACHINE, DEVICE).await;
    let handler = Arc::new(RecordingHandler::default());
    for (offset, control) in controls(&fixture).await.into_iter().enumerate() {
        let send = fixture.signed_key_control_send_for_test(
            RequestRouteId::from_bytes([0x50 + offset as u8; 16]),
            control,
            10 + offset as u64,
            false,
        );
        let route = admit_route(&fixture, &send).await.unwrap();
        assert!(matches!(
            route_ingress_before_core(
                route,
                handler.as_ref(),
                &Arc::downgrade(&fixture.core_arc()),
            )
            .await
            .expect("key-control is consumed"),
            PreCoreIngressOutcome::KeyControl(KeyControlIngressOutcome::Consumed)
        ));
    }
    assert_eq!(handler.controls.lock().await.len(), 3);
    assert_eq!(fixture.core().remote_registration_calls_for_test(), 0);
    fixture.shutdown().await;
}

#[tokio::test]
async fn signature_aad_aead_and_nonce_reuse_fail_before_control_consumer() {
    let fixture = active_remote_dispatch_for_test(MACHINE, DEVICE).await;
    let handler = RecordingHandler::default();
    let control = controls(&fixture).await[0].clone();
    let valid = fixture.signed_key_control_send_for_test(
        RequestRouteId::from_bytes([0x61; 16]),
        control.clone(),
        20,
        false,
    );

    let mut bad_signature = valid.send().clone();
    let last = bad_signature.sealed_blob.0.len() - 1;
    bad_signature.sealed_blob.0[last] ^= 1;
    assert!(matches!(
        fixture.dispatcher().verify_send(bad_signature).await,
        Err(RemoteDispatchError::InvalidSignature)
    ));

    let mut bad_aad = valid.send().clone();
    bad_aad.request_route = RequestRouteId::from_bytes([0x62; 16]);
    assert!(matches!(
        fixture.dispatcher().verify_send(bad_aad).await,
        Err(RemoteDispatchError::InvalidSignature)
    ));

    let bad_ciphertext = fixture.signed_key_control_send_for_test(
        RequestRouteId::from_bytes([0x63; 16]),
        control.clone(),
        21,
        true,
    );
    assert!(matches!(
        admitted_route_error(&fixture, &bad_ciphertext).await,
        RemoteDispatchError::InvalidCiphertext
    ));

    let route = admit_route(&fixture, &valid).await.unwrap();
    route_ingress_before_core(route, &handler, &Arc::downgrade(&fixture.core_arc()))
        .await
        .expect("first tuple is consumed");
    let different = fixture.signed_key_control_send_for_test(
        RequestRouteId::from_bytes([0x64; 16]),
        controls(&fixture).await[1].clone(),
        20,
        false,
    );
    assert!(matches!(
        admit_route(&fixture, &different).await,
        Err(RemoteLinkError::Replay(ReplayError::NonceReuse))
    ));
    assert_eq!(handler.controls.lock().await.len(), 1);
    assert_eq!(fixture.core().remote_registration_calls_for_test(), 0);
    fixture.shutdown().await;
}

#[tokio::test]
async fn sealed_payload_kind_keeps_runtime_json_and_key_control_disjoint() {
    let fixture = active_remote_dispatch_for_test(MACHINE, DEVICE).await;
    let control = controls(&fixture).await[0].clone();
    let key_control_as_runtime = fixture.signed_payload_send_for_test(
        RequestRouteId::from_bytes([0x71; 16]),
        SealedPayloadKind::CommandRequest,
        control.canonical_bytes().unwrap(),
        30,
        false,
    );
    assert!(matches!(
        admitted_route_error(&fixture, &key_control_as_runtime).await,
        RemoteDispatchError::InvalidRuntimeRequest
    ));

    let runtime = RuntimeEnvelope {
        version: RUNTIME_PROTOCOL_VERSION,
        message_id: MessageId::new("runtime-is-not-key-control"),
        body: RuntimeMessage::Request(RuntimeRequest::DescribeAgents),
    };
    let runtime_as_key_control = fixture.signed_payload_send_for_test(
        RequestRouteId::from_bytes([0x72; 16]),
        SealedPayloadKind::KeyUpdate,
        runtime.to_json_bytes_checked().unwrap(),
        31,
        false,
    );
    assert!(matches!(
        admitted_route_error(&fixture, &runtime_as_key_control).await,
        RemoteDispatchError::InvalidKeyControl
    ));
    fixture.shutdown().await;
}

#[tokio::test]
async fn key_control_authority_must_match_the_exact_active_proof_before_control_consumer() {
    let fixture = active_remote_dispatch_for_test(MACHINE, DEVICE).await;
    let KeyControlRequestV1::KeySync { request } = controls(&fixture).await[0].clone() else {
        unreachable!("first fixture control is KeySync")
    };
    let mut mismatches = Vec::new();

    let mut wrong = request.clone();
    wrong.machine_route = MachineRouteId::from_bytes([0x33; 16]);
    mismatches.push(KeyControlRequestV1::key_sync(wrong));
    let mut wrong = request.clone();
    wrong.device_route = DeviceRouteId::from_bytes([0xd2; 16]);
    mismatches.push(KeyControlRequestV1::key_sync(wrong));
    let mut wrong = request.clone();
    wrong.grant_serial = GrantSerial::new(request.grant_serial.value() + 1);
    mismatches.push(KeyControlRequestV1::key_sync(wrong));
    let mut wrong = request;
    wrong.root_trust_epoch = TrustEpoch::new(wrong.root_trust_epoch.value() + 1);
    mismatches.push(KeyControlRequestV1::key_sync(wrong));

    for (offset, control) in mismatches.into_iter().enumerate() {
        let send = fixture.signed_key_control_send_for_test(
            RequestRouteId::from_bytes([0x74 + offset as u8; 16]),
            control,
            34 + offset as u64,
            false,
        );
        assert!(matches!(
            admitted_route_error(&fixture, &send).await,
            RemoteDispatchError::InvalidKeyControl
        ));
    }
    assert_eq!(fixture.core().remote_registration_calls_for_test(), 0);
    fixture.shutdown().await;
}

#[tokio::test]
async fn active_transition_fence_rejects_business_before_runtime_core() {
    let fixture = active_remote_dispatch_for_test(MACHINE, DEVICE).await;
    let handler = RecordingHandler::default();
    handler.transition_fenced.store(true, Ordering::SeqCst);
    let send = fixture.signed_runtime_send(
        RequestRouteId::from_bytes([0x81; 16]),
        MessageId::new("business-transition-fenced"),
        RuntimeRequest::DescribeAgents,
        40,
    );
    let route = admit_route(&fixture, &send).await.unwrap();
    assert!(matches!(
        route_ingress_before_core(route, &handler, &Arc::downgrade(&fixture.core_arc())).await,
        Err(super::link::RemoteLinkError::KeyControl(
            KeyControlIngressError::TransitionFenced
        ))
    ));
    assert_eq!(fixture.core().remote_registration_calls_for_test(), 0);
    assert!(handler.controls.lock().await.is_empty());
    fixture.shutdown().await;
}

#[tokio::test]
async fn control_plane_only_link_consumes_key_control_and_promotes_only_after_business_store_gate()
{
    let fixture = active_remote_dispatch_for_test(MACHINE, DEVICE).await;
    let handler = RecordingHandler::default();
    handler.transition_fenced.store(true, Ordering::SeqCst);
    let mut mode = RemoteLinkIngressMode::ControlPlaneOnly;

    let fenced = fixture.signed_runtime_send(
        RequestRouteId::from_bytes([0x83; 16]),
        MessageId::new("control-only-business-fenced"),
        RuntimeRequest::DescribeAgents,
        42,
    );
    let route = admit_route(&fixture, &fenced).await.unwrap();
    assert!(matches!(
        route_ingress_before_core_with_mode(
            route,
            &handler,
            &Arc::downgrade(&fixture.core_arc()),
            &mut mode,
        )
        .await,
        Err(RemoteLinkError::KeyControl(
            KeyControlIngressError::TransitionFenced
        ))
    ));
    assert_eq!(mode, RemoteLinkIngressMode::ControlPlaneOnly);
    assert_eq!(fixture.core().remote_registration_calls_for_test(), 0);

    let control = fixture.signed_key_control_send_for_test(
        RequestRouteId::from_bytes([0x84; 16]),
        controls(&fixture).await[0].clone(),
        43,
        false,
    );
    let route = admit_route(&fixture, &control).await.unwrap();
    assert!(matches!(
        route_ingress_before_core_with_mode(
            route,
            &handler,
            &Arc::downgrade(&fixture.core_arc()),
            &mut mode,
        )
        .await
        .expect("control-only link must keep consuming authenticated KeyControl"),
        PreCoreIngressOutcome::KeyControl(KeyControlIngressOutcome::Consumed)
    ));
    assert_eq!(mode, RemoteLinkIngressMode::ControlPlaneOnly);
    assert_eq!(handler.controls.lock().await.len(), 1);
    assert_eq!(fixture.core().remote_registration_calls_for_test(), 0);

    handler.transition_fenced.store(false, Ordering::SeqCst);
    let released = fixture.signed_runtime_send(
        RequestRouteId::from_bytes([0x85; 16]),
        MessageId::new("control-only-business-released"),
        RuntimeRequest::DescribeAgents,
        44,
    );
    let route = admit_route(&fixture, &released).await.unwrap();
    assert!(matches!(
        route_ingress_before_core_with_mode(
            route,
            &handler,
            &Arc::downgrade(&fixture.core_arc()),
            &mut mode,
        )
        .await
        .expect("Store readback releases the next business frame"),
        PreCoreIngressOutcome::Business(_)
    ));
    assert_eq!(mode, RemoteLinkIngressMode::BusinessReady);
    assert_eq!(fixture.core().remote_registration_calls_for_test(), 1);
    fixture.shutdown().await;
}

#[tokio::test]
async fn durable_counter_retirement_fences_all_business_before_runtime_core() {
    let fixture = active_remote_dispatch_for_test(MACHINE, DEVICE).await;
    let store = fixture.store();
    let key_id = KeyId {
        purpose: KeyPurpose::Catalog,
        epoch: 91,
    };
    let scope = CounterScope::publication(
        store.machine_trust_domain().expect("machine trust domain"),
        key_id,
        [0x91; 16],
    )
    .expect("counter retirement scope");
    let genesis = store
        .load_remote_counter_record(scope.token(), key_id)
        .await
        .expect("load counter genesis");
    store
        .retire_remote_counter(RemoteCounterRetirementRequest {
            scope_token: scope.token(),
            key_id,
            expected_reserved_end: genesis.reserved_end,
            expected_db_anchor: genesis.db_anchor,
            retired_through: 1_024,
        })
        .await
        .expect("durably retire counter scope");

    let handler = StoreBackedKeyControlIngressHandler::new(store);
    let send = fixture.signed_runtime_send(
        RequestRouteId::from_bytes([0x82; 16]),
        MessageId::new("business-counter-retired"),
        RuntimeRequest::DescribeAgents,
        41,
    );
    let route = admit_route(&fixture, &send).await.unwrap();
    assert!(matches!(
        route_ingress_before_core(route, &handler, &Arc::downgrade(&fixture.core_arc())).await,
        Err(RemoteLinkError::KeyControl(
            KeyControlIngressError::CounterRetired
        ))
    ));
    assert_eq!(fixture.core().remote_registration_calls_for_test(), 0);
    fixture.shutdown().await;
}

fn key_update_set(revision: KeyDirectoryRevision) -> KeyUpdateSetV1 {
    KeyUpdateSetV1 {
        key_directory_revision: revision,
        device_route: DEVICE,
        updates: vec![KeyUpdateV1 {
            key_directory_revision: revision,
            key_id: KeyId {
                purpose: KeyPurpose::Catalog,
                epoch: 2,
            },
            device_route: DEVICE,
            stream_route: None,
            enc: vec![0x51; 32],
            wrapped_key: vec![0x52; 48],
            signature: Ed25519Signature([0x53; 64]),
        }],
    }
}

async fn stage_directed_reply_counter_recovery(
    fixture: &ActiveRemoteDispatchFixture,
) -> (
    KeyDirectoryRevision,
    KeyDirectoryRevision,
    [u8; 32],
    KeyId,
    [u8; 32],
    KeyId,
    KeyUpdateSetV1,
) {
    let store = fixture.store();
    let authorization = store
        .load_active_sender_counter_bindings()
        .await
        .expect("load directed sender inventory")
        .into_iter()
        .find_map(|binding| match binding {
            ActiveSenderCounterBinding::DirectedReply { authorization } => Some(authorization),
            ActiveSenderCounterBinding::SharedPublication { .. } => None,
        })
        .expect("active directed reply authorization");
    let known_revision = authorization.key_directory_revision();
    let retired_key_id = KeyId {
        purpose: KeyPurpose::DeviceReplyTx,
        epoch: authorization.reply_key_epoch(),
    };
    let retired_scope = CounterScope::directed_reply_for_trust_epoch(
        authorization.machine_trust_domain(),
        authorization.machine_route(),
        authorization.trust_epoch(),
        authorization.device_route(),
        authorization.grant_serial(),
        retired_key_id.epoch,
    )
    .expect("derive retired directed scope");
    let retired_genesis = store
        .load_remote_counter_record(retired_scope.token(), retired_key_id)
        .await
        .expect("load retired directed genesis");
    store
        .retire_remote_counter(RemoteCounterRetirementRequest {
            scope_token: retired_scope.token(),
            key_id: retired_key_id,
            expected_reserved_end: retired_genesis.reserved_end,
            expected_db_anchor: retired_genesis.db_anchor,
            retired_through: 1_024,
        })
        .await
        .expect("retire old DeviceReplyTx counter");
    let replacement_key_id = KeyId {
        purpose: KeyPurpose::DeviceReplyTx,
        epoch: retired_key_id.epoch + 1,
    };
    let replacement_scope = CounterScope::directed_reply_for_trust_epoch(
        authorization.machine_trust_domain(),
        authorization.machine_route(),
        authorization.trust_epoch(),
        authorization.device_route(),
        authorization.grant_serial(),
        replacement_key_id.epoch,
    )
    .expect("derive replacement directed scope");
    let operation_id = [0x8d; 16];
    let staged = store
        .stage_remote_counter_recovery(CounterRecoveryStageRequest {
            operation_id,
            retired_scope_token: retired_scope.token(),
            retired_key_id,
            replacement_scope_token: replacement_scope.token(),
            target: CounterRecoveryStageTarget::DirectedReply {
                authorization: authorization.clone(),
            },
        })
        .await
        .expect("stage directed reply CounterRecovery");
    assert_eq!(staged.disposition, CounterRecoveryDisposition::Staged);
    let requested_revision = known_revision.next().expect("revision has successor");
    assert_eq!(
        staged
            .binding
            .expect("counter recovery binding")
            .to_revision,
        requested_revision.value()
    );
    store
        .finalize_key_directory_rotation(operation_id)
        .await
        .expect("finalize directed CounterRecovery key-directory axes");
    let mut update_set = key_update_set(requested_revision);
    update_set.updates.push(KeyUpdateV1 {
        key_directory_revision: requested_revision,
        key_id: replacement_key_id,
        device_route: DEVICE,
        stream_route: None,
        enc: vec![0x61; 32],
        wrapped_key: vec![0x62; 48],
        signature: Ed25519Signature([0x63; 64]),
    });
    update_set
        .validate()
        .expect("recovery set carries sorted replacement DeviceReplyTx entry");
    store
        .freeze_key_updates(
            operation_id,
            vec![FrozenKeyUpdate {
                recipient: KeyTransitionRecipient {
                    device_route: *DEVICE.as_bytes(),
                    grant_serial: authorization.grant_serial().value(),
                },
                key_revision: requested_revision.value(),
                canonical_update_set: update_set
                    .canonical_bytes()
                    .expect("canonical counter-recovery update set"),
            }],
        )
        .await
        .expect("freeze directed recovery update");
    store
        .freeze_key_barriers(operation_id, Vec::new())
        .await
        .expect("freeze zero-cut directed recovery barriers");
    store
        .mark_key_barriers_committed(operation_id)
        .await
        .expect("commit zero-cut directed recovery barriers");
    let recovered = store
        .mark_remote_counter_recovery_business_ready(operation_id)
        .await
        .expect("release directed counter fence after BusinessReady");
    assert_eq!(recovered.kind, RemoteCounterRecordKind::Recovered);
    assert!(
        !store
            .has_retired_remote_counter()
            .await
            .expect("read recovered counter fence")
    );
    (
        known_revision,
        requested_revision,
        retired_scope.token(),
        retired_key_id,
        replacement_scope.token(),
        replacement_key_id,
        update_set,
    )
}

#[tokio::test]
async fn directed_counter_recovery_uses_device_hpke_machine_data_sign_and_zero_reply_counter() {
    let fixture = active_remote_dispatch_for_test(MACHINE, DEVICE).await;
    let (
        known_revision,
        requested_revision,
        retired_scope,
        retired_key_id,
        replacement_scope,
        replacement_key_id,
        expected_update,
    ) = stage_directed_reply_counter_recovery(&fixture).await;
    let active = fixture
        .store()
        .load_active_remote_ingress(MACHINE, DEVICE)
        .await
        .expect("load recovered current authorization");
    let request_route = RequestRouteId::from_bytes([0x8e; 16]);
    let control = KeyControlRequestV1::key_sync(KeySyncRequestV1 {
        format_version: E2EE_FORMAT_VERSION,
        runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
        relay_protocol_version: RELAY_PROTOCOL_VERSION,
        machine_route: MACHINE,
        device_route: DEVICE,
        grant_serial: active.grant_serial(),
        root_trust_epoch: active.trust_epoch(),
        known_key_directory_revision: known_revision,
        requested_key_directory_revision: requested_revision,
        key_id: KeyId {
            purpose: KeyPurpose::DeviceReplyTx,
            epoch: retired_key_id.epoch,
        },
        stream_route: None,
        attempt: 1,
    });
    let send = fixture.signed_key_control_probe_with_revision_for_test(
        request_route,
        control,
        81,
        requested_revision.value(),
    );
    let verified = fixture
        .dispatcher()
        .verify_send(send.send().clone())
        .await
        .expect("old command key authenticates CounterRecovery probe");
    let current = fixture
        .dispatcher()
        .recheck_current(verified)
        .await
        .expect("CounterRecovery authorization remains exact-current");
    let route = fixture
        .dispatcher()
        .admit_replay(current)
        .await
        .expect("durably admit CounterRecovery probe")
        .into_route()
        .expect("CounterRecovery payload decrypts")
        .expect("CounterRecovery probe reaches only key-control");
    let handler = StoreBackedKeyControlIngressHandler::new(fixture.store());
    let outcome = route_ingress_before_core(route, &handler, &Arc::downgrade(&fixture.core_arc()))
        .await
        .expect("resolve frozen CounterRecovery update before Core");
    let PreCoreIngressOutcome::KeyControl(KeyControlIngressOutcome::DirectedReply(reply)) = outcome
    else {
        panic!("CounterRecovery must return one typed directed reply")
    };
    let (recovery_known, recovery_update) = reply
        .device_key_recovery()
        .expect("retired DeviceReplyTx target requires DeviceHPKE recovery");
    assert_eq!(recovery_known, known_revision);
    assert_eq!(recovery_update, &expected_update);
    assert_eq!(fixture.core().remote_registration_calls_for_test(), 0);

    let old_counter_before = fixture
        .store()
        .load_remote_counter_record(retired_scope, retired_key_id)
        .await
        .expect("load retired counter before recovery reply");
    let new_counter_before = fixture
        .store()
        .load_remote_counter_record(replacement_scope, replacement_key_id)
        .await
        .expect("load replacement counter before recovery reply");
    let Some(MachineEnrollmentState::Active(machine)) = fixture
        .store()
        .load_machine_enrollment_state()
        .await
        .expect("load recovery machine enrollment")
    else {
        panic!("recovery fixture machine must remain active")
    };
    let data_certificate = machine.data_cert.clone();
    let (authority, _authority_lease) = machine_data_authority_for_transition_test(
        machine_pairing_anchor_for_test(
            machine.connection.relay_server_id,
            MACHINE,
            &machine.binding,
            data_certificate.clone(),
        ),
        [0x43; 32],
    );
    let sealer = Arc::new(DeviceReplyTxSealer::new(
        fixture.store(),
        Arc::new(MemoryKeyStore::new()),
        authority,
    ));
    let (mut transport, _pairing_lane, harness) = active_pairing_transport_for_test(MACHINE);
    let business = transport
        .take_business_lane()
        .expect("take recovery business lane");
    let mut pump = RemoteReplyPump::new(business, sealer);
    pump.forward_key_control(*reply)
        .await
        .expect("send independent DeviceHPKE recovery envelope");

    let duplicate_verified = fixture
        .dispatcher()
        .verify_send(send.send().clone())
        .await
        .expect("exact duplicate recovery probe still verifies");
    let duplicate_current = fixture
        .dispatcher()
        .recheck_current(duplicate_verified)
        .await
        .expect("exact duplicate remains current");
    let duplicate_admitted = fixture
        .dispatcher()
        .admit_replay(duplicate_current)
        .await
        .expect("exact duplicate replay lookup succeeds");
    assert_eq!(
        duplicate_admitted.decision(),
        ReplayDecision::ExactDuplicate
    );
    let duplicate_route = duplicate_admitted
        .into_route()
        .expect("exact duplicate payload decrypts")
        .expect("exact duplicate keeps its pre-Core recovery route");
    let duplicate_outcome = route_ingress_before_core(
        duplicate_route,
        &handler,
        &Arc::downgrade(&fixture.core_arc()),
    )
    .await
    .expect("exact duplicate resolves the same frozen recovery set");
    let PreCoreIngressOutcome::KeyControl(KeyControlIngressOutcome::DirectedReply(duplicate_reply)) =
        duplicate_outcome
    else {
        panic!("exact duplicate must remain a typed recovery reply")
    };
    let (duplicate_known, duplicate_update) = duplicate_reply
        .device_key_recovery()
        .expect("exact duplicate remains on DeviceHPKE recovery carrier");
    assert_eq!(duplicate_known, known_revision);
    assert_eq!(duplicate_update, &expected_update);
    assert_eq!(duplicate_reply.route().request_route, request_route);
    pump.forward_key_control(*duplicate_reply)
        .await
        .expect("exact duplicate recovery reply is safely resealed");
    assert_eq!(harness.sent_count(), 2);

    assert_eq!(
        fixture
            .store()
            .load_remote_counter_record(retired_scope, retired_key_id)
            .await
            .expect("reload retired counter after recovery reply"),
        old_counter_before
    );
    assert_eq!(
        fixture
            .store()
            .load_remote_counter_record(replacement_scope, replacement_key_id)
            .await
            .expect("reload replacement counter after recovery reply"),
        new_counter_before,
        "DeviceHPKE recovery must not reserve a DeviceReplyTx counter"
    );

    let frames = harness.sent_frames();
    assert_eq!(frames.len(), 2);
    let replies = frames
        .iter()
        .map(|frame| {
            let RelayFrameBody::Reply(sent) = &frame.body else {
                panic!("recovery carrier must stay inside opaque Relay Reply")
            };
            assert_eq!(sent.device_route, DEVICE);
            assert_eq!(sent.request_route, request_route);
            DeviceKeyRecoveryReplyV1::from_canonical_bytes(&sent.sealed_blob.0)
                .expect("decode canonical DeviceHPKE recovery reply")
        })
        .collect::<Vec<_>>();
    let envelope = &replies[0];
    assert_eq!(envelope.info.known_key_directory_revision, known_revision);
    assert_eq!(
        envelope.info.target_key_directory_revision,
        requested_revision
    );
    assert_eq!(envelope.info.grant_serial, active.grant_serial());
    assert_eq!(envelope.info.root_trust_epoch, active.trust_epoch());
    let (device_private, _) = HpkePrivateKey::derive_keypair(&[0xa5; 32]);
    let machine_data_signing = SigningKey::from_seed(&[0x43; 32]);
    let machine_data_verifying = machine_data_signing.verifying_key();
    let signer = MachineDataSignerBindingV1::from_certificate(&data_certificate)
        .expect("fixture MachineData signer binding");
    let context = OuterContextV1::device_key_recovery(MACHINE, DEVICE, request_route);
    let opened = open_device_key_recovery_reply(
        DeviceKeyRecoveryOpenAuthority {
            device_hpke_private_key: &device_private,
            machine_data_verifying_key: &machine_data_verifying,
            signer: &signer,
        },
        &envelope.info,
        &context,
        envelope,
    )
    .expect("DeviceHPKE opens exact frozen update with MachineDataSign verified");
    assert_eq!(opened, expected_update);
    let replacement = opened
        .updates
        .iter()
        .find(|update| update.key_id.purpose == KeyPurpose::DeviceReplyTx)
        .expect("opened recovery set contains the deadlock-breaking reply key");
    assert_eq!(replacement.key_id, replacement_key_id);
    assert_eq!(replacement.key_directory_revision, requested_revision);
    assert_eq!(replacement.device_route, DEVICE);
    assert!(replacement.stream_route.is_none());
    let duplicate_opened = open_device_key_recovery_reply(
        DeviceKeyRecoveryOpenAuthority {
            device_hpke_private_key: &device_private,
            machine_data_verifying_key: &machine_data_verifying,
            signer: &signer,
        },
        &replies[1].info,
        &context,
        &replies[1],
    )
    .expect("exact duplicate recovery reply opens the same frozen update");
    assert_eq!(duplicate_opened, expected_update);
    transport.shutdown().await;
    fixture.shutdown().await;
}

async fn freeze_exact_key_sync_update(
    fixture: &ActiveRemoteDispatchFixture,
    grant_serial: GrantSerial,
    current_revision: KeyDirectoryRevision,
) -> ([u8; 16], KeyUpdateSetV1) {
    let recipient = KeyTransitionRecipient {
        device_route: *DEVICE.as_bytes(),
        grant_serial: grant_serial.value(),
    };
    let bootstrap = fixture
        .store()
        .load_active_key_transition()
        .await
        .expect("load production bootstrap KeySync transition")
        .expect("initial grant must stage a bootstrap KeySync transition");
    assert_eq!(bootstrap.transition.operation, KeyTransitionOperation::Add);
    assert_eq!(bootstrap.transition.from_revision, 0);
    assert_eq!(bootstrap.transition.to_revision, current_revision.value());
    assert_eq!(bootstrap.transition.recipients, vec![recipient]);
    let operation_id = bootstrap.transition.operation_id;
    fixture
        .store()
        .mark_key_transition_rotated(operation_id)
        .await
        .expect("rotate KeySync fixture transition");
    let update = matching_bootstrap_update_for_test(&fixture.store(), recipient).await;
    assert_eq!(update.key_revision, current_revision.value());
    let update_set = KeyUpdateSetV1::from_canonical_bytes(&update.canonical_update_set)
        .expect("decode exact matching bootstrap update set");
    fixture
        .store()
        .freeze_key_updates(operation_id, vec![update])
        .await
        .expect("freeze exact KeySync update set");
    (operation_id, update_set)
}

#[tokio::test]
async fn key_sync_preserves_exact_request_route_reads_frozen_set_and_sends_typed_reply_before_core()
{
    let fixture = active_remote_dispatch_with_pending_transition_for_test(MACHINE, DEVICE).await;
    let (grant_serial, trust_epoch, current_revision) = active_authority(&fixture).await;
    let (_operation_id, expected) =
        freeze_exact_key_sync_update(&fixture, grant_serial, current_revision).await;
    let exact_control = KeyControlRequestV1::key_sync(KeySyncRequestV1 {
        format_version: E2EE_FORMAT_VERSION,
        runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
        relay_protocol_version: RELAY_PROTOCOL_VERSION,
        machine_route: MACHINE,
        device_route: DEVICE,
        grant_serial,
        root_trust_epoch: trust_epoch,
        known_key_directory_revision: KeyDirectoryRevision::new(0),
        requested_key_directory_revision: current_revision,
        key_id: KeyId {
            purpose: KeyPurpose::Catalog,
            epoch: 1,
        },
        stream_route: None,
        attempt: 3,
    });
    let handler = StoreBackedKeyControlIngressHandler::new(fixture.store());

    let KeyControlRequestV1::KeySync { mut request } = exact_control.clone() else {
        unreachable!("exact control is KeySync")
    };
    request.known_key_directory_revision = current_revision;
    request.requested_key_directory_revision =
        KeyDirectoryRevision::new(current_revision.value() + 1);
    let current_route = RequestRouteId::from_bytes([0x93; 16]);
    let current_outcome = consume_store_control(
        &fixture,
        &handler,
        KeyControlRequestV1::key_sync(request),
        current_route,
        49,
    )
    .await
    .expect("current daemon revision returns a typed status");
    let KeyControlIngressOutcome::DirectedReply(current_reply) = current_outcome else {
        panic!("next-revision KeySync must return DirectoryCurrent")
    };
    let current_status = current_reply
        .directory_current()
        .expect("next-revision KeySync returns DirectoryCurrent");
    assert_eq!(current_reply.route().request_route, current_route);
    assert_eq!(
        current_status.current_key_directory_revision,
        current_revision
    );
    assert_eq!(
        current_status.requested_key_directory_revision,
        KeyDirectoryRevision::new(current_revision.value() + 1)
    );

    let request_route = RequestRouteId::from_bytes([0x94; 16]);
    let send = fixture.signed_key_control_send_for_test(request_route, exact_control, 50, false);
    let route = admit_route(&fixture, &send)
        .await
        .expect("admit authenticated KeySync route");
    let outcome = route_ingress_before_core(route, &handler, &Arc::downgrade(&fixture.core_arc()))
        .await
        .expect("read exact frozen KeySync reply before Core");
    let PreCoreIngressOutcome::KeyControl(KeyControlIngressOutcome::DirectedReply(reply)) = outcome
    else {
        panic!("KeySync must produce one typed directed reply")
    };
    assert_eq!(reply.route().machine_route, MACHINE);
    assert_eq!(reply.route().device_route, DEVICE);
    assert_eq!(reply.route().request_route, request_route);
    assert_eq!(reply.update_set(), Some(&expected));
    assert_eq!(fixture.core().remote_registration_calls_for_test(), 0);

    let (mut transport, _pairing_lane, harness) = active_pairing_transport_for_test(MACHINE);
    let business = transport
        .take_business_lane()
        .expect("take KeySync business lane");
    let sealer = Arc::new(RecordingKeyUpdateSealer::default());
    let mut pump = RemoteReplyPump::new(business, sealer.clone());
    pump.forward_key_control(*reply)
        .await
        .expect("seal and flush KeySync directed reply");
    assert_eq!(harness.sent_count(), 1);
    {
        let calls = sealer.calls.lock().expect("read KeySync sealer calls");
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].route.request_route, request_route);
        assert_eq!(calls[0].update_set, expected);
    }
    let sent = harness.sent_frames();
    let RelayFrameBody::Reply(sent_reply) = &sent[0].body else {
        panic!("KeySync must use the opaque Relay Reply family")
    };
    assert_eq!(sent_reply.device_route, DEVICE);
    assert_eq!(sent_reply.request_route, request_route);

    harness
        .push_frame(OpaqueRouteFrame {
            version: RELAY_PROTOCOL_VERSION,
            body: RelayFrameBody::RouteAccepted(RouteAccepted {
                accepted: AcceptedRef::Request { request_route },
            }),
        })
        .await;
    let event = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        pump.next_transport_event(),
    )
    .await
    .expect("observe transport-only RouteAccepted")
    .expect("healthy KeySync transport")
    .expect("concrete KeySync transport event");
    assert!(matches!(event, BusinessTransportEvent::RouteAccepted(_)));
    assert_eq!(
        harness.sent_count(),
        1,
        "Relay RouteAccepted must not synthesize a second reply or device ACK"
    );
    assert_eq!(fixture.core().remote_registration_calls_for_test(), 0);
    transport.shutdown().await;
    fixture.shutdown().await;
}

async fn exact_active_update(
    fixture: &ActiveRemoteDispatchFixture,
) -> crate::runtime::store::key_transition::KeyUpdateRecord {
    fixture
        .store()
        .load_active_key_transition()
        .await
        .expect("load active key transition")
        .expect("key transition remains active")
        .updates
        .into_iter()
        .next()
        .expect("active transition has one frozen update")
}

#[tokio::test]
async fn key_update_ack_is_store_resolved_canonical_and_exact_replay_preserves_first_record() {
    let fixture = active_remote_dispatch_with_pending_transition_for_test(MACHINE, DEVICE).await;
    let (grant_serial, trust_epoch, requested_revision) = active_authority(&fixture).await;
    let (operation_id, update_set) =
        freeze_exact_key_sync_update(&fixture, grant_serial, requested_revision).await;
    let ack = KeyUpdateAckV1 {
        format_version: E2EE_FORMAT_VERSION,
        runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
        relay_protocol_version: RELAY_PROTOCOL_VERSION,
        machine_route: MACHINE,
        device_route: DEVICE,
        grant_serial,
        root_trust_epoch: trust_epoch,
        key_directory_revision: requested_revision,
        update_set_sha256: update_set
            .canonical_sha256()
            .expect("hash exact frozen update set"),
    };
    let canonical_ack = ack.canonical_bytes().expect("canonical KeyUpdateAck");
    let handler = StoreBackedKeyControlIngressHandler::new(fixture.store());

    let (mut transport, _pairing_lane, harness) = active_pairing_transport_for_test(MACHINE);
    let business = transport
        .take_business_lane()
        .expect("take ACK transport lane");
    let mut pump = RemoteReplyPump::new(business, Arc::new(RecordingKeyUpdateSealer::default()));
    let before_route_accepted = exact_active_update(&fixture).await;
    assert_eq!(before_route_accepted.lifecycle, KeyUpdateLifecycle::Acked);
    assert!(before_route_accepted.canonical_ack.is_some());
    assert_ne!(
        before_route_accepted.canonical_ack.as_deref(),
        Some(canonical_ack.as_slice()),
        "bootstrap receipt starts as target-only ACK evidence, not a forged normal KeyUpdateAck"
    );
    let accepted_route = RequestRouteId::from_bytes([0xa0; 16]);
    harness
        .push_frame(OpaqueRouteFrame {
            version: RELAY_PROTOCOL_VERSION,
            body: RelayFrameBody::RouteAccepted(RouteAccepted {
                accepted: AcceptedRef::Request {
                    request_route: accepted_route,
                },
            }),
        })
        .await;
    assert!(matches!(
        pump.next_transport_event().await.unwrap(),
        Some(BusinessTransportEvent::RouteAccepted(_))
    ));
    assert_eq!(
        exact_active_update(&fixture).await,
        before_route_accepted,
        "Relay RouteAccepted must not mutate bootstrap ACK evidence"
    );
    transport.shutdown().await;

    assert!(matches!(
        consume_store_control(
            &fixture,
            &handler,
            KeyControlRequestV1::key_update_ack(ack.clone()),
            RequestRouteId::from_bytes([0xa1; 16]),
            60,
        )
        .await
        .expect("consume authenticated KeyUpdateAck"),
        KeyControlIngressOutcome::Consumed
    ));
    let first = exact_active_update(&fixture).await;
    assert_eq!(first.operation_id, operation_id);
    assert_eq!(first.lifecycle, KeyUpdateLifecycle::Acked);
    assert_eq!(
        first.state_changed_at_ms, before_route_accepted.state_changed_at_ms,
        "late normal ACK upgrades evidence without moving the bootstrap causal time"
    );
    assert_eq!(
        first.canonical_ack.as_deref(),
        Some(canonical_ack.as_slice())
    );

    tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    assert!(matches!(
        consume_store_control(
            &fixture,
            &handler,
            KeyControlRequestV1::key_update_ack(ack.clone()),
            RequestRouteId::from_bytes([0xa2; 16]),
            61,
        )
        .await
        .expect("consume exact later KeyUpdateAck replay"),
        KeyControlIngressOutcome::Consumed
    ));
    assert_eq!(
        exact_active_update(&fixture).await,
        first,
        "canonical ACK replay must preserve the first daemon-observed timestamp"
    );

    let mut wrong_hash = ack;
    wrong_hash.update_set_sha256[0] ^= 1;
    assert!(matches!(
        consume_store_control(
            &fixture,
            &handler,
            KeyControlRequestV1::key_update_ack(wrong_hash),
            RequestRouteId::from_bytes([0xa3; 16]),
            62,
        )
        .await,
        Err(RemoteLinkError::KeyControl(
            KeyControlIngressError::StoreRejected
        ))
    ));
    assert_eq!(exact_active_update(&fixture).await, first);
    assert_eq!(fixture.core().remote_registration_calls_for_test(), 0);
    fixture.shutdown().await;
}

async fn freeze_stream_ack_transition(
    fixture: &ActiveRemoteDispatchFixture,
    grant_serial: GrantSerial,
    known_revision: KeyDirectoryRevision,
    requested_revision: KeyDirectoryRevision,
) -> (KeyUpdateSetV1, KeyTransitionStreamCut) {
    let publication_stream_id = [0xb2; 16];
    let stream_route = [0xb3; 16];
    let generation = [0xb4; 16];
    fixture
        .store()
        .create_publication_stream(
            publication_stream_id,
            PublicationScope::Catalog,
            stream_route,
            generation,
        )
        .await
        .expect("create exact catalog publication stream");

    let pending = fixture
        .store()
        .load_active_key_transition()
        .await
        .expect("load production bootstrap stream ACK transition")
        .expect("stream ACK fixture preserves its bootstrap transition");
    let recipient = KeyTransitionRecipient {
        device_route: *DEVICE.as_bytes(),
        grant_serial: grant_serial.value(),
    };
    assert_eq!(pending.transition.operation, KeyTransitionOperation::Add);
    assert_eq!(pending.transition.from_revision, known_revision.value());
    assert_eq!(pending.transition.to_revision, requested_revision.value());
    assert_eq!(pending.transition.recipients, vec![recipient]);
    let operation_id = pending.transition.operation_id;
    fixture
        .store()
        .finalize_key_directory_rotation(operation_id)
        .await
        .expect("finalize stream ACK fixture key-directory axes");
    let update = matching_bootstrap_update_for_test(&fixture.store(), recipient).await;
    assert_eq!(update.key_revision, requested_revision.value());
    let update_set = KeyUpdateSetV1::from_canonical_bytes(&update.canonical_update_set)
        .expect("decode production bootstrap stream ACK update set");
    fixture
        .store()
        .freeze_key_updates(operation_id, vec![update])
        .await
        .expect("freeze stream ACK update set");
    let catalog = KeyTransitionStreamCut {
        scope: KeyTransitionStreamScope::Catalog,
        publication_stream_id,
        stream_route,
        generation,
        relay_committed_outer: None,
        relay_committed_inner: None,
        barrier_sequence: 0,
        old_epoch: 0,
        new_epoch: 1,
        epoch_barrier_sha256: [0xb5; 32],
    };
    fixture
        .store()
        .freeze_key_barriers(operation_id, vec![catalog])
        .await
        .expect("freeze exact stream ACK cuts");
    let frozen = freeze_counter_bound_publication(
        fixture,
        [0xe2; 16],
        publication_stream_id,
        generation,
        KeyId {
            purpose: KeyPurpose::Catalog,
            epoch: 1,
        },
        None,
        None,
        PublicationPayloadKind::Control,
        vec![0xe2; 32],
    )
    .await;
    assert_eq!(frozen.stream_seq, 0);
    fixture
        .store()
        .acknowledge_publication_commit(
            publication_stream_id,
            generation,
            frozen.stream_seq,
            frozen.blob_sha256,
        )
        .await
        .expect("commit exact epoch barrier publication");
    fixture
        .store()
        .acknowledge_publication_delivery(
            publication_stream_id,
            generation,
            frozen.stream_seq,
            frozen.blob_sha256,
        )
        .await
        .expect("locally acknowledge exact epoch barrier publication");
    fixture
        .store()
        .mark_key_barriers_committed(operation_id)
        .await
        .expect("commit exact stream ACK cuts");
    (update_set, catalog)
}

#[allow(clippy::too_many_arguments)]
async fn freeze_counter_bound_publication(
    fixture: &ActiveRemoteDispatchFixture,
    publication_id: [u8; 16],
    publication_stream_id: [u8; 16],
    generation: [u8; 16],
    key_id: KeyId,
    inner_after: Option<u64>,
    inner_through: Option<u64>,
    payload_kind: PublicationPayloadKind,
    blob: Vec<u8>,
) -> FrozenPublication {
    let store = fixture.store();
    let scope = CounterScope::publication(
        store.machine_trust_domain().expect("machine trust domain"),
        key_id,
        publication_stream_id,
    )
    .expect("derive exact stream ACK sender scope");
    store
        .register_remote_counter_guard_scope(scope.token())
        .await
        .expect("register exact stream ACK CounterGuard scope");
    store
        .mark_remote_counter_guard_scope_materialized(scope.token())
        .await
        .expect("materialize exact stream ACK CounterGuard scope");
    let database = store
        .load_remote_counter_record(scope.token(), key_id)
        .await
        .expect("load exact stream ACK counter genesis");
    let reserved_end = database
        .reserved_end
        .checked_add(1_024)
        .expect("reserve exact stream ACK counter block");
    store
        .freeze_signed_publication(FreezeSignedPublicationRequest {
            publication_id,
            publication_stream_id,
            generation,
            counter: RemoteCounterReservation {
                scope_token: scope.token(),
                key_id,
                previous_reserved_end: database.reserved_end,
                reserved_end,
                previous_db_anchor: database.db_anchor,
                reservation_id: publication_id,
                publication_id,
            },
            inner_after,
            inner_through,
            payload_kind,
            shared_binding: None,
            sealer_retained_bytes: blob.capacity(),
            sealer: Box::new(move |_| Ok(blob)),
        })
        .await
        .expect("freeze transaction-bound stream ACK publication")
}

#[tokio::test]
async fn stream_applied_ack_binds_tagged_inner_cursor_exact_cut_and_canonical_replay() {
    let fixture = active_remote_dispatch_with_pending_transition_for_test(MACHINE, DEVICE).await;
    let (grant_serial, trust_epoch, requested_revision) = active_authority(&fixture).await;
    let known_revision = KeyDirectoryRevision::new(
        requested_revision
            .value()
            .checked_sub(1)
            .expect("bootstrap transition has a predecessor revision"),
    );
    let conversation = RuntimeId::from_bytes(RuntimeIdKind::Conversation, [0xba; 16])
        .expect("valid stream ACK conversation id");
    let (update_set, cut) =
        freeze_stream_ack_transition(&fixture, grant_serial, known_revision, requested_revision)
            .await;
    let handler = StoreBackedKeyControlIngressHandler::new(fixture.store());
    let key_ack = KeyUpdateAckV1 {
        format_version: E2EE_FORMAT_VERSION,
        runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
        relay_protocol_version: RELAY_PROTOCOL_VERSION,
        machine_route: MACHINE,
        device_route: DEVICE,
        grant_serial,
        root_trust_epoch: trust_epoch,
        key_directory_revision: requested_revision,
        update_set_sha256: update_set.canonical_sha256().expect("hash stream update"),
    };
    consume_store_control(
        &fixture,
        &handler,
        KeyControlRequestV1::key_update_ack(key_ack),
        RequestRouteId::from_bytes([0xbb; 16]),
        70,
    )
    .await
    .expect("ACK stream fixture key update");

    let active = fixture
        .store()
        .load_active_remote_ingress(MACHINE, DEVICE)
        .await
        .expect("load stream ACK snapshot authorization");
    let current = fixture
        .store()
        .recheck_active_remote_ingress(&active)
        .await
        .expect("recheck stream ACK snapshot authorization");
    let permit = fixture
        .store()
        .resolve_transition_snapshot_permit(TransitionSnapshotRequest::new(
            current,
            KeyTransitionStreamScope::Catalog,
            StreamCursor::BeforeFirst,
        ))
        .await
        .expect("resolve bootstrap stream ACK snapshot permit");
    assert_eq!(permit.stream_route(), cut.stream_route);
    assert_eq!(permit.generation(), cut.generation);
    assert_eq!(permit.barrier_sequence(), cut.barrier_sequence);
    fixture
        .store()
        .mark_transition_snapshot_flushed(
            permit
                .into_flush([0xb7; 32])
                .expect("bind bootstrap stream ACK SyncComplete hash"),
        )
        .await
        .expect("persist bootstrap stream ACK snapshot flush");

    let exact_ack = StreamAppliedAckV1 {
        format_version: E2EE_FORMAT_VERSION,
        runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
        relay_protocol_version: RELAY_PROTOCOL_VERSION,
        machine_route: MACHINE,
        device_route: DEVICE,
        grant_serial,
        root_trust_epoch: trust_epoch,
        stream_route: StreamRouteId::from_bytes(cut.stream_route),
        stream_generation: StreamGenerationId::from_bytes(cut.generation),
        applied_stream_seq: cut.barrier_sequence,
        inner_cursor: RuntimeInnerCursor::Catalog {
            cursor: StreamCursor::from_high_water(cut.relay_committed_inner),
        },
        key_directory_revision: requested_revision,
        key_epoch: cut.new_epoch,
        epoch_barrier_sha256: cut.epoch_barrier_sha256,
    };
    let mut wrong_tag = exact_ack.clone();
    wrong_tag.inner_cursor = RuntimeInnerCursor::Conversation {
        conversation_id: ConversationId::new(conversation.to_canonical_string()),
        cursor: StreamCursor::from_high_water(cut.relay_committed_inner),
    };
    assert!(matches!(
        consume_store_control(
            &fixture,
            &handler,
            KeyControlRequestV1::stream_applied_ack(wrong_tag),
            RequestRouteId::from_bytes([0xbc; 16]),
            71,
        )
        .await,
        Err(RemoteLinkError::KeyControl(
            KeyControlIngressError::StoreRejected
        ))
    ));
    assert!(
        exact_active_update(&fixture)
            .await
            .stream_applied_acks
            .is_empty()
    );

    consume_store_control(
        &fixture,
        &handler,
        KeyControlRequestV1::stream_applied_ack(exact_ack.clone()),
        RequestRouteId::from_bytes([0xbd; 16]),
        72,
    )
    .await
    .expect("consume exact StreamAppliedAck");
    assert!(
        fixture
            .store()
            .load_active_key_transition()
            .await
            .expect("read transition slot after final authenticated ACK")
            .is_none(),
        "the final required device ACK must release the unique transition slot"
    );

    tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    consume_store_control(
        &fixture,
        &handler,
        KeyControlRequestV1::stream_applied_ack(exact_ack),
        RequestRouteId::from_bytes([0xbe; 16]),
        73,
    )
    .await
    .expect("consume exact later StreamAppliedAck replay");
    assert!(
        fixture
            .store()
            .load_active_key_transition()
            .await
            .expect("read transition slot after exact terminal ACK replay")
            .is_none(),
        "terminal ACK replay must not recreate the completed transition"
    );
    assert_eq!(fixture.core().remote_registration_calls_for_test(), 0);
    fixture.shutdown().await;
}
