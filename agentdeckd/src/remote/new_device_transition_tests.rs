use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use agentdeck_crypto::{
    AeadSendingKey, SecretAeadKey, SenderCounter, SigningKey, seal_symmetric, sha256, sign_sealed,
};
use agentdeck_protocol::e2ee::{
    AuthorizationCapabilityV1, AuthorizationPermissionV1, E2EE_FORMAT_VERSION, KeyControlRequestV1,
    KeyId, KeyPurpose, OuterContextV1, OuterFrameKind, SealedPayloadKind, SignedSealedBlobV1,
    StreamAppliedAckV1,
};
use agentdeck_protocol::relay_v2::frame::{
    AcceptedRef, OpaqueRouteFrame, Publish, RelayFrameBody, RouteAccepted, SealedBlob,
    Send as RouteSend,
};
use agentdeck_protocol::relay_v2::{
    DeviceRouteId, KeyDirectoryRevision, MachineRouteId, RELAY_PROTOCOL_VERSION, RequestRouteId,
    StreamGenerationId, StreamRouteId,
};
use agentdeck_protocol::runtime::identity::{ConversationId, MessageId};
use agentdeck_protocol::runtime::{
    BackfillRequest, CodexConversationConfiguration, ConversationConfiguration,
    RUNTIME_PROTOCOL_VERSION, RuntimeEnvelope, RuntimeInnerCursor, RuntimeMessage, RuntimeReply,
    RuntimeRequest, RuntimeStreamItem, RuntimeTransferCarrierV1, StreamCursor, SubscriptionReceipt,
    VendorConfigurationSnapshot,
};
use agentdeck_protocol::{CodexApprovalPolicy, CodexReasoningEffort, CodexSandboxMode};
use async_trait::async_trait;

use crate::runtime::events::RuntimeStreamTarget;
use crate::runtime::model::MachineEnrollmentState;
use crate::runtime::publication::{
    PublicationCommitReceipt, PublicationDispatchKey, PublicationTransport,
    PublicationTransportOutcome,
};
use crate::runtime::snapshot::{
    SnapshotMaterialization, SnapshotMaterializer, assemble_build_snapshot,
};
use crate::runtime::store::key_transition::{
    AcknowledgeKeyUpdate, KeyTransitionPhase, KeyTransitionStreamScope, KeyUpdateLifecycle,
    RemoteTransitionIngressClass, TransitionSnapshotPermit, TransitionSnapshotRequest,
    canonical_update_hash,
};
use crate::runtime::store::{
    ConfigureConversation, ConfigureConversationOutcome, FrozenPublication, IdempotencyOwner,
    PublicationPayloadKind, ReadySnapshotReference, RemoteReplyAuthorization, RuntimeId,
    RuntimeIdKind, StreamBindingPermit,
    active_authorization_store_with_pending_transition_for_test,
    pending_new_device_transition_fixture_for_test,
};
use crate::runtime::{AgentRouter, RuntimeCore};
use crate::security::{KeyStore, MemoryKeyStore, load_or_create_storage_kek};

use super::bootstrap::machine_pairing_anchor_for_test;
use super::counter::{COUNTER_BLOCK_SIZE, CounterGuardBackend, CounterGuardPhase, CounterScope};
use super::directed_reply::DeviceReplyTxSealer;
use super::dispatch::{RemoteIngressDispatcher, RemoteIngressRoute};
use super::identity::{
    KeyDirectoryGuard, OwnedKeyStoreCounterGuardBackend, install_key_directory_guard,
};
use super::key_control::{KeyControlIngressError, StoreBackedKeyControlIngressHandler};
use super::link::{
    DirectedReplyRoute, DirectedReplySeal, DirectedReplySealer, PreCoreIngressOutcome,
    RemoteLinkError, RemoteLinkIngressMode, RemoteLinkOwner, RemoteStreamPublisher,
    route_ingress_before_core_with_mode,
};
use super::publication_transport::{
    PublicationDriveOwner, tests::open_owner_with_transport_for_test,
};
use super::shared_publisher::{RuntimeStoreSharedPublicationBackend, SharedStreamPublisher};
use super::transition_owner::{KeyTransitionRecoveryOwner, TransitionReadiness};
use super::transport::active_pairing_transport_for_test;
use super::transport::tests::machine_data_authority_for_transition_test;

#[derive(Default)]
struct CommittingTransport;

#[async_trait]
impl PublicationTransport for CommittingTransport {
    async fn publish(&self, publication: FrozenPublication) -> PublicationTransportOutcome {
        PublicationTransportOutcome::Committed(PublicationCommitReceipt {
            key: PublicationDispatchKey::from(&publication),
        })
    }
}

struct SignedRuntimeSendAxes<'a> {
    machine_route: MachineRouteId,
    device_route: DeviceRouteId,
    request_route: RequestRouteId,
    message_id: &'a str,
    counter: u64,
}

fn signed_runtime_send(
    axes: SignedRuntimeSendAxes<'_>,
    request: RuntimeRequest,
    command_key: &AeadSendingKey,
    device_sign: &SigningKey,
) -> RouteSend {
    let SignedRuntimeSendAxes {
        machine_route,
        device_route,
        request_route,
        message_id,
        counter,
    } = axes;
    let envelope = RuntimeEnvelope {
        version: RUNTIME_PROTOCOL_VERSION,
        message_id: MessageId::new(message_id),
        body: RuntimeMessage::Request(request),
    };
    let payload = envelope
        .to_json_bytes_checked()
        .expect("encode new-device transition Runtime request");
    let context = OuterContextV1 {
        frame_kind: OuterFrameKind::UplinkSend,
        relay_protocol_version: RELAY_PROTOCOL_VERSION,
        e2ee_format_version: E2EE_FORMAT_VERSION,
        machine_route: Some(machine_route),
        device_route: Some(device_route),
        stream_route: None,
        request_route: Some(request_route),
        pair_route: None,
        stream_generation: None,
        stream_cursor: None,
        stream_seq: None,
        message_key_epoch: command_key.epoch,
    };
    let unsigned = seal_symmetric(
        command_key,
        &context,
        SealedPayloadKind::CommandRequest,
        &payload,
        SenderCounter(counter),
    )
    .expect("seal new-device transition Runtime request");
    let signed = sign_sealed(unsigned, device_sign, &context);
    RouteSend {
        device_route,
        request_route,
        sealed_blob: SealedBlob(signed.to_wire_bytes()),
    }
}

fn signed_key_control_send(
    machine_route: MachineRouteId,
    device_route: DeviceRouteId,
    request_route: RequestRouteId,
    control: KeyControlRequestV1,
    counter: u64,
    command_key: &AeadSendingKey,
    device_sign: &SigningKey,
) -> RouteSend {
    let payload = control
        .canonical_bytes()
        .expect("encode new-device transition key-control request");
    let context = OuterContextV1 {
        frame_kind: OuterFrameKind::UplinkSend,
        relay_protocol_version: RELAY_PROTOCOL_VERSION,
        e2ee_format_version: E2EE_FORMAT_VERSION,
        machine_route: Some(machine_route),
        device_route: Some(device_route),
        stream_route: None,
        request_route: Some(request_route),
        pair_route: None,
        stream_generation: None,
        stream_cursor: None,
        stream_seq: None,
        message_key_epoch: command_key.epoch,
    };
    let unsigned = seal_symmetric(
        command_key,
        &context,
        SealedPayloadKind::KeyUpdate,
        &payload,
        SenderCounter(counter),
    )
    .expect("seal new-device transition key-control request");
    let signed = sign_sealed(unsigned, device_sign, &context);
    RouteSend {
        device_route,
        request_route,
        sealed_blob: SealedBlob(signed.to_wire_bytes()),
    }
}

fn business_frame(send: RouteSend) -> OpaqueRouteFrame {
    OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::Send(send),
    }
}

#[derive(Clone, Debug)]
struct TransitionReplyAttempt {
    scope: KeyTransitionStreamScope,
    reply: RuntimeReply,
    accepted: bool,
}

struct ObservingTransitionSealer {
    inner: DeviceReplyTxSealer,
    harness: Arc<super::transport::RemoteTransportTestHarness>,
    attempts: Mutex<Vec<TransitionReplyAttempt>>,
    attempt_changed: tokio::sync::Notify,
    flush_count: AtomicUsize,
    flush_changed: tokio::sync::Notify,
    flushed_scopes: Mutex<Vec<KeyTransitionStreamScope>>,
}

impl ObservingTransitionSealer {
    fn new(
        inner: DeviceReplyTxSealer,
        harness: Arc<super::transport::RemoteTransportTestHarness>,
    ) -> Self {
        Self {
            inner,
            harness,
            attempts: Mutex::new(Vec::new()),
            attempt_changed: tokio::sync::Notify::new(),
            flush_count: AtomicUsize::new(0),
            flush_changed: tokio::sync::Notify::new(),
            flushed_scopes: Mutex::new(Vec::new()),
        }
    }

    fn attempts_for_scope(&self, scope: KeyTransitionStreamScope) -> Vec<TransitionReplyAttempt> {
        self.attempts
            .lock()
            .expect("read transition reply attempts")
            .iter()
            .filter(|attempt| attempt.scope == scope)
            .cloned()
            .collect()
    }

    async fn wait_for_sync(&self, scope: KeyTransitionStreamScope) {
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                let changed = self.attempt_changed.notified();
                let complete = self.attempts_for_scope(scope).iter().any(|attempt| {
                    !attempt.accepted || matches!(attempt.reply, RuntimeReply::SyncComplete(_))
                });
                if complete {
                    break;
                }
                changed.await;
            }
        })
        .await
        .expect("transition snapshot reaches SyncComplete or a typed sealer rejection");
    }

    async fn wait_for_flush_count(&self, expected: usize) {
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                let changed = self.flush_changed.notified();
                if self.flush_count.load(Ordering::SeqCst) >= expected {
                    break;
                }
                changed.await;
            }
        })
        .await
        .expect("transition snapshot persists its exact flush marker");
    }

    fn flushed_scopes(&self) -> Vec<KeyTransitionStreamScope> {
        self.flushed_scopes
            .lock()
            .expect("read flushed transition scopes")
            .clone()
    }
}

#[async_trait]
impl DirectedReplySealer for ObservingTransitionSealer {
    fn admission_ready(&self) -> bool {
        self.inner.admission_ready()
    }

    async fn seal_exact(
        &self,
        authorization: &RemoteReplyAuthorization,
        route: DirectedReplyRoute,
        runtime_bytes: Arc<[u8]>,
    ) -> Result<DirectedReplySeal, RemoteLinkError> {
        self.inner
            .seal_exact(authorization, route, runtime_bytes)
            .await
    }

    async fn seal_transfer_exact(
        &self,
        authorization: &RemoteReplyAuthorization,
        route: DirectedReplyRoute,
        carrier: RuntimeTransferCarrierV1,
    ) -> Result<DirectedReplySeal, RemoteLinkError> {
        self.inner
            .seal_transfer_exact(authorization, route, carrier)
            .await
    }

    async fn seal_transition_snapshot_exact(
        &self,
        authorization: &RemoteReplyAuthorization,
        route: DirectedReplyRoute,
        permit: &TransitionSnapshotPermit,
        runtime_bytes: Arc<[u8]>,
    ) -> Result<DirectedReplySeal, RemoteLinkError> {
        let envelope: RuntimeEnvelope = serde_json::from_slice(&runtime_bytes)
            .expect("transition reply is a canonical Runtime envelope");
        let RuntimeMessage::Reply(reply) = envelope.body else {
            panic!("transition directed egress must be a Runtime reply")
        };
        let result = self
            .inner
            .seal_transition_snapshot_exact(authorization, route, permit, runtime_bytes)
            .await;
        if result.is_ok() && matches!(reply, RuntimeReply::SyncComplete(_)) {
            self.harness.hold_send_flush();
        }
        self.attempts
            .lock()
            .expect("record transition reply attempt")
            .push(TransitionReplyAttempt {
                scope: permit.scope(),
                reply,
                accepted: result.is_ok(),
            });
        self.attempt_changed.notify_one();
        result
    }

    async fn seal_transition_snapshot_transfer_exact(
        &self,
        authorization: &RemoteReplyAuthorization,
        route: DirectedReplyRoute,
        permit: &TransitionSnapshotPermit,
        carrier: RuntimeTransferCarrierV1,
    ) -> Result<DirectedReplySeal, RemoteLinkError> {
        self.inner
            .seal_transition_snapshot_transfer_exact(authorization, route, permit, carrier)
            .await
    }

    async fn seal_stream_binding_exact(
        &self,
        authorization: &RemoteReplyAuthorization,
        route: DirectedReplyRoute,
        permit: StreamBindingPermit,
    ) -> Result<SignedSealedBlobV1, RemoteLinkError> {
        self.inner
            .seal_stream_binding_exact(authorization, route, permit)
            .await
    }

    async fn mark_transition_snapshot_flushed(
        &self,
        permit: TransitionSnapshotPermit,
        sync_complete_sha256: [u8; 32],
    ) -> Result<(), RemoteLinkError> {
        let scope = permit.scope();
        let result = self
            .inner
            .mark_transition_snapshot_flushed(permit, sync_complete_sha256)
            .await;
        if result.is_ok() {
            self.flushed_scopes
                .lock()
                .expect("record flushed transition scope")
                .push(scope);
            self.flush_count.fetch_add(1, Ordering::SeqCst);
            self.flush_changed.notify_one();
        }
        result
    }
}

struct ObservingSharedPublisher {
    inner: SharedStreamPublisher,
    started: Mutex<Vec<RuntimeStreamItem>>,
    completed: Mutex<Vec<RuntimeStreamItem>>,
    completion_changed: tokio::sync::Notify,
}

impl ObservingSharedPublisher {
    fn new(inner: SharedStreamPublisher) -> Self {
        Self {
            inner,
            started: Mutex::new(Vec::new()),
            completed: Mutex::new(Vec::new()),
            completion_changed: tokio::sync::Notify::new(),
        }
    }

    fn started_items(&self) -> Vec<RuntimeStreamItem> {
        self.started
            .lock()
            .expect("read started shared publication items")
            .clone()
    }

    fn completed_items(&self) -> Vec<RuntimeStreamItem> {
        self.completed
            .lock()
            .expect("read completed shared publication items")
            .clone()
    }

    async fn wait_for_completed_count(&self, expected: usize) {
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                let changed = self.completion_changed.notified();
                if self.completed_items().len() >= expected {
                    break;
                }
                changed.await;
            }
        })
        .await
        .expect("production shared publisher completes exact publications");
    }
}

#[async_trait]
impl RemoteStreamPublisher for ObservingSharedPublisher {
    fn admission_ready(&self) -> bool {
        RemoteStreamPublisher::admission_ready(&self.inner)
    }

    async fn publish_exact(&self, runtime_bytes: Arc<[u8]>) -> Result<(), RemoteLinkError> {
        let observed = serde_json::from_slice::<RuntimeEnvelope>(runtime_bytes.as_ref())
            .ok()
            .and_then(|envelope| match envelope.body {
                RuntimeMessage::Stream(item) => Some(item),
                _ => None,
            });
        if let Some(item) = observed.as_ref() {
            self.started
                .lock()
                .expect("record started shared publication item")
                .push(item.clone());
        }
        let result = RemoteStreamPublisher::publish_exact(&self.inner, runtime_bytes).await;
        if result.is_ok()
            && let Some(item) = observed
        {
            self.completed
                .lock()
                .expect("record completed shared publication item")
                .push(item);
            self.completion_changed.notify_one();
        }
        result
    }

    async fn publish_transfer_exact(
        &self,
        carrier: RuntimeTransferCarrierV1,
    ) -> Result<(), RemoteLinkError> {
        RemoteStreamPublisher::publish_transfer_exact(&self.inner, carrier).await
    }

    async fn notify_reconnected(&self) -> Result<(), RemoteLinkError> {
        RemoteStreamPublisher::notify_reconnected(&self.inner).await
    }
}

async fn wait_for_next_relay_publish(
    harness: &super::transport::RemoteTransportTestHarness,
    sent_cursor: &mut usize,
) -> Publish {
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            let frames = harness.sent_frames();
            while *sent_cursor < frames.len() {
                let index = *sent_cursor;
                *sent_cursor += 1;
                if let RelayFrameBody::Publish(publish) = &frames[index].body {
                    return publish.clone();
                }
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("existing MachineLink emits a Relay Publish")
}

async fn accept_relay_publish(
    harness: &super::transport::RemoteTransportTestHarness,
    publish: &Publish,
) {
    harness
        .push_frame(OpaqueRouteFrame {
            version: RELAY_PROTOCOL_VERSION,
            body: RelayFrameBody::RouteAccepted(RouteAccepted {
                accepted: AcceptedRef::StreamFrame {
                    stream_route: publish.stream_route,
                    stream_seq: publish.stream_seq,
                },
            }),
        })
        .await;
}

fn relay_publish_count(harness: &super::transport::RemoteTransportTestHarness) -> usize {
    harness
        .sent_frames()
        .iter()
        .filter(|frame| matches!(&frame.body, RelayFrameBody::Publish(_)))
        .count()
}

async fn append_transition_configuration(
    store: &crate::runtime::store::RuntimeStoreHandle,
    conversation_id: RuntimeId,
    expected_revision: u64,
    effort: CodexReasoningEffort,
    idempotency_key: &str,
) -> u64 {
    let outcome = store
        .configure_conversation(ConfigureConversation {
            conversation_id,
            owner: IdempotencyOwner::Local {
                machine_trust_domain: store
                    .machine_trust_domain()
                    .expect("load transition configuration trust domain"),
                uid: 501,
                client_installation_id: [0xf2; 16],
            },
            idempotency_key: idempotency_key.to_owned(),
            expected_configuration_revision: expected_revision,
            configuration: ConversationConfiguration::new(VendorConfigurationSnapshot::Codex(
                CodexConversationConfiguration::new(
                    CodexApprovalPolicy::OnRequest,
                    CodexSandboxMode::WorkspaceWrite,
                    effort,
                ),
            )),
        })
        .await
        .expect("append local event during active remote transition");
    let ConfigureConversationOutcome::Applied { configuration } = outcome else {
        panic!("fresh local transition configuration must append exactly once: {outcome:?}")
    };
    configuration.event_seq
}

async fn persist_latest_conversation_snapshot(
    store: &crate::runtime::store::RuntimeStoreHandle,
    conversation_id: RuntimeId,
) -> (ReadySnapshotReference, Vec<u8>) {
    let source = store
        .acquire_snapshot_build_source(conversation_id)
        .await
        .expect("capture latest conversation snapshot source");
    let materializer = SnapshotMaterializer::new(
        store.clone(),
        Arc::new(AgentRouter::with_runtime_store(store.clone())),
    );
    let SnapshotMaterialization::Build(mut build) = materializer
        .materialize(source)
        .await
        .expect("materialize latest managed conversation snapshot")
    else {
        panic!("direct managed snapshot capture must produce Build")
    };
    let assembled = assemble_build_snapshot(&mut build, Vec::new())
        .expect("assemble latest managed conversation snapshot");
    let write = build
        .bind_assembled_snapshot(assembled)
        .expect("bind latest managed conversation snapshot");
    let stored = store
        .store_conversation_snapshot(write)
        .await
        .expect("persist later durable conversation snapshot");
    let logical_bytes = u64::try_from(stored.payload.len()).expect("snapshot bytes fit u64");
    let reference = ReadySnapshotReference {
        snapshot_id: stored.snapshot_id,
        target: RuntimeStreamTarget::Conversation(conversation_id),
        base: StreamCursor::from_high_water(stored.base_event_seq),
        item_count: stored.item_count,
        logical_bytes,
        content_sha256: stored.content_sha256,
    };
    (reference, stored.payload)
}

async fn admitted_route(
    dispatcher: &RemoteIngressDispatcher,
    send: RouteSend,
) -> RemoteIngressRoute {
    let verified = dispatcher
        .verify_send(send)
        .await
        .expect("new-device transition ingress verifies");
    let current = dispatcher
        .recheck_current(verified)
        .await
        .expect("new-device transition authorization remains current");
    dispatcher
        .admit_replay(current)
        .await
        .expect("new-device transition replay tuple is durably admitted")
        .into_route()
        .expect("new-device transition payload decodes")
        .expect("fresh new-device transition request produces a route")
}

async fn assert_transition_fenced_before_core(
    route: RemoteIngressRoute,
    handler: &StoreBackedKeyControlIngressHandler,
    core: &Arc<RuntimeCore>,
    mode: &mut RemoteLinkIngressMode,
) {
    let before = core.remote_registration_calls_for_test();
    assert!(matches!(
        route_ingress_before_core_with_mode(route, handler, &Arc::downgrade(core), mode).await,
        Err(RemoteLinkError::KeyControl(
            KeyControlIngressError::TransitionFenced
        ))
    ));
    assert_eq!(*mode, RemoteLinkIngressMode::ControlPlaneOnly);
    assert_eq!(
        core.remote_registration_calls_for_test(),
        before,
        "transition-fenced request must not register a RuntimeCore principal"
    );
}

#[tokio::test]
async fn bootstrap_receipt_releases_zero_cut_transition_without_redundant_key_update_ack() {
    let root = tempfile::tempdir().expect("create active-transition fence root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
            .expect("secure active-transition fence root");
    }
    let database = root.path().join("runtime.db");
    let keys = Arc::new(MemoryKeyStore::new());
    let storage_kek =
        load_or_create_storage_kek(keys.as_ref(), &database).expect("create transition KEK");
    let store = active_authorization_store_with_pending_transition_for_test(
        &database,
        storage_kek,
        vec![AuthorizationCapabilityV1::Catalog],
        vec![AuthorizationPermissionV1::CatalogRead],
    )
    .await;
    let pending = store
        .load_active_key_transition()
        .await
        .expect("load pending production transition")
        .expect("initial device activation leaves an active transition");
    let identity = store
        .load_machine_identity_state()
        .await
        .expect("load machine identity")
        .expect("machine identity exists");
    install_key_directory_guard(
        keys.as_ref(),
        KeyDirectoryGuard::new(
            identity.database_id,
            identity.binding.root_fingerprint,
            pending.transition.from_revision,
        ),
    )
    .expect("install pre-transition key-directory guard");
    let Some(MachineEnrollmentState::Active(active)) = store
        .load_machine_enrollment_state()
        .await
        .expect("load active enrollment")
    else {
        panic!("transition fixture must remain actively enrolled")
    };
    let machine_route = MachineRouteId::from_bytes(active.record.machine_route);
    let (machine_data, _machine_data_owner) = machine_data_authority_for_transition_test(
        machine_pairing_anchor_for_test(
            active.connection.relay_server_id,
            machine_route,
            &active.binding,
            active.data_cert,
        ),
        [0x43; 32],
    );
    let publication =
        open_owner_with_transport_for_test(store.clone(), Arc::new(CommittingTransport))
            .await
            .expect("open production publication owner");
    let key_store: Arc<dyn KeyStore> = keys;
    let transition = KeyTransitionRecoveryOwner::start(
        store.clone(),
        key_store,
        machine_route,
        machine_data,
        publication.handle(),
    )
    .expect("start production transition owner");

    assert!(matches!(
        transition.handle().drive_to_business_ready().await,
        Ok(TransitionReadiness::BusinessReady { barrier_count: 0 })
    ));
    assert!(
        store
            .load_active_key_transition()
            .await
            .expect("load completed zero-cut transition")
            .is_none(),
        "DeviceSign PairResponseReceived proof must release the exact bootstrap target"
    );
    store
        .check_remote_transition_ingress(RemoteTransitionIngressClass::Business)
        .await
        .expect("zero-cut bootstrap receipt makes business ingress ready");

    transition
        .shutdown()
        .await
        .expect("shutdown transition owner");
    publication
        .shutdown()
        .await
        .expect("shutdown publication owner");
    store.shutdown().await.expect("shutdown Runtime Store");
}

#[tokio::test]
async fn pending_new_device_with_committed_history_reaches_barriers_committed() {
    let root = tempfile::tempdir().expect("create pending new-device root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
            .expect("secure pending new-device root");
    }
    let database = root.path().join("runtime.db");
    let keys = Arc::new(MemoryKeyStore::new());
    let storage_kek =
        load_or_create_storage_kek(keys.as_ref(), &database).expect("create transition KEK");
    let fixture = pending_new_device_transition_fixture_for_test(
        &database,
        storage_kek,
        vec![
            AuthorizationCapabilityV1::Catalog,
            AuthorizationCapabilityV1::Conversation,
        ],
        vec![
            AuthorizationPermissionV1::CatalogRead,
            AuthorizationPermissionV1::ConversationRead,
        ],
    )
    .await;
    let store = fixture.store;
    let pending = store
        .load_active_key_transition()
        .await
        .expect("load pending new-device transition")
        .expect("new-device transition remains active");
    let identity = store
        .load_machine_identity_state()
        .await
        .expect("load machine identity")
        .expect("machine identity exists");
    install_key_directory_guard(
        keys.as_ref(),
        KeyDirectoryGuard::new(
            identity.database_id,
            identity.binding.root_fingerprint,
            pending.transition.from_revision,
        ),
    )
    .expect("install pre-transition key-directory guard");
    let Some(MachineEnrollmentState::Active(active)) = store
        .load_machine_enrollment_state()
        .await
        .expect("load active enrollment")
    else {
        panic!("new-device transition fixture must remain enrolled")
    };
    let machine_route = MachineRouteId::from_bytes(active.record.machine_route);
    let (machine_data, _machine_data_owner) = machine_data_authority_for_transition_test(
        machine_pairing_anchor_for_test(
            active.connection.relay_server_id,
            machine_route,
            &active.binding,
            active.data_cert,
        ),
        [0x43; 32],
    );
    let publication =
        open_owner_with_transport_for_test(store.clone(), Arc::new(CommittingTransport))
            .await
            .expect("open production publication owner");
    let key_store: Arc<dyn KeyStore> = keys;
    let transition = KeyTransitionRecoveryOwner::start(
        store.clone(),
        key_store,
        machine_route,
        machine_data,
        publication.handle(),
    )
    .expect("start production new-device transition owner");

    let readiness = transition.handle().drive_to_business_ready().await;
    let committed = store
        .load_active_key_transition()
        .await
        .expect("load committed new-device transition")
        .expect("required new-device ACKs remain outstanding");
    assert!(
        matches!(
            readiness,
            Ok(TransitionReadiness::ControlPlaneReady { barrier_count: 2 })
        ),
        "existing Catalog/history must produce two control-plane barriers: {readiness:?}; phase={:?}",
        committed.transition.phase,
    );
    assert_eq!(
        committed.transition.phase,
        KeyTransitionPhase::BarriersCommitted
    );
    assert_eq!(committed.transition.cuts.len(), 2);

    transition
        .shutdown()
        .await
        .expect("shutdown transition owner");
    publication
        .shutdown()
        .await
        .expect("shutdown publication owner");
    store.shutdown().await.expect("shutdown Runtime Store");
}

#[tokio::test]
async fn exact_snapshot_subscribe_is_the_only_business_capability_during_active_transition() {
    let root = tempfile::tempdir().expect("create exact transition-snapshot root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
            .expect("secure exact transition-snapshot root");
    }
    let database = root.path().join("runtime.db");
    let keys = Arc::new(MemoryKeyStore::new());
    let storage_kek =
        load_or_create_storage_kek(keys.as_ref(), &database).expect("create transition KEK");
    let fixture = pending_new_device_transition_fixture_for_test(
        &database,
        storage_kek,
        vec![
            AuthorizationCapabilityV1::Catalog,
            AuthorizationCapabilityV1::Conversation,
        ],
        vec![
            AuthorizationPermissionV1::CatalogRead,
            AuthorizationPermissionV1::ConversationRead,
        ],
    )
    .await;
    let store = fixture.store;
    let conversation_scope =
        KeyTransitionStreamScope::Conversation(*fixture.conversation_id.as_bytes());
    let conversation_id = ConversationId::new(fixture.conversation_id.to_canonical_string());

    let pending = store
        .load_active_key_transition()
        .await
        .expect("load pending exact transition snapshot")
        .expect("new-device transition remains active");
    let identity = store
        .load_machine_identity_state()
        .await
        .expect("load machine identity")
        .expect("machine identity exists");
    install_key_directory_guard(
        keys.as_ref(),
        KeyDirectoryGuard::new(
            identity.database_id,
            identity.binding.root_fingerprint,
            pending.transition.from_revision,
        ),
    )
    .expect("install pre-transition key-directory guard");
    let Some(MachineEnrollmentState::Active(active_enrollment)) = store
        .load_machine_enrollment_state()
        .await
        .expect("load active enrollment")
    else {
        panic!("new-device transition fixture must remain enrolled")
    };
    let machine_route = MachineRouteId::from_bytes(active_enrollment.record.machine_route);
    let (machine_data, _machine_data_owner) = machine_data_authority_for_transition_test(
        machine_pairing_anchor_for_test(
            active_enrollment.connection.relay_server_id,
            machine_route,
            &active_enrollment.binding,
            active_enrollment.data_cert,
        ),
        [0x43; 32],
    );
    let publication =
        open_owner_with_transport_for_test(store.clone(), Arc::new(CommittingTransport))
            .await
            .expect("open production publication owner");
    let key_store: Arc<dyn KeyStore> = keys;
    let transition = KeyTransitionRecoveryOwner::start(
        store.clone(),
        key_store,
        machine_route,
        machine_data,
        publication.handle(),
    )
    .expect("start exact transition-snapshot owner");
    assert!(matches!(
        transition.handle().drive_to_business_ready().await,
        Ok(TransitionReadiness::ControlPlaneReady { barrier_count: 2 })
    ));

    let committed = store
        .load_active_key_transition()
        .await
        .expect("load barrier-committed exact transition snapshot")
        .expect("snapshot application remains outstanding");
    assert_eq!(
        committed.transition.phase,
        KeyTransitionPhase::BarriersCommitted
    );
    let update = committed
        .updates
        .iter()
        .find(|update| update.recipient.device_route == *fixture.device_route.as_bytes())
        .cloned()
        .expect("new device has an exact frozen KeyUpdate");
    let cut = committed
        .transition
        .cuts
        .iter()
        .find(|cut| cut.scope == conversation_scope)
        .copied()
        .expect("transition freezes the exact conversation cut");

    let active = store
        .load_active_remote_ingress(machine_route, fixture.device_route)
        .await
        .expect("load exact new-device authorization");
    let key_directory_revision = active.key_directory_revision().value();
    let command_key_epoch = active.command_key_epoch();
    let authorization_hash = active.authorization_hash();
    let trust_domain = active.machine_trust_domain();
    let command_key = AeadSendingKey::with_derived_nonce_prefix(
        KeyId {
            purpose: KeyPurpose::DeviceCommandTx,
            epoch: command_key_epoch,
        },
        command_key_epoch,
        key_directory_revision,
        SecretAeadKey::from_bytes([0xdc; 32]),
    );
    let device_sign = SigningKey::from_seed(&[0xa4; 32]);
    let dispatcher = RemoteIngressDispatcher::new(machine_route, store.clone());
    let core = Arc::new(
        RuntimeCore::new(
            store.clone(),
            Arc::new(AgentRouter::with_runtime_store(store.clone())),
            trust_domain,
        )
        .expect("construct exact transition-snapshot Core"),
    );
    core.recover()
        .await
        .expect("recover Core before RemoteLink ingress");
    let handler = StoreBackedKeyControlIngressHandler::new(store.clone());
    let mut mode = RemoteLinkIngressMode::ControlPlaneOnly;

    let exact_subscribe = || RuntimeRequest::Subscribe {
        inner_cursor: RuntimeInnerCursor::Conversation {
            conversation_id: conversation_id.clone(),
            cursor: StreamCursor::BeforeFirst,
        },
    };
    assert_eq!(update.lifecycle, KeyUpdateLifecycle::Acked);
    assert!(
        update.canonical_ack.is_some(),
        "DeviceSign receipt must pre-ACK only the bootstrap target update"
    );

    let nonexistent = RuntimeId::from_bytes(RuntimeIdKind::Conversation, [0xf1; 16])
        .expect("construct nonexistent conversation id");
    let fenced_requests = [
        RuntimeRequest::DescribeAgents,
        RuntimeRequest::Backfill(BackfillRequest::Conversation {
            conversation_id: conversation_id.clone(),
            after: StreamCursor::BeforeFirst,
        }),
        RuntimeRequest::Subscribe {
            inner_cursor: RuntimeInnerCursor::Conversation {
                conversation_id: ConversationId::new(nonexistent.to_canonical_string()),
                cursor: StreamCursor::BeforeFirst,
            },
        },
        RuntimeRequest::Subscribe {
            inner_cursor: RuntimeInnerCursor::Conversation {
                conversation_id: conversation_id.clone(),
                cursor: StreamCursor::At(
                    cut.relay_committed_inner
                        .expect("conversation cut has an exact inner high-water"),
                ),
            },
        },
    ];
    for (index, request) in fenced_requests.into_iter().enumerate() {
        let route = admitted_route(
            &dispatcher,
            signed_runtime_send(
                SignedRuntimeSendAxes {
                    machine_route,
                    device_route: fixture.device_route,
                    request_route: RequestRouteId::from_bytes([0xe2 + index as u8; 16]),
                    message_id: &format!("transition-snapshot-fenced-{index}"),
                    counter: 2 + index as u64,
                },
                request,
                &command_key,
                &device_sign,
            ),
        )
        .await;
        assert_transition_fenced_before_core(route, &handler, &core, &mut mode).await;
    }

    let current = store
        .recheck_active_remote_ingress(
            &store
                .load_active_remote_ingress(machine_route, fixture.device_route)
                .await
                .expect("reload exact new-device authorization"),
        )
        .await
        .expect("authorization remains current after bootstrap receipt ACK");
    let permit = store
        .resolve_transition_snapshot_permit(TransitionSnapshotRequest::new(
            current,
            conversation_scope,
            StreamCursor::BeforeFirst,
        ))
        .await
        .expect("resolve exact Store-issued transition snapshot permit");
    assert_eq!(permit.operation_id(), committed.transition.operation_id);
    assert_eq!(permit.recipient(), update.recipient);
    assert_eq!(permit.authorization_hash(), authorization_hash);
    assert_eq!(permit.scope(), cut.scope);
    assert_eq!(permit.publication_stream_id(), cut.publication_stream_id);
    assert_eq!(permit.stream_route(), cut.stream_route);
    assert_eq!(permit.generation(), cut.generation);
    assert_eq!(permit.relay_committed_outer(), cut.relay_committed_outer);
    assert_eq!(permit.relay_committed_inner(), cut.relay_committed_inner);
    assert_eq!(permit.barrier_sequence(), cut.barrier_sequence);
    assert_eq!(permit.key_directory_revision(), update.key_revision);
    assert_eq!(permit.key_epoch(), cut.new_epoch);
    assert_eq!(permit.epoch_barrier_sha256(), cut.epoch_barrier_sha256);

    let before_exact = core.remote_registration_calls_for_test();
    let exact = admitted_route(
        &dispatcher,
        signed_runtime_send(
            SignedRuntimeSendAxes {
                machine_route,
                device_route: fixture.device_route,
                request_route: RequestRouteId::from_bytes([0xe6; 16]),
                message_id: "transition-snapshot-exact",
                counter: 6,
            },
            exact_subscribe(),
            &command_key,
            &device_sign,
        ),
    )
    .await;
    assert!(matches!(
        route_ingress_before_core_with_mode(exact, &handler, &Arc::downgrade(&core), &mut mode,)
            .await,
        Ok(PreCoreIngressOutcome::Business(_))
    ));
    assert_eq!(mode, RemoteLinkIngressMode::ControlPlaneOnly);
    assert_eq!(core.remote_registration_calls_for_test(), before_exact + 1);

    let after_exact = admitted_route(
        &dispatcher,
        signed_runtime_send(
            SignedRuntimeSendAxes {
                machine_route,
                device_route: fixture.device_route,
                request_route: RequestRouteId::from_bytes([0xe7; 16]),
                message_id: "transition-snapshot-after-exact",
                counter: 7,
            },
            RuntimeRequest::DescribeAgents,
            &command_key,
            &device_sign,
        ),
    )
    .await;
    assert_transition_fenced_before_core(after_exact, &handler, &core, &mut mode).await;

    transition
        .shutdown()
        .await
        .expect("shutdown exact transition-snapshot owner");
    publication
        .shutdown()
        .await
        .expect("shutdown exact transition-snapshot publication owner");
    core.shutdown()
        .await
        .expect("shutdown exact transition-snapshot Core");
}

#[tokio::test]
async fn full_link_transition_snapshot_flushes_before_ack_then_publishes_contiguous_catchup() {
    let root = tempfile::tempdir().expect("create full-link transition-snapshot root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
            .expect("secure full-link transition-snapshot root");
    }
    let database = root.path().join("runtime.db");
    let keys = Arc::new(MemoryKeyStore::new());
    let storage_kek =
        load_or_create_storage_kek(keys.as_ref(), &database).expect("create full-link KEK");
    let fixture = pending_new_device_transition_fixture_for_test(
        &database,
        storage_kek,
        vec![
            AuthorizationCapabilityV1::Catalog,
            AuthorizationCapabilityV1::Conversation,
        ],
        vec![
            AuthorizationPermissionV1::CatalogRead,
            AuthorizationPermissionV1::ConversationRead,
        ],
    )
    .await;
    let store = fixture.store;
    let conversation_scope =
        KeyTransitionStreamScope::Conversation(*fixture.conversation_id.as_bytes());
    let conversation_id = ConversationId::new(fixture.conversation_id.to_canonical_string());

    let pending = store
        .load_active_key_transition()
        .await
        .expect("load pending full-link transition")
        .expect("new-device full-link transition remains active");
    let identity = store
        .load_machine_identity_state()
        .await
        .expect("load full-link machine identity")
        .expect("full-link machine identity exists");
    install_key_directory_guard(
        keys.as_ref(),
        KeyDirectoryGuard::new(
            identity.database_id,
            identity.binding.root_fingerprint,
            pending.transition.from_revision,
        ),
    )
    .expect("install full-link key-directory guard");
    let Some(MachineEnrollmentState::Active(active_enrollment)) = store
        .load_machine_enrollment_state()
        .await
        .expect("load full-link enrollment")
    else {
        panic!("full-link transition fixture must remain enrolled")
    };
    let machine_route = MachineRouteId::from_bytes(active_enrollment.record.machine_route);
    let (machine_data, _machine_data_owner) = machine_data_authority_for_transition_test(
        machine_pairing_anchor_for_test(
            active_enrollment.connection.relay_server_id,
            machine_route,
            &active_enrollment.binding,
            active_enrollment.data_cert,
        ),
        [0x43; 32],
    );
    let (mut transport, _pairing_lane, harness) = active_pairing_transport_for_test(machine_route);
    let business = transport
        .take_business_lane()
        .expect("take the unique full-link business lane");
    let publication = PublicationDriveOwner::open(store.clone(), business.publication_handle())
        .await
        .expect("open the unique full-link publication owner");
    let publication_drive = publication.handle();
    let key_store: Arc<dyn KeyStore> = keys.clone();
    let transition = KeyTransitionRecoveryOwner::start(
        store.clone(),
        key_store.clone(),
        machine_route,
        machine_data.clone(),
        publication_drive.clone(),
    )
    .expect("start full-link transition owner");
    let transition_drive = tokio::spawn({
        let handle = transition.handle();
        async move { handle.drive_to_business_ready().await }
    });
    let mut sent_cursor = 0_usize;
    let mut barrier_publishes = Vec::new();
    for _ in 0..2 {
        let publish = wait_for_next_relay_publish(harness.as_ref(), &mut sent_cursor).await;
        accept_relay_publish(harness.as_ref(), &publish).await;
        barrier_publishes.push(publish);
    }
    let readiness = tokio::time::timeout(std::time::Duration::from_secs(2), transition_drive)
        .await
        .expect("transition barrier publication completes")
        .expect("join transition drive")
        .expect("drive transition through exact Relay COMMIT");
    assert!(matches!(
        readiness,
        TransitionReadiness::ControlPlaneReady { barrier_count: 2 }
    ));
    assert_eq!(barrier_publishes.len(), 2);

    let committed = store
        .load_active_key_transition()
        .await
        .expect("load full-link barrier-committed transition")
        .expect("full-link snapshot ACKs remain outstanding");
    assert_eq!(
        committed.transition.phase,
        KeyTransitionPhase::BarriersCommitted
    );
    let update = committed
        .updates
        .iter()
        .find(|update| update.recipient.device_route == *fixture.device_route.as_bytes())
        .cloned()
        .expect("full-link new device has a frozen KeyUpdate");
    let catalog_cut = committed
        .transition
        .cuts
        .iter()
        .find(|cut| cut.scope == KeyTransitionStreamScope::Catalog)
        .copied()
        .expect("full-link transition freezes Catalog cut");
    let conversation_cut = committed
        .transition
        .cuts
        .iter()
        .find(|cut| cut.scope == conversation_scope)
        .copied()
        .expect("full-link transition freezes conversation cut");
    let frozen_h = conversation_cut
        .relay_committed_inner
        .expect("conversation cut freezes exact H");

    store
        .acknowledge_key_update(AcknowledgeKeyUpdate {
            operation_id: committed.transition.operation_id,
            recipient: update.recipient,
            key_revision: update.key_revision,
            update_hash: canonical_update_hash(&update.canonical_update_set)
                .expect("hash full-link KeyUpdate"),
            canonical_ack: b"full-link-transition-key-update-ack".to_vec(),
            acknowledged_at_ms: committed.transition.state_changed_at_ms,
        })
        .await
        .expect("ack full-link KeyUpdate");

    let first_local = append_transition_configuration(
        &store,
        fixture.conversation_id,
        1,
        CodexReasoningEffort::High,
        "full-link-transition-local-h-plus-one",
    )
    .await;
    assert_eq!(first_local, frozen_h + 1);
    let (later_ready_snapshot, later_ready_payload) =
        persist_latest_conversation_snapshot(&store, fixture.conversation_id).await;
    assert_eq!(later_ready_snapshot.base, StreamCursor::At(first_local));

    let active = store
        .load_active_remote_ingress(machine_route, fixture.device_route)
        .await
        .expect("load full-link new-device authorization");
    let key_directory_revision = active.key_directory_revision().value();
    let command_key_epoch = active.command_key_epoch();
    let trust_domain = active.machine_trust_domain();
    let grant_serial = active.grant_serial();
    let trust_epoch = active.trust_epoch();
    let command_key = AeadSendingKey::with_derived_nonce_prefix(
        KeyId {
            purpose: KeyPurpose::DeviceCommandTx,
            epoch: command_key_epoch,
        },
        command_key_epoch,
        key_directory_revision,
        SecretAeadKey::from_bytes([0xdc; 32]),
    );
    let device_sign = SigningKey::from_seed(&[0xa4; 32]);
    let dispatcher = RemoteIngressDispatcher::new(machine_route, store.clone());
    let core = Arc::new(
        RuntimeCore::new(
            store.clone(),
            Arc::new(AgentRouter::with_runtime_store(store.clone())),
            trust_domain,
        )
        .expect("construct full-link transition Core"),
    );
    core.recover()
        .await
        .expect("recover Core before full-link transition ingress");
    let handler = Arc::new(StoreBackedKeyControlIngressHandler::new(store.clone()));
    let shared_guard = Arc::new(OwnedKeyStoreCounterGuardBackend::new(key_store.clone()));
    let shared_backend = Arc::new(
        RuntimeStoreSharedPublicationBackend::new(
            store.clone(),
            shared_guard.clone(),
            machine_route,
        )
        .expect("construct production shared publication backend"),
    );
    let production_publisher = SharedStreamPublisher::new(
        machine_route,
        shared_backend,
        Arc::new(publication_drive.clone()),
        Arc::new(machine_data.clone()),
    )
    .expect("construct production shared publisher");
    let sealer = Arc::new(ObservingTransitionSealer::new(
        DeviceReplyTxSealer::new(store.clone(), key_store, machine_data),
        harness.clone(),
    ));
    let publisher = Arc::new(ObservingSharedPublisher::new(production_publisher));
    let mut link = RemoteLinkOwner::start_with_ingress_mode_and_key_control_handler(
        machine_route,
        store.clone(),
        business,
        Arc::downgrade(&core),
        sealer.clone(),
        publisher.clone(),
        handler.clone(),
        RemoteLinkIngressMode::ControlPlaneOnly,
    )
    .expect("start full-link transition actor in control-plane-only mode");

    harness
        .push_frame(business_frame(signed_runtime_send(
            SignedRuntimeSendAxes {
                machine_route,
                device_route: fixture.device_route,
                request_route: RequestRouteId::from_bytes([0xd8; 16]),
                message_id: "full-link-transition-exact-subscribe",
                counter: 1,
            },
            RuntimeRequest::Subscribe {
                inner_cursor: RuntimeInnerCursor::Conversation {
                    conversation_id: conversation_id.clone(),
                    cursor: StreamCursor::BeforeFirst,
                },
            },
            &command_key,
            &device_sign,
        )))
        .await;
    sealer.wait_for_sync(conversation_scope).await;
    let attempts = sealer.attempts_for_scope(conversation_scope);
    assert!(
        attempts.iter().all(|attempt| attempt.accepted),
        "production transition sealer rejected required full-link egress: {attempts:?}"
    );
    assert_eq!(
        attempts.len(),
        3,
        "exact transition emits one receipt, snapshot, and SyncComplete"
    );
    let second_local = append_transition_configuration(
        &store,
        fixture.conversation_id,
        2,
        CodexReasoningEffort::Low,
        "full-link-transition-local-h-plus-two",
    )
    .await;
    assert_eq!(second_local, first_local + 1);
    let still_later_ready = store
        .load_conversation_snapshot_by_reference(later_ready_snapshot.clone())
        .await
        .expect("transition snapshot must not replace later durable D");
    assert_eq!(still_later_ready.payload, later_ready_payload);
    // Durable D 的逐字段读回已经完成；它携带全池 128 MiB read lease，不能让测试夹具
    // 把该诊断对象跨 ACK 持有并伪造 continuation page 的资源耗尽。
    drop(still_later_ready);
    let expected_generation = uuid::Uuid::from_bytes(conversation_cut.generation)
        .hyphenated()
        .to_string();
    match &attempts[0].reply {
        RuntimeReply::Subscription(SubscriptionReceipt::Subscribed { stream_generation }) => {
            assert_eq!(stream_generation.as_str(), expected_generation);
        }
        other => panic!("first exact transition reply must be Subscribed: {other:?}"),
    }
    match &attempts[1].reply {
        RuntimeReply::Snapshot(snapshot) => {
            assert_eq!(snapshot.conversation_id, conversation_id);
            assert_eq!(snapshot.base_event_cursor, StreamCursor::At(frozen_h));
        }
        other => panic!("second exact transition reply must be snapshot through H: {other:?}"),
    }
    match &attempts[2].reply {
        RuntimeReply::SyncComplete(sync) => {
            assert_eq!(sync.stream_generation.as_str(), expected_generation);
            assert_eq!(
                sync.stream_cursor,
                StreamCursor::from_high_water(conversation_cut.relay_committed_outer)
            );
            assert_eq!(
                sync.inner_cursor,
                RuntimeInnerCursor::Conversation {
                    conversation_id: conversation_id.clone(),
                    cursor: StreamCursor::At(frozen_h),
                }
            );
            assert_eq!(sync.key_directory_revision, update.key_revision);
        }
        other => {
            panic!("third exact transition reply must be SyncComplete(C/H/revision): {other:?}")
        }
    }

    let current_for_negative = store
        .recheck_active_remote_ingress(
            &store
                .load_active_remote_ingress(machine_route, fixture.device_route)
                .await
                .expect("reload authorization for negative transition snapshot egress"),
        )
        .await
        .expect("negative transition snapshot authorization remains current");
    let reply_authorization = current_for_negative.remote_reply_authorization();
    let conversation_permit = store
        .resolve_transition_snapshot_permit(TransitionSnapshotRequest::new(
            current_for_negative,
            conversation_scope,
            StreamCursor::BeforeFirst,
        ))
        .await
        .expect("resolve conversation permit for negative egress checks");
    let RuntimeReply::Snapshot(valid_snapshot) = attempts[1].reply.clone() else {
        unreachable!("second full-link transition reply was checked as a snapshot")
    };
    let mut wrong_conversation = valid_snapshot.clone();
    wrong_conversation.conversation_id = ConversationId::new(
        RuntimeId::from_bytes(RuntimeIdKind::Conversation, [0xee; 16])
            .expect("wrong transition snapshot conversation id")
            .to_canonical_string(),
    );
    let mut wrong_base = valid_snapshot;
    wrong_base.base_event_cursor = StreamCursor::At(
        frozen_h
            .checked_add(1)
            .expect("transition snapshot wrong base fits u64"),
    );
    for invalid_snapshot in [wrong_conversation, wrong_base] {
        let bytes: Arc<[u8]> = RuntimeEnvelope {
            version: RUNTIME_PROTOCOL_VERSION,
            message_id: MessageId::new("full-link-invalid-transition-snapshot"),
            body: RuntimeMessage::Reply(RuntimeReply::Snapshot(invalid_snapshot)),
        }
        .to_json_bytes_checked()
        .expect("encode invalid transition snapshot fixture")
        .into();
        assert!(matches!(
            sealer
                .inner
                .seal_transition_snapshot_exact(
                    &reply_authorization,
                    DirectedReplyRoute {
                        machine_route,
                        device_route: fixture.device_route,
                        request_route: RequestRouteId::from_bytes([0xec; 16]),
                    },
                    &conversation_permit,
                    bytes,
                )
                .await,
            Err(RemoteLinkError::InvalidCoreEgress)
        ));
    }

    assert_eq!(sealer.flush_count.load(Ordering::SeqCst), 0);
    assert!(
        publisher.started_items().is_empty(),
        "shared publisher must remain silent before exact ACK"
    );
    let exact_conversation_stream_ack = || {
        KeyControlRequestV1::stream_applied_ack(StreamAppliedAckV1 {
            format_version: E2EE_FORMAT_VERSION,
            runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
            relay_protocol_version: RELAY_PROTOCOL_VERSION,
            machine_route,
            device_route: fixture.device_route,
            grant_serial,
            root_trust_epoch: trust_epoch,
            stream_route: StreamRouteId::from_bytes(conversation_cut.stream_route),
            stream_generation: StreamGenerationId::from_bytes(conversation_cut.generation),
            applied_stream_seq: conversation_cut.barrier_sequence,
            inner_cursor: RuntimeInnerCursor::Conversation {
                conversation_id: conversation_id.clone(),
                cursor: StreamCursor::At(frozen_h),
            },
            key_directory_revision: KeyDirectoryRevision::new(update.key_revision),
            key_epoch: conversation_cut.new_epoch,
            epoch_barrier_sha256: conversation_cut.epoch_barrier_sha256,
        })
    };
    let premature = admitted_route(
        &dispatcher,
        signed_key_control_send(
            machine_route,
            fixture.device_route,
            RequestRouteId::from_bytes([0xd9; 16]),
            exact_conversation_stream_ack(),
            2,
            &command_key,
            &device_sign,
        ),
    )
    .await;
    let mut observed_mode = RemoteLinkIngressMode::ControlPlaneOnly;
    assert!(matches!(
        route_ingress_before_core_with_mode(
            premature,
            handler.as_ref(),
            &Arc::downgrade(&core),
            &mut observed_mode,
        )
        .await,
        Err(RemoteLinkError::KeyControl(
            KeyControlIngressError::StoreRejected
        ))
    ));
    assert_eq!(observed_mode, RemoteLinkIngressMode::ControlPlaneOnly);
    assert_eq!(sealer.flush_count.load(Ordering::SeqCst), 0);
    assert!(publisher.started_items().is_empty());

    // SyncComplete writer 仍被 test transport 持有；普通 business 排在 exact ACK 前，
    // 证明 snapshot capability 没有把 actor mode 提升成整条 business lane。
    harness
        .push_frame(business_frame(signed_runtime_send(
            SignedRuntimeSendAxes {
                machine_route,
                device_route: fixture.device_route,
                request_route: RequestRouteId::from_bytes([0xda; 16]),
                message_id: "full-link-transition-still-control-plane-only",
                counter: 3,
            },
            RuntimeRequest::DescribeAgents,
            &command_key,
            &device_sign,
        )))
        .await;
    harness.release_send_flush();
    sealer.wait_for_flush_count(1).await;
    assert!(
        publisher.started_items().is_empty(),
        "flush marker alone must not release shared catchup"
    );

    harness
        .push_frame(business_frame(signed_key_control_send(
            machine_route,
            fixture.device_route,
            RequestRouteId::from_bytes([0xdb; 16]),
            exact_conversation_stream_ack(),
            4,
            &command_key,
            &device_sign,
        )))
        .await;
    let pending_after_conversation =
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                let active = store
                    .load_active_key_transition()
                    .await
                    .expect("poll full-link transition after conversation ACK")
                    .expect("Catalog scope must keep transition active");
                let update = active
                    .updates
                    .iter()
                    .find(|candidate| candidate.recipient == update.recipient)
                    .expect("reload new-device update after conversation ACK");
                if update
                    .stream_applied_acks
                    .iter()
                    .any(|ack| ack.scope == conversation_scope)
                {
                    break active;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("conversation StreamApplied ACK becomes durable");
    assert!(
        pending_after_conversation
            .updates
            .iter()
            .flat_map(|candidate| candidate.stream_applied_acks.iter())
            .all(|ack| ack.scope != KeyTransitionStreamScope::Catalog)
    );
    assert!(
        publisher.started_items().is_empty(),
        "single-scope ACK must not release shared catchup"
    );
    assert_eq!(core.remote_registration_calls_for_test(), 1);
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while core.snapshot_sender_usage_for_test() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("Conversation transition snapshot releases its per-connection sender quota");
    let after_conversation_ack = admitted_route(
        &dispatcher,
        signed_runtime_send(
            SignedRuntimeSendAxes {
                machine_route,
                device_route: fixture.device_route,
                request_route: RequestRouteId::from_bytes([0xdc; 16]),
                message_id: "full-link-transition-catalog-still-fences-business",
                counter: 5,
            },
            RuntimeRequest::DescribeAgents,
            &command_key,
            &device_sign,
        ),
    )
    .await;
    let mut mode_after_conversation_ack = RemoteLinkIngressMode::ControlPlaneOnly;
    assert_transition_fenced_before_core(
        after_conversation_ack,
        handler.as_ref(),
        &core,
        &mut mode_after_conversation_ack,
    )
    .await;

    harness
        .push_frame(business_frame(signed_runtime_send(
            SignedRuntimeSendAxes {
                machine_route,
                device_route: fixture.device_route,
                request_route: RequestRouteId::from_bytes([0xdd; 16]),
                message_id: "full-link-transition-catalog-subscribe",
                counter: 6,
            },
            RuntimeRequest::Subscribe {
                inner_cursor: RuntimeInnerCursor::Catalog {
                    cursor: StreamCursor::BeforeFirst,
                },
            },
            &command_key,
            &device_sign,
        )))
        .await;
    sealer
        .wait_for_sync(KeyTransitionStreamScope::Catalog)
        .await;
    let catalog_attempts = sealer.attempts_for_scope(KeyTransitionStreamScope::Catalog);
    assert!(
        catalog_attempts.iter().all(|attempt| attempt.accepted),
        "production transition sealer rejected Catalog egress: {catalog_attempts:?}"
    );
    assert_eq!(
        catalog_attempts.len(),
        3,
        "Catalog transition emits one receipt, snapshot, and SyncComplete"
    );
    let expected_catalog_generation = uuid::Uuid::from_bytes(catalog_cut.generation)
        .hyphenated()
        .to_string();
    let catalog_h = StreamCursor::from_high_water(catalog_cut.relay_committed_inner);
    match &catalog_attempts[0].reply {
        RuntimeReply::Subscription(SubscriptionReceipt::Subscribed { stream_generation }) => {
            assert_eq!(stream_generation.as_str(), expected_catalog_generation);
        }
        other => panic!("first Catalog transition reply must be Subscribed: {other:?}"),
    }
    match &catalog_attempts[1].reply {
        RuntimeReply::Catalog(snapshot) => {
            assert_eq!(snapshot.base_catalog_cursor, catalog_h);
            assert!(snapshot.next_page_cursor().is_none());
        }
        other => panic!("second Catalog transition reply must be exact Catalog(H): {other:?}"),
    }
    match &catalog_attempts[2].reply {
        RuntimeReply::SyncComplete(sync) => {
            assert_eq!(sync.stream_generation.as_str(), expected_catalog_generation);
            assert_eq!(
                sync.stream_cursor,
                StreamCursor::from_high_water(catalog_cut.relay_committed_outer)
            );
            assert_eq!(
                sync.inner_cursor,
                RuntimeInnerCursor::Catalog { cursor: catalog_h }
            );
            assert_eq!(sync.key_directory_revision, update.key_revision);
        }
        other => panic!("third Catalog transition reply must be SyncComplete: {other:?}"),
    }
    assert_eq!(sealer.flush_count.load(Ordering::SeqCst), 1);
    assert!(publisher.started_items().is_empty());
    harness.release_send_flush();
    sealer.wait_for_flush_count(2).await;
    assert_eq!(
        sealer.flushed_scopes(),
        vec![conversation_scope, KeyTransitionStreamScope::Catalog]
    );
    assert!(
        store
            .load_active_key_transition()
            .await
            .expect("reload transition after both directed flushes")
            .is_some(),
        "flush markers alone must not release transition"
    );
    assert!(publisher.started_items().is_empty());

    let conversation_counter_scope = CounterScope::publication(
        trust_domain,
        KeyId {
            purpose: KeyPurpose::ConversationDek,
            epoch: conversation_cut.new_epoch,
        },
        conversation_cut.publication_stream_id,
    )
    .expect("derive conversation publication counter scope");
    let guard_before_catchup = shared_guard
        .load_guard(&conversation_counter_scope)
        .expect("load conversation CounterGuard baseline")
        .expect("EpochBarrier materialized conversation CounterGuard");
    assert_eq!(guard_before_catchup.phase(), CounterGuardPhase::Stable);
    let stream_before_catchup = store
        .load_publication_stream_record(conversation_cut.publication_stream_id)
        .await
        .expect("load conversation publication lineage before catchup");
    assert_eq!(
        stream_before_catchup.committed_high_water,
        Some(conversation_cut.barrier_sequence)
    );
    assert_eq!(
        stream_before_catchup.acknowledged_high_water,
        Some(conversation_cut.barrier_sequence)
    );
    assert_eq!(stream_before_catchup.committed_inner_cursor, Some(frozen_h));
    assert_eq!(
        stream_before_catchup.acknowledged_inner_cursor,
        Some(frozen_h)
    );
    assert_eq!(
        relay_publish_count(harness.as_ref()),
        barrier_publishes.len(),
        "only the two EpochBarriers may reach Relay before both scope ACKs"
    );
    assert!(
        store
            .load_pending_publications(conversation_cut.publication_stream_id)
            .await
            .expect("load pre-release conversation outbox")
            .is_empty()
    );

    let exact_catalog_stream_ack = || {
        KeyControlRequestV1::stream_applied_ack(StreamAppliedAckV1 {
            format_version: E2EE_FORMAT_VERSION,
            runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
            relay_protocol_version: RELAY_PROTOCOL_VERSION,
            machine_route,
            device_route: fixture.device_route,
            grant_serial,
            root_trust_epoch: trust_epoch,
            stream_route: StreamRouteId::from_bytes(catalog_cut.stream_route),
            stream_generation: StreamGenerationId::from_bytes(catalog_cut.generation),
            applied_stream_seq: catalog_cut.barrier_sequence,
            inner_cursor: RuntimeInnerCursor::Catalog { cursor: catalog_h },
            key_directory_revision: KeyDirectoryRevision::new(update.key_revision),
            key_epoch: catalog_cut.new_epoch,
            epoch_barrier_sha256: catalog_cut.epoch_barrier_sha256,
        })
    };
    harness
        .push_frame(business_frame(signed_key_control_send(
            machine_route,
            fixture.device_route,
            RequestRouteId::from_bytes([0xde; 16]),
            exact_catalog_stream_ack(),
            7,
            &command_key,
            &device_sign,
        )))
        .await;
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            if store
                .load_active_key_transition()
                .await
                .expect("poll full-link transition completion")
                .is_none()
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("final Catalog StreamApplied ACK completes transition");
    let first_publish = wait_for_next_relay_publish(harness.as_ref(), &mut sent_cursor).await;
    assert_eq!(publisher.started_items().len(), 1);
    assert!(
        publisher.completed_items().is_empty(),
        "Relay writer flush before RouteAccepted must not complete H+1"
    );
    assert_eq!(
        store
            .load_pending_publication_streams()
            .await
            .expect("enumerate frozen H+1 streams"),
        vec![conversation_cut.publication_stream_id]
    );
    let first_sender_counter = {
        let pending = store
            .load_pending_publications(conversation_cut.publication_stream_id)
            .await
            .expect("load frozen H+1 publication");
        assert_eq!(pending.len(), 1);
        let frozen = &pending[0];
        assert_eq!(frozen.payload_kind, PublicationPayloadKind::Event);
        assert_eq!(frozen.inner_after, Some(frozen_h));
        assert_eq!(frozen.inner_through, Some(first_local));
        assert_eq!(frozen.stream_route, *first_publish.stream_route.as_bytes());
        assert_eq!(frozen.generation, *first_publish.generation.as_bytes());
        assert_eq!(frozen.stream_seq, first_publish.stream_seq);
        assert_eq!(
            frozen.blob.as_slice(),
            first_publish.sealed_blob.0.as_slice()
        );
        assert_eq!(frozen.blob_sha256, sha256(frozen.blob.as_slice()));
        let signed = SignedSealedBlobV1::from_wire_bytes(&frozen.blob)
            .expect("decode exact frozen H+1 MachineData blob");
        let nonce_counter = u64::from_be_bytes(
            signed.inner.nonce[4..]
                .try_into()
                .expect("MachineData nonce has a fixed sender-counter suffix"),
        );
        assert_eq!(nonce_counter, frozen.sender_counter);
        frozen.sender_counter
    };
    let stream_before_first_accept = store
        .load_publication_stream_record(conversation_cut.publication_stream_id)
        .await
        .expect("load stream before first RouteAccepted");
    assert_eq!(
        stream_before_first_accept.committed_high_water,
        Some(conversation_cut.barrier_sequence)
    );
    assert_eq!(
        stream_before_first_accept.acknowledged_high_water,
        Some(conversation_cut.barrier_sequence)
    );
    assert_eq!(
        stream_before_first_accept.acknowledged_inner_cursor,
        Some(frozen_h)
    );
    accept_relay_publish(harness.as_ref(), &first_publish).await;

    let second_publish = wait_for_next_relay_publish(harness.as_ref(), &mut sent_cursor).await;
    assert_eq!(
        publisher.completed_items().len(),
        1,
        "H+2 may start only after H+1 Relay COMMIT and exact local ACK"
    );
    assert_eq!(
        store
            .load_pending_publication_streams()
            .await
            .expect("enumerate frozen H+2 streams"),
        vec![conversation_cut.publication_stream_id]
    );
    let second_sender_counter = {
        let pending = store
            .load_pending_publications(conversation_cut.publication_stream_id)
            .await
            .expect("load frozen H+2 publication");
        assert_eq!(pending.len(), 1);
        let frozen = &pending[0];
        assert_eq!(frozen.payload_kind, PublicationPayloadKind::Event);
        assert_eq!(frozen.inner_after, Some(first_local));
        assert_eq!(frozen.inner_through, Some(second_local));
        assert_eq!(frozen.stream_route, *second_publish.stream_route.as_bytes());
        assert_eq!(frozen.generation, *second_publish.generation.as_bytes());
        assert_eq!(frozen.stream_seq, first_publish.stream_seq + 1);
        assert_eq!(frozen.stream_seq, second_publish.stream_seq);
        assert_eq!(
            frozen.blob.as_slice(),
            second_publish.sealed_blob.0.as_slice()
        );
        assert_eq!(frozen.blob_sha256, sha256(frozen.blob.as_slice()));
        let signed = SignedSealedBlobV1::from_wire_bytes(&frozen.blob)
            .expect("decode exact frozen H+2 MachineData blob");
        let nonce_counter = u64::from_be_bytes(
            signed.inner.nonce[4..]
                .try_into()
                .expect("MachineData nonce has a fixed sender-counter suffix"),
        );
        assert_eq!(nonce_counter, frozen.sender_counter);
        frozen.sender_counter
    };
    assert_eq!(
        second_sender_counter,
        first_sender_counter
            .checked_add(COUNTER_BLOCK_SIZE)
            .expect("H+1 sender counter leaves room for H+2"),
        "each crash-safe publication must consume one disjoint counter block"
    );
    let stream_before_second_accept = store
        .load_publication_stream_record(conversation_cut.publication_stream_id)
        .await
        .expect("load stream after first exact local ACK");
    assert_eq!(
        stream_before_second_accept.committed_high_water,
        Some(first_publish.stream_seq)
    );
    assert_eq!(
        stream_before_second_accept.acknowledged_high_water,
        Some(first_publish.stream_seq)
    );
    assert_eq!(
        stream_before_second_accept.committed_inner_cursor,
        Some(first_local)
    );
    assert_eq!(
        stream_before_second_accept.acknowledged_inner_cursor,
        Some(first_local)
    );
    accept_relay_publish(harness.as_ref(), &second_publish).await;
    publisher.wait_for_completed_count(2).await;

    assert!(
        store
            .load_pending_publications(conversation_cut.publication_stream_id)
            .await
            .expect("load completed conversation outbox")
            .is_empty(),
        "exact local ACK must delete both frozen catchup rows"
    );
    assert!(
        store
            .load_pending_publication_streams()
            .await
            .expect("enumerate final publication outbox")
            .is_empty(),
        "no sibling stream may retain an unacknowledged frozen row"
    );
    let final_stream = store
        .load_publication_stream_record(conversation_cut.publication_stream_id)
        .await
        .expect("load final acknowledged conversation stream");
    assert_eq!(
        final_stream.committed_high_water,
        Some(second_publish.stream_seq)
    );
    assert_eq!(
        final_stream.acknowledged_high_water,
        Some(second_publish.stream_seq)
    );
    assert_eq!(final_stream.committed_inner_cursor, Some(second_local));
    assert_eq!(final_stream.acknowledged_inner_cursor, Some(second_local));
    assert_eq!(
        final_stream.sender_counter_high_water,
        Some(second_sender_counter),
        "authenticated stream sender lineage must end at exact H+2 counter"
    );
    let final_guard = shared_guard
        .load_guard(&conversation_counter_scope)
        .expect("load final conversation CounterGuard")
        .expect("final conversation CounterGuard remains present");
    assert_eq!(final_guard.phase(), CounterGuardPhase::Stable);
    assert!(second_sender_counter < final_guard.reserved_through());
    let final_counter_record = store
        .load_remote_counter_record(
            conversation_counter_scope.token(),
            KeyId {
                purpose: KeyPurpose::ConversationDek,
                epoch: conversation_cut.new_epoch,
            },
        )
        .await
        .expect("load final conversation counter row");
    assert_eq!(
        final_counter_record.reserved_end,
        final_guard.reserved_through()
    );
    assert_eq!(
        final_counter_record.db_anchor,
        final_guard.database_anchor()
    );

    let catchup = publisher.completed_items();
    let event_sequences: Vec<u64> = catchup
        .iter()
        .map(|item| match item {
            RuntimeStreamItem::Event(event) => event.event_seq,
            other => panic!("conversation catchup must contain only events: {other:?}"),
        })
        .collect();
    assert_eq!(event_sequences, vec![first_local, second_local]);
    assert_eq!(
        event_sequences[0],
        frozen_h + 1,
        "first shared event must not skip H+1"
    );
    assert_eq!(core.remote_registration_calls_for_test(), 2);

    link.shutdown()
        .await
        .expect("shutdown full-link transition actor");
    transition
        .shutdown()
        .await
        .expect("shutdown full-link transition owner");
    publication
        .shutdown()
        .await
        .expect("shutdown full-link publication owner");
    transport.shutdown().await;
    core.shutdown()
        .await
        .expect("shutdown full-link transition Core");
}
