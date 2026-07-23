use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Weak};
use std::{fs, path::PathBuf};

use agentdeck_crypto::{
    AeadReceivingKey, SigningKey, open_sealed_payload, sha256, sign_sealed, sign_tbs, verify_sealed,
};
use agentdeck_protocol::e2ee::{
    AuthorizationCapabilityV1, AuthorizationPermissionV1, DirectoryCurrentV1, E2EE_FORMAT_VERSION,
    KeyControlV1, KeyId, KeyPurpose, KeyUpdateSetV1, KeyUpdateV1, OuterContextV1, OuterFrameKind,
    SealedPayloadKind, SignedSealedBlobV1, UnsignedSealedBlobV1,
};
use agentdeck_protocol::relay_v2::{
    DeviceRevocation, DeviceRouteId, Ed25519Signature, GrantSerial, KeyDirectoryRevision,
    MachineRouteId, RELAY_PROTOCOL_VERSION, RequestRouteId,
};
use agentdeck_protocol::runtime::identity::{
    ConversationId, DeviceHandle, GrantSerial as RuntimeGrantSerial, MessageId, StreamGeneration,
    TransferId,
};
use agentdeck_protocol::runtime::{
    CatalogSnapshot, ConversationStartReceipt, RUNTIME_PROTOCOL_VERSION, RuntimeEnvelope,
    RuntimeFailure, RuntimeInnerCursor, RuntimeMessage, RuntimeReply, RuntimeSyncComplete,
    RuntimeTransferCarrierV1, RuntimeTransferChannel, StreamCursor, SubscriptionReceipt,
    TransferEnvelope,
};
use rusqlite::{Connection, OpenFlags};

use crate::remote::counter::{
    COUNTER_BLOCK_SIZE, CounterGuardBackend, CounterGuardCas, CounterGuardState, CounterScope,
};
use crate::remote::identity::KeyStoreCounterGuardBackend;
use crate::remote::link::{
    DirectedReplyRoute, DirectedReplySealer, RemoteLinkError, RemoteReplyPump, ReplyRouteLifecycle,
};
use crate::runtime::backfill::BarrierRequest;
use crate::runtime::events::{RegisterStreamBarrier, RuntimeStreamTarget, WatchGeneration};
use crate::runtime::store::key_transition::{
    AcknowledgeKeyUpdate, AcknowledgeStreamApplied, FrozenKeyUpdate, KeyTransitionStreamCut,
    KeyTransitionStreamScope, TransitionSnapshotRequest, canonical_update_hash,
};
use crate::runtime::store::pairing_grant::GlobalKeyStateV1;
use crate::runtime::store::remote_counter::RemoteCounterRecordKind;
use crate::runtime::store::{
    ActiveSenderCounterBinding, BeginDeviceRevocation, BeginDeviceRevocationOutcome,
    FreezePublicationRequest, MachineEnrollmentState, NewConversation, PublicationPayloadKind,
    PublicationScope, RemoteReplyAuthorization, RevocationTargetStatus, RuntimeId, RuntimeIdKind,
    RuntimeStoreConfig, RuntimeStoreError, RuntimeStoreHandle,
    active_authorization_store_with_pending_transition_for_test,
    active_authorization_store_with_permissions_for_test,
};
use crate::runtime::{ConnectionId, ConnectionWrite};
use crate::security::{MemoryKeyStore, load_or_create_storage_kek};

use super::directed_reply::{DeviceReplyTxSealer, DirectedDataAuthority, directed_payload_kind};
use super::transport::active_pairing_transport_for_test;

const MACHINE: MachineRouteId = MachineRouteId::from_bytes([0x32; 16]);
const DEVICE: DeviceRouteId = DeviceRouteId::from_bytes([0xd1; 16]);
const REQUEST: RequestRouteId = RequestRouteId::from_bytes([0xe1; 16]);

struct TestRoot(PathBuf);

impl TestRoot {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "agentdeck-directed-reply-{label}-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        fs::create_dir(&path).expect("create directed reply test root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("secure directed reply test root");
        }
        Self(path)
    }

    fn database(&self) -> PathBuf {
        self.0.join("runtime.db")
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct TestAuthorityOwner {
    signing: SigningKey,
    calls: AtomicUsize,
    fail: AtomicBool,
}

struct WeakTestAuthority(Weak<TestAuthorityOwner>);

impl DirectedDataAuthority for WeakTestAuthority {
    fn sign_sealed(
        &self,
        unsigned: UnsignedSealedBlobV1,
        context: &OuterContextV1,
    ) -> Result<SignedSealedBlobV1, ()> {
        let owner = self.0.upgrade().ok_or(())?;
        owner.calls.fetch_add(1, Ordering::SeqCst);
        if owner.fail.swap(false, Ordering::SeqCst) {
            return Err(());
        }
        Ok(sign_sealed(unsigned, &owner.signing, context))
    }
}

fn authority(fail_once: bool) -> (Arc<TestAuthorityOwner>, Arc<dyn DirectedDataAuthority>) {
    let owner = Arc::new(TestAuthorityOwner {
        signing: SigningKey::from_seed(&[0x73; 32]),
        calls: AtomicUsize::new(0),
        fail: AtomicBool::new(fail_once),
    });
    let authority: Arc<dyn DirectedDataAuthority> =
        Arc::new(WeakTestAuthority(Arc::downgrade(&owner)));
    (owner, authority)
}

fn runtime_bytes(body: RuntimeMessage) -> Arc<[u8]> {
    RuntimeEnvelope {
        version: RUNTIME_PROTOCOL_VERSION,
        message_id: MessageId::new("directed-reply-test"),
        body,
    }
    .to_json_bytes_checked()
    .expect("valid Runtime fixture")
    .into()
}

fn failure_reply() -> Arc<[u8]> {
    runtime_bytes(RuntimeMessage::Reply(RuntimeReply::Failure(
        RuntimeFailure::new("test.directed", "directed reply"),
    )))
}

fn key_update_set(revision: u64) -> KeyUpdateSetV1 {
    let revision = KeyDirectoryRevision::new(revision);
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
            enc: vec![0x61; 32],
            wrapped_key: vec![0x62; 48],
            signature: Ed25519Signature([0x63; 64]),
        }],
    }
}

async fn active_store(
    database: &std::path::Path,
    storage_keys: &MemoryKeyStore,
) -> RuntimeStoreHandle {
    let storage_kek =
        load_or_create_storage_kek(storage_keys, database).expect("load directed StorageKEK");
    active_authorization_store_with_permissions_for_test(
        database,
        storage_kek,
        vec![AuthorizationCapabilityV1::Catalog],
        vec![AuthorizationPermissionV1::CatalogRead],
    )
    .await
}

async fn authorization(store: &RuntimeStoreHandle) -> RemoteReplyAuthorization {
    let proof = store
        .load_active_remote_ingress(MACHINE, DEVICE)
        .await
        .expect("load exact active ingress");
    store
        .recheck_active_remote_ingress(&proof)
        .await
        .expect("recheck exact active ingress")
        .remote_reply_authorization()
}

async fn stage_conversation_activation_for_reply_test(
    store: &RuntimeStoreHandle,
) -> (RuntimeId, [u8; 16]) {
    let conversation_id =
        RuntimeId::from_bytes(RuntimeIdKind::Conversation, [0x91; 16]).expect("conversation id");
    store
        .create_conversation(NewConversation {
            conversation_id,
            adapter_state_key: RuntimeId::from_bytes(RuntimeIdKind::AdapterState, [0x92; 16])
                .expect("adapter state key"),
            descriptor: crate::runtime::model::ConversationDescriptor {
                agent_kind: agentdeck_protocol::AgentKind::Codex,
                title: Some("remote start reply upgrade".to_owned()),
                cwd: PathBuf::from("/tmp/agentdeck-remote-start-reply"),
            },
        })
        .await
        .expect("create conversation and stage activation");
    let transition = store
        .load_active_key_transition()
        .await
        .expect("load conversation activation")
        .expect("conversation activation transition exists");
    assert_eq!(
        transition.transition.operation,
        crate::runtime::store::key_transition::KeyTransitionOperation::ActivateConversation
    );
    (conversation_id, transition.transition.operation_id)
}

async fn commit_conversation_activation_for_reply_test(
    store: &RuntimeStoreHandle,
) -> (RuntimeId, RemoteReplyAuthorization) {
    let (conversation_id, _) = stage_conversation_activation_for_reply_test(store).await;
    crate::runtime::store::complete_active_zero_cut_transition(store).await;
    (conversation_id, authorization(store).await)
}

#[tokio::test]
async fn startup_sender_inventory_covers_active_shared_and_directed_reply_scopes() {
    let root = TestRoot::new("startup-sender-inventory");
    let keys = MemoryKeyStore::new();
    let store = active_store(&root.database(), &keys).await;
    let publication_stream_id = [0x21; 16];
    store
        .create_publication_stream(
            publication_stream_id,
            crate::runtime::store::PublicationScope::Catalog,
            [0x22; 16],
            [0x23; 16],
        )
        .await
        .expect("create active catalog publication stream");

    let bindings = store
        .load_active_sender_counter_bindings()
        .await
        .expect("load authenticated active sender inventory");
    assert_eq!(bindings.len(), 2);
    assert!(bindings.iter().any(|binding| matches!(
        binding,
        ActiveSenderCounterBinding::SharedPublication {
            publication_stream_id: observed,
            key_id: KeyId {
                purpose: KeyPurpose::Catalog,
                epoch: 1,
            },
        } if *observed == publication_stream_id
    )));
    assert!(bindings.iter().any(|binding| matches!(
        binding,
        ActiveSenderCounterBinding::DirectedReply { authorization }
            if authorization.machine_route() == MACHINE
                && authorization.device_route() == DEVICE
                && authorization.reply_key_epoch() == 1
    )));

    store
        .shutdown()
        .await
        .expect("shutdown sender inventory Store");
}

fn route() -> DirectedReplyRoute {
    DirectedReplyRoute {
        machine_route: MACHINE,
        device_route: DEVICE,
        request_route: REQUEST,
    }
}

fn device_handle() -> DeviceHandle {
    DeviceHandle::new(format!(
        "device-{}",
        DEVICE
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    ))
}

async fn begin_local_revocation(store: &RuntimeStoreHandle) {
    let target = match store
        .load_revocation_target(&device_handle(), RuntimeGrantSerial::new(1))
        .await
        .expect("load revocation target")
        .expect("active target exists")
    {
        RevocationTargetStatus::Ready { target } => target,
        other => panic!("active target must be ready: {other:?}"),
    };
    let Some(MachineEnrollmentState::Active(active)) = store
        .load_machine_enrollment_state()
        .await
        .expect("load active enrollment")
    else {
        panic!("directed fixture must keep enrollment active")
    };
    let grant = target.grant();
    let mut revocation = DeviceRevocation {
        machine_route: grant.machine_route,
        device_route: grant.device_route,
        grant_serial: GrantSerial::new(1),
        root_key_id: grant.root_key_id,
        trust_epoch: grant.trust_epoch,
        signature: Ed25519Signature([0; 64]),
    };
    revocation.signature = sign_tbs(
        &SigningKey::from_seed(&[0x41; 32]),
        &revocation.to_be_signed_v1(
            active.connection.relay_server_id,
            active.binding.root_fingerprint,
        ),
    )
    .into();
    assert!(matches!(
        store
            .begin_device_revocation(BeginDeviceRevocation::local(revocation))
            .await
            .expect("begin local revocation"),
        BeginDeviceRevocationOutcome::Prepared { .. }
    ));
}

fn context(authorization: &RemoteReplyAuthorization) -> OuterContextV1 {
    OuterContextV1 {
        frame_kind: OuterFrameKind::DirectedReply,
        relay_protocol_version: RELAY_PROTOCOL_VERSION,
        e2ee_format_version: agentdeck_protocol::e2ee::E2EE_FORMAT_VERSION,
        machine_route: Some(MACHINE),
        device_route: Some(DEVICE),
        stream_route: None,
        request_route: Some(REQUEST),
        pair_route: None,
        stream_generation: None,
        stream_cursor: None,
        stream_seq: None,
        message_key_epoch: authorization.reply_key_epoch(),
    }
}

fn reply_key(global: &GlobalKeyStateV1) -> AeadReceivingKey {
    let view = global
        .device_transport_key(DEVICE, KeyPurpose::DeviceReplyTx)
        .expect("active directed reply key");
    AeadReceivingKey::new(
        KeyId {
            purpose: KeyPurpose::DeviceReplyTx,
            epoch: view.epoch,
        },
        view.epoch,
        view.key,
    )
}

#[test]
fn generic_runtime_reply_uses_command_receipt_carrier_and_non_reply_is_rejected() {
    let reply = failure_reply();
    assert!(matches!(
        directed_payload_kind(&reply),
        Ok(SealedPayloadKind::CommandReceipt)
    ));
    assert!(directed_payload_kind(b"not-json").is_err());
}

#[tokio::test]
async fn exact_active_reply_is_aead_sealed_machine_data_signed_and_never_enters_shared_outbox() {
    let root = TestRoot::new("directed-happy");
    let database = root.database();
    let storage_keys = MemoryKeyStore::new();
    let counter_keys = Arc::new(MemoryKeyStore::new());
    let store = active_store(&database, &storage_keys).await;
    let authorization = authorization(&store).await;
    let receiving = reply_key(
        &store
            .load_global_key_state()
            .await
            .expect("load global keys")
            .expect("global keys exist"),
    );
    let (owner, authority) = authority(false);
    let sealer =
        DeviceReplyTxSealer::with_authority_for_test(store.clone(), counter_keys, authority);
    let plaintext = failure_reply();
    let reply = sealer
        .seal_exact(&authorization, route(), plaintext.clone())
        .await
        .expect("seal directed reply");
    let scope = CounterScope::directed_reply_for_trust_epoch(
        authorization.machine_trust_domain(),
        authorization.machine_route(),
        authorization.trust_epoch(),
        authorization.device_route(),
        authorization.grant_serial(),
        authorization.reply_key_epoch(),
    )
    .expect("directed reply scope");
    assert_eq!(
        store
            .load_remote_counter_guard_cleanup_manifest()
            .await
            .expect("load directed reply guard manifest"),
        vec![(scope.token(), true)]
    );
    assert_eq!(reply.authorization_used, authorization);
    let sealed = reply.sealed;
    assert_eq!(owner.calls.load(Ordering::SeqCst), 1);
    assert_eq!(sealed.inner.key_id.purpose, KeyPurpose::DeviceReplyTx);
    assert_eq!(sealed.inner.key_epoch, authorization.reply_key_epoch());
    let verified = verify_sealed(
        sealed,
        &owner.signing.verifying_key(),
        &context(&authorization),
    )
    .expect("verify MachineData signature");
    let opened = open_sealed_payload(&receiving, &context(&authorization), verified)
        .expect("open directed reply");
    assert_eq!(opened.payload_kind, SealedPayloadKind::CommandReceipt);
    assert_eq!(opened.payload, plaintext.as_ref());

    let count: i64 = Connection::open_with_flags(&database, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .expect("open read-only Store")
        .query_row("SELECT COUNT(*) FROM publication_outbox", [], |row| {
            row.get(0)
        })
        .expect("count shared outbox");
    assert_eq!(count, 0, "directed reply must never enter shared outbox");
}

#[tokio::test]
async fn stream_binding_uses_barrier_publication_axes_and_rejects_post_barrier_advance() {
    let root = TestRoot::new("stream-binding-exact-cut");
    let database = root.database();
    let storage_keys = MemoryKeyStore::new();
    let counter_keys = Arc::new(MemoryKeyStore::new());
    let store = active_store(&database, &storage_keys).await;
    let publication_stream_id = [0x71; 16];
    let stream_route = [0x72; 16];
    let generation = [0x73; 16];
    let counter_scope_token = [0x74; 32];
    store
        .create_publication_stream(
            publication_stream_id,
            PublicationScope::Catalog,
            stream_route,
            generation,
        )
        .await
        .expect("create catalog publication stream");
    let first = store
        .freeze_publication(FreezePublicationRequest {
            publication_id: [0x75; 16],
            publication_stream_id,
            generation,
            counter_scope_token,
            sender_counter: 0,
            inner_after: None,
            inner_through: None,
            payload_kind: PublicationPayloadKind::Control,
            blob: b"first committed publication cut".to_vec(),
        })
        .await
        .expect("freeze first publication");
    store
        .acknowledge_publication_commit(
            publication_stream_id,
            generation,
            first.stream_seq,
            first.blob_sha256,
        )
        .await
        .expect("commit first publication");

    let registration = store
        .register_stream_barrier(RegisterStreamBarrier {
            target: RuntimeStreamTarget::Catalog,
            generation: WatchGeneration::new(91).expect("local watch generation"),
            request: BarrierRequest::Subscribe {
                cursor: StreamCursor::BeforeFirst,
            },
        })
        .await
        .expect("capture authenticated publication cut");
    let permit = registration
        .relay_committed
        .stream_binding
        .expect("remote key directory issues binding permit");
    assert_eq!(permit.generation(), generation);
    assert_eq!(permit.outer(), StreamCursor::At(0));
    assert_eq!(permit.inner(), StreamCursor::BeforeFirst);
    drop(registration);

    let authorization = authorization(&store).await;
    let receiving = reply_key(
        &store
            .load_global_key_state()
            .await
            .expect("load global keys")
            .expect("global keys exist"),
    );
    let (owner, authority) = authority(false);
    let sealer =
        DeviceReplyTxSealer::with_authority_for_test(store.clone(), counter_keys, authority);
    let sealed = sealer
        .seal_stream_binding_exact(&authorization, route(), permit)
        .await
        .expect("seal Store-issued binding");
    let verified = verify_sealed(
        sealed,
        &owner.signing.verifying_key(),
        &context(&authorization),
    )
    .expect("verify binding MachineData signature");
    let opened = open_sealed_payload(&receiving, &context(&authorization), verified)
        .expect("open binding DeviceReplyTx payload");
    assert_eq!(opened.payload_kind, SealedPayloadKind::KeyUpdate);
    let KeyControlV1::StreamBinding { binding, .. } =
        KeyControlV1::from_canonical_bytes(&opened.payload).expect("decode stream binding")
    else {
        panic!("expected StreamBinding key-control carrier")
    };
    assert_eq!(binding.stream_route.as_bytes(), &stream_route);
    assert_eq!(binding.stream_generation.as_bytes(), &generation);
    assert_eq!(binding.stream_cursor, StreamCursor::At(0));
    assert_eq!(
        binding.inner_cursor,
        RuntimeInnerCursor::Catalog {
            cursor: StreamCursor::BeforeFirst,
        }
    );
    assert_eq!(binding.key_id.purpose, KeyPurpose::Catalog);
    assert_eq!(
        binding.key_directory_revision,
        authorization.key_directory_revision()
    );

    let advanced = store
        .freeze_publication(FreezePublicationRequest {
            publication_id: [0x76; 16],
            publication_stream_id,
            generation,
            counter_scope_token,
            sender_counter: 1,
            inner_after: None,
            inner_through: None,
            payload_kind: PublicationPayloadKind::Control,
            blob: b"advanced publication cut".to_vec(),
        })
        .await
        .expect("freeze advanced publication");
    store
        .acknowledge_publication_commit(
            publication_stream_id,
            generation,
            advanced.stream_seq,
            advanced.blob_sha256,
        )
        .await
        .expect("commit advanced publication");
    assert!(matches!(
        sealer
            .seal_stream_binding_exact(&authorization, route(), permit)
            .await,
        Err(RemoteLinkError::ReplySealUnavailable)
    ));
    assert_eq!(
        owner.calls.load(Ordering::SeqCst),
        1,
        "post-barrier publication advance must reject before a second signature"
    );
    store.shutdown().await.expect("shutdown binding Store");
}

#[tokio::test]
async fn conversation_stream_binding_selects_exact_conversation_dek_identity() {
    let root = TestRoot::new("conversation-stream-binding-key");
    let storage_keys = MemoryKeyStore::new();
    let store = active_store(&root.database(), &storage_keys).await;
    let (conversation_id, authorization) =
        commit_conversation_activation_for_reply_test(&store).await;
    let registration = store
        .register_stream_barrier(RegisterStreamBarrier {
            target: RuntimeStreamTarget::Conversation(conversation_id),
            generation: WatchGeneration::new(92).expect("conversation watch generation"),
            request: BarrierRequest::Subscribe {
                cursor: StreamCursor::BeforeFirst,
            },
        })
        .await
        .expect("capture conversation publication cut");
    let permit = registration
        .relay_committed
        .stream_binding
        .expect("conversation binding permit");
    let binding = permit.to_protocol(
        authorization.machine_route(),
        authorization.device_route(),
        authorization.grant_serial(),
        authorization.trust_epoch(),
    );
    assert_eq!(binding.key_id.purpose, KeyPurpose::ConversationDek);
    assert_eq!(binding.key_id.epoch, 1);
    assert_eq!(
        binding.key_directory_revision,
        authorization.key_directory_revision()
    );
    assert!(matches!(
        binding.inner_cursor,
        RuntimeInnerCursor::Conversation {
            conversation_id: observed,
            cursor: StreamCursor::BeforeFirst,
        } if observed.as_str() == conversation_id.to_canonical_string()
    ));
    drop(registration);
    store
        .shutdown()
        .await
        .expect("shutdown conversation binding Store");
}

#[tokio::test]
async fn conversation_start_reply_uses_exact_next_authorization_after_business_ready() {
    let root = TestRoot::new("conversation-start-reply-upgrade");
    let database = root.database();
    let storage_keys = MemoryKeyStore::new();
    let counter_keys = Arc::new(MemoryKeyStore::new());
    let store = active_store(&database, &storage_keys).await;
    let before = authorization(&store).await;
    let (conversation_id, current) = commit_conversation_activation_for_reply_test(&store).await;
    assert_eq!(
        current.key_directory_revision().value(),
        before.key_directory_revision().value() + 1
    );
    assert_eq!(current.reply_key_epoch(), before.reply_key_epoch());
    assert_eq!(current.authorization_hash(), before.authorization_hash());
    assert_eq!(current.grant_serial(), before.grant_serial());
    assert_eq!(current.trust_epoch(), before.trust_epoch());

    let receiving = reply_key(
        &store
            .load_global_key_state()
            .await
            .expect("load post-activation global keys")
            .expect("post-activation global keys exist"),
    );
    let (owner, authority) = authority(false);
    let sealer = Arc::new(DeviceReplyTxSealer::with_authority_for_test(
        store.clone(),
        counter_keys,
        authority,
    ));
    let (mut transport, _pairing_lane, harness) = active_pairing_transport_for_test(MACHINE);
    let business = transport
        .take_business_lane()
        .expect("take conversation Start reply lane");
    let mut pump = RemoteReplyPump::new(business, sealer);
    let connection_id = ConnectionId::from_test_bytes([0x93; 16]);
    let message_id = MessageId::new("conversation-start-reply-upgrade");
    pump.bind(
        connection_id,
        message_id.clone(),
        route(),
        before,
        ReplyRouteLifecycle::OneShot,
    )
    .expect("bind pre-Core reply authorization");
    let bytes: Arc<[u8]> = RuntimeEnvelope {
        version: RUNTIME_PROTOCOL_VERSION,
        message_id,
        body: RuntimeMessage::Reply(RuntimeReply::ConversationStart(ConversationStartReceipt {
            conversation_id: ConversationId::new(conversation_id.to_canonical_string()),
            replayed: false,
        })),
    }
    .to_json_bytes_checked()
    .expect("encode ConversationStart receipt")
    .into();
    let (write, acknowledged) = ConnectionWrite::for_transport_test(bytes.clone());
    pump.forward(connection_id, write)
        .await
        .expect("seal Start receipt with exact post-activation authorization");
    acknowledged
        .await
        .expect("ACK Start receipt only after Relay flush");
    assert_eq!(harness.sent_count(), 1);
    let sent = harness.sent_frames();
    let agentdeck_protocol::relay_v2::frame::RelayFrameBody::Reply(reply) = &sent[0].body else {
        panic!("ConversationStart must use directed Relay Reply")
    };
    let sealed = SignedSealedBlobV1::from_wire_bytes(&reply.sealed_blob.0)
        .expect("decode upgraded Start reply");
    assert_eq!(
        sealed.inner.key_directory_revision,
        current.key_directory_revision().value()
    );
    let verified = verify_sealed(sealed, &owner.signing.verifying_key(), &context(&current))
        .expect("verify upgraded Start reply signature");
    let opened = open_sealed_payload(&receiving, &context(&current), verified)
        .expect("open upgraded Start reply");
    assert_eq!(opened.payload_kind, SealedPayloadKind::CommandReceipt);
    assert_eq!(opened.payload, bytes.as_ref());

    transport.shutdown().await;
    store.shutdown().await.expect("shutdown Start reply Store");
}

#[tokio::test]
async fn compact_and_sync_replies_refresh_to_the_business_ready_authorization() {
    let root = TestRoot::new("long-lived-reply-upgrade");
    let database = root.database();
    let storage_keys = MemoryKeyStore::new();
    let store = active_store(&database, &storage_keys).await;
    let frozen = authorization(&store).await;
    let (_, current) = commit_conversation_activation_for_reply_test(&store).await;
    let receiving = reply_key(
        &store
            .load_global_key_state()
            .await
            .expect("load upgraded global keys")
            .expect("upgraded global keys exist"),
    );
    let (owner, authority) = authority(false);
    let sealer = DeviceReplyTxSealer::with_authority_for_test(
        store.clone(),
        Arc::new(MemoryKeyStore::new()),
        authority,
    );

    let transfer = TransferEnvelope::new_json(
        TransferId::new("upgraded-compact-transfer"),
        0,
        1,
        sha256(&[0x71, 0x72, 0x73]),
        3,
        vec![0x71, 0x72, 0x73],
    )
    .expect("valid upgraded compact transfer");
    let carrier = RuntimeTransferCarrierV1::new(
        MessageId::new("upgraded-compact-transfer"),
        RuntimeTransferChannel::Reply,
        transfer,
    );
    let expected_compact = carrier.encode().expect("encode upgraded compact carrier");
    let compact = sealer
        .seal_transfer_exact(&frozen, route(), carrier)
        .await
        .expect("seal compact reply with refreshed authorization");
    assert_eq!(compact.authorization_used, current);
    let verified = verify_sealed(
        compact.sealed,
        &owner.signing.verifying_key(),
        &context(&current),
    )
    .expect("verify upgraded compact reply");
    let opened = open_sealed_payload(&receiving, &context(&current), verified)
        .expect("open upgraded compact reply");
    assert_eq!(opened.payload_kind, SealedPayloadKind::TransferPart);
    assert_eq!(opened.payload, expected_compact);

    let sync = RuntimeSyncComplete {
        stream_generation: StreamGeneration::new("upgraded-sync-generation"),
        stream_cursor: StreamCursor::BeforeFirst,
        inner_cursor: RuntimeInnerCursor::Conversation {
            conversation_id: ConversationId::new("11111111-2222-4333-8444-666666666666"),
            cursor: StreamCursor::BeforeFirst,
        },
        key_directory_revision: 0,
    };
    let sync = sealer
        .seal_exact(
            &frozen,
            route(),
            runtime_bytes(RuntimeMessage::Reply(RuntimeReply::SyncComplete(sync))),
        )
        .await
        .expect("seal SyncComplete with refreshed authorization");
    assert_eq!(sync.authorization_used, current);
    let verified = verify_sealed(
        sync.sealed,
        &owner.signing.verifying_key(),
        &context(&current),
    )
    .expect("verify upgraded SyncComplete");
    let opened = open_sealed_payload(&receiving, &context(&current), verified)
        .expect("open upgraded SyncComplete");
    let envelope: RuntimeEnvelope =
        serde_json::from_slice(&opened.payload).expect("decode upgraded SyncComplete");
    let RuntimeMessage::Reply(RuntimeReply::SyncComplete(sync)) = envelope.body else {
        panic!("upgraded directed payload must remain SyncComplete");
    };
    assert_eq!(
        sync.key_directory_revision,
        current.key_directory_revision().value()
    );
    assert_eq!(owner.calls.load(Ordering::SeqCst), 2);
    store
        .shutdown()
        .await
        .expect("shutdown upgraded reply Store");
}

#[tokio::test]
async fn reply_refresh_rejects_pre_ready_and_post_rotation_cancel_before_signing() {
    let root = TestRoot::new("reply-upgrade-transition-fence");
    let database = root.database();
    let storage_keys = MemoryKeyStore::new();
    let store = active_store(&database, &storage_keys).await;
    let frozen = authorization(&store).await;
    let (_, operation_id) = stage_conversation_activation_for_reply_test(&store).await;
    store
        .mark_key_transition_rotated(operation_id)
        .await
        .expect("rotate reply-refresh transition");
    let rotated = authorization(&store).await;
    assert_eq!(
        rotated.key_directory_revision().value(),
        frozen.key_directory_revision().value() + 1
    );
    let (owner, authority) = authority(false);
    let sealer = DeviceReplyTxSealer::with_authority_for_test(
        store.clone(),
        Arc::new(MemoryKeyStore::new()),
        authority,
    );
    assert!(matches!(
        sealer.seal_exact(&frozen, route(), failure_reply()).await,
        Err(RemoteLinkError::ReplySealUnavailable)
    ));
    assert_eq!(owner.calls.load(Ordering::SeqCst), 0);

    assert!(matches!(
        store.cancel_key_transition(operation_id).await,
        Err(RuntimeStoreError::InvalidStateTransition)
    ));
    assert!(matches!(
        sealer.seal_exact(&frozen, route(), failure_reply()).await,
        Err(RemoteLinkError::ReplySealUnavailable)
    ));
    assert_eq!(
        owner.calls.load(Ordering::SeqCst),
        0,
        "rejected post-rotation cancellation must preserve the revision fence"
    );
    store
        .shutdown()
        .await
        .expect("shutdown transition-fenced reply Store");
}

#[tokio::test]
async fn stale_directory_current_never_uses_business_reply_revision_refresh() {
    let root = TestRoot::new("directory-current-exact-policy");
    let database = root.database();
    let storage_keys = MemoryKeyStore::new();
    let store = active_store(&database, &storage_keys).await;
    let frozen = authorization(&store).await;
    let (_, current) = commit_conversation_activation_for_reply_test(&store).await;
    assert!(current.key_directory_revision() > frozen.key_directory_revision());
    let requested = frozen
        .key_directory_revision()
        .next()
        .expect("frozen revision has successor");
    let status = DirectoryCurrentV1 {
        format_version: E2EE_FORMAT_VERSION,
        runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
        relay_protocol_version: RELAY_PROTOCOL_VERSION,
        machine_route: MACHINE,
        device_route: DEVICE,
        grant_serial: frozen.grant_serial(),
        root_trust_epoch: frozen.trust_epoch(),
        current_key_directory_revision: frozen.key_directory_revision(),
        requested_key_directory_revision: requested,
    };
    let (owner, authority) = authority(false);
    let sealer = DeviceReplyTxSealer::with_authority_for_test(
        store.clone(),
        Arc::new(MemoryKeyStore::new()),
        authority,
    );
    assert!(matches!(
        sealer
            .seal_directory_current_exact(&frozen, route(), status)
            .await,
        Err(RemoteLinkError::ReplySealUnavailable)
    ));
    assert_eq!(
        owner.calls.load(Ordering::SeqCst),
        0,
        "revision-bound KeyControl must remain exact-only"
    );
    store
        .shutdown()
        .await
        .expect("shutdown exact-policy DirectoryCurrent Store");
}

#[tokio::test]
async fn directory_current_reply_uses_exact_current_reply_key_and_counter() {
    let root = TestRoot::new("directory-current-production-sealer");
    let database = root.database();
    let storage_keys = MemoryKeyStore::new();
    let store = active_store(&database, &storage_keys).await;
    let authorization = authorization(&store).await;
    let receiving = reply_key(
        &store
            .load_global_key_state()
            .await
            .expect("load DirectoryCurrent global keys")
            .expect("DirectoryCurrent global keys exist"),
    );
    let current = authorization.key_directory_revision();
    let requested = current.next().expect("current revision has successor");
    let status = DirectoryCurrentV1 {
        format_version: E2EE_FORMAT_VERSION,
        runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
        relay_protocol_version: RELAY_PROTOCOL_VERSION,
        machine_route: MACHINE,
        device_route: DEVICE,
        grant_serial: authorization.grant_serial(),
        root_trust_epoch: authorization.trust_epoch(),
        current_key_directory_revision: current,
        requested_key_directory_revision: requested,
    };
    let (owner, authority) = authority(false);
    let sealer = DeviceReplyTxSealer::with_authority_for_test(
        store.clone(),
        Arc::new(MemoryKeyStore::new()),
        authority,
    );
    let sealed = sealer
        .seal_directory_current_exact(&authorization, route(), status.clone())
        .await
        .expect("seal DirectoryCurrent with production reply path");
    assert_eq!(owner.calls.load(Ordering::SeqCst), 1);
    assert_eq!(sealed.inner.key_id.purpose, KeyPurpose::DeviceReplyTx);
    assert_eq!(sealed.inner.key_epoch, authorization.reply_key_epoch());
    assert_eq!(sealed.inner.key_directory_revision, current.value());
    assert_ne!(sealed.inner.key_directory_revision, requested.value());
    assert_eq!(
        u64::from_be_bytes(
            sealed.inner.nonce[4..]
                .try_into()
                .expect("DirectoryCurrent counter bytes"),
        ),
        0
    );

    let scope = CounterScope::directed_reply_for_trust_epoch(
        authorization.machine_trust_domain(),
        authorization.machine_route(),
        authorization.trust_epoch(),
        authorization.device_route(),
        authorization.grant_serial(),
        authorization.reply_key_epoch(),
    )
    .expect("DirectoryCurrent directed counter scope");
    let counter = store
        .load_remote_counter_record(
            scope.token(),
            KeyId {
                purpose: KeyPurpose::DeviceReplyTx,
                epoch: authorization.reply_key_epoch(),
            },
        )
        .await
        .expect("load DirectoryCurrent durable counter");
    assert_eq!(counter.kind, RemoteCounterRecordKind::Gap);
    assert_eq!(counter.reserved_end, COUNTER_BLOCK_SIZE);

    let verified = verify_sealed(
        sealed,
        &owner.signing.verifying_key(),
        &context(&authorization),
    )
    .expect("verify DirectoryCurrent MachineData signature");
    let opened = open_sealed_payload(&receiving, &context(&authorization), verified)
        .expect("open production DirectoryCurrent reply");
    assert_eq!(opened.payload_kind, SealedPayloadKind::KeyUpdate);
    assert_eq!(
        KeyControlV1::from_canonical_bytes(&opened.payload)
            .expect("decode canonical DirectoryCurrent"),
        KeyControlV1::directory_current(status)
    );
    store
        .shutdown()
        .await
        .expect("shutdown DirectoryCurrent Store");
}

#[tokio::test]
async fn key_sync_reply_reuses_device_reply_counter_and_seals_typed_key_update_payload() {
    let root = TestRoot::new("directed-key-sync");
    let database = root.database();
    let storage_keys = MemoryKeyStore::new();
    let store = active_store(&database, &storage_keys).await;
    let authorization = authorization(&store).await;
    let receiving = reply_key(
        &store
            .load_global_key_state()
            .await
            .expect("load KeySync global keys")
            .expect("KeySync global keys exist"),
    );
    let (owner, authority) = authority(false);
    let sealer = DeviceReplyTxSealer::with_authority_for_test(
        store,
        Arc::new(MemoryKeyStore::new()),
        authority,
    );
    let stale_plus_one = key_update_set(authorization.key_directory_revision().value() + 1);
    assert!(matches!(
        sealer
            .seal_key_update_exact(&authorization, route(), stale_plus_one)
            .await,
        Err(RemoteLinkError::InvalidKeyControlReply)
    ));
    assert_eq!(
        owner.calls.load(Ordering::SeqCst),
        0,
        "legacy auth+1 KeySync shape must fail before counter reservation or signing"
    );

    let update_set = key_update_set(authorization.key_directory_revision().value());
    let sealed = sealer
        .seal_key_update_exact(&authorization, route(), update_set.clone())
        .await
        .expect("seal typed KeySync update set");
    assert_eq!(owner.calls.load(Ordering::SeqCst), 1);
    assert_eq!(sealed.inner.key_id.purpose, KeyPurpose::DeviceReplyTx);
    let verified = verify_sealed(
        sealed,
        &owner.signing.verifying_key(),
        &context(&authorization),
    )
    .expect("verify KeySync MachineData signature");
    let opened = open_sealed_payload(&receiving, &context(&authorization), verified)
        .expect("open KeySync directed reply");
    assert_eq!(opened.payload_kind, SealedPayloadKind::KeyUpdate);
    assert_eq!(
        KeyControlV1::from_canonical_bytes(&opened.payload).expect("decode typed KeySync control"),
        KeyControlV1::update_set(update_set)
    );
}

#[tokio::test]
async fn directed_transfer_part_uses_compact_adrt1_carrier_inside_the_sealed_payload() {
    let root = TestRoot::new("directed-transfer-carrier");
    let database = root.database();
    let storage_keys = MemoryKeyStore::new();
    let store = active_store(&database, &storage_keys).await;
    let authorization = authorization(&store).await;
    let receiving = reply_key(
        &store
            .load_global_key_state()
            .await
            .expect("load global keys")
            .expect("global keys exist"),
    );
    let (owner, authority) = authority(false);
    let sealer = DeviceReplyTxSealer::with_authority_for_test(
        store,
        Arc::new(MemoryKeyStore::new()),
        authority,
    );
    let transfer = TransferEnvelope::new_json(
        TransferId::new("directed-transfer-1"),
        0,
        1,
        sha256(&[0x51, 0x52, 0x53]),
        3,
        vec![0x51, 0x52, 0x53],
    )
    .expect("valid JSON/UDS transfer part");
    let reply = sealer
        .seal_exact(
            &authorization,
            route(),
            runtime_bytes(RuntimeMessage::Reply(RuntimeReply::TransferPart(
                transfer.clone(),
            ))),
        )
        .await
        .expect("seal directed transfer part");
    assert_eq!(reply.authorization_used, authorization);
    let sealed = reply.sealed;
    let verified = verify_sealed(
        sealed,
        &owner.signing.verifying_key(),
        &context(&authorization),
    )
    .expect("verify MachineData signature");
    let opened = open_sealed_payload(&receiving, &context(&authorization), verified)
        .expect("open directed transfer part");

    assert_eq!(opened.payload_kind, SealedPayloadKind::TransferPart);
    assert!(
        opened.payload.starts_with(b"ADRT1"),
        "remote transfer plaintext must not retain the JSON/UDS carrier"
    );
    let carrier = RuntimeTransferCarrierV1::decode(&opened.payload)
        .expect("decode compact remote transfer carrier");
    assert_eq!(carrier.message_id, MessageId::new("directed-reply-test"));
    assert_eq!(carrier.channel, RuntimeTransferChannel::Reply);
    assert_eq!(carrier.transfer, transfer);

    let exact_compact = carrier.encode().expect("encode exact compact carrier");
    let reply = sealer
        .seal_transfer_exact(&authorization, route(), carrier)
        .await
        .expect("seal already-compact directed transfer part");
    assert_eq!(reply.authorization_used, authorization);
    let sealed = reply.sealed;
    let verified = verify_sealed(
        sealed,
        &owner.signing.verifying_key(),
        &context(&authorization),
    )
    .expect("verify compact directed MachineData signature");
    let opened = open_sealed_payload(&receiving, &context(&authorization), verified)
        .expect("open compact directed transfer part");
    assert_eq!(opened.payload_kind, SealedPayloadKind::TransferPart);
    assert_eq!(opened.payload, exact_compact);
}

#[tokio::test]
async fn directed_sync_complete_binds_the_current_nonzero_key_directory_revision() {
    let root = TestRoot::new("directed-sync-revision");
    let database = root.database();
    let storage_keys = MemoryKeyStore::new();
    let store = active_store(&database, &storage_keys).await;
    let authorization = authorization(&store).await;
    let receiving = reply_key(
        &store
            .load_global_key_state()
            .await
            .expect("load global keys")
            .expect("global keys exist"),
    );
    let (owner, authority) = authority(false);
    let sealer = DeviceReplyTxSealer::with_authority_for_test(
        store,
        Arc::new(MemoryKeyStore::new()),
        authority,
    );
    let sync = RuntimeSyncComplete {
        stream_generation: StreamGeneration::new("directed-sync-generation"),
        stream_cursor: StreamCursor::BeforeFirst,
        inner_cursor: RuntimeInnerCursor::Conversation {
            conversation_id: ConversationId::new("11111111-2222-4333-8444-555555555555"),
            cursor: StreamCursor::BeforeFirst,
        },
        key_directory_revision: 0,
    };
    let reply = sealer
        .seal_exact(
            &authorization,
            route(),
            runtime_bytes(RuntimeMessage::Reply(RuntimeReply::SyncComplete(sync))),
        )
        .await
        .expect("seal directed SyncComplete");
    assert_eq!(reply.authorization_used, authorization);
    let sealed = reply.sealed;
    let verified = verify_sealed(
        sealed,
        &owner.signing.verifying_key(),
        &context(&authorization),
    )
    .expect("verify MachineData signature");
    let opened = open_sealed_payload(&receiving, &context(&authorization), verified)
        .expect("open directed SyncComplete");
    let envelope: RuntimeEnvelope =
        serde_json::from_slice(&opened.payload).expect("decode normalized remote SyncComplete");
    let RuntimeMessage::Reply(RuntimeReply::SyncComplete(sync)) = envelope.body else {
        panic!("directed payload must remain SyncComplete");
    };
    assert_eq!(
        sync.key_directory_revision,
        authorization.key_directory_revision().value()
    );
    assert_ne!(sync.key_directory_revision, 0);
}

#[tokio::test]
async fn failed_transaction_bound_sign_then_reopen_abandons_block_and_never_reuses_counter() {
    let root = TestRoot::new("directed-crash-gap");
    let database = root.database();
    let storage_keys = MemoryKeyStore::new();
    let counter_keys = Arc::new(MemoryKeyStore::new());
    let store = active_store(&database, &storage_keys).await;
    let authorization = authorization(&store).await;
    let (failing_owner, failing_authority) = authority(true);
    let failing = DeviceReplyTxSealer::with_authority_for_test(
        store.clone(),
        counter_keys.clone(),
        failing_authority,
    );
    assert!(matches!(
        failing
            .seal_exact(&authorization, route(), failure_reply())
            .await,
        Err(RemoteLinkError::ReplySealUnavailable)
    ));
    assert_eq!(failing_owner.calls.load(Ordering::SeqCst), 1);
    let scope = CounterScope::directed_reply_for_trust_epoch(
        authorization.machine_trust_domain(),
        authorization.machine_route(),
        authorization.trust_epoch(),
        authorization.device_route(),
        authorization.grant_serial(),
        authorization.reply_key_epoch(),
    )
    .expect("failed directed scope");
    assert_eq!(
        store
            .load_remote_counter_guard_cleanup_manifest()
            .await
            .expect("failed transaction still persists materialized guard inventory"),
        vec![(scope.token(), true)]
    );
    drop(failing);
    store.shutdown().await.expect("shutdown after failed seal");

    let reopened = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(database.clone()),
        load_or_create_storage_kek(&storage_keys, &database).expect("reload StorageKEK"),
    )
    .await
    .expect("reopen directed Store");
    let (owner, authority) = authority(false);
    let sealer =
        DeviceReplyTxSealer::with_authority_for_test(reopened.clone(), counter_keys, authority);
    let reply = sealer
        .seal_exact(&authorization, route(), failure_reply())
        .await
        .expect("reconcile gap and seal next block");
    assert_eq!(reply.authorization_used, authorization);
    let sealed = reply.sealed;
    let used = u64::from_be_bytes(sealed.inner.nonce[4..].try_into().expect("counter bytes"));
    assert_eq!(
        used, COUNTER_BLOCK_SIZE,
        "counter zero belongs to abandoned block"
    );
    assert_eq!(owner.calls.load(Ordering::SeqCst), 1);

    assert_eq!(
        reopened
            .load_remote_counter_guard_cleanup_manifest()
            .await
            .expect("reopened transaction keeps exact guard inventory"),
        vec![(scope.token(), true)]
    );
    let record = reopened
        .load_remote_counter_record(
            scope.token(),
            KeyId {
                purpose: KeyPurpose::DeviceReplyTx,
                epoch: authorization.reply_key_epoch(),
            },
        )
        .await
        .expect("load durable directed counter");
    assert_eq!(record.kind, RemoteCounterRecordKind::Gap);
    assert_eq!(record.reserved_end, COUNTER_BLOCK_SIZE * 2);
}

#[tokio::test]
async fn durable_retired_directed_scope_survives_restart_and_returns_typed_error_without_signing() {
    let root = TestRoot::new("directed-retired");
    let database = root.database();
    let storage_keys = MemoryKeyStore::new();
    let store = active_store(&database, &storage_keys).await;
    let authorization = authorization(&store).await;
    let scope = CounterScope::directed_reply_for_trust_epoch(
        authorization.machine_trust_domain(),
        authorization.machine_route(),
        authorization.trust_epoch(),
        authorization.device_route(),
        authorization.grant_serial(),
        authorization.reply_key_epoch(),
    )
    .expect("directed scope");
    let key_id = KeyId {
        purpose: KeyPurpose::DeviceReplyTx,
        epoch: authorization.reply_key_epoch(),
    };
    let genesis = store
        .load_remote_counter_record(scope.token(), key_id)
        .await
        .expect("load authenticated genesis");
    let counter_keys = Arc::new(MemoryKeyStore::new());
    let backend = KeyStoreCounterGuardBackend::new(counter_keys.as_ref());
    let divergent = CounterGuardState::pending(
        scope.token(),
        0,
        COUNTER_BLOCK_SIZE,
        [0x91; 16],
        [0x92; 16],
        [0x93; 32],
    )
    .expect("divergent guard fixture");
    assert_ne!(divergent.database_anchor(), genesis.db_anchor);
    assert_eq!(
        backend
            .compare_and_swap_guard(&scope, None, divergent)
            .expect("persist divergent guard"),
        CounterGuardCas::Swapped(divergent)
    );
    let (first_owner, first_authority) = authority(false);
    let first = DeviceReplyTxSealer::with_authority_for_test(
        store.clone(),
        counter_keys.clone(),
        first_authority,
    );
    let error = first
        .seal_exact(&authorization, route(), failure_reply())
        .await
        .expect_err("divergent guard must durably retire before sealing");
    assert_eq!(error.code(), "daemon.remote.counter.retired");
    assert_eq!(first_owner.calls.load(Ordering::SeqCst), 0);
    let retired = store
        .load_remote_counter_record(scope.token(), key_id)
        .await
        .expect("authenticated retirement readback");
    assert_eq!(retired.kind, RemoteCounterRecordKind::Retired);
    assert_eq!(retired.reserved_end, COUNTER_BLOCK_SIZE);
    assert!(
        store
            .has_retired_remote_counter()
            .await
            .expect("authenticated retired gate")
    );
    store.shutdown().await.expect("shutdown retired Store");

    let reopened = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(database.clone()),
        load_or_create_storage_kek(&storage_keys, &database).expect("reload StorageKEK"),
    )
    .await
    .expect("reopen retired Store");
    assert_eq!(
        reopened
            .load_remote_counter_record(scope.token(), key_id)
            .await
            .expect("authenticated retired readback")
            .kind,
        RemoteCounterRecordKind::Retired
    );
    let (owner, authority) = authority(false);
    let sealer =
        DeviceReplyTxSealer::with_authority_for_test(reopened.clone(), counter_keys, authority);
    let error = sealer
        .seal_exact(&authorization, route(), failure_reply())
        .await
        .expect_err("retired directed scope must never seal again");
    assert_eq!(error.code(), "daemon.remote.counter.retired");
    assert_eq!(owner.calls.load(Ordering::SeqCst), 0);
    reopened.shutdown().await.expect("shutdown reopened Store");
}

#[tokio::test]
async fn weak_machine_data_owner_shutdown_fails_closed_inside_store_transaction() {
    let root = TestRoot::new("directed-owner-drop");
    let database = root.database();
    let storage_keys = MemoryKeyStore::new();
    let store = active_store(&database, &storage_keys).await;
    let authorization = authorization(&store).await;
    let counter_keys = Arc::new(MemoryKeyStore::new());
    let (owner, authority) = authority(false);
    let sealer = DeviceReplyTxSealer::with_authority_for_test(store, counter_keys, authority);
    drop(owner);
    assert!(matches!(
        sealer
            .seal_exact(&authorization, route(), failure_reply())
            .await,
        Err(RemoteLinkError::ReplySealUnavailable)
    ));
}

#[tokio::test]
async fn mismatched_device_route_is_rejected_before_machine_data_signing() {
    let root = TestRoot::new("directed-route-mismatch");
    let database = root.database();
    let storage_keys = MemoryKeyStore::new();
    let store = active_store(&database, &storage_keys).await;
    let authorization = authorization(&store).await;
    let (owner, authority) = authority(false);
    let sealer = DeviceReplyTxSealer::with_authority_for_test(
        store.clone(),
        Arc::new(MemoryKeyStore::new()),
        authority,
    );
    let mut wrong = route();
    wrong.device_route = DeviceRouteId::from_bytes([0xd2; 16]);
    assert!(matches!(
        sealer
            .seal_exact(&authorization, wrong, failure_reply())
            .await,
        Err(RemoteLinkError::ReplyAuthorizationMismatch)
    ));
    assert_eq!(owner.calls.load(Ordering::SeqCst), 0);
    assert!(
        store
            .load_remote_counter_guard_manifest()
            .await
            .expect("route mismatch manifest readback")
            .is_empty()
    );
}

#[tokio::test]
async fn local_revoke_invalidates_previously_issued_reply_authorization_before_seal() {
    let root = TestRoot::new("directed-revoked");
    let database = root.database();
    let storage_keys = MemoryKeyStore::new();
    let store = active_store(&database, &storage_keys).await;
    let stale = authorization(&store).await;
    begin_local_revocation(&store).await;
    let (owner, authority) = authority(false);
    let sealer = DeviceReplyTxSealer::with_authority_for_test(
        store.clone(),
        Arc::new(MemoryKeyStore::new()),
        authority,
    );
    assert!(matches!(
        sealer.seal_exact(&stale, route(), failure_reply()).await,
        Err(RemoteLinkError::ReplySealUnavailable)
    ));
    assert_eq!(
        owner.calls.load(Ordering::SeqCst),
        0,
        "revoked authorization must be rejected before AEAD/sign closure"
    );
    assert!(
        store
            .load_remote_counter_guard_manifest()
            .await
            .expect("revoked authorization manifest readback")
            .is_empty()
    );
}

#[tokio::test]
async fn transition_snapshot_sealer_requires_exact_store_permit_and_records_flush_marker() {
    let root = TestRoot::new("transition-snapshot-permit");
    let database = root.database();
    let storage_keys = MemoryKeyStore::new();
    let store = active_authorization_store_with_pending_transition_for_test(
        &database,
        load_or_create_storage_kek(&storage_keys, &database)
            .expect("load transition snapshot StorageKEK"),
        vec![AuthorizationCapabilityV1::Catalog],
        vec![AuthorizationPermissionV1::CatalogRead],
    )
    .await;
    let pending = store
        .load_active_key_transition()
        .await
        .expect("load initial Add transition")
        .expect("initial Add transition exists");
    let operation_id = pending.transition.operation_id;
    let recipient = pending.transition.recipients[0];
    let key_revision = pending.transition.to_revision;
    assert_eq!(recipient.device_route, *DEVICE.as_bytes());

    let publication_stream_id = [0x81; 16];
    let stream_route = [0x82; 16];
    let generation = [0x83; 16];
    store
        .create_publication_stream(
            publication_stream_id,
            PublicationScope::Catalog,
            stream_route,
            generation,
        )
        .await
        .expect("create genesis catalog publication stream");
    store
        .mark_key_transition_rotated(operation_id)
        .await
        .expect("advance initial Add transition");
    let canonical_update_set = b"transition-snapshot-directed-sealer".to_vec();
    store
        .freeze_key_updates(
            operation_id,
            vec![FrozenKeyUpdate {
                recipient,
                key_revision,
                canonical_update_set: canonical_update_set.clone(),
            }],
        )
        .await
        .expect("freeze transition snapshot KeyUpdate");
    let barrier_sha256 = [0x84; 32];
    store
        .freeze_key_barriers(
            operation_id,
            vec![KeyTransitionStreamCut {
                scope: KeyTransitionStreamScope::Catalog,
                publication_stream_id,
                stream_route,
                generation,
                relay_committed_outer: None,
                relay_committed_inner: None,
                barrier_sequence: 0,
                old_epoch: 0,
                new_epoch: 1,
                epoch_barrier_sha256: barrier_sha256,
            }],
        )
        .await
        .expect("freeze exact genesis catalog cut");
    let barrier = store
        .freeze_publication(FreezePublicationRequest {
            publication_id: [0x85; 16],
            publication_stream_id,
            generation,
            counter_scope_token: [0x86; 32],
            sender_counter: 0,
            inner_after: None,
            inner_through: None,
            payload_kind: PublicationPayloadKind::Control,
            blob: b"transition-snapshot-epoch-barrier".to_vec(),
        })
        .await
        .expect("freeze transition epoch barrier publication");
    store
        .acknowledge_publication_commit(
            publication_stream_id,
            generation,
            barrier.stream_seq,
            barrier.blob_sha256,
        )
        .await
        .expect("commit transition epoch barrier publication");
    let committed = store
        .mark_key_barriers_committed(operation_id)
        .await
        .expect("mark transition barriers committed");
    store
        .acknowledge_key_update(AcknowledgeKeyUpdate {
            operation_id,
            recipient,
            key_revision,
            update_hash: canonical_update_hash(&canonical_update_set)
                .expect("hash transition snapshot KeyUpdate"),
            canonical_ack: b"transition-snapshot-key-update-ack".to_vec(),
            acknowledged_at_ms: committed.state_changed_at_ms,
        })
        .await
        .expect("ack transition snapshot KeyUpdate");

    let active = store
        .load_active_remote_ingress(MACHINE, DEVICE)
        .await
        .expect("load transition snapshot authorization");
    let current = store
        .recheck_active_remote_ingress(&active)
        .await
        .expect("recheck transition snapshot authorization");
    let authorization = current.remote_reply_authorization();
    let permit = store
        .resolve_transition_snapshot_permit(TransitionSnapshotRequest::new(
            current,
            KeyTransitionStreamScope::Catalog,
            StreamCursor::BeforeFirst,
        ))
        .await
        .expect("resolve Store-issued transition snapshot permit");
    assert_eq!(
        permit.authorization_hash(),
        authorization.authorization_hash()
    );

    let (owner, authority) = authority(false);
    let sealer = DeviceReplyTxSealer::with_authority_for_test(
        store.clone(),
        Arc::new(MemoryKeyStore::new()),
        authority,
    );
    assert!(matches!(
        sealer
            .seal_exact(&authorization, route(), failure_reply())
            .await,
        Err(RemoteLinkError::ReplySealUnavailable)
    ));
    assert_eq!(
        owner.calls.load(Ordering::SeqCst),
        0,
        "ordinary business reply must stay fenced while Add transition is active"
    );

    let wrong_generation =
        StreamGeneration::new(uuid::Uuid::from_bytes([0x88; 16]).hyphenated().to_string());
    for invalid_receipt in [
        SubscriptionReceipt::Subscribed {
            stream_generation: wrong_generation,
        },
        SubscriptionReceipt::Unsubscribed,
    ] {
        assert!(matches!(
            sealer
                .seal_transition_snapshot_exact(
                    &authorization,
                    route(),
                    &permit,
                    runtime_bytes(RuntimeMessage::Reply(RuntimeReply::Subscription(
                        invalid_receipt,
                    ))),
                )
                .await,
            Err(RemoteLinkError::InvalidCoreEgress)
        ));
    }
    assert!(matches!(
        sealer
            .seal_transition_snapshot_exact(
                &authorization,
                route(),
                &permit,
                runtime_bytes(RuntimeMessage::Reply(RuntimeReply::Catalog(
                    CatalogSnapshot::new(StreamCursor::At(0), Vec::new(), None)
                        .expect("construct wrong-base Catalog snapshot"),
                ))),
            )
            .await,
        Err(RemoteLinkError::InvalidCoreEgress)
    ));
    assert_eq!(
        owner.calls.load(Ordering::SeqCst),
        0,
        "wrong receipt or wrong snapshot base must be rejected before signing"
    );

    let sync = RuntimeSyncComplete {
        stream_generation: StreamGeneration::new(
            uuid::Uuid::from_bytes(permit.generation())
                .hyphenated()
                .to_string(),
        ),
        stream_cursor: StreamCursor::BeforeFirst,
        inner_cursor: RuntimeInnerCursor::Catalog {
            cursor: StreamCursor::BeforeFirst,
        },
        key_directory_revision: permit.key_directory_revision(),
    };
    let sync_bytes = runtime_bytes(RuntimeMessage::Reply(RuntimeReply::SyncComplete(sync)));
    let transition_reply = sealer
        .seal_transition_snapshot_exact(&authorization, route(), &permit, sync_bytes.clone())
        .await
        .expect("seal exact transition SyncComplete under Store permit");
    assert_eq!(transition_reply.authorization_used, authorization);
    assert_eq!(owner.calls.load(Ordering::SeqCst), 1);

    let transfer = TransferEnvelope::new_json(
        TransferId::new("transition-snapshot-transfer"),
        0,
        1,
        sha256(b"transition-snapshot-transfer"),
        28,
        b"transition-snapshot-transfer".to_vec(),
    )
    .expect("build transition snapshot transfer");
    let carrier = RuntimeTransferCarrierV1::new(
        MessageId::new("transition-snapshot-transfer"),
        RuntimeTransferChannel::Reply,
        transfer,
    );
    let transition_transfer = sealer
        .seal_transition_snapshot_transfer_exact(&authorization, route(), &permit, carrier)
        .await
        .expect("seal exact transition snapshot transfer under Store permit");
    assert_eq!(transition_transfer.authorization_used, authorization);
    assert_eq!(owner.calls.load(Ordering::SeqCst), 2);

    assert!(matches!(
        sealer
            .mark_transition_snapshot_flushed(permit.clone(), [0; 32])
            .await,
        Err(RemoteLinkError::ReplySealUnavailable)
    ));
    let sync_complete_sha256 = [0x87; 32];
    sealer
        .mark_transition_snapshot_flushed(permit.clone(), sync_complete_sha256)
        .await
        .expect("persist transition snapshot writer flush marker");
    let recovered = store
        .load_active_key_transition()
        .await
        .expect("reload transition after snapshot flush")
        .expect("StreamAppliedAck still keeps transition active");
    assert_eq!(recovered.updates[0].snapshot_flushes.len(), 1);
    assert_eq!(
        recovered.updates[0].snapshot_flushes[0].sync_complete_sha256,
        sync_complete_sha256
    );

    let marker = recovered.updates[0].snapshot_flushes[0].clone();
    store
        .acknowledge_stream_applied(AcknowledgeStreamApplied {
            operation_id,
            recipient,
            key_revision,
            scope: permit.scope(),
            stream_route: permit.stream_route(),
            stream_generation: permit.generation(),
            applied_stream_seq: permit.barrier_sequence(),
            inner_cursor: permit.relay_committed_inner(),
            key_epoch: permit.key_epoch(),
            epoch_barrier_sha256: permit.epoch_barrier_sha256(),
            authorization_hash: permit.authorization_hash(),
            canonical_ack: b"transition-snapshot-stream-applied-ack".to_vec(),
            acknowledged_at_ms: marker.flushed_at_ms,
        })
        .await
        .expect("ack exact transition snapshot cut");
    store
        .try_complete_key_transition(operation_id)
        .await
        .expect("complete transition after both ACK families");
    assert!(
        store
            .load_active_key_transition()
            .await
            .expect("reload completed transition")
            .is_none()
    );
    assert!(matches!(
        sealer
            .seal_transition_snapshot_exact(&authorization, route(), &permit, sync_bytes)
            .await,
        Err(RemoteLinkError::ReplySealUnavailable)
    ));
    assert_eq!(
        owner.calls.load(Ordering::SeqCst),
        2,
        "completed transition must invalidate the old permit before signing"
    );

    store
        .shutdown()
        .await
        .expect("shutdown transition snapshot Store");
}
