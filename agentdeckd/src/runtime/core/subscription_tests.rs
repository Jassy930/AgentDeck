use super::*;

use agentdeck_protocol::runtime::command::CatalogRequest;
use agentdeck_protocol::runtime::identity::{
    CatalogPageCursor, ConversationId as WireConversationId, EntityId, ItemId, MessageId,
};
use agentdeck_protocol::runtime::{
    BackfillChunk, BackfillRequest, CatalogChange, ConversationSnapshot, MAX_JSON_PART_BYTES,
    MAX_RUNTIME_JSON_FRAME_BYTES, RuntimeInnerCursor, RuntimeStreamItem, RuntimeSubscriptionTarget,
    SnapshotItem, StreamCursor,
};
use agentdeck_protocol::{AgentItem, AgentItemMeta};
use tokio::time::{Duration, timeout};

use crate::runtime::store::{
    AuthorizeExecutionRelease, ExecutionFence, RuntimeBackfillPlan, RuntimeBackfillTarget,
    RuntimeStoreError, RuntimeStoreFaultInjector, RuntimeStoreLane, RuntimeStoreOperation,
};

struct FailConfigureAfterCommitOnce {
    armed: AtomicBool,
}

struct FailMetadataAfterCommitOnce {
    armed: AtomicBool,
}

impl RuntimeStoreFaultInjector for FailConfigureAfterCommitOnce {
    fn before_operation(&self, operation: RuntimeStoreOperation) -> Result<(), RuntimeStoreError> {
        if operation == RuntimeStoreOperation::ConfigureConversationAfterCommit
            && self.armed.swap(false, Ordering::SeqCst)
        {
            return Err(RuntimeStoreError::InvalidConfig(
                "injected Configure after-COMMIT fault",
            ));
        }
        Ok(())
    }
}

impl RuntimeStoreFaultInjector for FailMetadataAfterCommitOnce {
    fn before_operation(&self, operation: RuntimeStoreOperation) -> Result<(), RuntimeStoreError> {
        if operation == RuntimeStoreOperation::UpdateConversationMetadataAfterCommit
            && self.armed.swap(false, Ordering::SeqCst)
        {
            return Err(RuntimeStoreError::InvalidConfig(
                "injected metadata Update after-COMMIT fault",
            ));
        }
        Ok(())
    }
}

async fn connect_recording(
    core: &RuntimeCore,
    seed: u8,
) -> (
    ConnectionId,
    mpsc::Receiver<crate::runtime::ConnectionWrite>,
) {
    let principal = core
        .issue_verified_local_principal(501, [seed; 16])
        .expect("issue recording principal");
    let (sink, receiver) = mpsc::channel(16);
    let connection = core
        .connect(principal, ConnectionSink::new(sink))
        .expect("connect recording sink");
    (connection, receiver)
}

fn backfill_envelope(message: &str) -> RuntimeEnvelope {
    RuntimeEnvelope {
        version: RUNTIME_PROTOCOL_VERSION,
        message_id: MessageId::new(message),
        body: RuntimeMessage::Request(RuntimeRequest::Backfill(BackfillRequest::Catalog {
            after: StreamCursor::BeforeFirst,
        })),
    }
}

fn conversation_backfill_after_envelope(
    message: &str,
    conversation_id: RuntimeId,
    after: StreamCursor,
) -> RuntimeEnvelope {
    RuntimeEnvelope {
        version: RUNTIME_PROTOCOL_VERSION,
        message_id: MessageId::new(message),
        body: RuntimeMessage::Request(RuntimeRequest::Backfill(BackfillRequest::Conversation {
            conversation_id: WireConversationId::new(conversation_id.to_canonical_string()),
            after,
        })),
    }
}

fn subscribe_catalog_envelope(message: &str) -> RuntimeEnvelope {
    RuntimeEnvelope {
        version: RUNTIME_PROTOCOL_VERSION,
        message_id: MessageId::new(message),
        body: RuntimeMessage::Request(RuntimeRequest::Subscribe {
            inner_cursor: agentdeck_protocol::runtime::RuntimeInnerCursor::Catalog {
                cursor: StreamCursor::BeforeFirst,
            },
        }),
    }
}

fn subscribe_conversation_envelope(message: &str, conversation_id: RuntimeId) -> RuntimeEnvelope {
    RuntimeEnvelope {
        version: RUNTIME_PROTOCOL_VERSION,
        message_id: MessageId::new(message),
        body: RuntimeMessage::Request(RuntimeRequest::Subscribe {
            inner_cursor: agentdeck_protocol::runtime::RuntimeInnerCursor::Conversation {
                conversation_id: WireConversationId::new(conversation_id.to_canonical_string()),
                cursor: StreamCursor::BeforeFirst,
            },
        }),
    }
}

fn publication_axis_id(seed: u8) -> RuntimeId {
    RuntimeId::from_bytes(RuntimeIdKind::RemoteOutbox, [seed; 16]).expect("publication axis id")
}

async fn store_ready_snapshot_with_text_bytes(
    core: &RuntimeCore,
    conversation_id: RuntimeId,
    text_bytes: usize,
) {
    use crate::runtime::snapshot::{
        SnapshotMaterialization, SnapshotMaterializer, assemble_build_snapshot,
    };

    let source = core
        .store
        .acquire_snapshot_build_source(conversation_id)
        .await
        .expect("capture large snapshot source");
    let materializer = SnapshotMaterializer::new(core.store.clone(), core.router.clone());
    let SnapshotMaterialization::Build(mut build) = materializer
        .materialize(source)
        .await
        .expect("prepare large snapshot")
    else {
        panic!("fresh conversation must build a snapshot")
    };
    let assembled = assemble_build_snapshot(
        &mut build,
        vec![SnapshotItem::Item {
            item_id: ItemId::new("large-snapshot-item"),
            entity_id: EntityId::new("large-snapshot-entity"),
            command_id: None,
            item: AgentItem::AssistantMessage {
                text: "x".repeat(text_bytes),
                meta: AgentItemMeta::default(),
            },
        }],
    )
    .expect("assemble large canonical snapshot");
    assert!(
        assembled.canonical_payload().len() > MAX_JSON_PART_BYTES,
        "fixture must take the real transfer path"
    );
    let write = build
        .bind_assembled_snapshot(assembled)
        .expect("bind large snapshot write");
    core.store
        .store_conversation_snapshot(write)
        .await
        .expect("store large ready snapshot");
}

async fn append_large_snapshot_event(
    core: &RuntimeCore,
    conversation_id: RuntimeId,
    command_id: RuntimeId,
    turn_id: RuntimeId,
    event_id: RuntimeId,
    owner_seed: u8,
    text_bytes: usize,
) {
    let configuration_connection = connect_local(core, owner_seed.wrapping_add(0x40)).await;
    let configuration_key = format!("large-snapshot-configuration-{owner_seed}");
    configure_codex_revision_one(
        core,
        configuration_connection,
        WireConversationId::new(conversation_id.to_canonical_string()),
        &configuration_key,
    )
    .await;
    core.disconnect(configuration_connection).await;
    let owner = crate::runtime::store::IdempotencyOwner::Local {
        machine_trust_domain: [owner_seed; 32],
        uid: 501,
        client_installation_id: [owner_seed.wrapping_add(1); 16],
    };
    let accepted = core
        .store
        .accept_command(crate::runtime::store::AcceptCommand {
            conversation_id,
            owner: owner.clone(),
            idempotency_key: format!("large-snapshot-{owner_seed}"),
            expected_configuration_revision: 1,
            payload: b"large snapshot prompt".to_vec(),
        })
        .await
        .expect("accept large snapshot command");
    assert!(matches!(
        accepted,
        crate::runtime::store::AcceptOutcome::Accepted { ref command, .. }
            if command.command_id == command_id
    ));
    let daemon_boot_id =
        RuntimeId::from_bytes(RuntimeIdKind::DaemonBoot, [owner_seed.wrapping_add(2); 16])
            .expect("large snapshot daemon boot id");
    let execution_nonce = vec![owner_seed; 16];
    let started = core
        .store
        .mark_started_with_event(crate::runtime::store::StartCommand {
            conversation_id,
            command_id,
            daemon_boot_id,
            execution_nonce: execution_nonce.clone(),
        })
        .await
        .expect("commit canonical TurnStarted");
    assert!(matches!(
        started,
        crate::runtime::store::StartOutcome::Started { ref intent, ref event, .. }
            if intent.turn_id == turn_id
                && event.event_id == event_id
                && intent.daemon_boot_id == daemon_boot_id
                && intent.execution_nonce == execution_nonce
    ));
    core.store
        .persist_execution_fence(ExecutionFence {
            command_id,
            daemon_boot_id,
            execution_nonce: execution_nonce.clone(),
            process_group_id: i64::from(owner_seed) + 8_000,
            leader_pid: i64::from(owner_seed) + 8_000,
            leader_start_time: u64::from(owner_seed) + 8_000,
            payload: b"large-snapshot-test-fence".to_vec(),
        })
        .await
        .expect("persist large snapshot execution fence");
    core.store
        .authorize_execution_release(AuthorizeExecutionRelease {
            command_id,
            daemon_boot_id,
            execution_nonce,
        })
        .await
        .expect("authorize large snapshot execution release");
    let item_event_id =
        RuntimeId::from_bytes(RuntimeIdKind::Event, [owner_seed.wrapping_add(3); 16])
            .expect("large snapshot item event id");
    assert!(matches!(
        core.store
            .append_execution_event(crate::runtime::store::AppendExecutionEvent::item(
                conversation_id,
                command_id,
                turn_id,
                item_event_id,
                ItemId::new(format!("large-item-{owner_seed}")),
                EntityId::new(format!("large-entity-{owner_seed}")),
                AgentItem::AssistantMessage {
                    text: "x".repeat(text_bytes),
                    meta: AgentItemMeta::default(),
                },
            ))
            .await
            .expect("append large canonical snapshot item"),
        crate::runtime::store::AppendExecutionEventOutcome::Appended { event }
            if event.event_id == item_event_id && event.event_seq == 2
    ));
}

fn catalog_request_envelope(
    message: &str,
    page_cursor: Option<CatalogPageCursor>,
) -> RuntimeEnvelope {
    RuntimeEnvelope {
        version: RUNTIME_PROTOCOL_VERSION,
        message_id: MessageId::new(message),
        body: RuntimeMessage::Request(RuntimeRequest::Catalog(CatalogRequest { page_cursor })),
    }
}

async fn request_catalog_page(
    core: &RuntimeCore,
    connection: ConnectionId,
    receiver: &mut mpsc::Receiver<crate::runtime::ConnectionWrite>,
    message: &str,
    page_cursor: Option<CatalogPageCursor>,
) -> agentdeck_protocol::runtime::CatalogSnapshot {
    request_catalog_page_with_timeout(
        core,
        connection,
        receiver,
        message,
        page_cursor,
        Duration::from_secs(2),
    )
    .await
}

async fn request_catalog_page_with_timeout(
    core: &RuntimeCore,
    connection: ConnectionId,
    receiver: &mut mpsc::Receiver<crate::runtime::ConnectionWrite>,
    message: &str,
    page_cursor: Option<CatalogPageCursor>,
    reply_timeout: Duration,
) -> agentdeck_protocol::runtime::CatalogSnapshot {
    core.handle_envelope(connection, catalog_request_envelope(message, page_cursor))
        .await
        .expect("enqueue catalog request");
    let write = timeout(reply_timeout, receiver.recv())
        .await
        .expect("catalog reply timeout")
        .expect("catalog reply");
    let envelope = decode(&write);
    assert_eq!(envelope.message_id.as_str(), message);
    let RuntimeMessage::Reply(RuntimeReply::Catalog(snapshot)) = envelope.body else {
        panic!("expected catalog reply");
    };
    write.acknowledge().expect("flush catalog reply");
    wait_catalog_jobs_idle(core).await;
    snapshot
}

async fn wait_catalog_jobs_idle(core: &RuntimeCore) {
    timeout(Duration::from_secs(2), async {
        loop {
            if core
                .subscriptions
                .catalog_metrics_for_test()
                .expect("catalog job metrics")
                == (0, 0)
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("catalog jobs must release after transport ACK");
}

fn decode(write: &crate::runtime::ConnectionWrite) -> RuntimeEnvelope {
    serde_json::from_slice(write.bytes()).expect("decode runtime writer envelope")
}

async fn receive_envelope_and_ack(
    receiver: &mut mpsc::Receiver<crate::runtime::ConnectionWrite>,
    label: &str,
) -> RuntimeEnvelope {
    let write = timeout(Duration::from_secs(2), receiver.recv())
        .await
        .unwrap_or_else(|_| panic!("{label} timeout"))
        .unwrap_or_else(|| panic!("{label} writer closed"));
    let envelope = decode(&write);
    write
        .acknowledge()
        .unwrap_or_else(|_| panic!("flush {label}"));
    envelope
}

fn catalog_conversation(seed: u8) -> NewConversation {
    NewConversation {
        conversation_id: RuntimeId::from_bytes(RuntimeIdKind::Conversation, [seed; 16])
            .expect("conversation id"),
        adapter_state_key: RuntimeId::from_bytes(
            RuntimeIdKind::AdapterState,
            [seed.wrapping_add(1); 16],
        )
        .expect("adapter state id"),
        descriptor: ConversationDescriptor {
            agent_kind: AgentKind::Codex,
            title: Some("live-after-sync".to_owned()),
            cwd: PathBuf::from("/tmp/agentdeck-subscription-test"),
        },
    }
}

fn indexed_catalog_conversation(index: u16) -> NewConversation {
    let value = u128::from(index) + 1;
    NewConversation {
        conversation_id: RuntimeId::from_bytes(RuntimeIdKind::Conversation, value.to_be_bytes())
            .expect("indexed conversation id"),
        adapter_state_key: RuntimeId::from_bytes(
            RuntimeIdKind::AdapterState,
            ((1_u128 << 127) | value).to_be_bytes(),
        )
        .expect("indexed adapter state id"),
        descriptor: ConversationDescriptor {
            agent_kind: AgentKind::Codex,
            title: Some(format!("catalog-{index:04}")),
            cwd: PathBuf::from("/tmp/agentdeck-subscription-test"),
        },
    }
}

fn large_catalog_conversation(index: u16) -> NewConversation {
    let mut conversation = indexed_catalog_conversation(index);
    conversation.descriptor.title = Some(format!(
        "large-catalog-{index:04}-{}",
        "x".repeat(600 * 1024)
    ));
    conversation
}

async fn create_indexed_catalog_rows(core: &RuntimeCore, first: u16, count: u16) {
    for index in first..first + count {
        core.store
            .create_conversation(indexed_catalog_conversation(index))
            .await
            .expect("create indexed catalog row");
    }
}

#[path = "subscription_tests/a1a2_legacy_readback.rs"]
mod a1a2_legacy_readback;
#[path = "subscription_tests/catalog.rs"]
mod catalog;
#[path = "subscription_tests/dynamic_native.rs"]
mod dynamic_native;
#[path = "subscription_tests/snapshot_store.rs"]
mod snapshot_store;
#[path = "subscription_tests/terminal_gate.rs"]
mod terminal_gate;

#[tokio::test]
async fn fresh_catalog_subscribe_delivers_snapshot_before_sync_complete() {
    let root = TestRoot::new("subscription-fresh-catalog-snapshot");
    let core = core(&root).await;
    core.recover().await.expect("recover core");
    let (connection, mut receiver) = connect_recording(&core, 0x70).await;

    core.handle_envelope(
        connection,
        subscribe_catalog_envelope("fresh-catalog-subscribe"),
    )
    .await
    .expect("start fresh catalog subscription");

    let subscribed = timeout(Duration::from_secs(2), receiver.recv())
        .await
        .expect("subscription receipt timeout")
        .expect("subscription receipt");
    assert!(matches!(
        decode(&subscribed).body,
        RuntimeMessage::Reply(RuntimeReply::Subscription(
            SubscriptionReceipt::Subscribed { .. }
        ))
    ));
    subscribed
        .acknowledge()
        .expect("flush subscription receipt");

    let snapshot = timeout(Duration::from_secs(2), receiver.recv())
        .await
        .expect("catalog snapshot timeout")
        .expect("catalog snapshot");
    assert!(matches!(
        decode(&snapshot).body,
        RuntimeMessage::Reply(RuntimeReply::Catalog(snapshot))
            if snapshot.base_catalog_cursor == StreamCursor::BeforeFirst
                && snapshot.entries().is_empty()
    ));
    snapshot.acknowledge().expect("flush catalog snapshot");

    let sync = timeout(Duration::from_secs(2), receiver.recv())
        .await
        .expect("catalog sync timeout")
        .expect("catalog sync");
    assert!(matches!(
        decode(&sync).body,
        RuntimeMessage::Reply(RuntimeReply::SyncComplete(_))
    ));
    sync.acknowledge().expect("flush catalog sync");

    core.disconnect(connection).await;
    core.shutdown().await.expect("shutdown core");
}

#[tokio::test]
async fn configure_applied_replay_and_conflict_have_exact_stream_effects() {
    // 威胁场景：Core 若自行广播 Configure，或 Store 把 Configure 当 catalog mutation，
    // exact replay/conflict 会制造重复 conversation event 或无关 CatalogDelta。
    let root = TestRoot::new("configure-exact-stream-effects");
    let core = core(&root).await;
    core.recover().await.expect("recover Configure stream core");
    let (conversation_connection, mut conversation_receiver) = connect_recording(&core, 0x90).await;
    let conversation = start_receipt(
        core.handle(
            conversation_connection,
            start_request("configure-stream-start"),
        )
        .await,
    );
    let conversation_id =
        parse_conversation_id(&conversation.conversation_id).expect("parse stream conversation");

    core.handle_envelope(
        conversation_connection,
        subscribe_conversation_envelope("configure-conversation-live", conversation_id),
    )
    .await
    .expect("subscribe Configure conversation");
    assert!(matches!(
        receive_envelope_and_ack(
            &mut conversation_receiver,
            "conversation subscription receipt"
        )
        .await
        .body,
        RuntimeMessage::Reply(RuntimeReply::Subscription(
            SubscriptionReceipt::Subscribed { .. }
        ))
    ));
    let initial_snapshot =
        receive_envelope_and_ack(&mut conversation_receiver, "conversation initial snapshot").await;
    assert!(matches!(
        initial_snapshot.body,
        RuntimeMessage::Reply(RuntimeReply::Snapshot(snapshot))
            if snapshot.base_event_cursor == StreamCursor::BeforeFirst
                && snapshot.configuration_state.configuration_revision() == 0
                && snapshot.configuration_state.configuration().is_none()
    ));
    assert!(matches!(
        receive_envelope_and_ack(&mut conversation_receiver, "conversation initial sync")
            .await
            .body,
        RuntimeMessage::Reply(RuntimeReply::SyncComplete(sync))
            if sync.inner_cursor == RuntimeInnerCursor::Conversation {
                conversation_id: conversation.conversation_id.clone(),
                cursor: StreamCursor::BeforeFirst,
            }
    ));

    let (catalog_connection, mut catalog_receiver) = connect_recording(&core, 0x91).await;
    core.handle_envelope(
        catalog_connection,
        subscribe_catalog_envelope("configure-catalog-live"),
    )
    .await
    .expect("subscribe Configure catalog");
    assert!(matches!(
        receive_envelope_and_ack(&mut catalog_receiver, "catalog subscription receipt")
            .await
            .body,
        RuntimeMessage::Reply(RuntimeReply::Subscription(
            SubscriptionReceipt::Subscribed { .. }
        ))
    ));
    assert!(matches!(
        receive_envelope_and_ack(&mut catalog_receiver, "catalog initial snapshot")
            .await
            .body,
        RuntimeMessage::Reply(RuntimeReply::Catalog(snapshot))
            if snapshot.entries().len() == 1
    ));
    assert!(matches!(
        receive_envelope_and_ack(&mut catalog_receiver, "catalog initial sync")
            .await
            .body,
        RuntimeMessage::Reply(RuntimeReply::SyncComplete(_))
    ));

    let configuration = codex_configuration(CodexReasoningEffort::High);
    let exact_request = ConfigureConversationRequest::new(
        conversation.conversation_id.clone(),
        IdempotencyKey::new("configure-stream-exact"),
        0,
        configuration.clone(),
    );
    assert!(matches!(
        core.handle(
            conversation_connection,
            RuntimeRequest::ConfigureConversation(exact_request.clone()),
        )
        .await,
        RuntimeReply::Configuration(ConfigurationReceipt::Applied {
            configuration_revision: 1,
            ..
        })
    ));
    let live =
        receive_envelope_and_ack(&mut conversation_receiver, "configuration live event").await;
    let RuntimeMessage::Stream(RuntimeStreamItem::Event(event)) = live.body else {
        panic!("Configure Applied must emit one conversation event")
    };
    assert_eq!(event.conversation_id, conversation.conversation_id);
    assert_eq!(event.event_seq, 0);
    assert!(event.command_id.is_none());
    assert!(event.item_id.is_none());
    assert!(event.entity_id.is_none());
    let RuntimeEventBody::ConfigurationChanged { state } = event.body else {
        panic!("Configure event must be ConfigurationChanged")
    };
    assert_eq!(state.configuration_revision(), 1);
    assert_eq!(state.configuration(), Some(&configuration));
    assert!(
        timeout(Duration::from_millis(100), conversation_receiver.recv())
            .await
            .is_err(),
        "Applied emitted more than one conversation event"
    );
    assert!(
        timeout(Duration::from_millis(100), catalog_receiver.recv())
            .await
            .is_err(),
        "Configure changed the catalog stream"
    );

    assert!(matches!(
        core.handle(
            conversation_connection,
            RuntimeRequest::ConfigureConversation(exact_request),
        )
        .await,
        RuntimeReply::Configuration(ConfigurationReceipt::Replayed {
            configuration_revision: 1,
            ..
        })
    ));
    assert!(matches!(
        core.handle(
            conversation_connection,
            RuntimeRequest::ConfigureConversation(ConfigureConversationRequest::new(
                conversation.conversation_id,
                IdempotencyKey::new("configure-stream-conflict"),
                0,
                codex_configuration(CodexReasoningEffort::Low),
            )),
        )
        .await,
        RuntimeReply::Configuration(ConfigurationReceipt::Conflict {
            current_configuration_revision: 1,
            ..
        })
    ));
    assert!(
        timeout(Duration::from_millis(100), conversation_receiver.recv())
            .await
            .is_err(),
        "replay or conflict emitted a conversation event"
    );
    assert!(
        timeout(Duration::from_millis(100), catalog_receiver.recv())
            .await
            .is_err(),
        "replay or conflict emitted a CatalogDelta"
    );

    core.disconnect(conversation_connection).await;
    core.disconnect(catalog_connection).await;
    core.shutdown()
        .await
        .expect("shutdown Configure stream core");
}

#[tokio::test]
async fn metadata_applied_emits_one_exact_catalog_delta_and_no_conversation_event() {
    // 威胁场景：metadata mutation 若复用 conversation event 或重复广播，Companion
    // 会把独立 entry/catalog revision 错当成 event_seq，并在 replay/conflict 时重复更新 UI。
    let root = TestRoot::new("metadata-exact-stream-effects");
    let core = core(&root).await;
    core.recover().await.expect("recover metadata stream core");
    let (conversation_connection, mut conversation_receiver) = connect_recording(&core, 0x94).await;
    let conversation = start_receipt(
        core.handle(
            conversation_connection,
            start_request("metadata-stream-start"),
        )
        .await,
    );
    let conversation_id =
        parse_conversation_id(&conversation.conversation_id).expect("parse metadata conversation");

    core.handle_envelope(
        conversation_connection,
        subscribe_conversation_envelope("metadata-conversation-live", conversation_id),
    )
    .await
    .expect("subscribe metadata conversation");
    assert!(matches!(
        receive_envelope_and_ack(
            &mut conversation_receiver,
            "metadata conversation subscription receipt"
        )
        .await
        .body,
        RuntimeMessage::Reply(RuntimeReply::Subscription(
            SubscriptionReceipt::Subscribed { .. }
        ))
    ));
    assert!(matches!(
        receive_envelope_and_ack(
            &mut conversation_receiver,
            "metadata conversation initial snapshot"
        )
        .await
        .body,
        RuntimeMessage::Reply(RuntimeReply::Snapshot(_))
    ));
    assert!(matches!(
        receive_envelope_and_ack(
            &mut conversation_receiver,
            "metadata conversation initial sync"
        )
        .await
        .body,
        RuntimeMessage::Reply(RuntimeReply::SyncComplete(_))
    ));

    let (catalog_connection, mut catalog_receiver) = connect_recording(&core, 0x95).await;
    core.handle_envelope(
        catalog_connection,
        subscribe_catalog_envelope("metadata-catalog-live"),
    )
    .await
    .expect("subscribe metadata catalog");
    assert!(matches!(
        receive_envelope_and_ack(
            &mut catalog_receiver,
            "metadata catalog subscription receipt"
        )
        .await
        .body,
        RuntimeMessage::Reply(RuntimeReply::Subscription(
            SubscriptionReceipt::Subscribed { .. }
        ))
    ));
    let initial_catalog =
        receive_envelope_and_ack(&mut catalog_receiver, "metadata catalog initial snapshot").await;
    let RuntimeMessage::Reply(RuntimeReply::Catalog(initial_snapshot)) = initial_catalog.body
    else {
        panic!("metadata catalog must start with a snapshot")
    };
    assert_eq!(initial_snapshot.base_catalog_cursor, StreamCursor::At(0));
    let [initial_entry] = initial_snapshot.entries() else {
        panic!("metadata fixture must contain exactly one catalog entry")
    };
    assert_eq!(initial_entry.conversation_id, conversation.conversation_id);
    assert_eq!(initial_entry.title.as_deref(), Some("core test"));
    assert!(!initial_entry.archived);
    assert_eq!(initial_entry.entry_revision, 0);
    let initial_last_active_ms = initial_entry.last_active_ms;
    assert!(matches!(
        receive_envelope_and_ack(&mut catalog_receiver, "metadata catalog initial sync")
            .await
            .body,
        RuntimeMessage::Reply(RuntimeReply::SyncComplete(sync))
            if sync.inner_cursor == RuntimeInnerCursor::Catalog {
                cursor: StreamCursor::At(0),
            }
    ));

    let exact_request = ConversationMetadataMutationRequest::new(
        conversation.conversation_id.clone(),
        IdempotencyKey::new("metadata-stream-exact"),
        0,
        ConversationMetadataMutation::SetArchived { archived: true },
    )
    .expect("valid metadata stream request");
    assert!(matches!(
        core.handle(
            conversation_connection,
            RuntimeRequest::UpdateConversationMetadata(exact_request.clone()),
        )
        .await,
        RuntimeReply::ConversationMetadata(ConversationMetadataReceipt::Applied {
            ref conversation_id,
            entry_revision: 1,
        }) if conversation_id == &conversation.conversation_id
    ));

    let live = receive_envelope_and_ack(&mut catalog_receiver, "metadata catalog delta").await;
    let RuntimeMessage::Stream(RuntimeStreamItem::CatalogDelta(delta)) = live.body else {
        panic!("metadata Applied must emit one CatalogDelta")
    };
    assert_eq!(delta.catalog_revision, 1);
    let [CatalogChange::Upserted { entry }] = delta.changes.as_slice() else {
        panic!("metadata delta must contain exactly one upsert")
    };
    assert_eq!(entry.conversation_id, conversation.conversation_id);
    assert_eq!(entry.agent_kind, AgentKind::Codex);
    assert_eq!(entry.title.as_deref(), Some("core test"));
    assert_eq!(
        entry.cwd.as_deref(),
        Some(Path::new("/tmp/agentdeck-core-test"))
    );
    assert_eq!(entry.last_active_ms, initial_last_active_ms);
    assert!(entry.archived);
    assert_eq!(entry.entry_revision, 1);
    assert!(
        timeout(Duration::from_millis(100), catalog_receiver.recv())
            .await
            .is_err(),
        "metadata Applied emitted more than one CatalogDelta"
    );
    assert!(
        timeout(Duration::from_millis(100), conversation_receiver.recv())
            .await
            .is_err(),
        "metadata Applied emitted a conversation event"
    );

    assert!(matches!(
        core.handle(
            conversation_connection,
            RuntimeRequest::UpdateConversationMetadata(exact_request),
        )
        .await,
        RuntimeReply::ConversationMetadata(ConversationMetadataReceipt::Replayed {
            ref conversation_id,
            entry_revision: 1,
        }) if conversation_id == &conversation.conversation_id
    ));
    assert!(matches!(
        core.handle(
            conversation_connection,
            RuntimeRequest::UpdateConversationMetadata(
                ConversationMetadataMutationRequest::new(
                    conversation.conversation_id.clone(),
                    IdempotencyKey::new("metadata-stream-conflict"),
                    0,
                    ConversationMetadataMutation::SetArchived { archived: false },
                )
                .expect("valid metadata conflict request"),
            ),
        )
        .await,
        RuntimeReply::ConversationMetadata(ConversationMetadataReceipt::Conflict {
            ref conversation_id,
            current_entry_revision: 1,
        }) if conversation_id == &conversation.conversation_id
    ));
    assert!(
        timeout(Duration::from_millis(100), catalog_receiver.recv())
            .await
            .is_err(),
        "metadata replay or conflict emitted a CatalogDelta"
    );
    assert!(
        timeout(Duration::from_millis(100), conversation_receiver.recv())
            .await
            .is_err(),
        "metadata replay or conflict emitted a conversation event"
    );

    core.disconnect(conversation_connection).await;
    core.disconnect(catalog_connection).await;
    core.shutdown()
        .await
        .expect("shutdown metadata stream core");
}

#[tokio::test]
async fn metadata_after_commit_unknown_notifies_once_and_exact_retry_replays() {
    // 威胁场景：metadata COMMIT 已成功但调用方只看到 unknown 时，Catalog 通知必须
    // 仍由 durable effects 发出一次；exact retry 只能读回账本，不能再广播或写 conversation event。
    let root = TestRoot::new("metadata-after-commit-unknown-stream");
    let store = RuntimeStoreHandle::open(
        crate::runtime::store::RuntimeStoreConfig::new(root.path.join("runtime.db"))
            .with_command_capacity(1_024)
            .with_fault_injector(Arc::new(FailMetadataAfterCommitOnce {
                armed: AtomicBool::new(true),
            })),
        root.kek(),
    )
    .await
    .expect("open metadata after-COMMIT unknown store");
    let router = Arc::new(AgentRouter::with_runtime_store(store.clone()));
    let core = Arc::new(RuntimeCore::new(store, router, [0xAA; 32]).expect("construct core"));
    core.recover()
        .await
        .expect("recover metadata after-COMMIT unknown core");

    let (conversation_connection, mut conversation_receiver) = connect_recording(&core, 0x96).await;
    let conversation = start_receipt(
        core.handle(
            conversation_connection,
            start_request("metadata-unknown-start"),
        )
        .await,
    );
    let conversation_id = parse_conversation_id(&conversation.conversation_id)
        .expect("parse metadata unknown-outcome conversation");
    core.handle_envelope(
        conversation_connection,
        subscribe_conversation_envelope("metadata-unknown-conversation", conversation_id),
    )
    .await
    .expect("subscribe conversation before unknown metadata Update");
    for label in [
        "metadata unknown conversation subscription receipt",
        "metadata unknown conversation snapshot",
        "metadata unknown conversation sync",
    ] {
        receive_envelope_and_ack(&mut conversation_receiver, label).await;
    }

    let (catalog_connection, mut catalog_receiver) = connect_recording(&core, 0x97).await;
    core.handle_envelope(
        catalog_connection,
        subscribe_catalog_envelope("metadata-unknown-catalog"),
    )
    .await
    .expect("subscribe catalog before unknown metadata Update");
    for label in [
        "metadata unknown catalog subscription receipt",
        "metadata unknown catalog snapshot",
        "metadata unknown catalog sync",
    ] {
        receive_envelope_and_ack(&mut catalog_receiver, label).await;
    }

    let request = ConversationMetadataMutationRequest::new(
        conversation.conversation_id.clone(),
        IdempotencyKey::new("metadata-unknown-exact"),
        0,
        ConversationMetadataMutation::SetArchived { archived: true },
    )
    .expect("valid metadata unknown-outcome request");
    assert!(matches!(
        core.handle(
            conversation_connection,
            RuntimeRequest::UpdateConversationMetadata(request.clone()),
        )
        .await,
        RuntimeReply::ConversationMetadata(ConversationMetadataReceipt::Failed {
            failure: RuntimeFailure { code, .. }
        }) if code == "daemon.runtime.store_unavailable"
    ));

    let live =
        receive_envelope_and_ack(&mut catalog_receiver, "metadata unknown catalog delta").await;
    let RuntimeMessage::Stream(RuntimeStreamItem::CatalogDelta(delta)) = live.body else {
        panic!("committed metadata unknown outcome must emit one CatalogDelta")
    };
    assert_eq!(delta.catalog_revision, 1);
    let [CatalogChange::Upserted { entry }] = delta.changes.as_slice() else {
        panic!("metadata unknown delta must contain exactly one upsert")
    };
    assert_eq!(entry.conversation_id, conversation.conversation_id);
    assert_eq!(entry.entry_revision, 1);
    assert!(entry.archived);
    assert!(
        timeout(Duration::from_millis(100), catalog_receiver.recv())
            .await
            .is_err(),
        "metadata after-COMMIT unknown emitted duplicate CatalogDelta"
    );
    assert!(
        timeout(Duration::from_millis(100), conversation_receiver.recv())
            .await
            .is_err(),
        "metadata after-COMMIT unknown emitted a conversation event"
    );

    assert!(matches!(
        core.handle(
            conversation_connection,
            RuntimeRequest::UpdateConversationMetadata(request),
        )
        .await,
        RuntimeReply::ConversationMetadata(ConversationMetadataReceipt::Replayed {
            entry_revision: 1,
            ..
        })
    ));
    assert!(
        timeout(Duration::from_millis(100), catalog_receiver.recv())
            .await
            .is_err(),
        "metadata exact retry emitted a second CatalogDelta"
    );
    assert!(
        timeout(Duration::from_millis(100), conversation_receiver.recv())
            .await
            .is_err(),
        "metadata exact retry emitted a conversation event"
    );

    core.disconnect(conversation_connection).await;
    core.disconnect(catalog_connection).await;
    core.shutdown()
        .await
        .expect("shutdown metadata after-COMMIT unknown core");
}

#[tokio::test]
async fn reconnect_uses_frozen_snapshot_then_configuration_backfill() {
    // 威胁场景：重连若用 current configuration 覆盖旧 snapshot，客户端随后再应用
    // ConfigurationChanged backfill 会重复或跳过 revision，失去 cursor 一致性。
    let root = TestRoot::new("configure-reconnect-snapshot-backfill");
    let core = core(&root).await;
    core.recover().await.expect("recover reconnect core");
    let (initial_connection, mut initial_receiver) = connect_recording(&core, 0x92).await;
    let conversation = start_receipt(
        core.handle(
            initial_connection,
            start_request("configure-reconnect-start"),
        )
        .await,
    );
    let conversation_id =
        parse_conversation_id(&conversation.conversation_id).expect("parse reconnect conversation");
    core.handle_envelope(
        initial_connection,
        subscribe_conversation_envelope("configure-reconnect-baseline", conversation_id),
    )
    .await
    .expect("subscribe reconnect baseline");
    assert!(matches!(
        receive_envelope_and_ack(&mut initial_receiver, "baseline subscription receipt")
            .await
            .body,
        RuntimeMessage::Reply(RuntimeReply::Subscription(
            SubscriptionReceipt::Subscribed { .. }
        ))
    ));
    assert!(matches!(
        receive_envelope_and_ack(&mut initial_receiver, "baseline snapshot")
            .await
            .body,
        RuntimeMessage::Reply(RuntimeReply::Snapshot(snapshot))
            if snapshot.base_event_cursor == StreamCursor::BeforeFirst
                && snapshot.configuration_state.configuration_revision() == 0
                && snapshot.configuration_state.configuration().is_none()
    ));
    assert!(matches!(
        receive_envelope_and_ack(&mut initial_receiver, "baseline sync")
            .await
            .body,
        RuntimeMessage::Reply(RuntimeReply::SyncComplete(_))
    ));
    core.disconnect(initial_connection).await;

    let configuration_connection = connect_local(&core, 0x93).await;
    assert!(matches!(
        core.handle(
            configuration_connection,
            RuntimeRequest::ConfigureConversation(ConfigureConversationRequest::new(
                conversation.conversation_id.clone(),
                IdempotencyKey::new("configure-reconnect-rev1"),
                0,
                codex_configuration(CodexReasoningEffort::High),
            )),
        )
        .await,
        RuntimeReply::Configuration(ConfigurationReceipt::Applied {
            configuration_revision: 1,
            ..
        })
    ));

    let (reconnect, mut reconnect_receiver) = connect_recording(&core, 0x94).await;
    core.handle_envelope(
        reconnect,
        subscribe_conversation_envelope("configure-reconnect-current", conversation_id),
    )
    .await
    .expect("subscribe after offline Configure");
    assert!(matches!(
        receive_envelope_and_ack(&mut reconnect_receiver, "reconnect subscription receipt")
            .await
            .body,
        RuntimeMessage::Reply(RuntimeReply::Subscription(
            SubscriptionReceipt::Subscribed { .. }
        ))
    ));
    assert!(matches!(
        receive_envelope_and_ack(&mut reconnect_receiver, "reconnect frozen snapshot")
            .await
            .body,
        RuntimeMessage::Reply(RuntimeReply::Snapshot(snapshot))
            if snapshot.base_event_cursor == StreamCursor::BeforeFirst
                && snapshot.configuration_state.configuration_revision() == 0
                && snapshot.configuration_state.configuration().is_none()
    ));
    let backfill = receive_envelope_and_ack(&mut reconnect_receiver, "reconnect backfill").await;
    let RuntimeMessage::Reply(RuntimeReply::Backfill(BackfillChunk::Conversation {
        conversation_id: backfill_conversation,
        range,
        events,
        ..
    })) = backfill.body
    else {
        panic!("reconnect must backfill ConfigurationChanged after the frozen snapshot")
    };
    assert_eq!(backfill_conversation, conversation.conversation_id);
    assert_eq!(range.after(), StreamCursor::BeforeFirst);
    assert_eq!(range.through(), StreamCursor::At(0));
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_seq, 0);
    assert_eq!(events[0].conversation_id, conversation.conversation_id);
    assert!(matches!(
        &events[0].body,
        RuntimeEventBody::ConfigurationChanged { state }
            if state.configuration_revision() == 1
                && state.configuration().is_some()
    ));
    let sync = receive_envelope_and_ack(&mut reconnect_receiver, "reconnect sync").await;
    assert!(matches!(
        sync.body,
        RuntimeMessage::Reply(RuntimeReply::SyncComplete(sync))
            if sync.inner_cursor == RuntimeInnerCursor::Conversation {
                conversation_id: conversation.conversation_id.clone(),
                cursor: StreamCursor::At(0),
            }
    ));

    core.disconnect(configuration_connection).await;
    core.disconnect(reconnect).await;
    core.shutdown().await.expect("shutdown reconnect core");
}

#[tokio::test]
async fn configure_after_commit_unknown_notifies_once_and_exact_retry_replays() {
    // 威胁场景：COMMIT 成功但 reply 变成 unknown 时，通知若依赖成功返回会丢事件；
    // 若 retry 再广播，则客户端会看到同一 durable revision 两次。
    let root = TestRoot::new("configure-after-commit-unknown-stream");
    let store = RuntimeStoreHandle::open(
        crate::runtime::store::RuntimeStoreConfig::new(root.path.join("runtime.db"))
            .with_command_capacity(1_024)
            .with_fault_injector(Arc::new(FailConfigureAfterCommitOnce {
                armed: AtomicBool::new(true),
            })),
        root.kek(),
    )
    .await
    .expect("open after-COMMIT unknown store");
    let router = Arc::new(AgentRouter::with_runtime_store(store.clone()));
    let core = Arc::new(RuntimeCore::new(store, router, [0xA7; 32]).expect("construct core"));
    core.recover()
        .await
        .expect("recover after-COMMIT unknown core");
    let (connection, mut receiver) = connect_recording(&core, 0x95).await;
    let conversation = start_receipt(
        core.handle(connection, start_request("configure-unknown-start"))
            .await,
    );
    let conversation_id = parse_conversation_id(&conversation.conversation_id)
        .expect("parse unknown-outcome conversation");
    core.handle_envelope(
        connection,
        subscribe_conversation_envelope("configure-unknown-live", conversation_id),
    )
    .await
    .expect("subscribe before unknown Configure");
    for label in [
        "unknown subscription receipt",
        "unknown snapshot",
        "unknown sync",
    ] {
        receive_envelope_and_ack(&mut receiver, label).await;
    }

    let request = ConfigureConversationRequest::new(
        conversation.conversation_id.clone(),
        IdempotencyKey::new("configure-unknown-exact"),
        0,
        codex_configuration(CodexReasoningEffort::Medium),
    );
    assert!(matches!(
        core.handle(
            connection,
            RuntimeRequest::ConfigureConversation(request.clone()),
        )
        .await,
        RuntimeReply::Configuration(ConfigurationReceipt::Failed {
            failure: RuntimeFailure { code, .. }
        }) if code == "daemon.runtime.store_unavailable"
    ));
    let live = receive_envelope_and_ack(&mut receiver, "unknown committed event").await;
    assert!(matches!(
        live.body,
        RuntimeMessage::Stream(RuntimeStreamItem::Event(RuntimeEvent {
            event_seq: 0,
            body: RuntimeEventBody::ConfigurationChanged { ref state },
            ..
        })) if state.configuration_revision() == 1
    ));
    assert!(
        timeout(Duration::from_millis(100), receiver.recv())
            .await
            .is_err(),
        "after-COMMIT unknown emitted duplicate live events"
    );
    assert!(matches!(
        core.handle(connection, RuntimeRequest::ConfigureConversation(request),)
            .await,
        RuntimeReply::Configuration(ConfigurationReceipt::Replayed {
            configuration_revision: 1,
            ..
        })
    ));
    assert!(
        timeout(Duration::from_millis(100), receiver.recv())
            .await
            .is_err(),
        "exact retry emitted a second ConfigurationChanged"
    );
    let durable = core
        .store
        .load_configuration_state_at_event_cursor(conversation_id, Some(0))
        .await
        .expect("read durable unknown-outcome configuration");
    assert_eq!(durable.configuration_revision(), 1);

    core.disconnect(connection).await;
    core.shutdown()
        .await
        .expect("shutdown after-COMMIT unknown core");
}

#[tokio::test]
async fn sync_complete_cannot_overtake_snapshot_transfer_completion() {
    let root = TestRoot::new("subscription-transfer-before-sync");
    let core = core(&root).await;
    core.recover().await.expect("recover core");
    let created = catalog_conversation(0x58);
    let conversation_id = created.conversation_id;
    core.store
        .create_conversation(created)
        .await
        .expect("create large snapshot conversation");
    store_ready_snapshot_with_text_bytes(&core, conversation_id, MAX_JSON_PART_BYTES + 4096).await;
    let (connection, mut receiver) = connect_recording(&core, 0x7B).await;

    core.handle_envelope(
        connection,
        subscribe_conversation_envelope("large-snapshot-subscribe", conversation_id),
    )
    .await
    .expect("start large snapshot subscription");
    let receipt = timeout(Duration::from_secs(2), receiver.recv())
        .await
        .expect("large snapshot receipt timeout")
        .expect("large snapshot receipt");
    assert!(matches!(
        decode(&receipt).body,
        RuntimeMessage::Reply(RuntimeReply::Subscription(
            SubscriptionReceipt::Subscribed { .. }
        ))
    ));
    receipt.acknowledge().expect("flush subscription receipt");

    let first = timeout(Duration::from_secs(2), receiver.recv())
        .await
        .expect("first snapshot transfer part timeout")
        .expect("first snapshot transfer part");
    let first_envelope = decode(&first);
    let RuntimeMessage::Reply(RuntimeReply::TransferPart(first_part)) = first_envelope.body else {
        panic!("large snapshot must use the real paced transfer path");
    };
    assert!(first_part.part_count > 1);
    let part_count = first_part.part_count;
    let mut assembled = Vec::with_capacity(first_part.total_bytes as usize);
    let mut current = Some((first, first_part));
    for expected_index in 0..part_count {
        let (write, part) = if let Some(first) = current.take() {
            first
        } else {
            let write = timeout(Duration::from_secs(2), receiver.recv())
                .await
                .expect("next snapshot transfer part timeout")
                .expect("next snapshot transfer part");
            let envelope = decode(&write);
            let RuntimeMessage::Reply(RuntimeReply::TransferPart(part)) = envelope.body else {
                panic!("SyncComplete overtook an unfinished snapshot transfer");
            };
            (write, part)
        };
        assert_eq!(part.part_index, expected_index);
        assert_eq!(part.part_count, part_count);
        assembled.extend_from_slice(&part.part);
        assert!(
            receiver.try_recv().is_err(),
            "next part or SyncComplete overtook the current FlushReceipt"
        );
        write.acknowledge().expect("flush snapshot transfer part");
    }
    let decoded: ConversationSnapshot =
        serde_json::from_slice(&assembled).expect("reassemble canonical snapshot");
    assert_eq!(decoded.items().len(), 2);

    let sync = timeout(Duration::from_secs(2), receiver.recv())
        .await
        .expect("SyncComplete timeout after final transfer flush")
        .expect("SyncComplete after final transfer flush");
    assert!(matches!(
        decode(&sync).body,
        RuntimeMessage::Reply(RuntimeReply::SyncComplete(_))
    ));
    sync.acknowledge().expect("flush SyncComplete");

    core.disconnect(connection).await;
    core.shutdown().await.expect("shutdown core");
}

#[tokio::test]
async fn unacked_conversation_snapshot_holds_global_build_budget_until_flush() {
    // 威胁场景：默认并发回归同时运行多份真实大快照时，纯测试 harness 的短 deadline
    // 会在预算不变量尚未被观察前误杀用例；该 deadline 只约束死锁，不是产品延迟承诺。
    const REAL_SNAPSHOT_BUILD_TIMEOUT: Duration = Duration::from_secs(120);
    let root = TestRoot::new("subscription-global-snapshot-build-budget");
    let first_command =
        RuntimeId::from_bytes(RuntimeIdKind::Command, [0x61; 16]).expect("first command id");
    let first_turn = RuntimeId::from_bytes(RuntimeIdKind::Turn, [0x62; 16]).expect("first turn id");
    let first_event =
        RuntimeId::from_bytes(RuntimeIdKind::Event, [0x63; 16]).expect("first event id");
    let first_configuration_event = RuntimeId::from_bytes(RuntimeIdKind::Event, [0x60; 16])
        .expect("first configuration event id");
    let second_command =
        RuntimeId::from_bytes(RuntimeIdKind::Command, [0x64; 16]).expect("second command id");
    let second_turn =
        RuntimeId::from_bytes(RuntimeIdKind::Turn, [0x65; 16]).expect("second turn id");
    let second_event =
        RuntimeId::from_bytes(RuntimeIdKind::Event, [0x66; 16]).expect("second event id");
    let second_configuration_event = RuntimeId::from_bytes(RuntimeIdKind::Event, [0x6A; 16])
        .expect("second configuration event id");
    let store = RuntimeStoreHandle::open(
        crate::runtime::store::RuntimeStoreConfig::new(root.path.join("runtime.db"))
            .with_command_capacity(1_024)
            .with_id_source(SequenceIdSource::new([
                publication_axis_id(0xA0),
                publication_axis_id(0xA1),
                publication_axis_id(0xA2),
                publication_axis_id(0xA3),
                publication_axis_id(0xA4),
                publication_axis_id(0xA5),
                first_configuration_event,
                first_command,
                first_turn,
                first_event,
                second_configuration_event,
                second_command,
                second_turn,
                second_event,
            ])),
        root.kek(),
    )
    .await
    .expect("open deterministic snapshot budget store");
    let router = Arc::new(AgentRouter::with_runtime_store(store.clone()));
    let core = Arc::new(
        RuntimeCore::new(store, router, [0xA1; 32]).expect("construct snapshot budget core"),
    );
    core.recover().await.expect("recover snapshot budget core");

    let first_input = catalog_conversation(0x67);
    let first_conversation = first_input.conversation_id;
    let second_input = catalog_conversation(0x69);
    let second_conversation = second_input.conversation_id;
    core.store
        .create_conversation(first_input)
        .await
        .expect("create first build conversation");
    core.store
        .create_conversation(second_input)
        .await
        .expect("create second build conversation");
    append_large_snapshot_event(
        &core,
        first_conversation,
        first_command,
        first_turn,
        first_event,
        0x71,
        33 * 1024 * 1024,
    )
    .await;
    append_large_snapshot_event(
        &core,
        second_conversation,
        second_command,
        second_turn,
        second_event,
        0x73,
        33 * 1024 * 1024,
    )
    .await;

    let (first_connection, mut first_receiver) = connect_recording(&core, 0x85).await;
    let (second_connection, mut second_receiver) = connect_recording(&core, 0x86).await;
    core.handle_envelope(
        first_connection,
        subscribe_conversation_envelope("first-build-snapshot", first_conversation),
    )
    .await
    .expect("start first build snapshot");
    let first_receipt = timeout(Duration::from_secs(2), first_receiver.recv())
        .await
        .expect("first subscription receipt timeout")
        .expect("first subscription receipt");
    assert!(matches!(
        decode(&first_receipt).body,
        RuntimeMessage::Reply(RuntimeReply::Subscription(
            SubscriptionReceipt::Subscribed { .. }
        ))
    ));
    first_receipt
        .acknowledge()
        .expect("flush first subscription receipt");
    // 这个用例故意走真实 33 MiB snapshot 的解密、归约、canonical 编码与持久化，
    // 首个 part 的准备时间不应沿用小 fixture 的 2 秒交互超时。
    let first_part_write = timeout(REAL_SNAPSHOT_BUILD_TIMEOUT, first_receiver.recv())
        .await
        .expect("first build TransferPart timeout")
        .expect("first build TransferPart");
    let RuntimeMessage::Reply(RuntimeReply::TransferPart(first_part)) =
        decode(&first_part_write).body
    else {
        panic!("first build snapshot must enter real TransferPart egress")
    };
    assert_eq!(first_part.part_index, 0);
    assert!(first_part.part_count > 1);

    core.handle_envelope(
        second_connection,
        subscribe_conversation_envelope("second-build-snapshot", second_conversation),
    )
    .await
    .expect("start second build snapshot");
    let second_receipt = timeout(Duration::from_secs(2), second_receiver.recv())
        .await
        .expect("second subscription receipt timeout")
        .expect("second subscription receipt");
    assert!(matches!(
        decode(&second_receipt).body,
        RuntimeMessage::Reply(RuntimeReply::Subscription(
            SubscriptionReceipt::Subscribed { .. }
        ))
    ));
    second_receipt
        .acknowledge()
        .expect("flush second subscription receipt");

    assert!(
        timeout(Duration::from_millis(100), second_receiver.recv())
            .await
            .is_err(),
        "second connection materialized while the first FlushReceipt retained the global budget"
    );
    // 第二个 build 此时可能正在占用 Runtime read lane 读取 33 MiB event page；
    // 用独立只读 WAL connection 核对 durable row count，避免把预期的 WorkerBusy
    // 当成预算语义。第一份已落盘，第二份若越过预算这里就会变成 2。
    let raw = rusqlite::Connection::open_with_flags(
        root.path.join("runtime.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("open independent read-only snapshot probe");
    let durable_snapshot_count: i64 = raw
        .query_row("SELECT COUNT(*) FROM snapshots", [], |row| row.get(0))
        .expect("count durable snapshots while second build is blocked");
    assert_eq!(
        durable_snapshot_count, 1,
        "second build reached durable materialization before the first transfer flushed"
    );
    drop(raw);

    let part_count = first_part.part_count;
    let mut current = Some((first_part_write, first_part));
    for expected_index in 0..part_count {
        let (write, part) = if let Some(first) = current.take() {
            first
        } else {
            let write = timeout(Duration::from_secs(2), first_receiver.recv())
                .await
                .expect("next first build TransferPart timeout")
                .expect("next first build TransferPart");
            let RuntimeMessage::Reply(RuntimeReply::TransferPart(part)) = decode(&write).body
            else {
                panic!("first SyncComplete overtook snapshot transfer")
            };
            (write, part)
        };
        assert_eq!(part.part_index, expected_index);
        assert!(
            second_receiver.try_recv().is_err(),
            "second materialization advanced before first part {expected_index} flushed"
        );
        write.acknowledge().expect("flush first build TransferPart");
    }

    let second_part_write = timeout(REAL_SNAPSHOT_BUILD_TIMEOUT, second_receiver.recv())
        .await
        .expect("second build must resume after first transfer flush")
        .expect("second build TransferPart after budget release");
    assert!(matches!(
        decode(&second_part_write).body,
        RuntimeMessage::Reply(RuntimeReply::TransferPart(ref part)) if part.part_index == 0
    ));
    assert!(
        core.store
            .load_conversation_snapshot(second_conversation)
            .await
            .expect("load second durable snapshot after budget release")
            .is_some(),
        "second build did not materialize after the first FlushReceipt released the budget"
    );

    let first_sync = timeout(Duration::from_secs(2), first_receiver.recv())
        .await
        .expect("first SyncComplete timeout")
        .expect("first SyncComplete");
    assert!(matches!(
        decode(&first_sync).body,
        RuntimeMessage::Reply(RuntimeReply::SyncComplete(_))
    ));
    first_sync.acknowledge().expect("flush first SyncComplete");

    core.disconnect(first_connection).await;
    core.disconnect(second_connection).await;
    drop(second_part_write);
    core.shutdown()
        .await
        .expect("shutdown snapshot budget core");
}

#[tokio::test]
async fn regular_near_limit_backfill_pages_charge_dto_and_payload_in_one_pool() {
    let root = TestRoot::new("regular-backfill-combined-read-budget");
    let command_id = RuntimeId::from_bytes(RuntimeIdKind::Command, [0x81; 16]).expect("command id");
    let turn_id = RuntimeId::from_bytes(RuntimeIdKind::Turn, [0x82; 16]).expect("turn id");
    let event_id = RuntimeId::from_bytes(RuntimeIdKind::Event, [0x83; 16]).expect("event id");
    let configuration_event =
        RuntimeId::from_bytes(RuntimeIdKind::Event, [0x80; 16]).expect("configuration event id");
    let store = RuntimeStoreHandle::open(
        crate::runtime::store::RuntimeStoreConfig::new(root.path.join("runtime.db"))
            .with_command_capacity(1_024)
            .with_id_source(SequenceIdSource::new([
                publication_axis_id(0xA0),
                publication_axis_id(0xA1),
                publication_axis_id(0xA2),
                configuration_event,
                command_id,
                turn_id,
                event_id,
            ])),
        root.kek(),
    )
    .await
    .expect("open deterministic regular backfill store");
    let router = Arc::new(AgentRouter::with_runtime_store(store.clone()));
    let core = Arc::new(
        RuntimeCore::new(store, router, [0xA1; 32]).expect("construct regular backfill core"),
    );
    core.recover().await.expect("recover regular backfill core");

    let input = catalog_conversation(0x84);
    let conversation_id = input.conversation_id;
    core.store
        .create_conversation(input)
        .await
        .expect("create regular backfill conversation");
    append_large_snapshot_event(
        &core,
        conversation_id,
        command_id,
        turn_id,
        event_id,
        0x85,
        7 * 1024 * 1024,
    )
    .await;

    let RuntimeBackfillPlan::Pinned(pin) = core
        .store
        .acquire_backfill_pin(
            RuntimeBackfillTarget::Conversation(conversation_id),
            Some(1),
        )
        .await
        .expect("pin regular near-limit backfill")
    else {
        panic!("event one must produce a regular pinned page")
    };
    let mut held = Vec::new();
    for _ in 0..8 {
        let page = core
            .store
            .load_event_backfill_page(pin.clone(), Some(1))
            .await
            .expect("eight DTO+payload leases fit the shared 128 MiB pool");
        assert_eq!(page.events.len(), 1);
        held.push(page);
    }
    assert!(matches!(
        core.store
            .load_event_backfill_page(pin.clone(), Some(1))
            .await,
        Err(RuntimeStoreError::WorkerBusy {
            lane: RuntimeStoreLane::Read
        })
    ));

    drop(held.pop());
    let replacement = core
        .store
        .load_event_backfill_page(pin.clone(), Some(1))
        .await
        .expect("dropping one slow page returns exactly one combined lease");
    drop(replacement);
    drop(held);
    core.store
        .release_backfill_pin(pin.pin_id)
        .await
        .expect("release regular backfill pin");
    core.shutdown()
        .await
        .expect("shutdown regular backfill core");
}

#[tokio::test]
async fn oversized_backfill_payload_holds_exclusive_read_lease_until_flush_and_cancel() {
    let root = TestRoot::new("oversized-backfill-egress-lease");
    let command_id = RuntimeId::from_bytes(RuntimeIdKind::Command, [0x91; 16]).expect("command id");
    let turn_id = RuntimeId::from_bytes(RuntimeIdKind::Turn, [0x92; 16]).expect("turn id");
    let event_id = RuntimeId::from_bytes(RuntimeIdKind::Event, [0x93; 16]).expect("event id");
    let configuration_event =
        RuntimeId::from_bytes(RuntimeIdKind::Event, [0x90; 16]).expect("configuration event id");
    let store = RuntimeStoreHandle::open(
        crate::runtime::store::RuntimeStoreConfig::new(root.path.join("runtime.db"))
            .with_command_capacity(1_024)
            .with_id_source(SequenceIdSource::new([
                publication_axis_id(0xA0),
                publication_axis_id(0xA1),
                publication_axis_id(0xA2),
                configuration_event,
                command_id,
                turn_id,
                event_id,
            ])),
        root.kek(),
    )
    .await
    .expect("open deterministic oversized backfill store");
    let router = Arc::new(AgentRouter::with_runtime_store(store.clone()));
    let core = Arc::new(
        RuntimeCore::new(store, router, [0xA1; 32]).expect("construct oversized backfill core"),
    );
    core.recover()
        .await
        .expect("recover oversized backfill core");

    let input = catalog_conversation(0x94);
    let conversation_id = input.conversation_id;
    core.store
        .create_conversation(input)
        .await
        .expect("create oversized backfill conversation");
    append_large_snapshot_event(
        &core,
        conversation_id,
        command_id,
        turn_id,
        event_id,
        0x95,
        9 * 1024 * 1024,
    )
    .await;

    let (connection, mut receiver) = connect_recording(&core, 0x97).await;
    core.handle_envelope(
        connection,
        conversation_backfill_after_envelope(
            "oversized-backfill-flush",
            conversation_id,
            StreamCursor::At(1),
        ),
    )
    .await
    .expect("start oversized directed backfill");
    let first_write = timeout(Duration::from_secs(30), receiver.recv())
        .await
        .expect("first oversized TransferPart timeout")
        .expect("first oversized TransferPart");
    let RuntimeMessage::Reply(RuntimeReply::TransferPart(first_part)) = decode(&first_write).body
    else {
        panic!("oversized backfill must use TransferPart")
    };
    assert_eq!(first_part.part_index, 0);
    assert!(first_part.part_count > 1);

    let RuntimeBackfillPlan::Pinned(probe_pin) = core
        .store
        .acquire_backfill_pin(
            RuntimeBackfillTarget::Conversation(conversation_id),
            Some(1),
        )
        .await
        .expect("acquire competing oversized probe pin")
    else {
        panic!("event one must produce a pinned probe")
    };
    assert!(matches!(
        core.store
            .load_event_backfill_page(probe_pin.clone(), Some(1))
            .await,
        Err(RuntimeStoreError::WorkerBusy {
            lane: RuntimeStoreLane::Read
        })
    ));

    let part_count = first_part.part_count;
    let mut current = Some((first_write, first_part));
    for expected_index in 0..part_count {
        let (write, part) = if let Some(first) = current.take() {
            first
        } else {
            let write = timeout(Duration::from_secs(5), receiver.recv())
                .await
                .expect("next oversized TransferPart timeout")
                .expect("next oversized TransferPart");
            let RuntimeMessage::Reply(RuntimeReply::TransferPart(part)) = decode(&write).body
            else {
                panic!("SyncComplete overtook oversized backfill")
            };
            (write, part)
        };
        assert_eq!(part.part_index, expected_index);
        write
            .acknowledge()
            .expect("flush oversized backfill TransferPart");
    }
    let sync = timeout(Duration::from_secs(5), receiver.recv())
        .await
        .expect("oversized backfill SyncComplete timeout")
        .expect("oversized backfill SyncComplete");
    assert!(matches!(
        decode(&sync).body,
        RuntimeMessage::Reply(RuntimeReply::SyncComplete(_))
    ));

    let replayed = core
        .store
        .load_event_backfill_page(probe_pin.clone(), Some(1))
        .await
        .expect("final FlushReceipt releases the oversized read lease");
    assert_eq!(replayed.events.len(), 1);
    drop(replayed);
    core.store
        .release_backfill_pin(probe_pin.pin_id)
        .await
        .expect("release flush probe pin");
    sync.acknowledge().expect("flush SyncComplete");
    core.disconnect(connection).await;

    let (cancelled_connection, mut cancelled_receiver) = connect_recording(&core, 0x98).await;
    core.handle_envelope(
        cancelled_connection,
        conversation_backfill_after_envelope(
            "oversized-backfill-cancel",
            conversation_id,
            StreamCursor::At(1),
        ),
    )
    .await
    .expect("start cancellable oversized backfill");
    let held = timeout(Duration::from_secs(30), cancelled_receiver.recv())
        .await
        .expect("cancellable oversized TransferPart timeout")
        .expect("cancellable oversized TransferPart");
    assert!(matches!(
        decode(&held).body,
        RuntimeMessage::Reply(RuntimeReply::TransferPart(ref part)) if part.part_index == 0
    ));
    let RuntimeBackfillPlan::Pinned(cancel_probe) = core
        .store
        .acquire_backfill_pin(
            RuntimeBackfillTarget::Conversation(conversation_id),
            Some(1),
        )
        .await
        .expect("acquire cancellation probe pin")
    else {
        panic!("event one must produce a cancellation probe")
    };
    assert!(matches!(
        core.store
            .load_event_backfill_page(cancel_probe.clone(), Some(1))
            .await,
        Err(RuntimeStoreError::WorkerBusy {
            lane: RuntimeStoreLane::Read
        })
    ));
    timeout(
        Duration::from_secs(5),
        core.disconnect(cancelled_connection),
    )
    .await
    .expect("disconnect cancels an unflushed oversized backfill");
    drop(held);
    let replayed = core
        .store
        .load_event_backfill_page(cancel_probe.clone(), Some(1))
        .await
        .expect("cancellation releases the oversized read lease");
    assert_eq!(replayed.events.len(), 1);
    drop(replayed);
    core.store
        .release_backfill_pin(cancel_probe.pin_id)
        .await
        .expect("release cancellation probe pin");

    core.shutdown()
        .await
        .expect("shutdown oversized backfill core");
}

#[tokio::test]
async fn slow_snapshot_reader_lags_only_its_connection_and_never_blocks_actor() {
    let root = TestRoot::new("subscription-slow-reader-isolation");
    let core = core(&root).await;
    core.recover().await.expect("recover core");
    let (slow_connection, mut slow_receiver) = connect_recording(&core, 0x7C).await;
    let (fast_connection, mut fast_receiver) = connect_recording(&core, 0x7D).await;

    core.handle_envelope(
        slow_connection,
        subscribe_catalog_envelope("slow-catalog-subscribe"),
    )
    .await
    .expect("start slow catalog subscription");
    let slow_receipt = timeout(Duration::from_secs(2), slow_receiver.recv())
        .await
        .expect("slow receipt timeout")
        .expect("slow receipt");
    slow_receipt
        .acknowledge()
        .expect("flush slow subscription receipt");
    let slow_snapshot = timeout(Duration::from_secs(2), slow_receiver.recv())
        .await
        .expect("slow snapshot timeout")
        .expect("slow snapshot");
    assert!(matches!(
        decode(&slow_snapshot).body,
        RuntimeMessage::Reply(RuntimeReply::Catalog(_))
    ));

    core.handle_envelope(
        fast_connection,
        subscribe_catalog_envelope("fast-catalog-subscribe"),
    )
    .await
    .expect("start independent fast catalog subscription");
    let fast_receipt = timeout(Duration::from_secs(2), fast_receiver.recv())
        .await
        .expect("fast receipt timeout")
        .expect("fast receipt");
    fast_receipt
        .acknowledge()
        .expect("flush fast subscription receipt");
    let fast_snapshot = timeout(Duration::from_secs(2), fast_receiver.recv())
        .await
        .expect("fast snapshot must not wait for slow connection")
        .expect("fast snapshot");
    assert!(matches!(
        decode(&fast_snapshot).body,
        RuntimeMessage::Reply(RuntimeReply::Catalog(_))
    ));
    fast_snapshot.acknowledge().expect("flush fast snapshot");
    let fast_sync = timeout(Duration::from_secs(2), fast_receiver.recv())
        .await
        .expect("fast SyncComplete must not wait for slow connection")
        .expect("fast SyncComplete");
    assert!(matches!(
        decode(&fast_sync).body,
        RuntimeMessage::Reply(RuntimeReply::SyncComplete(_))
    ));
    fast_sync.acknowledge().expect("flush fast SyncComplete");

    timeout(
        Duration::from_secs(2),
        core.store.create_conversation(catalog_conversation(0x59)),
    )
    .await
    .expect("slow writer must not block the store actor")
    .expect("commit catalog mutation while slow snapshot is unflushed");
    let fast_live = timeout(Duration::from_secs(2), fast_receiver.recv())
        .await
        .expect("fast connection must receive live delta")
        .expect("fast live delta");
    assert!(matches!(
        decode(&fast_live).body,
        RuntimeMessage::Stream(RuntimeStreamItem::CatalogDelta(_))
    ));
    fast_live.acknowledge().expect("flush fast live delta");
    assert!(
        slow_receiver.try_recv().is_err(),
        "slow connection advanced past its own unflushed snapshot"
    );

    slow_snapshot.acknowledge().expect("release slow snapshot");
    let slow_sync = timeout(Duration::from_secs(2), slow_receiver.recv())
        .await
        .expect("slow SyncComplete timeout")
        .expect("slow SyncComplete");
    assert!(matches!(
        decode(&slow_sync).body,
        RuntimeMessage::Reply(RuntimeReply::SyncComplete(_))
    ));
    slow_sync.acknowledge().expect("flush slow SyncComplete");
    let slow_live = timeout(Duration::from_secs(2), slow_receiver.recv())
        .await
        .expect("slow connection must catch up after its own ACK")
        .expect("slow catch-up delta");
    assert!(matches!(
        decode(&slow_live).body,
        RuntimeMessage::Stream(RuntimeStreamItem::CatalogDelta(_))
    ));
    slow_live.acknowledge().expect("flush slow catch-up delta");

    core.disconnect(slow_connection).await;
    core.disconnect(fast_connection).await;
    core.shutdown().await.expect("shutdown core");
}

#[tokio::test]
async fn catalog_subscription_flushes_all_501_rows_before_sync_complete() {
    let root = TestRoot::new("subscription-catalog-501-pages");
    let core = core(&root).await;
    core.recover().await.expect("recover core");
    create_indexed_catalog_rows(&core, 0, 501).await;
    let (connection, mut receiver) = connect_recording(&core, 0x7A).await;

    core.handle_envelope(
        connection,
        subscribe_catalog_envelope("catalog-501-subscribe"),
    )
    .await
    .expect("start 501-row catalog subscription");

    let receipt = timeout(Duration::from_secs(2), receiver.recv())
        .await
        .expect("subscription receipt timeout")
        .expect("subscription receipt");
    assert!(matches!(
        decode(&receipt).body,
        RuntimeMessage::Reply(RuntimeReply::Subscription(
            SubscriptionReceipt::Subscribed { .. }
        ))
    ));
    receipt.acknowledge().expect("flush subscription receipt");

    let first = timeout(Duration::from_secs(2), receiver.recv())
        .await
        .expect("first catalog page timeout")
        .expect("first catalog page");
    let RuntimeMessage::Reply(RuntimeReply::Catalog(first_snapshot)) = decode(&first).body else {
        panic!("first Catalog subscription page must be a snapshot");
    };
    assert_eq!(first_snapshot.base_catalog_cursor, StreamCursor::At(500));
    assert_eq!(first_snapshot.entries().len(), 500);
    assert!(first_snapshot.current_page_cursor().is_none());
    let second_page_cursor = first_snapshot
        .next_page_cursor()
        .cloned()
        .expect("first Catalog page must issue the second-page cursor");
    assert!(
        receiver.try_recv().is_err(),
        "second page overtook the first page FlushReceipt"
    );
    first.acknowledge().expect("flush first catalog page");

    let second = timeout(Duration::from_secs(2), receiver.recv())
        .await
        .expect("second catalog page timeout")
        .expect("second catalog page");
    let RuntimeMessage::Reply(RuntimeReply::Catalog(second_snapshot)) = decode(&second).body else {
        panic!("second Catalog subscription page must be a snapshot");
    };
    assert_eq!(second_snapshot.base_catalog_cursor, StreamCursor::At(500));
    assert_eq!(second_snapshot.entries().len(), 1);
    assert_eq!(
        second_snapshot.current_page_cursor(),
        Some(&second_page_cursor)
    );
    assert!(second_snapshot.next_page_cursor().is_none());
    assert!(
        receiver.try_recv().is_err(),
        "SyncComplete overtook the second page FlushReceipt"
    );
    second.acknowledge().expect("flush second catalog page");

    let sync = timeout(Duration::from_secs(2), receiver.recv())
        .await
        .expect("catalog sync timeout")
        .expect("catalog sync");
    assert!(matches!(
        decode(&sync).body,
        RuntimeMessage::Reply(RuntimeReply::SyncComplete(_))
    ));
    sync.acknowledge().expect("flush catalog sync");

    core.disconnect(connection).await;
    core.shutdown().await.expect("shutdown core");
}

#[tokio::test]
async fn refreshed_catalog_snapshot_does_not_replay_its_covered_delta() {
    let root = TestRoot::new("subscription-catalog-refresh-no-duplicate");
    let core = core(&root).await;
    core.recover().await.expect("recover core");
    let (connection, mut receiver) = connect_recording(&core, 0x76).await;

    core.handle_envelope(
        connection,
        subscribe_catalog_envelope("catalog-empty-baseline"),
    )
    .await
    .expect("create empty durable catalog baseline");
    for expected in ["subscription", "catalog", "sync"] {
        let write = timeout(Duration::from_secs(2), receiver.recv())
            .await
            .unwrap_or_else(|_| panic!("{expected} baseline timeout"))
            .unwrap_or_else(|| panic!("{expected} baseline write"));
        write.acknowledge().expect("flush baseline frame");
    }
    core.subscriptions
        .unsubscribe(
            connection,
            crate::runtime::events::RuntimeStreamTarget::Catalog,
        )
        .await
        .expect("stop baseline subscription");

    core.store
        .create_conversation(catalog_conversation(0x42))
        .await
        .expect("append catalog revision zero");
    core.handle_envelope(
        connection,
        subscribe_catalog_envelope("catalog-refreshed-snapshot"),
    )
    .await
    .expect("subscribe from refreshed catalog snapshot");

    let receipt = timeout(Duration::from_secs(2), receiver.recv())
        .await
        .expect("refresh receipt timeout")
        .expect("refresh receipt");
    assert!(matches!(
        decode(&receipt).body,
        RuntimeMessage::Reply(RuntimeReply::Subscription(
            SubscriptionReceipt::Subscribed { .. }
        ))
    ));
    receipt.acknowledge().expect("flush refresh receipt");

    let snapshot = timeout(Duration::from_secs(2), receiver.recv())
        .await
        .expect("refreshed snapshot timeout")
        .expect("refreshed snapshot");
    assert!(matches!(
        decode(&snapshot).body,
        RuntimeMessage::Reply(RuntimeReply::Catalog(snapshot))
            if snapshot.base_catalog_cursor == StreamCursor::At(0)
                && snapshot.entries().len() == 1
    ));
    snapshot.acknowledge().expect("flush refreshed snapshot");

    let sync = timeout(Duration::from_secs(2), receiver.recv())
        .await
        .expect("refresh sync timeout")
        .expect("refresh sync");
    assert!(
        matches!(
            decode(&sync).body,
            RuntimeMessage::Reply(RuntimeReply::SyncComplete(_))
        ),
        "snapshot-covered catalog delta must not be replayed before SyncComplete"
    );
    sync.acknowledge().expect("flush refresh sync");

    core.disconnect(connection).await;
    core.shutdown().await.expect("shutdown core");
}

#[tokio::test]
async fn stale_prepared_commit_cannot_replace_the_newer_committed_job() {
    let root = TestRoot::new("subscription-stale-prepared-commit");
    let core = core(&root).await;
    core.recover().await.expect("recover core");
    let (connection, mut receiver) = connect_recording(&core, 0x74).await;

    let stale = core
        .subscriptions
        .prepare(
            connection,
            MessageId::new("stale-prepared"),
            crate::runtime::events::RuntimeStreamTarget::Catalog,
            crate::runtime::backfill::BarrierRequest::Backfill {
                after: StreamCursor::BeforeFirst,
            },
            false,
        )
        .await
        .expect("prepare first generation");
    let current = core
        .subscriptions
        .prepare(
            connection,
            MessageId::new("current-prepared"),
            crate::runtime::events::RuntimeStreamTarget::Catalog,
            crate::runtime::backfill::BarrierRequest::Backfill {
                after: StreamCursor::BeforeFirst,
            },
            false,
        )
        .await
        .expect("prepare replacement generation");

    current.commit().await.expect("commit current generation");
    assert!(
        stale.commit().await.is_err(),
        "stale PreparedSubscription must fail before touching the current job"
    );

    let sync = timeout(Duration::from_secs(2), receiver.recv())
        .await
        .expect("current sync timeout")
        .expect("current sync");
    let envelope = decode(&sync);
    assert_eq!(envelope.message_id.as_str(), "current-prepared");
    assert!(matches!(
        envelope.body,
        RuntimeMessage::Reply(RuntimeReply::SyncComplete(_))
    ));
    sync.acknowledge().expect("flush current sync");
    assert!(
        timeout(Duration::from_millis(100), receiver.recv())
            .await
            .is_err(),
        "stale prepared generation emitted a frame"
    );

    core.disconnect(connection).await;
    core.shutdown().await.expect("shutdown core");
}

#[tokio::test]
async fn terminal_backfill_job_removes_its_exact_registry_entry() {
    let root = TestRoot::new("subscription-terminal-job-cleanup");
    let core = core(&root).await;
    core.recover().await.expect("recover core");
    let (connection, mut receiver) = connect_recording(&core, 0x75).await;

    core.handle_envelope(
        connection,
        RuntimeEnvelope {
            version: RUNTIME_PROTOCOL_VERSION,
            message_id: MessageId::new("cursor-ahead-terminal"),
            body: RuntimeMessage::Request(RuntimeRequest::Backfill(BackfillRequest::Catalog {
                after: StreamCursor::At(0),
            })),
        },
    )
    .await
    .expect("start terminal backfill");
    let failure = timeout(Duration::from_secs(2), receiver.recv())
        .await
        .expect("terminal failure timeout")
        .expect("terminal failure");
    assert!(matches!(
        decode(&failure).body,
        RuntimeMessage::Reply(RuntimeReply::Failure(_))
    ));
    failure.acknowledge().expect("flush terminal failure");

    timeout(Duration::from_secs(2), async {
        loop {
            if core
                .subscriptions
                .metrics_for_test()
                .expect("subscription metrics")
                == (0, 0, 0, 0)
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("finished job must self-clean");

    core.disconnect(connection).await;
    core.shutdown().await.expect("shutdown core");
}

#[tokio::test]
async fn asynchronous_snapshot_failure_emits_a_directed_terminal_failure() {
    let root = TestRoot::new("subscription-async-snapshot-failure");
    let core = core(&root).await;
    core.recover().await.expect("recover core");
    let (connection, mut receiver) = connect_recording(&core, 0x77).await;
    let input = catalog_conversation(0x43);
    let conversation_id = input.conversation_id;
    core.store
        .create_conversation(input)
        .await
        .expect("create failure conversation");
    configure_codex_revision_one(
        &core,
        connection,
        WireConversationId::new(conversation_id.to_canonical_string()),
        "noncanonical-snapshot-configuration",
    )
    .await;
    let owner = crate::runtime::store::IdempotencyOwner::Local {
        machine_trust_domain: [0xD1; 32],
        uid: 501,
        client_installation_id: [0xD2; 16],
    };
    let command_id = match core
        .store
        .accept_command(crate::runtime::store::AcceptCommand {
            conversation_id,
            owner: owner.clone(),
            idempotency_key: "noncanonical-snapshot-event".to_owned(),
            expected_configuration_revision: 1,
            payload: b"prompt".to_vec(),
        })
        .await
        .expect("accept failure command")
    {
        crate::runtime::store::AcceptOutcome::Accepted { command, .. } => command.command_id,
        crate::runtime::store::AcceptOutcome::Replayed { .. } => panic!("first accept replayed"),
    };
    core.store
        .terminate_accepted_command(crate::runtime::store::TerminateAcceptedCommand {
            conversation_id,
            command_id,
            expected_owner: owner,
            reason: crate::runtime::store::AcceptedTerminationReason::Canceled,
            // P3.5 fixed audit bytes are intentionally not a canonical RuntimeEvent;
            // the v4 replay index therefore requires a new snapshot boundary.
        })
        .await
        .expect("commit noncanonical audit event");

    core.handle_envelope(
        connection,
        RuntimeEnvelope {
            version: RUNTIME_PROTOCOL_VERSION,
            message_id: MessageId::new("async-snapshot-failure"),
            body: RuntimeMessage::Request(RuntimeRequest::Subscribe {
                inner_cursor: agentdeck_protocol::runtime::RuntimeInnerCursor::Conversation {
                    conversation_id: agentdeck_protocol::runtime::identity::ConversationId::new(
                        conversation_id.to_canonical_string(),
                    ),
                    cursor: StreamCursor::BeforeFirst,
                },
            }),
        },
    )
    .await
    .expect("install subscription before async materialization failure");

    let subscribed = timeout(Duration::from_secs(2), receiver.recv())
        .await
        .expect("subscribed receipt timeout")
        .expect("subscribed receipt");
    assert!(matches!(
        decode(&subscribed).body,
        RuntimeMessage::Reply(RuntimeReply::Subscription(
            SubscriptionReceipt::Subscribed { .. }
        ))
    ));
    subscribed.acknowledge().expect("flush subscribed receipt");

    let failure = timeout(Duration::from_secs(2), receiver.recv())
        .await
        .expect("async terminal failure timeout")
        .expect("async terminal failure");
    let failure_envelope = decode(&failure);
    assert_eq!(
        failure_envelope.message_id.as_str(),
        "async-snapshot-failure"
    );
    assert!(matches!(
        failure_envelope.body,
        RuntimeMessage::Reply(RuntimeReply::Failure(_))
    ));
    failure.acknowledge().expect("flush async terminal failure");

    timeout(Duration::from_secs(2), async {
        loop {
            if core
                .subscriptions
                .metrics_for_test()
                .expect("subscription metrics")
                == (0, 0, 0, 0)
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("failed job must release registry and job entry");

    core.disconnect(connection).await;
    core.shutdown().await.expect("shutdown core");
}

#[tokio::test]
async fn failure_after_flushed_snapshot_fail_closes_the_connection() {
    use crate::runtime::snapshot::{
        SnapshotMaterialization, SnapshotMaterializer, assemble_build_snapshot,
    };

    let root = TestRoot::new("subscription-partial-failure-close");
    let command_id = RuntimeId::from_bytes(RuntimeIdKind::Command, [0x51; 16]).expect("command id");
    let turn_id = RuntimeId::from_bytes(RuntimeIdKind::Turn, [0x53; 16]).expect("turn id");
    let event_id = RuntimeId::from_bytes(RuntimeIdKind::Event, [0x52; 16]).expect("event id");
    let configuration_event =
        RuntimeId::from_bytes(RuntimeIdKind::Event, [0x50; 16]).expect("configuration event id");
    let store = RuntimeStoreHandle::open(
        crate::runtime::store::RuntimeStoreConfig::new(root.path.join("runtime.db"))
            .with_command_capacity(1_024)
            .with_id_source(SequenceIdSource::new([
                publication_axis_id(0xA0),
                publication_axis_id(0xA1),
                publication_axis_id(0xA2),
                configuration_event,
                command_id,
                turn_id,
                event_id,
            ])),
        root.kek(),
    )
    .await
    .expect("open deterministic store");
    let router = Arc::new(AgentRouter::with_runtime_store(store.clone()));
    let core = Arc::new(
        RuntimeCore::new(store, router, [0xA1; 32]).expect("construct deterministic core"),
    );
    core.recover().await.expect("recover core");
    let (connection, mut receiver) = connect_recording(&core, 0x78).await;
    let input = catalog_conversation(0x44);
    let conversation_id = input.conversation_id;
    core.store
        .create_conversation(input)
        .await
        .expect("create partial-failure conversation");

    let source = core
        .store
        .acquire_snapshot_build_source(conversation_id)
        .await
        .expect("capture empty snapshot base");
    let materializer = SnapshotMaterializer::new(core.store.clone(), core.router.clone());
    let SnapshotMaterialization::Build(mut build) = materializer
        .materialize(source)
        .await
        .expect("prepare empty snapshot")
    else {
        panic!("fresh conversation must build a snapshot")
    };
    let assembled = assemble_build_snapshot(&mut build, Vec::new()).expect("assemble snapshot");
    let write = build
        .bind_assembled_snapshot(assembled)
        .expect("bind snapshot write");
    core.store
        .store_conversation_snapshot(write)
        .await
        .expect("store ready empty snapshot");
    configure_codex_revision_one(
        &core,
        connection,
        WireConversationId::new(conversation_id.to_canonical_string()),
        "partial-failure-configuration",
    )
    .await;

    let owner = crate::runtime::store::IdempotencyOwner::Local {
        machine_trust_domain: [0xD3; 32],
        uid: 501,
        client_installation_id: [0xD4; 16],
    };
    let accepted = core
        .store
        .accept_command(crate::runtime::store::AcceptCommand {
            conversation_id,
            owner: owner.clone(),
            idempotency_key: "partial-failure-command".to_owned(),
            expected_configuration_revision: 1,
            payload: b"prompt".to_vec(),
        })
        .await
        .expect("accept deterministic command");
    assert!(matches!(
        accepted,
        crate::runtime::store::AcceptOutcome::Accepted { ref command, .. }
            if command.command_id == command_id
    ));
    let started = core
        .store
        .mark_started_with_event(crate::runtime::store::StartCommand {
            conversation_id,
            command_id,
            daemon_boot_id: RuntimeId::from_bytes(RuntimeIdKind::DaemonBoot, [0x54; 16])
                .expect("daemon boot id"),
            execution_nonce: b"partial-failure-start".to_vec(),
        })
        .await
        .expect("commit canonical TurnStarted after snapshot");
    assert!(matches!(
        started,
        crate::runtime::store::StartOutcome::Started { ref intent, ref event, .. }
            if intent.turn_id == turn_id && event.event_id == event_id
    ));

    core.handle_envelope(
        connection,
        RuntimeEnvelope {
            version: RUNTIME_PROTOCOL_VERSION,
            message_id: MessageId::new("partial-snapshot-failure"),
            body: RuntimeMessage::Request(RuntimeRequest::Subscribe {
                inner_cursor: agentdeck_protocol::runtime::RuntimeInnerCursor::Conversation {
                    conversation_id: agentdeck_protocol::runtime::identity::ConversationId::new(
                        conversation_id.to_canonical_string(),
                    ),
                    cursor: StreamCursor::BeforeFirst,
                },
            }),
        },
    )
    .await
    .expect("install partial-failure subscription");
    let subscribed = timeout(Duration::from_secs(2), receiver.recv())
        .await
        .expect("partial subscribed timeout")
        .expect("partial subscribed");
    subscribed.acknowledge().expect("flush subscribed receipt");

    let snapshot = timeout(Duration::from_secs(2), receiver.recv())
        .await
        .expect("partial snapshot timeout")
        .expect("partial snapshot");
    assert!(matches!(
        decode(&snapshot).body,
        RuntimeMessage::Reply(RuntimeReply::Snapshot(_))
    ));

    let tamper = rusqlite::Connection::open(root.path.join("runtime.db"))
        .expect("open retention tamper connection");
    assert_eq!(
        tamper
            .execute(
                "UPDATE event_stream_index SET metadata_token = zeroblob(32)\
                 WHERE conversation_id = ?1 AND event_seq = '00000000000000000001'",
                [&conversation_id.as_bytes()[..]],
            )
            .expect("tamper backfill row after snapshot delivery"),
        1
    );
    drop(tamper);
    snapshot
        .acknowledge()
        .expect("flush snapshot before backfill failure");

    let post_snapshot = timeout(Duration::from_secs(2), receiver.recv())
        .await
        .expect("connection close timeout");
    assert!(
        post_snapshot.is_none(),
        "partial delivery failure must close instead of sending a misleading frame: {:?}",
        post_snapshot.as_ref().map(decode)
    );
    assert!(core.connections.principal(connection).is_err());
    timeout(Duration::from_secs(2), async {
        loop {
            if core
                .subscriptions
                .metrics_for_test()
                .expect("subscription metrics")
                == (0, 0, 0, 0)
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("partial failure must self-clean");

    core.disconnect(connection).await;
    core.shutdown().await.expect("shutdown core");
}

#[tokio::test]
async fn barrier_deadline_cancels_snapshot_budget_wait_and_emits_terminal_failure() {
    let root = TestRoot::new("subscription-barrier-deadline");
    let core = core(&root).await;
    core.recover().await.expect("recover core");
    core.subscriptions
        .set_barrier_ttl_for_test(Duration::from_millis(20));
    let held_budget = core.subscriptions.exhaust_snapshot_budget_for_test().await;
    let (connection, mut receiver) = connect_recording(&core, 0x79).await;
    let input = catalog_conversation(0x45);
    let conversation_id = input.conversation_id;
    core.store
        .create_conversation(input)
        .await
        .expect("create deadline conversation");

    core.handle_envelope(
        connection,
        RuntimeEnvelope {
            version: RUNTIME_PROTOCOL_VERSION,
            message_id: MessageId::new("snapshot-budget-deadline"),
            body: RuntimeMessage::Request(RuntimeRequest::Subscribe {
                inner_cursor: agentdeck_protocol::runtime::RuntimeInnerCursor::Conversation {
                    conversation_id: agentdeck_protocol::runtime::identity::ConversationId::new(
                        conversation_id.to_canonical_string(),
                    ),
                    cursor: StreamCursor::BeforeFirst,
                },
            }),
        },
    )
    .await
    .expect("install deadline subscription");
    let subscribed = timeout(Duration::from_secs(2), receiver.recv())
        .await
        .expect("deadline subscribed timeout")
        .expect("deadline subscribed");
    subscribed.acknowledge().expect("flush deadline subscribed");

    let failure = timeout(Duration::from_secs(2), receiver.recv())
        .await
        .expect("deadline terminal timeout")
        .expect("deadline terminal failure");
    assert!(matches!(
        decode(&failure).body,
        RuntimeMessage::Reply(RuntimeReply::Failure(_))
    ));
    timeout(Duration::from_secs(2), async {
        loop {
            let metrics = core
                .subscriptions
                .metrics_for_test()
                .expect("subscription metrics before terminal ACK");
            if metrics == (0, 0, 0, 1) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("deadline must release registry quotas before terminal ACK");
    assert_eq!(
        core.subscriptions
            .metrics_for_test()
            .expect("released registry metrics before terminal ACK"),
        (0, 0, 0, 1),
        "terminal writer wait may retain the job, but no live/barrier/snapshot-sender quota"
    );
    failure.acknowledge().expect("flush deadline failure");
    timeout(Duration::from_secs(2), async {
        loop {
            if core
                .subscriptions
                .metrics_for_test()
                .expect("subscription metrics")
                == (0, 0, 0, 0)
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("deadline must release subscription budgets and job");
    drop(held_budget);

    core.disconnect(connection).await;
    core.shutdown().await.expect("shutdown core");
}

#[tokio::test]
async fn live_event_cannot_overtake_sync_complete() {
    let root = TestRoot::new("subscription-sync-before-live");
    let core = core(&root).await;
    core.recover().await.expect("recover core");
    let (connection, mut receiver) = connect_recording(&core, 0x71).await;

    core.handle_envelope(connection, backfill_envelope("sync-before-live"))
        .await
        .expect("start empty catalog backfill");
    let sync_write = timeout(Duration::from_secs(2), receiver.recv())
        .await
        .expect("sync write timeout")
        .expect("sync write");
    assert!(matches!(
        decode(&sync_write).body,
        RuntimeMessage::Reply(RuntimeReply::SyncComplete(_))
    ));

    timeout(
        Duration::from_secs(2),
        core.store.create_conversation(catalog_conversation(0x31)),
    )
    .await
    .expect("store mutation must not wait for slow writer")
    .expect("create live catalog mutation");
    assert!(
        receiver.try_recv().is_err(),
        "live delta overtook unflushed SyncComplete"
    );

    sync_write.acknowledge().expect("flush SyncComplete");
    let live_write = timeout(Duration::from_secs(2), receiver.recv())
        .await
        .expect("live write timeout")
        .expect("live write");
    assert!(matches!(
        decode(&live_write).body,
        RuntimeMessage::Stream(RuntimeStreamItem::CatalogDelta(_))
    ));
    live_write.acknowledge().expect("flush live delta");
    core.shutdown().await.expect("shutdown core");
}

#[tokio::test]
async fn subscribe_unsubscribe_and_disconnect_cleanup_are_idempotent() {
    let root = TestRoot::new("subscription-cleanup-idempotent");
    let core = core(&root).await;
    core.recover().await.expect("recover core");
    let (connection, mut receiver) = connect_recording(&core, 0x72).await;

    core.handle_envelope(connection, backfill_envelope("cleanup-backfill"))
        .await
        .expect("start catalog backfill");
    let sync = timeout(Duration::from_secs(2), receiver.recv())
        .await
        .expect("sync timeout")
        .expect("sync write");
    sync.acknowledge().expect("flush sync");

    for index in 0..2 {
        core.handle_envelope(
            connection,
            RuntimeEnvelope {
                version: RUNTIME_PROTOCOL_VERSION,
                message_id: MessageId::new(format!("unsubscribe-{index}")),
                body: RuntimeMessage::Request(RuntimeRequest::Unsubscribe {
                    target: RuntimeSubscriptionTarget::Catalog,
                }),
            },
        )
        .await
        .expect("idempotent unsubscribe");
        let receipt = timeout(Duration::from_secs(2), receiver.recv())
            .await
            .expect("unsubscribe timeout")
            .expect("unsubscribe receipt");
        assert!(matches!(
            decode(&receipt).body,
            RuntimeMessage::Reply(RuntimeReply::Subscription(
                SubscriptionReceipt::Unsubscribed
            ))
        ));
        receipt.acknowledge().expect("flush unsubscribe receipt");
    }
    assert_eq!(
        core.subscriptions
            .metrics_for_test()
            .expect("subscription metrics"),
        (0, 0, 0, 0)
    );
    core.disconnect(connection).await;
    core.disconnect(connection).await;
    assert_eq!(
        core.subscriptions
            .metrics_for_test()
            .expect("post-disconnect metrics"),
        (0, 0, 0, 0)
    );
    core.shutdown().await.expect("shutdown core");
}

#[tokio::test]
async fn stale_subscription_generation_cannot_enqueue_after_resubscribe() {
    let root = TestRoot::new("subscription-stale-generation");
    let core = core(&root).await;
    core.recover().await.expect("recover core");
    let (connection, mut receiver) = connect_recording(&core, 0x73).await;

    core.handle_envelope(connection, backfill_envelope("old-generation"))
        .await
        .expect("start old generation");
    let old_sync = timeout(Duration::from_secs(2), receiver.recv())
        .await
        .expect("old sync timeout")
        .expect("old sync write");
    assert_eq!(decode(&old_sync).message_id.as_str(), "old-generation");

    timeout(
        Duration::from_secs(2),
        core.handle_envelope(connection, backfill_envelope("new-generation")),
    )
    .await
    .expect("resubscribe must cancel old flush wait")
    .expect("install new generation");
    core.store
        .create_conversation(catalog_conversation(0x41))
        .await
        .expect("commit event for current generation");
    assert!(
        receiver.try_recv().is_err(),
        "new generation overtook the already queued old frame"
    );

    old_sync
        .acknowledge()
        .expect("drain old pre-resubscribe frame");
    let new_sync = timeout(Duration::from_secs(2), receiver.recv())
        .await
        .expect("new sync timeout")
        .expect("new sync write");
    let new_sync_envelope = decode(&new_sync);
    assert_eq!(new_sync_envelope.message_id.as_str(), "new-generation");
    assert!(matches!(
        new_sync_envelope.body,
        RuntimeMessage::Reply(RuntimeReply::SyncComplete(_))
    ));
    assert!(
        receiver.try_recv().is_err(),
        "live event overtook current generation SyncComplete"
    );
    new_sync.acknowledge().expect("flush current SyncComplete");

    let live = timeout(Duration::from_secs(2), receiver.recv())
        .await
        .expect("current live timeout")
        .expect("current live write");
    assert!(matches!(
        decode(&live).body,
        RuntimeMessage::Stream(RuntimeStreamItem::CatalogDelta(_))
    ));
    live.acknowledge().expect("flush current live event");
    assert!(
        timeout(Duration::from_millis(100), receiver.recv())
            .await
            .is_err(),
        "stale generation emitted an extra frame after resubscribe"
    );
    core.shutdown().await.expect("shutdown core");
}
