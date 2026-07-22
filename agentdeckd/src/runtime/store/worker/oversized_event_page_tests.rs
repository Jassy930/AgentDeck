use std::collections::VecDeque;
use std::fs;
use std::sync::atomic::AtomicU64;

use agentdeck_protocol::runtime::event::RuntimeEventBody;
use agentdeck_protocol::runtime::identity::{CommandId, ConversationId, EntityId, EventId, ItemId};
use agentdeck_protocol::runtime::{
    CodexConversationConfiguration, ConversationConfiguration, RuntimeEvent,
    VendorConfigurationSnapshot,
};
use agentdeck_protocol::{
    AgentItem, AgentItemMeta, AgentKind, CodexApprovalPolicy, CodexReasoningEffort,
    CodexSandboxMode,
};

use super::*;
use crate::runtime::model::MAX_RUNTIME_EVENT_BYTES;
use crate::runtime::store::identity::{RuntimeIdError, RuntimeIdSource};
use crate::runtime::store::{
    AppendExecutionEvent, AppendExecutionEventOutcome, AuthorizeExecutionRelease,
    ConfigureConversation, ConfigureConversationOutcome, ConversationDescriptor, ExecutionFence,
    IdempotencyOwner, NewConversation,
};
use crate::security::{MemoryKeyStore, load_or_create_storage_kek};

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

struct TestRoot(PathBuf);

impl TestRoot {
    fn new() -> Self {
        let sequence = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "agentdeckd-runtime-oversized-event-page-{}-{sequence}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).expect("create oversized event test root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("secure oversized event test root");
        }
        Self(path)
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct OrderedIdSource(VecDeque<RuntimeId>);

impl RuntimeIdSource for OrderedIdSource {
    fn next_id(&mut self, kind: RuntimeIdKind) -> Result<RuntimeId, RuntimeIdError> {
        let next = self.0.pop_front().expect("ordered runtime id available");
        if next.kind() != kind {
            return Err(RuntimeIdError::SourceKindMismatch {
                kind,
                actual: next.kind(),
            });
        }
        Ok(next)
    }
}

fn runtime_id(kind: RuntimeIdKind, seed: u8) -> RuntimeId {
    RuntimeId::from_bytes(kind, [seed; 16]).expect("non-zero runtime id")
}

fn assert_single_event(events: &[RuntimeEvent], expected: &RuntimeEvent) {
    assert_eq!(
        events.len(),
        1,
        "page must contain the exact oversized event"
    );
    assert_eq!(
        serde_json::to_vec(&events[0]).expect("encode replayed event"),
        serde_json::to_vec(expected).expect("encode expected event"),
        "replayed event must remain byte-equivalent canonical JSON",
    );
}

#[tokio::test]
async fn nine_mib_canonical_event_replays_through_backfill_and_snapshot_pages() {
    let root = TestRoot::new();
    let keys = MemoryKeyStore::new();
    let command_id = runtime_id(RuntimeIdKind::Command, 0x31);
    let turn_id = runtime_id(RuntimeIdKind::Turn, 0x32);
    let event_id = runtime_id(RuntimeIdKind::Event, 0x33);
    let configuration_event_id = runtime_id(RuntimeIdKind::Event, 0x37);
    let item_event_id = runtime_id(RuntimeIdKind::Event, 0x36);
    let config = RuntimeStoreConfig::new(root.0.join("runtime.db")).with_id_source(
        OrderedIdSource(VecDeque::from([
            runtime_id(RuntimeIdKind::RemoteOutbox, 0x38),
            runtime_id(RuntimeIdKind::RemoteOutbox, 0x39),
            runtime_id(RuntimeIdKind::RemoteOutbox, 0x3A),
            configuration_event_id,
            command_id,
            turn_id,
            event_id,
        ])),
    );
    let storage_kek = load_or_create_storage_kek(&keys, &root.0.join("key-state.db"))
        .expect("create oversized event StorageKEK");
    let store = RuntimeStoreHandle::open(config, storage_kek)
        .await
        .expect("open oversized event store");
    let conversation_id = runtime_id(RuntimeIdKind::Conversation, 0x30);
    store
        .create_conversation(NewConversation {
            conversation_id,
            adapter_state_key: runtime_id(RuntimeIdKind::AdapterState, 0x34),
            descriptor: ConversationDescriptor {
                agent_kind: AgentKind::Codex,
                title: Some("oversized canonical event".to_owned()),
                cwd: PathBuf::from("/tmp/agentdeck-oversized-event"),
            },
        })
        .await
        .expect("create oversized event conversation");
    assert!(matches!(
        store
            .configure_conversation(ConfigureConversation {
                conversation_id,
                owner: IdempotencyOwner::Local {
                    machine_trust_domain: [0x43; 32],
                    uid: 501,
                    client_installation_id: [0x44; 16],
                },
                idempotency_key: "oversized-event-configuration".to_owned(),
                expected_configuration_revision: 0,
                configuration: ConversationConfiguration::new(
                    VendorConfigurationSnapshot::Codex(CodexConversationConfiguration::new(
                        CodexApprovalPolicy::OnRequest,
                        CodexSandboxMode::WorkspaceWrite,
                        CodexReasoningEffort::Medium,
                    )),
                ),
            })
            .await
            .expect("configure oversized event conversation"),
        ConfigureConversationOutcome::Applied { configuration }
            if configuration.configuration_revision == 1
                && configuration.event_id == configuration_event_id
                && configuration.event_seq == 0
    ));
    let command = match store
        .accept_command(AcceptCommand {
            conversation_id,
            owner: IdempotencyOwner::Local {
                machine_trust_domain: [0x41; 32],
                uid: 501,
                client_installation_id: [0x42; 16],
            },
            idempotency_key: "oversized-event".to_owned(),
            expected_configuration_revision: 1,
            payload: b"oversized event command".to_vec(),
        })
        .await
        .expect("accept oversized event command")
    {
        AcceptOutcome::Accepted { command, .. } => command,
        AcceptOutcome::Replayed { .. } => panic!("first command cannot replay"),
    };
    assert_eq!(command.command_id, command_id);

    let message = "x".repeat(9 * 1024 * 1024);
    let canonical = RuntimeEvent::new(
        ConversationId::new(conversation_id.to_canonical_string()),
        EventId::new(item_event_id.to_canonical_string()),
        2,
        Some(CommandId::new(command_id.to_canonical_string())),
        Some(ItemId::new("oversized-item")),
        Some(EntityId::new("oversized-entity")),
        RuntimeEventBody::Item {
            item: AgentItem::AssistantMessage {
                text: message.clone(),
                meta: AgentItemMeta::default(),
            },
        },
    )
    .expect("construct 9 MiB canonical event");
    let encoded = serde_json::to_vec(&canonical).expect("encode 9 MiB canonical event");
    assert!(encoded.len() > usize::try_from(MAX_RUNTIME_READ_PAGE_BYTES).expect("page cap"));
    assert!(encoded.len() <= MAX_RUNTIME_EVENT_BYTES);
    let daemon_boot_id = runtime_id(RuntimeIdKind::DaemonBoot, 0x35);
    let execution_nonce = b"oversized-event-nonce".to_vec();
    match store
        .mark_started_with_event(StartCommand {
            conversation_id,
            command_id,
            daemon_boot_id,
            execution_nonce: execution_nonce.clone(),
        })
        .await
        .expect("persist canonical TurnStarted")
    {
        StartOutcome::Started { intent, event, .. } => {
            assert_eq!(event.event_id, event_id);
            assert_eq!(intent.daemon_boot_id, daemon_boot_id);
            assert_eq!(intent.execution_nonce, execution_nonce);
        }
        StartOutcome::Replayed { .. } => panic!("first start cannot replay"),
    }
    store
        .persist_execution_fence(ExecutionFence {
            command_id,
            daemon_boot_id,
            execution_nonce: execution_nonce.clone(),
            process_group_id: 7_401,
            leader_pid: 7_401,
            leader_start_time: 7_401,
            payload: b"oversized-event-test-fence".to_vec(),
        })
        .await
        .expect("persist oversized event execution fence");
    store
        .authorize_execution_release(AuthorizeExecutionRelease {
            command_id,
            daemon_boot_id,
            execution_nonce,
        })
        .await
        .expect("authorize oversized event execution release");
    assert!(matches!(
        store
            .append_execution_event(AppendExecutionEvent::item(
                conversation_id,
                command_id,
                turn_id,
                item_event_id,
                ItemId::new("oversized-item"),
                EntityId::new("oversized-entity"),
                AgentItem::AssistantMessage {
                    text: message,
                    meta: AgentItemMeta::default(),
                },
            ))
            .await
            .expect("append 9 MiB canonical item"),
        AppendExecutionEventOutcome::Appended { event }
            if event.event_id == item_event_id && event.event_seq == 2
    ));

    let RuntimeBackfillPlan::Pinned(backfill_pin) = store
        .acquire_backfill_pin(
            RuntimeBackfillTarget::Conversation(conversation_id),
            Some(1),
        )
        .await
        .expect("pin oversized event backfill")
    else {
        panic!("event zero requires a pinned backfill page");
    };
    let page = store
        .load_event_backfill_page(backfill_pin.clone(), Some(1))
        .await
        .expect("load oversized event through snapshot-sized lease");
    assert_single_event(&page.events, &canonical);
    assert!(page.complete);
    assert_eq!(page.next_after, 2);
    assert!(matches!(
        store
            .load_event_backfill_page(backfill_pin.clone(), Some(1))
            .await,
        Err(RuntimeStoreError::WorkerBusy {
            lane: RuntimeStoreLane::Read
        })
    ));
    let completion = page.completion().clone();
    drop(page);

    let replayed = store
        .load_event_backfill_page(backfill_pin.clone(), Some(1))
        .await
        .expect("dropping oversized page returns the 128 MiB lease");
    assert_single_event(&replayed.events, &canonical);
    drop(replayed);
    store
        .complete_backfill_page(completion)
        .await
        .expect("complete oversized backfill pin");
    assert!(matches!(
        store
            .load_event_backfill_page(backfill_pin.clone(), Some(1))
            .await,
        Err(RuntimeStoreError::InvalidBackfillPin)
    ));
    store
        .release_backfill_pin(backfill_pin.pin_id)
        .await
        .expect("completed backfill cleanup is idempotent");

    let source = store
        .acquire_snapshot_build_source(conversation_id)
        .await
        .expect("acquire exact snapshot reducer source");
    let snapshot_pin = source
        .build_pin()
        .expect("non-ready conversation returns a build pin")
        .clone();
    let (events, next_after, complete, lease) = store
        .load_snapshot_event_page(snapshot_pin.clone(), Some(1))
        .await
        .expect("snapshot reducer page reaches oversized fallback");
    assert_single_event(&events, &canonical);
    assert_eq!(next_after, 2);
    assert!(complete);
    assert!(matches!(
        store
            .load_snapshot_event_page(snapshot_pin.clone(), Some(1))
            .await,
        Err(RuntimeStoreError::WorkerBusy {
            lane: RuntimeStoreLane::Read
        })
    ));
    drop(lease);

    let (events, _, _, lease) = store
        .load_snapshot_event_page(snapshot_pin.clone(), Some(1))
        .await
        .expect("snapshot page lease is returned after reducer consumption");
    drop(events);
    drop(lease);
    drop(source);
    for _ in 0..100 {
        if store
            .active_snapshot_build_pin_count_for_test()
            .await
            .expect("count snapshot pins")
            == 0
        {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(
        store
            .active_snapshot_build_pin_count_for_test()
            .await
            .expect("snapshot source drop cleans exact pin"),
        0
    );
    assert!(matches!(
        store.load_snapshot_event_page(snapshot_pin, None).await,
        Err(RuntimeStoreError::InvalidStateTransition)
    ));
    store
        .shutdown()
        .await
        .expect("shutdown oversized event store");
}
