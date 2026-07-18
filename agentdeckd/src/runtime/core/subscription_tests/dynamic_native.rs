use super::*;

use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use agentdeck_protocol::runtime::failure::{
    DAEMON_COMMAND_HISTORY_ONLY, DAEMON_RUNTIME_READ_UNAVAILABLE,
};
use agentdeck_protocol::runtime::{
    ClaudeCodeConversationConfiguration, ConversationConfiguration, QueryReceiptSelector,
    RuntimeFailure, VendorConfigurationSnapshot,
};
use agentdeck_protocol::{AgentItem, AgentItemMeta, AgentKind, ClaudeCodePermissionMode};
use rusqlite::{Connection, OpenFlags};
use tokio::sync::{Notify, Semaphore};

use crate::agent::{
    CanonicalNativeHistoryItem, CanonicalNativeHistoryRead, NativeHistoryReadError,
    NativeHistoryReader, NativeItemKey, NativeTurnKey,
};
use crate::runtime::store::{
    ConversationDescriptor, ImportNativeProjection, ImportNativeProjectionOutcome, RuntimeId,
};
use crate::security::SecretBytes;

const NATIVE_BODY_SENTINEL: &str = "DYNAMIC_NATIVE_BODY_MUST_STAY_EPHEMERAL";
const PRIVATE_REFERENCE_SENTINEL: &[u8] = b"dynamic-native-private-reference-v1";

#[derive(Clone)]
struct NativeItemFixture {
    turn_key: [u8; 32],
    item_key: [u8; 32],
    item: AgentItem,
}

struct FakeNativeHistoryReader {
    expected_adapter_state_key: RuntimeId,
    state: StdMutex<FakeNativeHistoryState>,
}

struct FakeNativeHistoryState {
    items: Vec<NativeItemFixture>,
    fail_next: Option<NativeHistoryReadError>,
}

struct ControlledNativeHistoryReader {
    expected_adapter_state_key: RuntimeId,
    reads: Vec<Vec<NativeItemFixture>>,
    entered: AtomicUsize,
    entered_notify: Notify,
    release_first: Semaphore,
    expected_receipt_on_second: StdMutex<
        Option<(
            crate::runtime::history_receipt::HistoryOnlyReceiptRegistry,
            RuntimeId,
            RuntimeId,
        )>,
    >,
    second_entry_saw_first_receipt: AtomicBool,
}

impl ControlledNativeHistoryReader {
    fn new(expected_adapter_state_key: RuntimeId, reads: Vec<Vec<NativeItemFixture>>) -> Self {
        Self {
            expected_adapter_state_key,
            reads,
            entered: AtomicUsize::new(0),
            entered_notify: Notify::new(),
            release_first: Semaphore::new(0),
            expected_receipt_on_second: StdMutex::new(None),
            second_entry_saw_first_receipt: AtomicBool::new(false),
        }
    }

    fn expect_receipt_before_second_read(
        &self,
        registry: crate::runtime::history_receipt::HistoryOnlyReceiptRegistry,
        conversation_id: RuntimeId,
        command_id: RuntimeId,
    ) {
        *self
            .expected_receipt_on_second
            .lock()
            .expect("lock controlled receipt expectation") =
            Some((registry, conversation_id, command_id));
    }

    async fn wait_until_entered(&self, count: usize) {
        timeout(Duration::from_secs(2), async {
            loop {
                let notified = self.entered_notify.notified();
                if self.entered.load(Ordering::Acquire) >= count {
                    break;
                }
                notified.await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("controlled native reader call {count} did not enter"));
    }

    fn entered(&self) -> usize {
        self.entered.load(Ordering::Acquire)
    }

    fn release_first(&self) {
        self.release_first.add_permits(1);
    }

    fn second_entry_saw_first_receipt(&self) -> bool {
        self.second_entry_saw_first_receipt.load(Ordering::Acquire)
    }
}

impl FakeNativeHistoryReader {
    fn new(expected_adapter_state_key: RuntimeId, items: Vec<NativeItemFixture>) -> Self {
        Self {
            expected_adapter_state_key,
            state: StdMutex::new(FakeNativeHistoryState {
                items,
                fail_next: None,
            }),
        }
    }

    fn append(&self, item: NativeItemFixture) {
        self.state
            .lock()
            .expect("lock fake native history append")
            .items
            .push(item);
    }

    fn fail_next(&self, error: NativeHistoryReadError) {
        self.state
            .lock()
            .expect("lock fake native history failure")
            .fail_next = Some(error);
    }
}

#[async_trait::async_trait]
impl NativeHistoryReader for FakeNativeHistoryReader {
    async fn read_native_history(
        &self,
        adapter_state_key: RuntimeId,
    ) -> Result<CanonicalNativeHistoryRead, NativeHistoryReadError> {
        if adapter_state_key != self.expected_adapter_state_key {
            return Err(NativeHistoryReadError::InvalidSource);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| NativeHistoryReadError::ReadUnavailable)?;
        if let Some(error) = state.fail_next.take() {
            return Err(error);
        }
        let items = state
            .items
            .iter()
            .cloned()
            .map(|fixture| {
                CanonicalNativeHistoryItem::new(
                    NativeTurnKey::from_verified_bytes(fixture.turn_key)
                        .expect("verified fake native turn key"),
                    NativeItemKey::from_verified_bytes(fixture.item_key)
                        .expect("verified fake native item key"),
                    fixture.item,
                )
                .expect("modeled fake native history item")
            })
            .collect();
        CanonicalNativeHistoryRead::new(AgentKind::ClaudeCode, items, 4 * 1024)
            .map_err(|_| NativeHistoryReadError::InvalidSource)
    }
}

#[async_trait::async_trait]
impl NativeHistoryReader for ControlledNativeHistoryReader {
    async fn read_native_history(
        &self,
        adapter_state_key: RuntimeId,
    ) -> Result<CanonicalNativeHistoryRead, NativeHistoryReadError> {
        if adapter_state_key != self.expected_adapter_state_key {
            return Err(NativeHistoryReadError::InvalidSource);
        }
        let call = self.entered.fetch_add(1, Ordering::AcqRel);
        let fixtures = self
            .reads
            .get(call)
            .cloned()
            .ok_or(NativeHistoryReadError::ReadUnavailable)?;
        if call == 1 {
            let expectation = self
                .expected_receipt_on_second
                .lock()
                .map_err(|_| NativeHistoryReadError::ReadUnavailable)?
                .clone()
                .ok_or(NativeHistoryReadError::ReadUnavailable)?;
            let observed = expectation
                .0
                .contains(expectation.1, expectation.2)
                .map_err(|_| NativeHistoryReadError::ReadUnavailable)?;
            self.second_entry_saw_first_receipt
                .store(observed, Ordering::Release);
        }
        self.entered_notify.notify_one();
        if call == 0 {
            let permit = self
                .release_first
                .acquire()
                .await
                .map_err(|_| NativeHistoryReadError::ReadUnavailable)?;
            permit.forget();
        }
        let items = fixtures
            .into_iter()
            .map(|fixture| {
                CanonicalNativeHistoryItem::new(
                    NativeTurnKey::from_verified_bytes(fixture.turn_key)
                        .expect("verified controlled native turn key"),
                    NativeItemKey::from_verified_bytes(fixture.item_key)
                        .expect("verified controlled native item key"),
                    fixture.item,
                )
                .expect("modeled controlled native history item")
            })
            .collect();
        CanonicalNativeHistoryRead::new(AgentKind::ClaudeCode, items, 4 * 1024)
            .map_err(|_| NativeHistoryReadError::InvalidSource)
    }
}

fn native_item(turn: u8, item: u8, body: AgentItem) -> NativeItemFixture {
    NativeItemFixture {
        turn_key: [turn; 32],
        item_key: [item; 32],
        item: body,
    }
}

fn initial_native_items() -> Vec<NativeItemFixture> {
    vec![
        native_item(
            0x11,
            0x21,
            AgentItem::UserMessage {
                text: "native user turn".to_owned(),
                meta: AgentItemMeta::default(),
            },
        ),
        native_item(
            0x11,
            0x22,
            AgentItem::AssistantMessage {
                text: NATIVE_BODY_SENTINEL.to_owned(),
                meta: AgentItemMeta::default(),
            },
        ),
        native_item(
            0x12,
            0x23,
            AgentItem::AssistantMessage {
                text: "native second turn".to_owned(),
                meta: AgentItemMeta::default(),
            },
        ),
    ]
}

fn native_configuration() -> ConversationConfiguration {
    ConversationConfiguration::new(VendorConfigurationSnapshot::ClaudeCode(
        ClaudeCodeConversationConfiguration::new(
            ClaudeCodePermissionMode::Default,
            None,
            None,
            None,
        )
        .expect("valid native Dynamic configuration"),
    ))
}

async fn native_dynamic_core(
    root: &TestRoot,
) -> (Arc<RuntimeCore>, Arc<FakeNativeHistoryReader>, RuntimeId) {
    let store = root.open_store().await;
    let imported = store
        .claude_code_native_projection_store()
        .import(ImportNativeProjection {
            descriptor: ConversationDescriptor {
                agent_kind: AgentKind::ClaudeCode,
                title: None,
                cwd: PathBuf::new(),
            },
            default_configuration: native_configuration(),
            private_reference: SecretBytes::new(PRIVATE_REFERENCE_SENTINEL.to_vec()),
            scan_generation: [0x61; 16],
        })
        .await
        .expect("import real NativeProjected conversation and private binding");
    let ImportNativeProjectionOutcome::Imported { conversation, .. } = imported else {
        panic!("fresh Dynamic fixture must import exactly once")
    };
    let reader = Arc::new(FakeNativeHistoryReader::new(
        conversation.adapter_state_key,
        initial_native_items(),
    ));
    let mut router = AgentRouter::with_runtime_store(store.clone());
    router.register_native_history_reader(AgentKind::ClaudeCode, reader.clone());
    let core = Arc::new(
        RuntimeCore::new(store, Arc::new(router), [0xD1; 32])
            .expect("construct Dynamic native RuntimeCore"),
    );
    core.recover()
        .await
        .expect("recover Dynamic native RuntimeCore");
    (core, reader, conversation.conversation_id)
}

async fn controlled_native_dynamic_core(
    root: &TestRoot,
    reads: Vec<Vec<NativeItemFixture>>,
) -> (
    Arc<RuntimeCore>,
    Arc<ControlledNativeHistoryReader>,
    RuntimeId,
) {
    let store = root.open_store().await;
    let imported = store
        .claude_code_native_projection_store()
        .import(ImportNativeProjection {
            descriptor: ConversationDescriptor {
                agent_kind: AgentKind::ClaudeCode,
                title: None,
                cwd: PathBuf::new(),
            },
            default_configuration: native_configuration(),
            private_reference: SecretBytes::new(PRIVATE_REFERENCE_SENTINEL.to_vec()),
            scan_generation: [0x62; 16],
        })
        .await
        .expect("import controlled NativeProjected conversation");
    let ImportNativeProjectionOutcome::Imported { conversation, .. } = imported else {
        panic!("fresh controlled Dynamic fixture must import exactly once")
    };
    let reader = Arc::new(ControlledNativeHistoryReader::new(
        conversation.adapter_state_key,
        reads,
    ));
    let mut router = AgentRouter::with_runtime_store(store.clone());
    router.register_native_history_reader(AgentKind::ClaudeCode, reader.clone());
    let core = Arc::new(
        RuntimeCore::new(store, Arc::new(router), [0xD2; 32])
            .expect("construct controlled Dynamic native RuntimeCore"),
    );
    core.recover()
        .await
        .expect("recover controlled Dynamic native RuntimeCore");
    (core, reader, conversation.conversation_id)
}

#[derive(Debug, Eq, PartialEq)]
struct DurableEvidence {
    snapshot_rows: i64,
    event_rows: i64,
    event_stream_rows: i64,
    ledger_command_count: i64,
    ledger_event_count: i64,
    ledger_snapshot_count: i64,
    ledger_snapshot_bytes: i64,
    ledger_token: Vec<u8>,
    main: Vec<u8>,
    wal: Option<Vec<u8>>,
}

fn durable_evidence(database: &Path) -> DurableEvidence {
    let connection = Connection::open_with_flags(
        database,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("open Dynamic durable evidence read-only");
    let scalar = |query: &str| {
        connection
            .query_row(query, [], |row| row.get(0))
            .expect("read Dynamic durable scalar")
    };
    let (
        ledger_command_count,
        ledger_event_count,
        ledger_snapshot_count,
        ledger_snapshot_bytes,
        ledger_token,
    ) = connection
        .query_row(
            "SELECT command_count, event_count, snapshot_count, snapshot_bytes, metadata_token
             FROM runtime_meta WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .expect("read Dynamic authenticated ledger evidence");
    let evidence = DurableEvidence {
        snapshot_rows: scalar("SELECT COUNT(*) FROM snapshots"),
        event_rows: scalar("SELECT COUNT(*) FROM event_journal"),
        event_stream_rows: scalar("SELECT COUNT(*) FROM event_stream_index"),
        ledger_command_count,
        ledger_event_count,
        ledger_snapshot_count,
        ledger_snapshot_bytes,
        ledger_token,
        main: Vec::new(),
        wal: None,
    };
    drop(connection);
    let main = fs::read(database).expect("read Dynamic runtime main database");
    let wal = fs::read(PathBuf::from(format!("{}-wal", database.display()))).ok();
    DurableEvidence {
        main,
        wal,
        ..evidence
    }
}

fn artifacts_contain(evidence: &DurableEvidence, needle: &[u8]) -> bool {
    evidence
        .main
        .windows(needle.len())
        .any(|window| window == needle)
        || evidence
            .wal
            .as_ref()
            .is_some_and(|wal| wal.windows(needle.len()).any(|window| window == needle))
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProjectedIdentity {
    command_id: String,
    item_id: String,
    entity_id: String,
}

fn projected_identities(snapshot: &ConversationSnapshot) -> Vec<ProjectedIdentity> {
    let SnapshotItem::Capabilities { capabilities, .. } = &snapshot.items()[0] else {
        panic!("Dynamic snapshot must start with Capabilities")
    };
    assert_eq!(capabilities.agent_kind, AgentKind::ClaudeCode);
    snapshot
        .items()
        .iter()
        .skip(1)
        .map(|item| {
            let SnapshotItem::Item {
                command_id: Some(command_id),
                item_id,
                entity_id,
                ..
            } = item
            else {
                panic!("native Dynamic body must use fully identified SnapshotItem::Item")
            };
            ProjectedIdentity {
                command_id: command_id.as_str().to_owned(),
                item_id: item_id.as_str().to_owned(),
                entity_id: entity_id.as_str().to_owned(),
            }
        })
        .collect()
}

async fn subscribe_and_flush_dynamic(
    core: &RuntimeCore,
    conversation_id: RuntimeId,
    seed: u8,
    message: &str,
) -> ConversationSnapshot {
    let (connection, mut receiver) = connect_recording(core, seed).await;
    core.handle_envelope(
        connection,
        subscribe_conversation_envelope(message, conversation_id),
    )
    .await
    .expect("start Dynamic subscription");
    assert!(matches!(
        receive_envelope_and_ack(&mut receiver, "Dynamic subscription receipt")
            .await
            .body,
        RuntimeMessage::Reply(RuntimeReply::Subscription(
            SubscriptionReceipt::Subscribed { .. }
        ))
    ));
    let envelope = receive_envelope_and_ack(&mut receiver, "Dynamic snapshot").await;
    let RuntimeMessage::Reply(RuntimeReply::Snapshot(snapshot)) = envelope.body else {
        panic!("expected canonical Dynamic snapshot")
    };
    assert!(matches!(
        receive_envelope_and_ack(&mut receiver, "Dynamic sync complete")
            .await
            .body,
        RuntimeMessage::Reply(RuntimeReply::SyncComplete(_))
    ));
    assert_eq!(
        core.store
            .active_snapshot_build_pin_count_for_test()
            .await
            .expect("count flushed Dynamic TEMP pin"),
        0
    );
    core.disconnect(connection).await;
    snapshot
}

async fn wait_for_zero_dynamic_pins(core: &RuntimeCore) {
    timeout(Duration::from_secs(2), async {
        loop {
            if core
                .store
                .active_snapshot_build_pin_count_for_test()
                .await
                .expect("count Dynamic TEMP pins")
                == 0
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("Dynamic TEMP pin cleanup must complete");
}

#[tokio::test]
async fn native_dynamic_snapshot_is_ephemeral_queryable_and_identity_stable_across_append() {
    let root = TestRoot::new("native-dynamic-consumer");
    let (core, reader, conversation_id) = native_dynamic_core(&root).await;
    let durable_before = durable_evidence(&root.path.join("runtime.db"));
    assert!(!artifacts_contain(
        &durable_before,
        NATIVE_BODY_SENTINEL.as_bytes()
    ));

    let query_connection = connect_local(&core, 0xD2).await;
    let (subscription_connection, mut receiver) = connect_recording(&core, 0xD3).await;
    core.handle_envelope(
        subscription_connection,
        subscribe_conversation_envelope("native-dynamic-first", conversation_id),
    )
    .await
    .expect("start first Dynamic subscription");
    assert!(matches!(
        receive_envelope_and_ack(&mut receiver, "first Dynamic subscription receipt")
            .await
            .body,
        RuntimeMessage::Reply(RuntimeReply::Subscription(
            SubscriptionReceipt::Subscribed { .. }
        ))
    ));
    let snapshot_write = timeout(Duration::from_secs(2), receiver.recv())
        .await
        .expect("first Dynamic snapshot timeout")
        .expect("first Dynamic snapshot writer");
    let adapter_state_wire_sentinel = reader.expected_adapter_state_key.to_canonical_string();
    assert!(
        snapshot_write
            .bytes()
            .windows(NATIVE_BODY_SENTINEL.len())
            .any(|window| window == NATIVE_BODY_SENTINEL.as_bytes())
    );
    assert!(
        !snapshot_write
            .bytes()
            .windows(PRIVATE_REFERENCE_SENTINEL.len())
            .any(|window| window == PRIVATE_REFERENCE_SENTINEL)
    );
    assert!(
        !snapshot_write
            .bytes()
            .windows(adapter_state_wire_sentinel.len())
            .any(|window| window == adapter_state_wire_sentinel.as_bytes())
    );
    let RuntimeMessage::Reply(RuntimeReply::Snapshot(first_snapshot)) =
        decode(&snapshot_write).body
    else {
        panic!("expected first Dynamic snapshot")
    };
    let first_identities = projected_identities(&first_snapshot);
    assert_eq!(first_identities.len(), 3);
    assert_eq!(
        first_identities[0].command_id, first_identities[1].command_id,
        "all items from one native turn must share one derived commandId"
    );
    assert_ne!(
        first_identities[1].command_id,
        first_identities[2].command_id
    );
    assert_eq!(
        core.store
            .active_snapshot_build_pin_count_for_test()
            .await
            .expect("count unflushed Dynamic TEMP pin"),
        1,
        "wire payload and exact TEMP pin must remain leased until transport flush"
    );

    let preflush_query = core
        .handle(
            query_connection,
            RuntimeRequest::QueryReceipt(QueryReceiptSelector::Command {
                conversation_id: first_snapshot.conversation_id.clone(),
                command_id: agentdeck_protocol::runtime::identity::CommandId::new(
                    first_identities[0].command_id.clone(),
                ),
            }),
        )
        .await;
    assert!(matches!(
        preflush_query,
        RuntimeReply::Failure(RuntimeFailure { code, .. })
            if code == DAEMON_COMMAND_HISTORY_ONLY
    ));

    snapshot_write
        .acknowledge()
        .expect("flush first Dynamic snapshot");
    assert!(matches!(
        receive_envelope_and_ack(&mut receiver, "first Dynamic sync complete")
            .await
            .body,
        RuntimeMessage::Reply(RuntimeReply::SyncComplete(_))
    ));
    assert_eq!(
        core.store
            .active_snapshot_build_pin_count_for_test()
            .await
            .expect("count released first Dynamic TEMP pin"),
        0
    );
    core.disconnect(subscription_connection).await;

    let reread =
        subscribe_and_flush_dynamic(&core, conversation_id, 0xD4, "native-dynamic-reread").await;
    assert_eq!(projected_identities(&reread), first_identities);

    let appended_native_item = native_item(
        0x13,
        0x24,
        AgentItem::AssistantMessage {
            text: "native appended turn".to_owned(),
            meta: AgentItemMeta::default(),
        },
    );
    reader.append(appended_native_item.clone());
    let appended =
        subscribe_and_flush_dynamic(&core, conversation_id, 0xD5, "native-dynamic-append").await;
    let appended_identities = projected_identities(&appended);
    assert_eq!(
        &appended_identities[..first_identities.len()],
        &first_identities
    );
    assert_eq!(appended_identities.len(), first_identities.len() + 1);

    let durable_after = durable_evidence(&root.path.join("runtime.db"));
    assert_eq!(
        durable_after, durable_before,
        "Dynamic reads must not add snapshot/event/ledger/main+WAL durable bytes"
    );
    assert!(!artifacts_contain(
        &durable_after,
        NATIVE_BODY_SENTINEL.as_bytes()
    ));

    core.disconnect(query_connection).await;
    core.shutdown()
        .await
        .expect("shutdown Dynamic consumer core");
    drop(core);

    let reopened_store = root.open_store().await;
    let mut reopened_items = initial_native_items();
    reopened_items.push(appended_native_item);
    let reopened_reader = Arc::new(FakeNativeHistoryReader::new(
        reader.expected_adapter_state_key,
        reopened_items,
    ));
    let mut reopened_router = AgentRouter::with_runtime_store(reopened_store.clone());
    reopened_router.register_native_history_reader(AgentKind::ClaudeCode, reopened_reader);
    let reopened_core = Arc::new(
        RuntimeCore::new(reopened_store, Arc::new(reopened_router), [0xD1; 32])
            .expect("construct reopened Dynamic native RuntimeCore"),
    );
    reopened_core
        .recover()
        .await
        .expect("recover reopened Dynamic native RuntimeCore");
    let after_restart = subscribe_and_flush_dynamic(
        &reopened_core,
        conversation_id,
        0xD8,
        "native-dynamic-after-restart",
    )
    .await;
    assert_eq!(
        projected_identities(&after_restart),
        appended_identities,
        "same StorageKEK and native keys must preserve every command/item/entity ID across restart"
    );
    reopened_core
        .shutdown()
        .await
        .expect("shutdown reopened Dynamic consumer core");
}

#[tokio::test]
async fn native_reader_failure_preserves_last_successful_history_receipts() {
    let root = TestRoot::new("native-dynamic-reader-failure");
    let (core, reader, conversation_id) = native_dynamic_core(&root).await;
    let successful =
        subscribe_and_flush_dynamic(&core, conversation_id, 0xD6, "native-dynamic-success").await;
    let successful_identities = projected_identities(&successful);
    let retained_command =
        parse_command_id(&agentdeck_protocol::runtime::identity::CommandId::new(
            successful_identities[0].command_id.clone(),
        ))
        .expect("parse derived history command");
    assert!(
        core.history_receipts
            .contains(conversation_id, retained_command)
            .expect("inspect successful history receipt set")
    );

    reader.fail_next(NativeHistoryReadError::ReadUnavailable);
    let (connection, mut receiver) = connect_recording(&core, 0xD7).await;
    core.handle_envelope(
        connection,
        subscribe_conversation_envelope("native-dynamic-reader-failure", conversation_id),
    )
    .await
    .expect("start failing Dynamic subscription");
    assert!(matches!(
        receive_envelope_and_ack(&mut receiver, "failing Dynamic subscription receipt")
            .await
            .body,
        RuntimeMessage::Reply(RuntimeReply::Subscription(
            SubscriptionReceipt::Subscribed { .. }
        ))
    ));
    let failure = receive_envelope_and_ack(&mut receiver, "failing Dynamic terminal").await;
    assert!(matches!(
        failure.body,
        RuntimeMessage::Reply(RuntimeReply::Failure(RuntimeFailure { code, .. }))
            if code == DAEMON_RUNTIME_READ_UNAVAILABLE
    ));
    assert!(
        core.history_receipts
            .contains(conversation_id, retained_command)
            .expect("inspect receipts after failed native read"),
        "a failed read must not clear or replace the last successful volatile set"
    );
    wait_for_zero_dynamic_pins(&core).await;

    core.disconnect(connection).await;
    core.shutdown()
        .await
        .expect("shutdown failed Dynamic reader core");
}

#[tokio::test]
async fn dynamic_reads_linearize_receipt_replace_before_the_next_reader_enters() {
    let root = TestRoot::new("native-dynamic-receipt-linearization");
    let first_read = initial_native_items();
    let second_read = vec![native_item(
        0x31,
        0x41,
        AgentItem::AssistantMessage {
            text: "newer controlled native transcript".to_owned(),
            meta: AgentItemMeta::default(),
        },
    )];
    let (core, reader, conversation_id) =
        controlled_native_dynamic_core(&root, vec![first_read, second_read]).await;
    let expected_first_command = core
        .store
        .derive_native_history_command_id(conversation_id, &[0x11; 32])
        .expect("derive expected first controlled history command");
    reader.expect_receipt_before_second_read(
        core.history_receipts.clone(),
        conversation_id,
        expected_first_command,
    );

    let (first_connection, mut first_receiver) = connect_recording(&core, 0xE1).await;
    let (second_connection, mut second_receiver) = connect_recording(&core, 0xE2).await;
    core.handle_envelope(
        first_connection,
        subscribe_conversation_envelope("dynamic-linearization-first", conversation_id),
    )
    .await
    .expect("start first controlled Dynamic subscription");
    assert!(matches!(
        receive_envelope_and_ack(&mut first_receiver, "first controlled subscription receipt")
            .await
            .body,
        RuntimeMessage::Reply(RuntimeReply::Subscription(
            SubscriptionReceipt::Subscribed { .. }
        ))
    ));
    reader.wait_until_entered(1).await;

    core.handle_envelope(
        second_connection,
        subscribe_conversation_envelope("dynamic-linearization-second", conversation_id),
    )
    .await
    .expect("start second controlled Dynamic subscription");
    assert!(matches!(
        receive_envelope_and_ack(
            &mut second_receiver,
            "second controlled subscription receipt"
        )
        .await
        .body,
        RuntimeMessage::Reply(RuntimeReply::Subscription(
            SubscriptionReceipt::Subscribed { .. }
        ))
    ));
    assert_eq!(
        reader.entered(),
        1,
        "the second connection must remain outside the reader while the first read owns the gate"
    );

    reader.release_first();
    let first_write = timeout(Duration::from_secs(2), first_receiver.recv())
        .await
        .expect("first controlled Dynamic snapshot timeout")
        .expect("first controlled Dynamic snapshot writer");
    let RuntimeMessage::Reply(RuntimeReply::Snapshot(first_snapshot)) = decode(&first_write).body
    else {
        panic!("expected first controlled Dynamic snapshot")
    };
    let first_identities = projected_identities(&first_snapshot);
    assert_eq!(first_identities.len(), 3);
    assert!(
        core.history_receipts
            .contains(conversation_id, expected_first_command)
            .expect("inspect first linearized receipt"),
        "receipt replacement must complete before the first snapshot reaches egress"
    );
    assert!(
        timeout(Duration::from_millis(50), reader.wait_until_entered(2))
            .await
            .is_err(),
        "the second reader must not enter before the first payload releases its memory owner"
    );

    first_write
        .acknowledge()
        .expect("flush first controlled Dynamic snapshot");
    reader.wait_until_entered(2).await;
    assert!(
        reader.second_entry_saw_first_receipt(),
        "the next native reader must enter only after the prior receipt set is linearized"
    );

    let second_write = timeout(Duration::from_secs(2), second_receiver.recv())
        .await
        .expect("second controlled Dynamic snapshot timeout")
        .expect("second controlled Dynamic snapshot writer");
    let RuntimeMessage::Reply(RuntimeReply::Snapshot(second_snapshot)) = decode(&second_write).body
    else {
        panic!("expected second controlled Dynamic snapshot")
    };
    let second_identities = projected_identities(&second_snapshot);
    assert_eq!(second_identities.len(), 1);
    let second_command = parse_command_id(&agentdeck_protocol::runtime::identity::CommandId::new(
        second_identities[0].command_id.clone(),
    ))
    .expect("parse newer controlled history command");
    assert!(
        !core
            .history_receipts
            .contains(conversation_id, expected_first_command)
            .expect("inspect removed first receipt"),
        "the older read must never overwrite the newer complete receipt set"
    );
    assert!(
        core.history_receipts
            .contains(conversation_id, second_command)
            .expect("inspect newer receipt")
    );

    second_write
        .acknowledge()
        .expect("flush second controlled Dynamic snapshot");
    assert!(matches!(
        receive_envelope_and_ack(&mut first_receiver, "first controlled Dynamic sync")
            .await
            .body,
        RuntimeMessage::Reply(RuntimeReply::SyncComplete(_))
    ));
    assert!(matches!(
        receive_envelope_and_ack(&mut second_receiver, "second controlled Dynamic sync")
            .await
            .body,
        RuntimeMessage::Reply(RuntimeReply::SyncComplete(_))
    ));

    core.disconnect(first_connection).await;
    core.disconnect(second_connection).await;
    core.shutdown()
        .await
        .expect("shutdown controlled Dynamic reader core");
}
