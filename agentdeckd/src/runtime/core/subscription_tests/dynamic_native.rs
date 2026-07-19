use super::*;

use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use agentdeck_protocol::runtime::failure::{
    DAEMON_COMMAND_HISTORY_ONLY, DAEMON_RUNTIME_READ_UNAVAILABLE,
};
use agentdeck_protocol::runtime::{
    ClaudeCodeConversationConfiguration, ConversationConfiguration, QueryReceiptSelector,
    RuntimeFailure, RuntimeTransferChannel, TransferProgress, TransferReassembler,
    VendorConfigurationSnapshot,
};
use agentdeck_protocol::{AgentItem, AgentItemMeta, AgentKind, ClaudeCodePermissionMode};
use rusqlite::{Connection, OpenFlags};
use tokio::sync::{Notify, Semaphore};
use tokio::time::Instant;

use crate::agent::{
    CanonicalNativeHistoryItem, CanonicalNativeHistoryRead, NativeHistoryReadError,
    NativeHistoryReader, NativeItemKey, NativeProjectionStep, NativeTurnKey,
    native_projection_scan_issuer_for_test,
};
use crate::runtime::store::{
    ConversationDescriptor, ImportNativeProjection, ImportNativeProjectionOutcome, RuntimeId,
    SnapshotOrigin,
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

enum RealDynamicAttempt {
    Snapshot {
        snapshot: ConversationSnapshot,
        reassembled_transfer: bool,
    },
    TypedFailure,
}

async fn receive_real_dynamic_envelope(
    receiver: &mut mpsc::Receiver<crate::runtime::ConnectionWrite>,
    global_deadline: Instant,
) -> Result<RuntimeEnvelope, &'static str> {
    let frame_deadline = std::cmp::min(global_deadline, Instant::now() + Duration::from_secs(2));
    let write = tokio::time::timeout_at(frame_deadline, receiver.recv())
        .await
        .map_err(|_| "real Dynamic candidate reply timed out")?
        .ok_or("real Dynamic candidate writer closed")?;
    let decoded = serde_json::from_slice(write.bytes());
    write
        .acknowledge()
        .map_err(|_| "real Dynamic candidate reply ACK failed")?;
    decoded.map_err(|_| "real Dynamic candidate reply was not a Runtime envelope")
}

async fn wait_for_zero_dynamic_pins_result(core: &RuntimeCore) -> Result<(), &'static str> {
    timeout(Duration::from_secs(2), async {
        loop {
            let count = core
                .store
                .active_snapshot_build_pin_count_for_test()
                .await
                .map_err(|_| "count real Dynamic TEMP pins failed")?;
            if count == 0 {
                return Ok(());
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|_| "real Dynamic TEMP pin cleanup timed out")?
}

async fn try_real_dynamic_snapshot(
    core: &RuntimeCore,
    conversation_id: RuntimeId,
    owner_seed: u8,
    message: &str,
    global_deadline: Instant,
) -> Result<RealDynamicAttempt, &'static str> {
    let (connection, mut receiver) = connect_recording(core, owner_seed).await;
    let attempt = async {
        tokio::time::timeout_at(
            global_deadline,
            core.handle_envelope(
                connection,
                subscribe_conversation_envelope(message, conversation_id),
            ),
        )
        .await
        .map_err(|_| "start real Dynamic candidate subscription timed out")?
        .map_err(|_| "start real Dynamic candidate subscription failed")?;
        if !matches!(
            receive_real_dynamic_envelope(&mut receiver, global_deadline)
                .await?
                .body,
            RuntimeMessage::Reply(RuntimeReply::Subscription(
                SubscriptionReceipt::Subscribed { .. }
            ))
        ) {
            return Err("real Dynamic candidate did not return a subscription receipt");
        }

        match receive_real_dynamic_envelope(&mut receiver, global_deadline)
            .await?
            .body
        {
            RuntimeMessage::Reply(RuntimeReply::Snapshot(snapshot)) => {
                match receive_real_dynamic_envelope(&mut receiver, global_deadline)
                    .await?
                    .body
                {
                    RuntimeMessage::Reply(RuntimeReply::SyncComplete(_)) => {
                        Ok(RealDynamicAttempt::Snapshot {
                            snapshot,
                            reassembled_transfer: false,
                        })
                    }
                    RuntimeMessage::Reply(RuntimeReply::Failure(_)) => {
                        Ok(RealDynamicAttempt::TypedFailure)
                    }
                    _ => Err("real Dynamic snapshot did not terminate with SyncComplete"),
                }
            }
            RuntimeMessage::Reply(RuntimeReply::Failure(_)) => Ok(RealDynamicAttempt::TypedFailure),
            RuntimeMessage::Reply(RuntimeReply::TransferPart(first_part)) => {
                let transfer_started = Instant::now();
                let mut reassembler = TransferReassembler::new();
                let mut next_part = Some(first_part);
                let payload = loop {
                    let part = if let Some(first) = next_part.take() {
                        first
                    } else {
                        match receive_real_dynamic_envelope(&mut receiver, global_deadline)
                            .await?
                            .body
                        {
                            RuntimeMessage::Reply(RuntimeReply::TransferPart(part)) => part,
                            RuntimeMessage::Reply(RuntimeReply::Failure(_)) => {
                                return Ok(RealDynamicAttempt::TypedFailure);
                            }
                            _ => return Err("real Dynamic transfer ended before completion"),
                        }
                    };
                    let now_ms =
                        u64::try_from(transfer_started.elapsed().as_millis()).unwrap_or(u64::MAX);
                    match reassembler
                        .accept_json(RuntimeTransferChannel::Reply, part, now_ms)
                        .map_err(|_| "real Dynamic transfer failed integrity validation")?
                    {
                        TransferProgress::InProgress { .. } => {}
                        TransferProgress::Complete(payload) => break payload,
                        TransferProgress::AlreadyComplete => {
                            return Err("real Dynamic transfer completed more than once");
                        }
                    }
                };
                let snapshot: ConversationSnapshot = serde_json::from_slice(&payload)
                    .map_err(|_| "real Dynamic transfer was not a ConversationSnapshot")?;
                match receive_real_dynamic_envelope(&mut receiver, global_deadline)
                    .await?
                    .body
                {
                    RuntimeMessage::Reply(RuntimeReply::SyncComplete(_)) => {
                        Ok(RealDynamicAttempt::Snapshot {
                            snapshot,
                            reassembled_transfer: true,
                        })
                    }
                    RuntimeMessage::Reply(RuntimeReply::Failure(_)) => {
                        Ok(RealDynamicAttempt::TypedFailure)
                    }
                    _ => Err("real Dynamic transfer did not terminate with SyncComplete"),
                }
            }
            _ => Err("real Dynamic candidate returned an unexpected reply family"),
        }
    }
    .await;

    // Candidate-specific failure paths deliberately stop the remaining writer job. Every frame
    // observed above is ACKed; disconnect owns all remaining cleanup.
    core.disconnect(connection).await;
    wait_for_zero_dynamic_pins_result(core).await?;
    attempt
}

#[tokio::test]
async fn real_dynamic_attempt_reassembles_large_snapshot_and_releases_all_pins() {
    let root = TestRoot::new("native-dynamic-real-helper-transfer");
    let (core, reader, conversation_id) = native_dynamic_core(&root).await;
    reader.append(native_item(
        0x13,
        0x24,
        AgentItem::AssistantMessage {
            text: "x".repeat(MAX_JSON_PART_BYTES + 4096),
            meta: AgentItemMeta::default(),
        },
    ));

    let attempt = try_real_dynamic_snapshot(
        &core,
        conversation_id,
        0xDA,
        "native-dynamic-real-helper-transfer",
        Instant::now() + Duration::from_secs(10),
    )
    .await
    .expect("large Dynamic helper attempt");
    let RealDynamicAttempt::Snapshot {
        snapshot,
        reassembled_transfer,
    } = attempt
    else {
        panic!("large valid Dynamic snapshot must not be classified as a typed failure")
    };
    assert!(
        reassembled_transfer,
        "large Dynamic snapshot must exercise the JSON transfer reassembler"
    );
    assert_eq!(projected_identities(&snapshot).len(), 4);
    assert_eq!(
        core.store
            .active_snapshot_build_pin_count_for_test()
            .await
            .expect("count pins after reassembled Dynamic helper"),
        0
    );

    core.shutdown()
        .await
        .expect("shutdown reassembled Dynamic helper core");
}

#[tokio::test]
async fn real_dynamic_attempt_deadline_disconnects_and_releases_all_pins() {
    let root = TestRoot::new("native-dynamic-real-helper-deadline");
    let (core, reader, conversation_id) =
        controlled_native_dynamic_core(&root, vec![initial_native_items()]).await;
    let result = try_real_dynamic_snapshot(
        &core,
        conversation_id,
        0xDB,
        "native-dynamic-real-helper-deadline",
        Instant::now() + Duration::from_millis(500),
    )
    .await;
    assert!(
        matches!(result, Err(reason) if reason.contains("timed out")),
        "blocked Dynamic helper must return its typed test timeout"
    );
    assert_eq!(reader.entered(), 1);
    assert_eq!(
        core.store
            .active_snapshot_build_pin_count_for_test()
            .await
            .expect("count pins after Dynamic helper deadline"),
        0
    );

    core.shutdown()
        .await
        .expect("shutdown timed-out Dynamic helper core");
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
    wait_for_zero_dynamic_pins_result(core)
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
async fn removed_then_reappeared_dynamic_snapshot_rebuilds_history_receipt_set() {
    let root = TestRoot::new("native-dynamic-reappeared-receipts");
    let (core, _reader, conversation_id) = native_dynamic_core(&root).await;
    let first = subscribe_and_flush_dynamic(
        &core,
        conversation_id,
        0xD9,
        "native-dynamic-before-removed",
    )
    .await;
    let first_identities = projected_identities(&first);
    let first_command = parse_command_id(&agentdeck_protocol::runtime::identity::CommandId::new(
        first_identities[0].command_id.clone(),
    ))
    .expect("parse pre-Removed history command");
    assert!(
        core.history_receipts
            .contains(conversation_id, first_command)
            .expect("inspect pre-Removed history receipt")
    );

    // 用真实 Store plan + actor lease 执行一页完整 Removed lifecycle。projector
    // focused tests 另行锁定 apply failure/unknown 的 exact 顺序；这里验证 Core 内
    // 与 dynamic snapshot 共享的同一个 volatile registry 会先失效、后重建。
    let removed_generation = [0x64; 16];
    let completed = native_projection_scan_issuer_for_test(removed_generation)
        .expect("issue completed Removed generation")
        .complete(removed_generation, 0, 0)
        .expect("complete empty Removed generation");
    let projector_store = core.store.claude_code_native_projection_store();
    let completed = projector_store
        .accept_completed_scan(completed)
        .await
        .expect("accept Removed generation");
    let plan = projector_store
        .plan_completed_page(completed, None)
        .await
        .expect("plan Removed generation");
    let lease = core
        .conversations
        .prepare_projection_reconciliation(plan.candidate_ids().collect::<Vec<_>>())
        .await;
    let dispositions = lease.dispositions();
    let removed_ids = lease.removed_conversation_ids().collect::<Vec<_>>();
    projector_store
        .apply_completed_page(plan, dispositions)
        .await
        .expect("durably apply Removed generation");
    for removed_id in removed_ids {
        core.history_receipts
            .clear(removed_id)
            .expect("clear exact durable Removed receipt set");
    }
    core.conversations
        .uninstall_reconciled(lease)
        .await
        .expect("uninstall durable Removed actor");
    assert!(
        !core
            .history_receipts
            .contains(conversation_id, first_command)
            .expect("inspect receipt after Removed")
    );

    let reappeared = projector_store
        .import(ImportNativeProjection {
            descriptor: ConversationDescriptor {
                agent_kind: AgentKind::ClaudeCode,
                title: None,
                cwd: PathBuf::new(),
            },
            default_configuration: native_configuration(),
            private_reference: SecretBytes::new(PRIVATE_REFERENCE_SENTINEL.to_vec()),
            scan_generation: [0x65; 16],
        })
        .await
        .expect("reimport the same verified native source");
    let ImportNativeProjectionOutcome::Reappeared { conversation, .. } = reappeared else {
        panic!("tombstoned native source must reappear with its stable identity")
    };
    assert_eq!(conversation.conversation_id, conversation_id);
    core.conversations
        .install(conversation, Vec::new())
        .await
        .expect("reinstall reappeared native actor");
    assert!(
        !core
            .history_receipts
            .contains(conversation_id, first_command)
            .expect("reappearance alone must not synthesize receipts"),
        "only a successful verified dynamic read may rebuild the receipt set"
    );

    let reread = subscribe_and_flush_dynamic(
        &core,
        conversation_id,
        0xDA,
        "native-dynamic-after-reappeared",
    )
    .await;
    assert_eq!(projected_identities(&reread), first_identities);
    assert!(
        core.history_receipts
            .contains(conversation_id, first_command)
            .expect("inspect rebuilt reappeared receipt"),
        "successful reappeared Dynamic snapshot must atomically replace the receipt set"
    );

    core.shutdown()
        .await
        .expect("shutdown reappeared Dynamic receipt core");
}

/// Opt-in real current-account smoke。它不需要或执行 `claude` binary，只经 production
/// native source 只读扫描当前 EUID 的 verified JSONL，再走 Runtime Catalog 与 dynamic
/// Snapshot。输出严格限制为计数和 neutral Runtime ID kind。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires AGENTDECK_E2E=1 and at least one current-account Claude Code JSONL"]
async fn real_current_account_jsonl_projects_through_catalog_and_dynamic_snapshot() {
    if std::env::var("AGENTDECK_E2E").as_deref() != Ok("1") {
        eprintln!(
            "BLOCKED real_current_account_jsonl_projects_through_catalog_and_dynamic_snapshot: set AGENTDECK_E2E=1"
        );
        return;
    }

    let root = TestRoot::new("real-current-account-native-projector");
    let store = root.open_store().await;
    let router = Arc::new(AgentRouter::with_runtime_store(store.clone()));
    // 先独立证明 production source 的 list/read/parser seam 至少能交付一条候选；
    // 错误只报告中立 failure enum，绝不输出 path/session/body。
    let mut probe = router
        .begin_native_projection_scan(AgentKind::ClaudeCode, [0xDE; 16])
        .expect("open current-account Claude Code native source");
    let mut probe_found_candidate = false;
    for _ in 0..8 {
        match probe.next() {
            Ok(NativeProjectionStep::Candidate(_)) => {
                probe_found_candidate = true;
                break;
            }
            Ok(NativeProjectionStep::Yielded(_)) => probe
                .resume_after_yield()
                .expect("resume bounded current-account source probe"),
            Ok(NativeProjectionStep::Complete) => break,
            Err(error) => panic!("current-account native source probe failed: {error:?}"),
        }
    }
    assert!(
        probe_found_candidate,
        "current-account native source completed bounded probe without an importable JSONL"
    );
    drop(probe);
    let core = Arc::new(
        RuntimeCore::with_execution_coordinator(
            store,
            router,
            [0xDB; 32],
            Arc::new(DisabledExecutionCoordinator),
            DEFAULT_ADAPTER_CONCURRENCY,
            true,
        )
        .expect("construct real current-account native projector Core"),
    );
    let smoke_core = core.clone();
    let database = root.database();
    let smoke = tokio::spawn(async move {
        const MAX_REAL_CATALOG_PAGES: usize = 32;
        const MAX_REAL_NATIVE_CANDIDATES: usize = 500;
        const MAX_REAL_NATIVE_ATTEMPTS: usize = 64;

        smoke_core
            .recover()
            .await
            .map_err(|_| "recover real current-account native projector Core failed")?;
        let (catalog_connection, mut catalog_receiver) = connect_recording(&smoke_core, 0xDB).await;
        let mut request_index = 0_u64;
        let catalog_ready = timeout(Duration::from_secs(10), async {
            loop {
                let snapshot = request_catalog_page(
                    &smoke_core,
                    catalog_connection,
                    &mut catalog_receiver,
                    &format!("real-native-catalog-ready-{request_index}"),
                    None,
                )
                .await;
                if snapshot
                    .entries()
                    .iter()
                    .any(|entry| entry.agent_kind == AgentKind::ClaudeCode)
                {
                    break;
                }
                request_index = request_index.saturating_add(1);
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .is_ok();
        if !catalog_ready {
            smoke_core.disconnect(catalog_connection).await;
            return Err("bounded production scan imported no current-account Claude Code JSONL");
        }

        // Freeze only projector-owned source work. A fresh frozen catalog read below then
        // enumerates exact authenticated NativeProjected entries without racing continuation.
        smoke_core.native_projector.shutdown().await;
        let candidates = match timeout(Duration::from_secs(20), async {
            let mut candidates = Vec::new();
            let mut page_cursor = None;
            let mut exhausted = false;
            for page_index in 0..MAX_REAL_CATALOG_PAGES {
                let snapshot = request_catalog_page(
                    &smoke_core,
                    catalog_connection,
                    &mut catalog_receiver,
                    &format!("real-native-catalog-frozen-{page_index}"),
                    page_cursor,
                )
                .await;
                for entry in snapshot
                    .entries()
                    .iter()
                    .filter(|entry| entry.agent_kind == AgentKind::ClaudeCode)
                {
                    let conversation_id = parse_conversation_id(&entry.conversation_id)
                        .map_err(|_| "parse neutral Runtime catalog conversation ID failed")?;
                    let context = smoke_core
                        .store
                        .load_authenticated_conversation_snapshot_context(conversation_id)
                        .await
                        .map_err(|_| "authenticate real native catalog candidate failed")?;
                    if context.origin == SnapshotOrigin::NativeProjected {
                        candidates.push(conversation_id);
                        if candidates.len() == MAX_REAL_NATIVE_CANDIDATES {
                            break;
                        }
                    }
                }
                if candidates.len() == MAX_REAL_NATIVE_CANDIDATES {
                    break;
                }
                page_cursor = snapshot.next_page_cursor().cloned();
                if page_cursor.is_none() {
                    exhausted = true;
                    break;
                }
            }
            if !exhausted && candidates.len() < MAX_REAL_NATIVE_CANDIDATES {
                return Err("real native catalog traversal exceeded its page bound");
            }
            if candidates.is_empty() {
                return Err("frozen catalog contained no authenticated NativeProjected candidate");
            }
            Ok::<_, &'static str>(candidates)
        })
        .await
        {
            Ok(result) => result,
            Err(_) => Err("real native catalog traversal timed out"),
        };
        smoke_core.disconnect(catalog_connection).await;
        let candidates = candidates?;
        let durable_before = durable_evidence(&database);

        let mut attempted = 0_usize;
        let mut typed_failures = 0_usize;
        let mut reassembled_transfers = 0_usize;
        let mut changed_between_reads = 0_usize;
        let mut empty_snapshots = 0_usize;
        let dynamic_deadline = Instant::now() + Duration::from_secs(30);
        let mut success = None;
        for (candidate_index, conversation_id) in candidates
            .iter()
            .copied()
            .take(MAX_REAL_NATIVE_ATTEMPTS)
            .enumerate()
        {
            if Instant::now() >= dynamic_deadline {
                break;
            }
            attempted += 1;
            let first = match try_real_dynamic_snapshot(
                &smoke_core,
                conversation_id,
                0xDC,
                &format!("real-native-dynamic-{candidate_index}-first"),
                dynamic_deadline,
            )
            .await?
            {
                RealDynamicAttempt::Snapshot {
                    snapshot,
                    reassembled_transfer,
                } => {
                    reassembled_transfers += usize::from(reassembled_transfer);
                    snapshot
                }
                RealDynamicAttempt::TypedFailure => {
                    typed_failures += 1;
                    continue;
                }
            };
            let first_identities = projected_identities(&first);
            if first_identities.is_empty() {
                empty_snapshots += 1;
                continue;
            }
            let second = match try_real_dynamic_snapshot(
                &smoke_core,
                conversation_id,
                0xDD,
                &format!("real-native-dynamic-{candidate_index}-second"),
                dynamic_deadline,
            )
            .await?
            {
                RealDynamicAttempt::Snapshot {
                    snapshot,
                    reassembled_transfer,
                } => {
                    reassembled_transfers += usize::from(reassembled_transfer);
                    snapshot
                }
                RealDynamicAttempt::TypedFailure => {
                    typed_failures += 1;
                    continue;
                }
            };
            let second_identities = projected_identities(&second);
            if second_identities.len() < first_identities.len()
                || second_identities[..first_identities.len()] != first_identities
            {
                changed_between_reads += 1;
                continue;
            }
            success = Some((conversation_id, first.items().len()));
            break;
        }

        if durable_evidence(&database) != durable_before {
            return Err("real dynamic transcript reads changed durable Runtime artifacts");
        }
        let (conversation_id, snapshot_items) = success
            .ok_or("no bounded NativeProjected candidate produced two stable Dynamic snapshots")?;
        Ok::<_, &'static str>((
            snapshot_items,
            conversation_id.kind(),
            candidates.len(),
            attempted,
            typed_failures,
            reassembled_transfers,
            changed_between_reads,
            empty_snapshots,
        ))
    })
    .await;

    // The child isolates every assertion/panic from ownership cleanup. Core shutdown is always
    // awaited before a failure is propagated back into the test harness.
    let shutdown = core.shutdown().await;
    let summary = match smoke {
        Ok(Ok(summary)) => summary,
        Ok(Err(reason)) => {
            if let Err(failure) = shutdown {
                panic!(
                    "real current-account smoke failed and shutdown failed: {}",
                    failure.code
                );
            }
            panic!("{reason}");
        }
        Err(join) if join.is_panic() => {
            let _ = shutdown;
            std::panic::resume_unwind(join.into_panic());
        }
        Err(_) => {
            let _ = shutdown;
            panic!("real current-account smoke task was cancelled");
        }
    };
    if let Err(failure) = shutdown {
        panic!(
            "shutdown real current-account native projector Core: {}",
            failure.code
        );
    }
    eprintln!(
        "PASS real_current_account_jsonl_projects_through_catalog_and_dynamic_snapshot: snapshot_items={} conversation_id_kind={:?} native_candidates={} attempted={} typed_failures={} reassembled_transfers={} changed_between_reads={} empty_snapshots={}",
        summary.0, summary.1, summary.2, summary.3, summary.4, summary.5, summary.6, summary.7,
    );
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
