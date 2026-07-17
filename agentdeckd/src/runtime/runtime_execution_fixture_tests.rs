//! 脱敏真实 vendor 录制 → typed RuntimeTranslator → production identity wrapper
//! → durable Store/reopen/backfill 的 crate unit gate。

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use agentdeck_protocol::runtime::RuntimeEventBody;
use agentdeck_protocol::runtime::identity::{EntityId, ItemId};
use agentdeck_protocol::{AgentItem, AgentKind, TurnSummary};

use super::append_adapter_event;
use crate::agent::{AdapterEvent, AdapterItemKey};
use crate::runtime::store::identity::OsRuntimeIdSource;
use crate::runtime::store::{
    AcceptCommand, AcceptOutcome, AuthorizeExecutionRelease, CommandTerminal, CompleteCommand,
    CompleteOutcome, ConversationDescriptor, ExecutionFence, IdempotencyOwner, NewConversation,
    RUNTIME_SCHEMA_VERSION, RuntimeBackfillPlan, RuntimeBackfillTarget, RuntimeId, RuntimeIdKind,
    RuntimeIdSource, RuntimeStoreConfig, RuntimeStoreHandle, StartCommand, StartOutcome,
};
use crate::security::{MemoryKeyStore, StorageKek, load_or_create_storage_kek};

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

struct TestRoot {
    path: PathBuf,
}

impl TestRoot {
    fn new(label: &str) -> Self {
        let sequence = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "agentdeckd-runtime-real-fixture-{label}-{}-{sequence}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).expect("create real fixture test root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("secure real fixture test root");
        }
        Self { path }
    }

    fn database(&self) -> PathBuf {
        self.path.join("runtime.db")
    }

    fn storage_kek(&self, keys: &MemoryKeyStore) -> StorageKek {
        load_or_create_storage_kek(keys, &self.path.join("key-state.db"))
            .expect("load real fixture StorageKEK")
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[derive(Clone, Copy)]
enum ExpectedItem {
    Assistant,
    Shell,
}

impl ExpectedItem {
    fn matches(self, item: &AgentItem) -> bool {
        match self {
            Self::Assistant => matches!(item, AgentItem::AssistantMessage { .. }),
            Self::Shell => matches!(item, AgentItem::Shell { .. }),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
struct ReplayCapture {
    event_bytes: Vec<Vec<u8>>,
    item_bytes: Vec<Vec<u8>>,
    item_identities: Vec<(String, String)>,
    terminal_count: usize,
}

fn daemon_id(kind: RuntimeIdKind) -> RuntimeId {
    OsRuntimeIdSource
        .next_id(kind)
        .expect("daemon OS identity allocation")
}

fn fixture_path(vendor: &str, name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(vendor)
        .join(name)
}

fn fixture_content(path: &Path) -> String {
    let content = fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("required real fixture {}: {error}", path.display()));
    assert!(
        !content.trim().is_empty(),
        "required real fixture {} is empty",
        path.display()
    );
    for (line_index, line) in content.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        serde_json::from_str::<serde_json::Value>(line).unwrap_or_else(|error| {
            panic!(
                "required real fixture {} line {} is not JSON: {error}",
                path.display(),
                line_index + 1
            )
        });
    }
    content
}

fn exactly_one_terminal(path: &Path, summaries: Vec<TurnSummary>) -> TurnSummary {
    let mut summaries = summaries.into_iter();
    let summary = summaries.next().unwrap_or_else(|| {
        panic!(
            "required real fixture {} produced no typed terminal",
            path.display()
        )
    });
    assert!(
        summaries.next().is_none(),
        "required real fixture {} produced more than one typed terminal",
        path.display()
    );
    summary
}

fn translate_recorded_claude_code(path: &Path) -> (Vec<AdapterEvent>, TurnSummary) {
    let content = fixture_content(path);
    let (events, summaries) = crate::claude_code::translate_runtime_fixture_for_test(&content)
        .unwrap_or_else(|error| {
            panic!(
                "required real fixture {} failed typed Claude Code translation: {}",
                path.display(),
                error.code
            )
        });
    (events, exactly_one_terminal(path, summaries))
}

fn translate_recorded_codex(path: &Path) -> (Vec<AdapterEvent>, TurnSummary) {
    let content = fixture_content(path);
    let (events, summaries) = crate::codex::translate_runtime_fixture_for_test(&content)
        .unwrap_or_else(|error| {
            panic!(
                "required real fixture {} failed typed Codex translation: {}",
                path.display(),
                error.code
            )
        });
    let summary = exactly_one_terminal(path, summaries);
    assert_eq!(
        summary.elapsed_ms, 3_213,
        "real Codex turn/completed params.turn.durationMs must survive typed translation"
    );
    (events, summary)
}

fn owner() -> IdempotencyOwner {
    IdempotencyOwner::Local {
        machine_trust_domain: [0x31; 32],
        uid: 501,
        client_installation_id: [0x32; 16],
    }
}

async fn capture_backfill(
    store: &RuntimeStoreHandle,
    conversation_id: RuntimeId,
    command_id: RuntimeId,
    expected_event_count: usize,
) -> ReplayCapture {
    // Store-local `Some(0)` 是 `StreamCursor::At(0)`：跳过 TurnStarted，读取
    // translated Item updates 与唯一 terminal。
    let RuntimeBackfillPlan::Pinned(pin) = store
        .acquire_backfill_pin(
            RuntimeBackfillTarget::Conversation(conversation_id),
            Some(0),
        )
        .await
        .expect("acquire At(0) fixture backfill")
    else {
        panic!("translated fixture events must remain in the logical replay suffix");
    };
    let mut after = Some(0);
    let mut capture = ReplayCapture {
        event_bytes: Vec::new(),
        item_bytes: Vec::new(),
        item_identities: Vec::new(),
        terminal_count: 0,
    };
    let mut expected_seq = 1_u64;
    let command_id_text = command_id.to_canonical_string();
    loop {
        let page = store
            .load_event_backfill_page(pin.clone(), after)
            .await
            .expect("load translated fixture backfill page");
        for event in &page.events {
            capture
                .event_bytes
                .push(serde_json::to_vec(event).expect("encode canonical replayed RuntimeEvent"));
            assert_eq!(event.event_seq, expected_seq);
            assert_eq!(
                event.command_id.as_ref().map(|id| id.as_str()),
                Some(command_id_text.as_str())
            );
            match &event.body {
                RuntimeEventBody::Item { item } => {
                    capture.item_bytes.push(
                        serde_json::to_vec(item).expect("encode canonical replayed AgentItem"),
                    );
                    capture.item_identities.push((
                        event
                            .item_id
                            .as_ref()
                            .expect("typed Item carries itemId")
                            .as_str()
                            .to_owned(),
                        event
                            .entity_id
                            .as_ref()
                            .expect("typed Item carries entityId")
                            .as_str()
                            .to_owned(),
                    ));
                }
                RuntimeEventBody::TurnCompleted { .. } => {
                    capture.terminal_count = capture
                        .terminal_count
                        .checked_add(1)
                        .expect("fixture terminal count remains bounded");
                }
                other => panic!("At(0) fixture backfill contains unexpected body: {other:?}"),
            }
            expected_seq = expected_seq
                .checked_add(1)
                .expect("fixture replay sequence remains bounded");
        }
        let next_after = page.next_after;
        let complete = page.complete;
        let completion = page.completion().clone();
        drop(page);
        store
            .complete_backfill_page(completion)
            .await
            .expect("ack translated fixture backfill page");
        if complete {
            break;
        }
        after = Some(next_after);
    }
    assert_eq!(capture.event_bytes.len(), expected_event_count);
    capture
}

#[allow(clippy::too_many_arguments)]
async fn run_recorded_fixture(
    name: &str,
    label: &str,
    expected: ExpectedItem,
    agent_kind: AgentKind,
    events: Vec<AdapterEvent>,
    terminal_summary: TurnSummary,
    expect_reused_item_key: bool,
) {
    let path = fixture_path(
        match agent_kind {
            AgentKind::Codex => "codex",
            AgentKind::ClaudeCode => "claude_code",
        },
        name,
    );
    assert!(
        !events.is_empty(),
        "{} produced no typed events",
        path.display()
    );
    assert!(
        events.iter().any(|event| matches!(
            event,
            AdapterEvent::Item { item, .. } if expected.matches(item)
        )),
        "required real fixture {} did not produce its expected modeled item",
        path.display()
    );

    let root = TestRoot::new(label);
    let keys = MemoryKeyStore::new();
    let config = RuntimeStoreConfig::new(root.database());
    let store = RuntimeStoreHandle::open(config.clone(), root.storage_kek(&keys))
        .await
        .expect("open real fixture RuntimeStore");
    let conversation_id = daemon_id(RuntimeIdKind::Conversation);
    store
        .create_conversation(NewConversation {
            conversation_id,
            adapter_state_key: daemon_id(RuntimeIdKind::AdapterState),
            descriptor: ConversationDescriptor {
                agent_kind,
                title: Some(format!("recorded fixture {name}")),
                cwd: PathBuf::from("/tmp/agentdeck-runtime-real-fixture"),
            },
        })
        .await
        .expect("create daemon-owned fixture conversation");
    let command = match store
        .accept_command(AcceptCommand {
            conversation_id,
            owner: owner(),
            idempotency_key: format!("recorded-fixture-{label}"),
            expected_configuration_revision: 0,
            payload: b"recorded fixture prompt is not persisted from vendor output".to_vec(),
        })
        .await
        .expect("accept recorded fixture command")
    {
        AcceptOutcome::Accepted { command, .. } => command,
        AcceptOutcome::Replayed { .. } => panic!("fresh recorded fixture command cannot replay"),
    };
    let daemon_boot_id = daemon_id(RuntimeIdKind::DaemonBoot);
    let execution_nonce = format!("recorded-fixture-nonce-{label}").into_bytes();
    let turn_id = match store
        .mark_started_with_event(StartCommand {
            conversation_id,
            command_id: command.command_id,
            daemon_boot_id,
            execution_nonce: execution_nonce.clone(),
        })
        .await
        .expect("commit Store-owned TurnStarted")
    {
        StartOutcome::Started { intent, .. } => intent.turn_id,
        StartOutcome::Replayed { .. } => panic!("fresh recorded fixture start cannot replay"),
    };
    store
        .persist_execution_fence(ExecutionFence {
            command_id: command.command_id,
            daemon_boot_id,
            execution_nonce: execution_nonce.clone(),
            process_group_id: 9_001,
            leader_pid: 9_001,
            leader_start_time: 9_001,
            payload: b"recorded fixture released fence".to_vec(),
        })
        .await
        .expect("persist recorded fixture ExecutionFence");
    store
        .authorize_execution_release(AuthorizeExecutionRelease {
            command_id: command.command_id,
            daemon_boot_id,
            execution_nonce,
        })
        .await
        .expect("authorize recorded fixture execution release");

    let appended_item_count = events.len();
    let mut item_identities = HashMap::<AdapterItemKey, (ItemId, EntityId)>::new();
    let mut key_counts = HashMap::<String, usize>::new();
    let mut expected_identity_by_key = HashMap::<String, (String, String)>::new();
    let mut expected_identity_sequence = Vec::with_capacity(events.len());
    let mut expected_item_bytes = Vec::with_capacity(events.len());
    for event in events {
        let (key, item) = match &event {
            AdapterEvent::Item {
                item: AgentItem::Raw { .. },
                ..
            } => panic!(
                "required real fixture {} produced Raw, which typed Runtime Store rejects",
                path.display()
            ),
            AdapterEvent::Item { key, item } => (key.clone(), item),
            other => panic!(
                "required real fixture {} produced non-item adapter event: {other:?}",
                path.display()
            ),
        };
        expected_item_bytes
            .push(serde_json::to_vec(item).expect("encode typed translated fixture AgentItem"));
        *key_counts.entry(key.as_str().to_owned()).or_default() += 1;
        append_adapter_event(
            &store,
            conversation_id,
            command.command_id,
            turn_id,
            &mut item_identities,
            event,
        )
        .await
        .expect("append typed translated real fixture item");
        let (item_id, entity_id) = item_identities
            .get(&key)
            .expect("production wrapper records AdapterItemKey identity");
        let identity = (item_id.as_str().to_owned(), entity_id.as_str().to_owned());
        if let Some(previous) = expected_identity_by_key.get(key.as_str()) {
            assert_eq!(
                previous, &identity,
                "same AdapterItemKey must retain one ItemId+EntityId pair"
            );
        } else {
            expected_identity_by_key.insert(key.as_str().to_owned(), identity.clone());
        }
        expected_identity_sequence.push(identity);
    }
    assert_eq!(
        key_counts.values().any(|count| *count > 1),
        expect_reused_item_key,
        "fixture AdapterItemKey reuse shape changed"
    );

    match store
        .complete_command_with_event(CompleteCommand {
            conversation_id,
            command_id: command.command_id,
            turn_id,
            terminal: CommandTerminal::completed(terminal_summary),
        })
        .await
        .expect("commit Store-owned fixture terminal")
    {
        CompleteOutcome::Completed { .. } => {}
        other => panic!("fresh fixture terminal returned unexpected outcome: {other:?}"),
    }

    let expected_event_count = appended_item_count
        .checked_add(1)
        .expect("fixture event count remains bounded");
    let live_capture = capture_backfill(
        &store,
        conversation_id,
        command.command_id,
        expected_event_count,
    )
    .await;
    assert_eq!(live_capture.item_bytes, expected_item_bytes);
    assert_eq!(live_capture.item_identities, expected_identity_sequence);
    assert_eq!(live_capture.terminal_count, 1);
    store
        .shutdown()
        .await
        .expect("shutdown before fixture reopen");

    let reopened = RuntimeStoreHandle::open(config, root.storage_kek(&keys))
        .await
        .expect("reopen and audit translated real fixture");
    let inspection = reopened
        .inspect()
        .await
        .expect("inspect reopened fixture store");
    assert_eq!(inspection.schema_version, RUNTIME_SCHEMA_VERSION);
    let reopened_capture = capture_backfill(
        &reopened,
        conversation_id,
        command.command_id,
        expected_event_count,
    )
    .await;
    assert_eq!(
        reopened_capture, live_capture,
        "reopen/backfill must preserve event, item/entity/command identity and bytes"
    );
    reopened
        .shutdown()
        .await
        .expect("shutdown reopened fixture store");
}

#[tokio::test]
async fn recorded_claude_simple_turn_survives_typed_runtime_append_and_reopen() {
    let path = fixture_path("claude_code", "simple_turn.jsonl");
    let (events, terminal) = translate_recorded_claude_code(&path);
    run_recorded_fixture(
        "simple_turn.jsonl",
        "simple-turn",
        ExpectedItem::Assistant,
        AgentKind::ClaudeCode,
        events,
        terminal,
        false,
    )
    .await;
}

#[tokio::test]
async fn recorded_claude_bash_start_and_result_reuse_identity_after_reopen() {
    let path = fixture_path("claude_code", "bash_tool_use.jsonl");
    let (events, terminal) = translate_recorded_claude_code(&path);
    run_recorded_fixture(
        "bash_tool_use.jsonl",
        "bash-tool-use",
        ExpectedItem::Shell,
        AgentKind::ClaudeCode,
        events,
        terminal,
        true,
    )
    .await;
}

#[tokio::test]
async fn recorded_codex_simple_turn_survives_typed_runtime_append_and_reopen() {
    let path = fixture_path("codex", "simple_turn.jsonl");
    let (events, terminal) = translate_recorded_codex(&path);
    run_recorded_fixture(
        "simple_turn.jsonl",
        "codex-simple-turn",
        ExpectedItem::Assistant,
        AgentKind::Codex,
        events,
        terminal,
        false,
    )
    .await;
}
