//! Codex / Claude Code 筛选脱敏录制到 Runtime typed event journal 的回归门禁。
//!
//! 威胁场景：translator 单测即使能从真实 JSONL 产出 `AgentItem`，adapter 接线仍可能在
//! daemon identity 包装、durable append 或重启 backfill 之间丢失/改写 modeled item。这里把
//! 已提交录制逐行送入 translator，再走 released execution 的生产 Store API。两类 fixture 的
//! provenance 与脱敏边界见 `tests/fixtures/README.md`；它们不替代 live vendor / exec-gate 门禁。

#[path = "support/store_admission.rs"]
mod store_admission;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use agentdeck_protocol::runtime::RuntimeEventBody;
use agentdeck_protocol::runtime::identity::{EntityId, ItemId};
use agentdeck_protocol::{
    AgentItem, AgentKind, ClaudeCodePermissionMode, ServerEvent, SessionId, ThreadId, TurnSummary,
};
use agentdeckd::claude_code::translate::ClaudeCodeTranslator;
use agentdeckd::codex::translate::CodexTranslator;
use agentdeckd::runtime::store::identity::OsRuntimeIdSource;
use agentdeckd::runtime::store::{
    AcceptCommand, AcceptOutcome, AppendExecutionEvent, AppendExecutionEventOutcome,
    AuthorizeExecutionRelease, CommandTerminal, CompleteCommand, CompleteOutcome,
    ConversationDescriptor, ExecutionFence, IdempotencyOwner, NewConversation,
    RUNTIME_SCHEMA_VERSION, RuntimeBackfillPlan, RuntimeBackfillTarget, RuntimeId, RuntimeIdKind,
    RuntimeIdSource, RuntimeStoreConfig, RuntimeStoreHandle, StartCommand, StartOutcome,
};
use agentdeckd::security::{MemoryKeyStore, StorageKek, load_or_create_storage_kek};

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

struct TestRoot {
    path: PathBuf,
    _permit: store_admission::Permit,
}

impl TestRoot {
    fn new(label: &str) -> Self {
        let permit = store_admission::acquire();
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
        Self {
            path,
            _permit: permit,
        }
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

fn translate_recorded_items(
    path: &Path,
    mut translate_line: impl FnMut(&str) -> Vec<ServerEvent>,
) -> (Vec<AgentItem>, Vec<TurnSummary>) {
    let content = fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("required real fixture {}: {error}", path.display()));
    assert!(
        !content.trim().is_empty(),
        "required real fixture {} is empty",
        path.display()
    );

    let mut modeled = Vec::new();
    let mut completed_summaries = Vec::new();
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
        for event in translate_line(line) {
            match event {
                ServerEvent::AgentItem {
                    item: AgentItem::Raw { .. },
                    ..
                } => panic!(
                    "required real fixture {} line {} produced Raw, which the production typed Store rejects",
                    path.display(),
                    line_index + 1
                ),
                ServerEvent::AgentItem { item, .. } => modeled.push(item),
                ServerEvent::TurnComplete { summary, .. } => {
                    completed_summaries.push(summary);
                }
                _ => {}
            }
        }
    }
    assert!(
        !modeled.is_empty(),
        "required real fixture {} produced no modeled AgentItem",
        path.display()
    );
    (modeled, completed_summaries)
}

fn exactly_one_terminal(path: &Path, summaries: Vec<TurnSummary>) -> TurnSummary {
    let mut summaries = summaries.into_iter();
    let summary = summaries.next().unwrap_or_else(|| {
        panic!(
            "required real fixture {} produced no TurnComplete",
            path.display()
        )
    });
    assert!(
        summaries.next().is_none(),
        "required real fixture {} produced more than one TurnComplete",
        path.display()
    );
    summary
}

fn translate_recorded_claude_code(path: &Path) -> (Vec<AgentItem>, TurnSummary) {
    let mut translator = ClaudeCodeTranslator::new(
        SessionId("runtime-real-fixture".to_owned()),
        ClaudeCodePermissionMode::BypassPermissions,
    );
    let (items, summaries) =
        translate_recorded_items(path, |line| translator.translate_line(line).events);
    (items, exactly_one_terminal(path, summaries))
}

fn translate_recorded_codex(path: &Path) -> (Vec<AgentItem>, TurnSummary) {
    let mut translator = CodexTranslator::new(
        SessionId("runtime-real-fixture".to_owned()),
        Some(ThreadId("019f0000-0000-7000-8000-000000000001".to_owned())),
    );
    let (items, summaries) = translate_recorded_items(path, |line| translator.translate_line(line));
    let summary = exactly_one_terminal(path, summaries);
    assert_eq!(
        summary.elapsed_ms, 3_213,
        "real Codex turn/completed params.turn.durationMs must survive translation"
    );
    (items, summary)
}

fn owner() -> IdempotencyOwner {
    IdempotencyOwner::Local {
        machine_trust_domain: [0x31; 32],
        uid: 501,
        client_installation_id: [0x32; 16],
    }
}

async fn run_recorded_fixture(
    name: &str,
    label: &str,
    expected: ExpectedItem,
    agent_kind: AgentKind,
    items: Vec<AgentItem>,
    terminal_summary: TurnSummary,
) {
    let path = fixture_path(
        match agent_kind {
            AgentKind::Codex => "codex",
            AgentKind::ClaudeCode => "claude_code",
        },
        name,
    );
    assert!(
        items.iter().any(|item| expected.matches(item)),
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

    let appended_item_count = items.len();
    let expected_item_bytes = items
        .iter()
        .map(|item| serde_json::to_vec(item).expect("encode translated fixture AgentItem"))
        .collect::<Vec<_>>();
    let mut expected_event_bytes = Vec::with_capacity(items.len());
    for (index, item) in items.into_iter().enumerate() {
        let event_id = daemon_id(RuntimeIdKind::Event);
        let item_id = ItemId::new(daemon_id(RuntimeIdKind::Event).to_canonical_string());
        let entity_id = EntityId::new(daemon_id(RuntimeIdKind::Event).to_canonical_string());
        let appended = store
            .append_execution_event(AppendExecutionEvent::item(
                conversation_id,
                command.command_id,
                turn_id,
                event_id,
                item_id,
                entity_id,
                item,
            ))
            .await
            .expect("append translated real fixture item");
        let expected_seq = u64::try_from(index)
            .expect("fixture item index fits u64")
            .checked_add(1)
            .expect("fixture event sequence remains bounded");
        match appended {
            AppendExecutionEventOutcome::Appended { event }
                if event.event_id == event_id && event.event_seq == expected_seq =>
            {
                expected_event_bytes.push(event.payload);
            }
            other => panic!("fresh fixture append returned unexpected outcome: {other:?}"),
        }
    }
    let terminal = store
        .complete_command_with_event(CompleteCommand {
            conversation_id,
            command_id: command.command_id,
            turn_id,
            terminal: CommandTerminal::completed(terminal_summary),
        })
        .await
        .expect("commit Store-owned fixture terminal");
    let expected_terminal_seq = u64::try_from(appended_item_count)
        .expect("fixture item count fits u64")
        .checked_add(1)
        .expect("fixture terminal sequence remains bounded");
    match terminal {
        CompleteOutcome::Completed { event, .. } if event.event_seq == expected_terminal_seq => {
            expected_event_bytes.push(event.payload);
        }
        other => panic!("fresh fixture terminal returned unexpected outcome: {other:?}"),
    }
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

    // Store-local `Some(0)` is `StreamCursor::At(0)`: skip TurnStarted and replay
    // every translated Item event from the durable logical index.
    let RuntimeBackfillPlan::Pinned(pin) = reopened
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
    let mut replayed_items = Vec::new();
    let mut replayed_event_bytes = Vec::new();
    let mut replayed_terminal_count = 0_usize;
    let mut expected_seq = 1_u64;
    let command_id_text = command.command_id.to_canonical_string();
    loop {
        let page = reopened
            .load_event_backfill_page(pin.clone(), after)
            .await
            .expect("load translated fixture backfill page");
        for event in &page.events {
            replayed_event_bytes
                .push(serde_json::to_vec(event).expect("encode canonical replayed RuntimeEvent"));
            assert_eq!(event.event_seq, expected_seq);
            assert_eq!(
                event.command_id.as_ref().map(|id| id.as_str()),
                Some(command_id_text.as_str())
            );
            match &event.body {
                RuntimeEventBody::Item { item } => replayed_items.push(item.clone()),
                RuntimeEventBody::TurnCompleted { .. } => {
                    replayed_terminal_count = replayed_terminal_count
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
        reopened
            .complete_backfill_page(completion)
            .await
            .expect("ack translated fixture backfill page");
        if complete {
            break;
        }
        after = Some(next_after);
    }

    let replayed_item_bytes = replayed_items
        .iter()
        .map(|item| serde_json::to_vec(item).expect("encode replayed fixture AgentItem"))
        .collect::<Vec<_>>();
    assert_eq!(
        replayed_event_bytes, expected_event_bytes,
        "reopened At(0) backfill must preserve every daemon identity and canonical event byte"
    );
    assert_eq!(replayed_terminal_count, 1);
    assert_eq!(
        replayed_item_bytes, expected_item_bytes,
        "reopened At(0) backfill must preserve every translated AgentItem byte-for-byte"
    );
    reopened
        .shutdown()
        .await
        .expect("shutdown reopened fixture store");
}

#[tokio::test]
async fn recorded_simple_turn_assistant_survives_released_typed_append_and_reopen() {
    let path = fixture_path("claude_code", "simple_turn.jsonl");
    let (items, terminal) = translate_recorded_claude_code(&path);
    run_recorded_fixture(
        "simple_turn.jsonl",
        "simple-turn",
        ExpectedItem::Assistant,
        AgentKind::ClaudeCode,
        items,
        terminal,
    )
    .await;
}

#[tokio::test]
async fn recorded_bash_tool_shell_survives_released_typed_append_and_reopen() {
    let path = fixture_path("claude_code", "bash_tool_use.jsonl");
    let (items, terminal) = translate_recorded_claude_code(&path);
    run_recorded_fixture(
        "bash_tool_use.jsonl",
        "bash-tool-use",
        ExpectedItem::Shell,
        AgentKind::ClaudeCode,
        items,
        terminal,
    )
    .await;
}

#[tokio::test]
async fn recorded_codex_simple_turn_assistant_survives_released_typed_append_and_reopen() {
    let path = fixture_path("codex", "simple_turn.jsonl");
    let (items, terminal) = translate_recorded_codex(&path);
    run_recorded_fixture(
        "simple_turn.jsonl",
        "codex-simple-turn",
        ExpectedItem::Assistant,
        AgentKind::Codex,
        items,
        terminal,
    )
    .await;
}
