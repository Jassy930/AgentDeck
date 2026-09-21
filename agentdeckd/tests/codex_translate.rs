//! Integration tests for `CodexTranslator` — verify the v2 wire shape
//! produced by the translator, end-to-end via the public `translate_line`
//! entry point (the same surface Task 3B's `CodexAdapter` will call).
//!
//! These tests complement the unit tests in `codex/translate.rs` by
//! exercising the JSONL line interface (string in, `ServerEvent` out) and
//! by replaying realistic short Codex turn sequences.

use agentdeck_protocol::{
    ActionKind, ActionRequestVendor, AgentItem, AgentItemState, AgentKind, CodexApprovalPolicy,
    CodexSandboxMode, DiffStatus, ServerEvent, SessionId, ShellStatus, ThreadId,
};
use agentdeckd::codex::translate::CodexTranslator;

fn new_translator() -> CodexTranslator {
    let mut t = CodexTranslator::new(SessionId("session-test".into()), None);
    t.set_thread_id(ThreadId("thread-1".into()));
    t
}

#[test]
fn fixture_replay_assistant_stream_has_stable_identity_and_cumulative_text() {
    let mut translator = new_translator();
    let events: Vec<_> = include_str!("fixtures/codex/assistant_stream.jsonl")
        .lines()
        .flat_map(|line| translator.translate_line(line))
        .collect();
    assert_eq!(events.len(), 3);
    for (event, (expected, expected_state)) in events.iter().zip([
        ("Hel", AgentItemState::Streaming),
        ("Hello!", AgentItemState::Streaming),
        ("Hello!", AgentItemState::Completed),
    ]) {
        let ServerEvent::AgentItem {
            session_id,
            thread_id,
            agent_kind,
            turn_id,
            item_id,
            state,
            item: AgentItem::AssistantMessage { text, .. },
        } = event
        else {
            panic!("expected assistant snapshot: {event:?}")
        };
        assert_eq!(session_id.0, "session-test");
        assert_eq!(thread_id.0, "thread-1");
        assert_eq!(*agent_kind, AgentKind::Codex);
        assert_eq!(turn_id.0, "turn-1");
        assert_eq!(item_id, "msg1");
        assert_eq!(*state, expected_state);
        assert_eq!(text, expected);
    }
}

#[test]
fn duplicate_sparse_reasoning_completion_does_not_erase_accumulated_text() {
    let mut translator = new_translator();
    translator.translate_line(
        r#"{"method":"item/reasoning/textDelta","params":{"itemId":"r1","contentIndex":0,"delta":"Thinking","threadId":"thread-1","turnId":"turn-1"}}"#,
    );
    let completed = r#"{"method":"item/completed","params":{"item":{"id":"r1","type":"reasoning"},"completedAtMs":1,"threadId":"thread-1","turnId":"turn-1"}}"#;
    let events = translator.translate_line(completed);
    assert!(matches!(&events[..], [ServerEvent::AgentItem {
        item_id, state: AgentItemState::Completed,
        item: AgentItem::Reasoning { text, .. }, ..
    }] if item_id == "r1" && text == "Thinking"));
    assert!(translator.translate_line(completed).is_empty());
}

#[test]
fn raw_requests_without_item_ids_get_distinct_ids_and_keep_vendor_item_ids() {
    let mut translator = new_translator();
    let mut generated_ids = Vec::new();
    for id in [1, 2] {
        let events = translator.translate_value(&serde_json::json!({
            "id": id, "method": "item/tool/call",
            "params": {
                "callId": format!("call-{id}"), "tool": "lookup", "arguments": {},
                "threadId": "thread-1", "turnId": "turn-1"
            }
        }));
        let [
            ServerEvent::AgentItem {
                item_id,
                item: AgentItem::Raw { .. },
                ..
            },
        ] = &events[..]
        else {
            panic!("expected raw item: {events:?}");
        };
        assert!(!item_id.is_empty());
        generated_ids.push(item_id.clone());
    }
    assert_ne!(generated_ids[0], generated_ids[1]);

    for params in [
        serde_json::json!({"itemId": "vendor-item"}),
        serde_json::json!({"item": {"id": "vendor-item"}}),
    ] {
        let events = translator.translate_value(&serde_json::json!({
            "method": "item/future/progress", "params": params
        }));
        assert!(
            matches!(&events[..], [ServerEvent::AgentItem { item_id, .. }] if item_id == "vendor-item")
        );
    }
}

#[test]
fn fixture_replay_full_shell_turn() {
    let mut t = new_translator();
    let lines = vec![
        r#"{"method":"thread/started","params":{"threadId":"thread-1"}}"#,
        r#"{"method":"turn/started","params":{"threadId":"thread-1","turnId":"turn-1"}}"#,
        r#"{"method":"item/started","params":{"item":{"id":"sh1","type":"commandExecution","command":"echo hi"},"threadId":"thread-1"}}"#,
        r#"{"method":"item/commandExecution/outputDelta","params":{"itemId":"sh1","deltaBase64":"aGk=","threadId":"thread-1"}}"#,
        r#"{"method":"item/completed","params":{"item":{"id":"sh1","type":"commandExecution","command":"echo hi","status":"completed","exitCode":0,"durationMs":5,"aggregatedOutput":"hi"},"threadId":"thread-1"}}"#,
        r#"{"method":"turn/completed","params":{"threadId":"thread-1","durationMs":42,"usage":{"inputTokens":5,"outputTokens":7}}}"#,
    ];
    let mut events = Vec::new();
    for l in lines {
        events.extend(t.translate_line(l));
    }
    // Expect:
    //   - 1 SessionStarted (from thread/started)
    //   - 1 AgentItem(Shell, Running) on item/started
    //   - 1 AgentItem(Shell, Completed) on item/completed
    //   - 1 TurnComplete
    // turn/started + commandExecution/outputDelta emit nothing.
    let kinds: Vec<&str> = events
        .iter()
        .map(|e| match e {
            ServerEvent::SessionStarted { .. } => "SessionStarted",
            ServerEvent::AgentItem { item, .. } => match item {
                AgentItem::Shell {
                    status: ShellStatus::Running,
                    ..
                } => "Shell(Running)",
                AgentItem::Shell {
                    status: ShellStatus::Completed,
                    ..
                } => "Shell(Completed)",
                AgentItem::Shell {
                    status: ShellStatus::Failed,
                    ..
                } => "Shell(Failed)",
                AgentItem::Shell {
                    status: ShellStatus::Canceled,
                    ..
                } => "Shell(Canceled)",
                _ => "AgentItem(other)",
            },
            ServerEvent::TurnComplete { .. } => "TurnComplete",
            _ => "other",
        })
        .collect();
    assert_eq!(
        kinds,
        vec![
            "SessionStarted",
            "Shell(Running)",
            "Shell(Completed)",
            "TurnComplete"
        ],
        "shell turn event sequence drifted: {events:?}"
    );
}

#[test]
fn fixture_replay_approval_request_with_codex_vendor_block() {
    let mut t = CodexTranslator::with_policy(
        SessionId("s".into()),
        Some(ThreadId("thread-1".into())),
        CodexApprovalPolicy::Never,
        CodexSandboxMode::ReadOnly,
        false,
    );
    let line = r#"{"id":42,"method":"item/commandExecution/requestApproval","params":{"itemId":"sh1","approvalId":"appr-9","command":"git push","cwd":"/repo","reason":"user requested","threadId":"thread-1"}}"#;
    let events = t.translate_line(line);
    assert_eq!(events.len(), 1);
    match &events[0] {
        ServerEvent::ActionRequest {
            request,
            agent_kind,
            thread_id,
            ..
        } => {
            assert_eq!(*agent_kind, AgentKind::Codex);
            assert_eq!(thread_id.0, "thread-1");
            assert_eq!(request.request_id, "appr-9");
            assert!(matches!(request.kind, ActionKind::ExecuteCommand));
            assert!(request.summary.contains("git push"));
            match request.vendor {
                ActionRequestVendor::Codex {
                    approval_policy_at_decision,
                    sandbox_at_decision,
                    can_persist,
                } => {
                    assert_eq!(approval_policy_at_decision, CodexApprovalPolicy::Never);
                    assert_eq!(sandbox_at_decision, CodexSandboxMode::ReadOnly);
                    assert!(!can_persist);
                }
                _ => panic!("expected ActionRequestVendor::Codex"),
            }
        }
        other => panic!("expected ActionRequest, got {other:?}"),
    }
}

#[test]
fn fixture_replay_unknown_item_type_falls_back_to_raw_not_silently_dropped() {
    let mut t = new_translator();
    let events = t.translate_line(
        r#"{"method":"item/completed","params":{"item":{"id":"x","type":"someBrandNewCodexThing","vendorSecret":"hidden"}}}"#,
    );
    assert_eq!(events.len(), 1);
    match &events[0] {
        ServerEvent::AgentItem {
            item:
                AgentItem::Raw {
                    raw_kind,
                    raw_payload,
                    ..
                },
            agent_kind,
            ..
        } => {
            assert_eq!(raw_kind, "someBrandNewCodexThing");
            assert_eq!(*agent_kind, AgentKind::Codex);
            // K9/N4: the safe type identifier remains visible, but arbitrary
            // vendor JSON must stay inside the adapter.
            assert_eq!(raw_payload, "[vendor payload withheld]");
            assert!(!raw_payload.contains("hidden"));
        }
        other => panic!("expected Raw AgentItem, got {other:?}"),
    }
}

#[test]
fn fixture_replay_subagent_activity_is_visible_once_after_started_completed_pair() {
    let mut t = new_translator();
    let item = r#"{"id":"activity-1","type":"subAgentActivity","kind":"started","agentThreadId":"child-1","agentPath":"/root/tool_ui_trace"}"#;
    let lines = [
        format!(r#"{{"method":"item/started","params":{{"item":{item},"threadId":"thread-1"}}}}"#),
        format!(
            r#"{{"method":"item/completed","params":{{"item":{item},"threadId":"thread-1"}}}}"#
        ),
    ];
    let events: Vec<_> = lines
        .iter()
        .flat_map(|line| t.translate_line(line))
        .collect();

    assert_eq!(
        events.len(),
        1,
        "started/completed must not duplicate one activity"
    );
    match &events[0] {
        ServerEvent::AgentItem {
            item:
                AgentItem::ToolCall {
                    name,
                    args,
                    result,
                    meta,
                },
            ..
        } => {
            assert_eq!(name, "Tool ui trace");
            assert_eq!(args["agentThreadId"], "child-1");
            assert_eq!(args["kind"], "started");
            assert!(result.is_none());
            assert_eq!(meta.vendor_extensions["activityKind"], "collaboration");
            assert_eq!(meta.vendor_extensions["activityEvent"], "started");
        }
        other => panic!("expected subagent activity ToolCall, got {other:?}"),
    }

    let mut completed_only = new_translator();
    let events = completed_only.translate_line(&format!(
        r#"{{"method":"item/completed","params":{{"item":{item},"threadId":"thread-1"}}}}"#
    ));
    assert_eq!(
        events.len(),
        1,
        "completed-only activity must remain visible"
    );
    assert!(matches!(
        &events[0],
        ServerEvent::AgentItem {
            item: AgentItem::ToolCall { .. },
            ..
        }
    ));
}

#[test]
fn fixture_replay_context_compaction_is_a_neutral_activity_not_raw_error() {
    let mut t = new_translator();
    let item = r#"{"id":"compact-1","type":"contextCompaction"}"#;
    let events = [
        format!(r#"{{"method":"item/started","params":{{"item":{item},"threadId":"thread-1"}}}}"#),
        format!(
            r#"{{"method":"item/completed","params":{{"item":{item},"threadId":"thread-1"}}}}"#
        ),
    ]
    .iter()
    .flat_map(|line| t.translate_line(line))
    .collect::<Vec<_>>();

    assert_eq!(events.len(), 1);
    match &events[0] {
        ServerEvent::AgentItem {
            item: AgentItem::ToolCall { meta, .. },
            ..
        } => {
            assert_eq!(meta.vendor_extensions["activityKind"], "contextMaintenance");
        }
        other => panic!("expected context maintenance ToolCall, got {other:?}"),
    }
}

#[test]
fn fixture_replay_malformed_line_yields_error_event_with_session_id() {
    let mut t = new_translator();
    let events = t.translate_line("{not valid json at all");
    assert_eq!(events.len(), 1);
    match &events[0] {
        ServerEvent::Error { session_id, error } => {
            assert_eq!(session_id.as_ref().unwrap().0, "session-test");
            assert_eq!(error.code, "codex-malformed-json");
            assert!(error.message.contains("malformed"));
        }
        other => panic!("expected Error, got {other:?}"),
    }
}

#[test]
fn fixture_replay_file_change_emits_diff_with_per_file_status() {
    let mut t = new_translator();
    let lines = vec![
        r#"{"method":"item/started","params":{"item":{"id":"f1","type":"fileChange"}}}"#,
        r#"{"method":"item/completed","params":{"item":{"id":"f1","type":"fileChange","changes":[{"path":"src/a.rs","diff":"+a\n","kind":"add"},{"path":"src/b.rs","diff":"-b\n","kind":"delete"},{"path":"src/c.rs","diff":"+c\n","kind":"update"}]}}}"#,
    ];
    let mut events = Vec::new();
    for l in lines {
        events.extend(t.translate_line(l));
    }
    assert_eq!(events.len(), 1);
    match &events[0] {
        ServerEvent::AgentItem {
            item: AgentItem::Diff { files, .. },
            ..
        } => {
            assert_eq!(files.len(), 3);
            assert!(matches!(files[0].status, DiffStatus::Added));
            assert!(matches!(files[1].status, DiffStatus::Deleted));
            assert!(matches!(files[2].status, DiffStatus::Modified));
            assert_eq!(files[0].path.to_string_lossy(), "src/a.rs");
        }
        other => panic!("expected Diff, got {other:?}"),
    }
}

#[test]
fn empty_or_whitespace_line_yields_no_events() {
    let mut t = new_translator();
    assert!(t.translate_line("").is_empty());
    assert!(t.translate_line("   \n\t  ").is_empty());
}

#[test]
fn plain_response_frame_emits_nothing() {
    // JSON-RPC response (id + result) is just an ack to one of OUR requests;
    // adapter handles it out-of-band. Translator emits nothing.
    let mut t = new_translator();
    let events = t.translate_line(r#"{"id":7,"result":{"ok":true}}"#);
    assert!(events.is_empty());
}
