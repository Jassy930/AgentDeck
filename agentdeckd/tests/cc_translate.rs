//! Unit tests for `ClaudeCodeTranslator`. Offline — no `claude` binary
//! required. Mirrors `tests/codex_translate.rs` in scope so the two
//! translators stay symmetric (N5).
//!
//! Test fixtures use the shape observed by probing
//! `claude --print --output-format stream-json` on 2.1.191 and the
//! stream-json control protocol on 2.1.304 (see
//! `claude_code/translate.rs` module doc for the per-type schema).

use agentdeck_protocol::*;
use agentdeckd::claude_code::translate::ClaudeCodeTranslator;
use serde_json::json;

fn tr() -> ClaudeCodeTranslator {
    let mut t =
        ClaudeCodeTranslator::new(SessionId("s1".into()), ClaudeCodePermissionMode::Default);
    t.set_thread_id(ThreadId("thread_1".into()));
    t.set_turn_id(TurnId("client-turn-1".into()));
    t
}

#[test]
fn assistant_text_becomes_assistant_message() {
    let mut t = tr();
    let line = json!({
        "type": "assistant",
        "session_id": "thread_1",
        "message": { "content": [{ "type": "text", "text": "hi" }] }
    });
    let out = t.translate_line(&line.to_string());
    assert_eq!(out.events.len(), 1);
    match &out.events[0] {
        ServerEvent::AgentItem {
            item: AgentItem::AssistantMessage { text, .. },
            agent_kind,
            thread_id,
            turn_id,
            item_id,
            state,
            ..
        } => {
            assert_eq!(turn_id.0, "client-turn-1");
            assert!(!item_id.is_empty());
            assert_eq!(*state, AgentItemState::Completed);
            assert_eq!(text, "hi");
            assert_eq!(*agent_kind, AgentKind::ClaudeCode);
            assert_eq!(thread_id.0, "thread_1");
        }
        other => panic!("expected AssistantMessage, got {other:?}"),
    }
}

#[test]
fn thinking_becomes_reasoning() {
    let mut t = tr();
    let line = json!({
        "type": "assistant",
        "session_id": "thread_1",
        "message": { "content": [{ "type": "thinking", "thinking": "let me consider..." }] }
    });
    let out = t.translate_line(&line.to_string());
    assert_eq!(out.events.len(), 1);
    match &out.events[0] {
        ServerEvent::AgentItem {
            item: AgentItem::Reasoning { text, .. },
            ..
        } => assert_eq!(text, "let me consider..."),
        other => panic!("expected Reasoning, got {other:?}"),
    }
}

#[test]
fn bash_tool_use_becomes_shell_running() {
    let mut t = tr();
    let line = json!({
        "type": "assistant",
        "session_id": "thread_1",
        "message": { "content": [{
            "type": "tool_use",
            "id": "tu_b1",
            "name": "Bash",
            "input": { "command": "ls -la" }
        }] }
    });
    let out = t.translate_line(&line.to_string());
    assert_eq!(out.events.len(), 1);
    match &out.events[0] {
        ServerEvent::AgentItem {
            item:
                AgentItem::Shell {
                    command,
                    status,
                    meta,
                    ..
                },
            agent_kind,
            ..
        } => {
            assert_eq!(command, "ls -la");
            assert!(matches!(status, ShellStatus::Running));
            assert_eq!(meta.vendor_extensions["toolUseId"], json!("tu_b1"));
            assert_eq!(*agent_kind, AgentKind::ClaudeCode);
        }
        other => panic!("expected Shell(Running), got {other:?}"),
    }
}

#[test]
fn tool_result_after_bash_emits_shell_completion() {
    let mut t = tr();
    // 1) tool_use → Running
    let tu = json!({
        "type": "assistant",
        "session_id": "thread_1",
        "message": { "content": [{
            "type": "tool_use",
            "id": "tu_b1",
            "name": "Bash",
            "input": { "command": "echo ok" }
        }] }
    });
    let _ = t.translate_line(&tu.to_string());
    // 2) tool_result → Completed
    let tr_line = json!({
        "type": "user",
        "session_id": "thread_1",
        "message": { "content": [{
            "type": "tool_result",
            "tool_use_id": "tu_b1",
            "content": "ok\n",
            "is_error": false
        }] }
    });
    let out = t.translate_line(&tr_line.to_string());
    assert_eq!(out.events.len(), 1);
    match &out.events[0] {
        ServerEvent::AgentItem {
            item:
                AgentItem::Shell {
                    command,
                    status,
                    exit_code,
                    meta,
                    ..
                },
            ..
        } => {
            assert_eq!(command, "echo ok");
            assert!(matches!(status, ShellStatus::Completed));
            assert_eq!(*exit_code, Some(0));
            assert_eq!(meta.vendor_extensions["toolUseId"], json!("tu_b1"));
        }
        other => panic!("expected Shell(Completed), got {other:?}"),
    }
}

#[test]
fn tool_progress_refreshes_running_shell_elapsed_time() {
    let mut t = tr();
    let tu = json!({
        "type": "assistant",
        "session_id": "thread_1",
        "message": { "content": [{
            "type": "tool_use",
            "id": "tu_b1",
            "name": "Bash",
            "input": { "command": "sleep 60" }
        }] }
    });
    let _ = t.translate_line(&tu.to_string());
    // Shape observed from claude: heartbeat id is derived, parent is the tool.
    let progress = json!({
        "type": "tool_progress",
        "tool_use_id": "tu_b1-heartbeat-0",
        "tool_name": "Bash",
        "parent_tool_use_id": "tu_b1",
        "elapsed_time_seconds": 30,
        "heartbeat": true,
        "session_id": "thread_1"
    });
    let out = t.translate_line(&progress.to_string());
    assert_eq!(out.events.len(), 1);
    match &out.events[0] {
        ServerEvent::AgentItem {
            item_id,
            state,
            item:
                AgentItem::Shell {
                    command,
                    status,
                    duration_ms,
                    ..
                },
            ..
        } => {
            assert_eq!(item_id, "tu_b1");
            assert_eq!(*state, AgentItemState::Streaming);
            assert_eq!(command, "sleep 60");
            assert!(matches!(status, ShellStatus::Running));
            assert_eq!(*duration_ms, Some(30_000));
        }
        other => panic!("expected Shell(Running), got {other:?}"),
    }

    // Non-Bash tools refresh their ToolCall card the same way.
    let agent = json!({
        "type": "assistant",
        "session_id": "thread_1",
        "message": { "content": [{
            "type": "tool_use",
            "id": "tu_a1",
            "name": "WebFetch",
            "input": { "url": "https://example.com" }
        }] }
    });
    let _ = t.translate_line(&agent.to_string());
    let progress = json!({
        "type": "tool_progress",
        "tool_use_id": "tu_a1-heartbeat-0",
        "tool_name": "WebFetch",
        "parent_tool_use_id": "tu_a1",
        "elapsed_time_seconds": 60
    });
    let out = t.translate_line(&progress.to_string());
    match &out.events[..] {
        [
            ServerEvent::AgentItem {
                item_id,
                state,
                item:
                    AgentItem::ToolCall {
                        name, meta, result, ..
                    },
                ..
            },
        ] => {
            assert_eq!(item_id, "tu_a1");
            assert_eq!(*state, AgentItemState::Streaming);
            assert_eq!(name, "WebFetch");
            assert!(result.is_none());
            assert_eq!(meta.vendor_extensions["status"], json!("inProgress"));
            assert_eq!(meta.vendor_extensions["durationMs"], json!(60_000));
        }
        other => panic!("expected ToolCall(inProgress), got {other:?}"),
    }

    // Unknown or already-finished parent: consumed, never a Raw card.
    let orphan = json!({
        "type": "tool_progress",
        "tool_use_id": "tu_x-heartbeat-0",
        "tool_name": "Agent",
        "parent_tool_use_id": "tu_x",
        "elapsed_time_seconds": 30
    });
    assert!(t.translate_line(&orphan.to_string()).events.is_empty());
}

#[test]
fn tool_result_with_error_emits_shell_failed() {
    let mut t = tr();
    let tu = json!({
        "type": "assistant",
        "session_id": "thread_1",
        "message": { "content": [{
            "type": "tool_use",
            "id": "tu_b2",
            "name": "Bash",
            "input": { "command": "false" }
        }] }
    });
    let _ = t.translate_line(&tu.to_string());
    let tr_line = json!({
        "type": "user",
        "session_id": "thread_1",
        "message": { "content": [{
            "type": "tool_result",
            "tool_use_id": "tu_b2",
            "content": "exit 1",
            "is_error": true
        }] }
    });
    let out = t.translate_line(&tr_line.to_string());
    assert_eq!(out.events.len(), 1);
    match &out.events[0] {
        ServerEvent::AgentItem {
            item: AgentItem::Shell {
                status, exit_code, ..
            },
            ..
        } => {
            assert!(matches!(status, ShellStatus::Failed));
            assert_eq!(*exit_code, Some(1));
        }
        other => panic!("expected Shell(Failed), got {other:?}"),
    }
}

#[test]
fn edit_tool_use_becomes_diff() {
    let mut t = tr();
    let line = json!({
        "type": "assistant",
        "session_id": "thread_1",
        "message": { "content": [{
            "type": "tool_use",
            "id": "tu_e1",
            "name": "Edit",
            "input": {
                "file_path": "/tmp/a.txt",
                "old_string": "foo",
                "new_string": "bar"
            }
        }] }
    });
    let out = t.translate_line(&line.to_string());
    assert_eq!(out.events.len(), 1);
    match &out.events[0] {
        ServerEvent::AgentItem {
            item: AgentItem::Diff { files, meta },
            ..
        } => {
            assert_eq!(files.len(), 1);
            assert_eq!(files[0].path.to_string_lossy(), "/tmp/a.txt");
            assert!(matches!(files[0].status, DiffStatus::Modified));
            let p = files[0].patch.as_deref().unwrap_or("");
            assert!(p.contains("-foo"));
            assert!(p.contains("+bar"));
            assert_eq!(meta.vendor_extensions["toolUseId"], json!("tu_e1"));
        }
        other => panic!("expected Diff, got {other:?}"),
    }
}

#[test]
fn write_tool_use_becomes_diff_added() {
    let mut t = tr();
    let line = json!({
        "type": "assistant",
        "session_id": "thread_1",
        "message": { "content": [{
            "type": "tool_use",
            "id": "tu_w1",
            "name": "Write",
            "input": {
                "file_path": "/tmp/new.txt",
                "content": "hello world"
            }
        }] }
    });
    let out = t.translate_line(&line.to_string());
    assert_eq!(out.events.len(), 1);
    match &out.events[0] {
        ServerEvent::AgentItem {
            item: AgentItem::Diff { files, .. },
            ..
        } => {
            assert_eq!(files.len(), 1);
            assert!(matches!(files[0].status, DiffStatus::Added));
            assert_eq!(files[0].patch.as_deref(), Some("hello world"));
        }
        other => panic!("expected Diff(Added), got {other:?}"),
    }
}

#[test]
fn unknown_tool_becomes_tool_call() {
    let mut t = tr();
    let line = json!({
        "type": "assistant",
        "session_id": "thread_1",
        "message": { "content": [{
            "type": "tool_use",
            "id": "tu_r1",
            "name": "Read",
            "input": { "file_path": "/tmp/x" }
        }] }
    });
    let out = t.translate_line(&line.to_string());
    assert_eq!(out.events.len(), 1);
    match &out.events[0] {
        ServerEvent::AgentItem {
            item: AgentItem::ToolCall {
                name, result, meta, ..
            },
            ..
        } => {
            assert_eq!(name, "Read");
            assert!(result.is_none()); // populated on tool_result
            assert_eq!(meta.vendor_extensions["toolUseId"], json!("tu_r1"));
            assert_eq!(meta.vendor_extensions["status"], json!("inProgress"));
        }
        other => panic!("expected ToolCall, got {other:?}"),
    }
}

#[test]
fn collaboration_tools_keep_neutral_activity_marker_from_start_to_result() {
    for (index, name) in ["Agent", "Task"].into_iter().enumerate() {
        let mut t = tr();
        let tool_use_id = format!("collab-{index}");
        let started = json!({
            "type": "assistant",
            "session_id": "thread_1",
            "message": { "content": [{
                "type": "tool_use",
                "id": tool_use_id,
                "name": name,
                "input": {
                    "description": "review grouping",
                    "subagent_type": "Explore",
                    "prompt": "inspect the UI"
                }
            }] }
        });
        let started_out = t.translate_line(&started.to_string());
        match &started_out.events[0] {
            ServerEvent::AgentItem {
                item: AgentItem::ToolCall { meta, .. },
                ..
            } => {
                assert_eq!(meta.vendor_extensions["toolUseId"], json!(tool_use_id));
                assert_eq!(
                    meta.vendor_extensions["activityKind"],
                    json!("collaboration")
                );
                assert_eq!(meta.vendor_extensions["status"], json!("inProgress"));
            }
            other => panic!("expected collaboration ToolCall start, got {other:?}"),
        }

        let finished = json!({
            "type": "user",
            "session_id": "thread_1",
            "message": { "content": [{
                "type": "tool_result",
                "tool_use_id": tool_use_id,
                "content": "done",
                "is_error": false
            }] }
        });
        let finished_out = t.translate_line(&finished.to_string());
        match &finished_out.events[0] {
            ServerEvent::AgentItem {
                item: AgentItem::ToolCall { meta, .. },
                ..
            } => {
                assert_eq!(meta.vendor_extensions["toolUseId"], json!(tool_use_id));
                assert_eq!(
                    meta.vendor_extensions["activityKind"],
                    json!("collaboration")
                );
                assert_eq!(meta.vendor_extensions["status"], json!("completed"));
            }
            other => panic!("expected collaboration ToolCall result, got {other:?}"),
        }
    }
}

#[test]
fn unknown_tool_result_preserves_failure_status_and_duration() {
    let mut t = tr();
    let started = json!({
        "type": "assistant",
        "session_id": "thread_1",
        "message": { "content": [{
            "type": "tool_use",
            "id": "tu_r2",
            "name": "Read",
            "input": { "file_path": "/tmp/missing" }
        }] }
    });
    let started_out = t.translate_line(&started.to_string());
    assert_eq!(started_out.events.len(), 1);
    match &started_out.events[0] {
        ServerEvent::AgentItem {
            item: AgentItem::ToolCall { meta, .. },
            ..
        } => {
            assert_eq!(meta.vendor_extensions["toolUseId"], json!("tu_r2"));
            assert_eq!(meta.vendor_extensions["status"], json!("inProgress"));
        }
        other => panic!("expected in-progress ToolCall, got {other:?}"),
    }

    let finished = json!({
        "type": "user",
        "session_id": "thread_1",
        "message": { "content": [{
            "type": "tool_result",
            "tool_use_id": "tu_r2",
            "content": "file not found",
            "is_error": true
        }] }
    });
    let out = t.translate_line(&finished.to_string());
    assert_eq!(out.events.len(), 1);
    match &out.events[0] {
        ServerEvent::AgentItem {
            item: AgentItem::ToolCall { result, meta, .. },
            ..
        } => {
            assert_eq!(result.as_ref(), Some(&json!("file not found")));
            assert_eq!(meta.vendor_extensions["toolUseId"], json!("tu_r2"));
            assert_eq!(meta.vendor_extensions["status"], json!("failed"));
            assert_eq!(meta.vendor_extensions["isError"], json!(true));
            assert!(meta.vendor_extensions["durationMs"].as_u64().is_some());
        }
        other => panic!("expected ToolCall failure, got {other:?}"),
    }
}

fn assistant_blocks(blocks: serde_json::Value) -> String {
    json!({
        "type": "assistant",
        "session_id": "thread_1",
        "message": { "id": "msg_1", "content": blocks }
    })
    .to_string()
}

fn only_tool_call(
    out: &agentdeckd::claude_code::translate::TranslateOutput,
) -> (&str, Option<&serde_json::Value>, &AgentItemMeta) {
    assert_eq!(out.events.len(), 1);
    match &out.events[0] {
        ServerEvent::AgentItem {
            item: AgentItem::ToolCall {
                name, result, meta, ..
            },
            ..
        } => (name.as_str(), result.as_ref(), meta),
        other => panic!("expected ToolCall, got {other:?}"),
    }
}

#[test]
fn server_tool_use_and_redacted_advisor_result_pair_into_one_tool_card() {
    let mut t = tr();
    // Shapes copied from a real CC 2.1 transcript: call and result arrive
    // as separate assistant lines of the same message.
    let out = t.translate_line(&assistant_blocks(json!([{
        "type": "server_tool_use", "id": "srvtoolu_1", "name": "advisor", "input": {}
    }])));
    let (name, result, meta) = only_tool_call(&out);
    assert_eq!(name, "advisor");
    assert!(result.is_none());
    assert_eq!(meta.vendor_extensions["toolUseId"], json!("srvtoolu_1"));
    assert_eq!(meta.vendor_extensions["status"], json!("inProgress"));

    let out = t.translate_line(&assistant_blocks(json!([{
        "type": "advisor_tool_result",
        "tool_use_id": "srvtoolu_1",
        "content": { "type": "advisor_redacted_result", "encrypted_content": "EtcT..." }
    }])));
    let (name, result, meta) = only_tool_call(&out);
    assert_eq!(name, "advisor");
    assert_eq!(result, Some(&json!("")));
    assert_eq!(meta.vendor_extensions["toolUseId"], json!("srvtoolu_1"));
    assert_eq!(meta.vendor_extensions["status"], json!("completed"));
}

#[test]
fn server_tool_errors_fail_the_card_and_orphans_stay_visible() {
    let mut t = tr();
    t.translate_line(&assistant_blocks(json!([{
        "type": "server_tool_use", "id": "srvtoolu_2", "name": "advisor", "input": {}
    }])));
    let out = t.translate_line(&assistant_blocks(json!([{
        "type": "advisor_tool_result",
        "tool_use_id": "srvtoolu_2",
        "content": { "type": "advisor_tool_result_error", "error_code": "unavailable" }
    }])));
    let (_, result, meta) = only_tool_call(&out);
    assert_eq!(result, Some(&json!("unavailable")));
    assert_eq!(meta.vendor_extensions["status"], json!("failed"));
    assert_eq!(meta.vendor_extensions["isError"], json!(true));

    let out = t.translate_line(&assistant_blocks(json!([{
        "type": "web_search_tool_result",
        "tool_use_id": "srvtoolu_missing",
        "content": []
    }])));
    assert_eq!(out.events.len(), 1);
    match &out.events[0] {
        ServerEvent::AgentItem {
            item: AgentItem::Raw { raw_kind, .. },
            ..
        } => assert_eq!(raw_kind, "user.tool_result_orphan"),
        other => panic!("expected orphan Raw, got {other:?}"),
    }
}

#[test]
fn web_search_results_list_titles_and_urls() {
    let mut t = tr();
    t.translate_line(&assistant_blocks(json!([{
        "type": "server_tool_use", "id": "srvtoolu_3", "name": "web_search", "input": { "query": "gpui" }
    }])));
    let out = t.translate_line(&assistant_blocks(json!([{
        "type": "web_search_tool_result",
        "tool_use_id": "srvtoolu_3",
        "content": [
            { "type": "web_search_result", "title": "GPUI", "url": "https://gpui.rs", "encrypted_content": "x" },
            { "type": "web_search_result", "url": "https://zed.dev" }
        ]
    }])));
    let (_, result, meta) = only_tool_call(&out);
    assert_eq!(
        result,
        Some(&json!(
            "GPUI https://gpui.rs\nhttps://zed.dev https://zed.dev"
        ))
    );
    assert_eq!(meta.vendor_extensions["status"], json!("completed"));
}

#[test]
fn result_message_becomes_turn_finished_with_usage() {
    let mut t = tr();
    let line = json!({
        "type": "result",
        "subtype": "success",
        "is_error": false,
        "session_id": "thread_1",
        "duration_ms": 5149u64,
        "usage": { "input_tokens": 3, "output_tokens": 11 }
    });
    let out = t.translate_line(&line.to_string());
    assert_eq!(out.events.len(), 1);
    match &out.events[0] {
        ServerEvent::TurnFinished {
            turn_id,
            outcome: TurnOutcome::Succeeded,
            next_state: TurnNextState::Ready,
            summary: Some(summary),
            error: None,
            ..
        } => {
            assert_eq!(turn_id.0, "client-turn-1");
            assert_eq!(summary.elapsed_ms, 5149);
            assert_eq!(summary.total_input_tokens, Some(3));
            assert_eq!(summary.total_output_tokens, Some(11));
        }
        other => panic!("expected succeeded TurnFinished, got {other:?}"),
    }
}

#[test]
fn error_result_becomes_failed_turn() {
    // Shape observed after an interrupt on claude 2.1.304; the owner maps
    // it to canceled when it sent the interrupt itself.
    let mut t = tr();
    let line = json!({
        "type": "result",
        "subtype": "error_during_execution",
        "is_error": true,
        "session_id": "thread_1",
        "duration_ms": 10u64
    });
    let out = t.translate_line(&line.to_string());
    match &out.events[0] {
        ServerEvent::TurnFinished {
            outcome: TurnOutcome::Failed,
            next_state: TurnNextState::Ready,
            error: Some(error),
            ..
        } => assert_eq!(error.code, "cc-turn-failed"),
        other => panic!("expected failed TurnFinished, got {other:?}"),
    }
}

#[test]
fn hook_started_becomes_vendor_panel_event() {
    let mut t = tr();
    let line = json!({
        "type": "system",
        "subtype": "hook_started",
        "session_id": "thread_1",
        "hook_id": "h1",
        "hook_name": "SessionStart:startup",
        "hook_event": "SessionStart"
    });
    let out = t.translate_line(&line.to_string());
    assert_eq!(out.events.len(), 1);
    match &out.events[0] {
        ServerEvent::VendorPanelEvent {
            agent_kind,
            payload,
            ..
        } => {
            assert_eq!(*agent_kind, AgentKind::ClaudeCode);
            match payload {
                VendorPanelPayload::ClaudeCode(ClaudeCodeVendorPanelEvent::HookFired {
                    matcher,
                    ..
                }) => assert_eq!(matcher, "SessionStart"),
                _ => panic!("expected ClaudeCode HookFired"),
            }
        }
        other => panic!("expected VendorPanelEvent, got {other:?}"),
    }
}

#[test]
fn system_init_captures_session_id_silently() {
    // `system.subtype=init` does NOT emit an event — the adapter has
    // already sent SessionStarted; the translator just captures
    // thread_id for downstream events.
    let mut t =
        ClaudeCodeTranslator::new(SessionId("s1".into()), ClaudeCodePermissionMode::Default);
    let line = json!({
        "type": "system",
        "subtype": "init",
        "session_id": "abc-uuid"
    });
    let out = t.translate_line(&line.to_string());
    assert!(out.events.is_empty());
    assert_eq!(t.thread_id().map(|t| t.0.as_str()), Some("abc-uuid"));
}

#[test]
fn stream_deltas_become_cumulative_snapshots_closed_by_the_assistant_message() {
    let mut t = tr();
    let stream = |event: serde_json::Value| {
        json!({"type": "stream_event", "session_id": "thread_1", "event": event}).to_string()
    };
    assert!(
        t.translate_line(&stream(
            json!({"type": "message_start", "message": {"id": "msg_1"}})
        ))
        .events
        .is_empty()
    );
    t.translate_line(&stream(json!({
        "type": "content_block_start", "index": 0,
        "content_block": {"type": "text", "text": ""}
    })));
    let mut snapshots = Vec::new();
    for chunk in ["Hel", "lo"] {
        let out = t.translate_line(&stream(json!({
            "type": "content_block_delta", "index": 0,
            "delta": {"type": "text_delta", "text": chunk}
        })));
        match &out.events[..] {
            [
                ServerEvent::AgentItem {
                    item_id,
                    state: AgentItemState::Streaming,
                    item: AgentItem::AssistantMessage { text, .. },
                    ..
                },
            ] => snapshots.push((item_id.clone(), text.clone())),
            other => panic!("expected one streaming snapshot, got {other:?}"),
        }
    }
    assert_eq!(snapshots[0], ("msg_1:0".to_string(), "Hel".to_string()));
    assert_eq!(snapshots[1], ("msg_1:0".to_string(), "Hello".to_string()));

    let out = t.translate_line(
        &json!({
            "type": "assistant",
            "session_id": "thread_1",
            "message": {"id": "msg_1", "content": [{"type": "text", "text": "Hello"}]}
        })
        .to_string(),
    );
    match &out.events[..] {
        [
            ServerEvent::AgentItem {
                item_id,
                state: AgentItemState::Completed,
                item: AgentItem::AssistantMessage { text, .. },
                ..
            },
        ] => {
            assert_eq!(item_id, "msg_1:0");
            assert_eq!(text, "Hello");
        }
        other => panic!("expected the streamed item to complete, got {other:?}"),
    }
}

/// `can_use_tool` control request as emitted by claude 2.1.304 under
/// `--permission-prompt-tool stdio --permission-mode default`.
fn can_use_tool(tool_name: &str, input: serde_json::Value) -> String {
    json!({
        "type": "control_request",
        "request_id": "0b0682b6-fab3-46ff-b3f9-eee64eb98df7",
        "request": {
            "subtype": "can_use_tool",
            "tool_name": tool_name,
            "display_name": tool_name,
            "input": input,
            "description": "a.txt",
            "permission_suggestions": [
                {"type": "setMode", "mode": "acceptEdits", "destination": "session"}
            ],
            "tool_use_id": "toolu_019XANuYGNme5v49bFsnxCfi"
        }
    })
    .to_string()
}

#[test]
fn can_use_tool_becomes_action_request_with_route() {
    let mut t = tr();
    let out = t.translate_line(&can_use_tool("Bash", json!({"command": "ls"})));
    match &out.events[..] {
        [
            ServerEvent::ActionRequest {
                agent_kind: AgentKind::ClaudeCode,
                request,
                ..
            },
        ] => {
            assert_eq!(request.request_id, "0b0682b6-fab3-46ff-b3f9-eee64eb98df7");
            assert!(matches!(request.kind, ActionKind::ExecuteCommand));
            assert_eq!(request.summary, "Bash: ls");
        }
        other => panic!("expected ActionRequest, got {other:?}"),
    }
    let route = out.permission_route_hint.expect("route for the owner");
    assert_eq!(route.request_id, "0b0682b6-fab3-46ff-b3f9-eee64eb98df7");
    assert_eq!(route.input, json!({"command": "ls"}));
    assert_eq!(route.suggestions[0]["mode"], "acceptEdits");
}

#[test]
fn control_responses_and_other_control_requests_emit_nothing() {
    let mut t = tr();
    for line in [
        json!({"type": "control_response", "response": {"subtype": "success", "request_id": "agentdeck-1"}}),
        json!({"type": "control_request", "request_id": "r", "request": {"subtype": "hook_callback"}}),
        json!({"type": "control_cancel_request", "request_id": "r"}),
    ] {
        let out = t.translate_line(&line.to_string());
        assert!(out.events.is_empty());
        assert!(out.permission_route_hint.is_none());
    }
}

#[test]
fn unknown_type_becomes_raw() {
    let mut t = tr();
    let line = json!({
        "type": "future_unknown_kind",
        "session_id": "thread_1",
        "data": "secret"
    });
    let out = t.translate_line(&line.to_string());
    assert_eq!(out.events.len(), 1);
    match &out.events[0] {
        ServerEvent::AgentItem {
            item: AgentItem::Raw { raw_kind, .. },
            ..
        } => assert_eq!(raw_kind, "future_unknown_kind"),
        other => panic!("expected Raw, got {other:?}"),
    }
}

#[test]
fn malformed_json_is_silently_dropped() {
    let mut t = tr();
    let out = t.translate_line("{not json");
    assert!(out.events.is_empty());
    assert!(out.permission_route_hint.is_none());
}

#[test]
fn permission_mode_is_stamped_on_action_request() {
    let mut t = ClaudeCodeTranslator::new(
        SessionId("s1".into()),
        ClaudeCodePermissionMode::AcceptEdits,
    );
    t.set_thread_id(ThreadId("t".into()));
    let out = t.translate_line(&can_use_tool("Edit", json!({"file_path": "foo.rs"})));
    let ServerEvent::ActionRequest { request, .. } = &out.events[0] else {
        panic!("expected ActionRequest");
    };
    match request.vendor {
        ActionRequestVendor::ClaudeCode {
            permission_mode_at_decision,
            ref tool_name,
            can_persist,
        } => {
            assert!(can_persist, "the fixture carries a setMode suggestion");
            assert_eq!(
                permission_mode_at_decision,
                ClaudeCodePermissionMode::AcceptEdits
            );
            assert_eq!(tool_name, "Edit");
        }
        _ => panic!("expected ClaudeCode vendor block"),
    }
    assert!(matches!(request.kind, ActionKind::EditFiles));
}

#[test]
fn tool_snapshots_preserve_their_identity_until_completion() {
    for (name, input) in [
        ("Bash", json!({"command":"true"})),
        (
            "Edit",
            json!({"file_path":"/tmp/a", "old_string":"a", "new_string":"b"}),
        ),
        ("Write", json!({"file_path":"/tmp/a", "content":"a"})),
        ("MultiEdit", json!({"file_path":"/tmp/a", "edits":[]})),
    ] {
        let mut translator = tr();
        let running = translator.translate_line(&json!({
            "type":"assistant", "message":{"content":[{"type":"tool_use", "id":"tool-1", "name":name, "input":input}]}
        }).to_string());
        let completed = translator.translate_line(&json!({
            "type":"user", "message":{"content":[{"type":"tool_result", "tool_use_id":"tool-1", "content":""}]}
        }).to_string());
        for (events, expected) in [
            (running.events, AgentItemState::Streaming),
            (completed.events, AgentItemState::Completed),
        ] {
            assert!(
                matches!(&events[..], [ServerEvent::AgentItem { item_id, turn_id, state, .. }]
                if item_id == "tool-1" && turn_id.0 == "client-turn-1" && *state == expected),
                "{name} should preserve identity through {expected:?}"
            );
        }
    }
}

#[test]
fn system_permission_mode_changes_emit_once() {
    // claude 2.1.304 pushes `status` with permissionMode after a plan approval
    // or a persisted setMode suggestion; `init` carries the starting mode.
    let mut t = tr();
    let status = |mode: &str| {
        json!({"type": "system", "subtype": "status", "status": null, "permissionMode": mode, "session_id": "thread_1"})
            .to_string()
    };
    let changed = |out: &agentdeckd::claude_code::translate::TranslateOutput| {
        out.events.iter().any(|e| {
            matches!(
                e,
                ServerEvent::VendorPanelEvent {
                    payload: VendorPanelPayload::ClaudeCode(
                        ClaudeCodeVendorPanelEvent::PermissionModeChanged {
                            mode: ClaudeCodePermissionMode::AcceptEdits
                        }
                    ),
                    ..
                }
            )
        })
    };
    assert!(changed(&t.translate_line(&status("acceptEdits"))));
    assert!(!changed(&t.translate_line(&status("acceptEdits"))));
}

#[test]
fn exit_plan_mode_becomes_plan_approval_with_the_plan_as_detail() {
    let mut t = tr();
    let line = json!({
        "type": "control_request",
        "request_id": "plan-1",
        "request": {
            "subtype": "can_use_tool",
            "tool_name": "ExitPlanMode",
            "input": {"plan": "# 计划：创建 a.txt\n\n1. 写入", "planFilePath": "/p.md"},
            "tool_use_id": "toolu_plan"
        }
    });
    let out = t.translate_line(&line.to_string());
    let ServerEvent::ActionRequest { request, .. } = &out.events[0] else {
        panic!("expected ActionRequest");
    };
    assert!(matches!(request.kind, ActionKind::ApprovePlan));
    assert_eq!(request.summary, "ExitPlanMode: 计划：创建 a.txt");
    assert_eq!(
        request.detail.as_deref(),
        Some("# 计划：创建 a.txt\n\n1. 写入")
    );
    assert!(matches!(
        request.vendor,
        ActionRequestVendor::ClaudeCode {
            can_persist: false,
            ..
        }
    ));
}

#[test]
fn edit_approval_detail_is_a_patch() {
    let mut t = tr();
    let out = t.translate_line(&can_use_tool(
        "Edit",
        json!({"file_path": "a.rs", "old_string": "old", "new_string": "new"}),
    ));
    let ServerEvent::ActionRequest { request, .. } = &out.events[0] else {
        panic!("expected ActionRequest");
    };
    let detail = request.detail.as_deref().unwrap();
    assert!(
        detail.contains("-old") && detail.contains("+new"),
        "{detail}"
    );
}

#[test]
fn ask_user_question_becomes_questions_without_detail() {
    // Shape recorded from claude 2.1.304; extra option fields are ignored.
    let mut t = tr();
    let line = json!({
        "type": "control_request",
        "request_id": "ask-1",
        "request": {
            "subtype": "can_use_tool",
            "tool_name": "AskUserQuestion",
            "input": {"questions": [
                {"question": "你喜欢哪种颜色？", "header": "颜色", "multiSelect": false,
                 "options": [{"label": "红", "description": "红色", "preview": "x"}, {"label": "蓝"}]},
                {"question": "你想要哪些水果？", "header": "水果", "multiSelect": true,
                 "options": [{"label": "苹果"}, {"label": "橙子"}]}
            ]},
            "tool_use_id": "toolu_ask",
            "requires_user_interaction": true
        }
    });
    let out = t.translate_line(&line.to_string());
    let ServerEvent::ActionRequest { request, .. } = &out.events[0] else {
        panic!("expected ActionRequest");
    };
    assert!(matches!(request.kind, ActionKind::AnswerQuestions));
    assert_eq!(request.summary, "AskUserQuestion: 你喜欢哪种颜色？");
    assert!(request.detail.is_none());
    let questions = request.questions.as_ref().unwrap();
    assert_eq!(questions.len(), 2);
    assert_eq!(questions[0].options[0].description.as_deref(), Some("红色"));
    assert!(questions[1].multi_select);
}
