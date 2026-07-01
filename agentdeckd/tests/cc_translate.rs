//! Unit tests for `ClaudeCodeTranslator`. Offline — no `claude` binary
//! required. Mirrors `tests/codex_translate.rs` in scope so the two
//! translators stay symmetric (N5).
//!
//! Test fixtures use the shape observed by probing
//! `claude --print --output-format stream-json` on 2.1.191 (see
//! `claude_code/translate.rs` module doc for the per-type schema).

use agentdeck_protocol::*;
use agentdeckd::claude_code::translate::ClaudeCodeTranslator;
use serde_json::json;

fn tr() -> ClaudeCodeTranslator {
    let mut t =
        ClaudeCodeTranslator::new(SessionId("s1".into()), ClaudeCodePermissionMode::Default);
    t.set_thread_id(ThreadId("thread_1".into()));
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
            ..
        } => {
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
            item: AgentItem::Shell {
                command, status, ..
            },
            agent_kind,
            ..
        } => {
            assert_eq!(command, "ls -la");
            assert!(matches!(status, ShellStatus::Running));
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
                    ..
                },
            ..
        } => {
            assert_eq!(command, "echo ok");
            assert!(matches!(status, ShellStatus::Completed));
            assert_eq!(*exit_code, Some(0));
        }
        other => panic!("expected Shell(Completed), got {other:?}"),
    }
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
            item: AgentItem::Diff { files, .. },
            ..
        } => {
            assert_eq!(files.len(), 1);
            assert_eq!(files[0].path.to_string_lossy(), "/tmp/a.txt");
            assert!(matches!(files[0].status, DiffStatus::Modified));
            let p = files[0].patch.as_deref().unwrap_or("");
            assert!(p.contains("-foo"));
            assert!(p.contains("+bar"));
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
            item: AgentItem::ToolCall { name, result, .. },
            ..
        } => {
            assert_eq!(name, "Read");
            assert!(result.is_none()); // populated on tool_result
        }
        other => panic!("expected ToolCall, got {other:?}"),
    }
}

#[test]
fn result_message_becomes_turn_complete_with_usage() {
    let mut t = tr();
    let line = json!({
        "type": "result",
        "subtype": "success",
        "session_id": "thread_1",
        "duration_ms": 5149u64,
        "usage": { "input_tokens": 3, "output_tokens": 11 }
    });
    let out = t.translate_line(&line.to_string());
    assert_eq!(out.events.len(), 1);
    match &out.events[0] {
        ServerEvent::TurnComplete {
            summary,
            agent_kind,
            ..
        } => {
            assert_eq!(*agent_kind, AgentKind::ClaudeCode);
            assert_eq!(summary.elapsed_ms, 5149);
            assert_eq!(summary.total_input_tokens, Some(3));
            assert_eq!(summary.total_output_tokens, Some(11));
        }
        other => panic!("expected TurnComplete, got {other:?}"),
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
fn stream_event_partial_deltas_are_dropped() {
    // We rely on the cumulative `assistant` snapshot for content; deltas
    // are noise.
    let mut t = tr();
    let line = json!({
        "type": "stream_event",
        "session_id": "thread_1",
        "event": {
            "type": "content_block_delta",
            "index": 0,
            "delta": { "type": "text_delta", "text": "Hel" }
        }
    });
    let out = t.translate_line(&line.to_string());
    assert!(out.events.is_empty());
}

#[test]
fn permission_request_becomes_action_request_with_cc_vendor() {
    // The actual wire-name is unknown without a real default-mode
    // fixture; we accept all three candidate envelopes.
    for type_name in &["permission_request", "permission", "prompt"] {
        let mut t = tr();
        let line = json!({
            "type": *type_name,
            "session_id": "thread_1",
            "tool_use_id": "tu_ask",
            "tool_name": "Bash",
            "summary": "run ls"
        });
        let out = t.translate_line(&line.to_string());
        let has_action = out.events.iter().any(|e| {
            matches!(
                e,
                ServerEvent::ActionRequest {
                    agent_kind: AgentKind::ClaudeCode,
                    request: ActionRequest {
                        vendor: ActionRequestVendor::ClaudeCode { .. },
                        ..
                    },
                    ..
                }
            )
        });
        assert!(has_action, "type {} did not yield ActionRequest", type_name);
        assert_eq!(out.permission_route_hint.as_deref(), Some("tu_ask"));
        // sanity: kind = ExecuteCommand for Bash
        if let ServerEvent::ActionRequest { request, .. } = &out.events[0] {
            assert!(matches!(request.kind, ActionKind::ExecuteCommand));
        }
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
    let line = json!({
        "type": "permission_request",
        "session_id": "t",
        "tool_use_id": "tu_x",
        "tool_name": "Edit",
        "summary": "patch foo.rs"
    });
    let out = t.translate_line(&line.to_string());
    let ServerEvent::ActionRequest { request, .. } = &out.events[0] else {
        panic!("expected ActionRequest");
    };
    match request.vendor {
        ActionRequestVendor::ClaudeCode {
            permission_mode_at_decision,
            ref tool_name,
        } => {
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
