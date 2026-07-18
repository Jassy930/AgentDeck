use agentdeck_protocol::{
    ActionKind, ActionRequestVendor, AgentItem, ClaudeCodePermissionMode, ServerEvent, SessionId,
    ShellStatus, ThreadId, TurnSummary,
};
use serde_json::json;

use super::history::parse_session_jsonl;
use super::runtime_translate::{ClaudeCodeRuntimeOutput, ClaudeCodeRuntimeTranslator};
use super::translate::ClaudeCodeTranslator;
use crate::agent::AdapterEvent;

#[test]
fn approval_metadata_uses_the_frozen_permission_mode() {
    let mut translator =
        ClaudeCodeRuntimeTranslator::with_permission_mode(ClaudeCodePermissionMode::Plan);
    let outputs = translator
        .translate_value(&json!({
            "type": "control_request",
            "request_id": "frozen-config-request",
            "request": {
                "subtype": "can_use_tool",
                "tool_name": "Bash",
                "input": {"command": "pwd"},
                "tool_use_id": "frozen-config-tool"
            }
        }))
        .expect("modeled control request with frozen permission mode");
    let [ClaudeCodeRuntimeOutput::Approval { request, .. }] = outputs.as_slice() else {
        panic!("control request must yield one approval")
    };
    assert!(matches!(
        request.vendor,
        ActionRequestVendor::ClaudeCode {
            permission_mode_at_decision: ClaudeCodePermissionMode::Plan,
            ..
        }
    ));
}

#[test]
fn recorded_simple_turn_translates_without_vendor_identity() {
    let mut translator = ClaudeCodeRuntimeTranslator::new();
    let mut items = Vec::new();
    let mut terminal = None;
    for line in include_str!("../../tests/fixtures/claude_code/simple_turn.jsonl").lines() {
        for output in translator
            .translate_line(line)
            .expect("recorded simple turn remains modeled")
        {
            match output {
                ClaudeCodeRuntimeOutput::Event(AdapterEvent::Item { key, item }) => {
                    assert!(key.as_str().starts_with("cc-item-"));
                    items.push(item);
                }
                ClaudeCodeRuntimeOutput::TurnComplete(summary) => terminal = Some(summary),
                ClaudeCodeRuntimeOutput::Approval { .. } => {
                    panic!("simple fixture unexpectedly requested approval")
                }
                ClaudeCodeRuntimeOutput::Event(other) => {
                    panic!("unexpected simple fixture event: {other:?}")
                }
            }
        }
    }
    assert!(matches!(
        &items[..],
        [AgentItem::AssistantMessage { text, .. }] if text == "你好，世界！"
    ));
    assert_eq!(
        serde_json::to_vec(&items).expect("canonical simple fixture items"),
        serde_json::to_vec(&history_recorded_items(include_str!(
            "../../tests/fixtures/claude_code/simple_turn.jsonl"
        )))
        .expect("history simple fixture items")
    );
    let terminal = terminal.expect("simple terminal");
    assert_eq!(terminal.elapsed_ms, 5_661);
    assert_eq!(
        canonical_projection(&items, &terminal),
        legacy_recorded_projection(include_str!(
            "../../tests/fixtures/claude_code/simple_turn.jsonl"
        )),
        "production translator bytes must equal the bytes exercised by append/reopen"
    );
}

#[test]
fn recorded_bash_turn_reuses_key_for_running_and_completed_shell() {
    let mut translator = ClaudeCodeRuntimeTranslator::new();
    let mut items = Vec::new();
    let mut shells = Vec::new();
    let mut terminal = None;
    for line in include_str!("../../tests/fixtures/claude_code/bash_tool_use.jsonl").lines() {
        for output in translator
            .translate_line(line)
            .expect("recorded bash turn remains modeled")
        {
            match output {
                ClaudeCodeRuntimeOutput::Event(AdapterEvent::Item { key, item }) => {
                    if let AgentItem::Shell {
                        status, exit_code, ..
                    } = &item
                    {
                        shells.push((key.as_str().to_owned(), *status, *exit_code));
                    }
                    items.push(item);
                }
                ClaudeCodeRuntimeOutput::TurnComplete(summary) => terminal = Some(summary),
                ClaudeCodeRuntimeOutput::Approval { .. } => {
                    panic!("bash output fixture unexpectedly requested approval")
                }
                ClaudeCodeRuntimeOutput::Event(other) => {
                    panic!("unexpected bash fixture event: {other:?}")
                }
            }
        }
    }
    assert_eq!(shells.len(), 2);
    assert_eq!(shells[0].0, shells[1].0);
    assert!(matches!(shells[0].1, ShellStatus::Running));
    assert!(matches!(shells[1].1, ShellStatus::Completed));
    assert_eq!(shells[0].2, None);
    assert_eq!(shells[1].2, None, "tool_result did not report an exit code");
    assert_eq!(
        canonical_projection(&items, &terminal.expect("bash terminal")),
        legacy_recorded_projection(include_str!(
            "../../tests/fixtures/claude_code/bash_tool_use.jsonl"
        )),
        "production translator bytes must equal the bytes exercised by append/reopen"
    );
    assert_eq!(
        serde_json::to_vec(&items).expect("canonical bash fixture items"),
        serde_json::to_vec(&history_recorded_items(include_str!(
            "../../tests/fixtures/claude_code/bash_tool_use.jsonl"
        )))
        .expect("history bash fixture items"),
        "canonical, legacy and history fixture projections must agree"
    );
}

#[test]
fn unmodeled_permission_content_and_orphan_result_fail_closed() {
    let mut translator = ClaudeCodeRuntimeTranslator::new();
    let unknown = translator
        .translate_value(&json!({"type": "future"}))
        .expect_err("unknown top-level frame must fail closed");
    assert_eq!(unknown.code, "cc-unmodeled-frame");

    let raw = translator
        .translate_value(&json!({
            "type": "assistant",
            "message": {"content": [{"type": "future_block"}]}
        }))
        .expect_err("unknown content block must fail closed");
    assert_eq!(raw.code, "cc-content-block-unmodeled");

    let permission = translator
        .translate_value(&json!({"type": "permission_request", "tool_use_id": "x"}))
        .expect_err("speculative permission wire must stay disabled");
    assert_eq!(permission.code, "cc-permission-wire-unverified");

    let orphan = translator
        .translate_value(&json!({
            "type": "user",
            "message": {"content": [{
                "type": "tool_result",
                "tool_use_id": "missing",
                "content": "no owner"
            }]}
        }))
        .expect_err("orphan tool result must fail closed");
    assert_eq!(orphan.code, "cc-tool-result-orphan");
}

#[test]
fn known_but_unverified_stream_delta_fails_closed() {
    let mut translator = ClaudeCodeRuntimeTranslator::new();
    let unverified = translator
        .translate_value(&json!({
            "type": "stream_event",
            "event": {"type": "content_block_delta"}
        }))
        .expect_err("unrecorded partial stream wire must fail closed");
    assert_eq!(unverified.code, "cc-stream-event-unverified");
    let error = translator
        .translate_value(&json!({
            "type": "stream_event",
            "event": {"type": "future_delta"}
        }))
        .expect_err("unknown stream delta must fail closed");
    assert_eq!(error.code, "cc-stream-event-unmodeled");
}

#[test]
fn successful_result_rejects_in_flight_tool_without_losing_state() {
    let mut translator = ClaudeCodeRuntimeTranslator::new();
    translator
        .translate_value(&json!({
            "type": "assistant",
            "message": {"content": [{
                "type": "tool_use",
                "id": "open-tool",
                "name": "Bash",
                "input": {"command": "pwd"}
            }]}
        }))
        .expect("modeled tool start");

    let incomplete = translator
        .translate_value(&json!({
            "type": "result",
            "subtype": "success",
            "is_error": false,
            "duration_ms": 9,
            "terminal_reason": "completed"
        }))
        .expect_err("success terminal with an open tool must fail closed");
    assert_eq!(incomplete.code, "cc-turn-incomplete");

    translator
        .translate_value(&json!({
            "type": "user",
            "message": {"content": [{
                "type": "tool_result",
                "tool_use_id": "open-tool",
                "content": "done"
            }]}
        }))
        .expect("rejected terminal must preserve in-flight tool state");
    let terminal = translator
        .translate_value(&json!({
            "type": "result",
            "subtype": "success",
            "is_error": false,
            "duration_ms": 9,
            "terminal_reason": "completed"
        }))
        .expect("terminal after tool completion is modeled");
    assert!(matches!(
        terminal.as_slice(),
        [ClaudeCodeRuntimeOutput::TurnComplete(summary)] if summary.elapsed_ms == 9
    ));
}

#[test]
fn recorded_lifecycle_frames_and_verified_progress_shapes_are_ignored() {
    // 威胁场景：Claude Code 2.1.207 的正常 status/hook/task/tool progress 若被当成
    // 未知帧，canonical turn 会在权威 result 前中止；只允许已核实的非权威 shape，
    // 未知 subtype 仍 fail-close。fixture 是两次受限真实运行的筛选脱敏输出。
    let mut translator = ClaudeCodeRuntimeTranslator::new();
    assert!(
        translator
            .translate_value(&json!({
                "type": "system",
                "subtype": "init",
                "session_id": "cc-fixture-session",
                "uuid": "cc-fixture-init"
            }))
            .expect("driver already validates the authoritative init identity")
            .is_empty()
    );

    for line in include_str!("../../tests/fixtures/claude_code/lifecycle_frames.jsonl").lines() {
        assert!(
            translator
                .translate_line(line)
                .expect("recorded lifecycle frame is explicitly ignored")
                .is_empty()
        );
    }

    for frame in [
        json!({
            "type": "system",
            "subtype": "status",
            "status": null,
            "session_id": "cc-fixture-session",
            "uuid": "cc-fixture-status-clear"
        }),
        json!({
            "type": "system",
            "subtype": "hook_progress",
            "hook_id": "hook-fixture-2",
            "hook_name": "fixture-hook",
            "session_id": "cc-fixture-session",
            "uuid": "cc-fixture-hook-progress"
        }),
        json!({
            "type": "system",
            "subtype": "task_progress",
            "task_id": "task-fixture-2",
            "tool_use_id": "toolu-fixture-2",
            "description": "fixture progress",
            "session_id": "cc-fixture-session",
            "uuid": "cc-fixture-task-progress"
        }),
        json!({
            "type": "system",
            "subtype": "task_started",
            "task_id": "task-without-tool-owner",
            "description": "ownerless fixture task",
            "session_id": "cc-fixture-session",
            "uuid": "cc-fixture-ownerless-task"
        }),
        json!({
            "type": "system",
            "subtype": "task_updated",
            "task_id": "task-fixture-2",
            "patch": {
                "status": "running",
                "description": "updated fixture task",
                "is_backgrounded": true,
                "total_paused_ms": 0
            },
            "session_id": "cc-fixture-session",
            "uuid": "cc-fixture-task-update"
        }),
        json!({
            "type": "system",
            "subtype": "background_tasks_changed",
            "tasks": [{
                "task_id": "task-fixture-2",
                "task_type": "local_bash",
                "description": "fixture progress"
            }],
            "session_id": "cc-fixture-session",
            "uuid": "cc-fixture-background-change"
        }),
        json!({
            "type": "tool_progress",
            "tool_use_id": "toolu-fixture-2",
            "tool_name": "Bash",
            "parent_tool_use_id": null,
            "elapsed_time_seconds": 1.5,
            "session_id": "cc-fixture-session",
            "uuid": "cc-fixture-tool-progress"
        }),
    ] {
        assert!(
            translator
                .translate_value(&frame)
                .expect("verified non-authoritative progress shape")
                .is_empty()
        );
    }

    let invalid = translator
        .translate_value(&json!({
            "type": "system",
            "subtype": "task_started",
            "description": "missing task identity",
            "session_id": "cc-fixture-session",
            "uuid": "cc-fixture-invalid-task"
        }))
        .expect_err("known lifecycle subtype with a drifted shape must fail closed");
    assert_eq!(invalid.code, "cc-system-frame-invalid");

    let invalid_update = translator
        .translate_value(&json!({
            "type": "system",
            "subtype": "task_updated",
            "task_id": "task-fixture-invalid-update",
            "patch": {"future_field": true},
            "session_id": "cc-fixture-session",
            "uuid": "cc-fixture-invalid-task-update"
        }))
        .expect_err("task update patch is a closed current-version contract");
    assert_eq!(invalid_update.code, "cc-system-frame-invalid");

    let unknown = translator
        .translate_value(&json!({
            "type": "system",
            "subtype": "future_system",
            "session_id": "cc-fixture-session",
            "uuid": "cc-fixture-future-system"
        }))
        .expect_err("unknown system subtype must fail closed");
    assert_eq!(unknown.code, "cc-system-frame-unmodeled");
}

#[test]
fn result_requires_an_explicit_completed_terminal_shape() {
    // 威胁场景：缺失 is_error/duration 或 tool_deferred 结果若被默认成成功，会提前
    // 写 Completed 并清理仍有后续工作的进程组。只有真实 2.1.207 success shape 可完成。
    for (frame, expected_code) in [
        (
            json!({
                "type": "result",
                "subtype": "success",
                "duration_ms": 9,
                "terminal_reason": "completed"
            }),
            "cc-turn-terminal-invalid",
        ),
        (
            json!({
                "type": "result",
                "subtype": "success",
                "is_error": "false",
                "duration_ms": 9,
                "terminal_reason": "completed"
            }),
            "cc-turn-terminal-invalid",
        ),
        (
            json!({
                "type": "result",
                "subtype": "success",
                "is_error": false,
                "terminal_reason": "completed"
            }),
            "cc-turn-terminal-invalid",
        ),
        (
            json!({
                "type": "result",
                "subtype": "success",
                "is_error": false,
                "duration_ms": -1,
                "terminal_reason": "completed"
            }),
            "cc-turn-terminal-invalid",
        ),
        (
            json!({
                "type": "result",
                "subtype": "success",
                "is_error": false,
                "duration_ms": 9
            }),
            "cc-turn-terminal-invalid",
        ),
        (
            json!({
                "type": "result",
                "subtype": "success",
                "is_error": false,
                "duration_ms": 9,
                "terminal_reason": "tool_deferred"
            }),
            "cc-turn-not-completed",
        ),
        (
            json!({
                "type": "result",
                "subtype": "success",
                "is_error": false,
                "duration_ms": 9,
                "terminal_reason": "completed",
                "deferred_tool_use": {"tool_use_id": "toolu-deferred"}
            }),
            "cc-turn-not-completed",
        ),
    ] {
        let error = ClaudeCodeRuntimeTranslator::new()
            .translate_value(&frame)
            .expect_err("non-authoritative result must not emit TurnComplete");
        assert_eq!(error.code, expected_code);
    }

    let completed = ClaudeCodeRuntimeTranslator::new()
        .translate_value(&json!({
            "type": "result",
            "subtype": "success",
            "is_error": false,
            "duration_ms": 13_349,
            "terminal_reason": "completed"
        }))
        .expect("recorded 2.1.207 success terminal");
    assert!(matches!(
        completed.as_slice(),
        [ClaudeCodeRuntimeOutput::TurnComplete(summary)] if summary.elapsed_ms == 13_349
    ));
}

#[test]
fn recorded_control_request_maps_only_the_selected_action_field() {
    // 威胁场景：把完整 CC input、permission_suggestions、blocked_path 或 description
    // 直接塞进 durable ActionRequest，会把编辑正文、路径和 vendor policy hint 写入 Store；
    // 这里只允许 Bash 的 command 作为审批人必须看到的最小动作摘要。
    let line =
        include_str!("../../tests/fixtures/claude_code/control_request_can_use_tool.jsonl").trim();
    let mut translator = ClaudeCodeRuntimeTranslator::new();
    let outputs = translator
        .translate_line(line)
        .expect("recorded can_use_tool request is modeled");
    let [ClaudeCodeRuntimeOutput::Approval { request, route }] = outputs.as_slice() else {
        panic!("recorded control request must yield one typed approval")
    };
    assert_eq!(request.request_id, "cc-request-fixture-1");
    assert_eq!(request.kind, ActionKind::ExecuteCommand);
    assert_eq!(
        request.summary,
        "Claude Code 请求执行命令：\"printf approval-action-visible\""
    );
    assert!(matches!(
        &request.vendor,
        ActionRequestVendor::ClaudeCode {
            permission_mode_at_decision: ClaudeCodePermissionMode::Default,
            tool_name,
        } if tool_name == "Bash"
    ));
    assert_eq!(route.request_id, "cc-request-fixture-1");
    assert_eq!(route.tool_use_id, "toolu_fixture_1");
    assert_eq!(route.tool_name, "Bash");
    let durable = serde_json::to_string(request).expect("encode neutral ActionRequest");
    for forbidden in [
        "raw-description-must-not-persist",
        "raw-suggestion-must-not-persist",
        "raw-path-must-not-persist",
    ] {
        assert!(
            !durable.contains(forbidden),
            "raw field leaked: {forbidden}"
        );
    }
}

#[test]
fn control_request_summary_is_bounded_utf8_safe_redacted_and_distinguishable() {
    let secret = "sk-summary-secret-123456789";
    let mut first = control_request("req-1", "toolu-1", "Bash");
    first["request"]["input"] = json!({"command": format!(
        "  运行\nBearer bearer-secret {secret} {}  ",
        "界".repeat(20)
    )});
    first["request"]["description"] = json!("raw-description-must-not-persist");
    first["request"]["permission_suggestions"] =
        json!([{"ruleContent": "raw-suggestion-must-not-persist"}]);
    first["request"]["blocked_path"] = json!("/raw/path/must-not-persist");

    let mut translator = ClaudeCodeRuntimeTranslator::new();
    let output = translator
        .translate_value(&first)
        .expect("bounded sanitized approval summary");
    let [ClaudeCodeRuntimeOutput::Approval { request, .. }] = output.as_slice() else {
        panic!("control request must yield one approval")
    };
    assert!(request.summary.len() <= 512);
    assert!(request.summary.is_char_boundary(request.summary.len()));
    assert!(request.summary.contains("<REDACTED>"));
    assert!(request.summary.contains(r#"\nBearer"#));
    assert!(!request.summary.contains(secret));
    assert!(!request.summary.contains('\n'));
    assert!(!request.summary.chars().any(char::is_control));
    let durable = serde_json::to_string(request).expect("encode sanitized approval");
    for forbidden in [
        "raw-description-must-not-persist",
        "raw-suggestion-must-not-persist",
        "/raw/path/must-not-persist",
    ] {
        assert!(!durable.contains(forbidden), "raw control field leaked");
    }

    let mut second = control_request("req-2", "toolu-2", "Bash");
    second["request"]["input"] = json!({"command": "执行另一条已验证动作"});
    let second = translator
        .translate_value(&second)
        .expect("second action summary");
    let [
        ClaudeCodeRuntimeOutput::Approval {
            request: second_request,
            ..
        },
    ] = second.as_slice()
    else {
        panic!("second control request must yield one approval")
    };
    assert_ne!(request.summary, second_request.summary);
}

#[test]
fn control_request_uses_only_the_tool_kind_action_field() {
    for (tool_name, input, expected) in [
        (
            "Edit",
            json!({"file_path": "/workspace/src/main.rs", "new_string": "raw-edit-body"}),
            "Claude Code 请求编辑文件：\"/workspace/src/main.rs\"",
        ),
        (
            "Write",
            json!({"file_path": "/workspace/src/new.rs", "content": "raw-write-body"}),
            "Claude Code 请求编辑文件：\"/workspace/src/new.rs\"",
        ),
        (
            "MultiEdit",
            json!({"file_path": "/workspace/src/multi.rs", "edits": ["raw-multi-body"]}),
            "Claude Code 请求编辑文件：\"/workspace/src/multi.rs\"",
        ),
        (
            "NotebookEdit",
            json!({"notebook_path": "/workspace/demo.ipynb", "new_source": "raw-cell-body"}),
            "Claude Code 请求编辑文件：\"/workspace/demo.ipynb\"",
        ),
        (
            "Read",
            json!({"file_path": "/workspace/README.md"}),
            "Claude Code 请求额外权限：\"/workspace/README.md\"",
        ),
    ] {
        let mut frame = control_request("req", "toolu", tool_name);
        frame["request"]["input"] = input;
        frame["request"]["description"] = json!("raw-description");
        frame["request"]["permission_suggestions"] = json!([{"raw": "raw-suggestion"}]);
        let mut translator = ClaudeCodeRuntimeTranslator::new();
        let outputs = translator
            .translate_value(&frame)
            .expect("tool-specific action summary");
        let [ClaudeCodeRuntimeOutput::Approval { request, .. }] = outputs.as_slice() else {
            panic!("control request must yield one approval")
        };
        assert_eq!(request.summary, expected);
        let durable = serde_json::to_string(request).expect("encode action summary");
        for forbidden in [
            "raw-edit-body",
            "raw-write-body",
            "raw-multi-body",
            "raw-cell-body",
            "raw-description",
            "raw-suggestion",
        ] {
            assert!(!durable.contains(forbidden));
        }
    }
}

#[test]
fn oversized_control_action_fails_closed_before_redaction() {
    let mut frame = control_request("req-large", "toolu-large", "Bash");
    frame["request"]["input"] = json!({
        "command": format!("{}tail-must-not-enter-summary", "界".repeat(1_000_000))
    });
    let mut translator = ClaudeCodeRuntimeTranslator::new();
    let error = translator
        .translate_value(&frame)
        .expect_err("truncated action must never produce an approval");
    assert_eq!(error.code, "cc-control-action-too-large");
}

#[test]
fn shell_tool_result_without_authoritative_code_never_fabricates_zero_or_one() {
    for is_error in [false, true] {
        let mut translator = ClaudeCodeRuntimeTranslator::new();
        translator
            .translate_value(&tool_start("tool-a", "Bash", json!({"command": "false"})))
            .expect("modeled shell start");
        let completed = translator
            .translate_value(&json!({
                "type": "user",
                "message": {"content": [{
                    "type": "tool_result",
                    "tool_use_id": "tool-a",
                    "content": "fixture result",
                    "is_error": is_error
                }]}
            }))
            .expect("modeled shell result");
        assert!(matches!(
            completed.as_slice(),
            [ClaudeCodeRuntimeOutput::Event(AdapterEvent::Item {
                item: AgentItem::Shell {
                    exit_code: None,
                    ..
                },
                ..
            })]
        ));
    }
}

#[test]
fn control_request_action_kind_mapping_is_exact() {
    for (tool_name, expected) in [
        ("Bash", ActionKind::ExecuteCommand),
        ("Edit", ActionKind::EditFiles),
        ("Write", ActionKind::EditFiles),
        ("MultiEdit", ActionKind::EditFiles),
        ("NotebookEdit", ActionKind::EditFiles),
        ("Read", ActionKind::GrantExtraPermission),
    ] {
        let mut translator = ClaudeCodeRuntimeTranslator::new();
        let outputs = translator
            .translate_value(&control_request("req-1", "toolu-1", tool_name))
            .expect("mapped can_use_tool request");
        assert!(matches!(
            outputs.as_slice(),
            [ClaudeCodeRuntimeOutput::Approval { request, .. }] if request.kind == expected
        ));
    }
}

#[test]
fn missing_action_and_unknown_tool_fail_closed_without_approval() {
    // 威胁场景：CC 提供泛化 description/display_name，却缺少具体 command/path，或发送
    // 尚未建模的新工具；若仍生成 Approval，用户只能盲签，且未知 input 可能被误分类。
    for tool_name in ["Bash", "Edit", "Write", "MultiEdit", "NotebookEdit", "Read"] {
        let mut frame = control_request("req-missing", "toolu-missing", tool_name);
        frame["request"]["input"] = json!({});
        frame["request"]["description"] = json!("generic fallback must not approve");
        frame["request"]["display_name"] = json!("generic display fallback");
        let mut translator = ClaudeCodeRuntimeTranslator::new();
        let error = translator
            .translate_value(&frame)
            .expect_err("missing tool-specific action must fail closed");
        assert_eq!(error.code, "cc-control-action-invalid");
    }

    let mut whitespace = control_request("req-whitespace", "toolu-whitespace", "Bash");
    whitespace["request"]["input"] = json!({"command": "\n\t\r"});
    let mut translator = ClaudeCodeRuntimeTranslator::new();
    let error = translator
        .translate_value(&whitespace)
        .expect_err("empty sanitized action must fail closed");
    assert_eq!(error.code, "cc-control-action-invalid");

    let mut unknown = control_request("req-unknown", "toolu-unknown", "FutureTool");
    unknown["request"]["input"] = json!({
        "command": "must not be inferred",
        "file_path": "/must/not/be/inferred"
    });
    unknown["request"]["description"] = json!("generic fallback must not approve");
    let error = translator
        .translate_value(&unknown)
        .expect_err("unknown tool must fail closed");
    assert_eq!(error.code, "cc-control-tool-unmodeled");
}

#[test]
fn unknown_control_subtype_and_unbounded_identity_fail_closed() {
    let mut translator = ClaudeCodeRuntimeTranslator::new();
    let unknown = translator
        .translate_value(&json!({
            "type": "control_request",
            "request_id": "req-1",
            "request": {
                "subtype": "future_control",
                "tool_name": "Bash",
                "tool_use_id": "toolu-1"
            }
        }))
        .expect_err("unknown control subtype must fail closed");
    assert_eq!(unknown.code, "cc-control-subtype-unmodeled");

    let oversized = "x".repeat(513);
    for frame in [
        control_request(&oversized, "toolu-1", "Bash"),
        control_request("req-1", &oversized, "Bash"),
        control_request("req-1", "toolu-1", &"x".repeat(129)),
    ] {
        assert!(
            translator.translate_value(&frame).is_err(),
            "unbounded control identity must be rejected"
        );
    }
}

#[test]
fn retained_state_limit_accepts_exact_payload_and_rejects_one_more_byte() {
    // 威胁场景：大量并发 tool_use 的 id/name/input 与 completed ids 若在 Store ACK
    // gate 前持续累积，会让 daemon 内存无界增长；translator 必须先限额再改变状态。
    let exact_input = json!({"value": "abc"});
    let larger_input = json!({"value": "abcd"});
    let exact_limit = "tool-a".len()
        + "CustomTool".len()
        + serde_json::to_vec(&exact_input)
            .expect("serialize exact input")
            .len();
    let larger_bytes = "tool-a".len()
        + "CustomTool".len()
        + serde_json::to_vec(&larger_input)
            .expect("serialize larger input")
            .len();
    assert_eq!(larger_bytes, exact_limit + 1);

    let mut exact = ClaudeCodeRuntimeTranslator::with_retained_byte_limit(exact_limit);
    let accepted = exact
        .translate_value(&tool_start("tool-a", "CustomTool", exact_input))
        .expect("exact retained payload limit is accepted");
    assert!(matches!(
        accepted.as_slice(),
        [ClaudeCodeRuntimeOutput::Event(AdapterEvent::Item { key, .. })]
            if key.as_str() == "cc-item-1"
    ));
    assert_eq!(exact.retained_bytes_for_test(), exact_limit);

    let mut over = ClaudeCodeRuntimeTranslator::with_retained_byte_limit(exact_limit);
    let error = over
        .translate_value(&tool_start("tool-a", "CustomTool", larger_input))
        .expect_err("one byte beyond retained payload limit must fail closed");
    assert_eq!(error.code, "cc-retained-state-limit");
    assert_eq!(over.retained_bytes_for_test(), 0);
    let text = over
        .translate_value(&json!({
            "type": "assistant",
            "message": {"content": [{"type": "text", "text": "still usable"}]}
        }))
        .expect("limit rejection must not consume the next neutral item key");
    assert!(matches!(
        text.as_slice(),
        [ClaudeCodeRuntimeOutput::Event(AdapterEvent::Item { key, .. })]
            if key.as_str() == "cc-item-1"
    ));
}

#[test]
fn retained_limit_rejection_preserves_open_tool_and_completion_releases_payload() {
    let input = json!({"command": "pwd"});
    let tool_bytes = "tool-a".len()
        + "Bash".len()
        + serde_json::to_vec(&input)
            .expect("serialize retained tool input")
            .len();
    let mut translator =
        ClaudeCodeRuntimeTranslator::with_retained_byte_limit(tool_bytes + "tool-a".len());
    let started = translator
        .translate_value(&tool_start("tool-a", "Bash", input.clone()))
        .expect("first tool fits retained payload limit");
    assert!(matches!(
        started.as_slice(),
        [ClaudeCodeRuntimeOutput::Event(AdapterEvent::Item { key, .. })]
            if key.as_str() == "cc-item-1"
    ));

    let over = translator
        .translate_value(&tool_start("tool-b", "Bash", input.clone()))
        .expect_err("second in-flight tool exceeds retained payload limit");
    assert_eq!(over.code, "cc-retained-state-limit");
    let incomplete = translator
        .translate_value(&json!({
            "type": "result",
            "subtype": "success",
            "is_error": false,
            "duration_ms": 9,
            "terminal_reason": "completed"
        }))
        .expect_err("limit rejection must not remove the first open tool");
    assert_eq!(incomplete.code, "cc-turn-incomplete");

    let completed = translator
        .translate_value(&tool_result("tool-a"))
        .expect("first tool remains available for completion");
    assert!(matches!(
        completed.as_slice(),
        [ClaudeCodeRuntimeOutput::Event(AdapterEvent::Item { key, .. })]
            if key.as_str() == "cc-item-1"
    ));
    assert_eq!(translator.retained_bytes_for_test(), "tool-a".len());
    let duplicate = translator
        .translate_value(&tool_result("tool-a"))
        .expect_err("completed id remains retained for duplicate rejection");
    assert_eq!(duplicate.code, "cc-tool-identity-duplicate");

    let second = translator
        .translate_value(&tool_start("tool-b", "Bash", input))
        .expect("completion releases name/input budget for the next tool");
    assert!(matches!(
        second.as_slice(),
        [ClaudeCodeRuntimeOutput::Event(AdapterEvent::Item { key, .. })]
            if key.as_str() == "cc-item-2"
    ));
}

fn tool_start(id: &str, name: &str, input: serde_json::Value) -> serde_json::Value {
    json!({
        "type": "assistant",
        "message": {"content": [{
            "type": "tool_use",
            "id": id,
            "name": name,
            "input": input
        }]}
    })
}

fn control_request(request_id: &str, tool_use_id: &str, tool_name: &str) -> serde_json::Value {
    let input = match tool_name {
        "Bash" => json!({"command": "printf fixture-action"}),
        "Edit" | "Write" | "MultiEdit" => json!({"file_path": "/workspace/fixture.txt"}),
        "NotebookEdit" => json!({"notebook_path": "/workspace/fixture.ipynb"}),
        "Read" => json!({"file_path": "/workspace/fixture.txt"}),
        _ => json!({}),
    };
    json!({
        "type": "control_request",
        "request_id": request_id,
        "request": {
            "subtype": "can_use_tool",
            "tool_name": tool_name,
            "tool_use_id": tool_use_id,
            "input": input
        }
    })
}

fn tool_result(id: &str) -> serde_json::Value {
    json!({
        "type": "user",
        "message": {"content": [{
            "type": "tool_result",
            "tool_use_id": id,
            "content": "done"
        }]}
    })
}

fn legacy_recorded_projection(lines: &str) -> Vec<u8> {
    let mut translator = ClaudeCodeTranslator::new(
        SessionId("runtime-production-byte-bridge".to_owned()),
        ClaudeCodePermissionMode::BypassPermissions,
    );
    let mut items = Vec::new();
    let mut terminal = None;
    for line in lines.lines() {
        for event in translator.translate_line(line).events {
            match event {
                ServerEvent::AgentItem { item, .. } => items.push(item),
                ServerEvent::TurnComplete { summary, .. } => terminal = Some(summary),
                _ => {}
            }
        }
    }
    canonical_projection(&items, &terminal.expect("legacy fixture terminal"))
}

fn history_recorded_items(lines: &str) -> Vec<AgentItem> {
    parse_session_jsonl(lines, ThreadId("runtime-history-byte-bridge".to_owned()))
        .expect("parse history fixture")
        .turns
        .into_iter()
        .flat_map(|turn| turn.items)
        .collect()
}

fn canonical_projection(items: &[AgentItem], terminal: &TurnSummary) -> Vec<u8> {
    serde_json::to_vec(&(items, terminal)).expect("canonical fixture projection")
}
