use agentdeck_protocol::{
    ActionDecision, ActionDecisionKind, ActionRequest, AgentItem, ServerEvent, SessionId,
    ShellStatus, ThreadId, TurnSummary,
};
use serde_json::json;

use super::adapter::approval_response_body;
use super::runtime_translate::{
    CodexRuntimeOutput, CodexRuntimeTranslator, MAX_APPROVAL_SUMMARY_BYTES,
};
use super::translate::CodexTranslator;
use crate::agent::AdapterEvent;

#[test]
fn recorded_turn_uses_only_neutral_item_keys_and_typed_items() {
    let mut translator = CodexRuntimeTranslator::new();
    let mut items = Vec::new();
    let mut terminal = None;

    for line in include_str!("../../tests/fixtures/codex/simple_turn.jsonl").lines() {
        for output in translator
            .translate_line(line)
            .expect("recorded Codex frame must remain modeled")
        {
            match output {
                CodexRuntimeOutput::Event(AdapterEvent::Item { key, item }) => {
                    assert!(key.as_str().starts_with("codex-item-"));
                    items.push(item);
                }
                CodexRuntimeOutput::TurnComplete(summary) => terminal = Some(summary),
                CodexRuntimeOutput::Event(AdapterEvent::Error(error)) => {
                    panic!("recorded fixture produced typed error: {}", error.code)
                }
                CodexRuntimeOutput::Approval { .. }
                | CodexRuntimeOutput::Diagnostic { .. }
                | CodexRuntimeOutput::Event(AdapterEvent::TurnComplete(_))
                | CodexRuntimeOutput::Event(AdapterEvent::VendorControl(_))
                | CodexRuntimeOutput::Event(AdapterEvent::VendorPanelEvent(_)) => {}
            }
        }
    }

    assert_eq!(items.len(), 1);
    assert!(matches!(
        &items[0],
        AgentItem::AssistantMessage { text, .. } if text == "fixture-ok"
    ));
    let terminal = terminal.expect("fixture terminal");
    assert_eq!(terminal.elapsed_ms, 3_213);
    assert_eq!(
        canonical_projection(&items, &terminal),
        legacy_recorded_projection(include_str!("../../tests/fixtures/codex/simple_turn.jsonl")),
        "production translator bytes must equal the bytes exercised by append/reopen"
    );
}

#[test]
fn canonical_assistant_metadata_never_persists_memory_citation_thread_ids() {
    // 威胁场景：memoryCitation 的 threadIds 若进入 AgentItemMeta，会越过 adapter
    // 私表并落到 Runtime Store/Relay；canonical event 只能保留无身份的 phase。
    let mut translator = CodexRuntimeTranslator::new();
    translator
        .translate_value(&json!({
            "method": "item/started",
            "params": {"item": {
                "type": "agentMessage",
                "id": "assistant-with-memory",
                "text": ""
            }}
        }))
        .expect("modeled assistant start");
    let completed = translator
        .translate_value(&json!({
            "method": "item/completed",
            "params": {"item": {
                "type": "agentMessage",
                "id": "assistant-with-memory",
                "text": "canonical answer",
                "phase": "commentary",
                "memoryCitation": {
                    "entries": [{
                        "path": "MEMORY.md",
                        "lineStart": 1,
                        "lineEnd": 2,
                        "note": "memory-note-sentinel"
                    }],
                    "threadIds": ["vendor-thread-sentinel"]
                }
            }}
        }))
        .expect("modeled assistant completion");
    let item = item_output(&completed[0]).1;
    let AgentItem::AssistantMessage { meta, .. } = item else {
        panic!("expected canonical assistant item")
    };
    assert_eq!(
        meta.vendor_extensions.get("phase"),
        Some(&json!("commentary"))
    );
    assert!(!meta.vendor_extensions.contains_key("memoryCitation"));
    let durable = serde_json::to_string(item).expect("encode canonical assistant item");
    for forbidden in [
        "memoryCitation",
        "threadIds",
        "vendor-thread-sentinel",
        "memory-note-sentinel",
    ] {
        assert!(!durable.contains(forbidden));
    }
}

#[test]
fn canonical_diff_uses_the_official_patch_kind_object_and_rejects_drift() {
    // 威胁场景：PatchChangeKind 被误当字符串时 add/delete 都降级成 Modified，
    // update.move_path 也无法标记 rename；未知 shape 必须 fail-close 且保留 state。
    let mut translator = CodexRuntimeTranslator::new();
    let changes = json!([
        {"path": "added.txt", "diff": "+added", "kind": {"type": "add"}},
        {"path": "deleted.txt", "diff": "-deleted", "kind": {"type": "delete"}},
        {"path": "updated.txt", "diff": "+updated", "kind": {"type": "update", "move_path": null}},
        {"path": "old.txt", "diff": "rename", "kind": {"type": "update", "move_path": "new.txt"}}
    ]);
    let started = translator
        .translate_value(&json!({
            "method": "item/started",
            "params": {"item": {
                "type": "fileChange",
                "id": "official-diff",
                "status": "inProgress",
                "changes": changes.clone()
            }}
        }))
        .expect("modeled diff start");
    assert_eq!(started.len(), 1, "proposed patch must precede approval");
    let completed = translator
        .translate_value(&json!({
            "method": "item/completed",
            "params": {"item": {
                "type": "fileChange",
                "id": "official-diff",
                "status": "completed",
                "changes": changes
            }}
        }))
        .expect("official diff completion");
    let AgentItem::Diff { files, .. } = item_output(&completed[0]).1 else {
        panic!("expected canonical diff item")
    };
    assert!(matches!(
        files[0].status,
        agentdeck_protocol::DiffStatus::Added
    ));
    assert!(matches!(
        files[1].status,
        agentdeck_protocol::DiffStatus::Deleted
    ));
    assert!(matches!(
        files[2].status,
        agentdeck_protocol::DiffStatus::Modified
    ));
    assert!(matches!(
        files[3].status,
        agentdeck_protocol::DiffStatus::Renamed
    ));

    let mut drift = CodexRuntimeTranslator::new();
    drift
        .translate_value(&json!({
            "method": "item/started",
            "params": {"item": {
                "type": "fileChange",
                "id": "drift-diff",
                "status": "inProgress",
                "changes": []
            }}
        }))
        .expect("modeled drift start");
    let error = drift
        .translate_value(&json!({
            "method": "item/completed",
            "params": {"item": {
                "type": "fileChange",
                "id": "drift-diff",
                "status": "completed",
                "changes": [{"path": "drift.txt", "diff": "+x", "kind": "add"}]
            }}
        }))
        .expect_err("legacy string kind must not enter canonical Runtime");
    assert_eq!(error.code, "codex-diff-shape-invalid");
    drift
        .translate_value(&json!({
            "method": "item/completed",
            "params": {"item": {
                "type": "fileChange",
                "id": "drift-diff",
                "status": "completed",
                "changes": [{"path": "drift.txt", "diff": "+x", "kind": {"type": "add"}}]
            }}
        }))
        .expect("rejected diff shape must preserve in-flight state");
}

#[test]
fn shell_running_and_completed_reuse_the_same_neutral_key() {
    let mut translator = CodexRuntimeTranslator::new();
    let started = translator
        .translate_value(&json!({
            "method": "item/started",
            "params": {"item": {"type": "commandExecution", "id": "vendor-shell", "command": "pwd"}}
        }))
        .expect("modeled shell start");
    let completed = translator
        .translate_value(&json!({
            "method": "item/completed",
            "params": {"item": {
                "type": "commandExecution",
                "id": "vendor-shell",
                "command": "pwd",
                "status": "completed",
                "exitCode": 0
            }}
        }))
        .expect("modeled shell completion");

    let (started_key, started_item) = item_output(&started[0]);
    let (completed_key, completed_item) = item_output(&completed[0]);
    assert_eq!(started_key, completed_key);
    assert!(matches!(
        started_item,
        AgentItem::Shell {
            status: ShellStatus::Running,
            ..
        }
    ));
    assert!(matches!(
        completed_item,
        AgentItem::Shell {
            status: ShellStatus::Completed,
            exit_code: Some(0),
            ..
        }
    ));
}

#[test]
fn shell_terminal_status_is_exact_and_declined_is_canceled() {
    // 威胁场景：官方 declined 或非终态/未知 status 被默认当成成功，会把未执行的
    // 命令永久记录为 Completed；拒绝帧后 translator 还必须保留原 in-flight state。
    for (status, expected) in [
        ("completed", "completed"),
        ("failed", "failed"),
        ("declined", "canceled"),
    ] {
        let mut translator = CodexRuntimeTranslator::new();
        translator
            .translate_value(&json!({
                "method": "item/started",
                "params": {"item": {
                    "type": "commandExecution",
                    "id": "shell-status",
                    "command": "pwd"
                }}
            }))
            .expect("modeled shell start");
        let completed = translator
            .translate_value(&json!({
                "method": "item/completed",
                "params": {"item": {
                    "type": "commandExecution",
                    "id": "shell-status",
                    "command": "pwd",
                    "status": status
                }}
            }))
            .expect("official shell terminal status");
        let AgentItem::Shell { status, .. } = item_output(&completed[0]).1 else {
            panic!("expected typed shell terminal")
        };
        assert_shell_status(status, expected);
    }

    for status in [Some("inProgress"), Some("success"), None] {
        let mut translator = CodexRuntimeTranslator::new();
        translator
            .translate_value(&json!({
                "method": "item/started",
                "params": {"item": {
                    "type": "commandExecution",
                    "id": "shell-invalid-status",
                    "command": "pwd"
                }}
            }))
            .expect("modeled shell start");
        let mut terminal = json!({
            "method": "item/completed",
            "params": {"item": {
                "type": "commandExecution",
                "id": "shell-invalid-status",
                "command": "pwd"
            }}
        });
        if let Some(status) = status {
            terminal["params"]["item"]["status"] = json!(status);
        }
        let error = translator
            .translate_value(&terminal)
            .expect_err("non-authoritative shell status must fail closed");
        assert_eq!(error.code, "codex-shell-terminal-status-invalid");

        translator
            .translate_value(&json!({
                "method": "item/completed",
                "params": {"item": {
                    "type": "commandExecution",
                    "id": "shell-invalid-status",
                    "command": "pwd",
                    "status": "completed"
                }}
            }))
            .expect("rejected terminal must preserve the in-flight shell");
    }
}

#[test]
fn item_completion_requires_the_exact_started_kind_without_losing_state() {
    let mut translator = CodexRuntimeTranslator::new();
    let started = translator
        .translate_value(&json!({
            "method": "item/started",
            "params": {"item": {
                "type": "commandExecution",
                "id": "kind-stable",
                "command": "pwd"
            }}
        }))
        .expect("modeled shell start");
    let started_key = item_output(&started[0]).0.to_owned();

    let mismatch = translator
        .translate_value(&json!({
            "method": "item/completed",
            "params": {"item": {
                "type": "agentMessage",
                "id": "kind-stable",
                "text": "fabricated type flip"
            }}
        }))
        .expect_err("terminal item kind cannot differ from its start frame");
    assert_eq!(mismatch.code, "codex-item-kind-mismatch");

    let completed = translator
        .translate_value(&json!({
            "method": "item/completed",
            "params": {"item": {
                "type": "commandExecution",
                "id": "kind-stable",
                "command": "pwd",
                "status": "completed"
            }}
        }))
        .expect("kind mismatch must preserve the exact in-flight item");
    assert_eq!(item_output(&completed[0]).0, started_key);
}

#[test]
fn approval_summary_uses_bounded_redacted_official_fields_only() {
    // 威胁场景：直接持久化 approval raw params 会泄漏密钥和未来 vendor 字段；
    // 只写泛化文案又会让用户无法判断自己批准的是哪条命令。
    let mut translator = CodexRuntimeTranslator::new();
    let output = translator
        .translate_value(&json!({
            "id": "approval-rpc",
            "method": "item/commandExecution/requestApproval",
            "params": {
                "approvalId": "approval-summary",
                "command": "deploy --token sk-command-secret\n--auth 'Bearer bearer-secret'",
                "cwd": "/workspace/project",
                "reason": "release requested",
                "commandActions": [{
                    "type": "unknown",
                    "command": "fallback-must-not-override-command"
                }],
                "futureRawField": "raw-frame-sentinel"
            }
        }))
        .expect("modeled command approval");
    let request = approval_output(&output[0]);
    assert!(request.summary.contains("deploy --token <REDACTED>"));
    assert!(request.summary.contains("Bearer <REDACTED>"));
    assert!(request.summary.contains(r#"\n--auth"#));
    assert!(!request.summary.contains('\n'));
    assert!(request.summary.contains(r#"cwd: "/workspace/project""#));
    assert!(request.summary.contains(r#"reason: "release requested""#));
    assert!(!request.summary.contains("sk-command-secret"));
    assert!(!request.summary.contains("bearer-secret"));
    assert!(
        !request
            .summary
            .contains("fallback-must-not-override-command")
    );
    assert!(!request.summary.contains("raw-frame-sentinel"));
    assert!(request.summary.len() <= MAX_APPROVAL_SUMMARY_BYTES);
    let durable = serde_json::to_string(request).expect("encode canonical approval");
    assert!(!durable.contains("futureRawField"));
    assert!(!durable.contains("raw-frame-sentinel"));

    let fallback = translator
        .translate_value(&json!({
            "id": "approval-actions-rpc",
            "method": "item/commandExecution/requestApproval",
            "params": {
                "approvalId": "approval-actions",
                "command": null,
                "commandActions": [
                    {"type": "read", "command": "cat README.md", "name": "README.md", "path": "/workspace/README.md"},
                    {"type": "search", "command": "rg TODO src", "path": "src", "query": "TODO"}
                ]
            }
        }))
        .expect("official commandActions fallback");
    let fallback = approval_output(&fallback[0]);
    assert!(fallback.summary.contains(r#"command: "cat README.md""#));
    assert!(fallback.summary.contains("rg TODO src"));
}

#[test]
fn approval_action_must_be_concrete_and_fully_displayable() {
    let mut translator = CodexRuntimeTranslator::new();
    let error = translator
        .translate_value(&json!({
            "id": "missing-action",
            "method": "item/commandExecution/requestApproval",
            "params": {"approvalId": "missing-command", "reason": "generic reason"}
        }))
        .expect_err("approval without a concrete action must fail closed");
    assert_eq!(error.code, "codex-approval-action-missing");

    translator
        .translate_value(&json!({
            "method": "item/started",
            "params": {"item": {
                "type": "fileChange",
                "id": "empty-file-change",
                "status": "inProgress",
                "changes": []
            }}
        }))
        .expect("official empty file change start");
    let error = translator
        .translate_value(&json!({
            "id": "missing-file-action",
            "method": "item/fileChange/requestApproval",
            "params": {
                "approvalId": "missing-file-action",
                "itemId": "empty-file-change",
                "reason": "generic reason"
            }
        }))
        .expect_err("file approval without concrete changes must fail closed");
    assert_eq!(error.code, "codex-approval-action-missing");

    let invalid_action = translator
        .translate_value(&json!({
            "id": "invalid-action",
            "method": "item/commandExecution/requestApproval",
            "params": {
                "approvalId": "invalid-action",
                "command": null,
                "commandActions": [{"type": "read", "command": "cat README.md", "name": "README.md"}]
            }
        }))
        .expect_err("incomplete official command action must fail closed");
    assert_eq!(invalid_action.code, "codex-invalid-approval-params");

    let command = "界".repeat(MAX_APPROVAL_SUMMARY_BYTES);
    let too_large = translator
        .translate_value(&json!({
            "id": "approval-long-rpc",
            "method": "item/commandExecution/requestApproval",
            "params": {"approvalId": "approval-long", "command": command}
        }))
        .expect_err("action that cannot be displayed completely must fail closed");
    assert_eq!(too_large.code, "codex-approval-summary-too-large");

    let boundary_secret = format!("{} {}A1", "p".repeat(980), "a".repeat(80));
    let boundary = translator
        .translate_value(&json!({
            "id": "approval-boundary-rpc",
            "method": "item/commandExecution/requestApproval",
            "params": {"approvalId": "approval-boundary", "command": boundary_secret}
        }))
        .expect("redaction look-ahead remains bounded");
    let boundary_summary = &approval_output(&boundary[0]).summary;
    assert!(boundary_summary.contains("<REDACTED>"));
    assert!(boundary_summary.len() <= MAX_APPROVAL_SUMMARY_BYTES);

    translator
        .translate_value(&json!({
            "method": "item/started",
            "params": {"item": {
                "type": "fileChange",
                "id": "approval-file-item",
                "status": "inProgress",
                "changes": [{
                    "path": "/workspace/generated/output.txt",
                    "diff": "+generated",
                    "kind": {"type": "add"}
                }]
            }}
        }))
        .expect("file change proposal is modeled");
    let file_change = translator
        .translate_value(&json!({
            "id": "approval-file-rpc",
            "method": "item/fileChange/requestApproval",
            "params": {
                "approvalId": "approval-file",
                "itemId": "approval-file-item",
                "grantRoot": "/workspace/generated",
                "reason": "write generated files"
            }
        }))
        .expect("modeled file approval");
    let file_summary = &approval_output(&file_change[0]).summary;
    assert!(file_summary.contains(r#"changes: add "/workspace/generated/output.txt""#));
    assert!(file_summary.contains(r#"root: "/workspace/generated""#));
    assert!(file_summary.contains(r#"reason: "write generated files""#));
}

#[test]
fn permission_summary_contains_the_full_validated_profile_projection() {
    let mut translator = CodexRuntimeTranslator::new();
    let params = json!({
        "approvalId": "approval-permission",
        "cwd": "/workspace",
        "permissions": {
            "fileSystem": {
                "read": ["/tmp/read"],
                "write": ["/tmp/write"],
                "entries": [
                    {"access": "read", "path": {"type": "path", "path": "/workspace/src"}},
                    {"access": "write", "path": {"type": "glob_pattern", "pattern": "/tmp/**"}},
                    {"access": "none", "path": {"type": "special", "value": {"kind": "project_roots", "subpath": "target"}}}
                ],
                "globScanMaxDepth": 3
            },
            "network": {"enabled": true}
        },
        "reason": "inspect dependency metadata"
    });
    let permission = translator
        .translate_value(&json!({
            "id": "approval-permission-rpc",
            "method": "item/permissions/requestApproval",
            "params": params
        }))
        .expect("modeled permission approval");
    let permission_summary = &approval_output(&permission[0]).summary;
    let response = approval_response_body(
        "item/permissions/requestApproval",
        &params,
        &ActionDecision {
            request_id: "approval-permission".to_owned(),
            decision: ActionDecisionKind::Approve,
            persist: false,
        },
    )
    .expect("the same profile is accepted by the response builder");
    let exact_profile =
        serde_json::to_string(&response["permissions"]).expect("encode validated response profile");
    assert!(
        permission_summary.contains(&format!("profile: {exact_profile}")),
        "non-secret profile fixture must contain every field echoed by the adapter"
    );
    assert!(permission_summary.contains("\"read\":[\"/tmp/read\"]"));
    assert!(permission_summary.contains("\"write\":[\"/tmp/write\"]"));
    assert!(permission_summary.contains("\"globScanMaxDepth\":3"));
    assert!(permission_summary.contains("\"enabled\":true"));
    assert!(permission_summary.contains("\"glob_pattern\""));
    assert!(permission_summary.contains("\"project_roots\""));
    assert!(permission_summary.contains(r#"cwd: "/workspace""#));
    assert!(permission_summary.contains(r#"reason: "inspect dependency metadata""#));
    assert!(permission_summary.len() <= MAX_APPROVAL_SUMMARY_BYTES);
}

#[test]
fn empty_malformed_or_oversized_permission_profiles_fail_closed() {
    let mut translator = CodexRuntimeTranslator::new();
    for (permissions, expected_code) in [
        (
            json!({"fileSystem": null, "network": null}),
            "codex-approval-action-missing",
        ),
        (
            json!({"fileSystem": {}, "network": {}}),
            "codex-approval-action-missing",
        ),
        (
            json!({"fileSystem": {"globScanMaxDepth": 3}, "network": null}),
            "codex-approval-action-missing",
        ),
        (
            json!({"network": {"enabled": "yes"}}),
            "codex-invalid-approval-params",
        ),
    ] {
        let error = translator
            .translate_value(&json!({
                "id": "permission-invalid",
                "method": "item/permissions/requestApproval",
                "params": {
                    "approvalId": "permission-invalid",
                    "cwd": "/workspace",
                    "permissions": permissions
                }
            }))
            .expect_err("unsafe permission profile must fail closed");
        assert_eq!(error.code, expected_code);
    }

    let oversized = translator
        .translate_value(&json!({
            "id": "permission-oversized",
            "method": "item/permissions/requestApproval",
            "params": {
                "approvalId": "permission-oversized",
                "cwd": "/workspace",
                "permissions": {
                    "fileSystem": {"read": [format!("/{}", "a".repeat(MAX_APPROVAL_SUMMARY_BYTES))]},
                    "network": null
                }
            }
        }))
        .expect_err("profile that cannot be shown completely must fail closed");
    assert_eq!(oversized.code, "codex-approval-summary-too-large");

    let redacted = translator
        .translate_value(&json!({
            "id": "permission-redacted",
            "method": "item/permissions/requestApproval",
            "params": {
                "approvalId": "permission-redacted",
                "cwd": "/workspace",
                "permissions": {
                    "fileSystem": {"read": ["/tmp/sk-profile-secret"]},
                    "network": null
                }
            }
        }))
        .expect("validated profile is passed through the canonical redactor");
    let summary = &approval_output(&redacted[0]).summary;
    assert!(summary.contains("/tmp/<REDACTED>"));
    assert!(!summary.contains("sk-profile-secret"));
}

#[test]
fn approval_output_debug_redacts_request_and_raw_route_params() {
    let mut translator = CodexRuntimeTranslator::new();
    let output = translator
        .translate_value(&json!({
            "id": "secret-rpc-id",
            "method": "item/commandExecution/requestApproval",
            "params": {
                "approvalId": "secret-approval-id",
                "command": "deploy --token sk-debug-secret",
                "cwd": "/private/debug-path",
                "rawSentinel": "raw-route-secret"
            }
        }))
        .expect("modeled approval with raw route params");
    let debug = format!("{:?}", output[0]);
    for forbidden in [
        "secret-rpc-id",
        "secret-approval-id",
        "sk-debug-secret",
        "/private/debug-path",
        "raw-route-secret",
    ] {
        assert!(!debug.contains(forbidden), "debug leaked {forbidden}");
    }
    assert!(debug.contains("<redacted>"));

    let CodexRuntimeOutput::Approval { route, .. } = &output[0] else {
        panic!("expected approval output")
    };
    let route_debug = format!("{route:?}");
    assert!(route_debug.contains("item/commandExecution/requestApproval"));
    assert!(!route_debug.contains("raw-route-secret"));
}

#[test]
fn approval_route_preserves_string_and_signed_integer_rpc_ids_exactly() {
    for rpc_id in [json!("rpc-string-7"), json!(-9_i64)] {
        let mut translator = CodexRuntimeTranslator::new();
        let output = translator
            .translate_value(&json!({
                "id": rpc_id,
                "method": "item/commandExecution/requestApproval",
                "params": {"approvalId": "approval-fixture", "command": "pwd"}
            }))
            .expect("modeled approval request");
        match &output[0] {
            CodexRuntimeOutput::Approval { route, .. } => assert_eq!(route.rpc_id, rpc_id),
            other => panic!("expected approval route, got {other:?}"),
        }
    }
}

#[test]
fn unknown_frames_and_raw_items_fail_closed() {
    let mut translator = CodexRuntimeTranslator::new();
    let unknown = translator
        .translate_value(&json!({"method": "future/unmodeled", "params": {}}))
        .expect_err("unknown notification must fail closed");
    assert_eq!(unknown.code, "codex-unmodeled-frame");

    let raw = translator
        .translate_value(&json!({
            "method": "item/started",
            "params": {"item": {"type": "futureItem", "id": "vendor-raw"}}
        }))
        .expect_err("unknown item must fail closed");
    assert_eq!(raw.code, "codex-unmodeled-item");

    let protocol_error = translator
        .translate_value(&json!({"id": 7, "error": {"code": -1}}))
        .expect_err("vendor protocol error must terminate the typed turn");
    assert_eq!(protocol_error.code, "codex-protocol-error");

    let unstructured = translator
        .translate_value(&json!({"future": true}))
        .expect_err("unstructured object must not be ignored");
    assert_eq!(unstructured.code, "codex-unmodeled-frame");

    let user_input = translator
        .translate_value(&json!({
            "id": "typed-answers-required",
            "method": "item/tool/requestUserInput",
            "params": {"prompt": "choose"}
        }))
        .expect_err("typed answers request cannot be fabricated as approval");
    assert_eq!(user_input.code, "codex-unmodeled-request");

    let unmodeled_item_notification = translator
        .translate_value(&json!({
            "method": "item/futureProgress",
            "params": {
                "threadId": "fixture-thread",
                "turnId": "fixture-turn",
                "itemId": "future-item"
            }
        }))
        .expect_err("unmodeled item notifications must terminate the typed turn");
    assert_eq!(unmodeled_item_notification.code, "codex-unmodeled-item");
}

#[test]
fn official_non_authoritative_notifications_preserve_authoritative_item_completion() {
    // 威胁场景：官方 progress、approval 确认或 panel-only hook 通知若进入 unknown-frame
    // 分支，正常 turn 会在 item/completed 前被中止；它们本身不落 durable event，
    // 最终 item 快照仍是权威输出。这里锁定的是官方 schema method contract；真实 fixture
    // 尚未覆盖这些通知，不能把本测试表述成真实录制验证。
    let mut translator = CodexRuntimeTranslator::new();
    translator
        .translate_value(&json!({
            "method": "item/started",
            "params": {"item": {"type": "plan", "id": "official-plan", "text": ""}}
        }))
        .expect("official plan start");

    for method in [
        "item/commandExecution/terminalInteraction",
        "item/fileChange/outputDelta",
        "item/plan/delta",
        "item/mcpToolCall/progress",
        "item/autoApprovalReview/started",
        "item/autoApprovalReview/completed",
        "serverRequest/resolved",
        "hook/started",
        "hook/completed",
    ] {
        let partial = translator
            .translate_value(&json!({
                "method": method,
                "params": {
                    "threadId": "fixture-thread",
                    "turnId": "fixture-turn",
                    "itemId": "official-plan"
                }
            }))
            .expect("official partial notification must remain modeled");
        assert!(partial.is_empty(), "partial notification must not persist");
    }

    let completed = translator
        .translate_value(&json!({
            "method": "item/completed",
            "params": {"item": {
                "type": "plan",
                "id": "official-plan",
                "text": "authoritative final step"
            }}
        }))
        .expect("authoritative plan completion");
    let AgentItem::Plan { steps, .. } = item_output(&completed[0]).1 else {
        panic!("expected canonical plan item")
    };
    assert_eq!(steps.len(), 1);
    assert_eq!(steps[0].title, "authoritative final step");
}

#[test]
fn file_patch_is_visible_before_approval_and_terminal_status_is_preserved() {
    // 威胁场景：只显示路径、不先落 proposed diff 会让远端用户盲签；declined/failed
    // 若丢 status 又会在回放中伪装成成功应用。
    let mut translator = CodexRuntimeTranslator::new();
    let started = translator
        .translate_value(&json!({
            "method": "item/started",
            "params": {"item": {
                "type": "fileChange",
                "id": "patch-item",
                "status": "inProgress",
                "changes": []
            }}
        }))
        .expect("file change start");
    let started_key = item_output(&started[0]).0.to_owned();

    let changes = json!([{
        "path": "/workspace/src/lib.rs",
        "diff": "@@ -1 +1 @@\n-old\n+new",
        "kind": {"type": "update", "move_path": null}
    }]);
    let patch = translator
        .translate_value(&json!({
            "method": "item/fileChange/patchUpdated",
            "params": {
                "threadId": "fixture-thread",
                "turnId": "fixture-turn",
                "itemId": "patch-item",
                "changes": changes.clone()
            }
        }))
        .expect("official patch update");
    assert_eq!(item_output(&patch[0]).0, started_key);
    let AgentItem::Diff { files, meta } = item_output(&patch[0]).1 else {
        panic!("expected proposed diff")
    };
    assert_eq!(files[0].patch.as_deref(), Some("@@ -1 +1 @@\n-old\n+new"));
    assert_eq!(
        meta.vendor_extensions.get("status"),
        Some(&json!("inProgress"))
    );

    let approval = translator
        .translate_value(&json!({
            "id": "patch-approval-rpc",
            "method": "item/fileChange/requestApproval",
            "params": {
                "approvalId": "patch-approval",
                "itemId": "patch-item",
                "grantRoot": null,
                "reason": "apply reviewed patch"
            }
        }))
        .expect("ordinary file approval does not require grantRoot");
    let summary = &approval_output(&approval[0]).summary;
    assert!(summary.contains(r#"update "/workspace/src/lib.rs""#));

    let completed = translator
        .translate_value(&json!({
            "method": "item/completed",
            "params": {"item": {
                "type": "fileChange",
                "id": "patch-item",
                "status": "declined",
                "changes": changes
            }}
        }))
        .expect("declined file change is an authoritative terminal item");
    assert_eq!(item_output(&completed[0]).0, started_key);
    let AgentItem::Diff { meta, .. } = item_output(&completed[0]).1 else {
        panic!("expected terminal diff")
    };
    assert_eq!(
        meta.vendor_extensions.get("status"),
        Some(&json!("declined"))
    );
}

#[test]
fn network_only_approval_uses_validated_host_and_protocol_without_amendment_leak() {
    let mut translator = CodexRuntimeTranslator::new();
    let output = translator
        .translate_value(&json!({
            "id": "network-rpc",
            "method": "item/commandExecution/requestApproval",
            "params": {
                "approvalId": "network-approval",
                "itemId": "network-item",
                "command": null,
                "commandActions": null,
                "networkApprovalContext": {"host": "api.example.com", "protocol": "https"},
                "proposedNetworkPolicyAmendments": [{
                    "host": "future-policy-secret.example",
                    "action": "allow"
                }]
            }
        }))
        .expect("official network-only approval");
    let summary = &approval_output(&output[0]).summary;
    assert!(summary.starts_with("Allow network access"));
    assert!(summary.contains(r#"network: https "api.example.com""#));
    assert!(!summary.contains("future-policy-secret"));
}

#[test]
fn official_extended_item_types_are_typed_or_explicitly_private() {
    let mut translator = CodexRuntimeTranslator::new();
    let fixtures = [
        json!({"type":"webSearch","id":"web","query":"rust async","action":{"type":"search","queries":["rust async"]}}),
        json!({"type":"subAgentActivity","id":"sub","agentPath":"reviewer","agentThreadId":"vendor-thread-secret","kind":"started"}),
        json!({"type":"sleep","id":"sleep","durationMs":250}),
        json!({"type":"imageGeneration","id":"image","status":"failed","result":"generation failed","savedPath":null,"revisedPrompt":null}),
        json!({"type":"enteredReviewMode","id":"review-in","review":"review scope"}),
        json!({"type":"exitedReviewMode","id":"review-out","review":"review result"}),
        json!({"type":"contextCompaction","id":"compact"}),
    ];
    let mut durable = Vec::new();
    for item in fixtures {
        translator
            .translate_value(&json!({"method":"item/started","params":{"item":item.clone()}}))
            .expect("official extended item start");
        let output = translator
            .translate_value(&json!({"method":"item/completed","params":{"item":item}}))
            .expect("official extended item completion");
        durable.push(serde_json::to_string(item_output(&output[0]).1).unwrap());
    }
    assert!(durable[0].contains("rust async"));
    assert!(durable[1].contains("reviewer"));
    assert!(!durable[1].contains("vendor-thread-secret"));
    assert!(durable[3].contains("generation failed"));

    let hook = json!({
        "type":"hookPrompt",
        "id":"hook-private",
        "fragments":[]
    });
    assert!(
        translator
            .translate_value(&json!({"method":"item/started","params":{"item":hook.clone()}}))
            .expect("hook prompt start")
            .is_empty()
    );
    assert!(
        translator
            .translate_value(&json!({"method":"item/completed","params":{"item":hook}}))
            .expect("hook prompt completion")
            .is_empty()
    );
}

#[test]
fn tool_items_use_explicit_privacy_projections() {
    let mut translator = CodexRuntimeTranslator::new();
    let mcp_started = json!({
        "type":"mcpToolCall","id":"mcp","server":"fixture-server","tool":"lookup",
        "arguments":{"query":"visible"},"status":"inProgress"
    });
    translator
        .translate_value(&json!({"method":"item/started","params":{"item":mcp_started}}))
        .expect("MCP start");
    let mcp = translator
        .translate_value(&json!({
            "method":"item/completed",
            "params":{"item":{
                "type":"mcpToolCall","id":"mcp","server":"fixture-server","tool":"lookup",
                "arguments":{"query":"visible"},"status":"completed","durationMs":4,
                "result":{
                    "content":[{"type":"text","text":"visible result"}],
                    "structuredContent":{"answer":42},
                    "_meta":{"privateIdentity":"mcp-private-sentinel"}
                },
                "error":null,
                "pluginId":"private-plugin-sentinel",
                "appContext":{"resourceUri":"private-resource-sentinel"}
            }}
        }))
        .expect("MCP completion");
    let durable = serde_json::to_string(item_output(&mcp[0]).1).unwrap();
    assert!(durable.contains("visible result"));
    assert!(durable.contains("structuredContent"));
    for forbidden in [
        "mcp-private-sentinel",
        "private-plugin-sentinel",
        "private-resource-sentinel",
        "_meta",
    ] {
        assert!(!durable.contains(forbidden));
    }

    let collab = json!({
        "type":"collabAgentToolCall","id":"collab","tool":"spawnAgent","status":"completed",
        "senderThreadId":"sender-vendor-secret","receiverThreadIds":["receiver-vendor-secret"],
        "agentsStates":{"receiver-vendor-secret":{"status":"completed","message":"private state"}},
        "prompt":"review visible scope","model":null,"reasoningEffort":"medium"
    });
    let mut collab_started = collab.clone();
    collab_started["status"] = json!("inProgress");
    translator
        .translate_value(&json!({"method":"item/started","params":{"item":collab_started}}))
        .expect("collaboration start");
    let collab = translator
        .translate_value(&json!({"method":"item/completed","params":{"item":collab}}))
        .expect("collaboration completion");
    let durable = serde_json::to_string(item_output(&collab[0]).1).unwrap();
    assert!(durable.contains("review visible scope"));
    assert!(!durable.contains("sender-vendor-secret"));
    assert!(!durable.contains("receiver-vendor-secret"));
    assert!(!durable.contains("private state"));
}

#[test]
fn command_output_delta_is_validated_but_not_retained() {
    let mut translator = CodexRuntimeTranslator::with_retained_byte_limit(64);
    translator
        .translate_value(&json!({
            "method":"item/started",
            "params":{"item":{"type":"commandExecution","id":"shell","command":"yes"}}
        }))
        .expect("shell start");
    for _ in 0..100 {
        translator
            .translate_value(&json!({
                "method":"item/commandExecution/outputDelta",
                "params":{"itemId":"shell","delta":"x".repeat(4096)}
            }))
            .expect("discarded output must not consume retained-state budget");
    }
    translator
        .translate_value(&json!({
            "method":"item/completed",
            "params":{"item":{
                "type":"commandExecution","id":"shell","command":"yes","status":"completed"
            }}
        }))
        .expect("shell completes after large output");
}

#[test]
fn recoverable_diagnostics_are_bounded_on_utf8_boundaries() {
    let mut translator = CodexRuntimeTranslator::new();
    let warning = translator
        .translate_value(&json!({
            "method":"warning",
            "params":{"message":"界".repeat(3000)}
        }))
        .expect("recoverable warning");
    let CodexRuntimeOutput::Diagnostic { detail, .. } = &warning[0] else {
        panic!("expected non-durable diagnostic")
    };
    assert!(detail.len() <= 4096);
    assert!(detail.ends_with('…'));

    let retry = translator
        .translate_value(&json!({
            "method":"error",
            "params":{
                "threadId":"fixture-thread","turnId":"fixture-turn","willRetry":true,
                "error":{"message":"temporary"}
            }
        }))
        .expect("retryable turn error remains non-terminal");
    assert!(matches!(
        retry.as_slice(),
        [CodexRuntimeOutput::Diagnostic { .. }]
    ));

    let fatal = translator
        .translate_value(&json!({
            "method":"error",
            "params":{
                "threadId":"fixture-thread","turnId":"fixture-turn","willRetry":false,
                "error":{"message":"fatal"}
            }
        }))
        .expect_err("non-retryable turn error must fail closed");
    assert_eq!(fatal.code, "codex-turn-error");
}

#[test]
fn duplicate_and_missing_item_identities_fail_closed() {
    let mut translator = CodexRuntimeTranslator::new();
    let started = json!({
        "method": "item/started",
        "params": {"item": {"type": "agentMessage", "id": "same-item", "text": ""}}
    });
    translator
        .translate_value(&started)
        .expect("first item start is modeled");
    let duplicate = translator
        .translate_value(&started)
        .expect_err("duplicate item start must fail closed");
    assert_eq!(duplicate.code, "codex-item-duplicate");

    let missing = translator
        .translate_value(&json!({
            "method": "item/completed",
            "params": {"item": {"type": "agentMessage", "text": "done"}}
        }))
        .expect_err("completed item without identity must fail closed");
    assert_eq!(missing.code, "codex-item-invalid");
}

#[test]
fn turn_completion_rejects_in_flight_item_without_losing_state() {
    let mut translator = CodexRuntimeTranslator::new();
    translator
        .translate_value(&json!({
            "method": "item/started",
            "params": {"item": {"type": "agentMessage", "id": "open-item", "text": ""}}
        }))
        .expect("modeled item start");

    let incomplete = translator
        .translate_value(&json!({
            "method": "turn/completed",
            "params": {
                "durationMs": 7,
                "turn": {"id": "turn-1", "status": "completed", "error": null}
            }
        }))
        .expect_err("terminal with an open item must fail closed");
    assert_eq!(incomplete.code, "codex-turn-incomplete");

    translator
        .translate_value(&json!({
            "method": "item/completed",
            "params": {"item": {
                "type": "agentMessage",
                "id": "open-item",
                "text": "closed"
            }}
        }))
        .expect("rejected terminal must preserve in-flight state");
    let terminal = translator
        .translate_value(&json!({
            "method": "turn/completed",
            "params": {
                "durationMs": 7,
                "turn": {"id": "turn-1", "status": "completed", "error": null}
            }
        }))
        .expect("terminal after item completion is modeled");
    assert!(matches!(
        terminal.as_slice(),
        [CodexRuntimeOutput::TurnComplete(summary)] if summary.elapsed_ms == 7
    ));
}

#[test]
fn turn_completion_requires_authoritative_success_status_without_an_error() {
    // 威胁场景：vendor 以 turn/completed 通知 failed/interrupted turn；若只按方法名
    // 判断 terminal，daemon 会把失败执行永久写成 Completed。
    for status in ["failed", "interrupted", "inProgress"] {
        let error = CodexRuntimeTranslator::new()
            .translate_value(&json!({
                "method": "turn/completed",
                "params": {"turn": {"status": status, "error": null}}
            }))
            .expect_err("non-success terminal must fail closed");
        assert_eq!(error.code, "codex-turn-not-completed");
    }

    let error = CodexRuntimeTranslator::new()
        .translate_value(&json!({
            "method": "turn/completed",
            "params": {
                "turn": {
                    "status": "completed",
                    "error": {"message": "vendor failure"}
                }
            }
        }))
        .expect_err("completed status with an error is not a successful terminal");
    assert_eq!(error.code, "codex-turn-not-completed");

    let missing = CodexRuntimeTranslator::new()
        .translate_value(&json!({"method": "turn/completed", "params": {}}))
        .expect_err("terminal without authoritative turn object must fail closed");
    assert_eq!(missing.code, "codex-turn-terminal-invalid");

    let omitted_optional_error = CodexRuntimeTranslator::new()
        .translate_value(&json!({
            "method": "turn/completed",
            "params": {"turn": {"id": "turn-1", "status": "completed"}}
        }))
        .expect("official Turn.error is optional for successful terminals");
    assert!(matches!(
        omitted_optional_error.as_slice(),
        [CodexRuntimeOutput::TurnComplete(_)]
    ));
}

#[test]
fn official_token_usage_update_is_bound_to_the_completed_turn() {
    let mut translator = CodexRuntimeTranslator::new();
    let update = json!({
        "method": "thread/tokenUsage/updated",
        "params": {
            "threadId": "thread-1",
            "turnId": "turn-1",
            "tokenUsage": {
                "last": {
                    "cachedInputTokens": 2,
                    "inputTokens": 11,
                    "outputTokens": 7,
                    "reasoningOutputTokens": 3,
                    "totalTokens": 18
                },
                "total": {
                    "cachedInputTokens": 2,
                    "inputTokens": 11,
                    "outputTokens": 7,
                    "reasoningOutputTokens": 3,
                    "totalTokens": 18
                }
            }
        }
    });
    assert!(
        translator
            .translate_value(&update)
            .expect("official token update")
            .is_empty()
    );

    let terminal = translator
        .translate_value(&json!({
            "method": "turn/completed",
            "params": {
                "turn": {
                    "id": "turn-1",
                    "status": "completed",
                    "error": null,
                    "durationMs": 9
                }
            }
        }))
        .expect("matching terminal consumes counters");
    assert!(matches!(
        terminal.as_slice(),
        [CodexRuntimeOutput::TurnComplete(TurnSummary {
            total_input_tokens: Some(11),
            total_output_tokens: Some(7),
            elapsed_ms: 9,
        })]
    ));

    let mut mismatch = CodexRuntimeTranslator::new();
    mismatch.translate_value(&update).expect("first update");
    let error = mismatch
        .translate_value(&json!({
            "method": "turn/completed",
            "params": {
                "turn": {"id": "turn-2", "status": "completed", "error": null}
            }
        }))
        .expect_err("usage cannot cross a turn identity");
    assert_eq!(error.code, "codex-token-usage-turn-mismatch");
}

#[test]
fn retained_state_limit_covers_open_text_and_completed_vendor_ids() {
    // 威胁场景：vendor 在一个 turn 中持续发送超长 item id/delta；若 translator
    // 只依赖稍后的 Store 上限，跨帧 HashMap/HashSet 会先把 daemon 内存耗尽。
    let mut translator = CodexRuntimeTranslator::with_retained_byte_limit(12);
    translator
        .translate_value(&json!({
            "method": "item/started",
            "params": {"item": {"type": "agentMessage", "id": "open", "text": "ab"}}
        }))
        .expect("six retained bytes fit");
    translator
        .translate_value(&json!({
            "method": "item/agentMessage/delta",
            "params": {"itemId": "open", "delta": "123456"}
        }))
        .expect("exact retained-byte limit fits");
    let overflow = translator
        .translate_value(&json!({
            "method": "item/agentMessage/delta",
            "params": {"itemId": "open", "delta": "x"}
        }))
        .expect_err("one byte past retained limit must fail closed");
    assert_eq!(overflow.code, "codex-retained-state-limit");

    translator
        .translate_value(&json!({
            "method": "item/completed",
            "params": {"item": {"type": "agentMessage", "id": "open", "text": "done"}}
        }))
        .expect("rejected delta must preserve the open item for exact completion");

    let completed_id_pressure = translator
        .translate_value(&json!({
            "method": "item/started",
            "params": {"item": {"type": "agentMessage", "id": "123456789", "text": ""}}
        }))
        .expect_err("completed vendor ids remain within the same retained-state budget");
    assert_eq!(completed_id_pressure.code, "codex-retained-state-limit");
}

#[test]
fn item_completion_and_deltas_without_start_fail_closed() {
    let mut translator = CodexRuntimeTranslator::new();
    let completion = translator
        .translate_value(&json!({
            "method": "item/completed",
            "params": {"item": {
                "type": "agentMessage",
                "id": "orphan-completion",
                "text": "done"
            }}
        }))
        .expect_err("completion without item start must fail closed");
    assert_eq!(completion.code, "codex-item-completion-orphan");

    let message_delta = translator
        .translate_value(&json!({
            "method": "item/agentMessage/delta",
            "params": {"itemId": "orphan-message", "delta": "partial"}
        }))
        .expect_err("message delta without item start must fail closed");
    assert_eq!(message_delta.code, "codex-item-delta-orphan");

    let command_delta = translator
        .translate_value(&json!({
            "method": "item/commandExecution/outputDelta",
            "params": {"itemId": "orphan-command", "delta": "partial"}
        }))
        .expect_err("command delta without item start must fail closed");
    assert_eq!(command_delta.code, "codex-item-delta-orphan");
}

fn item_output(output: &CodexRuntimeOutput) -> (&str, &AgentItem) {
    match output {
        CodexRuntimeOutput::Event(AdapterEvent::Item { key, item }) => (key.as_str(), item),
        other => panic!("expected typed item output, got {other:?}"),
    }
}

fn approval_output(output: &CodexRuntimeOutput) -> &ActionRequest {
    match output {
        CodexRuntimeOutput::Approval { request, .. } => request,
        other => panic!("expected typed approval output, got {other:?}"),
    }
}

fn assert_shell_status(status: &ShellStatus, expected: &str) {
    assert!(match expected {
        "completed" => matches!(status, ShellStatus::Completed),
        "failed" => matches!(status, ShellStatus::Failed),
        "canceled" => matches!(status, ShellStatus::Canceled),
        other => panic!("unmodeled expected shell status: {other}"),
    });
}

fn legacy_recorded_projection(lines: &str) -> Vec<u8> {
    let mut translator = CodexTranslator::new(
        SessionId("runtime-production-byte-bridge".to_owned()),
        Some(ThreadId("019f0000-0000-7000-8000-000000000001".to_owned())),
    );
    let mut items = Vec::new();
    let mut terminal = None;
    for line in lines.lines() {
        for event in translator.translate_line(line) {
            match event {
                ServerEvent::AgentItem { item, .. } => items.push(item),
                ServerEvent::TurnComplete { summary, .. } => terminal = Some(summary),
                _ => {}
            }
        }
    }
    canonical_projection(&items, &terminal.expect("legacy fixture terminal"))
}

fn canonical_projection(items: &[AgentItem], terminal: &TurnSummary) -> Vec<u8> {
    serde_json::to_vec(&(items, terminal)).expect("canonical fixture projection")
}
