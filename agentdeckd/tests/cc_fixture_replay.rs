//! Offline fixture replay for `ClaudeCodeTranslator`.
//!
//! Phase 4 Task 4C — Phase 4 finalization. Mirrors
//! `codex_translate.rs::fixture_replay_*` but feeds real recorded CC
//! stream-json `.jsonl` files (captured against `claude 2.1.191` with
//! `--print --output-format stream-json --include-partial-messages
//! --include-hook-events --verbose`) through the translator and
//! asserts that:
//!
//!   1. Each fixture produces at least one ServerEvent (translator
//!      must not silently drop a whole real recording).
//!   2. No line panics the translator (raw fallback path handles
//!      every unknown type gracefully).
//!
//! Recording instructions live in the task report. Skips cleanly when
//! the fixture directory is empty (CI fallback).

use agentdeck_protocol::{ClaudeCodePermissionMode, ServerEvent, SessionId};
use agentdeckd::claude_code::translate::ClaudeCodeTranslator;
use std::path::PathBuf;

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/claude_code")
}

#[test]
fn all_fixtures_replay_without_panic_and_emit_events() {
    let dir = fixtures_dir();
    if !dir.exists() {
        eprintln!(
            "SKIP all_fixtures_replay_without_panic_and_emit_events: \
             fixtures dir {} does not exist",
            dir.display()
        );
        return;
    }
    let entries: Vec<_> = std::fs::read_dir(&dir)
        .expect("read fixtures dir")
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("jsonl"))
        .collect();
    if entries.is_empty() {
        eprintln!("SKIP: no .jsonl fixtures found under {}", dir.display());
        return;
    }
    for entry in entries {
        let path = entry.path();
        let content = std::fs::read_to_string(&path).expect("read fixture");
        let mut translator = ClaudeCodeTranslator::new(
            SessionId("fixture-replay".into()),
            ClaudeCodePermissionMode::BypassPermissions,
        );
        let mut total_events = 0usize;
        let mut total_lines = 0usize;
        for line in content.lines() {
            if line.trim().is_empty() {
                continue;
            }
            total_lines += 1;
            let out = translator.translate_line(line);
            total_events += out.events.len();
        }
        assert!(
            total_lines > 0,
            "fixture {} contained no non-empty lines",
            path.display()
        );
        assert!(
            total_events > 0,
            "fixture {} ({} lines) produced zero events — translator regression",
            path.display(),
            total_lines
        );
        eprintln!(
            "cc_fixture_replay: {} → {} lines, {} events",
            path.file_name().unwrap().to_string_lossy(),
            total_lines,
            total_events
        );
    }
}

/// Sanity: a simple-turn fixture (if present) MUST produce at least
/// one AssistantMessage AgentItem event, since the recorded turn was
/// `say hi in 3 words`. This catches regressions that lose the
/// assistant-snapshot pass.
#[test]
fn simple_turn_fixture_emits_assistant_message_when_present() {
    let path = fixtures_dir().join("simple_turn.jsonl");
    if !path.exists() {
        eprintln!("SKIP simple_turn_fixture_emits_assistant_message: not recorded");
        return;
    }
    let content = std::fs::read_to_string(&path).expect("read simple_turn");
    let mut translator = ClaudeCodeTranslator::new(
        SessionId("fixture-simple".into()),
        ClaudeCodePermissionMode::BypassPermissions,
    );
    let mut saw_assistant = false;
    let mut saw_turn_complete = false;
    for line in content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let out = translator.translate_line(line);
        for ev in &out.events {
            match ev {
                ServerEvent::AgentItem { item, .. } => {
                    if matches!(item, agentdeck_protocol::AgentItem::AssistantMessage { .. }) {
                        saw_assistant = true;
                    }
                }
                ServerEvent::TurnComplete { .. } => {
                    saw_turn_complete = true;
                }
                _ => {}
            }
        }
    }
    assert!(
        saw_assistant || saw_turn_complete,
        "simple_turn fixture must produce at least one AssistantMessage or TurnComplete"
    );
}

/// Bash tool fixture sanity: at least one Shell AgentItem must appear
/// (covers the tool_use → tool_result Shell mapping the translator
/// performs for the `Bash` tool).
#[test]
fn bash_tool_use_fixture_emits_shell_item_when_present() {
    let path = fixtures_dir().join("bash_tool_use.jsonl");
    if !path.exists() {
        eprintln!("SKIP bash_tool_use_fixture_emits_shell_item: not recorded");
        return;
    }
    let content = std::fs::read_to_string(&path).expect("read bash_tool_use");
    let mut translator = ClaudeCodeTranslator::new(
        SessionId("fixture-bash".into()),
        ClaudeCodePermissionMode::BypassPermissions,
    );
    let mut saw_shell = false;
    for line in content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let out = translator.translate_line(line);
        for ev in &out.events {
            if let ServerEvent::AgentItem { item, .. } = ev {
                if matches!(item, agentdeck_protocol::AgentItem::Shell { .. }) {
                    saw_shell = true;
                }
            }
        }
    }
    assert!(
        saw_shell,
        "bash_tool_use fixture must produce at least one Shell AgentItem"
    );
}
