//! Gate: `AGENTDECK_E2E=1` — requires real `codex` binary in PATH and `codex login`.
//!
//! Run with:
//!   cargo build --locked -p agentdeckd --bin agentdeckd
//!   AGENTDECK_DAEMON_BIN="$PWD/target/debug/agentdeckd" AGENTDECK_E2E=1 \
//!     cargo test -p agentdeck-cli --test e2e_codex
//!
//! All tests double-gated: skip cleanly when `AGENTDECK_E2E` is unset OR
//! when the `codex` binary is absent.

mod support;

use support::{
    ADMIN_TIMEOUT, HISTORY_TIMEOUT, SESSION_TIMEOUT, real_e2e_enabled, run_cli, vendor_available,
};

fn codex_available() -> bool {
    vendor_available("codex")
}

// ── Basic plumbing ─────────────────────────────────────────────────────────────

#[test]
fn e2e_codex_ping() {
    if !real_e2e_enabled() {
        eprintln!("SKIP: set AGENTDECK_E2E=1 to run Codex E2E tests");
        return;
    }
    if !codex_available() {
        eprintln!("SKIP: codex not in PATH");
        return;
    }
    let out = run_cli(&["ping"], ADMIN_TIMEOUT);
    assert!(
        out.status.success(),
        "agentdeck ping failed\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let json: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("ping output must be valid JSON");
    assert_eq!(json["ok"], true, "ping reply must contain ok=true");
}

#[test]
fn e2e_codex_selfcheck() {
    if !real_e2e_enabled() {
        eprintln!("SKIP: set AGENTDECK_E2E=1");
        return;
    }
    if !codex_available() {
        eprintln!("SKIP: codex not in PATH");
        return;
    }
    let out = run_cli(&["selfcheck"], ADMIN_TIMEOUT);
    assert!(
        out.status.success(),
        "agentdeck selfcheck failed\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let json: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("selfcheck output must be valid JSON");
    assert_eq!(json["ok"], true, "selfcheck must return ok=true");
}

// ── Agent subcommands ─────────────────────────────────────────────────────────

#[test]
fn e2e_codex_agent_list_contains_codex() {
    if !real_e2e_enabled() {
        eprintln!("SKIP: set AGENTDECK_E2E=1");
        return;
    }
    if !codex_available() {
        eprintln!("SKIP: codex not in PATH");
        return;
    }
    let out = run_cli(&["agent", "list"], ADMIN_TIMEOUT);
    assert!(
        out.status.success(),
        "agentdeck agent list failed\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let json: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("agent list must be valid JSON");
    let agents: Vec<&str> = json["agents"]
        .as_array()
        .expect("agents must be an array")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert!(
        agents.contains(&"codex"),
        "expected 'codex' in agent list, got: {agents:?}"
    );
}

#[test]
fn e2e_codex_agent_capabilities_has_sandbox_mode() {
    if !real_e2e_enabled() {
        eprintln!("SKIP: set AGENTDECK_E2E=1");
        return;
    }
    if !codex_available() {
        eprintln!("SKIP: codex not in PATH");
        return;
    }
    let out = run_cli(
        &["agent", "capabilities", "--agent", "codex"],
        ADMIN_TIMEOUT,
    );
    assert!(
        out.status.success(),
        "agentdeck agent capabilities --agent codex failed\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let json: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("capabilities output must be valid JSON");
    let features: Vec<&str> = json["features"]
        .as_array()
        .expect("features must be an array")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert!(
        !features.is_empty(),
        "Codex capabilities must contain at least one feature"
    );
    assert!(
        features.contains(&"codexSandboxMode"),
        "Codex capabilities must include 'codexSandboxMode', got: {features:?}"
    );
    assert_eq!(
        json["agentKind"], "codex",
        "agentKind in capabilities reply must be 'codex'"
    );
}

// ── Session run / continue ─────────────────────────────────────────────────────

/// Run a Codex session and collect all JSONL event lines until TurnComplete.
/// Returns `(thread_id, events)`. Panics on hard timeout or error event.
fn run_codex_session(prompt: &str) -> (String, Vec<serde_json::Value>) {
    let cwd = std::env::current_dir()
        .unwrap()
        .to_string_lossy()
        .to_string();

    let output = run_cli(
        &[
            "session",
            "run",
            "--agent",
            "codex",
            "--cwd",
            &cwd,
            "--prompt",
            prompt,
            "--sandbox",
            "read-only",
            "--approval",
            "never",
            "--reasoning-effort",
            "minimal",
        ],
        SESSION_TIMEOUT,
    );

    let mut events: Vec<serde_json::Value> = Vec::new();
    let mut thread_id = String::new();

    for line in String::from_utf8_lossy(&output.stdout).lines() {
        if line.trim().is_empty() {
            continue;
        }
        let Ok(val) = serde_json::from_str::<serde_json::Value>(&line) else {
            continue;
        };
        // Capture threadId from sessionStarted or any event that has it
        if thread_id.is_empty() {
            if let Some(tid) = val.get("threadId").and_then(|v| v.as_str()) {
                thread_id = tid.to_string();
            }
        }
        let is_complete = val.get("type").and_then(|t| t.as_str()) == Some("turnComplete");
        let is_error = val.get("type").and_then(|t| t.as_str()) == Some("error");
        events.push(val.clone());
        if is_error {
            panic!("codex session produced error event: {val}");
        }
        if is_complete {
            break;
        }
    }

    assert!(
        output.status.success(),
        "agentdeck session run (codex) exited non-zero: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !thread_id.is_empty(),
        "no threadId found in session events: {events:?}"
    );

    // Assert N7: sessionCapabilities must appear before first agentItem
    let cap_pos = events
        .iter()
        .position(|v| v.get("type").and_then(|t| t.as_str()) == Some("sessionCapabilities"));
    let item_pos = events
        .iter()
        .position(|v| v.get("type").and_then(|t| t.as_str()) == Some("agentItem"));
    if let (Some(cp), Some(ip)) = (cap_pos, item_pos) {
        assert!(
            cp < ip,
            "N7 violation: sessionCapabilities (pos {cp}) must come before first agentItem (pos {ip})"
        );
    }

    // Assert turnComplete is present
    let has_complete = events
        .iter()
        .any(|v| v.get("type").and_then(|t| t.as_str()) == Some("turnComplete"));
    assert!(
        has_complete,
        "session must end with turnComplete; events: {events:?}"
    );

    (thread_id, events)
}

#[test]
fn e2e_codex_session_run_to_completion() {
    if !real_e2e_enabled() {
        eprintln!("SKIP: set AGENTDECK_E2E=1");
        return;
    }
    if !codex_available() {
        eprintln!("SKIP: codex not in PATH");
        return;
    }

    let (thread_id, events) = run_codex_session("say hi");

    // sessionStarted agentKind must be codex
    let started = events
        .iter()
        .find(|v| v.get("type").and_then(|t| t.as_str()) == Some("sessionStarted"))
        .expect("sessionStarted event must be present");
    assert_eq!(
        started["agentKind"], "codex",
        "sessionStarted agentKind must be 'codex'"
    );

    assert!(
        !thread_id.is_empty(),
        "threadId must be non-empty after run"
    );
    eprintln!(
        "codex session run OK, threadId={thread_id}, {} events",
        events.len()
    );
}

#[test]
fn e2e_codex_session_continue_to_completion() {
    if !real_e2e_enabled() {
        eprintln!("SKIP: set AGENTDECK_E2E=1");
        return;
    }
    if !codex_available() {
        eprintln!("SKIP: codex not in PATH");
        return;
    }

    // First run to get a thread_id
    let (thread_id, _) = run_codex_session("say hi");
    eprintln!("captured thread_id={thread_id} for continue test");

    // Now continue that session. C3 fix: --cwd is now required so the
    // adapter resumes from the same directory as the original session
    // (avoids `std::env::current_dir()` fallback).
    let cwd = std::env::current_dir()
        .unwrap()
        .to_string_lossy()
        .to_string();
    let out = run_cli(
        &[
            "session",
            "continue",
            "--thread-id",
            &thread_id,
            "--agent",
            "codex",
            "--cwd",
            &cwd,
            "--prompt",
            "ok",
        ],
        SESSION_TIMEOUT,
    );

    assert!(
        out.status.success(),
        "agentdeck session continue (codex) failed\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout_str = String::from_utf8_lossy(&out.stdout);
    let has_complete = stdout_str.lines().any(|l| {
        serde_json::from_str::<serde_json::Value>(l)
            .ok()
            .and_then(|v| {
                v.get("type")
                    .and_then(|t| t.as_str())
                    .map(|s| s == "turnComplete")
            })
            .unwrap_or(false)
    });
    assert!(
        has_complete,
        "session continue must produce turnComplete event\nstdout: {stdout_str}"
    );
    eprintln!("codex session continue OK (thread_id={thread_id})");
}

// ── History ────────────────────────────────────────────────────────────────────

#[test]
fn e2e_codex_history_list_succeeds() {
    if !real_e2e_enabled() {
        eprintln!("SKIP: set AGENTDECK_E2E=1");
        return;
    }
    if !codex_available() {
        eprintln!("SKIP: codex not in PATH");
        return;
    }

    let out = run_cli(&["history", "list", "--agent", "codex"], HISTORY_TIMEOUT);
    assert!(
        out.status.success(),
        "agentdeck history list --agent codex failed\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    // Must return valid JSON — either List (may be empty) or an error envelope
    let json: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("history list output must be valid JSON");
    // kind must be "list"
    assert_eq!(
        json["kind"], "list",
        "history list response must have kind=list; got: {json}"
    );
    eprintln!(
        "codex history list OK, {} items",
        json["value"].as_array().map(|a| a.len()).unwrap_or(0)
    );
}
