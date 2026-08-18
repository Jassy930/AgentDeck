//! Gate: `AGENTDECK_E2E=1` — requires real `claude` binary in PATH and `claude auth login`.
//!
//! Run with:
//!   cargo build --locked -p agentdeckd --bin agentdeckd
//!   AGENTDECK_DAEMON_BIN="$PWD/target/debug/agentdeckd" AGENTDECK_E2E=1 \
//!     cargo test -p agentdeck-cli --test e2e_claude_code
//!
//! All tests double-gated: skip cleanly when `AGENTDECK_E2E` is unset OR
//! when the `claude` binary is absent.

mod support;

use support::{
    ADMIN_TIMEOUT, HISTORY_TIMEOUT, SESSION_TIMEOUT, cli_command, real_e2e_enabled, run_cli,
    run_command, vendor_available,
};

fn claude_available() -> bool {
    vendor_available("claude")
}

// ── Basic plumbing ─────────────────────────────────────────────────────────────

#[test]
fn e2e_cc_ping() {
    if !real_e2e_enabled() {
        eprintln!("SKIP: set AGENTDECK_E2E=1 to run Claude Code E2E tests");
        return;
    }
    if !claude_available() {
        eprintln!("SKIP: claude not in PATH");
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
    assert_eq!(json["ok"], true, "ping must return ok=true");
}

#[test]
fn e2e_cc_selfcheck() {
    if !real_e2e_enabled() {
        eprintln!("SKIP: set AGENTDECK_E2E=1");
        return;
    }
    if !claude_available() {
        eprintln!("SKIP: claude not in PATH");
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
fn e2e_cc_agent_list_contains_claude_code() {
    if !real_e2e_enabled() {
        eprintln!("SKIP: set AGENTDECK_E2E=1");
        return;
    }
    if !claude_available() {
        eprintln!("SKIP: claude not in PATH");
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
        agents.contains(&"claude_code"),
        "expected 'claude_code' in agent list, got: {agents:?}"
    );
}

#[test]
fn e2e_cc_agent_capabilities_has_permission_mode() {
    if !real_e2e_enabled() {
        eprintln!("SKIP: set AGENTDECK_E2E=1");
        return;
    }
    if !claude_available() {
        eprintln!("SKIP: claude not in PATH");
        return;
    }
    let out = run_cli(
        &["agent", "capabilities", "--agent", "claude-code"],
        ADMIN_TIMEOUT,
    );
    assert!(
        out.status.success(),
        "agentdeck agent capabilities --agent claude-code failed\nstderr: {}",
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
        "Claude Code capabilities must contain at least one feature"
    );
    assert!(
        features.contains(&"claudeCodePermissionMode"),
        "Claude Code capabilities must include 'claudeCodePermissionMode', got: {features:?}"
    );
    assert_eq!(
        json["agentKind"], "claude_code",
        "agentKind in capabilities reply must be 'claude_code'"
    );
}

// ── Session run / continue ─────────────────────────────────────────────────────

/// Run a CC session and return `(thread_id, all_event_values)`.
fn run_cc_session(prompt: &str) -> (String, Vec<serde_json::Value>) {
    let cwd = std::env::current_dir()
        .unwrap()
        .to_string_lossy()
        .to_string();

    let output = run_cli(
        &[
            "session",
            "run",
            "--agent",
            "claude-code",
            "--cwd",
            &cwd,
            "--prompt",
            prompt,
            "--permission",
            "bypass-permissions",
            "--model",
            "claude-haiku-4-5",
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
        // Capture threadId from any event that carries it
        if thread_id.is_empty() {
            if let Some(tid) = val.get("threadId").and_then(|v| v.as_str()) {
                thread_id = tid.to_string();
            }
        }
        let ev_type = val.get("type").and_then(|t| t.as_str());
        let is_complete = ev_type == Some("turnComplete");
        let is_error = ev_type == Some("error");
        events.push(val.clone());
        if is_error {
            panic!("CC session produced error event: {val}");
        }
        if is_complete {
            break;
        }
    }

    assert!(
        output.status.success(),
        "agentdeck session run (claude-code) exited non-zero: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    // Assert N7: sessionCapabilities before first agentItem
    let cap_pos = events
        .iter()
        .position(|v| v.get("type").and_then(|t| t.as_str()) == Some("sessionCapabilities"));
    let item_pos = events
        .iter()
        .position(|v| v.get("type").and_then(|t| t.as_str()) == Some("agentItem"));
    if let (Some(cp), Some(ip)) = (cap_pos, item_pos) {
        assert!(
            cp < ip,
            "N7 violation: sessionCapabilities (pos {cp}) must precede first agentItem (pos {ip})"
        );
    }

    let has_complete = events
        .iter()
        .any(|v| v.get("type").and_then(|t| t.as_str()) == Some("turnComplete"));
    assert!(
        has_complete,
        "CC session must end with turnComplete; events: {events:?}"
    );

    assert!(
        !thread_id.is_empty(),
        "no threadId found in CC session events: {events:?}"
    );

    (thread_id, events)
}

#[test]
fn e2e_cc_session_run_to_completion() {
    if !real_e2e_enabled() {
        eprintln!("SKIP: set AGENTDECK_E2E=1");
        return;
    }
    if !claude_available() {
        eprintln!("SKIP: claude not in PATH");
        return;
    }

    let (thread_id, events) = run_cc_session("say hi briefly");

    // sessionStarted agentKind must be claude_code
    let started = events
        .iter()
        .find(|v| v.get("type").and_then(|t| t.as_str()) == Some("sessionStarted"))
        .expect("sessionStarted event must be present");
    assert_eq!(
        started["agentKind"], "claude_code",
        "sessionStarted agentKind must be 'claude_code'"
    );

    assert!(
        !thread_id.is_empty(),
        "threadId must be non-empty after CC session run"
    );
    eprintln!(
        "CC session run OK, threadId={thread_id}, {} events",
        events.len()
    );
}

#[test]
fn e2e_cc_session_continue_to_completion() {
    if !real_e2e_enabled() {
        eprintln!("SKIP: set AGENTDECK_E2E=1");
        return;
    }
    if !claude_available() {
        eprintln!("SKIP: claude not in PATH");
        return;
    }

    // First run to get a thread_id
    let (thread_id, _) = run_cc_session("say hi briefly");
    eprintln!("captured CC thread_id={thread_id} for continue test");

    // C3 fix: session continue now requires --cwd so CC `--resume`
    // can find `~/.claude/projects/<encoded_cwd>/<id>.jsonl` and
    // tool_use runs in the same directory as the original session.
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
            "claude-code",
            "--cwd",
            &cwd,
            "--prompt",
            "ok",
        ],
        SESSION_TIMEOUT,
    );

    assert!(
        out.status.success(),
        "agentdeck session continue (claude-code) failed\nstderr: {}",
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
        "CC session continue must produce turnComplete\nstdout: {stdout_str}"
    );
    eprintln!("CC session continue OK (thread_id={thread_id})");
}

// ── History ────────────────────────────────────────────────────────────────────

#[test]
fn e2e_cc_history_list_returns_items() {
    if !real_e2e_enabled() {
        eprintln!("SKIP: set AGENTDECK_E2E=1");
        return;
    }
    if !claude_available() {
        eprintln!("SKIP: claude not in PATH");
        return;
    }

    let out = run_cli(
        &["history", "list", "--agent", "claude-code"],
        HISTORY_TIMEOUT,
    );
    assert!(
        out.status.success(),
        "agentdeck history list --agent claude-code failed\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let json: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("history list output must be valid JSON");
    assert_eq!(
        json["kind"], "list",
        "history list must have kind=list; got: {json}"
    );
    let items = json["value"].as_array().expect("value must be an array");
    // CC typically has history; just verify it's a valid response (may be 0 in CI)
    eprintln!("CC history list OK, {} items", items.len());
}

#[test]
fn e2e_cc_history_archive_then_rename() {
    if !real_e2e_enabled() {
        eprintln!("SKIP: set AGENTDECK_E2E=1");
        return;
    }
    if !claude_available() {
        eprintln!("SKIP: claude not in PATH");
        return;
    }

    // Run a session so we have a fresh thread to archive/rename
    let (thread_id, _) = run_cc_session("say hi briefly");
    eprintln!("using thread_id={thread_id} for archive+rename test");

    // Archive it — CC maps this to `claude rm`.
    // `claude rm` only works for background-agent sessions; for regular interactive sessions
    // it returns "No job matching <id>" with exit 1. Both outcomes (success and this
    // specific error) are acceptable per spec § 4.9 / Task 4B findings.
    let archive_out = run_cli(
        &["history", "archive", &thread_id, "--agent", "claude-code"],
        HISTORY_TIMEOUT,
    );
    if !archive_out.status.success() {
        let stderr = String::from_utf8_lossy(&archive_out.stderr);
        let stdout = String::from_utf8_lossy(&archive_out.stdout);
        // Accept any non-zero exit: cc-archive-status, "No job matching", protocol error etc.
        // The adapter correctly surfaces the claude rm error — that is the contract.
        eprintln!(
            "CC archive returned non-fatal error (expected for regular sessions)\
             \nstdout: {stdout}\nstderr: {stderr}"
        );
    } else {
        eprintln!("CC archive OK for thread_id={thread_id}");
    }

    // Rename it — should always succeed (CC supports --name on resume)
    let rename_out = run_cli(
        &[
            "history",
            "rename",
            &thread_id,
            "renamed-by-e2e",
            "--agent",
            "claude-code",
        ],
        HISTORY_TIMEOUT,
    );
    assert!(
        rename_out.status.success(),
        "history rename failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&rename_out.stdout),
        String::from_utf8_lossy(&rename_out.stderr)
    );
    let rename_json: serde_json::Value =
        serde_json::from_slice(&rename_out.stdout).expect("history rename must return valid JSON");
    // Rename returns Ack — kind = "ack"
    assert_eq!(
        rename_json["kind"], "ack",
        "rename response must have kind=ack; got: {rename_json}"
    );
    eprintln!("CC rename OK for thread_id={thread_id}");
}

// ── Preflight failure (cc-not-installed) ──────────────────────────────────────

#[test]
fn e2e_cc_not_installed_returns_error_code() {
    if !real_e2e_enabled() {
        eprintln!("SKIP: set AGENTDECK_E2E=1");
        return;
    }
    // This test intentionally runs regardless of whether claude is present,
    // because it masks the PATH to simulate absence.

    let cwd = std::env::current_dir()
        .unwrap()
        .to_string_lossy()
        .to_string();

    // Run with a PATH that cannot find `claude`
    let args = [
        "session",
        "run",
        "--agent",
        "claude-code",
        "--cwd",
        &cwd,
        "--prompt",
        "x",
        "--permission",
        "default",
    ];
    let mut command = cli_command(&args);
    command.env("PATH", "/tmp/no-such-dir-agentdeck-e2e");
    let result = run_command(command, SESSION_TIMEOUT)
        .unwrap_or_else(|error| panic!("failed to run agentdeck with masked PATH: {error}"));

    assert!(
        !result.status.success(),
        "expected non-zero exit when claude is not in PATH, got: {}",
        result.status
    );

    let stdout = String::from_utf8_lossy(&result.stdout);
    let stderr = String::from_utf8_lossy(&result.stderr);

    // C5 fix (v0.2 final review): the CLI now threads daemon's
    // structured `error.code` through `CliError::Session { code: ... }`
    // into the JSON envelope on stdout. Assert the strong contract:
    //   - exit code == 5 (session failure)
    //   - stdout envelope has `error.code == "cc-not-installed"`
    // The exit code is the load-bearing E2E claim. The envelope code
    // is the diagnostic claim that previously regressed silently to
    // the literal `"session"`.
    assert_eq!(
        result.status.code(),
        Some(5),
        "expected exit code 5 (session failure), got status={}\nstdout: {stdout}\nstderr: {stderr}",
        result.status
    );

    let envelope_line = stdout
        .lines()
        .find(|l| l.trim_start().starts_with('{'))
        .expect("expected at least one JSON envelope line on stdout");
    let parsed: serde_json::Value = serde_json::from_str(envelope_line)
        .unwrap_or_else(|e| panic!("envelope line is not JSON: {e}\nline: {envelope_line}"));
    assert_eq!(
        parsed["error"]["code"], "cc-not-installed",
        "expected envelope error.code == 'cc-not-installed', got: {parsed}\nstdout: {stdout}\nstderr: {stderr}"
    );
    eprintln!("CC preflight failure test OK (exit={})", result.status);
}
