//! Gate: `AGENTDECK_E2E=1` — requires BOTH `codex` (with `codex login`) AND
//! `claude` (with `claude auth login`) to be present in PATH.
//!
//! Run with:
//!   cargo build --locked -p agentdeckd --bin agentdeckd
//!   AGENTDECK_DAEMON_BIN="$PWD/target/debug/agentdeckd" AGENTDECK_E2E=1 \
//!     cargo test -p agentdeck-cli --test e2e_cross_agent_history -- --test-threads=1
//!
//! Tests cross-agent history aggregation: run one session of each agent type,
//! then verify that `history list` (no filter) returns entries for both,
//! while per-agent filters return only their respective entries.

mod support;

use support::{HISTORY_TIMEOUT, SESSION_TIMEOUT, real_e2e_enabled, run_cli, vendor_available};

fn both_vendors_available() -> bool {
    vendor_available("codex") && vendor_available("claude")
}

/// Run a session and return `(thread_id, agent_kind_str)`.
fn run_session(agent: &str, extra_args: &[&str], prompt: &str) -> (String, String) {
    let cwd = std::env::current_dir()
        .unwrap()
        .to_string_lossy()
        .to_string();

    let mut command_args = vec![
        "session", "run", "--agent", agent, "--cwd", &cwd, "--prompt", prompt,
    ];
    command_args.extend_from_slice(extra_args);
    let output = run_cli(&command_args, SESSION_TIMEOUT);

    let mut thread_id = String::new();
    let mut agent_kind_out = String::new();
    let mut terminal_seen = false;

    for line in String::from_utf8_lossy(&output.stdout).lines() {
        if line.trim().is_empty() {
            continue;
        }
        let Ok(val) = serde_json::from_str::<serde_json::Value>(&line) else {
            continue;
        };
        // Capture threadId
        if thread_id.is_empty() {
            if let Some(tid) = val.get("threadId").and_then(|v| v.as_str()) {
                thread_id = tid.to_string();
            }
        }
        // Capture agentKind from sessionStarted
        if agent_kind_out.is_empty() {
            if val.get("type").and_then(|t| t.as_str()) == Some("sessionStarted") {
                if let Some(ak) = val.get("agentKind").and_then(|v| v.as_str()) {
                    agent_kind_out = ak.to_string();
                }
            }
        }
        let ev_type = val.get("type").and_then(|t| t.as_str());
        if matches!(ev_type, Some("turnFinished" | "turnComplete" | "error")) {
            terminal_seen = true;
            break;
        }
    }

    assert!(
        output.status.success(),
        "agentdeck session run --agent {agent} exited non-zero: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        terminal_seen,
        "session run --agent {agent} exited before turn terminal\nstdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        !thread_id.is_empty(),
        "no threadId found in session run --agent {agent}"
    );
    (thread_id, agent_kind_out)
}

// ── Cross-agent history tests ──────────────────────────────────────────────────

#[test]
fn e2e_cross_history_merged_list_contains_both_agents() {
    if !real_e2e_enabled() {
        eprintln!("SKIP: set AGENTDECK_E2E=1 to run cross-agent history E2E tests");
        return;
    }
    if !both_vendors_available() {
        eprintln!("SKIP: both codex and claude must be in PATH for cross-agent tests");
        return;
    }

    // Run a Codex session
    let (codex_tid, codex_kind) = run_session(
        "codex",
        &[
            "--sandbox",
            "read-only",
            "--approval",
            "never",
            "--reasoning-effort",
            "medium",
        ],
        "say hi",
    );
    eprintln!("codex session done: thread_id={codex_tid}, agentKind={codex_kind}");

    // Run a CC session
    let (cc_tid, cc_kind) = run_session(
        "claude-code",
        &[
            "--permission",
            "bypass-permissions",
            "--model",
            "claude-haiku-4-5",
        ],
        "say hi briefly",
    );
    eprintln!("CC session done: thread_id={cc_tid}, agentKind={cc_kind}");

    // Fetch merged history (no --agent filter)
    let out = run_cli(&["history", "list"], HISTORY_TIMEOUT);
    assert!(
        out.status.success(),
        "agentdeck history list (merged) failed\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let json: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("history list output must be valid JSON");
    assert_eq!(
        json["kind"], "list",
        "merged history must have kind=list; got: {json}"
    );

    let items = json["value"].as_array().expect("value must be an array");
    let contains_thread = |thread_id: &str, agent_kind: &str| {
        items.iter().any(|item| {
            item.get("threadId").and_then(|value| value.as_str()) == Some(thread_id)
                && item.get("agentKind").and_then(|value| value.as_str()) == Some(agent_kind)
        })
    };
    assert!(
        contains_thread(&codex_tid, "codex"),
        "merged history must contain the Codex thread created by this test: {codex_tid}"
    );
    assert!(
        contains_thread(&cc_tid, "claude_code"),
        "merged history must contain the Claude Code thread created by this test: {cc_tid}"
    );

    for (thread_id, agent) in [(&codex_tid, "codex"), (&cc_tid, "claude-code")] {
        let read = run_cli(
            &["history", "read", thread_id, "--agent", agent],
            HISTORY_TIMEOUT,
        );
        assert!(
            read.status.success(),
            "history read failed for {agent} thread {thread_id}\nstderr: {}",
            String::from_utf8_lossy(&read.stderr)
        );
        let detail: serde_json::Value =
            serde_json::from_slice(&read.stdout).expect("history read output must be valid JSON");
        assert_eq!(detail["kind"], "read");
        assert_eq!(detail["value"]["threadId"], thread_id.as_str());
        assert!(
            detail["value"]["turns"]
                .as_array()
                .is_some_and(|turns| !turns.is_empty()),
            "history read must return at least one persisted turn for {thread_id}"
        );
    }
    eprintln!(
        "merged history OK: {} total items, codex_tid={codex_tid}, cc_tid={cc_tid}",
        items.len()
    );
}

#[test]
fn e2e_cross_history_codex_filter_returns_only_codex() {
    if !real_e2e_enabled() {
        eprintln!("SKIP: set AGENTDECK_E2E=1");
        return;
    }
    if !both_vendors_available() {
        eprintln!("SKIP: both codex and claude must be in PATH");
        return;
    }

    let out = run_cli(&["history", "list", "--agent", "codex"], HISTORY_TIMEOUT);
    assert!(
        out.status.success(),
        "agentdeck history list --agent codex failed\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let json: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("history list --agent codex must be valid JSON");
    assert_eq!(json["kind"], "list");

    let items = json["value"].as_array().expect("value must be an array");
    for item in items {
        let kind = item
            .get("agentKind")
            .and_then(|v| v.as_str())
            .unwrap_or("(missing)");
        assert_eq!(
            kind, "codex",
            "all items with --agent codex filter must have agentKind=codex; found: {kind}"
        );
    }
    eprintln!("codex-only history filter OK: {} codex items", items.len());
}

#[test]
fn e2e_cross_history_cc_filter_returns_only_cc() {
    if !real_e2e_enabled() {
        eprintln!("SKIP: set AGENTDECK_E2E=1");
        return;
    }
    if !both_vendors_available() {
        eprintln!("SKIP: both codex and claude must be in PATH");
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
    let json: serde_json::Value = serde_json::from_slice(&out.stdout)
        .expect("history list --agent claude-code must be valid JSON");
    assert_eq!(json["kind"], "list");

    let items = json["value"].as_array().expect("value must be an array");
    for item in items {
        let kind = item
            .get("agentKind")
            .and_then(|v| v.as_str())
            .unwrap_or("(missing)");
        assert_eq!(
            kind, "claude_code",
            "all items with --agent claude-code filter must have agentKind=claude_code; found: {kind}"
        );
    }
    eprintln!(
        "CC-only history filter OK: {} claude_code items",
        items.len()
    );
}
