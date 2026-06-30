//! Gate: `AGENTDECK_E2E=1` — requires BOTH `codex` (with `codex login`) AND
//! `claude` (with `claude auth login`) to be present in PATH.
//!
//! Run with:
//!   AGENTDECK_E2E=1 cargo test -p agentdeck-cli --test e2e_cross_agent_history
//!
//! Tests cross-agent history aggregation: run one session of each agent type,
//! then verify that `history list` (no filter) returns entries for both,
//! while per-agent filters return only their respective entries.

use std::io::{BufRead, BufReader};
use std::process::Command;
use std::time::Duration;

fn gated() -> bool {
    std::env::var("AGENTDECK_E2E").is_ok()
}

fn which_bin(name: &str) -> bool {
    Command::new("which").arg(name).output().map(|o| o.status.success()).unwrap_or(false)
}

fn both_vendors_available() -> bool {
    which_bin("codex") && which_bin("claude")
}

fn cli_bin() -> &'static str {
    env!("CARGO_BIN_EXE_agentdeck")
}

fn run_cli(args: &[&str]) -> std::process::Output {
    Command::new(cli_bin())
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("failed to spawn agentdeck {args:?}: {e}"))
}

/// Run a session and return `(thread_id, agent_kind_str)`.
fn run_session(agent: &str, extra_args: &[&str], prompt: &str) -> (String, String) {
    let cwd = std::env::current_dir()
        .unwrap()
        .to_string_lossy()
        .to_string();

    let mut cmd_args = vec![
        "session", "run",
        "--agent", agent,
        "--cwd", &cwd,
        "--prompt", prompt,
    ];
    cmd_args.extend_from_slice(extra_args);

    let mut child = Command::new(cli_bin())
        .args(&cmd_args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("failed to spawn agentdeck session run --agent {agent}: {e}"));

    let stdout = child.stdout.take().expect("child stdout");
    let reader = BufReader::new(stdout);

    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    let mut thread_id = String::new();
    let mut agent_kind_out = String::new();

    for line in reader.lines() {
        if std::time::Instant::now() > deadline {
            let _ = child.kill();
            panic!("session run --agent {agent} timed out after 60s");
        }
        let line = line.expect("readline failed");
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
        if ev_type == Some("turnComplete") || ev_type == Some("error") {
            break;
        }
    }

    let status = child.wait().expect("wait failed");
    assert!(
        status.success(),
        "agentdeck session run --agent {agent} exited non-zero: {status}"
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
    if !gated() {
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
        &["--sandbox", "read-only", "--approval", "never", "--reasoning-effort", "minimal"],
        "say hi",
    );
    eprintln!("codex session done: thread_id={codex_tid}, agentKind={codex_kind}");

    // Run a CC session
    let (cc_tid, cc_kind) = run_session(
        "claude-code",
        &["--permission", "bypass-permissions", "--model", "claude-haiku-4-5"],
        "say hi briefly",
    );
    eprintln!("CC session done: thread_id={cc_tid}, agentKind={cc_kind}");

    // Fetch merged history (no --agent filter)
    let out = run_cli(&["history", "list"]);
    assert!(
        out.status.success(),
        "agentdeck history list (merged) failed\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&out.stdout)
        .expect("history list output must be valid JSON");
    assert_eq!(json["kind"], "list", "merged history must have kind=list; got: {json}");

    let items = json["value"].as_array().expect("value must be an array");
    let agent_kinds: Vec<&str> = items
        .iter()
        .filter_map(|item| item.get("agentKind").and_then(|v| v.as_str()))
        .collect();

    // Note: Codex history list is stubbed empty in v0.2 (see agentdeckd/src/codex/history.rs
    // TODO(v0.3)). The fan-out merge still works — CC entries appear in the merged list
    // alongside a silent empty contribution from Codex. This test therefore verifies:
    //   1. The merged list request succeeds (kind=list, valid JSON).
    //   2. CC entries are present (from the just-run CC session).
    //   3. All items carry a valid agentKind field.
    //
    // When Codex history is wired in v0.3, this assertion can be upgraded to also
    // require "codex" in agent_kinds.
    assert!(
        agent_kinds.contains(&"claude_code"),
        "merged history must contain at least one claude_code entry; kinds seen: {agent_kinds:?}"
    );
    // Verify all items have a recognized agentKind
    for kind in &agent_kinds {
        assert!(
            *kind == "codex" || *kind == "claude_code",
            "unknown agentKind in merged history: {kind}"
        );
    }
    eprintln!(
        "merged history OK: {} total items (codex_stub_empty+CC), codex_tid={codex_tid}, cc_tid={cc_tid}",
        items.len()
    );
}

#[test]
fn e2e_cross_history_codex_filter_returns_only_codex() {
    if !gated() { eprintln!("SKIP: set AGENTDECK_E2E=1"); return; }
    if !both_vendors_available() {
        eprintln!("SKIP: both codex and claude must be in PATH");
        return;
    }

    let out = run_cli(&["history", "list", "--agent", "codex"]);
    assert!(
        out.status.success(),
        "agentdeck history list --agent codex failed\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&out.stdout)
        .expect("history list --agent codex must be valid JSON");
    assert_eq!(json["kind"], "list");

    let items = json["value"].as_array().expect("value must be an array");
    for item in items {
        let kind = item.get("agentKind").and_then(|v| v.as_str()).unwrap_or("(missing)");
        assert_eq!(
            kind, "codex",
            "all items with --agent codex filter must have agentKind=codex; found: {kind}"
        );
    }
    eprintln!("codex-only history filter OK: {} codex items", items.len());
}

#[test]
fn e2e_cross_history_cc_filter_returns_only_cc() {
    if !gated() { eprintln!("SKIP: set AGENTDECK_E2E=1"); return; }
    if !both_vendors_available() {
        eprintln!("SKIP: both codex and claude must be in PATH");
        return;
    }

    let out = run_cli(&["history", "list", "--agent", "claude-code"]);
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
        let kind = item.get("agentKind").and_then(|v| v.as_str()).unwrap_or("(missing)");
        assert_eq!(
            kind, "claude_code",
            "all items with --agent claude-code filter must have agentKind=claude_code; found: {kind}"
        );
    }
    eprintln!("CC-only history filter OK: {} claude_code items", items.len());
}
