//! Gate: `AGENTDECK_E2E=1` — requires working daemon build.
//!
//! Tests cross-agent history subcommands.

mod support;

use support::{HISTORY_TIMEOUT, real_e2e_enabled, run_cli};

#[test]
fn history_list_default_returns_json() {
    if !real_e2e_enabled() {
        eprintln!("SKIP: set AGENTDECK_E2E=1 to run");
        return;
    }
    let out = run_cli(&["history", "list"], HISTORY_TIMEOUT);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    // Should be valid JSON (either {"kind":"list","value":[...]} or similar)
    let _: serde_json::Value = serde_json::from_slice(&out.stdout).expect("valid JSON output");
}

#[test]
fn history_list_with_codex_agent_filter_returns_json() {
    if !real_e2e_enabled() {
        return;
    }
    let out = run_cli(&["history", "list", "--agent", "codex"], HISTORY_TIMEOUT);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let _: serde_json::Value = serde_json::from_slice(&out.stdout).expect("valid JSON");
}

#[test]
fn history_list_with_cc_agent_filter_returns_json() {
    if !real_e2e_enabled() {
        return;
    }
    let out = run_cli(
        &["history", "list", "--agent", "claude-code"],
        HISTORY_TIMEOUT,
    );
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let _: serde_json::Value = serde_json::from_slice(&out.stdout).expect("valid JSON");
}
