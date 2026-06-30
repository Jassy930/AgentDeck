//! Gate: `AGENTDECK_E2E=1` — requires working daemon build.
//!
//! Tests cross-agent history subcommands.

use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_agentdeck")
}

fn gated() -> bool {
    std::env::var("AGENTDECK_E2E").is_ok()
}

#[test]
fn history_list_default_returns_json() {
    if !gated() {
        eprintln!("SKIP: set AGENTDECK_E2E=1 to run");
        return;
    }
    let out = Command::new(bin()).args(["history", "list"]).output().unwrap();
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    // Should be valid JSON (either {"kind":"list","value":[...]} or similar)
    let _: serde_json::Value = serde_json::from_slice(&out.stdout).expect("valid JSON output");
}

#[test]
fn history_list_with_codex_agent_filter_returns_json() {
    if !gated() {
        return;
    }
    let out = Command::new(bin())
        .args(["history", "list", "--agent", "codex"])
        .output()
        .unwrap();
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let _: serde_json::Value = serde_json::from_slice(&out.stdout).expect("valid JSON");
}

#[test]
fn history_list_with_cc_agent_filter_returns_json() {
    if !gated() {
        return;
    }
    let out = Command::new(bin())
        .args(["history", "list", "--agent", "claude-code"])
        .output()
        .unwrap();
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let _: serde_json::Value = serde_json::from_slice(&out.stdout).expect("valid JSON");
}
