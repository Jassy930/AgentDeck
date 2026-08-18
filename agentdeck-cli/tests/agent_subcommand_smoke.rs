//! Gate: `AGENTDECK_E2E=1` — requires working daemon build (both adapters registered).
//!
//! Tests `agentdeck agent list` and `agentdeck agent capabilities`.

mod support;

use support::{ADMIN_TIMEOUT, real_e2e_enabled, run_cli};

#[test]
fn agent_list_returns_both_kinds() {
    if !real_e2e_enabled() {
        eprintln!("SKIP: set AGENTDECK_E2E=1 to run");
        return;
    }
    let out = run_cli(&["agent", "list"], ADMIN_TIMEOUT);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let kinds: Vec<&str> = json["agents"]
        .as_array()
        .expect("agents array")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert!(kinds.contains(&"codex"), "expected codex in {:?}", kinds);
    assert!(
        kinds.contains(&"claude_code"),
        "expected claude_code in {:?}",
        kinds
    );
}

#[test]
fn agent_capabilities_codex_is_non_empty() {
    if !real_e2e_enabled() {
        return;
    }
    let out = run_cli(
        &["agent", "capabilities", "--agent", "codex"],
        ADMIN_TIMEOUT,
    );
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let features = json["features"].as_array().expect("features array");
    assert!(
        !features.is_empty(),
        "expected non-empty features for codex"
    );
    assert_eq!(json["agentKind"], "codex");
}

#[test]
fn agent_capabilities_claude_code_is_non_empty() {
    if !real_e2e_enabled() {
        return;
    }
    let out = run_cli(
        &["agent", "capabilities", "--agent", "claude-code"],
        ADMIN_TIMEOUT,
    );
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let features = json["features"].as_array().expect("features array");
    assert!(
        !features.is_empty(),
        "expected non-empty features for claude_code"
    );
    assert_eq!(json["agentKind"], "claude_code");
}
