//! Gate: `AGENTDECK_E2E=1` — requires working daemon build (both adapters registered).
//!
//! Tests `agentdeck agent list` and `agentdeck agent capabilities`.

use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_agentdeck")
}

fn gated() -> bool {
    std::env::var("AGENTDECK_E2E").is_ok()
}

#[test]
fn agent_list_returns_both_kinds() {
    if !gated() {
        eprintln!("SKIP: set AGENTDECK_E2E=1 to run");
        return;
    }
    let out = Command::new(bin()).args(["agent", "list"]).output().unwrap();
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
    assert!(kinds.contains(&"claude_code"), "expected claude_code in {:?}", kinds);
}

#[test]
fn agent_capabilities_codex_is_non_empty() {
    if !gated() {
        return;
    }
    let out = Command::new(bin())
        .args(["agent", "capabilities", "--agent", "codex"])
        .output()
        .unwrap();
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let features = json["features"].as_array().expect("features array");
    assert!(!features.is_empty(), "expected non-empty features for codex");
    assert_eq!(json["agentKind"], "codex");
}

#[test]
fn agent_capabilities_claude_code_is_non_empty() {
    if !gated() {
        return;
    }
    let out = Command::new(bin())
        .args(["agent", "capabilities", "--agent", "claude-code"])
        .output()
        .unwrap();
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let features = json["features"].as_array().expect("features array");
    assert!(!features.is_empty(), "expected non-empty features for claude_code");
    assert_eq!(json["agentKind"], "claude_code");
}
