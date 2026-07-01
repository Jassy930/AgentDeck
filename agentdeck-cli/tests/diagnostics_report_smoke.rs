//! Gate: `AGENTDECK_E2E=1` — requires a working daemon build.
//!
//! Tests `agentdeck diagnostics report`.

use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_agentdeck")
}

fn gated() -> bool {
    std::env::var("AGENTDECK_E2E").is_ok()
}

#[test]
fn diagnostics_report_returns_report_shape_not_protocol_schema() {
    if !gated() {
        eprintln!("SKIP: set AGENTDECK_E2E=1 to run");
        return;
    }

    let out = Command::new(bin())
        .args(["diagnostics", "report"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).expect("valid JSON");
    assert!(
        json.get("path").is_some(),
        "expected diagnostics path: {json}"
    );
    assert!(
        json.get("lineCount").is_some(),
        "expected diagnostics lineCount: {json}"
    );
    assert!(
        json.get("$schema").is_none(),
        "diagnostics report must not return protocol schema: {json}"
    );
}
