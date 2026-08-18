//! Gate: `AGENTDECK_E2E=1` — requires a working daemon build.
//!
//! Tests `agentdeck diagnostics report`.

mod support;

use support::{ADMIN_TIMEOUT, real_e2e_enabled, run_cli};

#[test]
fn diagnostics_report_returns_report_shape_not_protocol_schema() {
    if !real_e2e_enabled() {
        eprintln!("SKIP: set AGENTDECK_E2E=1 to run");
        return;
    }

    let out = run_cli(&["diagnostics", "report"], ADMIN_TIMEOUT);
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
