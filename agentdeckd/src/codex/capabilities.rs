//! Codex SessionCapabilities builder + version probe.
//!
//! The session owner resolves and validates one exact `CodexBinary`, then
//! passes its version to `build_codex_capabilities`. The daemon emits that
//! payload as `ServerEvent::SessionCapabilities` before any `AgentItem`
//! (invariant N7).
//!
//! The feature set is intentionally narrower than what app-server can do.
//! Capabilities describe AgentDeck's currently accepted product surface, not
//! every method offered by the pinned vendor binary. Issue #3 establishes the
//! lifecycle only; Issue #4 will add `StreamingMessages` after the translated
//! stream has its own deterministic acceptance evidence.

use std::collections::BTreeSet;
use std::path::Path;

use agentdeck_protocol::{
    AgentKind, CodexApprovalPolicy, CodexCapabilities, CodexReasoningEffort, CodexSandboxMode,
    ProtocolError, SessionCapabilities, VendorCapabilities,
};

const CODEX_VERSION_FILE: &str = include_str!("../../../protocol/CODEX_VERSION.txt");

fn unsupported_version_error(message: impl Into<String>) -> ProtocolError {
    ProtocolError {
        code: "codex-version-unsupported".into(),
        message: message.into(),
        diagnostic_ref: None,
    }
}

pub(crate) fn supported_codex_version() -> &'static str {
    CODEX_VERSION_FILE.trim()
}

/// Build the `SessionCapabilities` payload for a Codex session.
///
/// `version` is the already validated string returned by the same executable
/// used to spawn app-server. It is wire-visible to clients so they can route
/// UI features by both `features` set and optional version-string heuristics.
pub fn build_codex_capabilities(version: String) -> SessionCapabilities {
    let features = BTreeSet::new();

    SessionCapabilities {
        agent_kind: AgentKind::Codex,
        agent_version: version,
        features,
        vendor: VendorCapabilities::Codex(CodexCapabilities {
            sandbox_modes: vec![CodexSandboxMode::ReadOnly],
            persistence_supported: false,
            reasoning_effort_levels: vec![CodexReasoningEffort::Medium],
        }),
    }
}

/// All Codex approval policies the adapter supports (exposed so the UI can
/// build a picker without hard-coding the enum variants — keeps the wire
/// shape and the picker in sync as the protocol grows).
pub fn supported_approval_policies() -> Vec<CodexApprovalPolicy> {
    vec![CodexApprovalPolicy::Never]
}

/// Validate an injected `<absolute codex binary> --version` command result.
///
/// The runner receives the already-resolved binary path. This keeps the
/// version probe and app-server spawn tied to one executable and lets the
/// default test suite use a fake binary without consulting the user's PATH.
pub(crate) fn probe_codex_version_with_command<F>(
    binary: &Path,
    run: F,
) -> Result<String, ProtocolError>
where
    F: FnOnce(&Path) -> Result<(i32, Vec<u8>), String>,
{
    match run(binary) {
        Ok((0, stdout)) => {
            let stdout = String::from_utf8(stdout).map_err(|_| {
                unsupported_version_error("Codex CLI version output is not valid UTF-8")
            })?;
            let actual = stdout.trim();
            let expected = supported_codex_version();
            if actual == expected {
                Ok(actual.to_string())
            } else {
                Err(unsupported_version_error(format!(
                    "unsupported Codex CLI version; expected {expected}"
                )))
            }
        }
        Ok((_status, _stdout)) => Err(unsupported_version_error(
            "Codex CLI version probe exited unsuccessfully",
        )),
        Err(_error) => Err(unsupported_version_error(
            "Codex CLI version probe could not be executed",
        )),
    }
}

/// Probe one already-resolved Codex binary and require the exact version
/// pinned by `protocol/CODEX_VERSION.txt`.
pub(crate) fn probe_codex_version_at(binary: &Path) -> Result<String, ProtocolError> {
    probe_codex_version_with_command(binary, |binary| {
        use std::process::Command;
        Command::new(binary)
            .arg("--version")
            .output()
            .map(|out| (out.status.code().unwrap_or(-1), out.stdout))
            .map_err(|error| error.to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capabilities_advertise_codex_agent_kind_and_version() {
        let caps = build_codex_capabilities("codex 0.42.0".to_string());
        assert_eq!(caps.agent_kind, AgentKind::Codex);
        assert_eq!(caps.agent_version, "codex 0.42.0");
    }

    #[test]
    fn capabilities_do_not_overclaim_post_lifecycle_features() {
        let caps = build_codex_capabilities("v".into());
        assert!(caps.features.is_empty());
    }

    #[test]
    fn capabilities_vendor_block_reports_only_fixed_m0_options() {
        let caps = build_codex_capabilities("v".into());
        match caps.vendor {
            VendorCapabilities::Codex(codex) => {
                assert!(!codex.persistence_supported);
                assert_eq!(codex.sandbox_modes, vec![CodexSandboxMode::ReadOnly]);
                assert_eq!(
                    codex.reasoning_effort_levels,
                    vec![CodexReasoningEffort::Medium]
                );
            }
            VendorCapabilities::ClaudeCode(_) => panic!("expected codex vendor block"),
        }
    }

    #[test]
    fn capabilities_features_serialize_deterministically() {
        // BTreeSet guarantees ordering; round-trip through JSON to keep the
        // schema-drift snapshot stable.
        let caps = build_codex_capabilities("v".into());
        let a = serde_json::to_string(&caps).unwrap();
        let b = serde_json::to_string(&caps).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn supported_approval_policies_reports_fixed_m0_policy() {
        let p = supported_approval_policies();
        assert_eq!(p, vec![CodexApprovalPolicy::Never]);
    }

    #[test]
    fn probe_codex_version_accepts_injected_success() {
        let binary = Path::new("/fake/codex");
        let version = probe_codex_version_with_command(binary, |actual_binary| {
            assert_eq!(actual_binary, binary);
            Ok((0, b"codex-cli 0.145.0\n".to_vec()))
        })
        .unwrap();
        assert_eq!(version, "codex-cli 0.145.0");
    }

    #[test]
    fn probe_codex_version_rejects_injected_spawn_failure() {
        let error = probe_codex_version_with_command(Path::new("/fake/codex"), |_| {
            Err("missing".to_string())
        })
        .unwrap_err();
        assert_eq!(error.code, "codex-version-unsupported");
    }

    #[test]
    fn probe_codex_version_rejects_nonzero_empty_malformed_and_mismatch() {
        for result in [
            Ok((1, b"codex-cli 0.145.0".to_vec())),
            Ok((0, b" \n".to_vec())),
            Ok((0, vec![0xff])),
            Ok((0, b"codex-cli 0.146.0\n".to_vec())),
        ] {
            let error =
                probe_codex_version_with_command(Path::new("/fake/codex"), |_| result).unwrap_err();
            assert_eq!(error.code, "codex-version-unsupported");
        }
    }

    #[test]
    fn pinned_version_comes_from_protocol_snapshot() {
        assert_eq!(supported_codex_version(), "codex-cli 0.145.0");
    }
}
