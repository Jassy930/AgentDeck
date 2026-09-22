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
//! lifecycle and cumulative assistant streaming only.

use std::collections::BTreeSet;
use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use super::app_server::{SHORT_LIVED_SHUTDOWN_TIMEOUT, signal_process_group};

use agentdeck_protocol::{
    AgentKind, CapabilityId, CodexApprovalPolicy, CodexCapabilities, CodexReasoningEffort,
    CodexSandboxMode, ProtocolError, SessionCapabilities, VendorCapabilities,
};

const CODEX_VERSION_FILE: &str = include_str!("../../../protocol/CODEX_VERSION.txt");
const VERSION_PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const PROBE_POLL_INTERVAL: Duration = Duration::from_millis(10);

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
    let features = BTreeSet::from([CapabilityId::StreamingMessages]);

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
    probe_codex_version_with_timeout(binary, VERSION_PROBE_TIMEOUT)
}

fn probe_codex_version_with_timeout(
    binary: &Path,
    timeout: Duration,
) -> Result<String, ProtocolError> {
    let mut command = Command::new(binary);
    command
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let mut child = command
        .spawn()
        .map_err(|_| unsupported_version_error("Codex CLI version probe could not be executed"))?;
    let process_group_id = child.id();
    let deadline = Instant::now() + timeout;
    let result = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Err(_) => {
                break Err(unsupported_version_error(
                    "Codex CLI version probe could not be awaited",
                ));
            }
            Ok(None) if Instant::now() >= deadline => {
                break Err(ProtocolError {
                    code: "codex-version-timeout".into(),
                    message: format!("Codex CLI version probe exceeded {timeout:?}"),
                    diagnostic_ref: None,
                });
            }
            Ok(None) => std::thread::sleep(PROBE_POLL_INTERVAL),
        }
    };

    // A launcher can exit while its children retain stdout. Signal the saved
    // group before reading the pipe, including after a successful probe.
    let group_signal = signal_process_group(process_group_id);
    let _ = child.kill();
    let cleanup_error = |reason| ProtocolError {
        code: "codex-cleanup-failed".into(),
        message: format!("Codex CLI version probe cleanup failed: {reason}"),
        diagnostic_ref: None,
    };
    let cleanup_deadline = Instant::now() + SHORT_LIVED_SHUTDOWN_TIMEOUT;
    loop {
        let reaped = child
            .try_wait()
            .map_err(|error| cleanup_error(format!("wait: {error}")))?
            .is_some();
        if reaped {
            break;
        }
        if Instant::now() >= cleanup_deadline {
            return Err(cleanup_error(
                "process exit was not confirmed in time".into(),
            ));
        }
        std::thread::sleep(PROBE_POLL_INTERVAL);
    }
    group_signal.map_err(|error| cleanup_error(format!("signal process group: {error}")))?;
    let status = result?;
    let mut stdout = Vec::new();
    let output = child
        .stdout
        .take()
        .expect("piped version stdout")
        .read_to_end(&mut stdout)
        .map(|_| (status.code().unwrap_or(-1), stdout))
        .map_err(|error| error.to_string());
    probe_codex_version_with_command(binary, |_| output)
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
    fn capabilities_advertise_only_accepted_m0_streaming() {
        let caps = build_codex_capabilities("v".into());
        assert_eq!(
            caps.features,
            BTreeSet::from([CapabilityId::StreamingMessages])
        );
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
            Ok((0, format!("{}\n", supported_codex_version()).into_bytes()))
        })
        .unwrap();
        assert_eq!(version, supported_codex_version());
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
            Ok((1, supported_codex_version().as_bytes().to_vec())),
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
        assert_eq!(supported_codex_version(), "codex-cli 0.155.0-alpha.9.2");
    }

    #[cfg(unix)]
    #[test]
    fn version_probe_reaps_launcher_and_children_on_success_and_timeout() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;

        for times_out in [false, true] {
            let root = std::env::temp_dir().join(format!(
                "agentdeck-version-probe-{}-{}",
                std::process::id(),
                uuid::Uuid::new_v4()
            ));
            fs::create_dir(&root).unwrap();
            let binary = root.join("codex");
            let pids_file = root.join("pids");
            let pids_path = pids_file.to_string_lossy().replace('\'', "'\"'\"'");
            let finish = if times_out {
                "wait".to_string()
            } else {
                format!("printf '%s\\n' '{}'", supported_codex_version())
            };
            fs::write(
                &binary,
                format!(
                    "#!/bin/sh\n/bin/sleep 10 &\nprintf '%s %s\\n' \"$$\" \"$!\" > '{pids_path}'\n{finish}\n"
                ),
            )
            .unwrap();
            fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).unwrap();

            let started = Instant::now();
            let result = probe_codex_version_with_timeout(&binary, Duration::from_secs(2));
            assert!(started.elapsed() < Duration::from_secs(5));
            if times_out {
                assert_eq!(result.unwrap_err().code, "codex-version-timeout");
            } else {
                assert_eq!(result.unwrap(), supported_codex_version());
            }
            let pids = fs::read_to_string(&pids_file).unwrap();
            let pids: Vec<u32> = pids
                .split_whitespace()
                .map(|pid| pid.parse().unwrap())
                .collect();
            assert_eq!(pids.len(), 2);
            for pid in pids {
                let process = Command::new("/bin/ps")
                    .args(["-o", "pid=", "-p", &pid.to_string()])
                    .output()
                    .unwrap();
                assert!(
                    process.stdout.is_empty(),
                    "probe process {pid} still exists"
                );
            }
            fs::remove_dir_all(root).unwrap();
        }
    }
}
