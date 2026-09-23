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

use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::process::{Child, Command};
use tokio::sync::watch;
use tokio::time::{Instant, timeout_at};

use super::app_server::{SHORT_LIVED_SHUTDOWN_TIMEOUT, process_group_exists, signal_process_group};

use agentdeck_protocol::{
    AgentKind, CapabilityId, CodexApprovalPolicy, CodexCapabilities, CodexReasoningEffort,
    CodexSandboxMode, ProtocolError, SessionCapabilities, VendorCapabilities,
};

const CODEX_VERSION_FILE: &str = include_str!("../../../protocol/CODEX_VERSION.txt");
pub(super) const VERSION_PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const PROBE_POLL_INTERVAL: Duration = Duration::from_millis(10);

fn probe_error(code: &str, message: impl Into<String>) -> ProtocolError {
    ProtocolError {
        code: code.into(),
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
                probe_error(
                    "codex-version-probe-failed",
                    format!("Codex 版本输出不是有效 UTF-8；路径：{}", binary.display()),
                )
            })?;
            let actual = stdout.trim();
            let actual_version = actual
                .strip_prefix("codex-cli ")
                .and_then(|version| semver::Version::parse(version).ok())
                .ok_or_else(|| {
                    probe_error(
                        "codex-version-probe-failed",
                        format!("Codex 版本输出格式无效；路径：{}", binary.display()),
                    )
                })?;
            let expected = supported_codex_version();
            if actual == expected {
                Ok(actual.to_string())
            } else {
                let expected_version = semver::Version::parse(
                    expected
                        .strip_prefix("codex-cli ")
                        .expect("pinned Codex prefix"),
                )
                .expect("pinned Codex semver");
                let guidance = match actual_version.cmp_precedence(&expected_version) {
                    Ordering::Less => "请升级 Codex 桌面端或系统 CLI 到已验证版本。",
                    Ordering::Greater => {
                        "请升级 AgentDeck，或将 AGENTDECK_CODEX_BIN 指向已验证版本。"
                    }
                    Ordering::Equal => "请使用与已验证版本完全匹配的 Codex 构建。",
                };
                Err(probe_error(
                    "codex-version-unsupported",
                    format!(
                        "AgentDeck 尚未验证此 Codex 版本；实际：{actual}；已验证：{expected}；路径：{}。{guidance}",
                        binary.display()
                    ),
                ))
            }
        }
        Ok((status, _stdout)) => Err(probe_error(
            "codex-version-probe-failed",
            format!(
                "Codex 版本探测失败，退出码：{status}；路径：{}",
                binary.display()
            ),
        )),
        Err(_error) => Err(probe_error(
            "codex-version-probe-failed",
            format!("无法执行 Codex 版本探测；路径：{}", binary.display()),
        )),
    }
}

pub(super) fn check_probe_deadline(
    deadline: Instant,
    cancel: &watch::Receiver<bool>,
) -> Result<(), ProtocolError> {
    if *cancel.borrow() {
        Err(probe_error(
            "codex-open-canceled",
            "Codex startup was canceled",
        ))
    } else if Instant::now() >= deadline {
        Err(probe_error(
            "codex-version-timeout",
            "Codex CLI discovery exceeded its time budget",
        ))
    } else {
        Ok(())
    }
}

struct VersionProbe {
    child: Child,
    process_group_id: u32,
}

impl Drop for VersionProbe {
    fn drop(&mut self) {
        let _ = signal_process_group(self.process_group_id);
        let _ = self.child.start_kill();
    }
}

/// All candidates share one deadline. Cancellation stops discovery only after
/// the active probe and its process group have been reaped.
pub(super) async fn probe_codex_version_at(
    binary: &Path,
    deadline: Instant,
    cancel: &mut watch::Receiver<bool>,
) -> Result<String, ProtocolError> {
    check_probe_deadline(deadline, cancel)?;
    let mut command = Command::new(binary);
    command
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    #[cfg(unix)]
    command.process_group(0);
    let child = command.spawn().map_err(|error| {
        probe_error(
            "codex-version-probe-failed",
            format!("Codex CLI version probe could not be executed: {error}"),
        )
    })?;
    let mut probe = VersionProbe {
        process_group_id: child.id().expect("new probe pid"),
        child,
    };
    let result = tokio::select! {
        biased;
        _ = cancel.changed() => Err(probe_error("codex-open-canceled", "Codex startup was canceled")),
        result = timeout_at(deadline, probe.child.wait()) => match result {
            Ok(Ok(status)) => Ok(status),
            Ok(Err(error)) => Err(probe_error("codex-version-probe-failed", format!("Codex CLI version probe wait failed: {error}"))),
            Err(_) => Err(probe_error("codex-version-timeout", "Codex CLI discovery exceeded its time budget")),
        },
    };

    // Launchers may leave descendants holding stdout after exiting themselves.
    let signal = signal_process_group(probe.process_group_id);
    let _ = probe.child.start_kill();
    let cleanup = async {
        probe.child.wait().await?;
        signal?;
        while process_group_exists(probe.process_group_id)? {
            tokio::time::sleep(PROBE_POLL_INTERVAL).await;
        }
        let mut stdout = Vec::new();
        probe
            .child
            .stdout
            .take()
            .expect("piped version stdout")
            .read_to_end(&mut stdout)
            .await?;
        Ok::<_, std::io::Error>(stdout)
    };
    let stdout = tokio::time::timeout(SHORT_LIVED_SHUTDOWN_TIMEOUT, cleanup)
        .await
        .map_err(|_| {
            probe_error(
                "codex-cleanup-failed",
                "Codex CLI version probe cleanup timed out",
            )
        })?
        .map_err(|error| {
            probe_error(
                "codex-cleanup-failed",
                format!("Codex CLI version probe cleanup failed: {error}"),
            )
        })?;
    let status = result?;
    probe_codex_version_with_command(binary, |_| Ok((status.code().unwrap_or(-1), stdout)))
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
            Err("private launch details".to_string())
        })
        .unwrap_err();
        assert_eq!(error.code, "codex-version-probe-failed");
        assert!(error.message.contains("/fake/codex"));
        assert!(!error.message.contains("private launch details"));
    }

    #[test]
    fn probe_codex_version_rejects_nonzero_empty_and_malformed_without_raw_output() {
        for result in [
            Ok((1, b"PRIVATE_VENDOR_OUTPUT".to_vec())),
            Ok((0, b" \n".to_vec())),
            Ok((0, vec![0xff])),
            Ok((0, b"PRIVATE_VENDOR_OUTPUT\n".to_vec())),
            Ok((0, b"codex-cli 01.155.0\n".to_vec())),
            Ok((0, b"codex-cli 0.155.0-alpha..16\n".to_vec())),
            Ok((0, b"codex-cli 0.155.0-alpha.016\n".to_vec())),
            Ok((0, b"codex-cli 0.155.0-\n".to_vec())),
            Ok((0, b"codex-cli 0.155.0+\n".to_vec())),
        ] {
            let error =
                probe_codex_version_with_command(Path::new("/fake/codex"), |_| result).unwrap_err();
            assert_eq!(error.code, "codex-version-probe-failed");
            assert!(error.message.contains("/fake/codex"));
            assert!(!error.message.contains("PRIVATE_VENDOR_OUTPUT"));
            assert!(!error.message.contains("codex-cli "));
        }
    }

    #[test]
    fn probe_codex_version_mismatch_explains_version_path_and_next_step() {
        for (actual, guidance) in [
            ("codex-cli 0.146.0", "请升级 Codex 桌面端或系统 CLI"),
            (
                "codex-cli 0.155.0-alpha.9.2",
                "请升级 Codex 桌面端或系统 CLI",
            ),
            ("codex-cli 0.155.0-alpha.100", "请升级 AgentDeck"),
            ("codex-cli 0.155.0", "请升级 AgentDeck"),
            (
                "codex-cli 0.155.0-alpha.16+local",
                "请使用与已验证版本完全匹配的 Codex 构建",
            ),
        ] {
            let error = probe_codex_version_with_command(Path::new("/fake/codex"), |_| {
                Ok((0, format!("{actual}\n").into_bytes()))
            })
            .unwrap_err();
            assert_eq!(error.code, "codex-version-unsupported");
            for detail in [
                "尚未验证",
                actual,
                supported_codex_version(),
                "/fake/codex",
                guidance,
            ] {
                assert!(error.message.contains(detail), "{}", error.message);
            }
        }
    }

    #[test]
    fn pinned_version_comes_from_protocol_snapshot() {
        assert_eq!(supported_codex_version(), "codex-cli 0.155.0-alpha.16");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn version_probe_reaps_launcher_and_children_on_success_timeout_and_cancel() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;

        for mode in ["success", "timeout", "cancel"] {
            let root = std::env::temp_dir().join(format!(
                "agentdeck-version-probe-{}-{}",
                std::process::id(),
                uuid::Uuid::new_v4()
            ));
            fs::create_dir(&root).unwrap();
            let binary = root.join("codex");
            let pids_file = root.join("pids");
            let pids_path = pids_file.to_string_lossy().replace('\'', "'\"'\"'");
            let finish = if mode != "success" {
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
            let (cancel_tx, mut cancel) = watch::channel(false);
            let (result, ()) = tokio::join!(
                probe_codex_version_at(
                    &binary,
                    Instant::now() + Duration::from_secs(2),
                    &mut cancel
                ),
                async {
                    if mode == "cancel" {
                        while !pids_file.exists() {
                            assert!(started.elapsed() < Duration::from_secs(3));
                            tokio::time::sleep(Duration::from_millis(10)).await;
                        }
                        cancel_tx.send(true).unwrap();
                    }
                }
            );
            assert!(started.elapsed() < Duration::from_secs(5));
            if mode != "success" {
                assert_eq!(
                    result.unwrap_err().code,
                    if mode == "cancel" {
                        "codex-open-canceled"
                    } else {
                        "codex-version-timeout"
                    }
                );
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
                    .await
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
