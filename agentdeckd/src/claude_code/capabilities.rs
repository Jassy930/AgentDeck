//! Claude Code `SessionCapabilities` builder + probes.
//!
//! Phase 4 Task 4B. Replaces the 4A docstring stub with a real builder
//! used by `ClaudeCodeAdapter::capabilities`.
//!
//! ## CC capability surface
//!
//! `features` is a typed `BTreeSet<CapabilityId>` (deterministic
//! serialization). Each vendor advertises only its verified surface: CC
//! still drops partial assistant and reasoning deltas, so it does not claim
//! `StreamingMessages` or `StreamingReasoning` merely because Codex now streams
//! messages. The approval response wire is still speculative, so `Approval`
//! is also withheld. The vendor block
//! carries the 6 permission modes, a small curated `output_styles` list,
//! and the hook names CC accepts on `--include-hook-events` lifecycle output.
//!
//! ## Version probe
//!
//! `probe_claude_code_version()` shells out to `claude --version`
//! synchronously; the adapter caches the result in a `OnceLock`. If the
//! binary is missing the probe returns `"claude unknown"` so capability
//! emission never blocks. Mirrors `codex::capabilities::probe_codex_version`.

use std::collections::BTreeSet;

use agentdeck_protocol::{
    AgentKind, CapabilityId, ClaudeCodeCapabilities, ClaudeCodePermissionMode, SessionCapabilities,
    VendorCapabilities,
};

/// Build the `SessionCapabilities` payload for a Claude Code session.
///
/// `cli_version` should come from `probe_claude_code_version` and is
/// echoed both at `agent_version` (UI-facing) and inside the vendor
/// block (for vendor-specific routing / debugging).
pub fn build_claude_code_capabilities(cli_version: String) -> SessionCapabilities {
    let features: BTreeSet<CapabilityId> = [
        // —— Shared capabilities currently exposed by the CC adapter ——
        CapabilityId::Shell,
        CapabilityId::Diff,
        CapabilityId::Mcp,
        CapabilityId::TokenCounters,
        CapabilityId::AuthStatus,
        CapabilityId::ReasoningEffort,
        CapabilityId::ImageInput,
        CapabilityId::Worktree,
        // —— Claude-Code-only ——
        CapabilityId::ClaudeCodePermissionMode,
        CapabilityId::ClaudeCodeHooks,
        CapabilityId::ClaudeCodeOutputStyle,
        CapabilityId::ClaudeCodeSlashCommands,
        CapabilityId::ClaudeCodePlanMode,
        CapabilityId::ClaudeCodeBackgroundAgents,
        CapabilityId::ClaudeCodePluginDir,
        CapabilityId::ClaudeCodeForkSession,
    ]
    .into_iter()
    .collect();

    SessionCapabilities {
        agent_kind: AgentKind::ClaudeCode,
        agent_version: cli_version.clone(),
        features,
        vendor: VendorCapabilities::ClaudeCode(ClaudeCodeCapabilities {
            permission_modes: vec![
                ClaudeCodePermissionMode::Default,
                ClaudeCodePermissionMode::AcceptEdits,
                ClaudeCodePermissionMode::Plan,
                ClaudeCodePermissionMode::Auto,
                ClaudeCodePermissionMode::DontAsk,
                ClaudeCodePermissionMode::BypassPermissions,
            ],
            // Output styles ship with CC out-of-the-box (v0.2 only
            // advertises the built-ins; user-defined output styles
            // discovered via `~/.claude/output-styles/` scan are v0.3+).
            output_styles: vec!["default".into(), "explanatory".into(), "concise".into()],
            // Hook lifecycle names CC emits on `--include-hook-events`
            // and accepts in `settings.json`. Surfaced so the UI can
            // present a picker for `AddHook` vendor control.
            hooks_supported: vec![
                "PreToolUse".into(),
                "PostToolUse".into(),
                "UserPromptSubmit".into(),
                "Stop".into(),
                "SessionStart".into(),
                "SessionEnd".into(),
            ],
            cli_version,
        }),
    }
}

/// Classify an injected `claude --version` command result. Tests pass a fake
/// runner so the default suite never executes the user's vendor binary.
pub fn probe_claude_code_version_with_command<F>(run: F) -> String
where
    F: FnOnce() -> Result<(i32, String), String>,
{
    match run() {
        Ok((0, stdout)) => {
            let trimmed = stdout.trim();
            if trimmed.is_empty() {
                "claude unknown".to_string()
            } else {
                trimmed.to_string()
            }
        }
        _ => "claude unknown".to_string(),
    }
}

/// Probe the local `claude` binary's version string. Falls back to a
/// stable placeholder so capability emission never blocks on the probe.
///
/// Synchronous — the adapter caches the result behind a `OnceLock`, so
/// the shell-out happens at most once per process.
pub fn probe_claude_code_version() -> String {
    probe_claude_code_version_with_command(|| {
        use std::process::Command;
        Command::new("claude")
            .arg("--version")
            .output()
            .map(|out| {
                (
                    out.status.code().unwrap_or(-1),
                    String::from_utf8_lossy(&out.stdout).into_owned(),
                )
            })
            .map_err(|error| error.to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capabilities_advertise_cc_agent_kind_and_version() {
        let caps = build_claude_code_capabilities("2.1.191 (Claude Code)".into());
        assert_eq!(caps.agent_kind, AgentKind::ClaudeCode);
        assert_eq!(caps.agent_version, "2.1.191 (Claude Code)");
    }

    #[test]
    fn capabilities_feature_set_includes_shared_and_cc_specific() {
        let caps = build_claude_code_capabilities("v".into());
        // Shared
        for id in [
            CapabilityId::Shell,
            CapabilityId::Diff,
            CapabilityId::Mcp,
            CapabilityId::TokenCounters,
            CapabilityId::AuthStatus,
            CapabilityId::ReasoningEffort,
            CapabilityId::ImageInput,
            CapabilityId::Worktree,
        ] {
            assert!(caps.features.contains(&id), "missing shared {id:?}");
        }
        assert!(
            !caps.features.contains(&CapabilityId::StreamingMessages),
            "CC drops partial message deltas and must not advertise message streaming"
        );
        assert!(
            !caps.features.contains(&CapabilityId::StreamingReasoning),
            "CC drops partial reasoning deltas and must not advertise reasoning streaming"
        );
        assert!(
            !caps.features.contains(&CapabilityId::Approval),
            "CC approval response wire is speculative and must not be advertised"
        );
        // CC-only
        for id in [
            CapabilityId::ClaudeCodePermissionMode,
            CapabilityId::ClaudeCodeHooks,
            CapabilityId::ClaudeCodeOutputStyle,
            CapabilityId::ClaudeCodeSlashCommands,
            CapabilityId::ClaudeCodePlanMode,
            CapabilityId::ClaudeCodeBackgroundAgents,
            CapabilityId::ClaudeCodePluginDir,
            CapabilityId::ClaudeCodeForkSession,
        ] {
            assert!(caps.features.contains(&id), "missing cc-only {id:?}");
        }
        // No Codex-only features leaked in.
        assert!(!caps.features.contains(&CapabilityId::CodexSandboxMode));
        assert!(
            !caps
                .features
                .contains(&CapabilityId::CodexApprovalPersistence)
        );
        assert!(!caps.features.contains(&CapabilityId::CodexSkills));
        assert!(!caps.features.contains(&CapabilityId::CodexCustomPrompts));
    }

    #[test]
    fn capabilities_vendor_block_is_cc_with_all_six_permission_modes() {
        let caps = build_claude_code_capabilities("v".into());
        match caps.vendor {
            VendorCapabilities::ClaudeCode(cc) => {
                assert_eq!(cc.cli_version, "v");
                assert_eq!(cc.permission_modes.len(), 6);
                for m in [
                    ClaudeCodePermissionMode::Default,
                    ClaudeCodePermissionMode::AcceptEdits,
                    ClaudeCodePermissionMode::Plan,
                    ClaudeCodePermissionMode::Auto,
                    ClaudeCodePermissionMode::DontAsk,
                    ClaudeCodePermissionMode::BypassPermissions,
                ] {
                    assert!(cc.permission_modes.contains(&m), "missing {m:?}");
                }
                // Built-in output styles
                assert!(cc.output_styles.iter().any(|s| s == "default"));
                // Hook lifecycle names
                assert!(cc.hooks_supported.iter().any(|h| h == "PreToolUse"));
                assert!(cc.hooks_supported.iter().any(|h| h == "PostToolUse"));
                assert!(cc.hooks_supported.iter().any(|h| h == "SessionStart"));
            }
            VendorCapabilities::Codex(_) => panic!("expected CC vendor block"),
        }
    }

    #[test]
    fn capabilities_features_serialize_deterministically() {
        // BTreeSet guarantees ordering; round-trip through JSON to
        // keep the schema-drift snapshot stable.
        let caps = build_claude_code_capabilities("v".into());
        let a = serde_json::to_string(&caps).unwrap();
        let b = serde_json::to_string(&caps).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn probe_claude_code_version_accepts_injected_success() {
        let version = probe_claude_code_version_with_command(|| {
            Ok((0, "2.1.191 (Claude Code)\n".to_string()))
        });
        assert_eq!(version, "2.1.191 (Claude Code)");
    }

    #[test]
    fn probe_claude_code_version_degrades_on_injected_spawn_failure() {
        let version = probe_claude_code_version_with_command(|| Err("missing".to_string()));
        assert_eq!(version, "claude unknown");
    }

    #[test]
    fn probe_claude_code_version_degrades_on_injected_nonzero_or_empty_output() {
        assert_eq!(
            probe_claude_code_version_with_command(|| {
                Ok((1, "2.1.191 (Claude Code)".to_string()))
            }),
            "claude unknown"
        );
        assert_eq!(
            probe_claude_code_version_with_command(|| Ok((0, " \n".to_string()))),
            "claude unknown"
        );
    }
}
