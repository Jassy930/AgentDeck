//! Claude Code `SessionCapabilities` builder + probes.
//!
//! Phase 4 Task 4B. Replaces the 4A docstring stub with a real builder
//! used by `ClaudeCodeAdapter::capabilities`.
//!
//! ## CC capability surface
//!
//! `features` is a typed `BTreeSet<CapabilityId>` (deterministic
//! serialization). Shared capability 只有在对应 production wire 已验证后才广告；
//! canonical Runtime 通过已验证的 stdio `control_request/control_response` 广告
//! `Approval`，legacy compatibility constructor 仍隐藏它。canonical typed argv 未接通
//! hook control/事件交付，因此暂时隐藏 `ClaudeCodeHooks`；legacy compatibility surface
//! 保留既有广告。vendor block carries the 6 permission modes, a small curated
//! `output_styles` list, and the hook names CC accepts in user settings.
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
    build_capabilities(cli_version, false)
}

pub(super) fn build_canonical_claude_code_capabilities(cli_version: String) -> SessionCapabilities {
    build_capabilities(cli_version, true)
}

fn build_capabilities(cli_version: String, canonical_approval: bool) -> SessionCapabilities {
    let mut features: BTreeSet<CapabilityId> = [
        // —— Shared ——
        CapabilityId::StreamingMessages,
        CapabilityId::StreamingReasoning,
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
        CapabilityId::ClaudeCodeOutputStyle,
        CapabilityId::ClaudeCodeSlashCommands,
        CapabilityId::ClaudeCodePlanMode,
        CapabilityId::ClaudeCodeBackgroundAgents,
        CapabilityId::ClaudeCodePluginDir,
        CapabilityId::ClaudeCodeForkSession,
    ]
    .into_iter()
    .collect();
    if canonical_approval {
        features.insert(CapabilityId::Approval);
    } else {
        features.insert(CapabilityId::ClaudeCodeHooks);
    }

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
            // Hook lifecycle names CC accepts in `settings.json`; configured user hooks may
            // emit lifecycle frames even when canonical argv does not request hook opt-in.
            // Surfaced so the UI can
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

/// Probe the local `claude` binary's version string. Falls back to a
/// stable placeholder so capability emission never blocks on the probe.
///
/// Synchronous — the adapter caches the result behind a `OnceLock`, so
/// the shell-out happens at most once per process.
pub fn probe_claude_code_version() -> String {
    use std::process::Command;
    match Command::new("claude").arg("--version").output() {
        Ok(out) if out.status.success() => {
            let raw = String::from_utf8_lossy(&out.stdout);
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                "claude unknown".to_string()
            } else {
                trimmed.to_string()
            }
        }
        _ => "claude unknown".to_string(),
    }
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
            CapabilityId::StreamingMessages,
            CapabilityId::StreamingReasoning,
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
            !caps.features.contains(&CapabilityId::Approval),
            "unverified Claude Code approval wire must not be advertised"
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
    fn only_canonical_builder_advertises_verified_stdio_approval() {
        let legacy = build_claude_code_capabilities("legacy".into());
        let canonical = build_canonical_claude_code_capabilities("canonical".into());
        assert!(!legacy.features.contains(&CapabilityId::Approval));
        assert!(canonical.features.contains(&CapabilityId::Approval));
        assert!(
            !canonical.features.contains(&CapabilityId::ClaudeCodeHooks),
            "canonical typed argv has no verified hook control/delivery path"
        );
        assert!(
            !canonical
                .features
                .contains(&CapabilityId::CodexApprovalPersistence),
            "Claude Code P3.5 decisions remain persist=false"
        );
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
    fn probe_claude_code_version_returns_non_empty_string() {
        // Either claude is installed and we get a real version, or we
        // get "claude unknown". Both are non-empty.
        let v = probe_claude_code_version();
        assert!(!v.is_empty());
    }
}
