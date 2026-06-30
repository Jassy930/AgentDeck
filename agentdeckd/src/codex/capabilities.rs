//! Codex SessionCapabilities builder + version probe.
//!
//! Phase 3 Task 3A. The caller (Task 3B's CodexAdapter::capabilities) probes
//! the local `codex` binary version once at adapter construction and then
//! calls `build_codex_capabilities` to produce a `SessionCapabilities` that
//! the daemon emits as `ServerEvent::SessionCapabilities` before any
//! `AgentItem` (invariant N7).
//!
//! The capability set here mirrors what Codex's app-server supports today:
//! streaming messages + reasoning, shell execution, file diffs, approval
//! requests, MCP tools, token usage, auth status, reasoning effort
//! selection, image input, worktrees, plus Codex-only features
//! (sandbox modes, approval persistence, skills, custom prompts).

use std::collections::BTreeSet;

use agentdeck_protocol::{
    AgentKind, CapabilityId, CodexApprovalPolicy, CodexCapabilities,
    CodexReasoningEffort, CodexSandboxMode, SessionCapabilities, VendorCapabilities,
};

/// Build the `SessionCapabilities` payload for a Codex session.
///
/// `version` is the string returned by `codex --version` (or
/// `probe_codex_version()` below for the default case). It is wire-visible
/// to clients so they can route UI features by both `features` set and
/// optional version-string heuristics.
pub fn build_codex_capabilities(version: String) -> SessionCapabilities {
    let features: BTreeSet<CapabilityId> = [
        // —— Shared (Codex side of the symmetry constraint N5) ——
        CapabilityId::StreamingMessages,
        CapabilityId::StreamingReasoning,
        CapabilityId::Shell,
        CapabilityId::Diff,
        CapabilityId::Approval,
        CapabilityId::Mcp,
        CapabilityId::TokenCounters,
        CapabilityId::AuthStatus,
        CapabilityId::ReasoningEffort,
        CapabilityId::ImageInput,
        CapabilityId::Worktree,
        // —— Codex-only ——
        CapabilityId::CodexSandboxMode,
        CapabilityId::CodexApprovalPersistence,
        CapabilityId::CodexSkills,
        CapabilityId::CodexCustomPrompts,
    ]
    .into_iter()
    .collect();

    SessionCapabilities {
        agent_kind: AgentKind::Codex,
        agent_version: version,
        features,
        vendor: VendorCapabilities::Codex(CodexCapabilities {
            sandbox_modes: vec![
                CodexSandboxMode::ReadOnly,
                CodexSandboxMode::WorkspaceWrite,
                CodexSandboxMode::FullAccess,
            ],
            persistence_supported: true,
            reasoning_effort_levels: vec![
                CodexReasoningEffort::Minimal,
                CodexReasoningEffort::Low,
                CodexReasoningEffort::Medium,
                CodexReasoningEffort::High,
            ],
        }),
    }
}

/// All Codex approval policies the adapter supports (exposed so the UI can
/// build a picker without hard-coding the enum variants — keeps the wire
/// shape and the picker in sync as the protocol grows).
pub fn supported_approval_policies() -> Vec<CodexApprovalPolicy> {
    vec![
        CodexApprovalPolicy::OnRequest,
        CodexApprovalPolicy::Never,
        CodexApprovalPolicy::Always,
    ]
}

/// Probe the local `codex` binary's version string. Falls back to a stable
/// placeholder so capability emission never blocks on the probe.
///
/// Note: this is synchronous and shells out to `codex --version`. Task 3B's
/// adapter calls it once at construction, not per-session, so the cost is
/// negligible. If the binary is missing the placeholder makes it obvious
/// in the SessionCapabilities event (which downstream diagnostics surface).
pub fn probe_codex_version() -> String {
    use std::process::Command;
    match Command::new("codex").arg("--version").output() {
        Ok(out) if out.status.success() => {
            let raw = String::from_utf8_lossy(&out.stdout);
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                "codex unknown".to_string()
            } else {
                trimmed.to_string()
            }
        }
        _ => "codex unknown".to_string(),
    }
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
    fn capabilities_feature_set_includes_shared_and_codex_specific() {
        let caps = build_codex_capabilities("v".into());
        // Shared
        assert!(caps.features.contains(&CapabilityId::StreamingMessages));
        assert!(caps.features.contains(&CapabilityId::StreamingReasoning));
        assert!(caps.features.contains(&CapabilityId::Shell));
        assert!(caps.features.contains(&CapabilityId::Diff));
        assert!(caps.features.contains(&CapabilityId::Approval));
        assert!(caps.features.contains(&CapabilityId::Mcp));
        assert!(caps.features.contains(&CapabilityId::TokenCounters));
        assert!(caps.features.contains(&CapabilityId::AuthStatus));
        assert!(caps.features.contains(&CapabilityId::ReasoningEffort));
        assert!(caps.features.contains(&CapabilityId::ImageInput));
        assert!(caps.features.contains(&CapabilityId::Worktree));
        // Codex-only
        assert!(caps.features.contains(&CapabilityId::CodexSandboxMode));
        assert!(caps.features.contains(&CapabilityId::CodexApprovalPersistence));
        assert!(caps.features.contains(&CapabilityId::CodexSkills));
        assert!(caps.features.contains(&CapabilityId::CodexCustomPrompts));
        // No Claude-Code features leaked in.
        assert!(!caps.features.contains(&CapabilityId::ClaudeCodePermissionMode));
        assert!(!caps.features.contains(&CapabilityId::ClaudeCodeHooks));
    }

    #[test]
    fn capabilities_vendor_block_is_codex_with_all_sandbox_modes() {
        let caps = build_codex_capabilities("v".into());
        match caps.vendor {
            VendorCapabilities::Codex(codex) => {
                assert!(codex.persistence_supported);
                assert_eq!(codex.sandbox_modes.len(), 3);
                assert!(codex.sandbox_modes.contains(&CodexSandboxMode::ReadOnly));
                assert!(codex.sandbox_modes.contains(&CodexSandboxMode::WorkspaceWrite));
                assert!(codex.sandbox_modes.contains(&CodexSandboxMode::FullAccess));
                assert_eq!(codex.reasoning_effort_levels.len(), 4);
                assert!(codex.reasoning_effort_levels.contains(&CodexReasoningEffort::Minimal));
                assert!(codex.reasoning_effort_levels.contains(&CodexReasoningEffort::High));
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
    fn supported_approval_policies_covers_all_three() {
        let p = supported_approval_policies();
        assert!(p.contains(&CodexApprovalPolicy::OnRequest));
        assert!(p.contains(&CodexApprovalPolicy::Never));
        assert!(p.contains(&CodexApprovalPolicy::Always));
    }

    #[test]
    fn probe_codex_version_returns_non_empty_string() {
        // Either we have codex installed and get a real version, or we get
        // the "codex unknown" fallback — either way the function MUST NOT
        // panic and MUST return a non-empty string the adapter can put on
        // the wire.
        let v = probe_codex_version();
        assert!(!v.is_empty());
    }
}
