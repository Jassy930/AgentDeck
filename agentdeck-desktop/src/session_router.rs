use agentdeck_protocol::{
    CapabilityId, ClaudeCodePermissionMode, ClaudeCodeSessionOptions, CodexApprovalPolicy,
    CodexReasoningEffort, CodexSandboxMode, CodexSessionOptions, SessionCapabilities,
    VendorCapabilities, VendorSessionOptions,
};

pub struct SessionRouter<'a>(pub &'a SessionCapabilities);

impl SessionRouter<'_> {
    pub fn supports_messages(&self) -> bool {
        self.0.features.contains(&CapabilityId::StreamingMessages)
    }

    pub fn supports_approval(&self) -> bool {
        self.0.features.contains(&CapabilityId::Approval)
    }

    pub fn start_options(&self) -> Result<VendorSessionOptions, String> {
        match &self.0.vendor {
            VendorCapabilities::Codex(capabilities) => {
                if !capabilities
                    .sandbox_modes
                    .contains(&CodexSandboxMode::ReadOnly)
                {
                    return Err("当前能力不支持桌面所需的只读沙箱".into());
                }
                if !capabilities
                    .reasoning_effort_levels
                    .contains(&CodexReasoningEffort::Medium)
                {
                    return Err("当前能力不支持桌面所需的 medium 推理强度".into());
                }
                Ok(VendorSessionOptions::Codex(CodexSessionOptions {
                    approval_policy: CodexApprovalPolicy::Never,
                    sandbox: CodexSandboxMode::ReadOnly,
                    persist_approval: false,
                    reasoning_effort: CodexReasoningEffort::Medium,
                    mcp_overrides: vec![],
                }))
            }
            VendorCapabilities::ClaudeCode(capabilities) => {
                if !capabilities
                    .permission_modes
                    .contains(&ClaudeCodePermissionMode::Default)
                {
                    return Err("当前能力不支持桌面所需的 default 权限模式".into());
                }
                Ok(VendorSessionOptions::ClaudeCode(ClaudeCodeSessionOptions {
                    permission_mode: ClaudeCodePermissionMode::Default,
                    model: None,
                    effort: None,
                    hooks: vec![],
                    output_style: None,
                    allowed_tools: None,
                    disallowed_tools: None,
                    mcp_config_path: None,
                    plugin_dirs: vec![],
                    worktree: None,
                    session_name: None,
                    session_id: None,
                }))
            }
        }
    }
}

#[cfg(test)]
pub(crate) fn test_capabilities(kind: agentdeck_protocol::AgentKind) -> SessionCapabilities {
    use agentdeck_protocol::{AgentKind, ClaudeCodeCapabilities, CodexCapabilities};
    use std::collections::BTreeSet;

    let (features, vendor) = match kind {
        AgentKind::Codex => (
            BTreeSet::from([CapabilityId::StreamingMessages]),
            VendorCapabilities::Codex(CodexCapabilities {
                sandbox_modes: vec![CodexSandboxMode::ReadOnly],
                persistence_supported: false,
                reasoning_effort_levels: vec![CodexReasoningEffort::Medium],
            }),
        ),
        AgentKind::ClaudeCode => (
            BTreeSet::from([CapabilityId::StreamingMessages, CapabilityId::Approval]),
            VendorCapabilities::ClaudeCode(ClaudeCodeCapabilities {
                permission_modes: vec![ClaudeCodePermissionMode::Default],
                cli_version: "test".into(),
                ..Default::default()
            }),
        ),
    };
    SessionCapabilities {
        agent_kind: kind,
        agent_version: "test".into(),
        features,
        vendor,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentdeck_protocol::AgentKind;

    #[test]
    fn session_ui_does_not_branch_on_vendor_identity() {
        let shell = include_str!("shell.rs");
        for implementation in [
            include_str!("live.rs")
                .split("#[cfg(test)]")
                .next()
                .unwrap(),
            shell
                .split("fn current_live(")
                .nth(1)
                .unwrap()
                .split("fn load_machine(")
                .next()
                .unwrap(),
            shell
                .split("fn render_composer(")
                .nth(1)
                .unwrap()
                .split("\n}\n")
                .next()
                .unwrap(),
        ] {
            assert!(!implementation.contains("AgentKind::Codex"));
            assert!(!implementation.contains("AgentKind::ClaudeCode"));
        }
    }

    #[test]
    fn default_options_follow_typed_vendor_capabilities() {
        let mut capabilities = test_capabilities(AgentKind::Codex);
        capabilities.agent_kind = AgentKind::ClaudeCode;
        let VendorSessionOptions::Codex(options) =
            SessionRouter(&capabilities).start_options().unwrap()
        else {
            panic!("options must follow typed vendor capabilities");
        };
        assert_eq!(options.sandbox, CodexSandboxMode::ReadOnly);
        assert_eq!(options.reasoning_effort, CodexReasoningEffort::Medium);
        assert_eq!(options.approval_policy, CodexApprovalPolicy::Never);
        assert!(!options.persist_approval);
        assert!(options.mcp_overrides.is_empty());

        let capabilities = test_capabilities(AgentKind::ClaudeCode);
        let VendorSessionOptions::ClaudeCode(options) =
            SessionRouter(&capabilities).start_options().unwrap()
        else {
            panic!("expected Claude Code options");
        };
        assert_eq!(options.permission_mode, ClaudeCodePermissionMode::Default);
    }

    #[test]
    fn unsupported_defaults_do_not_fall_back_to_broader_permissions() {
        let mut capabilities = test_capabilities(AgentKind::Codex);
        let VendorCapabilities::Codex(vendor) = &mut capabilities.vendor else {
            unreachable!();
        };
        vendor.sandbox_modes = vec![CodexSandboxMode::FullAccess];
        assert!(SessionRouter(&capabilities).start_options().is_err());

        let mut capabilities = test_capabilities(AgentKind::Codex);
        let VendorCapabilities::Codex(vendor) = &mut capabilities.vendor else {
            unreachable!();
        };
        vendor.reasoning_effort_levels = vec![CodexReasoningEffort::High];
        assert!(SessionRouter(&capabilities).start_options().is_err());

        let mut capabilities = test_capabilities(AgentKind::ClaudeCode);
        let VendorCapabilities::ClaudeCode(vendor) = &mut capabilities.vendor else {
            unreachable!();
        };
        vendor.permission_modes = vec![ClaudeCodePermissionMode::BypassPermissions];
        assert!(SessionRouter(&capabilities).start_options().is_err());
    }

    #[test]
    fn shared_controls_follow_advertised_features() {
        let mut capabilities = test_capabilities(AgentKind::ClaudeCode);
        assert!(SessionRouter(&capabilities).supports_messages());
        assert!(SessionRouter(&capabilities).supports_approval());
        capabilities.features.remove(&CapabilityId::Approval);
        assert!(SessionRouter(&capabilities).supports_messages());
        assert!(!SessionRouter(&capabilities).supports_approval());
        capabilities.features.clear();
        assert!(!SessionRouter(&capabilities).supports_messages());
        assert!(!SessionRouter(&capabilities).supports_approval());
    }
}
