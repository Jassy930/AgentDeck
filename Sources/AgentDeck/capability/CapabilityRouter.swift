import AppKit

// MARK: - CapabilityRouter (Task 6B)
//
// 唯一一处「按 agentKind 决定渲染哪个 vendor SubView」的开关；其他视图层
// 不允许直接出现 `if agentKind == .X`（Task 6C 的 lint 测试会校验）。
//
// 路由四个 UI 位置：
//   1. bottomView(for:in:)        — ApprovalCard 底部 vendor 槽
//   2. controlBarMiniView(for:)   — AgentControlBar 内嵌的 vendor 控件
//   3. sessionOptionsForm(for:)   — NewSessionDialog 中的 vendor 选项表单
//   4. tokenAuthMiniPanel(for:)   — token/认证状态 mini 面板
public enum CapabilityRouter {

    /// ApprovalCardView 调用：根据 `request.vendor` 返回对应的 vendor 面板。
    @MainActor
    public static func bottomView(
        for request: ActionRequest,
        in caps: SessionCapabilities
    ) -> NSView {
        switch request.vendor {
        case let .codex(approvalPolicyAtDecision, sandboxAtDecision, canPersist):
            return CodexApprovalPanel(
                approvalPolicy: approvalPolicyAtDecision,
                sandbox: sandboxAtDecision,
                canPersist: canPersist,
                capabilities: caps
            )
        case let .claudeCode(permissionModeAtDecision, toolName):
            return ClaudeCodePermissionPanel(
                permissionMode: permissionModeAtDecision,
                toolName: toolName,
                capabilities: caps
            )
        }
    }

    /// AgentControlBar 调用：按 agentKind 返回顶部 mini 控件。
    @MainActor
    public static func controlBarMiniView(for caps: SessionCapabilities) -> NSView {
        switch caps.agentKind {
        case .codex:
            return CodexControlsView(capabilities: caps)
        case .claudeCode:
            return ClaudeCodeControlsView(capabilities: caps)
        }
    }

    /// NewSessionDialog 调用：按 agentKind 返回 vendor 配置表单。
    @MainActor
    public static func sessionOptionsForm(
        for kind: AgentKind
    ) -> NSViewController & VendorOptionsFormVC {
        switch kind {
        case .codex:
            return CodexSessionOptionsForm()
        case .claudeCode:
            return ClaudeCodeSessionOptionsForm()
        }
    }

    /// token / auth 状态 mini 面板（由 vendor 实现）。
    @MainActor
    public static func tokenAuthMiniPanel(for caps: SessionCapabilities) -> NSView {
        AgentTokenAuthMiniPanel(capabilities: caps)
    }
}

// MARK: - VendorOptionsFormVC
//
// 所有 vendor 的「会话选项表单」实现此协议，向上层暴露 `buildVendorOptions()`，
// NewSessionDialog 据此构造 `SessionStart`。
public protocol VendorOptionsFormVC: AnyObject {
    @MainActor func buildVendorOptions() -> VendorSessionOptions
}
