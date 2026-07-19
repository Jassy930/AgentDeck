import AgentDeckCore
import AppKit

/// AgentControlBar 只描述用户想修改的一个配置字段；SessionModel 会基于当前
/// RuntimeConversationConfigurationStateV2 重建完整配置并执行 revision CAS。
public enum RuntimeAgentControlMutation: Equatable, Sendable {
  case codexSandbox(CodexSandboxMode)
  case codexApprovalPolicy(CodexApprovalPolicy)
  case codexReasoningEffort(CodexReasoningEffort)
  case claudeCodePermissionMode(ClaudeCodePermissionMode)
  case claudeCodeOutputStyle(String?)
}

// MARK: - AgentControlBar (Task 6B)
//
// 会话顶部 mini 控制条：左侧 AgentKindIcon + 右侧 vendor 控件 (由
// CapabilityRouter.controlBarMiniView 决定)。SessionViewController 在
// `selectedRuntime?.capabilities` 改变时调用 `bind(capabilities:)`。
@MainActor
public final class AgentControlBar: NSView {

  /// 当前嵌入的 mini view（Codex/CC），暴露给测试 / 上层访问 typed controls。
  public private(set) var miniView: NSView?
  public private(set) var iconView: NSImageView?

  public override init(frame frameRect: NSRect) {
    super.init(frame: frameRect)
  }

  required init?(coder: NSCoder) { fatalError("init(coder:) is not supported") }

  /// 用 capabilities 重新装配子视图。无 capabilities 时应直接 `clear()`。
  /// Test-only overload — wires no callbacks. Production callers use
  /// `bind(capabilities:conversationID:onConfigurationChange:)`.
  public func bind(capabilities: SessionCapabilities) {
    bind(capabilities: capabilities, conversationID: nil, onConfigurationChange: nil)
  }

  /// Production bind: install the mini view and wire its callbacks
  /// so popup changes round-trip into the daemon as
  /// `VendorControlPayload` (C2 fix, v0.2 final review). Previously
  /// `bind(capabilities:)` instantiated the mini view but never
  /// assigned `onSandboxChange / onApprovalChange / onEffortChange /
  /// onPermissionChange / onOutputStyleChange`, so the user's toggles
  /// were silently dropped.
  ///
  /// `conversationID` 是 daemon 签发的 canonical identity；回调只携带字段级
  /// mutation，不复用旧 vendor-control payload 或 execution identity。
  public func bind(
    capabilities: SessionCapabilities,
    conversationID: RuntimeConversationID?,
    onConfigurationChange: ((RuntimeConversationID, RuntimeAgentControlMutation) -> Void)?
  ) {
    for subview in subviews {
      subview.removeFromSuperview()
    }

    let icon = NSImageView()
    if let img = AgentKindIcon.compactImage(for: capabilities.agentKind) {
      icon.image = img
    } else {
      icon.image = NSImage(
        systemSymbolName: "circle.dashed", accessibilityDescription: nil
      )
    }
    icon.contentTintColor = DesignTokens.text2  // 模板图着色，暗背景可见
    icon.imageScaling = .scaleProportionallyDown
    icon.translatesAutoresizingMaskIntoConstraints = false

    let mini = CapabilityRouter.controlBarMiniView(for: capabilities)
    mini.translatesAutoresizingMaskIntoConstraints = false

    // C2 fix: wire the typed control callbacks. We only forward
    // updates when both a conversationID and an onConfigurationChange sink
    // are present (Live sessions). For tests / preview both are
    // nil and the popups remain inert as before.
    if let conversationID, let sink = onConfigurationChange {
      if let codex = mini as? CodexControlsView {
        codex.onSandboxChange = { mode in
          sink(conversationID, .codexSandbox(mode))
        }
        codex.onApprovalChange = { policy in
          sink(conversationID, .codexApprovalPolicy(policy))
        }
        codex.onEffortChange = { effort in
          sink(conversationID, .codexReasoningEffort(effort))
        }
      } else if let cc = mini as? ClaudeCodeControlsView {
        cc.onPermissionChange = { mode in
          sink(conversationID, .claudeCodePermissionMode(mode))
        }
        cc.onOutputStyleChange = { name in
          sink(conversationID, .claudeCodeOutputStyle(name))
        }
      }
    }

    addSubview(icon)
    addSubview(mini)
    self.iconView = icon
    self.miniView = mini

    NSLayoutConstraint.activate([
      icon.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 4),
      icon.centerYAnchor.constraint(equalTo: centerYAnchor),
      icon.widthAnchor.constraint(equalToConstant: 18),
      icon.heightAnchor.constraint(equalToConstant: 18),

      mini.leadingAnchor.constraint(equalTo: icon.trailingAnchor, constant: 8),
      mini.trailingAnchor.constraint(lessThanOrEqualTo: trailingAnchor, constant: -8),
      mini.centerYAnchor.constraint(equalTo: centerYAnchor),
    ])
  }

  /// 清空子视图（无活动 runtime 时）。
  public func clear() {
    for subview in subviews {
      subview.removeFromSuperview()
    }
    miniView = nil
    iconView = nil
  }
}
