import AppKit

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
    public func bind(capabilities: SessionCapabilities) {
        subviews.forEach { $0.removeFromSuperview() }

        let icon = NSImageView()
        if let img = AgentKindIcon.compactImage(for: capabilities.agentKind) {
            icon.image = img
        } else {
            icon.image = NSImage(
                systemSymbolName: "circle.dashed", accessibilityDescription: nil
            )
        }
        icon.imageScaling = .scaleProportionallyDown
        icon.translatesAutoresizingMaskIntoConstraints = false

        let mini = CapabilityRouter.controlBarMiniView(for: capabilities)
        mini.translatesAutoresizingMaskIntoConstraints = false

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
        subviews.forEach { $0.removeFromSuperview() }
        miniView = nil
        iconView = nil
    }
}
