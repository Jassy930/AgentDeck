import AppKit

// MARK: - ClaudeCodePermissionPanel (Task 6B)
//
// Claude Code 在 ApprovalCardView 底部展示的「Permission mode + 工具名」面板。
// 当前 v0.2 仅为只读展示；Plan/Hook 等交互留待 T6.9。
@MainActor
public final class ClaudeCodePermissionPanel: NSView {

    public let permissionMode: ClaudeCodePermissionMode
    public let toolName: String

    public init(
        permissionMode: ClaudeCodePermissionMode,
        toolName: String,
        capabilities: SessionCapabilities
    ) {
        self.permissionMode = permissionMode
        self.toolName = toolName
        super.init(frame: .zero)
        _ = capabilities  // reserved

        let modeLabel = NSTextField(labelWithString: "Permission mode: \(permissionMode.rawValue)")
        modeLabel.font = .systemFont(ofSize: NSFont.systemFontSize(for: .small) + 1)
        modeLabel.textColor = DesignTokens.text2

        let toolLabel = NSTextField(labelWithString: "Tool: \(toolName)")
        toolLabel.font = .systemFont(ofSize: NSFont.systemFontSize(for: .small) + 1)
        toolLabel.textColor = DesignTokens.text2

        let stack = NSStackView(views: [modeLabel, toolLabel])
        stack.orientation = .horizontal
        stack.alignment = .centerY
        stack.spacing = 12
        stack.translatesAutoresizingMaskIntoConstraints = false
        addSubview(stack)
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 8),
            stack.trailingAnchor.constraint(lessThanOrEqualTo: trailingAnchor, constant: -8),
            stack.topAnchor.constraint(equalTo: topAnchor, constant: 4),
            stack.bottomAnchor.constraint(equalTo: bottomAnchor, constant: -4),
        ])
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) is not supported") }
}
