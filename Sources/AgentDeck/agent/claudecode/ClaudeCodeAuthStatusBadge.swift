import AppKit

// MARK: - ClaudeAuthState (Task 6B)
//
// Claude Code 客户端登录态的 UI 表示。实时探测由后端 daemon 完成（capability
// 协议 `authStatus`），本视图只负责显示传入的状态。
public enum ClaudeAuthState: Sendable {
    case loggedInSubscription
    case loggedInConsoleApiKey
    case notAuthenticated
    case unknown
}

// MARK: - ClaudeCodeAuthStatusBadge (Task 6B)
//
// 一个紧凑的 token-badge，展示 Claude 登录态。AgentTokenAuthMiniPanel 在
// agentKind == .claudeCode 分支会嵌入此视图。
@MainActor
public final class ClaudeCodeAuthStatusBadge: NSView {

    private let label: NSTextField = {
        let f = NSTextField(labelWithString: "Claude · ?")
        f.font = .systemFont(ofSize: NSFont.systemFontSize(for: .mini))
        f.textColor = DesignTokens.text2
        f.translatesAutoresizingMaskIntoConstraints = false
        return f
    }()

    public override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        addSubview(label)
        NSLayoutConstraint.activate([
            label.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 4),
            label.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -4),
            label.centerYAnchor.constraint(equalTo: centerYAnchor),
        ])
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) is not supported") }

    public func update(state: ClaudeAuthState) {
        switch state {
        case .loggedInSubscription:
            label.stringValue = "Claude · Pro/Max"
        case .loggedInConsoleApiKey:
            label.stringValue = "Claude · Console API"
        case .notAuthenticated:
            label.stringValue = "Claude · 未登录"
        case .unknown:
            label.stringValue = "Claude · ?"
        }
    }
}
