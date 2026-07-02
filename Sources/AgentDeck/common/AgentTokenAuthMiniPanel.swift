import AppKit

// MARK: - AgentTokenAuthMiniPanel (Task 6B)
//
// 顶部控制条上的 token/auth mini 面板：
// 左侧展示当前 turn 的 token 计数 (`tokens: in/out`)，右侧根据 agentKind
// 路由到不同的 auth 状态视图（Claude 用 ClaudeCodeAuthStatusBadge；
// Codex 暂时给一个占位 label，等 daemon 提供 codex auth 状态后补全）。
@MainActor
public final class AgentTokenAuthMiniPanel: NSView {

    public let agentKind: AgentKind

    private let tokenLabel: NSTextField = {
        let f = NSTextField(labelWithString: "tokens: -")
        f.font = .systemFont(ofSize: NSFont.systemFontSize(for: .mini))
        f.textColor = DesignTokens.text3
        return f
    }()
    private let authView: NSView
    private let claudeBadge: ClaudeCodeAuthStatusBadge?

    public init(capabilities: SessionCapabilities) {
        self.agentKind = capabilities.agentKind
        switch capabilities.agentKind {
        case .codex:
            let codexLabel = NSTextField(labelWithString: "Codex · auth")
            codexLabel.font = .systemFont(ofSize: NSFont.systemFontSize(for: .mini))
            codexLabel.textColor = DesignTokens.text2
            authView = codexLabel
            claudeBadge = nil
        case .claudeCode:
            let badge = ClaudeCodeAuthStatusBadge(frame: .zero)
            badge.update(state: .unknown)
            authView = badge
            claudeBadge = badge
        }
        super.init(frame: .zero)
        let stack = NSStackView(views: [tokenLabel, authView])
        stack.orientation = .horizontal
        stack.alignment = .centerY
        stack.spacing = 8
        stack.translatesAutoresizingMaskIntoConstraints = false
        addSubview(stack)
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: leadingAnchor),
            stack.trailingAnchor.constraint(lessThanOrEqualTo: trailingAnchor),
            stack.topAnchor.constraint(equalTo: topAnchor),
            stack.bottomAnchor.constraint(equalTo: bottomAnchor),
        ])
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) is not supported") }

    public func updateTokenCount(input: UInt64?, output: UInt64?) {
        if let i = input, let o = output {
            tokenLabel.stringValue = "tokens: \(i)/\(o)"
        } else {
            tokenLabel.stringValue = "tokens: -"
        }
    }

    public func updateClaudeAuth(state: ClaudeAuthState) {
        claudeBadge?.update(state: state)
    }
}
