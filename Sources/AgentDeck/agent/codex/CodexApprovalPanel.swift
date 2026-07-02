import AppKit

// MARK: - CodexApprovalPanel (Task 6B)
//
// 渲染 Codex 在 ApprovalCardView 底部展示的「策略 / 沙箱 / 持久化」信息。
// 由 CapabilityRouter.bottomView(for:in:) 在 vendor == .codex 分支生成。
@MainActor
public final class CodexApprovalPanel: NSView {

    private let policyLabel = NSTextField(labelWithString: "")
    private let sandboxLabel = NSTextField(labelWithString: "")
    private let persistCheckbox = NSButton(
        checkboxWithTitle: "Persist this decision", target: nil, action: nil
    )

    /// 用户在勾选「Persist this decision」时变为 true；ApprovalCardView 的
    /// Approve 按钮回调读取该状态决定是否带 `persist: true`。
    public private(set) var persistEnabled: Bool = false

    public init(
        approvalPolicy: CodexApprovalPolicy,
        sandbox: CodexSandboxMode,
        canPersist: Bool,
        capabilities: SessionCapabilities
    ) {
        super.init(frame: .zero)
        _ = capabilities  // 保留参数以支持后续 caps-aware 渲染（暂不使用）

        policyLabel.font = .systemFont(ofSize: NSFont.systemFontSize(for: .small) + 1)
        policyLabel.textColor = DesignTokens.text2
        sandboxLabel.font = .systemFont(ofSize: NSFont.systemFontSize(for: .small) + 1)
        sandboxLabel.textColor = DesignTokens.text2

        policyLabel.stringValue = "Policy: \(approvalPolicy.rawValue)"
        sandboxLabel.stringValue = "Sandbox: \(sandbox.rawValue)"

        persistCheckbox.target = self
        persistCheckbox.action = #selector(togglePersist)
        persistCheckbox.isHidden = !canPersist

        let stack = NSStackView(views: [policyLabel, sandboxLabel, persistCheckbox])
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

    @objc private func togglePersist() {
        persistEnabled = persistCheckbox.state == .on
    }
}
