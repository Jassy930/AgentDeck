import AppKit

// MARK: - CodexControlsView (Task 6B)
//
// AgentControlBar 中 Codex 会话的 mini 控件：
// `[ sandbox ▾ ]  [ approval ▾ ]  [ effort ▾ ]`
// 控件变更通过闭包回调；ControlBar 把它转译为 `vendorControl` 发送给 daemon。
@MainActor
public final class CodexControlsView: NSView {

    public var onSandboxChange: ((CodexSandboxMode) -> Void)?
    public var onApprovalChange: ((CodexApprovalPolicy) -> Void)?
    public var onEffortChange: ((CodexReasoningEffort) -> Void)?

    private let sandboxPopup = NSPopUpButton(frame: .zero, pullsDown: false)
    private let approvalPopup = NSPopUpButton(frame: .zero, pullsDown: false)
    private let effortPopup = NSPopUpButton(frame: .zero, pullsDown: false)

    // 索引 → 枚举值，用于把 popup selectedIndex 映射回 typed value。
    private var sandboxOrder: [CodexSandboxMode] = []
    private var approvalOrder: [CodexApprovalPolicy] = [.onRequest, .never, .always]
    private var effortOrder: [CodexReasoningEffort] = []

    public init(capabilities: SessionCapabilities) {
        super.init(frame: .zero)
        guard case let .codex(codexCaps) = capabilities.vendor else { return }

        // Sandbox popup — driven by capabilities.sandboxModes
        sandboxOrder = codexCaps.sandboxModes
        sandboxPopup.addItems(withTitles: sandboxOrder.map(\.rawValue))
        sandboxPopup.target = self
        sandboxPopup.action = #selector(sandboxChanged)

        // Approval popup — fixed three options
        approvalPopup.addItems(withTitles: approvalOrder.map(\.rawValue))
        approvalPopup.target = self
        approvalPopup.action = #selector(approvalChanged)

        // Effort popup — driven by capabilities.reasoningEffortLevels
        effortOrder = codexCaps.reasoningEffortLevels
        effortPopup.addItems(withTitles: effortOrder.map(\.rawValue))
        effortPopup.target = self
        effortPopup.action = #selector(effortChanged)

        let stack = NSStackView(views: [sandboxPopup, approvalPopup, effortPopup])
        stack.orientation = .horizontal
        stack.alignment = .centerY
        stack.spacing = 6
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

    // MARK: - Actions

    @objc private func sandboxChanged() {
        let idx = sandboxPopup.indexOfSelectedItem
        guard sandboxOrder.indices.contains(idx) else { return }
        onSandboxChange?(sandboxOrder[idx])
    }

    @objc private func approvalChanged() {
        let idx = approvalPopup.indexOfSelectedItem
        guard approvalOrder.indices.contains(idx) else { return }
        onApprovalChange?(approvalOrder[idx])
    }

    @objc private func effortChanged() {
        let idx = effortPopup.indexOfSelectedItem
        guard effortOrder.indices.contains(idx) else { return }
        onEffortChange?(effortOrder[idx])
    }
}
