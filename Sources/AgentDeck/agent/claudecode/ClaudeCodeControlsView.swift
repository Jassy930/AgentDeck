import AppKit

// MARK: - ClaudeCodeControlsView (Task 6B)
//
// AgentControlBar 中 Claude Code 会话的 mini 控件：
// `[ permission ▾ ]  [ Plan Mode (badge) ]  [ output style ▾ ]`
// Plan Mode badge 默认隐藏，由 runtime 在进入 plan 时调用 `setPlanModeVisible(true)`。
@MainActor
public final class ClaudeCodeControlsView: NSView {

    public var onPermissionChange: ((ClaudeCodePermissionMode) -> Void)?
    public var onOutputStyleChange: ((String?) -> Void)?

    private let permissionPopup = NSPopUpButton(frame: .zero, pullsDown: false)
    private let outputStylePopup = NSPopUpButton(frame: .zero, pullsDown: false)
    private let planBadge: NSTextField = {
        let f = NSTextField(labelWithString: "Plan Mode")
        f.font = .systemFont(ofSize: NSFont.systemFontSize(for: .mini), weight: .medium)
        f.textColor = DesignTokens.info
        f.isBezeled = false
        f.drawsBackground = false
        f.isHidden = true
        return f
    }()

    private var permissionOrder: [ClaudeCodePermissionMode] = []
    private var outputStyleOrder: [String?] = []

    public init(capabilities: SessionCapabilities) {
        super.init(frame: .zero)
        guard case let .claudeCode(ccCaps) = capabilities.vendor else { return }

        permissionOrder = ccCaps.permissionModes
        permissionPopup.addItems(withTitles: permissionOrder.map(\.rawValue))
        permissionPopup.target = self
        permissionPopup.action = #selector(permissionChanged)

        // Output style: 第一项是 "default" (nil)，后续为 caps 中声明的字符串。
        outputStyleOrder = [nil] + ccCaps.outputStyles.map { Optional($0) }
        outputStylePopup.addItems(withTitles: ["default"] + ccCaps.outputStyles)
        outputStylePopup.target = self
        outputStylePopup.action = #selector(outputStyleChanged)

        let stack = NSStackView(views: [permissionPopup, planBadge, outputStylePopup])
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

    public func setPlanModeVisible(_ visible: Bool) {
        planBadge.isHidden = !visible
    }

    // MARK: - Actions

    @objc private func permissionChanged() {
        let idx = permissionPopup.indexOfSelectedItem
        guard permissionOrder.indices.contains(idx) else { return }
        onPermissionChange?(permissionOrder[idx])
    }

    @objc private func outputStyleChanged() {
        let idx = outputStylePopup.indexOfSelectedItem
        guard outputStyleOrder.indices.contains(idx) else { return }
        onOutputStyleChange?(outputStyleOrder[idx])
    }
}
