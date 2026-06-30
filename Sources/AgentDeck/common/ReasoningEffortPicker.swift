import AppKit

// MARK: - ReasoningEffortPicker (Task 6B)
//
// Common 控件：根据 SessionCapabilities 选择推理 effort 等级。
// Codex 直接读 `capabilities.reasoningEffortLevels`；Claude Code 暂用
// 一组通用候选值（low/medium/high/xhigh/max），后续可由 daemon 通过
// `agentCapabilities` 提供。
@MainActor
public final class ReasoningEffortPicker: NSView {

    public var onChange: ((String) -> Void)?
    public let availableLevels: [String]
    private let popup = NSPopUpButton(frame: .zero, pullsDown: false)

    public init(capabilities: SessionCapabilities) {
        switch capabilities.vendor {
        case .codex(let codexCaps):
            self.availableLevels = codexCaps.reasoningEffortLevels.map(\.rawValue)
        case .claudeCode:
            self.availableLevels = ["low", "medium", "high", "xhigh", "max"]
        }
        super.init(frame: .zero)
        build()
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) is not supported") }

    private func build() {
        popup.translatesAutoresizingMaskIntoConstraints = false
        popup.addItems(withTitles: availableLevels)
        popup.target = self
        popup.action = #selector(selectionChanged)
        addSubview(popup)
        NSLayoutConstraint.activate([
            popup.leadingAnchor.constraint(equalTo: leadingAnchor),
            popup.trailingAnchor.constraint(equalTo: trailingAnchor),
            popup.topAnchor.constraint(equalTo: topAnchor),
            popup.bottomAnchor.constraint(equalTo: bottomAnchor),
        ])
    }

    @objc private func selectionChanged() {
        let idx = popup.indexOfSelectedItem
        guard availableLevels.indices.contains(idx) else { return }
        onChange?(availableLevels[idx])
    }
}
