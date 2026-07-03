import AppKit
import AgentDeckCore

// MARK: - ApprovalCardView (Task 8 → T6B vendor slot)
//
// The ONE card in the conversation pane (Design law D7: only approval draws a
// card). Ports the SwiftUI `approvalRow` (SessionView.swift ~915):
//
//   ┌─────────────────────────────────────────────────────────┐
//   │ 🖐  <title>                            [ Deny ] [Approve ]│
//   │ <detail, monospaced, secondary>                          │
//   │ ─── vendor slot (CapabilityRouter.bottomView) ────────── │
//   │ Codex:  Policy: on-request   Sandbox: workspace-write    │
//   │         [Persist this decision]                          │
//   │ Claude: Permission mode: default   Tool: Bash            │
//   └─────────────────────────────────────────────────────────┘
//
// Backed by a pending `ActionRequest` (ThreadRuntimeModel.swift). Approve/Deny
// route through `SessionModel.decidePendingAction(.approve|.deny, persist:)`;
// the `persist` flag is read from the vendor SubView (only Codex sets it for now).
@MainActor
final class ApprovalCardView: NSView {

    private weak var model: SessionModel?

    private let icon = NSImageView()
    private let titleLabel: NSTextField = {
        let field = NSTextField(labelWithString: "")
        field.font = ConversationRowMetrics.calloutMediumFont
        field.textColor = DesignTokens.text
        field.lineBreakMode = .byTruncatingTail
        field.translatesAutoresizingMaskIntoConstraints = false
        field.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        return field
    }()
    private let detailLabel: NSTextField = {
        let field = NSTextField(labelWithString: "")
        field.font = ConversationRowMetrics.monoCalloutFont
        field.textColor = DesignTokens.text2
        field.lineBreakMode = .byWordWrapping
        field.maximumNumberOfLines = 0
        field.isSelectable = true
        field.translatesAutoresizingMaskIntoConstraints = false
        return field
    }()
    private let denyButton = NSButton(title: "Deny", target: nil, action: nil)
    private let approveButton = NSButton(title: "Approve", target: nil, action: nil)

    /// 容纳 vendor 槽位的纵向 stack（垂直延伸 ApprovalCard 高度）。
    private let column: NSStackView = {
        let s = NSStackView()
        s.orientation = .vertical
        s.alignment = .leading
        s.spacing = 8
        s.translatesAutoresizingMaskIntoConstraints = false
        return s
    }()

    /// 当前嵌入的 vendor 视图（CodexApprovalPanel 或 ClaudeCodePermissionPanel）。
    private(set) var vendorBottomView: NSView?

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        build()
    }

    required init?(coder: NSCoder) {
        super.init(coder: coder)
        build()
    }

    private func build() {
        wantsLayer = true
        layer?.cornerRadius = DesignTokens.radiusMd
        layer?.cornerCurve = .continuous
        layer?.borderWidth = 1
        layer?.borderColor = DesignTokens.border.cgColor
        layer?.backgroundColor = DesignTokens.surface.cgColor
        layer?.shadowColor = DesignTokens.panelShadowColor.cgColor
        layer?.shadowOpacity = 1
        layer?.shadowRadius = DesignTokens.panelShadowBlur / 2
        layer?.shadowOffset = DesignTokens.panelShadowOffset
        layer?.masksToBounds = false

        icon.translatesAutoresizingMaskIntoConstraints = false
        icon.image = NSImage(systemSymbolName: "hand.raised.fill", accessibilityDescription: nil)
        icon.contentTintColor = DesignTokens.accent
        icon.imageScaling = .scaleProportionallyDown

        denyButton.target = self
        denyButton.action = #selector(deny)
        denyButton.bezelStyle = .rounded
        denyButton.translatesAutoresizingMaskIntoConstraints = false

        approveButton.target = self
        approveButton.action = #selector(approve)
        approveButton.bezelStyle = .rounded
        approveButton.keyEquivalent = "\r"
        approveButton.translatesAutoresizingMaskIntoConstraints = false

        let headerRow = NSStackView(views: [icon, titleLabel, denyButton, approveButton])
        headerRow.orientation = .horizontal
        headerRow.alignment = .centerY
        headerRow.spacing = 8
        headerRow.translatesAutoresizingMaskIntoConstraints = false
        headerRow.setCustomSpacing(8, after: icon)
        titleLabel.setContentHuggingPriority(.defaultLow, for: .horizontal)

        column.addArrangedSubview(headerRow)
        column.addArrangedSubview(detailLabel)

        addSubview(column)
        NSLayoutConstraint.activate([
            icon.widthAnchor.constraint(equalToConstant: 16),
            icon.heightAnchor.constraint(equalToConstant: 16),
            column.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 12),
            column.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -12),
            column.topAnchor.constraint(equalTo: topAnchor, constant: 10),
            column.bottomAnchor.constraint(equalTo: bottomAnchor, constant: -10),
            headerRow.leadingAnchor.constraint(equalTo: column.leadingAnchor),
            headerRow.trailingAnchor.constraint(equalTo: column.trailingAnchor),
            detailLabel.leadingAnchor.constraint(equalTo: column.leadingAnchor),
            detailLabel.trailingAnchor.constraint(equalTo: column.trailingAnchor),
        ])
    }

    /// Bind the card to the pending request and the model that decides it.
    ///
    /// `capabilities` 决定 vendor 槽位的渲染；为空时回退到只有 trunk 的旧
    /// 行为（兼容 capabilities 未到达前的窗口期）。
    func configure(
        action: PendingActionRequest,
        model: SessionModel,
        capabilities: SessionCapabilities? = nil
    ) {
        self.model = model
        let title: String
        switch action.actionKind {
        case .executeCommand: title = "Run command"
        case .editFiles: title = "Edit files"
        case .grantExtraPermission: title = "Grant extra permission"
        }
        titleLabel.stringValue = title
        detailLabel.stringValue = action.summary
        detailLabel.isHidden = action.summary.isEmpty

        // 替换 vendor 槽位
        vendorBottomView?.removeFromSuperview()
        vendorBottomView = nil
        guard let capabilities else { return }
        let request = ActionRequest(
            requestId: action.requestId,
            kind: action.actionKind,
            summary: action.summary,
            vendor: action.vendor
        )
        let bottom = CapabilityRouter.bottomView(for: request, in: capabilities)
        bottom.translatesAutoresizingMaskIntoConstraints = false
        column.addArrangedSubview(bottom)
        bottom.leadingAnchor.constraint(equalTo: column.leadingAnchor).isActive = true
        bottom.trailingAnchor.constraint(equalTo: column.trailingAnchor).isActive = true
        vendorBottomView = bottom
    }

    @objc private func approve() {
        let persist = (vendorBottomView as? CodexApprovalPanel)?.persistEnabled ?? false
        model?.decidePendingAction(.approve, persist: persist)
    }

    @objc private func deny() {
        model?.decidePendingAction(.deny)
    }
}
