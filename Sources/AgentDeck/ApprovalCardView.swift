import AppKit

// MARK: - ApprovalCardView (Task 8)
//
// The ONE card in the conversation pane (Design law D7: only approval draws a
// card). Ports the SwiftUI `approvalRow` (SessionView.swift ~915):
//
//   ┌─────────────────────────────────────────────────────────┐
//   │ 🖐  <title>                            [ Deny ] [Approve ]│
//   │ <detail, monospaced, secondary>                          │
//   └─────────────────────────────────────────────────────────┘
//
// Backed by a pending `ActionRequest` (ThreadRuntimeModel.swift). Approve/Deny
// route straight to `SessionModel.decidePendingAction("approve"|"deny")`.
@MainActor
final class ApprovalCardView: NSView {

    private weak var model: SessionModel?

    private let icon = NSImageView()
    private let titleLabel: NSTextField = {
        let field = NSTextField(labelWithString: "")
        field.font = ConversationRowMetrics.calloutMediumFont
        field.textColor = .labelColor
        field.lineBreakMode = .byTruncatingTail
        field.translatesAutoresizingMaskIntoConstraints = false
        field.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        return field
    }()
    private let detailLabel: NSTextField = {
        let field = NSTextField(labelWithString: "")
        field.font = ConversationRowMetrics.monoCalloutFont
        field.textColor = .secondaryLabelColor
        field.lineBreakMode = .byWordWrapping
        field.maximumNumberOfLines = 0
        field.isSelectable = true
        field.translatesAutoresizingMaskIntoConstraints = false
        return field
    }()
    private let denyButton = NSButton(title: "Deny", target: nil, action: nil)
    private let approveButton = NSButton(title: "Approve", target: nil, action: nil)

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
        layer?.cornerRadius = 8
        layer?.borderWidth = 1
        layer?.borderColor = NSColor.separatorColor.cgColor
        layer?.backgroundColor = NSColor.controlBackgroundColor.cgColor

        icon.translatesAutoresizingMaskIntoConstraints = false
        icon.image = NSImage(systemSymbolName: "hand.raised.fill", accessibilityDescription: nil)
        icon.contentTintColor = .systemOrange
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
        // Title takes the slack between glyph and the trailing buttons.
        headerRow.setCustomSpacing(8, after: icon)
        titleLabel.setContentHuggingPriority(.defaultLow, for: .horizontal)

        let column = NSStackView(views: [headerRow, detailLabel])
        column.orientation = .vertical
        column.alignment = .leading
        column.spacing = 8
        column.translatesAutoresizingMaskIntoConstraints = false

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
    func configure(action: ActionRequest, model: SessionModel) {
        self.model = model
        titleLabel.stringValue = action.title
        detailLabel.stringValue = action.detail
        detailLabel.isHidden = action.detail.isEmpty
    }

    @objc private func approve() {
        model?.decidePendingAction("approve")
    }

    @objc private func deny() {
        model?.decidePendingAction("deny")
    }
}
