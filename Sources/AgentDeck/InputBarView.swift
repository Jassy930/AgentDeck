import AppKit

// MARK: - InputBarView (Task 8)
//
// Ports the SwiftUI `inputBar` (SessionView.swift ~940): a 1–4 line
// auto-growing text input, a trailing "queued" count shown while a turn is in
// flight (Eng I1), and a send button.
//
//   ┌──────────────────────────────────────────────────────────┐
//   │ Ask Codex to…                          [2 queued]   [ ↩ ] │
//   └──────────────────────────────────────────────────────────┘
//
// Enter submits → `SessionModel.submit(text)`; Shift+Enter inserts a newline
// (handled by `InputTextView.doCommand(by:)`). The field auto-grows between one
// and four lines, then scrolls.
@MainActor
final class InputBarView: NSView {

    private weak var model: SessionModel?

    private let textView = InputTextView()
    private let scrollView = NSScrollView()
    private let placeholderLabel: NSTextField = {
        let field = NSTextField(labelWithString: "Ask Codex to…")
        field.font = ConversationRowMetrics.calloutFont
        field.textColor = .placeholderTextColor
        field.translatesAutoresizingMaskIntoConstraints = false
        field.isSelectable = false
        return field
    }()
    private let queuedLabel: NSTextField = {
        let field = NSTextField(labelWithString: "")
        field.font = ConversationRowMetrics.captionFont
        field.textColor = .tertiaryLabelColor
        field.translatesAutoresizingMaskIntoConstraints = false
        field.setContentHuggingPriority(.required, for: .horizontal)
        field.setContentCompressionResistancePriority(.required, for: .horizontal)
        return field
    }()

    /// T6B: Claude Code "Plan Mode" 角标 — 仅当 runtime.capabilities 包含
    /// `.claudeCodePlanMode` 且当前 permissionMode == .plan 时显示。
    private let planModeBadge: NSTextField = {
        let field = NSTextField(labelWithString: "Plan Mode")
        field.font = ConversationRowMetrics.captionFont
        field.textColor = .systemBlue
        field.translatesAutoresizingMaskIntoConstraints = false
        field.isHidden = true
        field.setContentHuggingPriority(.required, for: .horizontal)
        return field
    }()
    private let sendButton = NSButton()

    private var scrollHeightConstraint: NSLayoutConstraint!

    /// Single line height of the editing font, used to clamp growth 1…4 lines.
    private let lineHeight = ceil(ConversationRowMetrics.calloutFont.boundingRectForFont.height)
    private let verticalTextInset: CGFloat = 6
    private var minHeight: CGFloat { lineHeight + verticalTextInset * 2 }
    private var maxHeight: CGFloat { lineHeight * 4 + verticalTextInset * 2 }

    init(model: SessionModel) {
        self.model = model
        super.init(frame: .zero)
        build()
        refreshQueuedCount()
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) is not supported") }

    private func build() {
        translatesAutoresizingMaskIntoConstraints = false

        textView.onSubmit = { [weak self] in self?.send() }
        textView.onTextChange = { [weak self] in self?.textDidChange() }
        textView.isRichText = false
        textView.font = ConversationRowMetrics.calloutFont
        textView.textColor = .labelColor
        textView.drawsBackground = false
        textView.isVerticallyResizable = true
        textView.isHorizontallyResizable = false
        textView.textContainerInset = NSSize(width: 0, height: verticalTextInset)
        textView.textContainer?.lineFragmentPadding = 4
        textView.textContainer?.widthTracksTextView = true

        scrollView.documentView = textView
        scrollView.drawsBackground = false
        scrollView.hasVerticalScroller = false
        scrollView.hasHorizontalScroller = false
        scrollView.autohidesScrollers = true
        scrollView.borderType = .noBorder
        scrollView.translatesAutoresizingMaskIntoConstraints = false

        // Placeholder overlays the text view's first line.
        scrollView.addSubview(placeholderLabel)

        sendButton.image = NSImage(systemSymbolName: "return", accessibilityDescription: "Send")
        sendButton.bezelStyle = .rounded
        sendButton.target = self
        sendButton.action = #selector(sendAction)
        sendButton.translatesAutoresizingMaskIntoConstraints = false
        sendButton.setContentHuggingPriority(.required, for: .horizontal)

        addSubview(scrollView)
        addSubview(planModeBadge)
        addSubview(queuedLabel)
        addSubview(sendButton)

        scrollHeightConstraint = scrollView.heightAnchor.constraint(equalToConstant: minHeight)

        NSLayoutConstraint.activate([
            scrollView.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 16),
            scrollView.topAnchor.constraint(equalTo: topAnchor, constant: 10),
            scrollView.bottomAnchor.constraint(equalTo: bottomAnchor, constant: -10),
            scrollHeightConstraint,

            planModeBadge.leadingAnchor.constraint(equalTo: scrollView.trailingAnchor, constant: 10),
            planModeBadge.centerYAnchor.constraint(equalTo: sendButton.centerYAnchor),

            queuedLabel.leadingAnchor.constraint(equalTo: planModeBadge.trailingAnchor, constant: 8),
            queuedLabel.centerYAnchor.constraint(equalTo: sendButton.centerYAnchor),

            sendButton.leadingAnchor.constraint(equalTo: queuedLabel.trailingAnchor, constant: 8),
            sendButton.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -16),
            sendButton.centerYAnchor.constraint(equalTo: scrollView.centerYAnchor),

            placeholderLabel.leadingAnchor.constraint(equalTo: scrollView.leadingAnchor, constant: 4),
            placeholderLabel.topAnchor.constraint(equalTo: scrollView.topAnchor, constant: verticalTextInset),
        ])
    }

    /// Recompute queued count + send button enabled state (called by the
    /// controller whenever the model changes). Also refreshes the T6B Plan
    /// Mode badge from the currently selected runtime.
    func refreshQueuedCount() {
        let count = model?.queuedPrompts.count ?? 0
        queuedLabel.stringValue = count > 0 ? "\(count) queued" : ""
        queuedLabel.isHidden = count == 0
        refreshPlanModeBadge()
        updateSendEnabled()
    }

    /// Pure decision: should the Plan Mode badge be shown for this capabilities
    /// + permission state? Exposed `static` for unit testing.
    static func shouldShowPlanModeBadge(
        capabilities: SessionCapabilities?,
        permissionMode: ClaudeCodePermissionMode?
    ) -> Bool {
        guard let capabilities,
              capabilities.features.contains(.claudeCodePlanMode),
              permissionMode == .plan else { return false }
        return true
    }

    private func refreshPlanModeBadge() {
        let caps = model?.workbench.selectedRuntime?.capabilities
        let mode = model?.workbench.selectedRuntime?.claudeCurrentPermissionMode
        planModeBadge.isHidden = !Self.shouldShowPlanModeBadge(
            capabilities: caps, permissionMode: mode
        )
    }

    private func textDidChange() {
        placeholderLabel.isHidden = !textView.string.isEmpty
        updateSendEnabled()
        adjustHeight()
    }

    private func updateSendEnabled() {
        let trimmed = textView.string.trimmingCharacters(in: .whitespacesAndNewlines)
        sendButton.isEnabled = !trimmed.isEmpty
    }

    /// Grow the scroll view to fit the text, clamped between 1 and 4 lines.
    private func adjustHeight() {
        guard let layoutManager = textView.layoutManager,
              let container = textView.textContainer else { return }
        layoutManager.ensureLayout(for: container)
        let used = layoutManager.usedRect(for: container).height
        let target = min(max(used + verticalTextInset * 2, minHeight), maxHeight)
        if abs(scrollHeightConstraint.constant - target) > 0.5 {
            scrollHeightConstraint.constant = target
        }
    }

    @objc private func sendAction() { send() }

    private func send() {
        let text = textView.string.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { return }
        model?.submit(text)
        textView.string = ""
        textDidChange()
        refreshQueuedCount()
    }
}

// MARK: - InputTextView
//
// An `NSTextView` that submits on Enter and inserts a newline on Shift+Enter,
// matching the SwiftUI `TextField(axis: .vertical).onSubmit(send)` behaviour.
final class InputTextView: NSTextView {
    var onSubmit: (() -> Void)?
    var onTextChange: (() -> Void)?

    override func doCommand(by selector: Selector) {
        // Enter (insertNewline:) submits; Shift+Enter maps to
        // insertNewlineIgnoringFieldEditor: → real newline.
        if selector == #selector(NSResponder.insertNewline(_:)) {
            onSubmit?()
            return
        }
        super.doCommand(by: selector)
    }

    override func didChangeText() {
        super.didChangeText()
        onTextChange?()
    }
}
