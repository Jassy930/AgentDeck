import AppKit
import AgentDeckCore

// MARK: - InputBarView (Task 8)
//
// Ports the SwiftUI `inputBar` (SessionView.swift ~940): a 1–4 line
// auto-growing text input, a trailing "queued" count shown while a turn is in
// flight (Eng I1), and a send button.
//
//   ┌──────────────────────────────────────────────────────────┐
//   │ Ask Codex to…                          [2 queued]   [ ↑ ] │
//   └──────────────────────────────────────────────────────────┘
//
// Enter submits → `SessionModel.submit(text)`; Shift+Enter inserts a newline
// (handled by `InputTextView.doCommand(by:)`). The field auto-grows between one
// and four lines, then scrolls.
@MainActor
final class InputBarView: NSView {

    private weak var model: SessionModel?

    private let composerChrome = NSView()
    private let textView = InputTextView()
    private let scrollView = NSScrollView()
    private let placeholderLabel: NSTextField = {
        let field = NSTextField(labelWithString: "继续对话，或 @ 引用文件…")
        field.font = ConversationRowMetrics.calloutFont
        field.textColor = DesignTokens.text3
        field.translatesAutoresizingMaskIntoConstraints = false
        field.isSelectable = false
        return field
    }()
    private let queuedLabel: NSTextField = {
        let field = NSTextField(labelWithString: "")
        field.font = ConversationRowMetrics.captionFont
        field.textColor = DesignTokens.text3
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
        field.textColor = DesignTokens.info
        field.translatesAutoresizingMaskIntoConstraints = false
        field.isHidden = true
        field.setContentHuggingPriority(.required, for: .horizontal)
        return field
    }()
    // 设计系统：权限徽章 = 橙色胶囊（盾牌图标 + workspace-write），effort = 灰色胶囊（high）。
    private let approvalBadge = InputBarView.badgePill(
        icon: "shield.lefthalf.filled", text: "workspace-write",
        fg: CodexDesktopChrome.orange, bg: DesignTokens.warnWeak,
        border: DesignTokens.warn.withAlphaComponent(0.35))
    private let effortBadge = InputBarView.badgePill(
        icon: nil, text: "high",
        fg: DesignTokens.text2, bg: DesignTokens.surface2,
        border: DesignTokens.border)
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

    /// No-arg init for unit tests or standalone usage (no model binding).
    init() {
        self.model = nil
        super.init(frame: .zero)
        build()
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) is not supported") }

    /// 设计系统胶囊徽章：圆角容器 + 可选 SF Symbol 图标 + 文案。
    /// 用于 composer 权限（橙）/ 推理强度（灰）标签，视觉对齐设计系统。
    private static func badgePill(icon: String?, text: String,
                                  fg: NSColor, bg: NSColor, border: NSColor) -> NSView {
        let pill = NSView()
        pill.wantsLayer = true
        pill.layer?.backgroundColor = bg.cgColor
        pill.layer?.cornerRadius = 11
        pill.layer?.cornerCurve = .continuous
        pill.layer?.borderWidth = 1
        pill.layer?.borderColor = border.cgColor
        pill.translatesAutoresizingMaskIntoConstraints = false
        pill.setContentHuggingPriority(.required, for: .horizontal)
        pill.setContentCompressionResistancePriority(.required, for: .horizontal)

        let stack = NSStackView()
        stack.orientation = .horizontal
        stack.alignment = .centerY
        stack.spacing = 4
        stack.translatesAutoresizingMaskIntoConstraints = false
        if let icon, let img = NSImage(systemSymbolName: icon, accessibilityDescription: nil) {
            let iv = NSImageView(image: img)
            iv.contentTintColor = fg
            iv.imageScaling = .scaleProportionallyDown
            iv.translatesAutoresizingMaskIntoConstraints = false
            iv.widthAnchor.constraint(equalToConstant: 11).isActive = true
            iv.heightAnchor.constraint(equalToConstant: 11).isActive = true
            stack.addArrangedSubview(iv)
        }
        let label = NSTextField(labelWithString: text)
        label.font = ConversationRowMetrics.captionFont
        label.textColor = fg
        label.translatesAutoresizingMaskIntoConstraints = false
        stack.addArrangedSubview(label)

        pill.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: pill.leadingAnchor, constant: 8),
            stack.trailingAnchor.constraint(equalTo: pill.trailingAnchor, constant: -8),
            stack.topAnchor.constraint(equalTo: pill.topAnchor, constant: 3),
            stack.bottomAnchor.constraint(equalTo: pill.bottomAnchor, constant: -3),
        ])
        return pill
    }

    private func build() {
        translatesAutoresizingMaskIntoConstraints = false
        wantsLayer = true
        layer?.backgroundColor = NSColor.clear.cgColor

        composerChrome.translatesAutoresizingMaskIntoConstraints = false
        composerChrome.setAccessibilityIdentifier("codex-composer")
        CodexDesktopChrome.roundedPanel(composerChrome, radius: DesignTokens.radiusLg)

        textView.onSubmit = { [weak self] in self?.send() }
        textView.onTextChange = { [weak self] in self?.textDidChange() }
        textView.isRichText = false
        textView.font = ConversationRowMetrics.calloutFont
        textView.textColor = DesignTokens.text
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

        sendButton.setAccessibilityIdentifier("composer-send")
        sendButton.image = NSImage(systemSymbolName: "arrow.up", accessibilityDescription: "发送")
        sendButton.toolTip = "发送（Return）"
        // 浅色圆底上箭头需深色，否则模板图默认取浅色前景 → 白底白箭头看不见。
        sendButton.contentTintColor = CodexDesktopChrome.windowBackground
        sendButton.bezelStyle = .inline
        sendButton.isBordered = false
        sendButton.target = self
        sendButton.action = #selector(sendAction)
        sendButton.translatesAutoresizingMaskIntoConstraints = false
        sendButton.setContentHuggingPriority(.required, for: .horizontal)
        sendButton.wantsLayer = true
        sendButton.layer?.backgroundColor = DesignTokens.text.cgColor
        sendButton.layer?.cornerRadius = 22

        // 设计系统：左侧徽章成组（权限 / Plan Mode / 队列 / effort）。
        // 用 NSStackView 让隐藏项自动折叠，避免占位造成的空隙。
        let badgeStack = NSStackView(views: [approvalBadge, planModeBadge, queuedLabel, effortBadge])
        badgeStack.orientation = .horizontal
        badgeStack.alignment = .centerY
        badgeStack.spacing = 8
        badgeStack.detachesHiddenViews = true
        // 窄窗口下不能让徽章的 intrinsic width 挤坏右侧发送按钮。允许 stack
        // 按信息优先级自动摘除低优先级项：先 effort，再 Plan Mode；队列状态和
        // 权限徽章尽量保留。发送按钮的 required 44pt 约束始终不参与压缩。
        badgeStack.setClippingResistancePriority(.defaultLow, for: .horizontal)
        badgeStack.setVisibilityPriority(.mustHold, for: approvalBadge)
        badgeStack.setVisibilityPriority(.init(rawValue: 930), for: queuedLabel)
        badgeStack.setVisibilityPriority(.init(rawValue: 920), for: planModeBadge)
        badgeStack.setVisibilityPriority(.init(rawValue: 910), for: effortBadge)
        badgeStack.setAccessibilityIdentifier("composer-badges")
        badgeStack.translatesAutoresizingMaskIntoConstraints = false

        addSubview(composerChrome)
        composerChrome.addSubview(scrollView)
        composerChrome.addSubview(badgeStack)
        composerChrome.addSubview(sendButton)

        scrollHeightConstraint = scrollView.heightAnchor.constraint(equalToConstant: minHeight)

        NSLayoutConstraint.activate([
            composerChrome.topAnchor.constraint(equalTo: topAnchor),
            composerChrome.leadingAnchor.constraint(equalTo: leadingAnchor),
            composerChrome.trailingAnchor.constraint(equalTo: trailingAnchor),
            composerChrome.bottomAnchor.constraint(equalTo: bottomAnchor),

            scrollView.leadingAnchor.constraint(equalTo: composerChrome.leadingAnchor, constant: 14),
            scrollView.topAnchor.constraint(equalTo: composerChrome.topAnchor, constant: 14),
            scrollView.trailingAnchor.constraint(equalTo: composerChrome.trailingAnchor, constant: -14),
            scrollHeightConstraint,

            // 只呈现已接通的控件：徽章组靠左，发送按钮靠右。
            // 未实现的附件/语音入口不占位，避免把装饰误认为可操作能力。
            badgeStack.leadingAnchor.constraint(equalTo: composerChrome.leadingAnchor, constant: 14),
            badgeStack.centerYAnchor.constraint(equalTo: sendButton.centerYAnchor),
            badgeStack.trailingAnchor.constraint(lessThanOrEqualTo: sendButton.leadingAnchor, constant: -12),

            sendButton.topAnchor.constraint(equalTo: scrollView.bottomAnchor, constant: 10),
            sendButton.bottomAnchor.constraint(equalTo: composerChrome.bottomAnchor, constant: -10),
            sendButton.trailingAnchor.constraint(equalTo: composerChrome.trailingAnchor, constant: -12),
            sendButton.centerYAnchor.constraint(equalTo: badgeStack.centerYAnchor),
            sendButton.widthAnchor.constraint(equalToConstant: 44),
            sendButton.heightAnchor.constraint(equalToConstant: 44),

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

    /// T6C: programmatically set the plan-mode badge state (for testing or
    /// external binding). Pass `true` to show the badge, `false` to hide it.
    func applyState(planMode: Bool) {
        planModeBadge.isHidden = !planMode
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
