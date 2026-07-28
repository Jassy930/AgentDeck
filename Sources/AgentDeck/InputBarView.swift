import AppKit
import AgentDeckCore

struct InputBarDraftCacheLimits: Equatable, Sendable {
  static let production = Self(
    maximumOwners: 32,
    maximumDraftBytes: RuntimePromptPayloadV1.maxUTF8Bytes,
    maximumTotalDraftBytes: 4 * RuntimePromptPayloadV1.maxUTF8Bytes)

  let maximumOwners: Int
  let maximumDraftBytes: Int
  let maximumTotalDraftBytes: Int

  init(maximumOwners: Int, maximumDraftBytes: Int, maximumTotalDraftBytes: Int) {
    precondition(maximumOwners > 0)
    precondition(maximumDraftBytes > 0)
    precondition(maximumTotalDraftBytes > 0)
    self.maximumOwners = maximumOwners
    self.maximumDraftBytes = maximumDraftBytes
    self.maximumTotalDraftBytes = maximumTotalDraftBytes
  }
}

// MARK: - InputBarView (Task 8)
//
// Ports the SwiftUI `inputBar` (SessionView.swift ~940): a 1–4 line
// auto-growing text input, a truthful daemon-admission/queued status, and a send button.
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
        field.font = ConversationTypography.bodyFont
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
  private let retryStartButton = NSButton(title: "Retry start", target: nil, action: nil)
  private let draftCacheLimits: InputBarDraftCacheLimits
  private var composerOwner: PromptComposerOwner?
  private var draftsByOwner: [PromptComposerOwner: String] = [:]
  private var draftOwnerRecency: [PromptComposerOwner] = []
  private var cachedDraftBytes = 0

  private var scrollHeightConstraint: NSLayoutConstraint!

    /// Single line height of the editing font, used to clamp growth 1…4 lines.
    private let lineHeight = ceil(ConversationTypography.bodyFont.boundingRectForFont.height)
    private let verticalTextInset: CGFloat = 6
    private var minHeight: CGFloat { lineHeight + verticalTextInset * 2 }
    private var maxHeight: CGFloat { lineHeight * 4 + verticalTextInset * 2 }

  init(
    model: SessionModel,
    draftCacheLimits: InputBarDraftCacheLimits = .production
  ) {
    self.model = model
    self.draftCacheLimits = draftCacheLimits
    super.init(frame: .zero)
        build()
    refreshPromptStatus()
  }

    /// No-arg init for unit tests or standalone usage (no model binding).
    init() {
        self.model = nil
    self.draftCacheLimits = .production
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
        composerChrome.layer?.backgroundColor = DesignTokens.surface2.cgColor

        textView.onSubmit = { [weak self] in self?.send() }
        textView.onTextChange = { [weak self] in self?.textDidChange() }
        textView.isRichText = false
        textView.font = ConversationTypography.bodyFont
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

    retryStartButton.setAccessibilityIdentifier("composer-retry-start")
    retryStartButton.toolTip = "Retry the exact conversation start"
    retryStartButton.bezelStyle = .inline
    retryStartButton.font = ConversationRowMetrics.captionFont
    retryStartButton.contentTintColor = DesignTokens.info
    retryStartButton.target = self
    retryStartButton.action = #selector(retryStartAction)
    retryStartButton.translatesAutoresizingMaskIntoConstraints = false
    retryStartButton.isHidden = true
    retryStartButton.setContentHuggingPriority(.required, for: .horizontal)
    retryStartButton.setContentCompressionResistancePriority(
      .required,
      for: .horizontal
    )

    // 设计系统：左侧徽章成组（权限 / Plan Mode / 队列 / effort）。
        // 用 NSStackView 让隐藏项自动折叠，避免占位造成的空隙。
    let badgeStack = NSStackView(
      views: [
        approvalBadge,
        planModeBadge,
        queuedLabel,
        retryStartButton,
        effortBadge,
      ]
    )
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

            scrollView.leadingAnchor.constraint(equalTo: composerChrome.leadingAnchor, constant: 16),
            scrollView.topAnchor.constraint(equalTo: composerChrome.topAnchor, constant: 12),
            scrollView.trailingAnchor.constraint(equalTo: composerChrome.trailingAnchor, constant: -16),
            scrollHeightConstraint,

            // 只呈现已接通的控件：徽章组靠左，发送按钮靠右。
            // 未实现的附件/语音入口不占位，避免把装饰误认为可操作能力。
            badgeStack.leadingAnchor.constraint(equalTo: composerChrome.leadingAnchor, constant: 14),
            badgeStack.centerYAnchor.constraint(equalTo: sendButton.centerYAnchor),
            badgeStack.trailingAnchor.constraint(lessThanOrEqualTo: sendButton.leadingAnchor, constant: -12),

            sendButton.topAnchor.constraint(equalTo: scrollView.bottomAnchor, constant: 6),
            sendButton.bottomAnchor.constraint(equalTo: composerChrome.bottomAnchor, constant: -8),
            sendButton.trailingAnchor.constraint(equalTo: composerChrome.trailingAnchor, constant: -12),
            sendButton.centerYAnchor.constraint(equalTo: badgeStack.centerYAnchor),
            sendButton.widthAnchor.constraint(equalToConstant: 44),
            sendButton.heightAnchor.constraint(equalToConstant: 44),

            placeholderLabel.leadingAnchor.constraint(equalTo: scrollView.leadingAnchor, constant: 4),
            placeholderLabel.topAnchor.constraint(equalTo: scrollView.topAnchor, constant: verticalTextInset),
        ])
    }

  /// Recompute admission/queued status + send button enabled state (called by the
  /// controller whenever the model changes). Also refreshes the T6B Plan
    /// Mode badge from the currently selected runtime.
  func refreshPromptStatus() {
    let nextOwner = model?.promptComposerOwner
    switchComposerOwner(to: nextOwner)
    let retryDraft = model?.retryRequiredPromptDraft
    if let retryDraft,
      retryDraft.owner == composerOwner,
      textView.string.isEmpty
    {
      textView.string = retryDraft.prompt
      textDidChange()
    }
    let status = Self.promptStatusText(
      sendingCount: model?.sendingPrompts.count ?? 0,
      queuedCount: model?.queuedPrompts.count ?? 0,
      retryRequired: retryDraft?.owner == composerOwner
        || model?.canRetryPromptlessConversationStart == true,
      bootstrapInFlight: model?.isConversationBootstrapAdmissionInFlight == true)
    queuedLabel.stringValue = status
    queuedLabel.isHidden = status.isEmpty
    retryStartButton.isHidden = model?.canRetryConversationStart != true
    retryStartButton.isEnabled = model?.canRetryConversationStart == true
    refreshPlanModeBadge()
        updateSendEnabled()
    }

  static func promptStatusText(
    sendingCount: Int,
    queuedCount: Int,
    retryRequired: Bool = false,
    bootstrapInFlight: Bool = false
  ) -> String {
    if sendingCount > 0 { return "\(sendingCount) sending" }
    if bootstrapInFlight { return "starting conversation" }
    if retryRequired { return "retry required" }
    if queuedCount > 0 { return "\(queuedCount) queued" }
    return ""
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
    let admissionAvailable = model?.isComposerAdmissionInFlight != true
    let requiresSeparateStartRetry = requiresSeparateConversationStartRetry()
    sendButton.isEnabled =
      !trimmed.isEmpty && admissionAvailable && !requiresSeparateStartRetry
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

  @objc private func retryStartAction() {
    let clearsExactRetryDraft: Bool = {
      guard let retryDraft = model?.retryRequiredPromptDraft,
        retryDraft.owner == composerOwner
      else { return false }
      return textView.string.utf8.elementsEqual(retryDraft.prompt.utf8)
    }()
    model?.retryConversationStart()
    if clearsExactRetryDraft {
      textView.string = ""
      textDidChange()
    }
    refreshPromptStatus()
  }

  private func send() {
    let text = textView.string
    guard !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return }
    guard model?.submit(text, expectedComposerOwner: composerOwner) == true else {
      refreshPromptStatus()
      return
    }
    textView.string = ""
        textDidChange()
    refreshPromptStatus()
  }

  private func switchComposerOwner(to nextOwner: PromptComposerOwner?) {
    guard composerOwner != nextOwner else { return }
    let previousOwner = composerOwner
    let previousText = textView.string
    let carriedBootstrapDraft: String? = {
      guard case .bootstrap = previousOwner,
        case .conversation? = nextOwner,
        !previousText.isEmpty
      else { return nil }
      return previousText
    }()
    if let previousOwner {
      if carriedBootstrapDraft != nil {
        removeCachedDraft(for: previousOwner)
      } else {
        cacheInactiveDraft(previousText, for: previousOwner)
      }
    }
    composerOwner = nextOwner
    textView.string =
      carriedBootstrapDraft
      ?? nextOwner.flatMap { takeCachedDraft(for: $0) }
      ?? ""
    textDidChange()
  }

  private func cacheInactiveDraft(_ text: String, for owner: PromptComposerOwner) {
    removeCachedDraft(for: owner)
    if text.isEmpty {
      return
    }
    let bytes = text.utf8.count
    guard bytes <= draftCacheLimits.maximumDraftBytes else {
      model?.recordComposerDraftCacheDrop(
        "A composer draft exceeded the 256 KiB cache limit and was not retained after switching targets"
      )
      return
    }
    draftsByOwner[owner] = text
    cachedDraftBytes += bytes
    draftOwnerRecency.append(owner)
    while draftOwnerRecency.count > draftCacheLimits.maximumOwners
      || cachedDraftBytes > draftCacheLimits.maximumTotalDraftBytes
    {
      let evicted = draftOwnerRecency.removeFirst()
      removeCachedDraft(for: evicted)
      model?.recordComposerDraftCacheDrop(
        "An older composer draft was evicted from the bounded local cache"
      )
    }
  }

  private func takeCachedDraft(for owner: PromptComposerOwner) -> String? {
    let value = draftsByOwner[owner]
    removeCachedDraft(for: owner)
    return value
  }

  private func removeCachedDraft(for owner: PromptComposerOwner) {
    if let removed = draftsByOwner.removeValue(forKey: owner) {
      cachedDraftBytes -= removed.utf8.count
    }
    draftOwnerRecency.removeAll { $0 == owner }
  }

  private func requiresSeparateConversationStartRetry() -> Bool {
    guard model?.canRetryConversationStart == true else { return false }
    guard let retryDraft = model?.retryRequiredPromptDraft,
      retryDraft.owner == composerOwner
    else { return true }
    return !textView.string.utf8.elementsEqual(retryDraft.prompt.utf8)
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
