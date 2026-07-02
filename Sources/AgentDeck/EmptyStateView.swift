import AppKit

// MARK: - EmptyStateView (Task 11)
//
// AppKit port of SessionView.emptyState (D5 first-frame / no-cwd state).
//
// Layout (vertical, centred):
//   "AgentDeck"                       — title (semibold, 28pt)
//   "Watch your coding agent…"        — subtitle (.body, secondary)
//   [Choose project directory…]       — borderedProminent → NSOpenPanel → model.chooseCwd
//   [Refresh history]                 — bordered → model.loadHistory
//   "e.g. "Fix the crash…""           — callout, tertiary
//
// The view is stateless; SessionViewController replaces it with
// ConversationViewController when model.cwd becomes non-nil.

@MainActor
final class EmptyStateView: NSView {

    // MARK: - Init

    private let model: SessionModel

    init(model: SessionModel) {
        self.model = model
        super.init(frame: .zero)
        setupSubviews()
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) not supported") }

    // MARK: - Layout

    private func setupSubviews() {
        translatesAutoresizingMaskIntoConstraints = false
        wantsLayer = true
        layer?.backgroundColor = CodexDesktopChrome.windowBackground.cgColor

        let titleLabel = NSTextField(labelWithString: "我们应该在 AgentDeck 中构建什么？")
        titleLabel.font = .systemFont(ofSize: 24, weight: .semibold)
        titleLabel.alignment = .center
        titleLabel.textColor = .labelColor
        titleLabel.translatesAutoresizingMaskIntoConstraints = false

        let composer = NSView()
        composer.translatesAutoresizingMaskIntoConstraints = false
        composer.setAccessibilityIdentifier("codex-empty-composer")
        CodexDesktopChrome.roundedPanel(composer, radius: 18)

        let promptLabel = NSTextField(wrappingLabelWithString: "选择一个项目目录后，AgentDeck 会在这里开始新的 Codex / Claude Code 会话。")
        promptLabel.font = .systemFont(ofSize: 13, weight: .medium)
        promptLabel.textColor = .secondaryLabelColor
        promptLabel.translatesAutoresizingMaskIntoConstraints = false

        let plusButton = iconButton("plus", tooltip: "选择项目目录")
        plusButton.target = self
        plusButton.action = #selector(pickDirectory)

        let accessButton = NSButton(title: "选择项目目录", target: self, action: #selector(pickDirectory))
        accessButton.bezelStyle = .inline
        accessButton.isBordered = false
        accessButton.font = .systemFont(ofSize: 13, weight: .medium)
        accessButton.contentTintColor = CodexDesktopChrome.orange
        accessButton.translatesAutoresizingMaskIntoConstraints = false

        let refreshButton = NSButton(title: "刷新历史", target: self, action: #selector(refreshHistory))
        refreshButton.bezelStyle = .inline
        refreshButton.isBordered = false
        refreshButton.font = .systemFont(ofSize: 13, weight: .medium)
        refreshButton.contentTintColor = .secondaryLabelColor
        refreshButton.translatesAutoresizingMaskIntoConstraints = false

        let sendButton = iconButton("arrow.up", tooltip: "开始")
        sendButton.target = self
        sendButton.action = #selector(pickDirectory)
        sendButton.wantsLayer = true
        sendButton.layer?.backgroundColor = NSColor.labelColor.cgColor
        sendButton.layer?.cornerRadius = 15

        let spacer = NSView()
        spacer.translatesAutoresizingMaskIntoConstraints = false
        let toolbar = NSStackView(views: [plusButton, accessButton, refreshButton, spacer, sendButton])
        toolbar.orientation = .horizontal
        toolbar.alignment = .centerY
        toolbar.spacing = 10
        toolbar.translatesAutoresizingMaskIntoConstraints = false

        composer.addSubview(promptLabel)
        composer.addSubview(toolbar)

        NSLayoutConstraint.activate([
            promptLabel.topAnchor.constraint(equalTo: composer.topAnchor, constant: 16),
            promptLabel.leadingAnchor.constraint(equalTo: composer.leadingAnchor, constant: 18),
            promptLabel.trailingAnchor.constraint(equalTo: composer.trailingAnchor, constant: -18),

            toolbar.topAnchor.constraint(equalTo: promptLabel.bottomAnchor, constant: 22),
            toolbar.leadingAnchor.constraint(equalTo: composer.leadingAnchor, constant: 14),
            toolbar.trailingAnchor.constraint(equalTo: composer.trailingAnchor, constant: -12),
            toolbar.bottomAnchor.constraint(equalTo: composer.bottomAnchor, constant: -12),

            composer.widthAnchor.constraint(equalToConstant: 620),
            plusButton.widthAnchor.constraint(equalToConstant: 26),
            plusButton.heightAnchor.constraint(equalToConstant: 26),
            sendButton.widthAnchor.constraint(equalToConstant: 30),
            sendButton.heightAnchor.constraint(equalToConstant: 30),
        ])

        let cards = NSStackView(views: [
            connectorCard(symbol: "sparkles", title: "连接消息传送", subtitle: "了解工程对话线程动态"),
            connectorCard(symbol: "chevron.left.forwardslash.chevron.right", title: "连接 GitHub", subtitle: "审查 PR、代码和 CI 检查项"),
            connectorCard(symbol: "circle.lefthalf.filled", title: "连接 Linear", subtitle: "跟踪缺陷和实施工作"),
        ])
        cards.orientation = .horizontal
        cards.alignment = .top
        cards.spacing = 12
        cards.translatesAutoresizingMaskIntoConstraints = false

        let resetPanel = resetLimitPanel()

        let stack = NSStackView(views: [titleLabel, composer, cards, resetPanel])
        stack.orientation = .vertical
        stack.alignment = .centerX
        stack.spacing = 26
        stack.setCustomSpacing(34, after: titleLabel)
        stack.setCustomSpacing(28, after: composer)
        stack.setCustomSpacing(92, after: cards)
        stack.translatesAutoresizingMaskIntoConstraints = false
        addSubview(stack)

        NSLayoutConstraint.activate([
            stack.centerYAnchor.constraint(equalTo: centerYAnchor, constant: 18),
            stack.centerXAnchor.constraint(equalTo: centerXAnchor),
            stack.leadingAnchor.constraint(greaterThanOrEqualTo: leadingAnchor, constant: 28),
            stack.trailingAnchor.constraint(lessThanOrEqualTo: trailingAnchor, constant: -28),
        ])
    }

    private func iconButton(_ symbol: String, tooltip: String) -> NSButton {
        let button = NSButton()
        button.image = NSImage(systemSymbolName: symbol, accessibilityDescription: tooltip)
        button.toolTip = tooltip
        button.bezelStyle = .inline
        button.isBordered = false
        button.contentTintColor = .secondaryLabelColor
        button.translatesAutoresizingMaskIntoConstraints = false
        return button
    }

    private func connectorCard(symbol: String, title: String, subtitle: String) -> NSView {
        let card = NSView()
        card.translatesAutoresizingMaskIntoConstraints = false
        CodexDesktopChrome.roundedPanel(card, radius: 10, border: true)
        card.layer?.backgroundColor = CodexDesktopChrome.cardBackground.cgColor

        let icon = NSImageView(image: NSImage(systemSymbolName: symbol, accessibilityDescription: nil) ?? NSImage())
        icon.contentTintColor = .secondaryLabelColor
        icon.translatesAutoresizingMaskIntoConstraints = false
        let titleLabel = NSTextField(labelWithString: title)
        titleLabel.font = .systemFont(ofSize: 13, weight: .medium)
        titleLabel.textColor = .labelColor
        let subtitleLabel = NSTextField(labelWithString: subtitle)
        subtitleLabel.font = .systemFont(ofSize: 12)
        subtitleLabel.textColor = .secondaryLabelColor
        for label in [titleLabel, subtitleLabel] {
            label.lineBreakMode = .byTruncatingTail
            label.translatesAutoresizingMaskIntoConstraints = false
        }

        let stack = NSStackView(views: [icon, titleLabel, subtitleLabel])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 7
        stack.translatesAutoresizingMaskIntoConstraints = false
        card.addSubview(stack)

        NSLayoutConstraint.activate([
            card.widthAnchor.constraint(equalToConstant: 168),
            card.heightAnchor.constraint(equalToConstant: 88),
            stack.topAnchor.constraint(equalTo: card.topAnchor, constant: 14),
            stack.leadingAnchor.constraint(equalTo: card.leadingAnchor, constant: 14),
            stack.trailingAnchor.constraint(equalTo: card.trailingAnchor, constant: -14),
            icon.widthAnchor.constraint(equalToConstant: 16),
            icon.heightAnchor.constraint(equalToConstant: 16),
        ])
        return card
    }

    private func resetLimitPanel() -> NSView {
        let panel = NSView()
        panel.translatesAutoresizingMaskIntoConstraints = false
        CodexDesktopChrome.roundedPanel(panel, radius: 18)

        let icon = NSImageView(image: NSImage(systemSymbolName: "seal", accessibilityDescription: nil) ?? NSImage())
        icon.contentTintColor = .secondaryLabelColor
        icon.translatesAutoresizingMaskIntoConstraints = false
        let title = NSTextField(labelWithString: "你有新的速率限制重置机会")
        title.font = .systemFont(ofSize: 13, weight: .semibold)
        title.textColor = .labelColor
        let subtitle = NSTextField(labelWithString: "你已获得一次速率限制重置机会，将于 30 天后失效。")
        subtitle.font = .systemFont(ofSize: 12)
        subtitle.textColor = .secondaryLabelColor
        for label in [title, subtitle] {
            label.translatesAutoresizingMaskIntoConstraints = false
        }
        let button = NSButton(title: "查看重置次数", target: nil, action: nil)
        button.bezelStyle = .rounded
        button.font = .systemFont(ofSize: 12, weight: .medium)
        button.translatesAutoresizingMaskIntoConstraints = false

        let textStack = NSStackView(views: [title, subtitle])
        textStack.orientation = .vertical
        textStack.alignment = .leading
        textStack.spacing = 5
        textStack.translatesAutoresizingMaskIntoConstraints = false

        panel.addSubview(icon)
        panel.addSubview(textStack)
        panel.addSubview(button)

        NSLayoutConstraint.activate([
            panel.widthAnchor.constraint(equalToConstant: 620),
            panel.heightAnchor.constraint(equalToConstant: 64),
            icon.leadingAnchor.constraint(equalTo: panel.leadingAnchor, constant: 18),
            icon.centerYAnchor.constraint(equalTo: panel.centerYAnchor),
            icon.widthAnchor.constraint(equalToConstant: 24),
            icon.heightAnchor.constraint(equalToConstant: 24),
            textStack.leadingAnchor.constraint(equalTo: icon.trailingAnchor, constant: 14),
            textStack.centerYAnchor.constraint(equalTo: panel.centerYAnchor),
            textStack.trailingAnchor.constraint(lessThanOrEqualTo: button.leadingAnchor, constant: -16),
            button.trailingAnchor.constraint(equalTo: panel.trailingAnchor, constant: -18),
            button.centerYAnchor.constraint(equalTo: panel.centerYAnchor),
        ])
        return panel
    }

    // MARK: - Actions

    @objc private func pickDirectory() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.allowsMultipleSelection = false
        // Run modally attached to the window when available, falling back to app-modal.
        if let window = window {
            panel.beginSheetModal(for: window) { [weak self] response in
                guard let self, response == .OK, let url = panel.url else { return }
                if let err = self.model.chooseCwd(url) {
                    self.model.errorMessage = err
                }
            }
        } else {
            if panel.runModal() == .OK, let url = panel.url {
                if let err = model.chooseCwd(url) {
                    model.errorMessage = err
                }
            }
        }
    }

    @objc private func refreshHistory() {
        model.loadHistory()
    }
}
