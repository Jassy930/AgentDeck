import AppKit

enum CodexDesktopChrome {
    static let windowBackground = NSColor(calibratedRed: 0.075, green: 0.075, blue: 0.075, alpha: 1)
    static let sidebarBackground = NSColor(calibratedRed: 0.17, green: 0.18, blue: 0.18, alpha: 0.92)
    static let sidebarTopTint = NSColor(calibratedRed: 0.08, green: 0.25, blue: 0.17, alpha: 0.38)
    static let panelBackground = NSColor(calibratedRed: 0.18, green: 0.18, blue: 0.18, alpha: 1)
    static let panelHoverBackground = NSColor(calibratedRed: 0.235, green: 0.235, blue: 0.235, alpha: 1)
    static let cardBackground = NSColor(calibratedRed: 0.105, green: 0.105, blue: 0.105, alpha: 1)
    static let border = NSColor(calibratedRed: 0.245, green: 0.245, blue: 0.245, alpha: 1)
    static let separator = NSColor(calibratedRed: 0.165, green: 0.165, blue: 0.165, alpha: 1)
    static let orange = NSColor(calibratedRed: 1.0, green: 0.49, blue: 0.18, alpha: 1)

    @MainActor
    static func roundedPanel(_ view: NSView, radius: CGFloat, border: Bool = true) {
        view.wantsLayer = true
        view.layer?.backgroundColor = panelBackground.cgColor
        view.layer?.cornerRadius = radius
        view.layer?.cornerCurve = .continuous
        if border {
            view.layer?.borderWidth = 1
            view.layer?.borderColor = CodexDesktopChrome.border.cgColor
        }
    }
}

@MainActor
final class CodexContentHeaderView: NSView {
    private weak var model: SessionModel?
    private let binder = ObservationBinder()

    private let titleLabel: NSTextField = {
        let label = NSTextField(labelWithString: "AgentDeck")
        label.font = .systemFont(ofSize: 14, weight: .semibold)
        label.textColor = .labelColor
        label.lineBreakMode = .byTruncatingTail
        label.translatesAutoresizingMaskIntoConstraints = false
        return label
    }()

    private let agentIcon = NSImageView()
    private let openLocationButton = NSButton(title: "打开位置⌄", target: nil, action: nil)
    private let controlsButton = NSButton()

    init(model: SessionModel) {
        self.model = model
        super.init(frame: .zero)
        build()
        bind()
        refresh()
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) not supported") }

    private func build() {
        translatesAutoresizingMaskIntoConstraints = false
        setAccessibilityIdentifier("codex-content-header")
        wantsLayer = true
        layer?.backgroundColor = CodexDesktopChrome.windowBackground.cgColor

        agentIcon.imageScaling = .scaleProportionallyUpOrDown
        agentIcon.translatesAutoresizingMaskIntoConstraints = false

        let moreButton = NSButton(title: "…", target: nil, action: nil)
        moreButton.bezelStyle = .inline
        moreButton.isBordered = false
        moreButton.font = .systemFont(ofSize: 15, weight: .semibold)
        moreButton.contentTintColor = .secondaryLabelColor
        moreButton.translatesAutoresizingMaskIntoConstraints = false

        openLocationButton.bezelStyle = .rounded
        openLocationButton.font = .systemFont(ofSize: NSFont.systemFontSize(for: .small), weight: .medium)
        openLocationButton.contentTintColor = .labelColor
        openLocationButton.translatesAutoresizingMaskIntoConstraints = false

        controlsButton.image = NSImage(systemSymbolName: "slider.horizontal.3", accessibilityDescription: "界面选项")
        controlsButton.bezelStyle = .rounded
        controlsButton.isBordered = true
        controlsButton.translatesAutoresizingMaskIntoConstraints = false

        let leftStack = NSStackView(views: [agentIcon, titleLabel, moreButton])
        leftStack.orientation = .horizontal
        leftStack.alignment = .centerY
        leftStack.spacing = 10
        leftStack.translatesAutoresizingMaskIntoConstraints = false

        let rightStack = NSStackView(views: [openLocationButton, controlsButton])
        rightStack.orientation = .horizontal
        rightStack.alignment = .centerY
        rightStack.spacing = 8
        rightStack.translatesAutoresizingMaskIntoConstraints = false

        addSubview(leftStack)
        addSubview(rightStack)

        NSLayoutConstraint.activate([
            leftStack.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 18),
            leftStack.centerYAnchor.constraint(equalTo: centerYAnchor),
            leftStack.trailingAnchor.constraint(lessThanOrEqualTo: rightStack.leadingAnchor, constant: -16),

            agentIcon.widthAnchor.constraint(equalToConstant: 16),
            agentIcon.heightAnchor.constraint(equalToConstant: 16),

            rightStack.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -18),
            rightStack.centerYAnchor.constraint(equalTo: centerYAnchor),
        ])
    }

    private func bind() {
        binder.bind({ [weak self] in
            guard let self, let model = self.model else { return }
            _ = model.cwd
            _ = model.workbench.selectedSessionId
            _ = model.workbench.selectedRuntime?.displayTitle
            _ = model.workbench.selectedRuntime?.capabilities?.agentKind
        }, onChange: { [weak self] in
            self?.refresh()
        })
    }

    private func refresh() {
        guard let model else { return }
        if let runtime = model.workbench.selectedRuntime {
            titleLabel.stringValue = runtime.displayTitle
            agentIcon.image = AgentKindIcon.compactImage(for: runtime.agentKind)
            agentIcon.isHidden = false
        } else if let cwd = model.cwd {
            titleLabel.stringValue = cwd.lastPathComponent
            agentIcon.image = nil
            agentIcon.isHidden = true
        } else {
            titleLabel.stringValue = "AgentDeck"
            agentIcon.image = nil
            agentIcon.isHidden = true
        }
        openLocationButton.isHidden = model.cwd == nil
    }

    deinit {
        let b = binder
        Task { @MainActor in b.invalidate() }
    }
}

@MainActor
final class CodexEnvironmentPanelView: NSView {
    override init(frame: NSRect) {
        super.init(frame: frame)
        build()
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) not supported") }

    private func build() {
        translatesAutoresizingMaskIntoConstraints = false
        CodexDesktopChrome.roundedPanel(self, radius: 18)

        let title = label("环境信息", size: 13, weight: .medium, color: .secondaryLabelColor)
        let add = symbolButton("plus", tooltip: "添加环境信息")
        let titleRow = row([title, spacer(), add], spacing: 8)

        let changes = metricRow(symbol: "plusminus.square", title: "变更", trailing: "+0 -0", trailingColor: .secondaryLabelColor)
        let local = metricRow(symbol: "laptopcomputer", title: "本地⌄", trailing: nil)
        let branch = metricRow(symbol: "point.3.connected.trianglepath.dotted", title: "master⌄", trailing: nil)
        let push = metricRow(symbol: "icloud.and.arrow.up", title: "提交或推送", trailing: nil)

        let divider = NSBox()
        divider.boxType = .separator
        divider.translatesAutoresizingMaskIntoConstraints = false

        let sourceTitle = label("来源", size: 13, weight: .regular, color: .secondaryLabelColor)
        let sourceEmpty = label("暂无来源", size: 13, weight: .regular, color: .tertiaryLabelColor)

        let stack = NSStackView(views: [titleRow, changes, local, branch, push, divider, sourceTitle, sourceEmpty])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 13
        stack.translatesAutoresizingMaskIntoConstraints = false
        addSubview(stack)

        NSLayoutConstraint.activate([
            widthAnchor.constraint(equalToConstant: 260),
            stack.topAnchor.constraint(equalTo: topAnchor, constant: 16),
            stack.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 16),
            stack.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -16),
            stack.bottomAnchor.constraint(lessThanOrEqualTo: bottomAnchor, constant: -16),
            divider.widthAnchor.constraint(equalTo: stack.widthAnchor),
        ])
    }

    private func metricRow(symbol: String, title: String, trailing: String?, trailingColor: NSColor = .labelColor) -> NSView {
        let icon = NSImageView(image: NSImage(systemSymbolName: symbol, accessibilityDescription: nil) ?? NSImage())
        icon.contentTintColor = .secondaryLabelColor
        icon.translatesAutoresizingMaskIntoConstraints = false
        let titleLabel = label(title, size: 13, weight: .medium, color: .labelColor)
        var views: [NSView] = [icon, titleLabel, spacer()]
        if let trailing {
            views.append(label(trailing, size: 13, weight: .semibold, color: trailingColor))
        }
        let v = row(views, spacing: 10)
        NSLayoutConstraint.activate([
            icon.widthAnchor.constraint(equalToConstant: 15),
            icon.heightAnchor.constraint(equalToConstant: 15),
        ])
        return v
    }

    private func label(_ string: String, size: CGFloat, weight: NSFont.Weight, color: NSColor) -> NSTextField {
        let label = NSTextField(labelWithString: string)
        label.font = .systemFont(ofSize: size, weight: weight)
        label.textColor = color
        label.translatesAutoresizingMaskIntoConstraints = false
        return label
    }

    private func symbolButton(_ symbol: String, tooltip: String) -> NSButton {
        let button = NSButton()
        button.image = NSImage(systemSymbolName: symbol, accessibilityDescription: tooltip)
        button.toolTip = tooltip
        button.bezelStyle = .inline
        button.isBordered = false
        button.contentTintColor = .secondaryLabelColor
        button.translatesAutoresizingMaskIntoConstraints = false
        return button
    }

    private func row(_ views: [NSView], spacing: CGFloat) -> NSStackView {
        let stack = NSStackView(views: views)
        stack.orientation = .horizontal
        stack.alignment = .centerY
        stack.spacing = spacing
        stack.translatesAutoresizingMaskIntoConstraints = false
        stack.widthAnchor.constraint(equalToConstant: 228).isActive = true
        return stack
    }

    private func spacer() -> NSView {
        let view = NSView()
        view.translatesAutoresizingMaskIntoConstraints = false
        view.setContentHuggingPriority(.defaultLow, for: .horizontal)
        return view
    }
}
