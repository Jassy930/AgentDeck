import AppKit

// 视觉 token 统一走 DesignTokens（由设计系统 SSOT 生成）。此处仅做语义别名，
// 保持既有调用点 API 不变，同时让全 App 配色对齐设计系统 codex 主题。
enum CodexDesktopChrome {
    static let windowBackground = DesignTokens.bg
    static let sidebarBackground = DesignTokens.sidebarBg
    /// 侧栏固定深色底（跨屏一致；贴近毛玻璃压暗后的观感，单值可调）。
    static let sidebarSolid = NSColor(srgbRed: 0.098, green: 0.098, blue: 0.098, alpha: 1)
    static let sidebarTopTint = NSColor(srgbRed: 0.08, green: 0.25, blue: 0.17, alpha: 0.30)
    static let panelBackground = DesignTokens.surface
    static let panelHoverBackground = DesignTokens.surface2
    static let cardBackground = DesignTokens.surface
    static let border = DesignTokens.border
    static let separator = DesignTokens.separator
    static let orange = DesignTokens.accent

    @MainActor
    static func roundedPanel(_ view: NSView, radius: CGFloat, border: Bool = true, shadow: Bool = false) {
        view.wantsLayer = true
        view.layer?.backgroundColor = panelBackground.cgColor
        view.layer?.cornerRadius = radius
        view.layer?.cornerCurve = .continuous
        if border {
            view.layer?.borderWidth = 1
            view.layer?.borderColor = CodexDesktopChrome.border.cgColor
        }
        if shadow {
            view.layer?.shadowColor = DesignTokens.panelShadowColor.cgColor
            view.layer?.shadowOpacity = 1
            view.layer?.shadowRadius = DesignTokens.panelShadowBlur / 2
            view.layer?.shadowOffset = DesignTokens.panelShadowOffset
            view.layer?.masksToBounds = false
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
        label.textColor = DesignTokens.text
        label.lineBreakMode = .byTruncatingTail
        label.translatesAutoresizingMaskIntoConstraints = false
        return label
    }()

    private let cwdLabel: NSTextField = {
        let label = NSTextField(labelWithString: "")
        label.font = .systemFont(ofSize: 12)
        label.textColor = DesignTokens.text3
        label.lineBreakMode = .byTruncatingMiddle
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
        // 模板图跟随此 tint（暗背景下可见；标题旁略醒目用 text）。
        agentIcon.contentTintColor = DesignTokens.text
        agentIcon.translatesAutoresizingMaskIntoConstraints = false

        // 设计系统：右侧用文件夹图标（打开位置），非文字按钮
        openLocationButton.image = NSImage(systemSymbolName: "folder", accessibilityDescription: "打开位置")
        openLocationButton.imagePosition = .imageOnly
        openLocationButton.title = ""
        openLocationButton.bezelStyle = .inline
        openLocationButton.isBordered = false
        openLocationButton.contentTintColor = DesignTokens.text2
        openLocationButton.translatesAutoresizingMaskIntoConstraints = false

        controlsButton.image = NSImage(systemSymbolName: "slider.horizontal.3", accessibilityDescription: "界面选项")
        controlsButton.bezelStyle = .inline
        controlsButton.isBordered = false
        controlsButton.contentTintColor = DesignTokens.text2
        controlsButton.translatesAutoresizingMaskIntoConstraints = false

        // 设计系统：agent 图标 + 标题 + cwd 灰字（无「…」）
        let leftStack = NSStackView(views: [agentIcon, titleLabel, cwdLabel])
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
        cwdLabel.stringValue = model.cwd.map { ($0.path as NSString).abbreviatingWithTildeInPath } ?? ""
        cwdLabel.isHidden = model.cwd == nil
        openLocationButton.isHidden = model.cwd == nil
    }

    deinit {
        let b = binder
        Task { @MainActor in b.invalidate() }
    }
}

@MainActor
final class CodexEnvironmentPanelView: NSView {
    private weak var model: SessionModel?
    private let binder = ObservationBinder()

    private let changesValue = NSTextField(labelWithString: "")
    private let fileCountValue = NSTextField(labelWithString: "")
    private let branchValue = NSTextField(labelWithString: "")
    private let commitValue = NSTextField(labelWithString: "")

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
        CodexDesktopChrome.roundedPanel(self, radius: DesignTokens.radiusLg, shadow: true)

        // 标题：变更 Changes
        let title = label("变更 Changes", size: 13, weight: .medium, color: DesignTokens.text2)

        // 大号统计：+128 -34   3 文件
        changesValue.font = .systemFont(ofSize: 22, weight: .semibold)
        changesValue.textColor = DesignTokens.text
        fileCountValue.font = .systemFont(ofSize: 12, weight: .regular)
        fileCountValue.textColor = DesignTokens.text3
        let changesRow = row([changesValue, fileCountValue, spacer()], spacing: 10)

        // 分组标题：Git
        let gitTitle = label("Git", size: 13, weight: .medium, color: DesignTokens.text2)

        // 键值：分支 …… main / 提交 …… a1b2c3d（值右对齐）
        let branchRow = keyValueRow("分支", value: branchValue)
        let commitRow = keyValueRow("提交", value: commitValue)

        let stack = NSStackView(views: [title, changesRow, gitTitle, branchRow, commitRow])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 12
        stack.translatesAutoresizingMaskIntoConstraints = false
        addSubview(stack)

        NSLayoutConstraint.activate([
            widthAnchor.constraint(equalToConstant: 260),
            stack.topAnchor.constraint(equalTo: topAnchor, constant: 16),
            stack.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 16),
            stack.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -16),
            stack.bottomAnchor.constraint(lessThanOrEqualTo: bottomAnchor, constant: -16),
        ])
    }

    private func bind() {
        binder.bind({ [weak self] in
            _ = self?.model?.environmentInfo
        }, onChange: { [weak self] in
            self?.refresh()
        })
    }

    private func refresh() {
        let info = model?.environmentInfo
        changesValue.stringValue = info?.changesSummary ?? "+0 -0"
        fileCountValue.stringValue = info?.fileCountSummary ?? "0 文件"
        branchValue.stringValue = info?.branch ?? "—"
        commitValue.stringValue = info?.commit ?? "—"
    }

    private func keyValueRow(_ key: String, value: NSTextField) -> NSView {
        let k = label(key, size: 13, weight: .regular, color: DesignTokens.text2)
        value.font = .monospacedSystemFont(ofSize: 12, weight: .regular)
        value.textColor = DesignTokens.text
        value.alignment = .right
        return row([k, spacer(), value], spacing: 10)
    }

    private func label(_ s: String, size: CGFloat, weight: NSFont.Weight, color: NSColor) -> NSTextField {
        let l = NSTextField(labelWithString: s)
        l.font = .systemFont(ofSize: size, weight: weight)
        l.textColor = color
        l.translatesAutoresizingMaskIntoConstraints = false
        return l
    }

    private func row(_ views: [NSView], spacing: CGFloat) -> NSStackView {
        let stack = NSStackView(views: views)
        stack.orientation = .horizontal
        stack.alignment = .firstBaseline
        stack.spacing = spacing
        stack.translatesAutoresizingMaskIntoConstraints = false
        stack.widthAnchor.constraint(equalToConstant: 228).isActive = true
        return stack
    }

    private func spacer() -> NSView {
        let v = NSView()
        v.translatesAutoresizingMaskIntoConstraints = false
        v.setContentHuggingPriority(.defaultLow, for: .horizontal)
        return v
    }

    /// 测试辅助：收集所有子 label 文本。
    func allLabelsForTest() -> [String] {
        func collect(_ v: NSView) -> [String] {
            var out: [String] = []
            if let tf = v as? NSTextField { out.append(tf.stringValue) }
            for sub in v.subviews { out += collect(sub) }
            return out
        }
        return collect(self)
    }

    deinit {
        let b = binder
        Task { @MainActor in b.invalidate() }
    }
}
