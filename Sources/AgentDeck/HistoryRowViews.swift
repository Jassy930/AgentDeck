import AppKit

// MARK: - Group Row View

/// NSTableCellView-style view for a HistoryProjectGroup row.
/// Displays the project name and a "+" button to start a new session.
final class HistoryGroupRowView: NSView {
    // MARK: Subviews
    let nameLabel = NSTextField(labelWithString: "")
    let countLabel = NSTextField(labelWithString: "")
    let addButton = NSButton()

    // MARK: Callbacks
    var onAdd: (() -> Void)?

    // MARK: Init
    override init(frame: NSRect) {
        super.init(frame: frame)
        setup()
    }

    required init?(coder: NSCoder) {
        super.init(coder: coder)
        setup()
    }

    private func setup() {
        // Project name label
        nameLabel.font = .systemFont(ofSize: NSFont.smallSystemFontSize, weight: .semibold)
        nameLabel.textColor = DesignTokens.text2
        nameLabel.lineBreakMode = .byTruncatingMiddle
        nameLabel.maximumNumberOfLines = 1
        nameLabel.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        nameLabel.setContentHuggingPriority(.defaultHigh, for: .horizontal)
        nameLabel.translatesAutoresizingMaskIntoConstraints = false
        addSubview(nameLabel)

        // 项目会话数（设计系统组标题："refactor-auth 6"）
        countLabel.font = .systemFont(ofSize: NSFont.smallSystemFontSize)
        countLabel.textColor = DesignTokens.text3
        countLabel.translatesAutoresizingMaskIntoConstraints = false
        addSubview(countLabel)

        // "+" button
        addButton.title = ""
        addButton.image = NSImage(systemSymbolName: "plus", accessibilityDescription: nil)
        addButton.image?.size = NSSize(width: 11, height: 11)
        addButton.bezelStyle = .inline
        addButton.isBordered = false
        addButton.contentTintColor = DesignTokens.text2
        addButton.target = self
        addButton.action = #selector(handleAdd)
        addButton.translatesAutoresizingMaskIntoConstraints = false
        addSubview(addButton)

        NSLayoutConstraint.activate([
            nameLabel.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 8),
            nameLabel.centerYAnchor.constraint(equalTo: centerYAnchor),

            countLabel.leadingAnchor.constraint(equalTo: nameLabel.trailingAnchor, constant: 6),
            countLabel.centerYAnchor.constraint(equalTo: centerYAnchor),
            countLabel.trailingAnchor.constraint(lessThanOrEqualTo: addButton.leadingAnchor, constant: -6),

            addButton.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -6),
            addButton.centerYAnchor.constraint(equalTo: centerYAnchor),
            addButton.widthAnchor.constraint(equalToConstant: 18),
            addButton.heightAnchor.constraint(equalToConstant: 18),
        ])
    }

    @objc private func handleAdd() {
        onAdd?()
    }

    func configure(with group: HistoryProjectGroup) {
        nameLabel.stringValue = group.projectName
        countLabel.stringValue = "\(group.threads.count)"
        addButton.toolTip = "New session in \(group.projectName)"
    }
}

// MARK: - Thread Row View

/// NSTableCellView-style view for a HistoryThreadSummary row.
/// Mirrors the SwiftUI `historyThreadRow` visual treatment.
final class HistoryThreadRowView: NSView {
    // MARK: Subviews
    private let accentBar = NSView()
    private let runtimeDotView = NSView()
    private let titleLabel = NSTextField(labelWithString: "")
    private let openingProgress = NSProgressIndicator()

    /// Size constraints for the runtime dot — updated on configure so the dot
    /// truly resizes between 5pt (cached) and 7pt (unread). Auto Layout owns
    /// the size; we never touch `layer.bounds` (which the next layout pass
    /// would overwrite).
    private var runtimeDotWidth: NSLayoutConstraint!
    private var runtimeDotHeight: NSLayoutConstraint!

    // MARK: Init
    override init(frame: NSRect) {
        super.init(frame: frame)
        setup()
    }

    required init?(coder: NSCoder) {
        super.init(coder: coder)
        setup()
    }

    private func setup() {
        // Accent bar on left edge
        accentBar.wantsLayer = true
        accentBar.layer?.cornerRadius = 1.5
        accentBar.translatesAutoresizingMaskIntoConstraints = false
        addSubview(accentBar)

        // Runtime phase dot
        runtimeDotView.wantsLayer = true
        runtimeDotView.layer?.cornerRadius = 2.5  // default 5pt dot
        runtimeDotView.translatesAutoresizingMaskIntoConstraints = false
        addSubview(runtimeDotView)
        runtimeDotWidth = runtimeDotView.widthAnchor.constraint(equalToConstant: 5)
        runtimeDotHeight = runtimeDotView.heightAnchor.constraint(equalToConstant: 5)

        // Title label
        titleLabel.font = .systemFont(ofSize: NSFont.systemFontSize)
        titleLabel.textColor = DesignTokens.text2
        titleLabel.lineBreakMode = .byTruncatingTail
        titleLabel.maximumNumberOfLines = 1
        titleLabel.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        titleLabel.translatesAutoresizingMaskIntoConstraints = false
        addSubview(titleLabel)

        // Opening progress spinner (mini)
        openingProgress.style = .spinning
        openingProgress.controlSize = .mini
        openingProgress.isIndeterminate = true
        openingProgress.isHidden = true
        openingProgress.translatesAutoresizingMaskIntoConstraints = false
        addSubview(openingProgress)

        NSLayoutConstraint.activate([
            // Accent bar: 3 px wide, near-full height
            accentBar.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 4),
            accentBar.topAnchor.constraint(equalTo: topAnchor, constant: 5),
            accentBar.bottomAnchor.constraint(equalTo: bottomAnchor, constant: -5),
            accentBar.widthAnchor.constraint(equalToConstant: 3),

            // Runtime dot — 垂直居中（单行）
            runtimeDotView.leadingAnchor.constraint(equalTo: accentBar.trailingAnchor, constant: 8),
            runtimeDotView.centerYAnchor.constraint(equalTo: centerYAnchor),
            runtimeDotWidth,
            runtimeDotHeight,

            // 单行标题填充（统一历史：不显示 agent 图标）
            titleLabel.leadingAnchor.constraint(equalTo: runtimeDotView.trailingAnchor, constant: 8),
            titleLabel.centerYAnchor.constraint(equalTo: centerYAnchor),
            titleLabel.trailingAnchor.constraint(lessThanOrEqualTo: trailingAnchor, constant: -10),

            // Opening spinner
            openingProgress.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -9),
            openingProgress.centerYAnchor.constraint(equalTo: centerYAnchor),
            openingProgress.widthAnchor.constraint(equalToConstant: 12),
            openingProgress.heightAnchor.constraint(equalToConstant: 12),
        ])
    }

    // MARK: Configure

    func configure(with thread: HistoryThreadSummary, presentation: HistoryThreadRowPresentation) {
        // Title
        let fontWeight: NSFont.Weight = presentation.isEmphasized ? .medium : .regular
        titleLabel.font = .systemFont(ofSize: NSFont.systemFontSize, weight: fontWeight)
        titleLabel.textColor = presentation.isEmphasized ? DesignTokens.text : DesignTokens.text2
        titleLabel.stringValue = thread.displayTitle

        // meta（status · 运行态 · 日期）转为 tooltip（单行不再显示文本；统一历史不显示 agent 图标）
        var metaParts: [String] = [thread.status]
        if let runtimeStatus = presentation.runtimeStatusLabel {
            metaParts.append(runtimeStatus)
        }
        metaParts.append(Self.updatedLabel(thread.updatedAt))
        toolTip = metaParts.joined(separator: " · ")

        // Accent bar
        let accentColor = Self.accentBarColor(presentation)
        accentBar.layer?.backgroundColor = accentColor.cgColor

        // Runtime dot — size driven by Auto Layout constraints (5pt cached / 7pt unread)
        if presentation.hasRuntimeIndicator {
            runtimeDotView.isHidden = false
            let dotSize: CGFloat = presentation.hasUnreadIndicator ? 7 : 5
            runtimeDotWidth.constant = dotSize
            runtimeDotHeight.constant = dotSize
            runtimeDotView.layer?.cornerRadius = dotSize / 2
            runtimeDotView.layer?.backgroundColor = Self.runtimeDotColor(presentation).cgColor
        } else {
            runtimeDotView.isHidden = true
            runtimeDotView.layer?.backgroundColor = NSColor.clear.cgColor
        }

        // Opening spinner
        if presentation.visualState == .opening {
            openingProgress.isHidden = false
            openingProgress.startAnimation(nil)
        } else {
            openingProgress.stopAnimation(nil)
            openingProgress.isHidden = true
        }

        // Accessibility
        setAccessibilityLabel("Open thread, \(thread.displayTitle)")
    }

    // MARK: Helpers

    private static func accentBarColor(_ p: HistoryThreadRowPresentation) -> NSColor {
        switch p.visualState {
        case .opening, .selected: return DesignTokens.accent
        case .hovered:            return DesignTokens.text3
        case .idle:               return .clear
        }
    }

    private static func runtimeDotColor(_ p: HistoryThreadRowPresentation) -> NSColor {
        if p.hasUnreadIndicator { return DesignTokens.accent }
        switch p.runtimePhase {
        case .running, .starting: return DesignTokens.running
        case .waitingApproval:    return DesignTokens.warn
        case .failed:             return DesignTokens.danger
        case .some:               return DesignTokens.text3
        case .none:               return .clear
        }
    }

    static func updatedLabel(_ updatedAt: Int) -> String {
        let date = Date(timeIntervalSince1970: Double(updatedAt))
        let now = Date()
        let diff = now.timeIntervalSince(date)
        if diff < 60 { return "just now" }
        if diff < 3600 { return "\(Int(diff / 60))m ago" }
        if diff < 86400 { return "\(Int(diff / 3600))h ago" }
        let formatter = DateFormatter()
        formatter.dateStyle = .short
        formatter.timeStyle = .none
        return formatter.string(from: date)
    }
}
