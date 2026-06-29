import AppKit

// MARK: - Group Row View

/// NSTableCellView-style view for a HistoryProjectGroup row.
/// Displays the project name and a "+" button to start a new session.
final class HistoryGroupRowView: NSView {
    // MARK: Subviews
    let nameLabel = NSTextField(labelWithString: "")
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
        nameLabel.textColor = .secondaryLabelColor
        nameLabel.lineBreakMode = .byTruncatingMiddle
        nameLabel.maximumNumberOfLines = 1
        nameLabel.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        nameLabel.translatesAutoresizingMaskIntoConstraints = false
        addSubview(nameLabel)

        // "+" button
        addButton.title = ""
        addButton.image = NSImage(systemSymbolName: "plus", accessibilityDescription: nil)
        addButton.image?.size = NSSize(width: 11, height: 11)
        addButton.bezelStyle = .inline
        addButton.isBordered = false
        addButton.contentTintColor = .secondaryLabelColor
        addButton.target = self
        addButton.action = #selector(handleAdd)
        addButton.translatesAutoresizingMaskIntoConstraints = false
        addSubview(addButton)

        NSLayoutConstraint.activate([
            nameLabel.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 8),
            nameLabel.centerYAnchor.constraint(equalTo: centerYAnchor),
            nameLabel.trailingAnchor.constraint(lessThanOrEqualTo: addButton.leadingAnchor, constant: -4),

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
        addButton.toolTip = "New session in \(group.projectName)"
    }
}

// MARK: - Thread Row View

/// NSTableCellView-style view for a HistoryThreadSummary row.
/// Mirrors the SwiftUI `historyThreadRow` visual treatment.
final class HistoryThreadRowView: NSView {
    // MARK: Subviews
    private let accentBar = NSView()
    private let agentIconView = NSImageView()
    private let runtimeDotView = NSView()
    private let titleLabel = NSTextField(labelWithString: "")
    private let metaLabel = NSTextField(labelWithString: "")
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

        // Agent icon (14×14)
        agentIconView.imageScaling = .scaleProportionallyUpOrDown
        agentIconView.contentTintColor = .secondaryLabelColor
        agentIconView.translatesAutoresizingMaskIntoConstraints = false
        addSubview(agentIconView)

        // Runtime phase dot
        runtimeDotView.wantsLayer = true
        runtimeDotView.layer?.cornerRadius = 2.5  // default 5pt dot
        runtimeDotView.translatesAutoresizingMaskIntoConstraints = false
        addSubview(runtimeDotView)
        runtimeDotWidth = runtimeDotView.widthAnchor.constraint(equalToConstant: 5)
        runtimeDotHeight = runtimeDotView.heightAnchor.constraint(equalToConstant: 5)

        // Title label
        titleLabel.font = .systemFont(ofSize: NSFont.systemFontSize)
        titleLabel.textColor = .secondaryLabelColor
        titleLabel.lineBreakMode = .byWordWrapping
        titleLabel.maximumNumberOfLines = 2
        titleLabel.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        titleLabel.translatesAutoresizingMaskIntoConstraints = false
        addSubview(titleLabel)

        // Meta label (status / source / date)
        metaLabel.font = .systemFont(ofSize: NSFont.smallSystemFontSize - 1)
        metaLabel.textColor = .tertiaryLabelColor
        metaLabel.lineBreakMode = .byTruncatingTail
        metaLabel.maximumNumberOfLines = 1
        metaLabel.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        metaLabel.translatesAutoresizingMaskIntoConstraints = false
        addSubview(metaLabel)

        // Opening progress spinner (mini)
        openingProgress.style = .spinning
        openingProgress.controlSize = .mini
        openingProgress.isIndeterminate = true
        openingProgress.isHidden = true
        openingProgress.translatesAutoresizingMaskIntoConstraints = false
        addSubview(openingProgress)

        let textStack = NSStackView(views: [titleLabel, metaLabel])
        textStack.orientation = .vertical
        textStack.alignment = .leading
        textStack.spacing = 3
        textStack.translatesAutoresizingMaskIntoConstraints = false
        addSubview(textStack)

        NSLayoutConstraint.activate([
            // Accent bar: 3 px wide, full height
            accentBar.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 4),
            accentBar.topAnchor.constraint(equalTo: topAnchor, constant: 4),
            accentBar.bottomAnchor.constraint(equalTo: bottomAnchor, constant: -4),
            accentBar.widthAnchor.constraint(equalToConstant: 3),

            // Agent icon
            agentIconView.leadingAnchor.constraint(equalTo: accentBar.trailingAnchor, constant: 6),
            agentIconView.centerYAnchor.constraint(equalTo: titleLabel.centerYAnchor),
            agentIconView.widthAnchor.constraint(equalToConstant: 14),
            agentIconView.heightAnchor.constraint(equalToConstant: 14),

            // Runtime dot (size driven by runtimeDotWidth/Height, updated on configure)
            runtimeDotView.leadingAnchor.constraint(equalTo: agentIconView.trailingAnchor, constant: 4),
            runtimeDotView.centerYAnchor.constraint(equalTo: titleLabel.centerYAnchor),
            runtimeDotWidth,
            runtimeDotHeight,

            // Title + meta stack
            textStack.leadingAnchor.constraint(equalTo: runtimeDotView.trailingAnchor, constant: 4),
            textStack.trailingAnchor.constraint(equalTo: openingProgress.leadingAnchor, constant: -4),
            textStack.topAnchor.constraint(equalTo: topAnchor, constant: 7),
            textStack.bottomAnchor.constraint(equalTo: bottomAnchor, constant: -7),

            // Opening spinner
            openingProgress.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -8),
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
        titleLabel.textColor = presentation.isEmphasized ? .labelColor : .secondaryLabelColor
        titleLabel.stringValue = thread.displayTitle

        // Meta line: status · runtimeStatus · source · date
        var metaParts: [String] = [thread.status]
        if let runtimeStatus = presentation.runtimeStatusLabel {
            metaParts.append(runtimeStatus)
        }
        metaParts.append(thread.source)
        metaParts.append(Self.updatedLabel(thread.updatedAt))
        metaLabel.stringValue = metaParts.joined(separator: " · ")

        // Accent bar
        let accentColor = Self.accentBarColor(presentation)
        accentBar.layer?.backgroundColor = accentColor.cgColor

        // Agent icon
        let imageCache = HistoryAgentImageCache.shared
        if let img = imageCache.image(named: presentation.agentSourceImageName) {
            agentIconView.image = img
            agentIconView.contentTintColor = presentation.isEmphasized ? .controlAccentColor : .secondaryLabelColor
        } else {
            agentIconView.image = NSImage(systemSymbolName: "questionmark.circle", accessibilityDescription: nil)
            agentIconView.contentTintColor = .secondaryLabelColor
        }
        agentIconView.toolTip = presentation.agentSourceLabel

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
        setAccessibilityLabel("Open \(presentation.agentSourceLabel) thread, \(thread.displayTitle)")
    }

    // MARK: Helpers

    private static func accentBarColor(_ p: HistoryThreadRowPresentation) -> NSColor {
        switch p.visualState {
        case .opening, .selected: return .controlAccentColor
        case .hovered:            return .tertiaryLabelColor
        case .idle:               return .clear
        }
    }

    private static func runtimeDotColor(_ p: HistoryThreadRowPresentation) -> NSColor {
        if p.hasUnreadIndicator { return .controlAccentColor }
        switch p.runtimePhase {
        case .running, .starting: return .controlAccentColor
        case .waitingApproval:    return .systemOrange
        case .failed:             return .systemRed
        case .some:               return .tertiaryLabelColor
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
