import AppKit

// MARK: - AppKit conversation row cell views (Task 7)
//
// One NSTableCellView subclass per `ConversationDisplayRow` kind. The EXISTING
// SwiftUI source (SessionView.swift / MessageRoleViews.swift) is the visual
// spec — each cell ports its corresponding SwiftUI branch faithfully:
//
//   userPrompt          ← UserPromptBlock (MessageRoleViews.swift)
//   message             ← assistantItemRow "message" + RichMessageView
//   reasoning           ← ReasoningRow (SessionView.swift)
//   shell               ← assistantItemRow "shell"
//   fileEdit            ← assistantItemRow "fileEdit"
//   webSearch           ← assistantItemRow "webSearch"
//   plan / hookPrompt / toolCall / collabAgentToolCall / media /
//   reviewMode / contextCompaction / raw  ← the matching branch
//   error / warning     ← errorRow / warningRow (standalone, used by Task 8)
//
// Design law D7: items are separated by typographic rhythm, NOT cards. No cell
// here draws a card (approval is the only card — that's Task 8).
//
// Streaming kinds (message / reasoning / shell / fileEdit) bind their primary
// text through `StreamingTextContainerView.bindBuffer(to:font:color:)` so the
// daemon stream flows straight into the text view. Everything else renders
// static text via `MarkdownAttributedStringBuilder` / `NSTextField`.

// MARK: - Disclosure persistence (C1)

/// Lets the collapsible tool cells (`ShellCellView` / `FileEditCellView`)
/// persist their expand/collapse state OUTSIDE the recycled cell, in the
/// controller. Cells are reconfigured on every ~30fps streaming flush; without
/// an external store each `configure` would reset the disclosure to collapsed,
/// snapping shut output the user just expanded mid-turn (C1).
///
/// `configure` reads `isItemExpanded` to restore state; the disclosure toggle
/// writes `setItem(_:expanded:)`, which persists the flag, invalidates the
/// cached row height and re-measures the row.
@MainActor
protocol ConversationDisclosureStateStore: AnyObject {
    func isItemExpanded(_ itemId: String) -> Bool
    func setItem(_ itemId: String, expanded: Bool)
}

// MARK: - Shared metrics & helpers

/// Layout constants shared by cells and the factory's height math. Centralised
/// so the rendered height and the measured height never drift.
enum ConversationRowMetrics {
    /// Body / callout text (SwiftUI `.callout` ≈ systemFontSize - 1 ≈ 12).
    static let calloutSize: CGFloat = NSFont.systemFontSize - 1
    /// Caption text (SwiftUI `.caption`).
    static let captionSize: CGFloat = NSFont.smallSystemFontSize

    static var calloutFont: NSFont { .systemFont(ofSize: calloutSize) }
    static var calloutMediumFont: NSFont { .systemFont(ofSize: calloutSize, weight: .medium) }
    static var captionFont: NSFont { .systemFont(ofSize: captionSize) }
    static var captionSemiboldFont: NSFont { .systemFont(ofSize: captionSize, weight: .semibold) }
    static var monoCalloutFont: NSFont { .monospacedSystemFont(ofSize: calloutSize, weight: .regular) }
    static var monoCalloutMediumFont: NSFont { .monospacedSystemFont(ofSize: calloutSize, weight: .medium) }
    static var monoCaptionFont: NSFont { .monospacedSystemFont(ofSize: captionSize, weight: .regular) }

    /// Single-line height for a font (used by the factory's fixed-element math).
    static func lineHeight(_ font: NSFont) -> CGFloat {
        ceil(font.boundingRectForFont.height)
    }
}

/// Factory helpers for the simple AppKit primitives the cells reuse. Keeping
/// these here avoids repeating the same `NSTextField` / disclosure-button
/// boilerplate in every cell.
@MainActor
enum ConversationRowControls {

    /// A non-editable, multiline, selectable label (mirrors SwiftUI `Text` +
    /// `.textSelection(.enabled)`).
    static func label(font: NSFont, color: NSColor, selectable: Bool = true) -> NSTextField {
        let field = NSTextField(labelWithString: "")
        field.font = font
        field.textColor = color
        field.lineBreakMode = .byWordWrapping
        field.maximumNumberOfLines = 0
        field.isSelectable = selectable
        field.translatesAutoresizingMaskIntoConstraints = false
        field.setContentHuggingPriority(.defaultLow, for: .horizontal)
        field.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        return field
    }

    /// A disclosure triangle button with a trailing caption label, matching the
    /// SwiftUI `DisclosureGroup` trigger. Returns the button so the caller can
    /// wire its action / title.
    static func disclosureButton(title: String) -> NSButton {
        let button = NSButton()
        button.setButtonType(.onOff)
        button.bezelStyle = .disclosure
        button.title = title
        button.font = ConversationRowMetrics.monoCaptionFont
        button.contentTintColor = DesignTokens.text3
        button.translatesAutoresizingMaskIntoConstraints = false
        return button
    }
}

// MARK: - Base cell

/// Common scaffolding: a top-anchored vertical content stack inset by the
/// row's leading margin and the kind's vertical padding. Subclasses populate
/// `contentStack`.
class ConversationRowCellView: NSTableCellView {

    /// Horizontal inset applied to every row (SwiftUI stream `.padding(.leading, 20)`).
    /// `nonisolated` so the factory's (MainActor) height math and any layout
    /// helper can read this pure constant without isolation noise.
    nonisolated static let horizontalInset: CGFloat = 20
    /// Default vertical padding for assistant tool rows (`.padding(.vertical, 10)`).
    var verticalPadding: CGFloat { 10 }

    let contentStack: NSStackView = {
        let stack = NSStackView()
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 5
        stack.translatesAutoresizingMaskIntoConstraints = false
        return stack
    }()

    private var topConstraint: NSLayoutConstraint?
    private var bottomConstraint: NSLayoutConstraint?

    /// Set by the controller when (re)configuring a collapsible cell so it can
    /// persist its disclosure state across reuse (C1). Weak — the controller
    /// owns the store; cells are recycled and must not extend its lifetime.
    weak var disclosureStore: ConversationDisclosureStateStore?

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        installContentStack()
    }

    required init?(coder: NSCoder) {
        super.init(coder: coder)
        installContentStack()
    }

    private func installContentStack() {
        addSubview(contentStack)
        let top = contentStack.topAnchor.constraint(equalTo: topAnchor, constant: verticalPadding)
        let bottom = bottomAnchor.constraint(equalTo: contentStack.bottomAnchor, constant: verticalPadding)
        topConstraint = top
        bottomConstraint = bottom
        NSLayoutConstraint.activate([
            top,
            bottom,
            contentStack.leadingAnchor.constraint(
                equalTo: leadingAnchor, constant: Self.horizontalInset),
            contentStack.trailingAnchor.constraint(
                lessThanOrEqualTo: trailingAnchor, constant: -Self.horizontalInset),
        ])
    }

    /// Apply the kind's vertical padding (called once the subclass's
    /// `verticalPadding` is known — `init` reads the overridden value already,
    /// but this lets subclasses re-assert it defensively).
    func applyVerticalPadding() {
        topConstraint?.constant = verticalPadding
        bottomConstraint?.constant = verticalPadding
    }

    /// Remove every arranged subview so a reused cell starts clean.
    func resetContent() {
        for view in contentStack.arrangedSubviews {
            contentStack.removeArrangedSubview(view)
            view.removeFromSuperview()
        }
    }

    /// Width available to wrapped text inside the content stack.
    func contentWidth(forRowWidth width: CGFloat) -> CGFloat {
        max(width - Self.horizontalInset * 2, 1)
    }

    func configure(row: ConversationDisplayRow, width: CGFloat, model: SessionModel) {
        // Overridden by subclasses.
    }
}

// MARK: - User prompt

/// Ports `UserPromptBlock`: left accent bar + "You" caption + markdown body,
/// wrapped in a quaternary-fill rounded rectangle.
final class UserPromptCellView: ConversationRowCellView {
    override var verticalPadding: CGFloat { 8 }

    private let bubble = NSView()
    private let accentBar = NSView()
    private let youLabel = ConversationRowControls.label(
        font: ConversationRowMetrics.captionSemiboldFont, color: DesignTokens.text2)
    private let bodyLabel = ConversationRowControls.label(
        font: ConversationRowMetrics.calloutFont, color: DesignTokens.text)

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        buildBubble()
    }

    required init?(coder: NSCoder) {
        super.init(coder: coder)
        buildBubble()
    }

    private func buildBubble() {
        applyVerticalPadding()
        bubble.translatesAutoresizingMaskIntoConstraints = false
        bubble.wantsLayer = true
        bubble.layer?.cornerRadius = 7
        bubble.layer?.backgroundColor = NSColor.quaternarySystemFill.cgColor

        accentBar.translatesAutoresizingMaskIntoConstraints = false
        accentBar.wantsLayer = true
        accentBar.layer?.cornerRadius = 1.5
        accentBar.layer?.backgroundColor = NSColor.controlAccentColor.withAlphaComponent(0.45).cgColor

        youLabel.stringValue = "You"

        let textColumn = NSStackView(views: [youLabel, bodyLabel])
        textColumn.orientation = .vertical
        textColumn.alignment = .leading
        textColumn.spacing = 5
        textColumn.translatesAutoresizingMaskIntoConstraints = false

        bubble.addSubview(accentBar)
        bubble.addSubview(textColumn)
        NSLayoutConstraint.activate([
            accentBar.leadingAnchor.constraint(equalTo: bubble.leadingAnchor, constant: 12),
            accentBar.topAnchor.constraint(equalTo: bubble.topAnchor, constant: 10),
            accentBar.bottomAnchor.constraint(equalTo: bubble.bottomAnchor, constant: -10),
            accentBar.widthAnchor.constraint(equalToConstant: 3),

            textColumn.leadingAnchor.constraint(equalTo: accentBar.trailingAnchor, constant: 10),
            textColumn.topAnchor.constraint(equalTo: bubble.topAnchor, constant: 10),
            textColumn.trailingAnchor.constraint(equalTo: bubble.trailingAnchor, constant: -12),
            textColumn.bottomAnchor.constraint(equalTo: bubble.bottomAnchor, constant: -10),
        ])

        contentStack.addArrangedSubview(bubble)
        bubble.leadingAnchor.constraint(equalTo: contentStack.leadingAnchor).isActive = true
        bubble.trailingAnchor.constraint(equalTo: contentStack.trailingAnchor).isActive = true
    }

    override func configure(row: ConversationDisplayRow, width: CGFloat, model: SessionModel) {
        let text = row.item.text
        bodyLabel.attributedStringValue = MarkdownAttributedStringBuilder.attributedString(from: text)
        bodyLabel.preferredMaxLayoutWidth = UserPromptCellView.bodyWidth(forRowWidth: width)
    }

    /// Markdown body width inside the bubble: row minus stream insets, bubble
    /// horizontal padding (12 + 12), accent bar (3) and its gap (10). Pure math,
    /// so `nonisolated` for the factory's height calculation.
    nonisolated static func bodyWidth(forRowWidth width: CGFloat) -> CGFloat {
        max(width - horizontalInset * 2 - 12 - 12 - 3 - 10, 1)
    }
}

// MARK: - Message (streaming markdown)

/// Ports the assistant "message" branch: streaming RICH markdown (design §5).
/// SwiftUI renders this through Textual's GitHub-flavoured markdown; the AppKit
/// transcript streams the text through `bindMarkdownBuffer`, which re-renders
/// the whole buffer via `MarkdownAttributedStringBuilder` on every change so
/// bold / inline-code / links appear — matching userPrompt and the original.
/// Height (factory) is measured from the SAME markdown attributed string, so
/// measurement and rendering can never disagree.
final class MessageCellView: ConversationRowCellView {
    override var verticalPadding: CGFloat { 4 }

    private let streamingView = StreamingTextContainerView()

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        applyVerticalPadding()
        streamingView.translatesAutoresizingMaskIntoConstraints = false
        contentStack.addArrangedSubview(streamingView)
        streamingView.leadingAnchor.constraint(equalTo: contentStack.leadingAnchor).isActive = true
        streamingView.trailingAnchor.constraint(equalTo: contentStack.trailingAnchor).isActive = true
    }

    required init?(coder: NSCoder) { super.init(coder: coder) }

    override func configure(row: ConversationDisplayRow, width: CGFloat, model: SessionModel) {
        streamingView.bindMarkdownBuffer(to: row.item.textBuffer, style: .standard)
    }
}

// MARK: - Reasoning (collapsible, monospaced streaming)

/// Ports `ReasoningRow`: a disclosure labelled "Reasoning", default-collapsed,
/// auto-expanded while a turn is running. The body is small secondary-coloured
/// streaming text.
final class ReasoningCellView: ConversationRowCellView {
    override var verticalPadding: CGFloat { 8 }

    private let disclosure = ConversationRowControls.disclosureButton(title: "Reasoning")
    private let streamingView = StreamingTextContainerView()
    private var bodyConstraints: [NSLayoutConstraint] = []

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        applyVerticalPadding()
        disclosure.title = "Reasoning"
        disclosure.font = ConversationRowMetrics.calloutFont
        disclosure.target = self
        disclosure.action = #selector(toggle)
        streamingView.translatesAutoresizingMaskIntoConstraints = false
        contentStack.addArrangedSubview(disclosure)
        contentStack.addArrangedSubview(streamingView)
        bodyConstraints = [
            streamingView.leadingAnchor.constraint(equalTo: contentStack.leadingAnchor),
            streamingView.trailingAnchor.constraint(equalTo: contentStack.trailingAnchor),
        ]
        NSLayoutConstraint.activate(bodyConstraints)
    }

    required init?(coder: NSCoder) { super.init(coder: coder) }

    @objc private func toggle() {
        setExpanded(disclosure.state == .on)
    }

    private func setExpanded(_ expanded: Bool) {
        disclosure.state = expanded ? .on : .off
        streamingView.isHidden = !expanded
    }

    override func configure(row: ConversationDisplayRow, width: CGFloat, model: SessionModel) {
        streamingView.bindBuffer(
            to: row.item.textBuffer,
            font: .systemFont(ofSize: NSFont.smallSystemFontSize),
            color: DesignTokens.text2
        )
        // Default-collapsed; auto-expand while the selected turn is running
        // (mirrors `model.shouldShowReasoningExpanded`).
        setExpanded(model.shouldShowReasoningExpanded)
    }
}

// MARK: - Shell

/// Ports the "shell" branch: `$ command` header (monospaced), metadata line,
/// collapsible output, and red exit-code line when non-zero.
final class ShellCellView: ConversationRowCellView {
    private let commandLabel = ConversationRowControls.label(
        font: ConversationRowMetrics.monoCalloutFont, color: DesignTokens.text)
    private let metadataLabel = ConversationRowControls.label(
        font: ConversationRowMetrics.monoCaptionFont, color: DesignTokens.text3)
    private let disclosure = ConversationRowControls.disclosureButton(title: "")
    private let outputView = StreamingTextContainerView()
    private let exitLabel = ConversationRowControls.label(
        font: ConversationRowMetrics.monoCaptionFont, color: DesignTokens.danger)

    private weak var model: SessionModel?
    private var itemId = ""

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        applyVerticalPadding()
        contentStack.spacing = 4
        disclosure.target = self
        disclosure.action = #selector(toggle)
        outputView.translatesAutoresizingMaskIntoConstraints = false

        contentStack.addArrangedSubview(commandLabel)
        contentStack.addArrangedSubview(metadataLabel)
        contentStack.addArrangedSubview(disclosure)
        contentStack.addArrangedSubview(outputView)
        contentStack.addArrangedSubview(exitLabel)
        pin(commandLabel)
        pin(metadataLabel)
        pin(outputView)
        pin(exitLabel)
    }

    required init?(coder: NSCoder) { super.init(coder: coder) }

    private func pin(_ view: NSView) {
        view.leadingAnchor.constraint(equalTo: contentStack.leadingAnchor).isActive = true
        view.trailingAnchor.constraint(equalTo: contentStack.trailingAnchor).isActive = true
    }

    @objc private func toggle() {
        let expanded = disclosure.state == .on
        outputView.isHidden = !expanded
        // Persist the expansion so a streaming reconfigure restores it (C1);
        // the store also re-measures the row height for the new body.
        disclosureStore?.setItem(itemId, expanded: expanded)
        if expanded {
            // Deferred materialization (SwiftUI `DeferredStreamingTextView`).
            model?.materializeDeferredContent(itemId: itemId, content: .output)
        }
    }

    override func configure(row: ConversationDisplayRow, width: CGFloat, model: SessionModel) {
        self.model = model
        let item = row.item
        itemId = item.id

        commandLabel.stringValue = "$ \(item.command)"
        commandLabel.preferredMaxLayoutWidth = contentWidth(forRowWidth: width)

        let metadata = ToolPresentation.shellMetadata(item)
        metadataLabel.stringValue = metadata.joined(separator: " · ")
        metadataLabel.isHidden = metadata.isEmpty

        let hasOutput = !item.output.isEmpty
        disclosure.isHidden = !hasOutput
        if hasOutput {
            disclosure.title = ToolPresentation.outputLabel(item.output)
            outputView.bindBuffer(
                to: item.outputBuffer,
                font: .monospacedSystemFont(ofSize: 13, weight: .regular),
                color: DesignTokens.text2
            )
        }
        // RESTORE persisted expansion instead of hard-resetting to collapsed —
        // otherwise every streaming flush snaps the output shut (C1). Defaults
        // to collapsed for items the user never expanded.
        let expanded = hasOutput && (disclosureStore?.isItemExpanded(item.id) ?? false)
        disclosure.state = expanded ? .on : .off
        outputView.isHidden = !expanded
        if expanded {
            model.materializeDeferredContent(itemId: item.id, content: .output)
        }

        if let code = item.exitCode, code != 0 {
            exitLabel.stringValue = "exit \(code)"
            exitLabel.isHidden = false
        } else {
            exitLabel.isHidden = true
        }
    }
}

// MARK: - File edit

/// Ports the "fileEdit" branch: path header (medium monospaced) + status line
/// + collapsible diff.
final class FileEditCellView: ConversationRowCellView {
    private let pathLabel = ConversationRowControls.label(
        font: ConversationRowMetrics.monoCalloutMediumFont, color: DesignTokens.text)
    private let statusLabel = ConversationRowControls.label(
        font: ConversationRowMetrics.monoCaptionFont, color: DesignTokens.text3)
    private let disclosure = ConversationRowControls.disclosureButton(title: "")
    private let diffView = StreamingTextContainerView()

    private weak var model: SessionModel?
    private var itemId = ""

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        applyVerticalPadding()
        contentStack.spacing = 4
        disclosure.target = self
        disclosure.action = #selector(toggle)
        diffView.translatesAutoresizingMaskIntoConstraints = false

        contentStack.addArrangedSubview(pathLabel)
        contentStack.addArrangedSubview(statusLabel)
        contentStack.addArrangedSubview(disclosure)
        contentStack.addArrangedSubview(diffView)
        pin(pathLabel)
        pin(statusLabel)
        pin(diffView)
    }

    required init?(coder: NSCoder) { super.init(coder: coder) }

    private func pin(_ view: NSView) {
        view.leadingAnchor.constraint(equalTo: contentStack.leadingAnchor).isActive = true
        view.trailingAnchor.constraint(equalTo: contentStack.trailingAnchor).isActive = true
    }

    @objc private func toggle() {
        let expanded = disclosure.state == .on
        diffView.isHidden = !expanded
        // Persist the expansion so a streaming reconfigure restores it (C1).
        disclosureStore?.setItem(itemId, expanded: expanded)
        if expanded {
            model?.materializeDeferredContent(itemId: itemId, content: .diff)
        }
    }

    override func configure(row: ConversationDisplayRow, width: CGFloat, model: SessionModel) {
        self.model = model
        let item = row.item
        itemId = item.id

        pathLabel.stringValue = item.path
        pathLabel.preferredMaxLayoutWidth = contentWidth(forRowWidth: width)

        statusLabel.stringValue = item.statusName
        statusLabel.isHidden = item.statusName.isEmpty

        let hasDiff = !item.diff.isEmpty
        disclosure.isHidden = !hasDiff
        if hasDiff {
            disclosure.title = ToolPresentation.outputLabel(item.diff, noun: "diff")
            diffView.bindBuffer(
                to: item.diffBuffer,
                font: .monospacedSystemFont(ofSize: 12, weight: .regular),
                color: DesignTokens.text
            )
        }
        // RESTORE persisted expansion instead of hard-resetting to collapsed (C1).
        let expanded = hasDiff && (disclosureStore?.isItemExpanded(item.id) ?? false)
        disclosure.state = expanded ? .on : .off
        diffView.isHidden = !expanded
        if expanded {
            model.materializeDeferredContent(itemId: item.id, content: .diff)
        }
    }
}

// MARK: - Web search

/// Ports the "webSearch" branch: magnifier + title caption, optional query
/// line, and the detail rows (query / queries / url / pattern).
final class WebSearchCellView: ConversationRowCellView {
    private let header = ConversationRowControls.label(
        font: ConversationRowMetrics.captionSemiboldFont, color: DesignTokens.text3)
    private let queryLabel = ConversationRowControls.label(
        font: ConversationRowMetrics.calloutFont, color: DesignTokens.text)
    private let detailLabel = ConversationRowControls.label(
        font: ConversationRowMetrics.monoCaptionFont, color: DesignTokens.text2)

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        applyVerticalPadding()
        contentStack.spacing = 5
        contentStack.addArrangedSubview(header)
        contentStack.addArrangedSubview(queryLabel)
        contentStack.addArrangedSubview(detailLabel)
        pin(header)
        pin(queryLabel)
        pin(detailLabel)
    }

    required init?(coder: NSCoder) { super.init(coder: coder) }

    private func pin(_ view: NSView) {
        view.leadingAnchor.constraint(equalTo: contentStack.leadingAnchor).isActive = true
        view.trailingAnchor.constraint(equalTo: contentStack.trailingAnchor).isActive = true
    }

    override func configure(row: ConversationDisplayRow, width: CGFloat, model: SessionModel) {
        let item = row.item
        header.stringValue = "🔍 " + ToolPresentation.webSearchTitle(item)

        queryLabel.stringValue = item.query
        queryLabel.isHidden = item.query.isEmpty
        queryLabel.preferredMaxLayoutWidth = contentWidth(forRowWidth: width)

        var lines: [String] = []
        if !item.actionQuery.isEmpty { lines.append("query  \(item.actionQuery)") }
        if !item.queries.isEmpty { lines.append("queries  \(item.queries.joined(separator: ", "))") }
        if !item.url.isEmpty { lines.append("url  \(item.url)") }
        if !item.pattern.isEmpty { lines.append("pattern  \(item.pattern)") }
        detailLabel.stringValue = lines.joined(separator: "\n")
        detailLabel.isHidden = lines.isEmpty
        detailLabel.preferredMaxLayoutWidth = contentWidth(forRowWidth: width)
    }
}

// MARK: - Tool-header based blocks (plan, hookPrompt, toolCall, collab, media, reviewMode, contextCompaction)

/// A reusable header row: SF Symbol glyph + tertiary caption title. Many tool
/// blocks share this (`toolHeader` in SwiftUI). The glyph is rendered as an
/// `NSImageView` template when available; the title stays in its own label.
final class ToolHeaderView: NSStackView {
    private let icon = NSImageView()
    private let titleLabel = ConversationRowControls.label(
        font: ConversationRowMetrics.captionSemiboldFont, color: DesignTokens.text3)

    init(systemImage: String, title: String) {
        super.init(frame: .zero)
        orientation = .horizontal
        alignment = .firstBaseline
        spacing = 6
        translatesAutoresizingMaskIntoConstraints = false
        icon.translatesAutoresizingMaskIntoConstraints = false
        icon.imageScaling = .scaleProportionallyDown
        icon.contentTintColor = DesignTokens.text3
        NSLayoutConstraint.activate([
            icon.widthAnchor.constraint(equalToConstant: 13),
            icon.heightAnchor.constraint(equalToConstant: 13),
        ])
        addArrangedSubview(icon)
        addArrangedSubview(titleLabel)
        update(systemImage: systemImage, title: title)
    }

    required init?(coder: NSCoder) { nil }

    func update(systemImage: String, title: String) {
        if let image = NSImage(systemSymbolName: systemImage, accessibilityDescription: nil) {
            icon.image = image
            icon.isHidden = false
        } else {
            icon.isHidden = true
        }
        titleLabel.stringValue = title
    }
}

/// Ports "plan" / "reviewMode" — `labelledBlock`: tool header + optional body.
final class LabelledBlockCellView: ConversationRowCellView {
    private let header = ToolHeaderView(systemImage: "checklist", title: "")
    private let bodyLabel = ConversationRowControls.label(
        font: ConversationRowMetrics.calloutFont, color: DesignTokens.text)

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        applyVerticalPadding()
        contentStack.spacing = 5
        contentStack.addArrangedSubview(header)
        contentStack.addArrangedSubview(bodyLabel)
        bodyLabel.leadingAnchor.constraint(equalTo: contentStack.leadingAnchor).isActive = true
        bodyLabel.trailingAnchor.constraint(equalTo: contentStack.trailingAnchor).isActive = true
    }

    required init?(coder: NSCoder) { super.init(coder: coder) }

    override func configure(row: ConversationDisplayRow, width: CGFloat, model: SessionModel) {
        let item = row.item
        let title: String
        let symbol: String
        let body: String
        switch item.kind {
        case "plan":
            title = "Plan"; symbol = "checklist"; body = item.text
        case "reviewMode":
            let entered = item.action == "entered"
            title = entered ? "Entered review mode" : "Exited review mode"
            symbol = entered ? "text.badge.checkmark" : "text.badge.xmark"
            body = item.review
        default:
            title = item.kind; symbol = "doc"; body = item.text
        }
        header.update(systemImage: symbol, title: title)
        bodyLabel.stringValue = body
        bodyLabel.isHidden = body.isEmpty
        bodyLabel.preferredMaxLayoutWidth = contentWidth(forRowWidth: width)
    }
}

/// Ports "hookPrompt": header + per-fragment (runId caption + body) rows.
final class HookPromptCellView: ConversationRowCellView {
    private let header = ToolHeaderView(systemImage: "curlybraces", title: "Hook prompt")
    private let fragmentsStack = NSStackView()

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        applyVerticalPadding()
        contentStack.spacing = 5
        fragmentsStack.orientation = .vertical
        fragmentsStack.alignment = .leading
        fragmentsStack.spacing = 6
        fragmentsStack.translatesAutoresizingMaskIntoConstraints = false
        contentStack.addArrangedSubview(header)
        contentStack.addArrangedSubview(fragmentsStack)
        fragmentsStack.leadingAnchor.constraint(equalTo: contentStack.leadingAnchor).isActive = true
        fragmentsStack.trailingAnchor.constraint(equalTo: contentStack.trailingAnchor).isActive = true
    }

    required init?(coder: NSCoder) { super.init(coder: coder) }

    override func configure(row: ConversationDisplayRow, width: CGFloat, model: SessionModel) {
        for view in fragmentsStack.arrangedSubviews {
            fragmentsStack.removeArrangedSubview(view)
            view.removeFromSuperview()
        }
        let contentW = contentWidth(forRowWidth: width)
        for fragment in row.item.fragments {
            let runId = ConversationRowControls.label(
                font: ConversationRowMetrics.monoCaptionFont, color: DesignTokens.text3)
            runId.stringValue = fragment.hookRunId
            runId.preferredMaxLayoutWidth = contentW
            let body = ConversationRowControls.label(
                font: ConversationRowMetrics.calloutFont, color: DesignTokens.text)
            body.stringValue = fragment.text
            body.preferredMaxLayoutWidth = contentW
            let column = NSStackView(views: [runId, body])
            column.orientation = .vertical
            column.alignment = .leading
            column.spacing = 2
            fragmentsStack.addArrangedSubview(column)
            column.leadingAnchor.constraint(equalTo: fragmentsStack.leadingAnchor).isActive = true
            column.trailingAnchor.constraint(equalTo: fragmentsStack.trailingAnchor).isActive = true
        }
    }
}

/// Ports "toolCall" / MCP: header + tool name + metadata + payload labels.
final class ToolCallCellView: ConversationRowCellView {
    private let header = ToolHeaderView(systemImage: "wrench.and.screwdriver", title: "Tool call")
    private let nameLabel = ConversationRowControls.label(
        font: ConversationRowMetrics.monoCalloutMediumFont, color: DesignTokens.text)
    private let metadataLabel = ConversationRowControls.label(
        font: ConversationRowMetrics.monoCaptionFont, color: DesignTokens.text3)
    private let payloadLabel = ConversationRowControls.label(
        font: ConversationRowMetrics.monoCaptionFont, color: DesignTokens.text2)

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        applyVerticalPadding()
        contentStack.spacing = 5
        contentStack.addArrangedSubview(header)
        contentStack.addArrangedSubview(nameLabel)
        contentStack.addArrangedSubview(metadataLabel)
        contentStack.addArrangedSubview(payloadLabel)
        pin(nameLabel); pin(metadataLabel); pin(payloadLabel)
    }

    required init?(coder: NSCoder) { super.init(coder: coder) }

    private func pin(_ view: NSView) {
        view.leadingAnchor.constraint(equalTo: contentStack.leadingAnchor).isActive = true
        view.trailingAnchor.constraint(equalTo: contentStack.trailingAnchor).isActive = true
    }

    override func configure(row: ConversationDisplayRow, width: CGFloat, model: SessionModel) {
        let item = row.item
        header.update(
            systemImage: "wrench.and.screwdriver",
            title: item.toolKind == "mcp" ? "MCP tool" : "Tool call"
        )
        let contentW = contentWidth(forRowWidth: width)
        nameLabel.stringValue = ToolPresentation.toolName(item)
        nameLabel.preferredMaxLayoutWidth = contentW

        let metadata = ToolPresentation.toolMetadata(item)
        metadataLabel.stringValue = metadata.joined(separator: " · ")
        metadataLabel.isHidden = metadata.isEmpty

        var payloads: [String] = []
        if !item.arguments.isEmpty { payloads.append("arguments\n\(item.arguments)") }
        if !item.result.isEmpty { payloads.append("result\n\(item.result)") }
        if !item.errorText.isEmpty { payloads.append("error\n\(item.errorText)") }
        payloadLabel.stringValue = payloads.joined(separator: "\n\n")
        payloadLabel.isHidden = payloads.isEmpty
        payloadLabel.preferredMaxLayoutWidth = contentW
    }
}

/// Ports "collabAgentToolCall": subagent header + metadata + prompt + receivers.
final class CollabAgentCellView: ConversationRowCellView {
    private let header = ToolHeaderView(systemImage: "person.2", title: "Subagent")
    private let metadataLabel = ConversationRowControls.label(
        font: ConversationRowMetrics.monoCaptionFont, color: DesignTokens.text3)
    private let promptLabel = ConversationRowControls.label(
        font: ConversationRowMetrics.calloutFont, color: DesignTokens.text)
    private let receiversLabel = ConversationRowControls.label(
        font: ConversationRowMetrics.monoCaptionFont, color: DesignTokens.text2)

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        applyVerticalPadding()
        contentStack.spacing = 5
        contentStack.addArrangedSubview(header)
        contentStack.addArrangedSubview(metadataLabel)
        contentStack.addArrangedSubview(promptLabel)
        contentStack.addArrangedSubview(receiversLabel)
        pin(metadataLabel); pin(promptLabel); pin(receiversLabel)
    }

    required init?(coder: NSCoder) { super.init(coder: coder) }

    private func pin(_ view: NSView) {
        view.leadingAnchor.constraint(equalTo: contentStack.leadingAnchor).isActive = true
        view.trailingAnchor.constraint(equalTo: contentStack.trailingAnchor).isActive = true
    }

    override func configure(row: ConversationDisplayRow, width: CGFloat, model: SessionModel) {
        let item = row.item
        let contentW = contentWidth(forRowWidth: width)

        let metadata = [item.tool, item.statusName, item.model, item.reasoningEffort]
            .filter { !$0.isEmpty }
        metadataLabel.stringValue = metadata.joined(separator: " · ")
        metadataLabel.isHidden = metadata.isEmpty

        promptLabel.stringValue = item.prompt
        promptLabel.isHidden = item.prompt.isEmpty
        promptLabel.preferredMaxLayoutWidth = contentW

        if item.receiverThreadIds.isEmpty {
            receiversLabel.isHidden = true
        } else {
            receiversLabel.isHidden = false
            receiversLabel.stringValue = "receivers  \(item.receiverThreadIds.joined(separator: ", "))"
            receiversLabel.preferredMaxLayoutWidth = contentW
        }
    }
}

/// Ports "media": header + image preview (`NSImage(contentsOfFile:)`) +
/// metadata + optional revised prompt.
final class MediaCellView: ConversationRowCellView {
    private let header = ToolHeaderView(systemImage: "photo", title: "Image")
    private let previewImageView = NSImageView()
    private let metadataLabel = ConversationRowControls.label(
        font: ConversationRowMetrics.monoCaptionFont, color: DesignTokens.text3)
    private let revisedLabel = ConversationRowControls.label(
        font: ConversationRowMetrics.monoCaptionFont, color: DesignTokens.text2)
    private var imageHeightConstraint: NSLayoutConstraint?

    nonisolated static let maxImageWidth: CGFloat = 420
    nonisolated static let maxImageHeight: CGFloat = 320

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        applyVerticalPadding()
        contentStack.spacing = 5
        previewImageView.translatesAutoresizingMaskIntoConstraints = false
        previewImageView.imageScaling = .scaleProportionallyUpOrDown
        previewImageView.wantsLayer = true
        previewImageView.layer?.cornerRadius = 6
        previewImageView.layer?.borderWidth = 1
        previewImageView.layer?.borderColor = NSColor.separatorColor.cgColor
        previewImageView.layer?.masksToBounds = true
        let heightConstraint = previewImageView.heightAnchor.constraint(equalToConstant: 0)
        imageHeightConstraint = heightConstraint

        contentStack.addArrangedSubview(header)
        contentStack.addArrangedSubview(previewImageView)
        contentStack.addArrangedSubview(metadataLabel)
        contentStack.addArrangedSubview(revisedLabel)
        NSLayoutConstraint.activate([
            previewImageView.leadingAnchor.constraint(equalTo: contentStack.leadingAnchor),
            previewImageView.widthAnchor.constraint(lessThanOrEqualToConstant: Self.maxImageWidth),
            heightConstraint,
        ])
        pin(metadataLabel); pin(revisedLabel)
    }

    required init?(coder: NSCoder) { super.init(coder: coder) }

    private func pin(_ view: NSView) {
        view.leadingAnchor.constraint(equalTo: contentStack.leadingAnchor).isActive = true
        view.trailingAnchor.constraint(equalTo: contentStack.trailingAnchor).isActive = true
    }

    override func configure(row: ConversationDisplayRow, width: CGFloat, model: SessionModel) {
        let item = row.item
        header.update(
            systemImage: "photo",
            title: item.mediaKind == "imageGeneration" ? "Image generation" : "Image"
        )
        let contentW = contentWidth(forRowWidth: width)

        let preview = MediaPreviewPresentation(item: item)
        if let image = preview.localImage {
            previewImageView.image = image
            previewImageView.isHidden = false
            imageHeightConstraint?.constant = MediaCellView.fittedImageHeight(for: image)
        } else {
            previewImageView.image = nil
            previewImageView.isHidden = true
            imageHeightConstraint?.constant = 0
        }

        let metadata = [item.statusName, item.path, item.savedPath].filter { !$0.isEmpty }
        metadataLabel.stringValue = metadata.joined(separator: " · ")
        metadataLabel.isHidden = metadata.isEmpty

        revisedLabel.stringValue = item.revisedPrompt.isEmpty
            ? ""
            : "revised prompt  \(item.revisedPrompt)"
        revisedLabel.isHidden = item.revisedPrompt.isEmpty
        revisedLabel.preferredMaxLayoutWidth = contentW
    }

    /// Image height after fitting within the 420×320 box (preserves aspect).
    /// `nonisolated` so the factory's height math can call it directly.
    nonisolated static func fittedImageHeight(for image: NSImage) -> CGFloat {
        let size = image.size
        guard size.width > 0, size.height > 0 else { return 0 }
        let scale = min(maxImageWidth / size.width, maxImageHeight / size.height, 1)
        return ceil(size.height * scale)
    }
}

/// Ports "contextCompaction": a lone tool header (no body).
final class ContextCompactionCellView: ConversationRowCellView {
    private let header = ToolHeaderView(
        systemImage: "arrow.down.right.and.arrow.up.left", title: "Context compacted")

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        applyVerticalPadding()
        contentStack.addArrangedSubview(header)
    }

    required init?(coder: NSCoder) { super.init(coder: coder) }

    override func configure(row: ConversationDisplayRow, width: CGFloat, model: SessionModel) {
        header.update(systemImage: "arrow.down.right.and.arrow.up.left", title: "Context compacted")
    }
}

/// Ports the default branch: neutralized unknown ("raw") — tertiary callout.
final class RawCellView: ConversationRowCellView {
    override var verticalPadding: CGFloat { 8 }

    private let bodyLabel = ConversationRowControls.label(
        font: ConversationRowMetrics.calloutFont, color: DesignTokens.text3)

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        applyVerticalPadding()
        contentStack.addArrangedSubview(bodyLabel)
        bodyLabel.leadingAnchor.constraint(equalTo: contentStack.leadingAnchor).isActive = true
        bodyLabel.trailingAnchor.constraint(equalTo: contentStack.trailingAnchor).isActive = true
    }

    required init?(coder: NSCoder) { super.init(coder: coder) }

    override func configure(row: ConversationDisplayRow, width: CGFloat, model: SessionModel) {
        bodyLabel.stringValue = row.item.descriptionText
        bodyLabel.preferredMaxLayoutWidth = contentWidth(forRowWidth: width)
    }
}

// MARK: - Standalone error / warning cells (consumed by Task 8 from model fields)

/// Shared scaffolding for the standalone error / warning cells: a leading
/// `exclamationmark.triangle.fill` glyph + a tinted callout message, mirroring
/// the SwiftUI `errorRow` / `warningRow` `HStack(spacing: 6)` layout. Both are
/// string-driven (the model's `errorMessage` / `warningMessage`), not a
/// `UIItem` kind, so Task 8 can drive them directly.
class BannerCellView: ConversationRowCellView {
    private let icon = NSImageView()
    let messageLabel: NSTextField
    private let tint: NSColor

    init(tint: NSColor) {
        self.tint = tint
        self.messageLabel = ConversationRowControls.label(
            font: ConversationRowMetrics.calloutFont, color: tint)
        super.init(frame: .zero)
        applyVerticalPadding()
        icon.translatesAutoresizingMaskIntoConstraints = false
        icon.image = NSImage(
            systemSymbolName: "exclamationmark.triangle.fill", accessibilityDescription: nil)
        icon.contentTintColor = tint
        icon.imageScaling = .scaleProportionallyDown
        let row = NSStackView(views: [icon, messageLabel])
        row.orientation = .horizontal
        row.alignment = .firstBaseline
        row.spacing = 6
        row.translatesAutoresizingMaskIntoConstraints = false
        contentStack.addArrangedSubview(row)
        NSLayoutConstraint.activate([
            icon.widthAnchor.constraint(equalToConstant: 14),
            icon.heightAnchor.constraint(equalToConstant: 14),
            row.leadingAnchor.constraint(equalTo: contentStack.leadingAnchor),
            row.trailingAnchor.constraint(equalTo: contentStack.trailingAnchor),
        ])
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) is not supported") }

    func configure(message: String, width: CGFloat) {
        messageLabel.stringValue = message
        messageLabel.textColor = tint
        // The leading glyph (14) + its 6pt gap shrink the wrap width.
        messageLabel.preferredMaxLayoutWidth = max(contentWidth(forRowWidth: width) - 14 - 6, 1)
    }
}

/// Ports `errorRow`: red triangle glyph + red callout message.
final class ErrorCellView: BannerCellView {
    init() { super.init(tint: DesignTokens.danger) }
    required init?(coder: NSCoder) { fatalError("init(coder:) is not supported") }

    override func configure(row: ConversationDisplayRow, width: CGFloat, model: SessionModel) {
        configure(message: row.item.errorText.isEmpty ? row.item.text : row.item.errorText, width: width)
    }
}

/// Ports `warningRow`: orange triangle + orange callout.
final class WarningCellView: BannerCellView {
    init() { super.init(tint: DesignTokens.accent) }
    required init?(coder: NSCoder) { fatalError("init(coder:) is not supported") }

    override func configure(row: ConversationDisplayRow, width: CGFloat, model: SessionModel) {
        configure(message: row.item.text, width: width)
    }
}
