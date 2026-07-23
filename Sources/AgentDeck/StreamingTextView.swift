import AppKit
import AgentDeckCore

enum StreamingTextStorageSyncResult: Equatable {
    case unchanged
    case appended(characterCount: Int)
    case replaced
}

enum StreamingTextStorageSynchronizer {
    @discardableResult
    static func sync(
        _ storage: NSTextStorage,
        to target: String,
        attributes: [NSAttributedString.Key: Any]
    ) -> StreamingTextStorageSyncResult {
        let current = storage.string
        if current == target {
            return .unchanged
        }

        storage.beginEditing()
        defer { storage.endEditing() }

        if target.hasPrefix(current) {
            let suffixStart = target.index(target.startIndex, offsetBy: current.count)
            let suffix = String(target[suffixStart...])
            storage.append(NSAttributedString(string: suffix, attributes: attributes))
            return .appended(characterCount: suffix.count)
        }

        storage.setAttributedString(NSAttributedString(string: target, attributes: attributes))
        return .replaced
    }
}

final class StreamingTextContainerView: NSView {
    private let textView = CoordinatedStreamingTextView(frame: .zero)
    private var measuredHeight: CGFloat = 1
    private var lastFont: NSFont?
    private var lastTextColor: NSColor?
    private weak var observedBuffer: StreamingTextBuffer?
    private var observationToken: UUID?
    /// Non-nil while the view is in markdown mode (design §5). In markdown mode
    /// every buffer change recomputes the full attributed string via
    /// `MarkdownAttributedStringBuilder` and replaces the storage — the builder
    /// owns the attributes, so the plain-text font/color path is bypassed.
    private var markdownStyle: MarkdownStyle?
    /// Reasoning 的正文允许在尚未收到内容时折叠为 0 高；一旦 buffer
    /// 流入文本，intrinsic height 会随同一次更新恢复。
    var collapsesWhenEmpty = false {
        didSet {
            guard collapsesWhenEmpty != oldValue else { return }
            recalculateHeight(for: max(bounds.width, 1))
        }
    }
    private lazy var selectionOwner = SessionTextSelectionOwner { [weak self] in
        self?.textView.clearSelection()
    }

    override var isFlipped: Bool { true }

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        configureTextView()
    }

    required init?(coder: NSCoder) {
        super.init(coder: coder)
        configureTextView()
    }

    override var intrinsicContentSize: NSSize {
        NSSize(width: NSView.noIntrinsicMetric, height: measuredHeight)
    }

    override func layout() {
        super.layout()
        let height = fittingHeight(for: bounds.width)
        textView.frame = NSRect(x: 0, y: 0, width: bounds.width, height: height)
    }

    // MARK: - Rebindable AppKit core interface (Task 6)

    /// Bind this view to a new buffer, cancelling any previous subscription.
    /// Safe to call multiple times (rebind for cell reuse). Plain-text mode:
    /// the supplied font/color style every glyph (correct for raw monospaced
    /// output — reasoning / shell / fileEdit).
    func bindBuffer(to buffer: StreamingTextBuffer, font: NSFont, color: NSColor) {
        unbind()
        markdownStyle = nil
        textView.isRichText = false
        textView.font = font
        textView.textColor = color
        textView.isSelectable = true
        observedBuffer = buffer
        observationToken = buffer.observe { [weak self] change in
            self?.apply(change)
        }
        markAppearanceChanged(font: font, textColor: color)
    }

    /// Bind this view to a new buffer in MARKDOWN mode (design §5). On every
    /// change the whole `buffer.text` is re-rendered through
    /// `MarkdownAttributedStringBuilder` and replaced into the storage so the
    /// streamed assistant message shows rich markdown (bold/inline-code/links),
    /// matching userPrompt and the original SwiftUI Textual rendering. Safe to
    /// call multiple times (rebind for cell reuse) and to alternate with the
    /// plain-text `bindBuffer`.
    func bindMarkdownBuffer(to buffer: StreamingTextBuffer, style: MarkdownStyle = .standard) {
        // Cell reuse re-runs `configure` on every streaming flush. If we are
        // already subscribed to this exact buffer object in markdown mode,
        // re-binding would tear down the live subscription and rewrite the
        // storage — wiping any in-progress text selection (C2). The buffer's
        // own observer already pushes new tokens into the storage, so keep the
        // existing subscription and selection untouched.
        if let markdownStyle,
           markdownStyle.isVisuallyEquivalent(to: style),
           observedBuffer === buffer {
            return
        }
        unbind()
        markdownStyle = style
        textView.isRichText = true
        textView.isSelectable = true
        // Track the body font so the empty-state line-height fallback is sane.
        textView.font = style.bodyFont
        textView.textColor = style.textColor
        observedBuffer = buffer
        observationToken = buffer.observe { [weak self] change in
            self?.apply(change)
        }
    }

    /// Cancel the current buffer subscription without clearing displayed text.
    func unbind() {
        if let token = observationToken {
            observedBuffer?.removeObserver(token)
            observationToken = nil
        }
        observedBuffer = nil
    }

    /// The text currently displayed in the text view. Read-only; intended for testing and AppKit consumers.
    var currentText: String {
        textView.string
    }

    /// The attributed string currently in the text storage. Read-only; lets
    /// tests assert that markdown mode produced rich attributes (bold / inline
    /// code / link), not just plain text.
    var currentAttributedText: NSAttributedString {
        textView.textStorage ?? NSTextStorage()
    }

    /// The text view's current selection. Exposed so tests can assert that a
    /// streaming reconfigure (same-buffer re-bind / unchanged markdown replace)
    /// does NOT collapse a selection the user is making (C2).
    var selectedRangeForTesting: NSRange {
        get { textView.selectedRange() }
        set { textView.setSelectedRange(newValue) }
    }

    deinit {
        if let observationToken {
            observedBuffer?.removeObserver(observationToken)
        }
    }

    func apply(_ change: StreamingTextBufferChange) {
        if let style = markdownStyle {
            applyMarkdown(change, style: style)
            recalculateHeight(for: max(bounds.width, 1))
            return
        }
        let attributes = currentAttributes()
        let storage = textView.textStorage ?? NSTextStorage()
        switch change {
        case .append(let suffix):
            storage.beginEditing()
            storage.append(NSAttributedString(string: suffix, attributes: attributes))
            storage.endEditing()
        case .replace(let text):
            _ = StreamingTextStorageSynchronizer.sync(
                storage,
                to: text,
                attributes: attributes
            )
        }
        recalculateHeight(for: max(bounds.width, 1))
    }

    /// Markdown mode: recompute the FULL attributed string and replace storage.
    /// Both append and replace resolve to the buffer's current full text — the
    /// builder is whole-string (inline intents can change as later tokens
    /// arrive), so incremental appends are not safe here (design §5 「重算→替换」).
    private func applyMarkdown(_ change: StreamingTextBufferChange, style: MarkdownStyle) {
        let fullText: String
        switch change {
        case .append:
            // The whole-string builder needs the buffer's current full text;
            // with no bound buffer there is nothing authoritative to render, so
            // leave the existing storage (and any selection) intact.
            guard let buffer = observedBuffer else { return }
            fullText = buffer.text
        case .replace(let text):
            fullText = text
        }
        let storage = textView.textStorage ?? NSTextStorage()
        let attributed = MarkdownAttributedStringBuilder.attributedString(from: fullText, style: style)
        // Mirror the plain path's `.unchanged` early-return, but compare the
        // complete attributed value: identical visible text can still acquire
        // markdown emphasis or a new paragraph style.
        if storage.isEqual(to: attributed) {
            return
        }
        let preservesSelection = storage.string == attributed.string
        let selectedRanges = preservesSelection ? textView.selectedRanges : []
        storage.beginEditing()
        storage.setAttributedString(attributed)
        storage.endEditing()
        if preservesSelection {
            textView.selectedRanges = selectedRanges
        }
    }

    private func currentAttributes() -> [NSAttributedString.Key: Any] {
        [
            .font: textView.font ?? NSFont.systemFont(ofSize: NSFont.systemFontSize),
            .foregroundColor: textView.textColor ?? DesignTokens.text,
        ]
    }

    private func refreshTextAttributes() {
        // In markdown mode the builder owns every attribute; a uniform
        // font/color sweep would strip the rich styling, so skip it.
        guard markdownStyle == nil, let storage = textView.textStorage else { return }
        let fullRange = NSRange(location: 0, length: storage.length)
        storage.beginEditing()
        storage.setAttributes(currentAttributes(), range: fullRange)
        storage.endEditing()
        recalculateHeight(for: max(bounds.width, 1))
    }

    private func markAppearanceChanged(font: NSFont, textColor: NSColor) {
        if lastFont != font || lastTextColor != textColor {
            lastFont = font
            lastTextColor = textColor
            refreshTextAttributes()
        }
    }

    func fittingHeight(for width: CGFloat) -> CGFloat {
        recalculateHeight(for: max(width, 1))
        return measuredHeight
    }

    private func configureTextView() {
        textView.selectionOwner = selectionOwner
        textView.drawsBackground = false
        textView.isEditable = false
        textView.isSelectable = true
        textView.isRichText = false
        textView.importsGraphics = false
        textView.allowsUndo = false
        textView.textContainerInset = .zero
        textView.textContainer?.lineFragmentPadding = 0
        textView.textContainer?.widthTracksTextView = true
        textView.isHorizontallyResizable = false
        textView.isVerticallyResizable = true
        addSubview(textView)
    }

    private func recalculateHeight(for width: CGFloat) {
        let targetWidth = max(width, 1)
        textView.frame.size.width = targetWidth
        textView.textContainer?.containerSize = NSSize(
            width: targetWidth,
            height: .greatestFiniteMagnitude
        )

        guard let layoutManager = textView.layoutManager,
              let textContainer = textView.textContainer else {
            measuredHeight = 1
            return
        }

        if collapsesWhenEmpty, textView.string.isEmpty {
            updateMeasuredHeight(0)
            return
        }

        layoutManager.ensureLayout(for: textContainer)
        let usedRect = layoutManager.usedRect(for: textContainer)
        let lineHeight: CGFloat
        if let markdownStyle {
            lineHeight = ConversationTypography.targetLineHeight(
                for: markdownStyle.bodyFont,
                text: textView.string,
                language: markdownStyle.lineHeightLanguage
            )
        } else {
            lineHeight = textView.font?.boundingRectForFont.height ?? 1
        }
        let nextHeight = max(ceil(usedRect.height), ceil(lineHeight), 1)
        updateMeasuredHeight(nextHeight)
    }

    private func updateMeasuredHeight(_ nextHeight: CGFloat) {
        if abs(nextHeight - measuredHeight) > 0.5 {
            measuredHeight = nextHeight
            invalidateIntrinsicContentSize()
            needsLayout = true
        }
    }
}

final class CoordinatedStreamingTextView: NSTextView {
    weak var selectionOwner: SessionTextSelectionOwner?
    var selectionCoordinator: SessionTextSelectionCoordinator = .shared

    override func mouseDown(with event: NSEvent) {
        if let selectionOwner {
            selectionCoordinator.activate(selectionOwner)
        }
        super.mouseDown(with: event)
    }

    override func selectAll(_ sender: Any?) {
        if let selectionOwner {
            selectionCoordinator.activate(selectionOwner)
        }
        super.selectAll(sender)
    }

    func clearSelection() {
        setSelectedRange(NSRange(location: 0, length: 0))
    }
}
