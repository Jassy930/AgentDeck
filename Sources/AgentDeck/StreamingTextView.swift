import AppKit
import SwiftUI

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

enum StreamingTextBufferChange: Equatable {
    case append(String)
    case replace(String)
}

// Owned by the main-render path. Marked unchecked only so AppKit deinit can
// detach observers under Swift 6's nonisolated deinitializer rules.
final class StreamingTextBuffer: @unchecked Sendable {
    private var observers: [UUID: (StreamingTextBufferChange) -> Void] = [:]
    private(set) var text = ""

    func append(_ suffix: String) {
        guard !suffix.isEmpty else { return }
        text.append(contentsOf: suffix)
        notify(.append(suffix))
    }

    func replace(with nextText: String) {
        text = nextText
        notify(.replace(nextText))
    }

    func observe(_ handler: @escaping (StreamingTextBufferChange) -> Void) -> UUID {
        let id = UUID()
        observers[id] = handler
        handler(.replace(text))
        return id
    }

    func removeObserver(_ id: UUID) {
        observers.removeValue(forKey: id)
    }

    private func notify(_ change: StreamingTextBufferChange) {
        for observer in observers.values {
            observer(change)
        }
    }
}

struct StreamingTextView: NSViewRepresentable {
    let buffer: StreamingTextBuffer
    let font: NSFont
    let textColor: NSColor
    var isSelectable = true

    func makeNSView(context: Context) -> StreamingTextContainerView {
        let view = StreamingTextContainerView()
        view.update(buffer: buffer, font: font, textColor: textColor, isSelectable: isSelectable)
        return view
    }

    func updateNSView(_ nsView: StreamingTextContainerView, context: Context) {
        nsView.update(buffer: buffer, font: font, textColor: textColor, isSelectable: isSelectable)
    }

    func sizeThatFits(
        _ proposal: ProposedViewSize,
        nsView: StreamingTextContainerView,
        context: Context
    ) -> CGSize? {
        let width = max(proposal.width ?? nsView.bounds.width, 1)
        return CGSize(width: width, height: nsView.fittingHeight(for: width))
    }
}

final class StreamingTextContainerView: NSView {
    private let textView = CoordinatedStreamingTextView(frame: .zero)
    private var measuredHeight: CGFloat = 1
    private var lastFont: NSFont?
    private var lastTextColor: NSColor?
    private weak var observedBuffer: StreamingTextBuffer?
    private var observationToken: UUID?
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
    /// Safe to call multiple times (rebind for cell reuse).
    func bindBuffer(to buffer: StreamingTextBuffer, font: NSFont, color: NSColor) {
        unbind()
        textView.font = font
        textView.textColor = color
        textView.isSelectable = true
        observedBuffer = buffer
        observationToken = buffer.observe { [weak self] change in
            self?.apply(change)
        }
        markAppearanceChanged(font: font, textColor: color)
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

    // MARK: - SwiftUI NSViewRepresentable path (unchanged)

    func update(buffer: StreamingTextBuffer, font: NSFont, textColor: NSColor, isSelectable: Bool) {
        textView.font = font
        textView.textColor = textColor
        textView.isSelectable = isSelectable

        if observedBuffer !== buffer {
            if let observationToken {
                observedBuffer?.removeObserver(observationToken)
            }
            observedBuffer = buffer
            observationToken = buffer.observe { [weak self] change in
                self?.apply(change)
            }
        }

        markAppearanceChanged(font: font, textColor: textColor)
    }

    deinit {
        if let observationToken {
            observedBuffer?.removeObserver(observationToken)
        }
    }

    func apply(_ change: StreamingTextBufferChange) {
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

    private func currentAttributes() -> [NSAttributedString.Key: Any] {
        [
            .font: textView.font ?? NSFont.systemFont(ofSize: NSFont.systemFontSize),
            .foregroundColor: textView.textColor ?? NSColor.labelColor,
        ]
    }

    private func refreshTextAttributes() {
        guard let storage = textView.textStorage else { return }
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

        layoutManager.ensureLayout(for: textContainer)
        let usedRect = layoutManager.usedRect(for: textContainer)
        let lineHeight = textView.font?.boundingRectForFont.height ?? 1
        let nextHeight = max(ceil(usedRect.height), ceil(lineHeight), 1)
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
